package rotate

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// writeFakeWg writes a stub `wg` that maintains peer/interface state under $WG_STATE
// so a test can prove a real cutover: after Rotate the peer trusts the NEW public
// key; after RevokeOld it no longer trusts the OLD one. It also appends every argv to
// argv.log so a leak-check can assert no PRIVATE key ever reached the argument list
// (private keys must arrive only on stdin).
func writeFakeWg(t *testing.T, state string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "wg")
	script := `#!/usr/bin/env bash
set -uo pipefail
S="` + state + `"
echo "$*" >> "$S/argv.log"
cmd="$1"; iface="$2"
peers="$S/$iface.peers"
case "$cmd" in
  set)
    case "$3" in
      private-key) cat > "$S/$iface.priv" ;;   # key arrives on stdin, never argv
      peer)
        pub="$4"
        touch "$peers"
        grep -Fv "$pub	" "$peers" > "$peers.tmp" 2>/dev/null || true
        mv "$peers.tmp" "$peers"
        if [ "$5" = "allowed-ips" ]; then printf '%s\t%s\n' "$pub" "$6" >> "$peers"; fi
        ;;   # "$5" = remove just leaves the grep -Fv result (entry dropped)
    esac
    ;;
  show)
    case "$3" in
      allowed-ips) cat "$peers" 2>/dev/null || true ;;
      peers) awk '{print $1}' "$peers" 2>/dev/null || true ;;
    esac
    ;;
esac
exit 0
`
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestWireGuardDetect(t *testing.T) {
	w := &WireGuard{}
	if !w.Detect(discover.Credential{Source: "wireguard"}) {
		t.Error("should detect Source=wireguard")
	}
	if w.Detect(discover.Credential{Source: "ssh"}) {
		t.Error("should not detect Source=ssh")
	}
}

func TestWireGuardRotateRealCutover(t *testing.T) {
	state := t.TempDir()
	wg := writeFakeWg(t, state)

	// Mint an old keypair the same way the driver would, seed it as the credential,
	// and seed the peer (wg1) so it trusts the OLD public key with some allowed-ips.
	oldPriv, oldPub, err := genWGKey()
	if err != nil {
		t.Fatal(err)
	}
	oldPrivB64 := base64.StdEncoding.EncodeToString(oldPriv)
	if err := os.WriteFile(filepath.Join(state, "wg1.peers"), []byte(oldPub+"\t10.0.0.2/32\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	w := &WireGuard{Bin: wg, Iface: "wg0", PeerIface: "wg1"}
	v := vault.New()
	defer v.Purge()
	cred := discover.Credential{Source: "wireguard", Identity: "wg0", Secret: v.Store([]byte(oldPrivB64))}
	ctx := context.Background()

	newH, err := w.Rotate(ctx, cred, v)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// Read back the new private key for inequality + leak assertions.
	nb, err := v.Open(newH)
	if err != nil {
		t.Fatal(err)
	}
	newPrivB64 := strings.TrimSpace(string(nb.Bytes()))
	if newPrivB64 == oldPrivB64 {
		t.Fatal("private key not changed by rotation")
	}

	if err := w.Verify(ctx, newH, v); err != nil {
		t.Errorf("Verify(new) should pass: %v", err)
	}

	// The new interface private key must have been applied (stdin → state file)...
	if got, _ := os.ReadFile(filepath.Join(state, "wg0.priv")); strings.TrimSpace(string(got)) != newPrivB64 {
		t.Error("interface private key was not applied")
	}
	// ...and NO private key may ever have appeared on a wg argument list.
	argv, _ := os.ReadFile(filepath.Join(state, "argv.log"))
	for _, secret := range []string{oldPrivB64, newPrivB64} {
		if strings.Contains(string(argv), secret) {
			t.Error("a private key leaked into wg argv")
		}
	}
	// The peer state must hold public keys only, never a private key.
	peers, _ := os.ReadFile(filepath.Join(state, "wg1.peers"))
	for _, secret := range []string{oldPrivB64, newPrivB64} {
		if strings.Contains(string(peers), secret) {
			t.Error("a private key leaked into peer state")
		}
	}

	// Cutover: after RevokeOld the peer drops the OLD pubkey but keeps the NEW one.
	if err := w.RevokeOld(ctx, cred, v); err != nil {
		t.Fatalf("RevokeOld: %v", err)
	}
	peers, _ = os.ReadFile(filepath.Join(state, "wg1.peers"))
	if strings.Contains(string(peers), oldPub) {
		t.Error("peer still trusts the OLD public key after RevokeOld")
	}
	if newPub, _ := w.pubOf(v, newH); !strings.Contains(string(peers), newPub) {
		t.Error("peer should still trust the NEW public key after RevokeOld")
	}
}

func TestWireGuardRejectsBadKey(t *testing.T) {
	w := &WireGuard{Bin: "/bin/false"}
	v := vault.New()
	defer v.Purge()
	cred := discover.Credential{Source: "wireguard", Secret: v.Store([]byte("not-base64-or-32-bytes"))}
	if _, err := w.Rotate(context.Background(), cred, v); err == nil {
		t.Error("Rotate should reject an unusable private key")
	}
}
