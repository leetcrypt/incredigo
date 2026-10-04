package rotate

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"golang.org/x/crypto/curve25519"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// WireGuard rotates a self-hosted WireGuard interface key, the LOCAL keypair pattern
// (the same family as SSHKey). The credential's secret is the interface PRIVATE key
// (base64, 32 bytes — the value of a `[Interface] PrivateKey =` line). Rotation:
//
//  1. mint a fresh Curve25519 keypair entirely in memory;
//  2. apply the NEW private key to the local interface (`wg set <iface> private-key`),
//     fed on stdin so it never lands in argv or on disk;
//  3. teach the PEER (the other end) to trust the NEW public key, carrying over the
//     old peer's allowed-ips (`wg set <peer_iface> peer <newpub> allowed-ips …`);
//  4. return a vault handle to the NEW private key (base64) — never written to disk;
//  5. Verify proves the peer now trusts the new public key;
//  6. RevokeOld removes the OLD public key from the peer — only after the new key is
//     verified and stored (Hard Rule #2, verify-new-before-revoke-old).
//
// SECURITY (Hard Rule #3 — no plaintext secrets on disk, ever):
//   - The new private key is generated and used ENTIRELY in process; it reaches `wg`
//     only via stdin (`wg set <iface> private-key /dev/stdin`), never argv, never a
//     key file. Only PUBLIC keys appear on the peer/`wg set peer` argument list. A
//     leak-check in the tests asserts no private-key material reaches any wg call's
//     argv or the peer state.
//
// Targeting (Meta, with struct-field / sensible defaults), so this models the
// self-hosted single-host case (an interface and its single peer the operator owns);
// a client→server split would propagate step 3/6 to the server over SSH/API instead:
//
//	Meta["wg_iface"]      local interface whose key we rotate (default wg0)
//	Meta["wg_peer_iface"] the peer interface that must trust our key (default wg1)
//	Meta["wg_allowed_ips"] fallback allowed-ips if the peer has none for the old key
type WireGuard struct {
	Bin        string // wg binary; defaults to "wg"
	Iface      string // default wg0
	PeerIface  string // default wg1
	AllowedIPs string // fallback allowed-ips for the re-added peer

	// mu guards inFlight: Verify in the Execute spine receives no credential, so
	// Rotate records what it just rotated and Verify reads it back. Execute is
	// sequential; the mutex keeps the single in-flight target race-clean.
	mu       sync.Mutex
	inFlight discover.Credential
}

// init registers the driver. Availability alone changes nothing; `rotate --execute`
// + INCREDIGO_ALLOW_EXECUTE=1 gate any real change.
func init() { Register(&WireGuard{}) }

// Name identifies the driver in plans and audit records.
func (w *WireGuard) Name() string { return "wireguard" }

// Detect claims credentials a wireguard scanner/seed emitted (Source == "wireguard").
func (w *WireGuard) Detect(c discover.Credential) bool { return c.Source == "wireguard" }

func (w *WireGuard) bin() string {
	if w.Bin != "" {
		return w.Bin
	}
	return "wg"
}

func (w *WireGuard) iface(c discover.Credential) string {
	if i := c.Meta["wg_iface"]; i != "" {
		return i
	}
	if w.Iface != "" {
		return w.Iface
	}
	return "wg0"
}

func (w *WireGuard) peerIface(c discover.Credential) string {
	if i := c.Meta["wg_peer_iface"]; i != "" {
		return i
	}
	if w.PeerIface != "" {
		return w.PeerIface
	}
	return "wg1"
}

func (w *WireGuard) allowedIPsFallback(c discover.Credential) string {
	if a := c.Meta["wg_allowed_ips"]; a != "" {
		return a
	}
	return w.AllowedIPs
}

// Rotate mints a new keypair in memory, applies the new private key to the local
// interface, teaches the peer to trust the new public key (carrying over the old
// peer's allowed-ips), and returns a vault handle to the new private key (base64).
// It does not remove the old key.
func (w *WireGuard) Rotate(ctx context.Context, c discover.Credential, v *vault.Vault) (*vault.Handle, error) {
	oldPub, err := w.pubOf(v, c.Secret)
	if err != nil {
		return nil, fmt.Errorf("wireguard: old key unusable: %w", err)
	}

	newPriv, newPub, err := genWGKey()
	if err != nil {
		return nil, fmt.Errorf("wireguard: generate key: %w", err)
	}

	// Carry over the allowed-ips the peer currently routes to our OLD key, so the
	// re-added entry keeps the same routing. Fall back to Meta/struct if absent.
	allowed := w.peerAllowedIPs(ctx, c, oldPub)
	if allowed == "" {
		allowed = w.allowedIPsFallback(c)
	}
	if allowed == "" {
		zeroBytes(newPriv)
		return nil, errors.New("wireguard: no allowed-ips for peer (set Meta wg_allowed_ips)")
	}

	// Apply the new private key to our interface via stdin — never argv, never disk.
	newPrivB64 := base64.StdEncoding.EncodeToString(newPriv)
	if _, err := w.wgStdin(ctx, newPrivB64+"\n", "set", w.iface(c), "private-key", "/dev/stdin"); err != nil {
		zeroBytes(newPriv)
		return nil, fmt.Errorf("wireguard: set interface key: %w", err)
	}

	// Teach the peer to trust the NEW public key (old still trusted until RevokeOld).
	if _, err := w.wg(ctx, "set", w.peerIface(c), "peer", newPub, "allowed-ips", allowed); err != nil {
		zeroBytes(newPriv)
		return nil, fmt.Errorf("wireguard: add peer pubkey: %w", err)
	}

	w.mu.Lock()
	w.inFlight = c
	w.mu.Unlock()

	h := v.Store([]byte(newPrivB64))
	zeroBytes(newPriv)
	return h, nil
}

// Verify proves the peer now trusts the public key derived from the new private key.
func (w *WireGuard) Verify(ctx context.Context, newSecret *vault.Handle, v *vault.Vault) error {
	newPub, err := w.pubOf(v, newSecret)
	if err != nil {
		return fmt.Errorf("wireguard verify: %w", err)
	}
	w.mu.Lock()
	c := w.inFlight
	w.mu.Unlock()

	out, err := w.wg(ctx, "show", w.peerIface(c), "peers")
	if err != nil {
		return fmt.Errorf("wireguard verify: %w", err)
	}
	if !strings.Contains(out, newPub) {
		return errors.New("wireguard verify: peer does not trust the new public key")
	}
	return nil
}

// RevokeOld removes the OLD public key from the peer. It derives the public key from
// the old PRIVATE secret in the vault, so it removes exactly the peer entry the old
// key authenticated with.
func (w *WireGuard) RevokeOld(ctx context.Context, c discover.Credential, v *vault.Vault) error {
	oldPub, err := w.pubOf(v, c.Secret)
	if err != nil {
		return fmt.Errorf("wireguard revoke: old key unusable: %w", err)
	}
	if _, err := w.wg(ctx, "set", w.peerIface(c), "peer", oldPub, "remove"); err != nil {
		return fmt.Errorf("wireguard revoke: %w", err)
	}
	return nil
}

// peerAllowedIPs reads the allowed-ips the peer currently maps to pub, or "" if the
// peer has no entry for it. Output of `wg show <iface> allowed-ips` is one
// "<pubkey>\t<ip>[,<ip>...]" row per peer.
func (w *WireGuard) peerAllowedIPs(ctx context.Context, c discover.Credential, pub string) string {
	out, err := w.wg(ctx, "show", w.peerIface(c), "allowed-ips")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == pub {
			return fields[1]
		}
	}
	return ""
}

// pubOf reads a base64 WireGuard private key from the vault and returns its base64
// public key, keeping the private bytes out of any retained Go string.
func (w *WireGuard) pubOf(v *vault.Vault, h *vault.Handle) (string, error) {
	if h == nil {
		return "", errors.New("nil secret handle")
	}
	buf, err := v.Open(h)
	if err != nil {
		return "", err
	}
	return pubFromPrivB64(strings.TrimSpace(string(buf.Bytes())))
}

// wg runs `wg <args...>` with no stdin and returns trimmed stdout, redacting nothing
// because only public keys / interface names ever appear here.
func (w *WireGuard) wg(ctx context.Context, args ...string) (string, error) {
	return w.wgStdin(ctx, "", args...)
}

// wgStdin runs `wg <args...>` feeding stdin (used to pass a private key to
// `set ... private-key /dev/stdin` without it touching argv or disk).
func (w *WireGuard) wgStdin(ctx context.Context, stdin string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, w.bin(), args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("%v: %s", err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

// genWGKey mints a clamped Curve25519 private key and its public key, the way
// `wg genkey | wg pubkey` would, entirely in memory.
func genWGKey() (priv []byte, pubB64 string, err error) {
	priv = make([]byte, 32)
	if _, err = rand.Read(priv); err != nil {
		return nil, "", err
	}
	// Curve25519 clamping (RFC 7748 §5).
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		zeroBytes(priv)
		return nil, "", err
	}
	return priv, base64.StdEncoding.EncodeToString(pub), nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
