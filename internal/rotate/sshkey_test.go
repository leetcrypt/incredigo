package rotate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// TestSSHKeyRotateRealCutover proves the full SSH cutover against an in-process
// SSH server: the new key authenticates, the old key is dropped from
// authorized_keys only after verify, and no private-key material is ever written
// to authorized_keys.
func TestSSHKeyRotateRealCutover(t *testing.T) {
	v := vault.New()
	defer v.Purge()

	authKeys := filepath.Join(t.TempDir(), "authorized_keys")

	// Seed an OLD keypair: pubkey trusted in authorized_keys, private PEM in vault.
	oldPub, oldPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen old key: %v", err)
	}
	oldSSHPub, err := ssh.NewPublicKey(oldPub)
	if err != nil {
		t.Fatalf("old ssh pub: %v", err)
	}
	if err := os.WriteFile(authKeys, ssh.MarshalAuthorizedKey(oldSSHPub), 0o600); err != nil {
		t.Fatalf("seed authorized_keys: %v", err)
	}
	oldBlock, err := ssh.MarshalPrivateKey(oldPriv, "old")
	if err != nil {
		t.Fatalf("marshal old priv: %v", err)
	}
	oldPEM := pem.EncodeToMemory(oldBlock)
	oldPEMCopy := append([]byte(nil), oldPEM...) // for later inequality check (Store wipes oldPEM)

	oldSigner, err := ssh.NewSignerFromKey(oldPriv)
	if err != nil {
		t.Fatalf("old signer: %v", err)
	}

	addr := startSSHServer(t, authKeys)

	cred := discover.Credential{
		Source:   "ssh",
		Kind:     discover.KindPrivateKey,
		Identity: "id_ed25519",
		Location: authKeys,
		Secret:   v.Store(oldPEM),
		Meta: map[string]string{
			"ssh_addr":        addr,
			"ssh_user":        "tester",
			"authorized_keys": authKeys,
		},
	}

	// Baseline: the old key authenticates before any rotation.
	if err := canAuth(addr, "tester", oldSigner); err != nil {
		t.Fatalf("old key should authenticate at start: %v", err)
	}

	s := &SSHKey{}
	ctx := context.Background()

	// 1. Rotate — mint new key, install its pubkey (old still trusted).
	newH, err := s.Rotate(ctx, cred, v)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	nb, err := v.Open(newH)
	if err != nil {
		t.Fatalf("open new secret: %v", err)
	}
	if bytes.Equal(nb.Bytes(), oldPEMCopy) {
		t.Fatal("new private key equals old — rotation minted nothing")
	}
	if !bytes.Contains(nb.Bytes(), []byte("PRIVATE KEY")) {
		t.Fatal("new secret is not a private key PEM")
	}
	newSigner, err := ssh.ParsePrivateKey(nb.Bytes())
	if err != nil {
		t.Fatalf("parse new private key: %v", err)
	}

	// After Rotate both keys authenticate (verify-before-revoke ordering).
	if err := canAuth(addr, "tester", oldSigner); err != nil {
		t.Fatalf("old key must still work before revoke: %v", err)
	}
	if err := canAuth(addr, "tester", newSigner); err != nil {
		t.Fatalf("new key must authenticate after install: %v", err)
	}

	// 2. Verify(new) via the driver.
	if err := s.Verify(ctx, newH, v); err != nil {
		t.Fatalf("Verify(new): %v", err)
	}

	// 3. RevokeOld — drop the old pubkey.
	if err := s.RevokeOld(ctx, cred, v); err != nil {
		t.Fatalf("RevokeOld: %v", err)
	}

	// Cutover assertions: old dead, new alive.
	if err := canAuth(addr, "tester", oldSigner); err == nil {
		t.Fatal("old key must be rejected after revoke")
	}
	if err := canAuth(addr, "tester", newSigner); err != nil {
		t.Fatalf("new key must still authenticate after revoke: %v", err)
	}

	// Hard Rule #3: no private-key material in authorized_keys.
	final, err := os.ReadFile(authKeys)
	if err != nil {
		t.Fatalf("read authorized_keys: %v", err)
	}
	if bytes.Contains(final, []byte("PRIVATE KEY")) {
		t.Fatal("authorized_keys leaked private key material")
	}
	// Exactly one key should remain (the new one).
	if got := bytes.Count(bytes.TrimSpace(final), []byte("ssh-ed25519")); got != 1 {
		t.Fatalf("expected exactly 1 trusted key after cutover, found %d", got)
	}
}

// TestSSHKeyBlobRoundTripNoMeta proves the self-contained blob shape drives a real
// cutover with NO Meta and as a SINGLE LINE — the exact conditions of the `rotate
// --execute` gopass path, which drops Meta and truncates multi-line secrets. All
// targeting (user/addr/authorized_keys) is recovered from the secret itself, and the
// rotated secret is again a single-line ssh:// blob (same targeting, new key).
func TestSSHKeyBlobRoundTripNoMeta(t *testing.T) {
	v := vault.New()
	defer v.Purge()

	authKeys := filepath.Join(t.TempDir(), "authorized_keys")
	oldPub, oldPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen old key: %v", err)
	}
	oldSSHPub, err := ssh.NewPublicKey(oldPub)
	if err != nil {
		t.Fatalf("old ssh pub: %v", err)
	}
	if err := os.WriteFile(authKeys, ssh.MarshalAuthorizedKey(oldSSHPub), 0o600); err != nil {
		t.Fatalf("seed authorized_keys: %v", err)
	}
	oldBlock, err := ssh.MarshalPrivateKey(oldPriv, "old")
	if err != nil {
		t.Fatalf("marshal old priv: %v", err)
	}
	oldPEM := pem.EncodeToMemory(oldBlock)
	oldSigner, err := ssh.NewSignerFromKey(oldPriv)
	if err != nil {
		t.Fatalf("old signer: %v", err)
	}

	addr := startSSHServer(t, authKeys)

	// Self-contained blob secret — Meta deliberately nil.
	blob := buildSSHBlob(sshTarget{user: "tester", addr: addr, authKeys: authKeys}, oldPEM)
	if bytes.ContainsRune([]byte(blob), '\n') {
		t.Fatal("seed blob is not single-line — would not survive the gopass sink")
	}
	cred := discover.Credential{
		Source:   "ssh",
		Kind:     discover.KindPrivateKey,
		Identity: "imported/ssh/labkey",
		Location: "imported/ssh/labkey",
		Secret:   v.Store([]byte(blob)),
	}

	if err := canAuth(addr, "tester", oldSigner); err != nil {
		t.Fatalf("old key should authenticate at start: %v", err)
	}

	s := &SSHKey{}
	ctx := context.Background()

	newH, err := s.Rotate(ctx, cred, v)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	nb, err := v.Open(newH)
	if err != nil {
		t.Fatalf("open new secret: %v", err)
	}
	newBlob := append([]byte(nil), nb.Bytes()...)
	if !bytes.HasPrefix(bytes.TrimSpace(newBlob), []byte("ssh://")) {
		t.Fatal("rotated secret is not a self-contained ssh:// blob")
	}
	if bytes.ContainsRune(newBlob, '\n') {
		t.Fatal("rotated blob is not single-line")
	}
	ntgt, nKeyPEM, isBlob, err := decodeSSHSecret(newBlob)
	if err != nil || !isBlob {
		t.Fatalf("decode rotated blob: err=%v blob=%v", err, isBlob)
	}
	if ntgt.user != "tester" || ntgt.addr != addr || ntgt.authKeys != authKeys {
		t.Fatalf("targeting not preserved across rotation: %+v", ntgt)
	}
	if bytes.Contains(nKeyPEM, []byte(oldPEM)) || bytes.Equal(nKeyPEM, oldPEM) {
		t.Fatal("new private key equals old — rotation minted nothing")
	}
	newSigner, err := ssh.ParsePrivateKey(nKeyPEM)
	if err != nil {
		t.Fatalf("parse new private key: %v", err)
	}

	// Verify(new) — targeting comes purely from the blob (no inFlight Meta needed).
	if err := s.Verify(ctx, newH, v); err != nil {
		t.Fatalf("Verify(new): %v", err)
	}

	if err := s.RevokeOld(ctx, cred, v); err != nil {
		t.Fatalf("RevokeOld: %v", err)
	}

	if err := canAuth(addr, "tester", oldSigner); err == nil {
		t.Fatal("old key must be rejected after revoke")
	}
	if err := canAuth(addr, "tester", newSigner); err != nil {
		t.Fatalf("new key must still authenticate after revoke: %v", err)
	}

	final, err := os.ReadFile(authKeys)
	if err != nil {
		t.Fatalf("read authorized_keys: %v", err)
	}
	if bytes.Contains(final, []byte("PRIVATE KEY")) {
		t.Fatal("authorized_keys leaked private key material")
	}
	if got := bytes.Count(bytes.TrimSpace(final), []byte("ssh-ed25519")); got != 1 {
		t.Fatalf("expected exactly 1 trusted key after cutover, found %d", got)
	}
}

// canAuth dials addr and authenticates with signer, returning nil on success.
func canAuth(addr, user string, signer ssh.Signer) error {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	cli, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return err
	}
	return cli.Close()
}

// startSSHServer launches an in-process SSH server on a random localhost port that
// authorizes any public key currently present in authKeysPath (re-read per attempt,
// so it reflects rotation). It returns the listen address; the listener is closed
// at test cleanup.
func startSSHServer(t *testing.T, authKeysPath string) string {
	t.Helper()

	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go serveSSH(conn, hostSigner, authKeysPath)
		}
	}()
	return ln.Addr().String()
}

func serveSSH(conn net.Conn, hostKey ssh.Signer, authKeysPath string) {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if keyAuthorized(authKeysPath, key) {
				return &ssh.Permissions{}, nil
			}
			return nil, ssh.ErrNoAuth
		},
	}
	cfg.AddHostKey(hostKey)

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		conn.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	go func() {
		for ch := range chans {
			ch.Reject(ssh.Prohibited, "no channels")
		}
	}()
	_ = sshConn
}

// keyAuthorized reports whether key matches any entry in authKeysPath.
func keyAuthorized(path string, key ssh.PublicKey) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	want := key.Marshal()
	for len(data) > 0 {
		pub, _, _, rest, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			break
		}
		if bytes.Equal(pub.Marshal(), want) {
			return true
		}
		data = rest
	}
	return false
}
