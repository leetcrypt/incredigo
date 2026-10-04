package rotate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// SSHKey rotates an SSH key pair by minting a brand-new keypair and swapping which
// PUBLIC key is trusted in an authorized_keys file. The credential's secret is the
// OpenSSH-format PRIVATE key (the whole key file). Rotation:
//
//  1. mint a fresh ed25519 keypair entirely in memory;
//  2. install the NEW public key into authorized_keys (old key still trusted);
//  3. return a vault handle to the NEW private key (PEM) — never written to disk;
//  4. Verify dials the SSH authority with the new key to prove it authenticates;
//  5. RevokeOld removes the OLD public key from authorized_keys — only after the
//     new key is verified and stored (Hard Rule #2, verify-new-before-revoke-old).
//
// SECURITY (Hard Rule #3 — no plaintext secrets on disk, ever):
//   - The new private key is generated, PEM-marshalled, parsed, and used to
//     authenticate ENTIRELY in process (golang.org/x/crypto/ssh). It is handed to
//     the vault and to gopass; it never touches the filesystem here. No external
//     ssh-keygen, no temp key file.
//   - Only PUBLIC keys are written to authorized_keys. A leak-check in the tests
//     asserts no "PRIVATE KEY" material reaches authorized_keys.
//
// Targeting comes from ONE of two secret shapes (see decodeSSHSecret):
//
//   - a raw OpenSSH PEM private key — the discovery shape. Targeting then comes
//     from the credential's Meta (so a scanner can point it at the right authority)
//     with struct-field / sensible defaults:
//     Meta["ssh_addr"]        host:port to dial         (default 127.0.0.1:22)
//     Meta["ssh_user"]        login user                (default current user)
//     Meta["authorized_keys"] file to edit              (default ~/.ssh/authorized_keys)
//
//   - a self-contained single-line blob that carries BOTH targeting AND the key:
//     ssh://<user>@<host>:<port>/<authorized_keys_path>#<base64url(privatePEM)>
//     This is the shape the `rotate --execute` path needs: its gopass round-trip
//     drops Meta and truncates a multi-line PEM to its first line, so a Meta-targeted
//     multi-line-PEM credential could never round-trip. Encoding everything on one
//     self-describing line (the same pattern the openwrt driver uses) makes the
//     driver usable end-to-end through the store, exactly like the DSN drivers.
type SSHKey struct {
	Addr         string              // default 127.0.0.1:22
	User         string              // default current OS user
	AuthKeysPath string              // default ~/.ssh/authorized_keys
	HostKey      ssh.HostKeyCallback // default InsecureIgnoreHostKey (we own the host)
	// Dial is injectable so tests can point at an in-process SSH server. Defaults
	// to ssh.Dial.
	Dial func(network, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error)

	// mu guards inFlight: Verify in the Execute spine receives no credential, so
	// Rotate records the credential it just rotated (for its Meta targeting) and
	// Verify reads it back. Execute is sequential, so a single in-flight target is
	// sufficient; the mutex keeps it race-clean under -race.
	mu       sync.Mutex
	inFlight discover.Credential
}

// init registers the ssh driver (self-register, like database/sql). Availability
// alone changes nothing; `rotate --execute` + INCREDIGO_ALLOW_EXECUTE=1 gate it.
func init() { Register(&SSHKey{}) }

// Name identifies the driver in plans and audit records.
func (s *SSHKey) Name() string { return "ssh" }

// Detect claims credentials the ssh scanner/seed emitted (Source == "ssh").
func (s *SSHKey) Detect(c discover.Credential) bool { return c.Source == "ssh" }

func (s *SSHKey) addr(c discover.Credential) string {
	if a := c.Meta["ssh_addr"]; a != "" {
		return a
	}
	if s.Addr != "" {
		return s.Addr
	}
	return "127.0.0.1:22"
}

func (s *SSHKey) loginUser(c discover.Credential) string {
	if u := c.Meta["ssh_user"]; u != "" {
		return u
	}
	if s.User != "" {
		return s.User
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

func (s *SSHKey) authKeys(c discover.Credential) string {
	if p := c.Meta["authorized_keys"]; p != "" {
		return p
	}
	if s.AuthKeysPath != "" {
		return s.AuthKeysPath
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ssh", "authorized_keys")
}

func (s *SSHKey) hostKey() ssh.HostKeyCallback {
	if s.HostKey != nil {
		return s.HostKey
	}
	// We rotate keys for hosts the operator owns; the trust boundary here is the
	// key auth, not host identity. Host-key pinning is a separate concern.
	return ssh.InsecureIgnoreHostKey()
}

func (s *SSHKey) dial() func(string, string, *ssh.ClientConfig) (*ssh.Client, error) {
	if s.Dial != nil {
		return s.Dial
	}
	return ssh.Dial
}

// sshTarget is the resolved rotation target: where the SSH authority lives and
// which authorized_keys file trusts the credential.
type sshTarget struct {
	user     string // login user
	addr     string // host:port to dial
	authKeys string // authorized_keys file to edit
}

// decodeSSHSecret classifies a credential secret into its targeting + private-key
// PEM. blob=true means the secret is a self-contained ssh:// URL that carries its
// OWN targeting (the round-trippable execute shape); blob=false means it is a raw
// PEM private key whose targeting must come from Meta/defaults (the discovery
// shape). keyPEM is always an independent copy safe to use after the vault buffer.
func decodeSSHSecret(raw []byte) (tgt sshTarget, keyPEM []byte, blob bool, err error) {
	trimmed := bytes.TrimSpace(raw)
	if bytes.HasPrefix(trimmed, []byte("ssh://")) {
		u, e := url.Parse(string(trimmed))
		if e != nil {
			return sshTarget{}, nil, false, fmt.Errorf("parse secret url: %w", e)
		}
		if u.User == nil || u.User.Username() == "" {
			return sshTarget{}, nil, false, errors.New("secret url has no user")
		}
		if u.Path == "" {
			return sshTarget{}, nil, false, errors.New("secret url has no authorized_keys path")
		}
		if u.Fragment == "" {
			return sshTarget{}, nil, false, errors.New("secret url carries no key")
		}
		key, e := base64.RawURLEncoding.DecodeString(u.Fragment)
		if e != nil {
			return sshTarget{}, nil, false, fmt.Errorf("decode key: %w", e)
		}
		port := u.Port()
		if port == "" {
			port = "22"
		}
		return sshTarget{
			user:     u.User.Username(),
			addr:     net.JoinHostPort(u.Hostname(), port),
			authKeys: u.Path,
		}, key, true, nil
	}
	if bytes.Contains(trimmed, []byte("PRIVATE KEY")) {
		return sshTarget{}, append([]byte(nil), raw...), false, nil
	}
	return sshTarget{}, nil, false, errors.New("secret is neither an ssh:// blob nor a PEM private key")
}

// buildSSHBlob rebuilds a self-contained ssh:// secret from a target and a private
// key PEM. Inverse of the blob branch of decodeSSHSecret; the key rides in the
// URL-safe (padding-free) fragment so it needs no escaping.
func buildSSHBlob(tgt sshTarget, keyPEM []byte) string {
	host, port, err := net.SplitHostPort(tgt.addr)
	if err != nil {
		host, port = tgt.addr, "22"
	}
	u := url.URL{
		Scheme:   "ssh",
		User:     url.User(tgt.user),
		Host:     net.JoinHostPort(host, port),
		Path:     tgt.authKeys,
		Fragment: base64.RawURLEncoding.EncodeToString(keyPEM),
	}
	return u.String()
}

// targetFor resolves targeting for a raw-PEM (Meta/default) credential.
func (s *SSHKey) targetFor(c discover.Credential) sshTarget {
	return sshTarget{user: s.loginUser(c), addr: s.addr(c), authKeys: s.authKeys(c)}
}

// Rotate mints a new ed25519 keypair in memory, installs the new PUBLIC key into
// authorized_keys (leaving the old one trusted), and returns a vault handle to the
// new secret. For a blob credential the new secret is a rebuilt ssh:// blob (same
// targeting, new key); for a raw-PEM credential it is the bare new PRIVATE PEM. It
// does not revoke the old key.
func (s *SSHKey) Rotate(ctx context.Context, c discover.Credential, v *vault.Vault) (*vault.Handle, error) {
	if c.Secret == nil {
		return nil, errors.New("ssh: nil secret handle")
	}
	buf, err := v.Open(c.Secret)
	if err != nil {
		return nil, err
	}
	tgt, oldPEM, blob, err := decodeSSHSecret(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("ssh: %w", err)
	}
	if !blob {
		tgt = s.targetFor(c)
	}
	// Validate we can parse the OLD key first — refuse to rotate something we don't
	// actually hold a usable secret for (encrypted keys without a passphrase, junk).
	if _, err := signerFromPEM(oldPEM); err != nil {
		return nil, fmt.Errorf("ssh: old key unusable: %w", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ssh: generate key: %w", err)
	}

	comment := fmt.Sprintf("incredigo-rotated-%s-%d", c.Identity, time.Now().Unix())
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, fmt.Errorf("ssh: marshal private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(block)

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("ssh: new public key: %w", err)
	}
	newLine := ssh.MarshalAuthorizedKey(sshPub) // "<type> <base64> ...\n"
	// strip generated comment-less trailing and re-append with our comment for
	// human readability in authorized_keys (the blob is unchanged).
	newLine = append(bytes.TrimRight(newLine, "\n"), []byte(" "+comment+"\n")...)

	if err := appendAuthorizedKey(tgt.authKeys, newLine); err != nil {
		return nil, fmt.Errorf("ssh: install new public key: %w", err)
	}

	// Record this credential's targeting for the credential-less Verify that
	// Execute calls next (used only by the raw-PEM path; a blob is self-targeting).
	s.mu.Lock()
	s.inFlight = c
	s.mu.Unlock()

	if blob {
		return v.Store([]byte(buildSSHBlob(tgt, privPEM))), nil
	}
	// Hand the new private key to the vault; Store wipes the passed slice.
	return v.Store(privPEM), nil
}

// Verify proves the newly minted private key authenticates by dialing the SSH
// authority and opening a session-less connection. A blob secret is self-targeting;
// a raw-PEM secret uses the credential Rotate recorded in inFlight.
func (s *SSHKey) Verify(ctx context.Context, newSecret *vault.Handle, v *vault.Vault) error {
	if newSecret == nil {
		return errors.New("ssh verify: nil secret handle")
	}
	buf, err := v.Open(newSecret)
	if err != nil {
		return fmt.Errorf("ssh verify: %w", err)
	}
	tgt, keyPEM, blob, err := decodeSSHSecret(buf.Bytes())
	if err != nil {
		return fmt.Errorf("ssh verify: %w", err)
	}
	if !blob {
		s.mu.Lock()
		c := s.inFlight
		s.mu.Unlock()
		tgt = s.targetFor(c)
	}
	signer, err := signerFromPEM(keyPEM)
	if err != nil {
		return fmt.Errorf("ssh verify: %w", err)
	}
	return s.dialTarget(ctx, tgt, signer)
}

// dialTarget opens (and immediately closes) an SSH connection to tgt authenticated
// by signer.
func (s *SSHKey) dialTarget(ctx context.Context, tgt sshTarget, signer ssh.Signer) error {
	cfg := &ssh.ClientConfig{
		User:            tgt.user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: s.hostKey(),
		Timeout:         10 * time.Second,
	}
	cli, err := s.dial()("tcp", tgt.addr, cfg)
	if err != nil {
		return fmt.Errorf("ssh dial %s: %w", tgt.addr, err)
	}
	_ = cli.Close()
	return nil
}

// RevokeOld removes the OLD public key from authorized_keys. It derives the public
// key from the old PRIVATE secret, so it removes exactly the line the old key would
// authenticate with (compared by the base64 key blob, ignoring options/comment
// differences). Targeting follows the secret's shape (blob self-targets; raw PEM
// uses Meta/defaults).
func (s *SSHKey) RevokeOld(ctx context.Context, c discover.Credential, v *vault.Vault) error {
	if c.Secret == nil {
		return errors.New("ssh revoke: nil secret handle")
	}
	buf, err := v.Open(c.Secret)
	if err != nil {
		return fmt.Errorf("ssh revoke: %w", err)
	}
	tgt, oldPEM, blob, err := decodeSSHSecret(buf.Bytes())
	if err != nil {
		return fmt.Errorf("ssh revoke: %w", err)
	}
	if !blob {
		tgt = s.targetFor(c)
	}
	signer, err := signerFromPEM(oldPEM)
	if err != nil {
		return fmt.Errorf("ssh revoke: old key unusable: %w", err)
	}
	oldLine := ssh.MarshalAuthorizedKey(signer.PublicKey())
	return removeAuthorizedKey(tgt.authKeys, oldLine)
}

// signerFromPEM parses an OpenSSH private key PEM into a Signer.
func signerFromPEM(keyPEM []byte) (ssh.Signer, error) {
	if len(keyPEM) == 0 {
		return nil, errors.New("empty private key")
	}
	signer, err := ssh.ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return signer, nil
}

// authKeyBlob returns the base64 key field (the 2nd whitespace-separated token) of
// an authorized_keys line, which uniquely identifies the key independent of any
// leading options or trailing comment. Returns nil if the line has no key blob.
func authKeyBlob(line []byte) []byte {
	line = bytes.TrimSpace(line)
	if len(line) == 0 || line[0] == '#' {
		return nil
	}
	fields := bytes.Fields(line)
	// Plain form: "<type> <base64> [comment]". Options form:
	// "<options> <type> <base64> [comment]". The key blob is the long base64
	// token that starts with the SSH key-type magic ("AAAA"); find it robustly.
	for _, f := range fields {
		if bytes.HasPrefix(f, []byte("AAAA")) {
			return f
		}
	}
	return nil
}

// appendAuthorizedKey adds line to the authorized_keys file if an entry with the
// same key blob is not already present. It creates ~/.ssh (0700) and the file
// (0600) as needed. line must end in a newline.
func appendAuthorizedKey(path string, line []byte) error {
	want := authKeyBlob(line)
	if want == nil {
		return errors.New("authorized_keys: refusing to write a line with no key blob")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if existing, err := os.ReadFile(path); err == nil {
		for _, l := range bytes.Split(existing, []byte("\n")) {
			if bytes.Equal(authKeyBlob(l), want) {
				return nil // already trusted — idempotent
			}
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if !bytes.HasSuffix(line, []byte("\n")) {
		line = append(line, '\n')
	}
	_, err = f.Write(line)
	return err
}

// removeAuthorizedKey rewrites authorized_keys without any line whose key blob
// matches line's, via a temp file + atomic rename so a crash never leaves a
// truncated file (which could lock the operator out).
func removeAuthorizedKey(path string, line []byte) error {
	target := authKeyBlob(line)
	if target == nil {
		return errors.New("authorized_keys: cannot revoke a line with no key blob")
	}
	existing, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // nothing to revoke
		}
		return err
	}
	var keep [][]byte
	for _, l := range bytes.Split(existing, []byte("\n")) {
		if bytes.Equal(authKeyBlob(l), target) {
			continue // drop the old key
		}
		keep = append(keep, l)
	}
	out := bytes.Join(keep, []byte("\n"))

	tmp := path + ".incredigo.tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
