package discover

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"incredigo/internal/vault"
)

func init() { Register(&sshScanner{}) }

// sshScanner harvests SSH private keys from their common locations:
//
//   - every regular file in ~/.ssh whose CONTENT is a private key (not just the
//     conventional id_* names — a key may be named anything), excluding the
//     obvious non-key companions (*.pub, known_hosts, authorized_keys, config…);
//   - any path referenced by an `IdentityFile` directive in ~/.ssh/config, which
//     legitimately points keys at non-default locations.
//
// The whole key file is the secret. Read-only; deduplicated by absolute path.
type sshScanner struct{}

func (s *sshScanner) Name() string { return "ssh" }

func (s *sshScanner) dir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ssh")
}

func (s *sshScanner) Available() bool {
	fi, err := os.Stat(s.dir())
	return err == nil && fi.IsDir()
}

// nonKeyNames are files that live in ~/.ssh but are never private keys; skipping
// them by name avoids reading large/irrelevant files (the content gate would also
// reject them, this is just cheaper and clearer).
var nonKeyNames = map[string]bool{
	"known_hosts":     true,
	"known_hosts.old": true,
	"authorized_keys": true,
	"config":          true,
	"environment":     true,
	"rc":              true,
}

func (s *sshScanner) Scan(ctx context.Context, v *vault.Vault) ([]Credential, error) {
	seen := map[string]bool{}
	var creds []Credential

	add := func(p string) {
		abs, err := filepath.Abs(p)
		if err != nil || seen[abs] {
			return
		}
		seen[abs] = true
		if c, ok := s.keyCred(abs, v); ok {
			creds = append(creds, c)
		}
	}

	// 1. Every regular file directly in ~/.ssh, filtered by name then content.
	if entries, err := os.ReadDir(s.dir()); err == nil {
		for _, e := range entries {
			name := e.Name()
			if !e.Type().IsRegular() {
				continue
			}
			if strings.HasSuffix(name, ".pub") || nonKeyNames[name] {
				continue
			}
			add(filepath.Join(s.dir(), name))
		}
	}

	// 2. Keys referenced from ~/.ssh/config (often outside ~/.ssh).
	for _, p := range s.identityFiles() {
		add(p)
	}

	return creds, nil
}

// keyCred reads p and, if it is a private key file, returns a Credential for it.
func (s *sshScanner) keyCred(p string, v *vault.Vault) (Credential, bool) {
	b, err := os.ReadFile(p) // read-only
	if err != nil {
		return Credential{}, false
	}
	if !bytes.Contains(b, []byte("PRIVATE KEY")) {
		return Credential{}, false // not a private key file
	}
	fi, _ := os.Stat(p)
	// Best-effort: PEM-encrypted keys carry an explicit marker. (OpenSSH-format
	// encryption isn't detectable without parsing the body, so this can
	// under-report; it never claims a plaintext key is encrypted.)
	encrypted := bytes.Contains(b, []byte("ENCRYPTED"))
	c := Credential{
		Source:   s.Name(),
		Kind:     KindPrivateKey,
		Identity: filepath.Base(p),
		Location: p,
		Secret:   v.Store(b),
		Meta:     map[string]string{"encrypted": strconv.FormatBool(encrypted)},
	}
	if fi != nil {
		c.Modified = fi.ModTime()
	}
	return c, true
}

// identityFiles parses ~/.ssh/config and returns the expanded paths of every
// IdentityFile directive. Tilde and $HOME are expanded; relative paths resolve
// against ~/.ssh (the ssh client's own behavior).
func (s *sshScanner) identityFiles() []string {
	f, err := os.Open(filepath.Join(s.dir(), "config"))
	if err != nil {
		return nil
	}
	defer f.Close()

	home, _ := os.UserHomeDir()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// "IdentityFile <path>" — keyword is case-insensitive, may use '=' .
		fields := strings.FieldsFunc(line, func(r rune) bool {
			return r == ' ' || r == '\t' || r == '='
		})
		if len(fields) < 2 || !strings.EqualFold(fields[0], "IdentityFile") {
			continue
		}
		p := strings.Trim(fields[1], `"`)
		switch {
		case strings.HasPrefix(p, "~/"):
			p = filepath.Join(home, p[2:])
		case strings.HasPrefix(p, "$HOME/"):
			p = filepath.Join(home, p[len("$HOME/"):])
		case !filepath.IsAbs(p):
			p = filepath.Join(s.dir(), p)
		}
		out = append(out, p)
	}
	return out
}
