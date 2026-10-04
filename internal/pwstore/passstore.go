package pwstore

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"incredigo/internal/vault"
)

// PassStore adapts the Unix password-store `pass` and its drop-in `gopass` as a
// read+update login source for the passwords engine. (This is distinct from
// sink.Gopass, which is incredigo's OWN backing store for imported creds — here the
// pass/gopass store is the *user's* manager being rotated.)
//
// One entry holds one secret. The de-facto layout (passff / browserpass) is line 1 =
// the password, followed by `key: value` metadata lines (login/username/user/email,
// url). Reading is `<bin> show <entry>`; updating rewrites the entry with
// `<bin> insert -m -f <entry>`, piping the full body on STDIN so neither the new
// password nor the metadata ever reaches argv — the off-argv write path, on par with
// Bitwarden/KeePassXC.
//
// Entry enumeration is the one place the two backends differ: gopass exposes a flat
// list (`gopass ls --flat`); `pass` has no flat flag, so we walk the password-store
// directory for *.gpg. The Flavor field selects which.
type PassStore struct {
	Bin    string // default == Flavor ("pass" or "gopass"); injectable for tests
	Flavor string // "pass" or "gopass"
	Store  string // store dir (pass walk); default $PASSWORD_STORE_DIR or ~/.password-store
	Prefix string // optional subtree to scope (e.g. "logins/")
}

func init() {
	Register(&PassStore{Flavor: "pass"})
	Register(&PassStore{Flavor: "gopass"})
}

func (p *PassStore) Name() string { return p.Flavor }

func (p *PassStore) bin() string {
	if p.Bin != "" {
		return p.Bin
	}
	return p.Flavor
}

// Available reports whether the backend CLI is resolvable.
func (p *PassStore) Available() bool {
	if p.Bin != "" {
		return true // injected (tests)
	}
	_, err := exec.LookPath(p.bin())
	return err == nil
}

// storeDir resolves the on-disk password-store root for the `pass` flavor.
func (p *PassStore) storeDir() string {
	if p.Store != "" {
		return p.Store
	}
	if d := os.Getenv("PASSWORD_STORE_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".password-store")
}

// listEntries returns the entry paths (without any .gpg suffix), scoped to Prefix.
func (p *PassStore) listEntries(ctx context.Context) ([]string, error) {
	var raw []string
	if p.Flavor == "gopass" {
		out, err := exec.CommandContext(ctx, p.bin(), "ls", "--flat").Output()
		if err != nil {
			return nil, fmt.Errorf("gopass: ls: %w", err)
		}
		for _, ln := range strings.Split(string(out), "\n") {
			if s := strings.TrimSpace(ln); s != "" {
				raw = append(raw, s)
			}
		}
	} else {
		root := p.storeDir()
		err := filepath.WalkDir(root, func(pth string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(pth, ".gpg") {
				return nil
			}
			rel, err := filepath.Rel(root, pth)
			if err != nil {
				return err
			}
			raw = append(raw, strings.TrimSuffix(filepath.ToSlash(rel), ".gpg"))
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("pass: walk %q: %w", root, err)
		}
	}
	prefix := strings.Trim(p.Prefix, "/")
	var out []string
	for _, e := range raw {
		if prefix != "" && !strings.HasPrefix(strings.Trim(e, "/"), prefix+"/") && strings.Trim(e, "/") != prefix {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// showRaw returns one entry's full decrypted body bytes (`<bin> show <entry>`).
func (p *PassStore) showRaw(ctx context.Context, entry string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, p.bin(), "show", entry)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: show %q: %v: %s", p.Flavor, entry, err, strings.TrimSpace(stderr.String()))
	}
	return out.Bytes(), nil
}

// Export reads every entry into v, mapping the first line to the password handle and
// the `key: value` body lines to username/url metadata.
func (p *PassStore) Export(ctx context.Context, v *vault.Vault) ([]Account, error) {
	entries, err := p.listEntries(ctx)
	if err != nil {
		return nil, err
	}
	var out []Account
	for _, entry := range entries {
		body, err := p.showRaw(ctx, entry)
		if err != nil {
			return nil, err
		}
		a := parsePassEntry(v, entry, body)
		zero(body) // wipe the transient decrypted capture
		out = append(out, a)
	}
	return out, nil
}

// parsePassEntry turns "<password>\n<key: value>…" into an Account. The password lands
// in the vault as a handle; only non-secret metadata is read into the struct.
func parsePassEntry(v *vault.Vault, entry string, body []byte) Account {
	text := strings.ReplaceAll(string(body), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	pw := ""
	if len(lines) > 0 {
		pw = lines[0]
	}
	a := Account{ID: entry, Meta: map[string]string{}}
	for _, ln := range lines[1:] {
		k, val, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(k))
		val = strings.TrimSpace(val)
		switch key {
		case "login", "username", "user", "email":
			if a.Username == "" {
				a.Username = val
			}
		case "url", "site", "website":
			if a.URL == "" {
				a.URL = val
			}
		}
	}
	a.Meta["name"] = path.Base(entry)
	if dir := path.Dir(entry); dir != "." && dir != "/" {
		a.Meta["group"] = dir
	}
	if a.URL != "" {
		a.Site = hostFromURL(a.URL)
	}
	if a.Site == "" {
		// Entry path often IS the host (e.g. "github.com/alice"); use its head.
		a.Site = hostFromURL(strings.SplitN(entry, "/", 2)[0])
	}
	a.Secret = v.Store([]byte(pw))
	wipeStr(&pw)
	return a
}

// UpdatePassword rewrites one entry's password while preserving its metadata body.
// It re-reads the current body, swaps the first line for the new password, and pipes
// the result to `<bin> insert -m -f <entry>` on STDIN (nothing secret on argv).
func (p *PassStore) UpdatePassword(ctx context.Context, v *vault.Vault, acct Account, newPassword *vault.Handle) error {
	if acct.ID == "" {
		return fmt.Errorf("%s: account has no entry path — cannot update in place", p.Flavor)
	}
	body, err := p.showRaw(ctx, acct.ID)
	if err != nil {
		return err
	}
	defer zero(body)
	pwBuf, err := v.Open(newPassword)
	if err != nil {
		return err
	}
	var stdin bytes.Buffer
	stdin.Write(pwBuf.Bytes())
	if i := bytes.IndexByte(body, '\n'); i >= 0 {
		stdin.Write(body[i:]) // keep the newline + every metadata line after line 1
	} else {
		stdin.WriteByte('\n')
	}
	cmd := exec.CommandContext(ctx, p.bin(), "insert", "-m", "-f", acct.ID)
	cmd.Stdin = &stdin
	out, err := cmd.CombinedOutput()
	stdin.Reset() // wipe the transient buffer holding the new password
	if err != nil {
		return fmt.Errorf("%s: insert %q: %v: %s", p.Flavor, acct.ID, err, bytes.TrimSpace(out))
	}
	return nil
}

// zero overwrites a byte slice in place (best-effort wipe of transient plaintext).
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
