package pwstore

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"incredigo/internal/vault"
)

// KeePassXC adapts the official `keepassxc-cli`. Both the database key and any new
// entry password are fed over STDIN (never argv): Export pipes the DB passphrase to
// `keepassxc-cli export -f csv <db>`; UpdatePassword pipes "<dbpass>\n<newpass>\n" to
// `keepassxc-cli edit -p <db> <entry>` (the -p/--password-prompt flag makes the CLI
// read the new entry password from stdin after the unlock prompt). This is the
// fully-off-argv write path, on par with Bitwarden.
//
// The KeePass database is a local file (DBPath); its passphrase lives in the RAM
// vault as DBKey. Entry identity is the KeePass entry path "/Group/Title", carried
// in Account.ID.
type KeePassXC struct {
	Bin    string        // default "keepassxc-cli"; injectable for tests
	DBPath string        // path to the .kdbx file
	DBKey  *vault.Handle // database passphrase, in the RAM vault
}

func init() { Register(&KeePassXC{}) }

func (k *KeePassXC) Name() string { return "keepassxc" }

func (k *KeePassXC) bin() string {
	if k.Bin != "" {
		return k.Bin
	}
	return "keepassxc-cli"
}

// Available reports whether a database path was configured and the CLI is resolvable.
func (k *KeePassXC) Available() bool {
	if k.DBPath == "" {
		return false
	}
	if _, err := os.Stat(k.DBPath); err != nil {
		return false
	}
	if k.Bin != "" {
		return true // injected (tests)
	}
	_, err := exec.LookPath("keepassxc-cli")
	return err == nil
}

// dbPass returns the database passphrase bytes from the vault (or empty for an
// unkeyed test DB). Caller uses it transiently on stdin only.
func (k *KeePassXC) dbPass(v *vault.Vault) (string, error) {
	if k.DBKey == nil {
		return "", nil
	}
	buf, err := v.Open(k.DBKey)
	if err != nil {
		return "", err
	}
	return string(buf.Bytes()), nil
}

// Export runs `keepassxc-cli export -f csv <db>` (DB passphrase piped on stdin) and
// maps every entry into an Account, deriving the entry path from Group + Title.
func (k *KeePassXC) Export(ctx context.Context, v *vault.Vault) ([]Account, error) {
	if k.DBPath == "" {
		return nil, fmt.Errorf("keepassxc: no database path set")
	}
	pass, err := k.dbPass(v)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, k.bin(), "export", "-f", "csv", k.DBPath)
	cmd.Stdin = strings.NewReader(pass + "\n")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("keepassxc: export: %w", err)
	}
	accts, err := parseLoginCSV(v, out)
	if err != nil {
		return nil, err
	}
	for i := range accts {
		accts[i].ID = kpEntryPath(accts[i].Meta["group"], accts[i].Meta["name"])
	}
	return accts, nil
}

// kpEntryPath builds the entry path keepassxc-cli edit/show expect. KeePassXC's CSV
// "Group" column is the FULL group path INCLUDING the root group name (e.g. the
// default DB names its root group "Passwords", so a top-level entry exports with
// Group="Passwords"). The CLI, however, addresses entries RELATIVE to the root —
// the root group name is omitted from the path: a root entry is "/GitHub", and a
// nested entry "Passwords/Web/GitHub" is addressed "/Web/GitHub". So we drop the
// first (root) segment of the exported group path. Verified against real
// keepassxc-cli 2.7.6 in the sandbox VM (the buggy "/Root/GitHub" form 404s).
func kpEntryPath(group, title string) string {
	group = strings.Trim(group, "/")
	if group == "" {
		return "/" + title
	}
	// Strip the leading root-group segment; keep any remaining nested subgroups.
	if _, rest, ok := strings.Cut(group, "/"); ok {
		return "/" + rest + "/" + title
	}
	return "/" + title
}

// UpdatePassword changes one entry's password via `keepassxc-cli edit -p <db> <entry>`.
// stdin carries two lines: the DB passphrase (unlock) then the new entry password
// (-p prompt). Nothing sensitive reaches argv.
func (k *KeePassXC) UpdatePassword(ctx context.Context, v *vault.Vault, acct Account, newPassword *vault.Handle) error {
	if acct.ID == "" {
		return fmt.Errorf("keepassxc: account has no entry path — cannot update in place")
	}
	pass, err := k.dbPass(v)
	if err != nil {
		return err
	}
	pwBuf, err := v.Open(newPassword)
	if err != nil {
		return err
	}
	var stdin bytes.Buffer
	stdin.WriteString(pass)
	stdin.WriteByte('\n')
	stdin.Write(pwBuf.Bytes())
	stdin.WriteByte('\n')

	cmd := exec.CommandContext(ctx, k.bin(), "edit", "-p", k.DBPath, acct.ID)
	cmd.Stdin = &stdin
	out, err := cmd.CombinedOutput()
	// Wipe the transient stdin buffer holding both secrets.
	stdin.Reset()
	if err != nil {
		return fmt.Errorf("keepassxc: edit: %w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}
