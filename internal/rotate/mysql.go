package rotate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// MySQL rotates a MySQL/MariaDB account password in place, the same in-place DB
// pattern as Postgres. The credential's secret is the full DSN
// ("mysql://user:pw@host:port/db"); rotation mints a new password and runs
//
//	ALTER USER CURRENT_USER() IDENTIFIED BY '<newpw>'
//
// over the OLD connection. CURRENT_USER() targets the *currently authenticated*
// account, so the driver never needs to know the user's 'name'@'host' grant tuple,
// and it is the form accepted by BOTH MySQL and MariaDB (MariaDB rejects the
// MySQL-only USER() spelling in ALTER USER). The ALTER is
// itself the cutover (the old password stops working immediately), so RevokeOld is a
// no-op and the §3 sealed backup is the recovery path — identical reasoning to
// Postgres (see docs/ROTATION.md §17).
//
// SECURITY: the password reaches the mysql client only via the MYSQL_PWD
// *environment* variable (never argv, never disk), and the SQL — which contains the
// NEW password — is fed on stdin so it never appears in the process argument list.
// The new password is hex ([0-9a-f]) so the single-quoted SQL literal cannot break
// out. Captured output is scrubbed of the new password before any error surfaces.
type MySQL struct {
	Bin string // mysql client binary; defaults to "mysql"
}

// init registers the driver. Registration only makes it available; changing a
// credential still requires `rotate --execute` AND INCREDIGO_ALLOW_EXECUTE=1.
func init() { Register(&MySQL{}) }

// Name identifies the driver in plans and audit records.
func (m *MySQL) Name() string { return "mysql" }

// Detect claims credentials a mysql scanner/seed emitted (Source == "mysql").
func (m *MySQL) Detect(c discover.Credential) bool { return c.Source == "mysql" }

func (m *MySQL) bin() string {
	if m.Bin != "" {
		return m.Bin
	}
	return "mysql"
}

// Rotate mints a new password, applies it to the currently-authenticated account
// over the existing (old) connection, and returns a vault handle to the rebuilt DSN.
//
// It tries, in order, the statements a user can run to change *their own* password,
// because no single statement works unprivileged across both engines and versions:
//
//  1. ALTER USER CURRENT_USER() IDENTIFIED BY '…'  — MySQL 5.7/8.0 self-service (no
//     special privilege). MariaDB rejects this for a non-admin (it demands the global
//     CREATE USER privilege even for your own account), so we fall through.
//  2. SET PASSWORD = PASSWORD('…')                 — MariaDB self-service (no priv);
//     also MySQL 5.7. Removed in MySQL 8.0, so we fall through there.
//  3. SET PASSWORD = '…'                           — MySQL 8.0 / MariaDB ≥10.4.
//
// The first to succeed wins. This matters for the target persona: a vibe coder's DB
// user is usually scoped to one schema (GRANT ALL ON app.*) and CANNOT ALTER USER on
// MariaDB, but can always change its own password via SET PASSWORD.
func (m *MySQL) Rotate(ctx context.Context, c discover.Credential, v *vault.Vault) (*vault.Handle, error) {
	u, err := openMySQLDSN(v, c.Secret)
	if err != nil {
		return nil, err
	}
	if u.User.Username() == "" {
		return nil, errors.New("mysql: dsn has no user")
	}
	oldPw, _ := u.User.Password()

	newPw, err := genHex(24)
	if err != nil {
		return nil, err
	}
	// New password is hex ([0-9a-f]) so the single-quoted literals below cannot break
	// out of the statement.
	stmts := []string{
		fmt.Sprintf("ALTER USER CURRENT_USER() IDENTIFIED BY '%s';", newPw),
		fmt.Sprintf("SET PASSWORD = PASSWORD('%s');", newPw),
		fmt.Sprintf("SET PASSWORD = '%s';", newPw),
	}
	var lastErr error
	changed := false
	for _, sql := range stmts {
		if _, err := m.mysql(ctx, u, oldPw, sql, newPw); err == nil {
			changed = true
			break
		} else {
			lastErr = err
		}
	}
	if !changed {
		return nil, fmt.Errorf("mysql: change password: %w", lastErr)
	}

	nu := *u
	nu.User = url.UserPassword(u.User.Username(), newPw)
	return v.Store([]byte(nu.String())), nil
}

// Verify proves the freshly minted DSN authenticates by issuing SELECT 1 with the
// new password.
func (m *MySQL) Verify(ctx context.Context, newSecret *vault.Handle, v *vault.Vault) error {
	u, err := openMySQLDSN(v, newSecret)
	if err != nil {
		return err
	}
	pw, _ := u.User.Password()
	out, err := m.mysql(ctx, u, pw, "SELECT 1;", pw)
	if err != nil {
		return fmt.Errorf("mysql verify: %w", err)
	}
	if !strings.Contains(out, "1") {
		return fmt.Errorf("mysql verify: unexpected result")
	}
	return nil
}

// RevokeOld is a no-op for an in-place engine: the ALTER in Rotate already
// invalidated the previous password. Defined to satisfy the safety-spine ordering.
func (m *MySQL) RevokeOld(ctx context.Context, c discover.Credential, v *vault.Vault) error {
	return nil
}

// mysql runs one SQL statement against the DSN's host/db as the DSN's user,
// authenticating via MYSQL_PWD and feeding sql on stdin (keeping any secret out of
// argv). redact, if non-empty, is scrubbed from captured output before it can reach
// an error string.
func (m *MySQL) mysql(ctx context.Context, u *url.URL, password, sql, redact string) (string, error) {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "3306"
	}
	args := []string{
		"--batch", "--skip-column-names",
		"-h", host, "-P", port, "-u", u.User.Username(),
	}
	if db := strings.TrimPrefix(u.Path, "/"); db != "" {
		args = append(args, "-D", db)
	}
	cmd := exec.CommandContext(ctx, m.bin(), args...)
	cmd.Env = append(os.Environ(), "MYSQL_PWD="+password)
	cmd.Stdin = strings.NewReader(sql + "\n")
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	so, se := out.String(), errb.String()
	if redact != "" {
		so = strings.ReplaceAll(so, redact, "***")
		se = strings.ReplaceAll(se, redact, "***")
	}
	if err != nil {
		return so, fmt.Errorf("%v: %s", err, strings.TrimSpace(se))
	}
	return so, nil
}

// openMySQLDSN reads a DSN secret from the vault and parses it, accepting the
// mysql:// and mariadb:// schemes. The DSN string is transient and never persisted.
func openMySQLDSN(v *vault.Vault, h *vault.Handle) (*url.URL, error) {
	buf, err := v.Open(h)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(strings.TrimSpace(string(buf.Bytes())))
	if err != nil {
		return nil, fmt.Errorf("mysql: parse dsn: %w", err)
	}
	if u.Scheme != "mysql" && u.Scheme != "mariadb" {
		return nil, fmt.Errorf("mysql: unexpected dsn scheme %q", u.Scheme)
	}
	return u, nil
}
