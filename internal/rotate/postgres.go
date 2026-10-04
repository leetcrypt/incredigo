package rotate

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// Postgres rotates a PostgreSQL role password in place. The credential's secret
// is the full libpq DSN ("postgres://user:pw@host:port/db"); rotation mints a new
// password, runs ALTER USER over the OLD connection, and stores a rebuilt DSN.
//
// In-place engines have no separate "old credential" to retire: the ALTER itself
// invalidates the old password, so RevokeOld is a no-op and Verify runs
// immediately after the change (the §3 sealed backup is the recovery path). See
// docs/ROTATION.md §17.
//
// SECURITY: rotation is the one boundary where a secret must leave the vault to
// authenticate — here it goes to psql via the PGPASSWORD *environment* variable
// (never disk, never argv, never logged), and the SQL is fed on stdin so the new
// password never appears in the process argument list (visible via ps/proc). The
// transient DSN/password strings below are the unavoidable cost of talking to the
// driver; they are not written anywhere and stderr is redacted before surfacing.
type Postgres struct {
	Bin string // psql binary; defaults to "psql"
}

// init registers the postgres driver (idiomatic database/sql-style self-register).
// Registration only makes the driver *available*; actually changing a credential
// still requires `rotate --execute` AND INCREDIGO_ALLOW_EXECUTE=1 (see main.go).
func init() { Register(&Postgres{}) }

// Name identifies the driver in plans and audit records.
func (p *Postgres) Name() string { return "postgres" }

// Detect claims credentials a postgres scanner/seed emitted (Source == "postgres").
func (p *Postgres) Detect(c discover.Credential) bool { return c.Source == "postgres" }

func (p *Postgres) bin() string {
	if p.Bin != "" {
		return p.Bin
	}
	return "psql"
}

// Rotate mints a new role password, applies it via ALTER USER over the existing
// (old) connection, and returns a vault handle to the rebuilt DSN. It does not
// revoke anything — the in-place ALTER is itself the cutover.
func (p *Postgres) Rotate(ctx context.Context, c discover.Credential, v *vault.Vault) (*vault.Handle, error) {
	u, err := openDSN(v, c.Secret)
	if err != nil {
		return nil, err
	}
	user := u.User.Username()
	if user == "" {
		return nil, errors.New("postgres: dsn has no user")
	}
	oldPw, _ := u.User.Password()

	newPw, err := genHex(24)
	if err != nil {
		return nil, err
	}
	// New password is hex ([0-9a-f]) so the single-quoted literal cannot break
	// out of the statement; the identifier is double-quote escaped regardless.
	sql := fmt.Sprintf("ALTER USER %s WITH PASSWORD '%s';", quoteIdent(user), newPw)
	if _, err := p.psql(ctx, u, oldPw, sql, newPw); err != nil {
		return nil, fmt.Errorf("postgres: ALTER USER: %w", err)
	}

	nu := *u
	nu.User = url.UserPassword(user, newPw)
	return v.Store([]byte(nu.String())), nil
}

// Verify proves the freshly minted DSN authenticates by issuing SELECT 1 with the
// new password.
func (p *Postgres) Verify(ctx context.Context, newSecret *vault.Handle, v *vault.Vault) error {
	u, err := openDSN(v, newSecret)
	if err != nil {
		return err
	}
	pw, _ := u.User.Password()
	out, err := p.psql(ctx, u, pw, "SELECT 1;", pw)
	if err != nil {
		return fmt.Errorf("postgres verify: %w", err)
	}
	if !strings.Contains(out, "1") {
		return fmt.Errorf("postgres verify: unexpected result")
	}
	return nil
}

// RevokeOld is a no-op for an in-place engine: the ALTER in Rotate already
// invalidated the previous password. Defined to satisfy the safety-spine ordering.
func (p *Postgres) RevokeOld(ctx context.Context, c discover.Credential, v *vault.Vault) error {
	return nil
}

// psql runs one SQL statement against the DSN's host/db as the DSN's user,
// authenticating with password via PGPASSWORD and feeding sql on stdin (keeping
// any secret out of argv). redact, if non-empty, is scrubbed from captured output
// before it can reach an error string.
func (p *Postgres) psql(ctx context.Context, u *url.URL, password, sql, redact string) (string, error) {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "5432"
	}
	db := strings.TrimPrefix(u.Path, "/")
	if db == "" {
		db = u.User.Username()
	}
	cmd := exec.CommandContext(ctx, p.bin(),
		"-v", "ON_ERROR_STOP=1", "-X", "-w",
		"-h", host, "-p", port, "-U", u.User.Username(), "-d", db,
		"-tA")
	cmd.Env = append(os.Environ(), "PGPASSWORD="+password)
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

// openDSN reads a DSN secret from the vault and parses it, rejecting non-postgres
// schemes. The DSN string is transient and never persisted.
func openDSN(v *vault.Vault, h *vault.Handle) (*url.URL, error) {
	buf, err := v.Open(h)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(strings.TrimSpace(string(buf.Bytes())))
	if err != nil {
		return nil, fmt.Errorf("postgres: parse dsn: %w", err)
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return nil, fmt.Errorf("postgres: unexpected dsn scheme %q", u.Scheme)
	}
	return u, nil
}

func genHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	s := hex.EncodeToString(b)
	for i := range b {
		b[i] = 0
	}
	return s, nil
}

func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}
