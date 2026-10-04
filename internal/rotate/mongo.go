package rotate

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// Mongo rotates a MongoDB user's password in place, the same in-place pattern as
// Postgres/MySQL/Redis. The credential's secret is a mongodb URI
// ("mongodb://user:pw@host:port/db?authSource=admin"); rotation mints a new password
// and runs, over the OLD (authenticated) connection:
//
//	db.getSiblingDB(<authSource>).changeUserPassword(<user>, <newpw>)
//
// changeUserPassword is itself the cutover — the old password stops authenticating new
// connections immediately — so RevokeOld is a no-op and the §3 sealed backup is the
// recovery path (see docs/ROTATION.md §17).
//
// SECURITY (Hard Rule #3): NO secret ever reaches argv. The connection URI passed to
// mongosh on the command line carries the host/db ONLY — never credentials. The script
// fed on stdin authenticates with the OLD password (db.auth) and sets the NEW one; both
// passwords live only in that stdin script (and the vault). The new password is hex
// ([0-9a-f]) so it cannot break out of the JS string literal. Captured output is
// scrubbed of both passwords before any error surfaces.
type Mongo struct {
	Bin string // mongosh binary; defaults to "mongosh"
}

// init registers the driver. Registration only makes it available; changing a
// credential still requires `rotate --execute` AND INCREDIGO_ALLOW_EXECUTE=1.
func init() { Register(&Mongo{}) }

// Name identifies the driver in plans and audit records.
func (m *Mongo) Name() string { return "mongo" }

// Detect claims credentials a mongo scanner/seed emitted (Source == "mongo").
func (m *Mongo) Detect(c discover.Credential) bool { return c.Source == "mongo" }

func (m *Mongo) bin() string {
	if m.Bin != "" {
		return m.Bin
	}
	return "mongosh"
}

// authSource returns the DB to authenticate against / change the password in. Mongo
// stores users in authSource (default "admin" unless the URI overrides it).
func authSourceOf(u *url.URL) string {
	if a := u.Query().Get("authSource"); a != "" {
		return a
	}
	return "admin"
}

// Rotate mints a new password, applies it via changeUserPassword over the existing
// (old) connection, and returns a vault handle to the rebuilt URI.
func (m *Mongo) Rotate(ctx context.Context, c discover.Credential, v *vault.Vault) (*vault.Handle, error) {
	u, err := openMongoURI(v, c.Secret)
	if err != nil {
		return nil, err
	}
	user := u.User.Username()
	if user == "" {
		return nil, fmt.Errorf("mongo: uri has no user")
	}
	oldPw, _ := u.User.Password()

	newPw, err := genHex(24)
	if err != nil {
		return nil, err
	}
	as := authSourceOf(u)
	// auth with the OLD password, then change to the NEW one — all on stdin.
	script := fmt.Sprintf(
		"db.getSiblingDB(%q).auth(%q,%q); db.getSiblingDB(%q).changeUserPassword(%q,%q); print('ROTATED');",
		as, user, oldPw, as, user, newPw)
	out, err := m.mongosh(ctx, u, script, oldPw, newPw)
	if err != nil {
		return nil, fmt.Errorf("mongo: changeUserPassword: %w", err)
	}
	if !strings.Contains(out, "ROTATED") {
		return nil, fmt.Errorf("mongo: changeUserPassword: unexpected result")
	}

	nu := *u
	nu.User = url.UserPassword(user, newPw)
	return v.Store([]byte(nu.String())), nil
}

// Verify proves the freshly minted URI authenticates by db.auth + ping with the new
// password.
func (m *Mongo) Verify(ctx context.Context, newSecret *vault.Handle, v *vault.Vault) error {
	u, err := openMongoURI(v, newSecret)
	if err != nil {
		return err
	}
	user := u.User.Username()
	pw, _ := u.User.Password()
	as := authSourceOf(u)
	script := fmt.Sprintf(
		"var ok = db.getSiblingDB(%q).auth(%q,%q); if (ok) { print('AUTH-OK'); } else { print('AUTH-FAIL'); }",
		as, user, pw)
	out, err := m.mongosh(ctx, u, script, pw, "")
	if err != nil {
		return fmt.Errorf("mongo verify: %w", err)
	}
	if !strings.Contains(out, "AUTH-OK") {
		return fmt.Errorf("mongo verify: new password did not authenticate")
	}
	return nil
}

// RevokeOld is a no-op for an in-place engine: changeUserPassword in Rotate already
// invalidated the previous password. Defined to satisfy the safety-spine ordering.
func (m *Mongo) RevokeOld(ctx context.Context, c discover.Credential, v *vault.Vault) error {
	return nil
}

// mongosh runs one JS script against the URI's host/port (credentials stripped from
// the URI before it reaches argv). redactA/redactB, if non-empty, are scrubbed from
// captured output before it can reach an error string.
func (m *Mongo) mongosh(ctx context.Context, u *url.URL, script, redactA, redactB string) (string, error) {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "27017"
	}
	// Credential-free connection target: host:port/db only.
	target := &url.URL{Scheme: "mongodb", Host: host + ":" + port, Path: u.Path}
	cmd := exec.CommandContext(ctx, m.bin(), "--quiet", "--norc", target.String())
	cmd.Env = os.Environ()
	cmd.Stdin = strings.NewReader(script + "\n")
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	so, se := out.String(), errb.String()
	for _, r := range []string{redactA, redactB} {
		if r != "" {
			so = strings.ReplaceAll(so, r, "***")
			se = strings.ReplaceAll(se, r, "***")
		}
	}
	if err != nil {
		return so, fmt.Errorf("%v: %s", err, strings.TrimSpace(se+" "+so))
	}
	return so, nil
}

// openMongoURI reads a mongodb URI secret from the vault and parses it, accepting the
// mongodb:// and mongodb+srv:// schemes. The URI string is transient and never persisted.
func openMongoURI(v *vault.Vault, h *vault.Handle) (*url.URL, error) {
	buf, err := v.Open(h)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(strings.TrimSpace(string(buf.Bytes())))
	if err != nil {
		return nil, fmt.Errorf("mongo: parse uri: %w", err)
	}
	if u.Scheme != "mongodb" && u.Scheme != "mongodb+srv" {
		return nil, fmt.Errorf("mongo: unexpected uri scheme %q", u.Scheme)
	}
	if u.User == nil {
		return nil, fmt.Errorf("mongo: uri has no user:password")
	}
	return u, nil
}
