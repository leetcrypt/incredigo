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

// Redis rotates a Redis instance's password in place, the same in-place pattern as
// Postgres/MySQL. The credential's secret is a redis URL
// ("redis://:pw@host:port" or "redis://user:pw@host:port/db"); rotation mints a new
// password and runs
//
//	CONFIG SET requirepass <newpw>
//
// over the OLD (authenticated) connection. CONFIG SET is itself the cutover — the
// old password stops authenticating new connections immediately — so RevokeOld is a
// no-op and the §3 sealed backup is the recovery path (see docs/ROTATION.md §17).
//
// SECURITY: the OLD password reaches redis-cli only via the REDISCLI_AUTH
// *environment* variable (never argv, never disk). The command — which carries the
// NEW password — is fed on stdin so the new password never appears in the process
// argument list. The new password is hex ([0-9a-f]) so it needs no quoting and
// cannot inject extra tokens. Captured output is scrubbed of the new password
// before any error surfaces.
//
// NOTE: this rotates the legacy single `requirepass` secret (the default-user
// password), which is the form vibe coders actually leak in REDIS_URL. ACL-user
// rotation (`ACL SETUSER`) is a separate future surface.
type Redis struct {
	Bin string // redis-cli binary; defaults to "redis-cli"
}

// init registers the driver. Registration only makes it available; changing a
// credential still requires `rotate --execute` AND INCREDIGO_ALLOW_EXECUTE=1.
func init() { Register(&Redis{}) }

// Name identifies the driver in plans and audit records.
func (r *Redis) Name() string { return "redis" }

// Detect claims credentials a redis scanner/seed emitted (Source == "redis").
func (r *Redis) Detect(c discover.Credential) bool { return c.Source == "redis" }

func (r *Redis) bin() string {
	if r.Bin != "" {
		return r.Bin
	}
	return "redis-cli"
}

// Rotate mints a new password, applies it via CONFIG SET requirepass over the
// existing (old) connection, and returns a vault handle to the rebuilt URL.
func (r *Redis) Rotate(ctx context.Context, c discover.Credential, v *vault.Vault) (*vault.Handle, error) {
	u, err := openRedisURL(v, c.Secret)
	if err != nil {
		return nil, err
	}
	oldPw, _ := u.User.Password()

	newPw, err := genHex(24)
	if err != nil {
		return nil, err
	}
	if _, err := r.redis(ctx, u, oldPw, "CONFIG SET requirepass "+newPw, newPw); err != nil {
		return nil, fmt.Errorf("redis: CONFIG SET requirepass: %w", err)
	}

	nu := *u
	nu.User = url.UserPassword(u.User.Username(), newPw)
	return v.Store([]byte(nu.String())), nil
}

// Verify proves the freshly minted URL authenticates by issuing PING with the new
// password.
func (r *Redis) Verify(ctx context.Context, newSecret *vault.Handle, v *vault.Vault) error {
	u, err := openRedisURL(v, newSecret)
	if err != nil {
		return err
	}
	pw, _ := u.User.Password()
	out, err := r.redis(ctx, u, pw, "PING", pw)
	if err != nil {
		return fmt.Errorf("redis verify: %w", err)
	}
	if !strings.Contains(out, "PONG") {
		return fmt.Errorf("redis verify: unexpected result")
	}
	return nil
}

// RevokeOld is a no-op for an in-place engine: the CONFIG SET in Rotate already
// invalidated the previous password. Defined to satisfy the safety-spine ordering.
func (r *Redis) RevokeOld(ctx context.Context, c discover.Credential, v *vault.Vault) error {
	return nil
}

// redis runs one command against the URL's host/port, authenticating via
// REDISCLI_AUTH and feeding the command on stdin (keeping any secret out of argv).
// redact, if non-empty, is scrubbed from captured output before it can reach an
// error string.
func (r *Redis) redis(ctx context.Context, u *url.URL, password, command, redact string) (string, error) {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "6379"
	}
	args := []string{"--no-raw", "-h", host, "-p", port}
	if db := strings.TrimPrefix(u.Path, "/"); db != "" {
		args = append(args, "-n", db)
	}
	if user := u.User.Username(); user != "" {
		args = append(args, "--user", user)
	}
	cmd := exec.CommandContext(ctx, r.bin(), args...)
	cmd.Env = os.Environ()
	if password != "" {
		cmd.Env = append(cmd.Env, "REDISCLI_AUTH="+password)
	}
	cmd.Stdin = strings.NewReader(command + "\n")
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	so, se := out.String(), errb.String()
	if redact != "" {
		so = strings.ReplaceAll(so, redact, "***")
		se = strings.ReplaceAll(se, redact, "***")
	}
	// redis-cli prints server error replies as a "(error) ..." line on stdout and
	// often still exits 0 (auth/command failures included), so surface stdout that
	// looks like an error even when the process exits clean.
	if err == nil && strings.HasPrefix(strings.TrimSpace(so), "(error)") {
		return so, fmt.Errorf("redis error: %s", strings.TrimSpace(so))
	}
	if err != nil {
		return so, fmt.Errorf("%v: %s", err, strings.TrimSpace(se+" "+so))
	}
	return so, nil
}

// openRedisURL reads a redis URL secret from the vault and parses it, accepting the
// redis:// and rediss:// schemes. The URL string is transient and never persisted.
func openRedisURL(v *vault.Vault, h *vault.Handle) (*url.URL, error) {
	buf, err := v.Open(h)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(strings.TrimSpace(string(buf.Bytes())))
	if err != nil {
		return nil, fmt.Errorf("redis: parse url: %w", err)
	}
	if u.Scheme != "redis" && u.Scheme != "rediss" {
		return nil, fmt.Errorf("redis: unexpected url scheme %q", u.Scheme)
	}
	return u, nil
}
