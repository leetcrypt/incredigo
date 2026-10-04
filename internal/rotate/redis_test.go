package rotate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// writeFakeRedisCli writes a stub `redis-cli` that emulates AUTH against a state
// file holding the instance's CURRENT requirepass. CONFIG SET requirepass updates
// the state (only if REDISCLI_AUTH matched the current password); PING succeeds only
// when REDISCLI_AUTH matches. This lets a test prove a real cutover: after Rotate
// the OLD password must stop authenticating. It models redis-cli's behaviour of
// printing "(error) ..." replies on stdout while still exiting 0.
func writeFakeRedisCli(t *testing.T, statePath string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "redis-cli")
	script := `#!/usr/bin/env bash
set -uo pipefail
cmd="$(cat)"
cur="$(cat "` + statePath + `" 2>/dev/null || true)"
# If a password is set on the instance, an authless or wrong-password client fails.
if [ -n "$cur" ] && [ "${REDISCLI_AUTH:-}" != "$cur" ]; then
  echo "(error) WRONGPASS invalid username-password pair"; exit 0
fi
case "$cmd" in
  "CONFIG SET requirepass "*)
    np="${cmd#CONFIG SET requirepass }"
    printf '%s' "$np" > "` + statePath + `"
    echo "OK"; exit 0 ;;
  "PING"*)
    echo "PONG"; exit 0 ;;
  *) echo "(error) ERR unknown command"; exit 0 ;;
esac
`
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRedisDetect(t *testing.T) {
	r := &Redis{}
	if !r.Detect(discover.Credential{Source: "redis"}) {
		t.Error("should detect Source=redis")
	}
	if r.Detect(discover.Credential{Source: "mysql"}) {
		t.Error("should not detect Source=mysql")
	}
}

func TestRedisRotateRealCutover(t *testing.T) {
	state := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(state, []byte("oldpw"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REDISCLI_AUTH", "") // ensure the driver, not the env, supplies it
	r := &Redis{Bin: writeFakeRedisCli(t, state)}

	v := vault.New()
	defer v.Purge()
	oldURL := "redis://:oldpw@127.0.0.1:6379"
	cred := discover.Credential{Source: "redis", Identity: "redis@127.0.0.1", Secret: v.Store([]byte(oldURL))}
	ctx := context.Background()

	newH, err := r.Rotate(ctx, cred, v)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if cur, _ := os.ReadFile(state); string(cur) == "oldpw" {
		t.Fatal("password not changed by CONFIG SET requirepass")
	}

	if err := r.Verify(ctx, newH, v); err != nil {
		t.Errorf("Verify(new) should pass: %v", err)
	}
	if err := r.Verify(ctx, cred.Secret, v); err == nil {
		t.Error("Verify(old) must fail after rotation — old password should be revoked")
	} else if strings.Contains(err.Error(), "oldpw") {
		t.Error("error leaked the old password")
	}

	if err := r.RevokeOld(ctx, cred, v); err != nil {
		t.Errorf("RevokeOld (no-op) returned: %v", err)
	}
}

func TestRedisRejectsNonRedisURL(t *testing.T) {
	r := &Redis{Bin: "/bin/false"}
	v := vault.New()
	defer v.Purge()
	cred := discover.Credential{Source: "redis", Secret: v.Store([]byte("postgres://u:p@h/db"))}
	if _, err := r.Rotate(context.Background(), cred, v); err == nil {
		t.Error("Rotate should reject a non-redis scheme")
	}
}
