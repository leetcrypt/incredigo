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

// writeFakeMysql writes a stub `mysql` that emulates password auth against a state
// file holding the account's CURRENT password. ALTER USER updates the state (only if
// MYSQL_PWD matched the current password); SELECT 1 succeeds only when MYSQL_PWD
// matches. This lets a test prove a real cutover: after Rotate the OLD password must
// stop authenticating.
func writeFakeMysql(t *testing.T, statePath string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "mysql")
	script := `#!/usr/bin/env bash
set -euo pipefail
sql="$(cat)"
cur="$(cat "` + statePath + `" 2>/dev/null || true)"
case "$sql" in
  *"ALTER USER"*)
    if [ "${MYSQL_PWD:-}" != "$cur" ]; then echo "ERROR 1045 (28000): Access denied" >&2; exit 1; fi
    np="$(printf '%s' "$sql" | sed -E "s/.*IDENTIFIED BY '([^']*)'.*/\1/")"
    printf '%s' "$np" > "` + statePath + `"
    exit 0 ;;
  *"SELECT 1"*)
    if [ "${MYSQL_PWD:-}" != "$cur" ]; then echo "ERROR 1045 (28000): Access denied" >&2; exit 1; fi
    echo "1"; exit 0 ;;
  *) echo "unrecognized" >&2; exit 1 ;;
esac
`
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMySQLDetect(t *testing.T) {
	m := &MySQL{}
	if !m.Detect(discover.Credential{Source: "mysql"}) {
		t.Error("should detect Source=mysql")
	}
	if m.Detect(discover.Credential{Source: "postgres"}) {
		t.Error("should not detect Source=postgres")
	}
}

func TestMySQLRotateRealCutover(t *testing.T) {
	state := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(state, []byte("oldpw"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MYSQL_PWD", "") // ensure the driver, not the env, supplies it
	m := &MySQL{Bin: writeFakeMysql(t, state)}

	v := vault.New()
	defer v.Purge()
	oldDSN := "mysql://labapp:oldpw@127.0.0.1:3306/labdb"
	cred := discover.Credential{Source: "mysql", Identity: "labapp@labdb", Secret: v.Store([]byte(oldDSN))}
	ctx := context.Background()

	newH, err := m.Rotate(ctx, cred, v)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if cur, _ := os.ReadFile(state); string(cur) == "oldpw" {
		t.Fatal("password not changed by ALTER USER")
	}

	if err := m.Verify(ctx, newH, v); err != nil {
		t.Errorf("Verify(new) should pass: %v", err)
	}
	if err := m.Verify(ctx, cred.Secret, v); err == nil {
		t.Error("Verify(old) must fail after rotation — old password should be revoked")
	} else if strings.Contains(err.Error(), "oldpw") {
		t.Error("error leaked the old password")
	}

	if err := m.RevokeOld(ctx, cred, v); err != nil {
		t.Errorf("RevokeOld (no-op) returned: %v", err)
	}
}

func TestMySQLRejectsNonMySQLDSN(t *testing.T) {
	m := &MySQL{Bin: "/bin/false"}
	v := vault.New()
	defer v.Purge()
	cred := discover.Credential{Source: "mysql", Secret: v.Store([]byte("postgres://u:p@h/db"))}
	if _, err := m.Rotate(context.Background(), cred, v); err == nil {
		t.Error("Rotate should reject a non-mysql scheme")
	}
}
