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

// writeFakePsql writes a stub `psql` that emulates password auth against a state
// file holding the role's CURRENT password. ALTER updates the state (only if the
// caller authenticated with the current password); SELECT 1 succeeds only when
// PGPASSWORD matches the current password. This lets a test prove a real cutover:
// after Rotate the OLD password must stop authenticating.
func writeFakePsql(t *testing.T, statePath string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "psql")
	script := `#!/usr/bin/env bash
set -euo pipefail
sql="$(cat)"
cur="$(cat "` + statePath + `" 2>/dev/null || true)"
case "$sql" in
  *"ALTER USER"*|*"ALTER ROLE"*)
    if [ "${PGPASSWORD:-}" != "$cur" ]; then echo "FATAL: password authentication failed" >&2; exit 2; fi
    np="$(printf '%s' "$sql" | sed -E "s/.*PASSWORD '([^']*)'.*/\1/")"
    printf '%s' "$np" > "` + statePath + `"
    echo "ALTER ROLE"; exit 0 ;;
  *"SELECT 1"*)
    if [ "${PGPASSWORD:-}" != "$cur" ]; then echo "FATAL: password authentication failed" >&2; exit 2; fi
    echo "1"; exit 0 ;;
  *) echo "unrecognized" >&2; exit 1 ;;
esac
`
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPostgresDetect(t *testing.T) {
	pg := &Postgres{}
	if !pg.Detect(discover.Credential{Source: "postgres"}) {
		t.Error("should detect Source=postgres")
	}
	if pg.Detect(discover.Credential{Source: "env"}) {
		t.Error("should not detect Source=env")
	}
}

func TestPostgresRotateRealCutover(t *testing.T) {
	state := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(state, []byte("oldpw"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PGPASSWORD", "") // ensure the driver, not the env, supplies it
	pg := &Postgres{Bin: writeFakePsql(t, state)}

	v := vault.New()
	defer v.Purge()
	oldDSN := "postgres://labapp:oldpw@127.0.0.1:5432/labdb"
	cred := discover.Credential{Source: "postgres", Identity: "labapp@labdb", Secret: v.Store([]byte(oldDSN))}
	ctx := context.Background()

	newH, err := pg.Rotate(ctx, cred, v)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// The fixture's current password must have changed.
	if cur, _ := os.ReadFile(state); string(cur) == "oldpw" {
		t.Fatal("password not changed by ALTER")
	}

	// New secret authenticates...
	if err := pg.Verify(ctx, newH, v); err != nil {
		t.Errorf("Verify(new) should pass: %v", err)
	}
	// ...and the OLD credential is now dead (real cutover).
	if err := pg.Verify(ctx, cred.Secret, v); err == nil {
		t.Error("Verify(old) must fail after rotation — old password should be revoked")
	} else if strings.Contains(err.Error(), "oldpw") {
		// sanity: error must not leak the secret
		t.Error("error leaked the old password")
	}

	if err := pg.RevokeOld(ctx, cred, v); err != nil {
		t.Errorf("RevokeOld (no-op) returned: %v", err)
	}
}

func TestPostgresRejectsNonPostgresDSN(t *testing.T) {
	pg := &Postgres{Bin: "/bin/false"}
	v := vault.New()
	defer v.Purge()
	cred := discover.Credential{Source: "postgres", Secret: v.Store([]byte("mysql://u:p@h/db"))}
	if _, err := pg.Rotate(context.Background(), cred, v); err == nil {
		t.Error("Rotate should reject a non-postgres scheme")
	}
}
