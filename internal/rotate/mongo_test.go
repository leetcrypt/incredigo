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

// writeFakeMongosh writes a stub `mongosh` that emulates a single mongo user against a
// state file holding the user's CURRENT password. The stdin script uses db.auth(user,pw)
// and changeUserPassword(user,newpw); the stub parses those literal calls: auth prints
// AUTH-OK only when the password matches the state, and changeUserPassword updates the
// state only when a preceding auth matched. This lets a test prove a real cutover — after
// Rotate the OLD password must stop authenticating.
func writeFakeMongosh(t *testing.T, statePath string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "mongosh")
	// The script extracts the auth password and the (optional) new password from the
	// JS on stdin using sed, compares to state, and acts accordingly.
	script := `#!/usr/bin/env bash
set -uo pipefail
js="$(cat)"
cur="$(cat "` + statePath + `" 2>/dev/null || true)"
# auth("user","PW")  -> capture PW from the FIRST .auth( call
authpw="$(printf '%s' "$js" | sed -n 's/.*\.auth([^,]*,"\([^"]*\)").*/\1/p' | head -n1)"
newpw="$(printf '%s' "$js" | sed -n 's/.*changeUserPassword([^,]*,"\([^"]*\)").*/\1/p' | head -n1)"
if [ "$authpw" != "$cur" ]; then
  # auth failed
  case "$js" in
    *AUTH-OK*) echo "AUTH-FAIL";;            # Verify path: report failure
    *) echo "auth failed"; exit 1;;          # Rotate path: error out
  esac
  exit 0
fi
# auth succeeded
if [ -n "$newpw" ]; then
  printf '%s' "$newpw" > "` + statePath + `"
  echo "ROTATED"
else
  echo "AUTH-OK"
fi
exit 0
`
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMongoDetect(t *testing.T) {
	m := &Mongo{}
	if !m.Detect(discover.Credential{Source: "mongo"}) {
		t.Error("should detect Source=mongo")
	}
	if m.Detect(discover.Credential{Source: "redis"}) {
		t.Error("should not detect Source=redis")
	}
}

func TestMongoRotateRealCutover(t *testing.T) {
	state := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(state, []byte("oldpw"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := &Mongo{Bin: writeFakeMongosh(t, state)}

	v := vault.New()
	defer v.Purge()
	oldURI := "mongodb://labapp:oldpw@127.0.0.1:27017/labdb?authSource=admin"
	cred := discover.Credential{Source: "mongo", Identity: "mongo labapp@labdb", Secret: v.Store([]byte(oldURI))}
	ctx := context.Background()

	newH, err := m.Rotate(ctx, cred, v)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if cur, _ := os.ReadFile(state); string(cur) == "oldpw" {
		t.Fatal("password not changed by changeUserPassword")
	}

	// The rebuilt URI must carry a fresh password (and same user/host/db).
	nb, _ := v.Open(newH)
	nu := strings.TrimSpace(string(nb.Bytes()))
	if strings.Contains(nu, ":oldpw@") {
		t.Fatal("rebuilt uri still carries old password")
	}
	if !strings.Contains(nu, "labapp:") || !strings.Contains(nu, "/labdb") {
		t.Errorf("rebuilt uri lost user/db: %q", nu)
	}

	if err := m.Verify(ctx, newH, v); err != nil {
		t.Errorf("Verify(new) should pass: %v", err)
	}
	// CUTOVER: the old password must be dead after the change.
	if err := m.Verify(ctx, cred.Secret, v); err == nil {
		t.Error("Verify(old) must fail after rotation — old password should be revoked")
	} else if strings.Contains(err.Error(), "oldpw") {
		t.Error("error leaked the old password")
	}

	if err := m.RevokeOld(ctx, cred, v); err != nil {
		t.Errorf("RevokeOld (no-op) returned: %v", err)
	}
}

func TestMongoRejectsBadURI(t *testing.T) {
	m := &Mongo{Bin: "/bin/false"}
	v := vault.New()
	defer v.Purge()
	// wrong scheme
	cred := discover.Credential{Source: "mongo", Secret: v.Store([]byte("redis://u:p@h:6379"))}
	if _, err := m.Rotate(context.Background(), cred, v); err == nil {
		t.Error("Rotate should reject a non-mongodb scheme")
	}
	// no user
	cred2 := discover.Credential{Source: "mongo", Secret: v.Store([]byte("mongodb://127.0.0.1:27017/db"))}
	if _, err := m.Rotate(context.Background(), cred2, v); err == nil {
		t.Error("Rotate should reject a uri with no user")
	}
}
