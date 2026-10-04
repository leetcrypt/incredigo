package pwstore

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"incredigo/internal/vault"
)

// fakeOP writes a tiny `op` stand-in. Each item is a KEY=VALUE file under $state so
// an `item edit <id> password=NEW` (argv assignment, exactly as the adapter shells
// it) is visible to a later `item get`. The fake also records the full argv of every
// invocation to argv.log so a test can assert what did / didn't reach the command line.
func fakeOP(t *testing.T) (bin, stateDir string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake op is a POSIX shell script")
	}
	dir := t.TempDir()
	stateDir = filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	seed := "ID=id1\nTITLE=GitHub\nUSERNAME=alice@example.com\nURL=https://github.com/login\nPW=old-secret\n"
	if err := os.WriteFile(filepath.Join(stateDir, "id1.item"), []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	bin = filepath.Join(dir, "op")
	script := `#!/usr/bin/env bash
set -euo pipefail
STATE="` + stateDir + `"
echo "$@" >> "$STATE/../argv.log"
cmd="${1:-}"; sub="${2:-}"
case "$cmd $sub" in
  "item list")
    first=1; printf '['
    for f in "$STATE"/*.item; do
      . "$f"
      [ "$first" = 1 ] || printf ','
      printf '{"id":"%s","category":"LOGIN"}' "$ID"
      first=0
    done
    printf ']'
    ;;
  "item get")
    id="${3:?}"; . "$STATE/$id.item"
    printf '{"id":"%s","title":"%s","category":"LOGIN","urls":[{"href":"%s"}],"fields":[{"id":"username","type":"STRING","value":"%s"},{"id":"password","type":"CONCEALED","value":"%s"}]}' \
      "$ID" "$TITLE" "$URL" "$USERNAME" "$PW"
    ;;
  "item edit")
    id="${3:?}"
    new=""
    for a in "$@"; do
      case "$a" in password=*) new="${a#password=}";; esac
    done
    f="$STATE/$id.item"
    . "$f"
    PW="$new"
    printf 'ID=%s\nTITLE=%s\nUSERNAME=%s\nURL=%s\nPW=%s\n' "$ID" "$TITLE" "$USERNAME" "$URL" "$PW" > "$f"
    printf '{"id":"%s"}' "$ID"
    ;;
  *)
    echo "fake op: unknown command: $*" >&2; exit 2
    ;;
esac
`
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin, stateDir
}

func TestOnePasswordExport(t *testing.T) {
	bin, _ := fakeOP(t)
	v := vault.New()
	defer v.Purge()
	o := &OnePassword{Bin: bin}

	if !o.Available() {
		t.Fatal("injected Bin should report Available")
	}
	accts, err := o.Export(context.Background(), v)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if len(accts) != 1 {
		t.Fatalf("got %d accounts, want 1", len(accts))
	}
	a := accts[0]
	if a.ID != "id1" || a.Username != "alice@example.com" || a.Site != "github.com" {
		t.Errorf("account = %+v", a)
	}
	if pw := handleStr(t, v, a.Secret); pw != "old-secret" {
		t.Errorf("password = %q, want old-secret", pw)
	}
}

func TestOnePasswordUpdatePassword(t *testing.T) {
	bin, stateDir := fakeOP(t)
	v := vault.New()
	defer v.Purge()
	o := &OnePassword{Bin: bin}

	accts, err := o.Export(context.Background(), v)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	newPw := v.Store([]byte("NEW-op-pw-7"))
	if err := o.UpdatePassword(context.Background(), v, accts[0], newPw); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(stateDir, "id1.item"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "PW=NEW-op-pw-7") {
		t.Errorf("item not updated:\n%s", raw)
	}
	// Re-export reads the new password back.
	v2 := vault.New()
	defer v2.Purge()
	accts2, _ := o.Export(context.Background(), v2)
	if pw := handleStr(t, v2, accts2[0].Secret); pw != "NEW-op-pw-7" {
		t.Errorf("re-read password = %q", pw)
	}
}

func TestOnePasswordUpdateNoIDFails(t *testing.T) {
	bin, _ := fakeOP(t)
	v := vault.New()
	defer v.Purge()
	o := &OnePassword{Bin: bin}
	h := v.Store([]byte("x"))
	if err := o.UpdatePassword(context.Background(), v, Account{}, h); err == nil {
		t.Error("expected error updating an account with no item id")
	}
}
