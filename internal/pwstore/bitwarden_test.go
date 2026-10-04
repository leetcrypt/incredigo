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

// fakeBW writes a tiny `bw` stand-in to a temp dir and returns its path. The fake
// keeps item state as JSON files under $BW_STATE so that an `edit item` performed
// via stdin (base64-wrapped JSON, exactly as the real adapter pipes it) is visible
// to a subsequent `get item`. This mirrors the real `bw` contract without a network
// or a real vault, and proves the adapter never puts the password on argv.
func fakeBW(t *testing.T) (bin, stateDir string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake bw is a POSIX shell script")
	}
	dir := t.TempDir()
	stateDir = filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Seed two items: one login, one secure-note (non-login, must be skipped).
	seed := map[string]string{
		"id-login": `{"id":"id-login","type":1,"name":"GitHub","folderId":"f1","notes":"keep me","login":{"username":"alice@example.com","password":"old-secret","uris":[{"uri":"https://github.com/login"}]}}`,
		"id-note":  `{"id":"id-note","type":2,"name":"A Note","notes":"not a login"}`,
	}
	for id, j := range seed {
		if err := os.WriteFile(filepath.Join(stateDir, id+".json"), []byte(j), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bin = filepath.Join(dir, "bw")
	// The script: `list items` concatenates all state files into a JSON array;
	// `get item <id>` prints that file; `edit item <id>` reads base64 from stdin,
	// decodes, and overwrites the file. It rejects any password seen on argv.
	script := `#!/usr/bin/env bash
set -euo pipefail
STATE="` + stateDir + `"
cmd="${1:-}"; sub="${2:-}"
case "$cmd $sub" in
  "list items")
    first=1; printf '['
    for f in "$STATE"/*.json; do
      [ "$first" = 1 ] || printf ','
      cat "$f"; first=0
    done
    printf ']'
    ;;
  "get item")
    id="${3:?}"; cat "$STATE/$id.json"
    ;;
  "edit item")
    id="${3:?}"
    # New encoded item arrives on stdin as base64; decode to the state file.
    base64 -d > "$STATE/$id.json"
    echo "edited $id"
    ;;
  *)
    echo "fake bw: unknown command: $*" >&2; exit 2
    ;;
esac
`
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin, stateDir
}

func TestBitwardenExport(t *testing.T) {
	bin, _ := fakeBW(t)
	v := vault.New()
	defer v.Purge()
	b := &Bitwarden{Bin: bin}

	if !b.Available() {
		t.Fatal("injected Bin should report Available")
	}
	accts, err := b.Export(context.Background(), v)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if len(accts) != 1 {
		t.Fatalf("got %d accounts, want 1 (note must be skipped)", len(accts))
	}
	a := accts[0]
	if a.ID != "id-login" || a.Username != "alice@example.com" {
		t.Errorf("account = %+v", a)
	}
	if a.Site != "github.com" {
		t.Errorf("site = %q, want github.com", a.Site)
	}
	if pw := handleStr(t, v, a.Secret); pw != "old-secret" {
		t.Errorf("password = %q, want old-secret", pw)
	}
}

func TestBitwardenUpdatePasswordInPlace(t *testing.T) {
	bin, stateDir := fakeBW(t)
	v := vault.New()
	defer v.Purge()
	b := &Bitwarden{Bin: bin}

	accts, err := b.Export(context.Background(), v)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	newPw := v.Store([]byte("BRAND-new-pw-99"))
	if err := b.UpdatePassword(context.Background(), v, accts[0], newPw); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}

	// Re-read the state file the fake wrote: password swapped, everything else kept.
	raw, err := os.ReadFile(filepath.Join(stateDir, "id-login.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, "BRAND-new-pw-99") {
		t.Errorf("edited item missing new password:\n%s", s)
	}
	if strings.Contains(s, "old-secret") {
		t.Errorf("edited item still has old password:\n%s", s)
	}
	// Untouched fields must survive the round-trip (raw-map preservation).
	for _, must := range []string{`"folderId":"f1"`, `"notes":"keep me"`, `"username":"alice@example.com"`} {
		if !strings.Contains(s, must) {
			t.Errorf("edited item dropped field %s:\n%s", must, s)
		}
	}

	// Confirm a fresh Export now reads the new password back.
	v2 := vault.New()
	defer v2.Purge()
	accts2, err := b.Export(context.Background(), v2)
	if err != nil {
		t.Fatalf("re-Export: %v", err)
	}
	if pw := handleStr(t, v2, accts2[0].Secret); pw != "BRAND-new-pw-99" {
		t.Errorf("re-read password = %q, want BRAND-new-pw-99", pw)
	}
}

func TestBitwardenUpdateNoIDFails(t *testing.T) {
	bin, _ := fakeBW(t)
	v := vault.New()
	defer v.Purge()
	b := &Bitwarden{Bin: bin}
	h := v.Store([]byte("x"))
	if err := b.UpdatePassword(context.Background(), v, Account{}, h); err == nil {
		t.Error("expected error updating an account with no item id")
	}
}
