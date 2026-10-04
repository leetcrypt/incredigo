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

// fakeSecurity writes a `security` stand-in backed by a flat "<server>\t<account>\t<pw>"
// db file. It implements dump-keychain (emits the inet-block format the parser reads),
// find-internet-password -s -a -w (prints the password), and add/delete-internet-password
// (rewrites the db). $KC_DB points at the db file.
func fakeSecurity(t *testing.T) (bin, db string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake security is a POSIX shell script")
	}
	dir := t.TempDir()
	db = filepath.Join(dir, "kc.db")
	// Two inet logins + one genp (generic) item that MUST be ignored by Export.
	seed := "inet\tgithub.com\talice@example.com\told-gh\n" +
		"inet\tgitlab.com\tbob@example.com\told-gl\n" +
		"genp\tWiFi\thome\twifi-pw\n"
	if err := os.WriteFile(db, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	bin = filepath.Join(dir, "security")
	script := `#!/usr/bin/env bash
set -euo pipefail
DB="${KC_DB:?need KC_DB}"
cmd="${1:-}"; shift || true
getopt_val() { # $1=flag ; echoes value after it in remaining args
  local want="$1"; shift
  while [ "$#" -gt 0 ]; do
    if [ "$1" = "$want" ]; then echo "$2"; return; fi
    shift
  done
}
case "$cmd" in
  dump-keychain)
    while IFS=$'\t' read -r class srvr acct pw; do
      printf 'keychain: "/fake/login.keychain-db"\n'
      printf '    class: "%s"\n' "$class"
      printf '    attributes:\n'
      printf '    "acct"<blob>="%s"\n' "$acct"
      printf '    "srvr"<blob>="%s"\n' "$srvr"
    done < "$DB"
    ;;
  find-internet-password)
    s="$(getopt_val -s "$@")"; a="$(getopt_val -a "$@")"
    while IFS=$'\t' read -r class srvr acct pw; do
      if [ "$class" = inet ] && [ "$srvr" = "$s" ] && [ "$acct" = "$a" ]; then
        printf '%s\n' "$pw"; exit 0
      fi
    done < "$DB"
    echo "not found" >&2; exit 44
    ;;
  add-internet-password)
    s="$(getopt_val -s "$@")"; a="$(getopt_val -a "$@")"; w="$(getopt_val -w "$@")"
    printf 'inet\t%s\t%s\t%s\n' "$s" "$a" "$w" >> "$DB"
    ;;
  delete-internet-password)
    s="$(getopt_val -s "$@")"; a="$(getopt_val -a "$@")"
    tmp="$(mktemp)"
    while IFS=$'\t' read -r class srvr acct pw; do
      if [ "$class" = inet ] && [ "$srvr" = "$s" ] && [ "$acct" = "$a" ]; then continue; fi
      printf '%s\t%s\t%s\t%s\n' "$class" "$srvr" "$acct" "$pw"
    done < "$DB" > "$tmp"
    mv "$tmp" "$DB"
    ;;
  *)
    echo "fake security: unknown command: $cmd" >&2; exit 2
    ;;
esac
`
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin, db
}

func TestKeychainExportInetOnly(t *testing.T) {
	bin, db := fakeSecurity(t)
	t.Setenv("KC_DB", db)
	v := vault.New()
	defer v.Purge()

	k := &Keychain{Bin: bin}
	if !k.Available() {
		t.Fatal("Available should be true with injected bin")
	}
	accts, err := k.Export(context.Background(), v)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if len(accts) != 2 {
		t.Fatalf("got %d accounts, want 2 (genp WiFi item must be skipped)", len(accts))
	}
	byUser := map[string]Account{}
	for _, a := range accts {
		byUser[a.Username] = a
	}
	gh, ok := byUser["alice@example.com"]
	if !ok {
		t.Fatalf("github account missing: %+v", accts)
	}
	if gh.Site != "github.com" || gh.URL != "github.com" {
		t.Errorf("github account = %+v", gh)
	}
	if pw := handleStr(t, v, gh.Secret); pw != "old-gh" {
		t.Errorf("github password = %q, want old-gh", pw)
	}
}

func TestKeychainUpdatePassword(t *testing.T) {
	bin, db := fakeSecurity(t)
	t.Setenv("KC_DB", db)
	v := vault.New()
	defer v.Purge()

	k := &Keychain{Bin: bin}
	accts, err := k.Export(context.Background(), v)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	var gh Account
	for _, a := range accts {
		if a.Username == "alice@example.com" {
			gh = a
		}
	}
	newPw := v.Store([]byte("NEW-kc-pw-9"))
	if err := k.UpdatePassword(context.Background(), v, gh, newPw); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}
	raw, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, "github.com\talice@example.com\tNEW-kc-pw-9") {
		t.Errorf("db not updated with new password:\n%s", s)
	}
	if strings.Contains(s, "old-gh") {
		t.Errorf("old github password still present (delete+add should have replaced it):\n%s", s)
	}
}

func TestKeychainUnavailableOffMacWithoutBin(t *testing.T) {
	k := &Keychain{}
	if runtime.GOOS != "darwin" && k.Available() {
		t.Error("Available should be false off macOS with no injected bin")
	}
}

func TestParseKeychainDumpValue(t *testing.T) {
	cases := []struct {
		line string
		want string
		ok   bool
	}{
		{`    "srvr"<blob>="github.com"`, "github.com", true},
		{`    "acct"<blob>="alice@example.com"`, "alice@example.com", true},
		{`    "srvr"<blob>=<NULL>`, "", false},
		{`    no equals here`, "", false},
	}
	for _, c := range cases {
		got, ok := kcAttrValue(c.line)
		if got != c.want || ok != c.ok {
			t.Errorf("kcAttrValue(%q) = (%q,%v), want (%q,%v)", c.line, got, ok, c.want, c.ok)
		}
	}
}
