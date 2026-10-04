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

// fakeKeePassXC writes a `keepassxc-cli` stand-in backed by a CSV "database" file.
// `export -f csv <db>` reads the DB passphrase from stdin (asserting it matches) and
// prints the CSV; `edit -p <db> <entry>` reads two stdin lines (db passphrase, then
// the new entry password) and rewrites the matching row — proving both secrets travel
// over stdin, never argv.
func fakeKeePassXC(t *testing.T) (bin, dbPath string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake keepassxc-cli is a POSIX shell script")
	}
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "lab.kdbx") // a CSV masquerading as a kdbx for the fake
	csv := "Group,Title,Username,Password,URL,Notes\n" +
		"Root,GitHub,alice@example.com,old-secret,https://github.com/login,\n"
	if err := os.WriteFile(dbPath, []byte(csv), 0o600); err != nil {
		t.Fatal(err)
	}
	bin = filepath.Join(dir, "keepassxc-cli")
	const wantPass = "db-master-pass"
	script := `#!/usr/bin/env bash
set -euo pipefail
DB_WANT_PASS="` + wantPass + `"
cmd="${1:-}"
case "$cmd" in
  export)
    # args: export -f csv <db>
    db="$4"
    read -r dbpass || true
    if [ "$dbpass" != "$DB_WANT_PASS" ]; then echo "bad db passphrase" >&2; exit 1; fi
    cat "$db"
    ;;
  edit)
    # args: edit -p <db> <entry>   ; stdin: <dbpass>\n<newpass>
    db="$3"; entry="$4"
    read -r dbpass || true
    read -r newpass || true
    if [ "$dbpass" != "$DB_WANT_PASS" ]; then echo "bad db passphrase" >&2; exit 1; fi
    # entry is /Root/GitHub -> title GitHub. Rewrite the Password column of that row.
    title="${entry##*/}"
    tmp="$(mktemp)"
    while IFS= read -r line; do
      case "$line" in
        *",$title,"*)
          IFS=',' read -r g ti us pw url notes <<< "$line"
          printf '%s,%s,%s,%s,%s,%s\n' "$g" "$ti" "$us" "$newpass" "$url" "$notes"
          ;;
        *) printf '%s\n' "$line";;
      esac
    done < "$db" > "$tmp"
    mv "$tmp" "$db"
    ;;
  *)
    echo "fake keepassxc-cli: unknown command: $*" >&2; exit 2
    ;;
esac
`
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin, dbPath
}

func TestKeePassXCExport(t *testing.T) {
	bin, db := fakeKeePassXC(t)
	v := vault.New()
	defer v.Purge()
	k := &KeePassXC{Bin: bin, DBPath: db, DBKey: v.Store([]byte("db-master-pass"))}

	if !k.Available() {
		t.Fatal("Available should be true with db path + injected bin")
	}
	accts, err := k.Export(context.Background(), v)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if len(accts) != 1 {
		t.Fatalf("got %d accounts, want 1", len(accts))
	}
	a := accts[0]
	// The root group name ("Root" here) is dropped — keepassxc-cli addresses entries
	// relative to the root, so a top-level entry is "/GitHub" not "/Root/GitHub".
	if a.ID != "/GitHub" {
		t.Errorf("entry path = %q, want /GitHub", a.ID)
	}
	if a.Username != "alice@example.com" || a.Site != "github.com" {
		t.Errorf("account = %+v", a)
	}
	if pw := handleStr(t, v, a.Secret); pw != "old-secret" {
		t.Errorf("password = %q, want old-secret", pw)
	}
}

func TestKeePassXCUpdatePassword(t *testing.T) {
	bin, db := fakeKeePassXC(t)
	v := vault.New()
	defer v.Purge()
	k := &KeePassXC{Bin: bin, DBPath: db, DBKey: v.Store([]byte("db-master-pass"))}

	accts, err := k.Export(context.Background(), v)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	newPw := v.Store([]byte("NEW-kp-pw-3"))
	if err := k.UpdatePassword(context.Background(), v, accts[0], newPw); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}
	raw, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, "NEW-kp-pw-3") {
		t.Errorf("db not updated with new password:\n%s", s)
	}
	if strings.Contains(s, "old-secret") {
		t.Errorf("db still has old password:\n%s", s)
	}
}

func TestKPEntryPathDropsRootGroup(t *testing.T) {
	cases := []struct{ group, title, want string }{
		{"Passwords", "GitHub", "/GitHub"},      // root entry: root name dropped
		{"Root", "GitHub", "/GitHub"},           // same, different root name
		{"", "GitHub", "/GitHub"},               // no group at all
		{"Passwords/Web", "GitHub", "/Web/GitHub"}, // nested: keep subgroup, drop root
		{"/Passwords/Web/", "GitHub", "/Web/GitHub"}, // surrounding slashes tolerated
	}
	for _, c := range cases {
		if got := kpEntryPath(c.group, c.title); got != c.want {
			t.Errorf("kpEntryPath(%q,%q) = %q, want %q", c.group, c.title, got, c.want)
		}
	}
}

func TestKeePassXCUnavailableWithoutDB(t *testing.T) {
	k := &KeePassXC{Bin: "keepassxc-cli"}
	if k.Available() {
		t.Error("Available should be false with no db path")
	}
}
