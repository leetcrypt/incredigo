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

// fakePassBin writes a `pass`/`gopass` stand-in backed by a store directory of
// `<entry>.gpg` files whose plaintext content IS the entry body (line 1 = password).
// It implements just the three subcommands the adapter uses: `show <entry>` (cat the
// file), `insert -m -f <entry>` (overwrite the file from stdin), and `ls --flat` (list
// entry names). The store dir is passed via $PASSWORD_STORE_DIR so both flavors find it.
func fakePassBin(t *testing.T) (bin, store string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake pass binary is a POSIX shell script")
	}
	store = filepath.Join(t.TempDir(), "store")
	if err := os.MkdirAll(filepath.Join(store, "web"), 0o700); err != nil {
		t.Fatal(err)
	}
	// github.com/alice: password + login + url metadata lines.
	body := "old-secret\nlogin: alice@example.com\nurl: https://github.com/login\n"
	if err := os.WriteFile(filepath.Join(store, "web", "github.com.gpg"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	bin = filepath.Join(t.TempDir(), "passbin")
	script := `#!/usr/bin/env bash
set -euo pipefail
STORE="${PASSWORD_STORE_DIR:?need PASSWORD_STORE_DIR}"
cmd="${1:-}"
case "$cmd" in
  show)
    entry="$2"
    cat "$STORE/$entry.gpg"
    ;;
  insert)
    # insert -m -f <entry> ; body on stdin
    entry="${@: -1}"
    mkdir -p "$(dirname "$STORE/$entry.gpg")"
    cat > "$STORE/$entry.gpg"
    ;;
  ls)
    # ls --flat
    ( cd "$STORE" && find . -name '*.gpg' | sed -e 's#^\./##' -e 's#\.gpg$##' )
    ;;
  *)
    echo "fake pass: unknown command: $*" >&2; exit 2
    ;;
esac
`
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin, store
}

func TestPassStoreExport(t *testing.T) {
	for _, flavor := range []string{"pass", "gopass"} {
		t.Run(flavor, func(t *testing.T) {
			bin, store := fakePassBin(t)
			t.Setenv("PASSWORD_STORE_DIR", store) // the fake bin (and pass walk) read this
			v := vault.New()
			defer v.Purge()

			p := &PassStore{Bin: bin, Flavor: flavor, Store: store}
			if !p.Available() {
				t.Fatal("Available should be true with injected bin")
			}
			accts, err := p.Export(context.Background(), v)
			if err != nil {
				t.Fatalf("Export: %v", err)
			}
			if len(accts) != 1 {
				t.Fatalf("got %d accounts, want 1", len(accts))
			}
			a := accts[0]
			if a.ID != "web/github.com" {
				t.Errorf("entry path = %q, want web/github.com", a.ID)
			}
			if a.Username != "alice@example.com" {
				t.Errorf("username = %q, want alice@example.com", a.Username)
			}
			if a.Site != "github.com" {
				t.Errorf("site = %q, want github.com", a.Site)
			}
			if a.Meta["group"] != "web" {
				t.Errorf("group = %q, want web", a.Meta["group"])
			}
			if pw := handleStr(t, v, a.Secret); pw != "old-secret" {
				t.Errorf("password = %q, want old-secret", pw)
			}
		})
	}
}

func TestPassStoreUpdatePreservesMetadata(t *testing.T) {
	bin, store := fakePassBin(t)
	t.Setenv("PASSWORD_STORE_DIR", store)
	v := vault.New()
	defer v.Purge()

	p := &PassStore{Bin: bin, Flavor: "pass", Store: store}
	accts, err := p.Export(context.Background(), v)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	newPw := v.Store([]byte("NEW-pass-pw-7"))
	if err := p.UpdatePassword(context.Background(), v, accts[0], newPw); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(store, "web", "github.com.gpg"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	// New password on line 1, OLD gone, metadata lines preserved.
	if got := s[:len("NEW-pass-pw-7")]; got != "NEW-pass-pw-7" {
		t.Errorf("first line = %q, want the new password", got)
	}
	if want := "login: alice@example.com"; !strings.Contains(s, want) {
		t.Errorf("metadata dropped: %q missing from:\n%s", want, s)
	}
	if strings.Contains(s, "old-secret") {
		t.Errorf("old password still present:\n%s", s)
	}
}

func TestPassStorePrefixScope(t *testing.T) {
	bin, store := fakePassBin(t)
	t.Setenv("PASSWORD_STORE_DIR", store)
	// Add an out-of-scope entry at the root.
	if err := os.WriteFile(filepath.Join(store, "root-note.gpg"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	v := vault.New()
	defer v.Purge()

	p := &PassStore{Bin: bin, Flavor: "pass", Store: store, Prefix: "web"}
	accts, err := p.Export(context.Background(), v)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if len(accts) != 1 || accts[0].ID != "web/github.com" {
		t.Fatalf("prefix scope failed: got %+v", accts)
	}
}
