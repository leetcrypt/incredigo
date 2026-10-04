package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/awnumar/memguard"

	"incredigo/internal/sink"
)

// fakeGopass installs a bash stand-in for gopass (ls/show/insert over a plain dir named by
// $FAKE_GOPASS_STORE) seeded with entries. Fake creds only.
func fakeGopass(t *testing.T, entries map[string]string) *sink.Gopass {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "gopass")
	script := `#!/usr/bin/env bash
store="$FAKE_GOPASS_STORE"
case "$1" in
  ls) (cd "$store" 2>/dev/null && find . -type f | sed 's#^\./##' | sort) ;;
  show) cat "$store/$3" ;;
  insert) shift; path=""; for a in "$@"; do case "$a" in --multiline=false|-f) ;; *) path="$a";; esac; done
    mkdir -p "$store/$(dirname "$path")"; cat > "$store/$path" ;;
esac
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	store := t.TempDir()
	t.Setenv("FAKE_GOPASS_STORE", store)
	for p, s := range entries {
		full := filepath.Join(store, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return &sink.Gopass{Bin: bin}
}

// restoreInto opens the sealed bundle and imports it into a FRESH fake store, returning
// that store's dir — a real restore, not just a record count.
func restoreInto(t *testing.T, gp *sink.Gopass, pass *memguard.LockedBuffer, bundle string) string {
	t.Helper()
	f, err := os.Open(bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var plain bytes.Buffer
	if err := (&sink.Age{}).Open(context.Background(), f, &plain, pass); err != nil {
		t.Fatalf("open bundle: %v", err)
	}
	restored := t.TempDir()
	t.Setenv("FAKE_GOPASS_STORE", restored)
	if _, err := gp.ImportFrom(context.Background(), &plain, true); err != nil {
		t.Fatalf("restore bundle: %v", err)
	}
	return restored
}

func TestBackupGate_containsRotatedEntry(t *testing.T) {
	cases := []struct {
		name      string
		storePath string
	}{
		{"default gitea path", "gitea/login-creds"},
		// Regression: a prefix not starting with "gitea" used to be silently excluded.
		{"store prefix outside gitea/", "imported/gitea/login-creds"},
		{"arbitrary path", "web/git.example.org/alice"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const old = "fake-old-pw-1"
			gp := fakeGopass(t, map[string]string{
				tc.storePath:  old,
				"other/entry": "fake-unrelated",
			})
			pass := memguard.NewBufferFromBytes([]byte("fake-backup-pass"))
			defer pass.Destroy()
			out := filepath.Join(t.TempDir(), "b.age")

			n, err := backupGate(context.Background(), gp, tc.storePath, &sink.Age{}, pass, out)
			if err != nil {
				t.Fatalf("backupGate: %v", err)
			}
			if n < 1 {
				t.Fatalf("sealed %d entries, want >=1", n)
			}

			restored := restoreInto(t, gp, pass, out)
			got, err := os.ReadFile(filepath.Join(restored, tc.storePath))
			if err != nil {
				t.Fatalf("rotated entry %q missing from the backup: %v", tc.storePath, err)
			}
			if string(bytes.TrimRight(got, "\n")) != old {
				t.Errorf("restored entry not byte-equal to the old secret")
			}
		})
	}
}

func TestBackupGate_missingEntryFailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		entries map[string]string
	}{
		{"empty store", map[string]string{}},
		// Only a sibling that shares the string prefix exists — not the entry itself.
		{"prefix sibling only", map[string]string{"gitea/login-creds-old": "fake-sibling"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gp := fakeGopass(t, tc.entries)
			pass := memguard.NewBufferFromBytes([]byte("fake-backup-pass"))
			defer pass.Destroy()
			out := filepath.Join(t.TempDir(), "b.age")

			if _, err := backupGate(context.Background(), gp, "gitea/login-creds", &sink.Age{}, pass, out); err == nil {
				t.Fatal("backupGate must refuse when the rotated entry would not be in the backup")
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Errorf("no bundle may be left behind on refusal (stat err=%v)", err)
			}
		})
	}
}
