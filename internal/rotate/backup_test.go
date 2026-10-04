package rotate

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/awnumar/memguard"

	"incredigo/internal/sink"
)

func fakeGopass(t *testing.T) *sink.Gopass {
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
	for p, s := range map[string]string{
		"imported/aws/default": "AKIA-secret-1",
		"imported/env/api":     "tok-2-末",
		"other/skip":           "not-backed-up",
	} {
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

func TestSnapshotBackupGate(t *testing.T) {
	gp := fakeGopass(t)
	pass := memguard.NewBufferFromBytes([]byte("backup-pass"))
	defer pass.Destroy()
	out := filepath.Join(t.TempDir(), "backup.age")

	n, err := Snapshot(context.Background(), gp, "imported/", &sink.Age{}, pass, out)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("backed up %d entries, want 2 (other/ excluded by prefix)", n)
	}
	fi, err := os.Stat(out)
	if err != nil || fi.Size() == 0 {
		t.Fatalf("backup bundle missing or empty: %v", err)
	}

	// The gate must refuse to overwrite an existing backup.
	if _, err := Snapshot(context.Background(), gp, "imported/", &sink.Age{}, pass, out); err == nil {
		t.Error("Snapshot should refuse to overwrite an existing backup path")
	}
}

func TestVerifyBundleDetectsTamper(t *testing.T) {
	gp := fakeGopass(t)
	pass := memguard.NewBufferFromBytes([]byte("pw"))
	defer pass.Destroy()
	out := filepath.Join(t.TempDir(), "b.age")
	if _, err := Snapshot(context.Background(), gp, "imported/", &sink.Age{}, pass, out); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 0x01 // flip a byte
	tampered := filepath.Join(t.TempDir(), "t.age")
	if err := os.WriteFile(tampered, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyBundle(context.Background(), &sink.Age{}, pass, tampered); err == nil {
		t.Error("verifyBundle must fail on a tampered bundle")
	}
}
