package sink

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"incredigo/internal/discover"
)

// writeFakeGopass writes a stub `gopass` binary that stores entries as files under
// $FAKE_GOPASS_STORE, supporting the ls/show/insert subcommands the bundle code
// uses (plus rm). This exercises the real framing + subprocess plumbing without touching the
// user's actual gopass store.
func writeFakeGopass(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "gopass")
	script := `#!/usr/bin/env bash
store="$FAKE_GOPASS_STORE"
case "$1" in
  ls) (cd "$store" 2>/dev/null && find . -type f | sed 's#^\./##' | sort) ;;
  show) cat "$store/$3" ;;
  insert)
    shift; path=""
    for a in "$@"; do case "$a" in --multiline=false|-f) ;; *) path="$a";; esac; done
    mkdir -p "$store/$(dirname "$path")"; cat > "$store/$path" ;;
  rm)
    shift; path=""
    for a in "$@"; do case "$a" in -f) ;; *) path="$a";; esac; done
    [[ -f "$store/$path" ]] || { echo "not found" >&2; exit 1; }
    rm -f "$store/$path" ;;
esac
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func seed(t *testing.T, store string, entries map[string]string) {
	t.Helper()
	for path, secret := range entries {
		full := filepath.Join(store, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(secret), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBundleRoundTrip(t *testing.T) {
	bin := writeFakeGopass(t)
	gp := &Gopass{Bin: bin}
	ctx := context.Background()

	src := t.TempDir()
	seed(t, src, map[string]string{
		"imported/aws/default": "AKIA/secret+with=specials",
		"imported/env/api":     "unicode-末-\U0001f511",
		"other/skip":           "should-not-export",
	})

	// Export the imported/ subtree to a framed (unsealed) buffer.
	t.Setenv("FAKE_GOPASS_STORE", src)
	var buf bytes.Buffer
	n, err := gp.ExportTo(ctx, &buf, "imported/")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("exported %d entries, want 2 (other/ excluded by prefix)", n)
	}

	// Import into a fresh store and assert byte-exact restoration.
	dst := t.TempDir()
	t.Setenv("FAKE_GOPASS_STORE", dst)
	m, err := gp.ImportFrom(ctx, &buf, true)
	if err != nil {
		t.Fatal(err)
	}
	if m != 2 {
		t.Fatalf("imported %d entries, want 2", m)
	}

	want := map[string]string{
		"imported/aws/default": "AKIA/secret+with=specials",
		"imported/env/api":     "unicode-末-\U0001f511",
	}
	for path, exp := range want {
		got, err := os.ReadFile(filepath.Join(dst, path))
		if err != nil {
			t.Fatalf("restored %s: %v", path, err)
		}
		if string(got) != exp {
			t.Errorf("%s: got %q want %q", path, got, exp)
		}
	}
	if _, err := os.Stat(filepath.Join(dst, "other", "skip")); !os.IsNotExist(err) {
		t.Error("other/skip leaked across the prefix filter")
	}
}

func TestStorePathNoDoubleSegment(t *testing.T) {
	gp := &Gopass{Prefix: "imported/"}
	c := discover.Credential{Source: "file", Identity: "keys/deploy"}
	if got := gp.StorePath(c); got != "imported/file/keys/deploy" {
		t.Errorf("StorePath = %q, want imported/file/keys/deploy", got)
	}
}

// TestStorePathNoDotSegment guards Hard Rule #1: a dot-prefixed path segment
// (e.g. ".env") is hidden by gopass `ls --flat`, which would make the entry
// invisible to the backup gate's coverage check. slug() must strip leading
// dots so every stored credential is enumerable and therefore backed up.
func TestStorePathNoDotSegment(t *testing.T) {
	gp := &Gopass{Prefix: "imported/"}
	cases := []struct {
		identity string
		want     string
	}{
		{".env / API_TOKEN", "imported/env/env/api_token"},
		{".env.prod / DATABASE_URL", "imported/env/env.prod/database_url"},
		{".netrc / password", "imported/env/netrc/password"},
	}
	for _, tc := range cases {
		c := discover.Credential{Source: "env", Identity: tc.identity}
		got := gp.StorePath(c)
		if got != tc.want {
			t.Errorf("StorePath(%q) = %q, want %q", tc.identity, got, tc.want)
		}
		for _, seg := range strings.Split(got, "/") {
			if strings.HasPrefix(seg, ".") {
				t.Errorf("StorePath(%q) = %q has hidden dot-segment %q", tc.identity, got, seg)
			}
		}
	}
}
