package rotate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const refTestTok = "0123456789abcdef0123456789abcdef01234567" // 40-hex, > minGiteaTokenLen

// TestEnumerateGiteaRefs proves the enumerator returns exactly the files that literally
// hold the token, skips files that do not, and skips missing/unreadable candidates.
func TestEnumerateGiteaRefs(t *testing.T) {
	dir := t.TempDir()

	hit1 := filepath.Join(dir, ".git-credentials")
	hit2 := filepath.Join(dir, "config") // embedded git remote URL
	miss := filepath.Join(dir, "unrelated.txt")
	absent := filepath.Join(dir, "does-not-exist")

	mustWrite(t, hit1, "http://alice:"+refTestTok+"@gitea.local\n")
	mustWrite(t, hit2, "\turl = http://alice:"+refTestTok+"@gitea.local/a/b.git\n")
	mustWrite(t, miss, "nothing sensitive here\n")

	got, err := enumerateGiteaRefs(refTestTok, []string{hit1, hit2, miss, absent, ""})
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	want := map[string]bool{hit1: true, hit2: true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want the two files holding the token", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected ref %q", g)
		}
	}
}

// TestEnumerateGiteaRefsDedup proves duplicate candidate paths (absolute vs relative to
// the same file) collapse to a single reference.
func TestEnumerateGiteaRefsDedup(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, ".git-credentials")
	mustWrite(t, f, "http://bob:"+refTestTok+"@gitea.local\n")

	got, err := enumerateGiteaRefs(refTestTok, []string{f, f})
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected dedup to 1 ref, got %v", got)
	}
}

// TestEnumerateGiteaRefsRejectsShortToken proves the length guard: a short token is
// refused before any file is read, so it can never match unrelated bytes.
func TestEnumerateGiteaRefsRejectsShortToken(t *testing.T) {
	if _, err := enumerateGiteaRefs("short", []string{"/etc/hosts"}); err == nil ||
		!strings.Contains(err.Error(), "shorter than") {
		t.Fatalf("expected short-token refusal, got %v", err)
	}
}

// TestGiteaGitConfigRefFiles proves only repo roots with a real .git/config are returned.
func TestGiteaGitConfigRefFiles(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(repo, ".git", "config")
	mustWrite(t, cfg, "[core]\n")
	noRepo := filepath.Join(dir, "not-a-repo") // no .git at all

	got := giteaGitConfigRefFiles(repo, noRepo)
	if len(got) != 1 || got[0] != cfg {
		t.Fatalf("expected only %q, got %v", cfg, got)
	}
}

// TestGiteaWellKnownRefFilesXDG proves the tea config path honors $XDG_CONFIG_HOME.
func TestGiteaWellKnownRefFilesXDG(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/xdg")
	got := giteaWellKnownRefFiles("/home/alice")
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "/home/alice/.git-credentials") {
		t.Errorf("missing git-credentials in %v", got)
	}
	if !strings.Contains(joined, "/xdg/tea/config.yml") {
		t.Errorf("tea config should honor XDG_CONFIG_HOME, got %v", got)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
