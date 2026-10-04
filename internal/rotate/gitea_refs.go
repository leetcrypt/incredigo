package rotate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Reference enumeration for the gitea blast-and-cutover.
//
// A real IN-USE Gitea PAT does not live only in the gopass blob the driver is
// handed — the same 40-hex string is embedded VERBATIM in several on-disk files:
// ~/.git-credentials lines, embedded git-remote URLs in each repo's .git/config,
// and the `tea` CLI config. Rotating the blob alone would break git auth in every
// un-updated place. The blast-and-cutover fixes this by writing one `ref=<file>`
// into the blob for every reference file; Rotate then rewrites the old token → new
// in each. This file produces that reference list, READ-ONLY.
//
// SECURITY: the token value is used only as a search key for a literal substring
// match; it is never logged, and no candidate file is modified here.

// giteaWellKnownRefFiles returns the standard credential files that commonly embed a
// Gitea token, resolved under the given home dir and honoring $XDG_CONFIG_HOME for
// the tea config (matching internal/discover/tea.go). Existence is NOT checked here —
// enumerateGiteaRefs filters to the files that actually contain the token.
func giteaWellKnownRefFiles(home string) []string {
	teaDir := filepath.Join(home, ".config", "tea")
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		teaDir = filepath.Join(x, "tea")
	}
	return []string{
		filepath.Join(home, ".git-credentials"),
		filepath.Join(teaDir, "config.yml"),
		filepath.Join(teaDir, "config.yaml"),
	}
}

// giteaGitConfigRefFiles returns the `.git/config` path for each given repo root that
// has one. These configs can embed a token inside a remote URL (a per-remote credential
// helper or a token baked into the URL). Roots are supplied by the caller (e.g. from the
// git scanner's known repos); this does not walk the filesystem on its own.
func giteaGitConfigRefFiles(roots ...string) []string {
	var out []string
	for _, root := range roots {
		cfg := filepath.Join(root, ".git", "config")
		if fi, err := os.Stat(cfg); err == nil && !fi.IsDir() {
			out = append(out, cfg)
		}
	}
	return out
}

// enumerateGiteaRefs filters a candidate list down to the files that LITERALLY contain
// the token, returning the reference set for the blast-and-cutover. It is read-only and
// never logs the token. Non-existent or unreadable candidates are skipped silently — a
// missing well-known file simply isn't a reference. Duplicate paths are collapsed.
//
// It refuses a token shorter than minGiteaTokenLen: a short literal could match unrelated
// bytes in these files, which would later cause the rewrite to corrupt them.
func enumerateGiteaRefs(token string, candidates []string) ([]string, error) {
	if len(token) < minGiteaTokenLen {
		return nil, fmt.Errorf("gitea: refusing to enumerate references for a token shorter than %d chars", minGiteaTokenLen)
	}
	var refs []string
	seen := map[string]bool{}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		abs, err := filepath.Abs(c)
		if err != nil {
			abs = c
		}
		if seen[abs] {
			continue
		}
		seen[abs] = true
		b, err := os.ReadFile(abs)
		if err != nil {
			continue // missing/unreadable → not a reference
		}
		if strings.Contains(string(b), token) {
			refs = append(refs, abs)
		}
	}
	return refs, nil
}
