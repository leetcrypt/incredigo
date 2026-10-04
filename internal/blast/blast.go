// Package blast builds a read-only "blast-radius" map: for each discovered
// credential, which OTHER files on disk appear to consume it. Rotation needs
// this so a later driver knows what to redeploy after a secret changes.
//
// SECURITY: markers are derived ONLY from a credential's non-secret metadata
// (env-var names, hostnames, identifiers in Identity/Meta) — NEVER from the
// vault secret value. We grep consumer files for those markers; the secret
// plaintext never leaves the vault and is never searched for. The scan is
// strictly read-only.
package blast

import (
	"bufio"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"incredigo/internal/discover"
)

// Hit is one place a credential marker was found.
type Hit struct {
	File   string
	Line   int
	Marker string
}

// CredConsumers is the blast radius of a single credential.
type CredConsumers struct {
	Credential discover.Credential
	Markers    []string // the non-secret tokens we searched for
	Hits       []Hit    // consumer references found (excludes the cred's own source file)
}

// Files returns the distinct consumer files for this credential.
func (cc CredConsumers) Files() []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range cc.Hits {
		if !seen[h.File] {
			seen[h.File] = true
			out = append(out, h.File)
		}
	}
	return out
}

// Options tunes the (read-only) filesystem walk.
type Options struct {
	Roots       []string // directories to search; defaults to "." when empty
	MaxFileSize int64    // skip files larger than this; defaults to 1 MiB
}

// skipDirs are noise directories we never descend into.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true,
	".incredigo": true, ".terraform": true, "dist": true, "build": true,
}

// Map computes the blast radius for each credential. Credentials with no usable
// non-secret marker yield an empty Hits slice (e.g. a fully-redacted AWS key id).
func Map(creds []discover.Credential, opts Options) ([]CredConsumers, error) {
	if len(opts.Roots) == 0 {
		opts.Roots = []string{"."}
	}
	if opts.MaxFileSize == 0 {
		opts.MaxFileSize = 1 << 20
	}

	out := make([]CredConsumers, len(creds))
	markersByCred := make([][]string, len(creds))
	sourceFiles := map[string]bool{} // a cred's own location is never its own consumer
	for i, c := range creds {
		out[i] = CredConsumers{Credential: c}
		markersByCred[i] = Markers(c)
		out[i].Markers = markersByCred[i]
		if c.Location != "" {
			if abs, err := filepath.Abs(c.Location); err == nil {
				sourceFiles[abs] = true
			}
		}
	}

	for _, root := range opts.Roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // unreadable entry: skip, don't abort the whole walk
			}
			if d.IsDir() {
				if skipDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Size() == 0 || info.Size() > opts.MaxFileSize {
				return nil
			}
			abs, _ := filepath.Abs(path)
			if sourceFiles[abs] {
				return nil // don't report a credential's own file as a consumer
			}
			scanFile(path, creds, markersByCred, out)
			return nil
		})
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// scanFile reads one file read-only and records marker hits into out.
func scanFile(path string, creds []discover.Credential, markersByCred [][]string, out []CredConsumers) {
	f, err := os.Open(path) // read-only
	if err != nil {
		return
	}
	defer f.Close()

	r := bufio.NewReader(f)
	// Binary sniff: if the first chunk holds a NUL byte, treat as binary and skip.
	head, _ := r.Peek(512)
	if bytes.IndexByte(head, 0) >= 0 {
		return
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		for i := range creds {
			for _, m := range markersByCred[i] {
				if containsToken(line, m) {
					out[i].Hits = append(out[i].Hits, Hit{File: path, Line: lineNo, Marker: m})
				}
			}
		}
	}
}

// containsToken reports whether marker appears in line bounded by non-identifier
// characters (so API_TOKEN matches ${API_TOKEN} but not MY_API_TOKEN_EXTRA).
func containsToken(line, marker string) bool {
	from := 0
	for {
		i := strings.Index(line[from:], marker)
		if i < 0 {
			return false
		}
		i += from
		leftOK := i == 0 || !isIdentByte(line[i-1])
		end := i + len(marker)
		rightOK := end == len(line) || !isIdentByte(line[end])
		if leftOK && rightOK {
			return true
		}
		from = i + 1
	}
}

func isIdentByte(b byte) bool {
	return b == '_' || b == '.' || // '.' so hostnames stay whole
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// Markers derives the non-secret search tokens for a credential from its
// Identity and Meta. It NEVER touches the secret value. Redacted fields (those
// containing '*') are skipped wholesale so masked key-ids don't leak partial
// tokens. A token qualifies if it is env-var-like (has '_', len>=4), an
// all-caps identifier (len>=6), or a hostname (contains '.').
func Markers(c discover.Credential) []string {
	seen := map[string]bool{}
	var out []string
	add := func(tok string) {
		if tok != "" && !seen[tok] {
			seen[tok] = true
			out = append(out, tok)
		}
	}

	consider := func(field string) {
		if strings.ContainsRune(field, '*') {
			return // redacted — skip the whole field
		}
		for _, tok := range tokenize(field) {
			if qualifies(tok) {
				add(tok)
			}
		}
	}

	consider(c.Identity)
	for _, v := range c.Meta {
		consider(v)
	}
	return out
}

// tokenize splits on runs of non-identifier characters, keeping '.' inside a
// token so hostnames survive.
func tokenize(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return !(r == '_' || r == '.' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
	})
}

func qualifies(tok string) bool {
	if !strings.ContainsFunc(tok, func(r rune) bool {
		return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
	}) {
		return false // need at least one letter
	}
	if strings.Contains(tok, "_") && len(tok) >= 4 {
		return true // env-var style: API_TOKEN, AWS_ACCESS_KEY_ID
	}
	if strings.Contains(tok, ".") && len(tok) >= 4 &&
		!strings.HasPrefix(tok, ".") && !strings.HasSuffix(tok, ".") {
		return true // hostname: github.com (but not a dotfile like .env)
	}
	if len(tok) >= 6 && tok == strings.ToUpper(tok) {
		return true // all-caps identifier: SENDGRID
	}
	return false
}
