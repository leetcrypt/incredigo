package discover

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"incredigo/internal/vault"
)

// maxHarvestFileSize bounds how large a file the "file" scanner will slurp as a
// single credential. Credential material (keys, tokens, service-account JSON) is
// small; this keeps an accidental directory of large blobs from being vaulted.
const maxHarvestFileSize = 1 << 20 // 1 MiB

var fileSingleton = &fileScanner{}

func init() { Register(fileSingleton) }

// AddPath registers an extra file or directory for the "file" scanner to harvest.
// Call before ScanAll — the CLI does this for each --path. A directory is walked
// recursively; a single file is harvested directly.
func AddPath(p string) {
	if p != "" {
		fileSingleton.targets = append(fileSingleton.targets, p)
	}
}

// ClearPaths drops all registered --path targets. The CLI is one-shot so it never
// needs this, but a long-lived process (notably a test binary invoking the CLI many
// times) must reset between runs or the singleton accumulates stale, since-removed
// paths and the scanner errors on the first vanished target.
func ClearPaths() { fileSingleton.targets = nil }

// fileScanner harvests whole files as credentials from user-supplied paths. Unlike
// the format-specific scanners (aws, env, …), it does no field parsing: each
// regular, non-empty, reasonably-sized file becomes ONE Credential whose secret is
// the file's entire contents — the natural fit for "point me at a directory of
// credential files and take them all." Strictly read-only.
type fileScanner struct{ targets []string }

func (f *fileScanner) Name() string { return "file" }

func (f *fileScanner) Available() bool { return len(f.targets) > 0 }

func (f *fileScanner) Scan(ctx context.Context, v *vault.Vault) ([]Credential, error) {
	var creds []Credential
	for _, t := range f.targets {
		info, err := os.Stat(t)
		if err != nil {
			return creds, fmt.Errorf("file scanner: %q: %w", t, err)
		}
		if !info.IsDir() {
			if c, ok := f.harvest(v, t, filepath.Dir(t)); ok {
				creds = append(creds, c)
			}
			continue
		}
		// Directory: walk recursively, harvesting each regular file. Per-entry
		// errors (unreadable, vanished) are skipped so one bad file doesn't abort
		// the whole harvest.
		walkErr := filepath.WalkDir(t, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() || !d.Type().IsRegular() {
				return nil
			}
			if c, ok := f.harvest(v, p, t); ok {
				creds = append(creds, c)
			}
			return nil
		})
		if walkErr != nil {
			return creds, walkErr
		}
	}
	return creds, nil
}

// harvest reads one file and turns it into a Credential. root is the target the
// file was found under, used to build a stable relative Identity. Returns ok=false
// for empty, oversized, or unreadable files (silently skipped).
func (f *fileScanner) harvest(v *vault.Vault, path, root string) (Credential, bool) {
	info, err := os.Stat(path)
	if err != nil || info.Size() == 0 || info.Size() > maxHarvestFileSize {
		return Credential{}, false
	}
	b, err := os.ReadFile(path) // read-only
	if err != nil {
		return Credential{}, false
	}

	kind := classifyContent(b) // inspect bytes BEFORE Store wipes them
	svc := ServiceForSecret(b) // recognise provider prefix BEFORE Store wipes them
	rel, e := filepath.Rel(root, path)
	if e != nil {
		rel = filepath.Base(path)
	}
	var meta map[string]string
	if svc != "" {
		meta = map[string]string{MetaService: svc}
	}
	// Identity is the relative path (non-secret, never the contents). We do NOT
	// prefix the scanner name here — StorePath already prepends the source
	// segment, so a "file / " prefix would double it to imported/file/file/<rel>.
	return Credential{
		Source:   f.Name(),
		Kind:     kind,
		Identity: rel,
		Location: path,
		Modified: info.ModTime(),
		Secret:   v.Store(b), // copies into locked mem, wipes b
		Meta:     meta,
	}, true
}

// classifyContent guesses a Kind from the file's leading bytes WITHOUT turning the
// secret into a Go string (it inspects the byte slice in place).
func classifyContent(b []byte) Kind {
	head := b
	if len(head) > 256 {
		head = head[:256]
	}
	if bytes.Contains(head, []byte("PRIVATE KEY-----")) {
		return KindPrivateKey
	}
	return KindToken
}
