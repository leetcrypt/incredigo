// Package discover holds the read-only credential scanners and their registry.
//
// Each scanner understands exactly one location/format, never modifies the files
// it reads, and emits Credential records whose secret value is a handle into the
// RAM vault — never a plaintext copy.
package discover

import (
	"context"
	"sort"
	"sync"
	"time"

	"incredigo/internal/vault"
)

// Kind classifies a credential for policy and pathing purposes.
type Kind string

const (
	KindAWSKey     Kind = "aws_key"
	KindToken      Kind = "token"
	KindPassword   Kind = "password"
	KindPrivateKey Kind = "private_key"
)

// Credential is a normalized, non-secret-bearing record. The actual secret is
// referenced by Secret (a vault handle); nothing here should ever be a plaintext
// secret. Identity must be pre-redacted (e.g. "default / AKIA…REDACTED").
type Credential struct {
	Source   string            // scanner name, e.g. "aws"
	Kind     Kind              // classification
	Identity string            // non-secret label
	Location string            // file the cred came from
	Modified time.Time         // source mtime — input to expiry policy
	Secret   *vault.Handle     // opaque handle into the RAM vault
	Meta     map[string]string // non-secret extras
}

// Scanner is the single interface a source must implement. Add a source by
// dropping one new file in this package that Registers a Scanner in init().
type Scanner interface {
	Name() string
	// Available reports whether this source exists on the current machine, so we
	// can skip cleanly rather than erroring on absent files.
	Available() bool
	// Scan reads the source read-only and stores any secrets in v, returning
	// metadata records that reference them.
	Scan(ctx context.Context, v *vault.Vault) ([]Credential, error)
}

var (
	regMu    sync.Mutex
	registry = map[string]Scanner{}
)

// Register adds a scanner to the global registry. Call from a scanner's init().
func Register(s Scanner) {
	regMu.Lock()
	defer regMu.Unlock()
	registry[s.Name()] = s
}

// Scanners returns all registered scanners sorted by name. If names is non-empty,
// only those are returned (unknown names are silently ignored by the caller's
// filtering; use Lookup if you need to detect unknown names).
func Scanners(names ...string) []Scanner {
	regMu.Lock()
	defer regMu.Unlock()

	var out []Scanner
	if len(names) == 0 {
		for _, s := range registry {
			out = append(out, s)
		}
	} else {
		for _, n := range names {
			if s, ok := registry[n]; ok {
				out = append(out, s)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// ScanAll runs the selected (or all) available scanners and aggregates results.
func ScanAll(ctx context.Context, v *vault.Vault, names ...string) ([]Credential, error) {
	var all []Credential
	for _, s := range Scanners(names...) {
		if !s.Available() {
			continue
		}
		creds, err := s.Scan(ctx, v)
		if err != nil {
			return all, err
		}
		all = append(all, creds...)
	}
	return all, nil
}
