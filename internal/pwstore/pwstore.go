// Package pwstore holds the password-manager adapters and the shared helpers the
// browser/password-manager rotation path (docs/BROWSER-ROTATION.md) is built on.
//
// An adapter reads a user's own login store into the RAM vault (passwords as
// handles, never plaintext copies) and writes new passwords back. Two write
// shapes exist, matching the two manager families:
//
//   - ItemUpdater  — CLI managers (Bitwarden/1Password/KeePassXC) update ONE item
//     in place by id over stdin/stdout. No plaintext file is ever created. Preferred.
//   - BulkImporter — browser stores (Chrome/Firefox) have no import API; the only
//     path is a plaintext CSV the browser reads off disk. That path is flag-gated,
//     written to tmpfs, and securely shredded (see writeShreddableCSV / Shred).
//
// Adapters contain ONLY real code; a fake binary / temp CSV is the only thing a
// test injects, exactly like sink.Gopass{Bin:…} and the rotation drivers' HTTPClient.
package pwstore

import (
	"context"
	"sort"
	"strings"
	"sync"

	"incredigo/internal/vault"
)

// Account is a single login. The password is a vault handle — never plaintext.
type Account struct {
	ID       string            // manager-native item id / entry path ("" for CSV rows)
	Site     string            // hostname used for the change-password link
	URL      string            // full login URL if the store has one
	Username string            // login name / email
	Secret   *vault.Handle     // OLD password, in the RAM vault
	Meta     map[string]string // non-secret extras (folder, title, …)
}

// Manager is the read side every adapter implements.
type Manager interface {
	Name() string
	// Available reports whether the backend exists on this machine (CLI installed
	// / export file present), so callers can skip cleanly rather than erroring.
	Available() bool
	// Export reads all logins into v, storing each password as a handle.
	Export(ctx context.Context, v *vault.Vault) ([]Account, error)
}

// ItemUpdater is implemented by CLI managers that can update one item in place by
// id without ever materializing a plaintext file. This is the safe write path.
type ItemUpdater interface {
	UpdatePassword(ctx context.Context, v *vault.Vault, acct Account, newPassword *vault.Handle) error
}

// BulkImporter is implemented by browser-CSV stores that can only re-import the
// whole store. Import MUST go through writeShreddableCSV (tmpfs + shred) and be
// gated behind the caller's explicit --allow-csv opt-in.
type BulkImporter interface {
	Import(ctx context.Context, v *vault.Vault, accts []Account) error
}

var (
	regMu    sync.Mutex
	registry = map[string]Manager{}
)

// Register adds a manager adapter to the global registry. Call from init().
func Register(m Manager) {
	regMu.Lock()
	defer regMu.Unlock()
	registry[m.Name()] = m
}

// Managers returns registered adapters sorted by name; if names is non-empty only
// those are returned.
func Managers(names ...string) []Manager {
	regMu.Lock()
	defer regMu.Unlock()
	var out []Manager
	if len(names) == 0 {
		for _, m := range registry {
			out = append(out, m)
		}
	} else {
		for _, n := range names {
			if m, ok := registry[n]; ok {
				out = append(out, m)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// Lookup returns a single registered adapter by name.
func Lookup(name string) (Manager, bool) {
	regMu.Lock()
	defer regMu.Unlock()
	m, ok := registry[name]
	return m, ok
}

// RedactIdentity builds a non-secret "site / us…@…" label for the audit log and
// worklist. It never includes the password. The username is partially masked so a
// full email/login is not echoed into a file.
func RedactIdentity(a Account) string {
	site := a.Site
	if site == "" {
		site = hostFromURL(a.URL)
	}
	user := maskUser(a.Username)
	switch {
	case site != "" && user != "":
		return site + " / " + user
	case site != "":
		return site
	case user != "":
		return user
	default:
		return "(unknown login)"
	}
}

// maskUser keeps the first character and the domain (for emails), masking the rest:
// "alice@example.com" -> "a…@example.com"; "alice" -> "a…".
func maskUser(u string) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return ""
	}
	if at := strings.LastIndexByte(u, '@'); at > 0 {
		local := u[:at]
		domain := u[at:] // includes '@'
		return firstRune(local) + "…" + domain
	}
	return firstRune(u) + "…"
}

func firstRune(s string) string {
	for _, r := range s {
		return string(r)
	}
	return ""
}

// hostFromURL extracts a bare host from a login URL for labeling/links, without a
// net/url import dependency for the common cases.
func hostFromURL(raw string) string {
	h := strings.TrimSpace(raw)
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimPrefix(h, "http://")
	if i := strings.IndexByte(h, '/'); i >= 0 {
		h = h[:i]
	}
	if i := strings.IndexByte(h, '@'); i >= 0 { // strip any userinfo
		h = h[i+1:]
	}
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return strings.ToLower(h)
}
