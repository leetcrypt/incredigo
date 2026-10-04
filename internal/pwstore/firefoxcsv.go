package pwstore

import (
	"context"
	"fmt"
	"os"

	"incredigo/internal/vault"
)

// FirefoxCSV adapts Firefox's about:logins store. Like Chrome it has no programmatic
// import API — the only path is the CSV the user re-imports through about:logins —
// so it is a BulkImporter routed through the same tmpfs + shred staging, gated behind
// the caller's --allow-csv opt-in (hard rule 3). The only difference from Chrome is
// the import column layout (Firefox keys on url/username/password), handled by
// firefoxLayout.
type FirefoxCSV struct {
	ExportPath string // CSV the user exported from Firefox (read side)
	importPath string // last staged path, for the "now re-import this" instruction
}

func init() { Register(&FirefoxCSV{}) }

func (f *FirefoxCSV) Name() string { return "firefox" }

// Available reports whether a Firefox export CSV was supplied to read from.
func (f *FirefoxCSV) Available() bool {
	if f.ExportPath == "" {
		return false
	}
	_, err := os.Stat(f.ExportPath)
	return err == nil
}

// Export reads the user-provided Firefox export CSV into Accounts. Firefox's export
// header (url,username,password,…) is resolved by name in colsFromHeader, so the
// shared parseLoginCSV handles it unchanged.
func (f *FirefoxCSV) Export(ctx context.Context, v *vault.Vault) ([]Account, error) {
	if f.ExportPath == "" {
		return nil, fmt.Errorf("firefox: no export CSV path set")
	}
	data, err := os.ReadFile(f.ExportPath)
	if err != nil {
		return nil, fmt.Errorf("firefox: read export: %w", err)
	}
	return parseLoginCSV(v, data)
}

// Import refuses for the same reason as Chrome: a bare Import would shred the staged
// CSV before the human re-imports it. Use ImportStaged.
func (f *FirefoxCSV) Import(ctx context.Context, v *vault.Vault, accts []Account) error {
	return fmt.Errorf("firefox: use ImportStaged — a bare Import would shred the CSV before the browser re-reads it")
}

// ImportStaged writes the new-password CSV (Firefox layout) to tmpfs and returns its
// path plus a cleanup func the caller MUST defer after the human confirms re-import.
func (f *FirefoxCSV) ImportStaged(v *vault.Vault, accts []Account, newPw map[int]*vault.Handle) (path string, cleanup func(), err error) {
	path, cleanup, err = writeShreddableCSVLayout(v, accts, newPw, firefoxLayout)
	if err != nil {
		return "", nil, err
	}
	f.importPath = path
	return path, cleanup, nil
}
