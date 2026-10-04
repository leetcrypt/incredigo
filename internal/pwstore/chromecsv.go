package pwstore

import (
	"context"
	"fmt"
	"os"

	"incredigo/internal/vault"
)

// ChromeCSV adapts a Chromium-family browser's password store, which has no
// programmatic import API: the ONLY supported propagation path is a plaintext CSV
// the user re-imports through chrome://password-manager/settings. That makes this a
// BulkImporter, not an ItemUpdater — and the reason every write here is forced
// through writeShreddableCSV (tmpfs + secure shred) and gated behind the caller's
// explicit --allow-csv opt-in (hard rule 3: no plaintext secret rests on disk).
//
// Read side: ExportFile parses a CSV the user exported from the browser. We never
// drive the browser to produce it — the human does the export/import; we only do the
// generate-and-stage work in between. Firefox uses the same shape (see firefoxcsv.go).
type ChromeCSV struct {
	// ExportPath is the CSV the user exported from Chrome (read side). Optional; if
	// empty, Export returns no accounts and Available() is false.
	ExportPath string
	// importDir, when set (tests), overrides where the shreddable CSV is written so a
	// test can inspect it before cleanup. Production uses tmpfs via writeShreddableCSV.
	importPath string // last path written by Import, for the caller's "now re-import this" instruction
}

func init() { Register(&ChromeCSV{}) }

func (c *ChromeCSV) Name() string { return "chrome" }

// Available reports whether a Chrome export CSV was supplied to read from.
func (c *ChromeCSV) Available() bool {
	if c.ExportPath == "" {
		return false
	}
	_, err := os.Stat(c.ExportPath)
	return err == nil
}

// Export reads the user-provided Chrome export CSV into Accounts (passwords land in
// the vault as handles). It does NOT shred the user's own export — that file is the
// user's to manage; we only own the file we ourselves write in Import.
func (c *ChromeCSV) Export(ctx context.Context, v *vault.Vault) ([]Account, error) {
	if c.ExportPath == "" {
		return nil, fmt.Errorf("chrome: no export CSV path set")
	}
	data, err := os.ReadFile(c.ExportPath)
	if err != nil {
		return nil, fmt.Errorf("chrome: read export: %w", err)
	}
	return parseLoginCSV(v, data)
}

// Import is the propagation path: it materializes accts (carrying their NEW
// passwords already swapped into Secret) as a Chrome-format CSV on tmpfs and IMMEDIATELY
// schedules its secure shred. The path is recorded so the caller can tell the human
// exactly which file to re-import; the cleanup MUST be deferred by the caller via
// ImportStaged, which is the only supported entry point (raw Import here would shred
// before the human re-imports). Hence Import itself returns an error directing callers
// to ImportStaged.
func (c *ChromeCSV) Import(ctx context.Context, v *vault.Vault, accts []Account) error {
	return fmt.Errorf("chrome: use ImportStaged — a bare Import would shred the CSV before the browser re-reads it")
}

// ImportStaged writes the new-password CSV to tmpfs and returns its path plus a
// cleanup func the caller MUST defer. Workflow: write → tell the human to open
// chrome://password-manager/settings and re-import this exact path → human confirms →
// caller invokes cleanup() to shred. newPw maps account index → new-password handle
// (indices without an entry keep their existing Secret untouched).
func (c *ChromeCSV) ImportStaged(v *vault.Vault, accts []Account, newPw map[int]*vault.Handle) (path string, cleanup func(), err error) {
	path, cleanup, err = writeShreddableCSV(v, accts, newPw)
	if err != nil {
		return "", nil, err
	}
	c.importPath = path
	return path, cleanup, nil
}
