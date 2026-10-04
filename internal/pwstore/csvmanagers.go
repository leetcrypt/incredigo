package pwstore

import (
	"context"
	"fmt"
	"os"

	"incredigo/internal/vault"
)

// csvManager is the shared adapter for every password manager / browser whose ONLY
// supported propagation path is a plaintext CSV the user re-imports by hand. It is the
// generalization of the Chrome/Firefox staging path (docs/BROWSER-ROTATION.md §3) to the
// rest of the CSV-import field (LastPass, Dashlane, Proton Pass, NordPass, RoboForm,
// Safari, Edge, Brave, …): read = the CSV the user exported; write = a tmpfs CSV in that
// manager's own import column layout, securely shredded after re-import, gated behind the
// caller's --allow-csv opt-in. No plaintext secret ever rests on stable storage (hard
// rule 3) — identical guarantees to ChromeCSV/FirefoxCSV, just data-driven by layout.
//
// Each backend differs ONLY in (1) its name, (2) the column layout its import expects, and
// (3) the reimport hint (where the human pastes the file). Export uses the shared,
// header-name-driven parseLoginCSV, so one type serves them all. A manager with no clean
// CSV import (e.g. Enpass, whose import is JSON) registers with a nil layout: it is
// read/guide-only and ImportStaged refuses with a pointer to the guided worklist.
type csvManager struct {
	name     string
	layout   csvLayout // import layout; record==nil => CSV import unsupported (read-only)
	reimport string    // human instruction: where to re-import the staged CSV

	// ExportPath is the CSV the user exported from this manager (read side). Optional;
	// if empty, Export returns an error and Available() is false.
	ExportPath string
	importPath string // last staged path written by ImportStaged
}

// csvManagerSpec is one backend's import layout + reimport hint, keyed by name.
type csvManagerSpec struct {
	layout   csvLayout
	reimport string
}

// csvManagerSpecs is the table of CSV-based backends. Adding a manager is one entry here
// (and, if its export header uses new column names, an alias in colsFromHeader).
var csvManagerSpecs = map[string]csvManagerSpec{
	// Chromium browsers re-import Chrome's exact CSV shape.
	"edge":  {chromeLayout, "re-import at edge://wallet/passwords/settings ▸ Import"},
	"brave": {chromeLayout, "re-import at brave://password-manager/passwords ▸ Import"},

	"lastpass":   {lastpassLayout, "import at LastPass ▸ Advanced Options ▸ Import ▸ Generic CSV"},
	"dashlane":   {dashlaneLayout, "import at Dashlane ▸ My Account ▸ Import data ▸ CSV"},
	"protonpass": {protonLayout, "import at Proton Pass ▸ Settings ▸ Import ▸ CSV"},
	"nordpass":   {nordpassLayout, "import at NordPass ▸ Settings ▸ Import/Export ▸ CSV"},
	"roboform":   {roboformLayout, "import at RoboForm ▸ Options ▸ Account & Data ▸ Import"},
	"safari":     {safariLayout, "re-import in the macOS Passwords app ▸ File ▸ Import Passwords"},

	// Enpass imports via JSON, not CSV — read/guide-only here (nil layout).
	"enpass": {csvLayout{}, ""},
}

func init() {
	for name, spec := range csvManagerSpecs {
		Register(&csvManager{name: name, layout: spec.layout, reimport: spec.reimport})
	}
}

// NewCSV builds a configured CSV-based adapter for the named manager, reading from
// exportPath. It is the constructor the CLI uses (the registry singletons are zero-valued
// for listing only). Unknown names return an error so the caller can fall through.
func NewCSV(name, exportPath string) (Manager, error) {
	spec, ok := csvManagerSpecs[name]
	if !ok {
		return nil, fmt.Errorf("pwstore: %q is not a CSV-based manager", name)
	}
	return &csvManager{name: name, layout: spec.layout, reimport: spec.reimport, ExportPath: exportPath}, nil
}

// IsCSV reports whether name is a registered CSV-based manager.
func IsCSV(name string) bool {
	_, ok := csvManagerSpecs[name]
	return ok
}

func (c *csvManager) Name() string { return c.name }

// Available reports whether an export CSV was supplied and exists.
func (c *csvManager) Available() bool {
	if c.ExportPath == "" {
		return false
	}
	_, err := os.Stat(c.ExportPath)
	return err == nil
}

// Export reads the user-provided export CSV into Accounts (passwords land in the vault as
// handles). It never shreds the user's own export — that file is the user's to manage; we
// only own the file we ourselves write in ImportStaged.
func (c *csvManager) Export(ctx context.Context, v *vault.Vault) ([]Account, error) {
	if c.ExportPath == "" {
		return nil, fmt.Errorf("%s: no export CSV path set", c.name)
	}
	data, err := os.ReadFile(c.ExportPath)
	if err != nil {
		return nil, fmt.Errorf("%s: read export: %w", c.name, err)
	}
	return parseLoginCSV(v, data)
}

// ImportStaged materializes accts (carrying NEW passwords already swapped into Secret, or
// via newPw by index) as a CSV in this manager's import layout on tmpfs, returning its path
// plus a cleanup func the caller MUST defer after the human confirms re-import. A manager
// without a CSV import format refuses here and directs the user to the guided worklist.
func (c *csvManager) ImportStaged(v *vault.Vault, accts []Account, newPw map[int]*vault.Handle) (string, func(), error) {
	if c.layout.record == nil {
		return "", nil, fmt.Errorf("%s: no CSV import format — rotate via `incredigo passwords guide` (worklist + change-URLs) instead", c.name)
	}
	path, cleanup, err := writeShreddableCSVLayout(v, accts, newPw, c.layout)
	if err != nil {
		return "", nil, err
	}
	c.importPath = path
	return path, cleanup, nil
}

// ReimportHint returns the manager-specific instruction for where to re-import the staged
// CSV, so the commit path can tell the user exactly where to go.
func (c *csvManager) ReimportHint() string { return c.reimport }

// ---- per-manager import layouts (the read side is header-driven via colsFromHeader) ----

// LastPass "Generic CSV" import: url,username,password,totp,extra,name,grouping,fav.
var lastpassLayout = csvLayout{
	header: []string{"url", "username", "password", "totp", "extra", "name", "grouping", "fav"},
	record: func(a Account, pw string) []string {
		return []string{a.URL, a.Username, pw, "", a.Meta["note"], a.Meta["name"], a.Meta["group"], ""}
	},
}

// Dashlane CSV import: username,username2,username3,title,password,note,url,category,otpSecret.
var dashlaneLayout = csvLayout{
	header: []string{"username", "username2", "username3", "title", "password", "note", "url", "category", "otpSecret"},
	record: func(a Account, pw string) []string {
		return []string{a.Username, "", "", a.Meta["name"], pw, a.Meta["note"], a.URL, a.Meta["group"], ""}
	},
}

// Proton Pass CSV import: name,url,email,username,password,note,totp,vault. Proton keeps
// email and username separate; we map the resolved login into username and leave email blank.
var protonLayout = csvLayout{
	header: []string{"name", "url", "email", "username", "password", "note", "totp", "vault"},
	record: func(a Account, pw string) []string {
		return []string{a.Meta["name"], a.URL, "", a.Username, pw, a.Meta["note"], "", a.Meta["group"]}
	},
}

// NordPass CSV import: name,url,username,password,note,folder.
var nordpassLayout = csvLayout{
	header: []string{"name", "url", "username", "password", "note", "folder"},
	record: func(a Account, pw string) []string {
		return []string{a.Meta["name"], a.URL, a.Username, pw, a.Meta["note"], a.Meta["group"]}
	},
}

// RoboForm CSV import: Name,Url,MatchUrl,Login,Pwd,Note,Folder.
var roboformLayout = csvLayout{
	header: []string{"Name", "Url", "MatchUrl", "Login", "Pwd", "Note", "Folder"},
	record: func(a Account, pw string) []string {
		return []string{a.Meta["name"], a.URL, a.URL, a.Username, pw, a.Meta["note"], a.Meta["group"]}
	},
}

// Safari / macOS Passwords app CSV import: Title,URL,Username,Password,Notes,OTPAuth.
var safariLayout = csvLayout{
	header: []string{"Title", "URL", "Username", "Password", "Notes", "OTPAuth"},
	record: func(a Account, pw string) []string {
		return []string{a.Meta["name"], a.URL, a.Username, pw, a.Meta["note"], ""}
	},
}
