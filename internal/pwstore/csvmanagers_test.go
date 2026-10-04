package pwstore

import (
	"context"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"incredigo/internal/vault"
)

// writeCSV writes body to a temp file and returns its path.
func writeCSV(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestColsFromHeaderAliases proves the new header aliases resolve the right columns so
// each manager's export parses without a bespoke parser.
func TestColsFromHeaderAliases(t *testing.T) {
	cases := []struct {
		name   string
		header []string
		// expected resolved indices (-1 if absent)
		user, pass, note, group int
	}{
		{"roboform", []string{"Name", "Url", "MatchUrl", "Login", "Pwd", "Note", "Folder"}, 3, 4, 5, 6},
		{"lastpass", []string{"url", "username", "password", "totp", "extra", "name", "grouping", "fav"}, 1, 2, 4, 6},
		{"dashlane", []string{"username", "title", "password", "note", "url", "category"}, 0, 2, 3, 5},
		{"nordpass", []string{"name", "url", "username", "password", "note", "folder"}, 2, 3, 4, 5},
		{"proton", []string{"name", "url", "email", "username", "password", "note", "vault"}, 3, 4, 5, 6},
	}
	for _, c := range cases {
		got := colsFromHeader(c.header)
		if got.username != c.user || got.password != c.pass || got.note != c.note || got.group != c.group {
			t.Errorf("%s: cols=%+v want user=%d pass=%d note=%d group=%d",
				c.name, got, c.user, c.pass, c.note, c.group)
		}
	}
}

// TestCSVManagerExportParsesAliases reads a representative export for each manager and
// asserts the login fields (incl. note via Meta) come through, with the password as a
// vault handle.
func TestCSVManagerExportParsesAliases(t *testing.T) {
	v := vault.New()
	defer v.Purge()

	cases := []struct {
		mgr, file, body string
	}{
		{"roboform", "rf.csv",
			"Name,Url,MatchUrl,Login,Pwd,Note,Folder\n" +
				"GitHub,https://github.com/,https://github.com/,alice@example.com,old1,my note,Dev\n"},
		{"lastpass", "lp.csv",
			"url,username,password,totp,extra,name,grouping,fav\n" +
				"https://github.com/,alice@example.com,old1,,my note,GitHub,Dev,0\n"},
		{"protonpass", "pp.csv",
			"name,url,email,username,password,note,totp,vault\n" +
				"GitHub,https://github.com/,alice@personal.com,alice@example.com,old1,my note,,Personal\n"},
	}
	for _, c := range cases {
		path := writeCSV(t, c.file, c.body)
		m, err := NewCSV(c.mgr, path)
		if err != nil {
			t.Fatalf("%s: NewCSV: %v", c.mgr, err)
		}
		if !m.Available() {
			t.Errorf("%s: Available should be true with an existing export", c.mgr)
		}
		accts, err := m.Export(context.Background(), v)
		if err != nil {
			t.Fatalf("%s: Export: %v", c.mgr, err)
		}
		if len(accts) != 1 {
			t.Fatalf("%s: got %d accounts, want 1", c.mgr, len(accts))
		}
		a := accts[0]
		if a.Site != "github.com" {
			t.Errorf("%s: site = %q, want github.com", c.mgr, a.Site)
		}
		if a.Username != "alice@example.com" {
			t.Errorf("%s: username = %q (alias must resolve the login column, not email)", c.mgr, a.Username)
		}
		if a.Meta["note"] != "my note" {
			t.Errorf("%s: note = %q, want preserved 'my note'", c.mgr, a.Meta["note"])
		}
		if pw := handleStr(t, v, a.Secret); pw != "old1" {
			t.Errorf("%s: password = %q, want old1", c.mgr, pw)
		}
	}
}

// TestCSVManagerImportStagedLayout proves each manager's staged CSV uses ITS import header,
// carries the substituted NEW password, preserves name/group/note, lands on tmpfs, and is
// shredded on cleanup.
func TestCSVManagerImportStagedLayout(t *testing.T) {
	v := vault.New()
	defer v.Purge()

	accts := []Account{{
		URL:      "https://github.com/",
		Username: "alice@example.com",
		Secret:   v.Store([]byte("OLD")),
		Meta:     map[string]string{"name": "GitHub", "group": "Dev", "note": "my note"},
	}}
	newPw := map[int]*vault.Handle{0: v.Store([]byte("NEW-PASS-1"))}

	wantHeader := map[string][]string{
		"lastpass":   {"url", "username", "password", "totp", "extra", "name", "grouping", "fav"},
		"dashlane":   {"username", "username2", "username3", "title", "password", "note", "url", "category", "otpSecret"},
		"protonpass": {"name", "url", "email", "username", "password", "note", "totp", "vault"},
		"nordpass":   {"name", "url", "username", "password", "note", "folder"},
		"roboform":   {"Name", "Url", "MatchUrl", "Login", "Pwd", "Note", "Folder"},
		"safari":     {"Title", "URL", "Username", "Password", "Notes", "OTPAuth"},
		"edge":       {"name", "url", "username", "password", "note"},
		"brave":      {"name", "url", "username", "password", "note"},
	}

	for mgr, hdr := range wantHeader {
		m, err := NewCSV(mgr, "ignored")
		if err != nil {
			t.Fatalf("%s: NewCSV: %v", mgr, err)
		}
		si, ok := m.(StagedImporter)
		if !ok {
			t.Fatalf("%s: not a StagedImporter", mgr)
		}
		path, cleanup, err := si.ImportStaged(v, accts, newPw)
		if err != nil {
			t.Fatalf("%s: ImportStaged: %v", mgr, err)
		}
		if !strings.HasPrefix(path, "/dev/shm/") && !strings.Contains(path, "incredigo") {
			t.Errorf("%s: staged path %q not under a tmpfs/incredigo dir", mgr, path)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: read staged: %v", mgr, err)
		}
		recs, err := csv.NewReader(strings.NewReader(string(raw))).ReadAll()
		if err != nil {
			t.Fatalf("%s: parse staged: %v", mgr, err)
		}
		if len(recs) < 2 {
			t.Fatalf("%s: staged csv has no data row:\n%s", mgr, raw)
		}
		if strings.Join(recs[0], ",") != strings.Join(hdr, ",") {
			t.Errorf("%s: header = %v, want %v", mgr, recs[0], hdr)
		}
		row := strings.Join(recs[1], ",")
		if !strings.Contains(row, "NEW-PASS-1") {
			t.Errorf("%s: row missing new password:\n%s", mgr, row)
		}
		if strings.Contains(row, "OLD") {
			t.Errorf("%s: row must carry the NEW password, not OLD:\n%s", mgr, row)
		}
		if !strings.Contains(row, "GitHub") {
			t.Errorf("%s: row dropped the entry name:\n%s", mgr, row)
		}
		if !strings.Contains(row, "my note") {
			t.Errorf("%s: row dropped the note (round-trip would wipe it):\n%s", mgr, row)
		}
		cleanup()
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s: staged csv not shredded after cleanup: %v", mgr, err)
		}
	}
}

// TestEnpassImportRefuses proves a manager with no CSV import format refuses ImportStaged
// and points at the guided worklist, while still being readable for the guide.
func TestEnpassImportRefuses(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	m, err := NewCSV("enpass", "ignored")
	if err != nil {
		t.Fatalf("NewCSV enpass: %v", err)
	}
	si := m.(StagedImporter)
	if _, _, err := si.ImportStaged(v, []Account{{Secret: v.Store([]byte("x"))}}, nil); err == nil {
		t.Error("enpass ImportStaged must refuse (no CSV import format)")
	}
}

// TestReimportHint proves the manager-specific re-import instruction is exposed.
func TestReimportHint(t *testing.T) {
	m, _ := NewCSV("lastpass", "x")
	r, ok := m.(Reimporter)
	if !ok {
		t.Fatal("csv manager should implement Reimporter")
	}
	if !strings.Contains(strings.ToLower(r.ReimportHint()), "lastpass") {
		t.Errorf("reimport hint = %q, want a LastPass-specific instruction", r.ReimportHint())
	}
}

// TestNewCSVUnknownRejected proves an unknown name is rejected so the CLI can fall through.
func TestNewCSVUnknownRejected(t *testing.T) {
	if _, err := NewCSV("nonsense", "x"); err == nil {
		t.Error("NewCSV must reject an unknown manager name")
	}
	if IsCSV("bitwarden") {
		t.Error("bitwarden is a CLI manager, not a CSV one")
	}
	if !IsCSV("lastpass") {
		t.Error("lastpass should be a CSV manager")
	}
}
