package pwstore

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"incredigo/internal/vault"
)

func writeTempCSV(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "chrome-export.csv")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestChromeExportFromCSV(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	path := writeTempCSV(t,
		"name,url,username,password,note\n"+
			"GitHub,https://github.com/login,alice@example.com,old1,\n"+
			"App,https://app.example.com/,bob,old2,\n")
	c := &ChromeCSV{ExportPath: path}

	if !c.Available() {
		t.Fatal("Available should be true when export file exists")
	}
	accts, err := c.Export(context.Background(), v)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if len(accts) != 2 {
		t.Fatalf("got %d accounts, want 2", len(accts))
	}
	if accts[0].Site != "github.com" {
		t.Errorf("site = %q", accts[0].Site)
	}
	if pw := handleStr(t, v, accts[0].Secret); pw != "old1" {
		t.Errorf("password = %q, want old1", pw)
	}
}

func TestChromeUnavailableWithoutPath(t *testing.T) {
	c := &ChromeCSV{}
	if c.Available() {
		t.Error("Available should be false with no export path")
	}
	if _, err := c.Export(context.Background(), vault.New()); err == nil {
		t.Error("Export should error with no export path")
	}
}

func TestChromeBareImportRefuses(t *testing.T) {
	c := &ChromeCSV{}
	if err := c.Import(context.Background(), vault.New(), nil); err == nil {
		t.Error("bare Import must refuse and direct callers to ImportStaged")
	}
}

func TestChromeImportStagedWritesThenShreds(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	c := &ChromeCSV{}
	accts := []Account{
		{URL: "https://a.test/", Username: "u1", Secret: v.Store([]byte("old1")), Meta: map[string]string{"name": "A"}},
		{URL: "https://b.test/", Username: "u2", Secret: v.Store([]byte("old2")), Meta: map[string]string{"name": "B"}},
	}
	newPw := map[int]*vault.Handle{0: v.Store([]byte("NEW-1"))}

	path, cleanup, err := c.ImportStaged(v, accts, newPw)
	if err != nil {
		t.Fatalf("ImportStaged: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read staged csv: %v", err)
	}
	s := string(raw)
	if !strings.Contains(s, "NEW-1") {
		t.Errorf("staged csv missing substituted new password:\n%s", s)
	}
	if !strings.Contains(s, "old2") {
		t.Errorf("staged csv missing untouched second password:\n%s", s)
	}
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("staged csv should be shredded+removed after cleanup, stat err = %v", err)
	}
}
