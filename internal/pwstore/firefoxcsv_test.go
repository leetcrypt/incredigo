package pwstore

import (
	"context"
	"os"
	"strings"
	"testing"

	"incredigo/internal/vault"
)

func TestFirefoxExportFromCSV(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	// Firefox export header order differs from Chrome; colsFromHeader maps by name.
	path := writeTempCSV(t,
		"url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\n"+
			"https://github.com/login,alice@example.com,old1,,https://github.com,{g1},0,0,0\n")
	f := &FirefoxCSV{ExportPath: path}

	if !f.Available() {
		t.Fatal("Available should be true when export file exists")
	}
	accts, err := f.Export(context.Background(), v)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if len(accts) != 1 {
		t.Fatalf("got %d accounts, want 1", len(accts))
	}
	if accts[0].Site != "github.com" || accts[0].Username != "alice@example.com" {
		t.Errorf("account = %+v", accts[0])
	}
	if pw := handleStr(t, v, accts[0].Secret); pw != "old1" {
		t.Errorf("password = %q, want old1", pw)
	}
}

func TestFirefoxBareImportRefuses(t *testing.T) {
	f := &FirefoxCSV{}
	if err := f.Import(context.Background(), vault.New(), nil); err == nil {
		t.Error("bare Import must refuse and direct callers to ImportStaged")
	}
}

func TestFirefoxImportStagedFirefoxLayout(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	f := &FirefoxCSV{}
	accts := []Account{
		{URL: "https://a.test/", Username: "u1", Secret: v.Store([]byte("old1")), Meta: map[string]string{"name": "A"}},
	}
	newPw := map[int]*vault.Handle{0: v.Store([]byte("NEW-ff-1"))}

	path, cleanup, err := f.ImportStaged(v, accts, newPw)
	if err != nil {
		t.Fatalf("ImportStaged: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read staged csv: %v", err)
	}
	s := string(raw)
	if !strings.HasPrefix(s, "url,username,password") {
		t.Errorf("staged csv should use Firefox header:\n%s", s)
	}
	if !strings.Contains(s, "NEW-ff-1") {
		t.Errorf("staged csv missing new password:\n%s", s)
	}
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("staged csv should be shredded+removed, stat err = %v", err)
	}
}
