package pwstore

import (
	"os"
	"strings"
	"testing"

	"incredigo/internal/vault"
)

func handleStr(t *testing.T, v *vault.Vault, h *vault.Handle) string {
	t.Helper()
	buf, err := v.Open(h)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return string(buf.Bytes())
}

func TestParseLoginCSVChrome(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	data := []byte("name,url,username,password,note\n" +
		"GitHub,https://github.com/login,alice@example.com,s3cr3t-old,\n" +
		"Example,https://app.example.com/,bob,hunter2,a note\n")
	accts, err := parseLoginCSV(v, data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(accts) != 2 {
		t.Fatalf("got %d accounts, want 2", len(accts))
	}
	if accts[0].Site != "github.com" || accts[0].Username != "alice@example.com" {
		t.Errorf("account0 = %+v", accts[0])
	}
	if pw := handleStr(t, v, accts[0].Secret); pw != "s3cr3t-old" {
		t.Errorf("account0 password = %q", pw)
	}
	if accts[1].Site != "app.example.com" || accts[1].Meta["name"] != "Example" {
		t.Errorf("account1 = %+v", accts[1])
	}
}

func TestParseLoginCSVNoPasswordColumn(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	if _, err := parseLoginCSV(v, []byte("name,url,username\nx,y,z\n")); err == nil {
		t.Error("expected error when csv has no password column")
	}
}

func TestRedactIdentity(t *testing.T) {
	cases := []struct{ site, url, user, want string }{
		{"github.com", "", "alice@example.com", "github.com / a…@example.com"},
		{"", "https://app.example.com/login", "bob", "app.example.com / b…"},
		{"site.test", "", "", "site.test"},
		{"", "", "", "(unknown login)"},
	}
	for _, c := range cases {
		got := RedactIdentity(Account{Site: c.site, URL: c.url, Username: c.user})
		if got != c.want {
			t.Errorf("RedactIdentity(%q,%q,%q) = %q, want %q", c.site, c.url, c.user, got, c.want)
		}
	}
}

func TestRedactIdentityNeverLeaksPassword(t *testing.T) {
	// The password is not even a field RedactIdentity sees, but assert the label
	// for a realistic account contains no secret-looking material beyond masked user.
	id := RedactIdentity(Account{Site: "bank.test", Username: "verylongusername@mail.test"})
	if strings.Contains(id, "verylongusername") {
		t.Errorf("identity %q leaked the full username", id)
	}
}

func TestWriteShreddableCSVAndShred(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	accts := []Account{
		{URL: "https://a.test/", Username: "u1", Secret: v.Store([]byte("old1")), Meta: map[string]string{"name": "A"}},
		{URL: "https://b.test/", Username: "u2", Secret: v.Store([]byte("old2")), Meta: map[string]string{"name": "B"}},
	}
	newPw := map[int]*vault.Handle{0: v.Store([]byte("NEW-pw-1"))}

	path, cleanup, err := writeShreddableCSV(v, accts, newPw)
	if err != nil {
		t.Fatalf("writeShreddableCSV: %v", err)
	}
	// Read it back BEFORE shred to confirm new pw substituted, old kept where absent.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	s := string(raw)
	if !strings.Contains(s, "NEW-pw-1") {
		t.Errorf("csv missing substituted new password:\n%s", s)
	}
	if !strings.Contains(s, "old2") {
		t.Errorf("csv missing untouched old password for second account:\n%s", s)
	}
	if !strings.HasPrefix(s, "name,url,username,password,note") {
		t.Errorf("csv header wrong:\n%s", s)
	}

	cleanup() // shred + remove
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected file removed after shred, stat err = %v", err)
	}
}

func TestShredMissingFileNoError(t *testing.T) {
	if err := Shred("/dev/shm/incredigo/does-not-exist-xyz.csv"); err != nil {
		t.Errorf("Shred of missing file should be nil, got %v", err)
	}
}
