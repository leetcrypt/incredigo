package rotate

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

func TestAppSecretDetect(t *testing.T) {
	a := &AppSecret{}
	if !a.Detect(discover.Credential{Source: "appsecret"}) {
		t.Error("should detect Source=appsecret")
	}
	if a.Detect(discover.Credential{Source: "env"}) {
		t.Error("should not detect Source=env")
	}
}

// TestAppSecretRotateRewritesAllFiles proves the real local cutover: the literal old
// value is replaced by a fresh value in EVERY target file (atomic rewrite), the new
// blob carries the new value, and Verify confirms presence-of-new / absence-of-old.
func TestAppSecretRotateRewritesAllFiles(t *testing.T) {
	dir := t.TempDir()
	oldVal := "s3cret-signing-value-abcdefghijklmnop"

	// Two files share the same app signing secret (e.g. an app .env and a worker .env).
	envPath := filepath.Join(dir, ".env")
	ymlPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(envPath, []byte("PORT=8080\nSECRET_KEY="+oldVal+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ymlPath, []byte("service:\n  secret_key: "+oldVal+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	v := vault.New()
	defer v.Purge()
	blob := "appsecret://local/?" + url.Values{
		"key":  {"SECRET_KEY"},
		"val":  {oldVal},
		"path": {envPath, ymlPath},
	}.Encode()
	cred := discover.Credential{
		Source:   "appsecret",
		Identity: ".env / SECRET_KEY",
		Secret:   v.Store([]byte(blob)),
	}
	a := &AppSecret{}
	ctx := context.Background()

	newH, err := a.Rotate(ctx, cred, v)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	nb, _ := v.Open(newH)
	nu, _ := url.Parse(strings.TrimSpace(string(nb.Bytes())))
	newVal := nu.Query().Get("val")
	if newVal == "" || newVal == oldVal {
		t.Fatalf("blob carries no fresh value (got %q)", newVal)
	}

	// CUTOVER PROOF: both files now hold the new value and NOT the old one.
	for _, p := range []string{envPath, ymlPath} {
		b, _ := os.ReadFile(p)
		if !strings.Contains(string(b), newVal) {
			t.Errorf("%s missing new value after rotation", filepath.Base(p))
		}
		if strings.Contains(string(b), oldVal) {
			t.Errorf("%s still contains the OLD value after rotation", filepath.Base(p))
		}
	}

	// Untouched lines survive (atomic full-file rewrite, not truncation).
	eb, _ := os.ReadFile(envPath)
	if !strings.Contains(string(eb), "PORT=8080") {
		t.Error("unrelated config line lost during rewrite")
	}

	// Mode preserved on the 0644 file.
	if fi, _ := os.Stat(ymlPath); fi.Mode().Perm() != 0o644 {
		t.Errorf("file mode not preserved: got %o", fi.Mode().Perm())
	}

	if err := a.Verify(ctx, newH, v); err != nil {
		t.Errorf("Verify(new) should pass: %v", err)
	}

	// Verify(old) must FAIL — the old value is gone from the files.
	if err := a.Verify(ctx, cred.Secret, v); err == nil {
		t.Error("Verify(old) must fail after rotation — old value should be absent")
	}

	if err := a.RevokeOld(ctx, cred, v); err != nil {
		t.Errorf("RevokeOld (no-op) returned: %v", err)
	}

	// Leak-check: no secret value in the credential's non-secret metadata.
	if strings.Contains(cred.Identity, oldVal) || strings.Contains(cred.Identity, newVal) {
		t.Error("secret value leaked into credential metadata")
	}
}

// TestAppSecretNoMatchIsError proves we never claim a rotation when the old value is
// not actually present in any file (would otherwise silently mint+discard a value).
func TestAppSecretNoMatchIsError(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".env")
	if err := os.WriteFile(p, []byte("SECRET_KEY=something-else-entirely-here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	v := vault.New()
	defer v.Purge()
	blob := "appsecret://local/?" + url.Values{
		"key": {"SECRET_KEY"}, "val": {"value-that-is-not-present-xx"}, "path": {p},
	}.Encode()
	cred := discover.Credential{Source: "appsecret", Secret: v.Store([]byte(blob))}
	if _, err := (&AppSecret{}).Rotate(context.Background(), cred, v); err == nil {
		t.Error("Rotate should error when the old value is in no target file")
	}
}

func TestAppSecretRejectsShortOrEmpty(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	a := &AppSecret{}
	// too-short value (under minSecretLen) must be refused.
	short := discover.Credential{Source: "appsecret",
		Secret: v.Store([]byte("appsecret://local/?val=abc&path=/tmp/x"))}
	if _, err := a.Rotate(context.Background(), short, v); err == nil {
		t.Error("Rotate should reject a too-short value")
	}
	// no path must be refused.
	nopath := discover.Credential{Source: "appsecret",
		Secret: v.Store([]byte("appsecret://local/?val=a-long-enough-value-here"))}
	if _, err := a.Rotate(context.Background(), nopath, v); err == nil {
		t.Error("Rotate should reject a secret with no target file")
	}
}
