package discover

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"incredigo/internal/vault"
)

func writeFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// assertNoLeak fails if any secret substring appears in a non-secret field
// (Identity, Location, Source, Kind, or any Meta key/value).
func assertNoLeak(t *testing.T, creds []Credential, secrets ...string) {
	t.Helper()
	for _, c := range creds {
		fields := []string{c.Identity, c.Source, c.Location, string(c.Kind)}
		for k, val := range c.Meta {
			fields = append(fields, k, val)
		}
		for _, f := range fields {
			for _, s := range secrets {
				if s != "" && strings.Contains(f, s) {
					t.Errorf("secret %q leaked into non-secret field %q", s, f)
				}
			}
		}
	}
}

func openSecret(t *testing.T, v *vault.Vault, c Credential) string {
	t.Helper()
	buf, err := v.Open(c.Secret)
	if err != nil {
		t.Fatalf("open vaulted secret: %v", err)
	}
	return string(buf.Bytes())
}

// byIdentity indexes creds by Identity for assertions.
func byIdentity(creds []Credential) map[string]Credential {
	m := make(map[string]Credential, len(creds))
	for _, c := range creds {
		m[c.Identity] = c
	}
	return m
}

func TestAWSScanner(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "credentials")
	writeFixture(t, p, "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrSECRETkeyMaterial0123\n")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", p)

	v := vault.New()
	defer v.Purge()
	creds, err := (&awsScanner{}).Scan(context.Background(), v)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 1 {
		t.Fatalf("want 1 cred, got %d", len(creds))
	}
	c := creds[0]
	if c.Kind != KindAWSKey {
		t.Errorf("kind = %s, want aws_key", c.Kind)
	}
	if !strings.Contains(c.Identity, "default") {
		t.Errorf("identity %q missing profile", c.Identity)
	}
	// Secret is now the driver-ready blob: aws://<keyID>:<secret>@aws/?region=...
	blob := openSecret(t, v, c)
	u, err := url.Parse(blob)
	if err != nil {
		t.Fatalf("secret is not a parseable blob: %v", err)
	}
	if u.Scheme != "aws" || u.User.Username() != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("blob keyID wrong: %q", blob)
	}
	if pw, _ := u.User.Password(); pw != "wJalrSECRETkeyMaterial0123" {
		t.Errorf("blob secret round-trip = %q", pw)
	}
	if u.Query().Get("region") == "" {
		t.Errorf("blob missing region: %q", blob)
	}
	// Identity/Meta must stay redacted even though the blob carries the full values.
	assertNoLeak(t, creds, "wJalrSECRETkeyMaterial0123", "AKIAIOSFODNN7EXAMPLE")
}

func TestEnvScanner(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeFixture(t, filepath.Join(dir, ".env"),
		"PORT=8080\nDEBUG=true\nSTRIPE_API_KEY=sk_live_envSECRET0123456789\nexport DB_PASSWORD=\"pw-envSECRET-xyz\"\n"+
			"DATABASE_URL=postgres://labapp:pgSECRET@127.0.0.1:5432/labdb\n"+
			"REDIS_URL=redis://:redisSECRET@127.0.0.1:6379\n"+
			"MYSQL_URL=mysql://root:weak@127.0.0.1:3306/app\n")

	v := vault.New()
	defer v.Purge()
	creds, err := (&envScanner{}).Scan(context.Background(), v)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 5 {
		t.Fatalf("want 5 creds (secret-ish + DB URLs), got %d: %+v", len(creds), creds)
	}
	idents := byIdentity(creds)
	if sk, ok := idents[".env / STRIPE_API_KEY"]; !ok {
		t.Errorf("missing STRIPE_API_KEY; got %v", idents)
	} else if sk.Meta[MetaService] != "stripe" {
		// The sk_live_ prefix must be recognised as a non-secret service hint so the
		// worklist can offer a guided change-password page (Stripe has no rotate API).
		t.Errorf("STRIPE_API_KEY missing service hint; Meta=%v", sk.Meta)
	}
	for id := range idents {
		if strings.Contains(id, "PORT") || strings.Contains(id, "DEBUG") {
			t.Errorf("non-secret %q should have been filtered out", id)
		}
	}
	// DB connection strings must be re-tagged with their rotation-driver Source so
	// the postgres/mysql/redis drivers can Detect them straight from a .env scan.
	bySource := map[string]string{} // source -> identity
	for _, c := range creds {
		bySource[c.Source] = c.Identity
	}
	for _, want := range []string{"postgres", "mysql", "redis"} {
		if _, ok := bySource[want]; !ok {
			t.Errorf("DB URL not tagged Source=%q; got sources %v", want, bySource)
		}
	}
	assertNoLeak(t, creds, "sk_live_envSECRET0123456789", "pw-envSECRET-xyz",
		"pgSECRET", "redisSECRET", "weak")
}

// TestEnvScannerAppSecret proves an app SIGNING secret (SECRET_KEY) is tagged
// Source="appsecret" with a self-contained blob carrying its value AND file path, so
// the local in-place rotator can Detect+Rotate it straight from a .env scan — while a
// generic API key in the same file stays a plain env secret.
func TestEnvScannerAppSecret(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	appVal := "django-insecure-0123456789abcdefghijABCDEF"
	writeFixture(t, filepath.Join(dir, ".env"),
		"SECRET_KEY="+appVal+"\nSTRIPE_API_KEY=sk_live_keepGenericEnv00\n")

	v := vault.New()
	defer v.Purge()
	creds, err := (&envScanner{}).Scan(context.Background(), v)
	if err != nil {
		t.Fatal(err)
	}

	var app *Credential
	for i := range creds {
		if creds[i].Source == "appsecret" {
			app = &creds[i]
		}
	}
	if app == nil {
		t.Fatalf("SECRET_KEY not tagged Source=appsecret; got %+v", creds)
	}
	if app.Identity != ".env / SECRET_KEY" {
		t.Errorf("unexpected identity %q", app.Identity)
	}

	// The blob must round-trip the value AND the file path for the rotator.
	buf, _ := v.Open(app.Secret)
	u, err := url.Parse(strings.TrimSpace(string(buf.Bytes())))
	if err != nil || u.Scheme != "appsecret" {
		t.Fatalf("appsecret blob malformed: %v (%q)", err, string(buf.Bytes()))
	}
	if u.Query().Get("val") != appVal {
		t.Error("appsecret blob does not carry the signing value")
	}
	if got := u.Query().Get("path"); !strings.HasSuffix(got, ".env") {
		t.Errorf("appsecret blob path missing/wrong: %q", got)
	}

	// The generic API key in the same file must NOT be tagged appsecret.
	for _, c := range creds {
		if c.Source == "appsecret" && strings.Contains(c.Identity, "STRIPE") {
			t.Error("generic API key wrongly tagged appsecret")
		}
	}

	// Leak-check: the signing value must not appear in any non-secret field.
	assertNoLeak(t, creds, appVal)
}

func TestNetrcScanner(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeFixture(t, filepath.Join(home, ".netrc"),
		"machine api.example.com login alice password netrcSECRETaaa\ndefault login bob password netrcDEFAULTbbb\n")

	v := vault.New()
	defer v.Purge()
	creds, err := (&netrcScanner{}).Scan(context.Background(), v)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 2 {
		t.Fatalf("want 2 creds, got %d", len(creds))
	}
	idents := byIdentity(creds)
	if c, ok := idents["alice @ api.example.com"]; !ok {
		t.Errorf("missing machine entry; got %v", idents)
	} else if got := openSecret(t, v, c); got != "netrcSECRETaaa" {
		t.Errorf("secret = %q", got)
	}
	if _, ok := idents["bob @ default"]; !ok {
		t.Errorf("missing default entry; got %v", idents)
	}
	assertNoLeak(t, creds, "netrcSECRETaaa", "netrcDEFAULTbbb")
}

func TestDockerScanner(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DOCKER_CONFIG", dir)
	writeFixture(t, filepath.Join(dir, "config.json"),
		`{"auths":{"registry.example.com":{"auth":"ZG9ja2VyU0VDUkVUZWVl"},"ghcr.io":{"identitytoken":"dockerTOKENfff"}}}`)

	v := vault.New()
	defer v.Purge()
	creds, err := (&dockerScanner{}).Scan(context.Background(), v)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 2 {
		t.Fatalf("want 2 creds, got %d", len(creds))
	}
	idents := byIdentity(creds)
	if c, ok := idents["registry.example.com"]; !ok || c.Kind != KindPassword {
		t.Errorf("registry entry wrong: %+v", c)
	}
	if c, ok := idents["ghcr.io"]; !ok || c.Kind != KindToken {
		t.Errorf("ghcr entry wrong: %+v", c)
	}
	assertNoLeak(t, creds, "ZG9ja2VyU0VDUkVUZWVl", "dockerTOKENfff")
}

func TestKubeScanner(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config")
	t.Setenv("KUBECONFIG", p)
	writeFixture(t, p, `apiVersion: v1
users:
- name: admin
  user:
    token: kubeSECRETggg
- name: certuser
  user:
    client-key-data: a3ViZUtFWWhoaA==
- name: execuser
  user:
    exec:
      command: aws
`)

	v := vault.New()
	defer v.Purge()
	creds, err := (&kubeScanner{}).Scan(context.Background(), v)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 2 {
		t.Fatalf("want 2 creds (exec user skipped), got %d", len(creds))
	}
	idents := byIdentity(creds)
	if c, ok := idents["admin"]; !ok || c.Kind != KindToken {
		t.Errorf("admin entry wrong: %+v", c)
	}
	if c, ok := idents["certuser"]; !ok || c.Kind != KindPrivateKey {
		t.Errorf("certuser entry wrong: %+v", c)
	}
	if _, ok := idents["execuser"]; ok {
		t.Error("execuser (dynamic) should be skipped")
	}
	assertNoLeak(t, creds, "kubeSECRETggg", "a3ViZUtFWWhoaA==")
}

func TestGitScanner(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeFixture(t, filepath.Join(home, ".git-credentials"),
		"https://alice:gitSECRETiii@github.com\nhttps://gitlab.com\n")

	v := vault.New()
	defer v.Purge()
	creds, err := (&gitScanner{}).Scan(context.Background(), v)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 1 {
		t.Fatalf("want 1 cred (no-cred line skipped), got %d", len(creds))
	}
	c := creds[0]
	if c.Identity != "alice @ github.com" {
		t.Errorf("identity = %q", c.Identity)
	}
	if got := openSecret(t, v, c); got != "gitSECRETiii" {
		t.Errorf("secret = %q", got)
	}
	assertNoLeak(t, creds, "gitSECRETiii")
}

func TestSSHScanner(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeFixture(t, filepath.Join(home, ".ssh", "id_ed25519"),
		"-----BEGIN OPENSSH PRIVATE KEY-----\nsshSECRETkeyccc\n-----END OPENSSH PRIVATE KEY-----\n")
	writeFixture(t, filepath.Join(home, ".ssh", "id_ed25519.pub"), "ssh-ed25519 AAAA pub")
	writeFixture(t, filepath.Join(home, ".ssh", "id_rsa_enc"),
		"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nsshSECRETencddd\n-----END RSA PRIVATE KEY-----\n")

	v := vault.New()
	defer v.Purge()
	creds, err := (&sshScanner{}).Scan(context.Background(), v)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 2 {
		t.Fatalf("want 2 private keys (.pub ignored), got %d: %+v", len(creds), creds)
	}
	idents := byIdentity(creds)
	if c, ok := idents["id_rsa_enc"]; !ok || c.Meta["encrypted"] != "true" {
		t.Errorf("encrypted key not flagged: %+v", c)
	}
	if c, ok := idents["id_ed25519"]; !ok || c.Meta["encrypted"] != "false" {
		t.Errorf("plaintext key wrongly flagged: %+v", c)
	}
	assertNoLeak(t, creds, "sshSECRETkeyccc", "sshSECRETencddd")
}

// TestSSHScannerDynamicDiscovery covers the broadened discovery: a key with a
// non-conventional name (no id_ prefix) inside ~/.ssh, and a key in a
// non-default location referenced by an IdentityFile directive in ~/.ssh/config.
func TestSSHScannerDynamicDiscovery(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Oddly-named key in ~/.ssh — found by content, not by id_ prefix.
	writeFixture(t, filepath.Join(home, ".ssh", "work-deploy"),
		"-----BEGIN OPENSSH PRIVATE KEY-----\nsshSECRETwork111\n-----END OPENSSH PRIVATE KEY-----\n")
	// Non-key companions that must be ignored.
	writeFixture(t, filepath.Join(home, ".ssh", "known_hosts"), "host ssh-ed25519 AAAA notakey")
	writeFixture(t, filepath.Join(home, ".ssh", "work-deploy.pub"), "ssh-ed25519 AAAA pub")

	// Key outside ~/.ssh, referenced via IdentityFile in config.
	writeFixture(t, filepath.Join(home, "keys", "prod.key"),
		"-----BEGIN OPENSSH PRIVATE KEY-----\nsshSECRETprod222\n-----END OPENSSH PRIVATE KEY-----\n")
	writeFixture(t, filepath.Join(home, ".ssh", "config"),
		"Host prod\n  HostName prod.example.com\n  IdentityFile ~/keys/prod.key\n")

	v := vault.New()
	defer v.Purge()
	creds, err := (&sshScanner{}).Scan(context.Background(), v)
	if err != nil {
		t.Fatal(err)
	}
	idents := byIdentity(creds)
	if _, ok := idents["work-deploy"]; !ok {
		t.Errorf("non-id_ key not discovered by content: %v", idents)
	}
	if c, ok := idents["prod.key"]; !ok {
		t.Errorf("IdentityFile-referenced key not discovered: %v", idents)
	} else if got := openSecret(t, v, c); !strings.Contains(got, "sshSECRETprod222") {
		t.Errorf("prod.key secret = %q", got)
	}
	if _, ok := idents["known_hosts"]; ok {
		t.Error("known_hosts wrongly treated as a key")
	}
	if _, ok := idents["work-deploy.pub"]; ok {
		t.Error(".pub wrongly treated as a key")
	}
	if len(creds) != 2 {
		t.Fatalf("want 2 keys (work-deploy + prod.key), got %d: %v", len(creds), idents)
	}
	assertNoLeak(t, creds, "sshSECRETwork111", "sshSECRETprod222")
}

func TestTeaScanner(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "") // force ~/.config fallback
	writeFixture(t, filepath.Join(home, ".config", "tea", "config.yml"),
		"logins:\n"+
			"- name: work\n"+
			"  url: https://gitea.example.com\n"+
			"  user: alice\n"+
			"  token: teaSECRETtok111\n"+
			"  default: true\n"+
			"- name: notoken\n"+
			"  url: https://other.example.com\n")

	v := vault.New()
	defer v.Purge()
	creds, err := (&teaScanner{}).Scan(context.Background(), v)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 1 {
		t.Fatalf("want 1 gitea login (token-less skipped), got %d: %+v", len(creds), creds)
	}
	c := creds[0]
	if c.Source != "gitea" {
		t.Errorf("source = %q, want gitea (so the driver Detects it)", c.Source)
	}
	if c.Identity != "alice @ gitea.example.com" {
		t.Errorf("identity = %q", c.Identity)
	}
	// Secret is the driver-ready blob carrying the token.
	if got := openSecret(t, v, c); !strings.Contains(got, "teaSECRETtok111") ||
		!strings.HasPrefix(got, "https://alice:") {
		t.Errorf("secret blob = %q", got)
	}
	assertNoLeak(t, creds, "teaSECRETtok111")
}

func TestFileScanner(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, filepath.Join(root, "github-token"), "fileSECRETtok")
	writeFixture(t, filepath.Join(root, "keys", "deploy.pem"),
		"-----BEGIN OPENSSH PRIVATE KEY-----\nfileKEYmaterial\n-----END OPENSSH PRIVATE KEY-----\n")
	writeFixture(t, filepath.Join(root, "empty"), "")

	v := vault.New()
	defer v.Purge()
	fs := &fileScanner{targets: []string{root}}
	creds, err := fs.Scan(context.Background(), v)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 2 {
		t.Fatalf("want 2 creds (empty skipped), got %d: %+v", len(creds), creds)
	}
	idents := byIdentity(creds)
	if c, ok := idents["github-token"]; !ok {
		t.Errorf("missing github-token; got %v", idents)
	} else if got := openSecret(t, v, c); got != "fileSECRETtok" {
		t.Errorf("secret = %q", got)
	}
	if c, ok := idents[filepath.Join("keys", "deploy.pem")]; !ok || c.Kind != KindPrivateKey {
		t.Errorf("pem not classified as private_key: %+v", c)
	}
	assertNoLeak(t, creds, "fileSECRETtok", "fileKEYmaterial")
}
