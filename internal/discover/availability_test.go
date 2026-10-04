package discover

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"incredigo/internal/vault"
)

// TestAvailable exercises every scanner's Available() against a HOME that has
// none of the expected files/dirs, then again once the expected artifact is
// created — the "does this source exist on this machine" branch that ScanAll
// relies on to skip cleanly instead of erroring on an absent file.
func TestAvailable(t *testing.T) {
	t.Run("aws", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "credentials")
		t.Setenv("AWS_SHARED_CREDENTIALS_FILE", p)
		s := &awsScanner{}
		if s.Available() {
			t.Error("Available() = true before file exists")
		}
		writeFixture(t, p, "[default]\n")
		if !s.Available() {
			t.Error("Available() = false after file created")
		}
	})

	t.Run("docker", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("DOCKER_CONFIG", dir)
		s := &dockerScanner{}
		if s.Available() {
			t.Error("Available() = true before config.json exists")
		}
		writeFixture(t, filepath.Join(dir, "config.json"), `{}`)
		if !s.Available() {
			t.Error("Available() = false after config.json created")
		}
	})

	t.Run("docker home fallback", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("DOCKER_CONFIG", "")
		s := &dockerScanner{}
		if s.path() != filepath.Join(home, ".docker", "config.json") {
			t.Errorf("path() = %q, want home-relative default", s.path())
		}
		if s.Available() {
			t.Error("Available() = true before config.json exists")
		}
		writeFixture(t, filepath.Join(home, ".docker", "config.json"), `{}`)
		if !s.Available() {
			t.Error("Available() = false after config.json created")
		}
	})

	t.Run("git", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		s := &gitScanner{}
		if s.Available() {
			t.Error("Available() = true before .git-credentials exists")
		}
		writeFixture(t, filepath.Join(home, ".git-credentials"), "")
		if !s.Available() {
			t.Error("Available() = false after .git-credentials created")
		}
	})

	t.Run("kube", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "config")
		t.Setenv("KUBECONFIG", p)
		s := &kubeScanner{}
		if s.Available() {
			t.Error("Available() = true before config exists")
		}
		writeFixture(t, p, "apiVersion: v1\n")
		if !s.Available() {
			t.Error("Available() = false after config created")
		}
	})

	t.Run("kube KUBECONFIG colon list uses first entry", func(t *testing.T) {
		dir := t.TempDir()
		first := filepath.Join(dir, "first")
		second := filepath.Join(dir, "second")
		t.Setenv("KUBECONFIG", first+":"+second)
		s := &kubeScanner{}
		if s.path() != first {
			t.Errorf("path() = %q, want first entry %q", s.path(), first)
		}
	})

	t.Run("netrc", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		s := &netrcScanner{}
		if s.Available() {
			t.Error("Available() = true before .netrc/.authinfo exist")
		}
		writeFixture(t, filepath.Join(home, ".authinfo"), "")
		if !s.Available() {
			t.Error("Available() = false after .authinfo created (either file counts)")
		}
	})

	t.Run("ssh", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		s := &sshScanner{}
		if s.Available() {
			t.Error("Available() = true before ~/.ssh exists")
		}
		writeFixture(t, filepath.Join(home, ".ssh", ".keep"), "")
		if !s.Available() {
			t.Error("Available() = false after ~/.ssh created")
		}
	})

	t.Run("ssh dir is a plain file, not a directory", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		writeFixture(t, filepath.Join(home, ".ssh"), "not a directory")
		s := &sshScanner{}
		if s.Available() {
			t.Error("Available() = true when ~/.ssh is a regular file")
		}
	})

	t.Run("gitea/tea", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("XDG_CONFIG_HOME", "")
		s := &teaScanner{}
		if s.Available() {
			t.Error("Available() = true before tea config exists")
		}
		writeFixture(t, filepath.Join(home, ".config", "tea", "config.yml"), "logins: []\n")
		if !s.Available() {
			t.Error("Available() = false after tea config created")
		}
	})

	t.Run("gitea/tea XDG_CONFIG_HOME override", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("XDG_CONFIG_HOME", dir)
		s := &teaScanner{}
		want := filepath.Join(dir, "tea", "config.yml")
		if s.path() != want {
			t.Errorf("path() = %q, want %q", s.path(), want)
		}
	})

	t.Run("file scanner is available only once a path is registered", func(t *testing.T) {
		ClearPaths()
		defer ClearPaths()
		s := fileSingleton
		if s.Available() {
			t.Error("Available() = true with no registered paths")
		}
		AddPath("/some/path")
		if !s.Available() {
			t.Error("Available() = false after AddPath")
		}
		ClearPaths()
		if s.Available() {
			t.Error("Available() = true after ClearPaths")
		}
	})

	t.Run("env is available only when .env or .env.* exist in cwd", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		s := &envScanner{}
		if s.Available() {
			t.Error("Available() = true with no .env files")
		}
		writeFixture(t, filepath.Join(dir, ".env.local"), "")
		if !s.Available() {
			t.Error("Available() = false after .env.local created")
		}
	})
}

func TestAddPathIgnoresEmptyString(t *testing.T) {
	ClearPaths()
	defer ClearPaths()
	AddPath("")
	if fileSingleton.Available() {
		t.Error("AddPath(\"\") should not register a target")
	}
	if len(fileSingleton.targets) != 0 {
		t.Errorf("targets = %v, want empty", fileSingleton.targets)
	}
}

func TestAWSRegion(t *testing.T) {
	t.Run("AWS_REGION takes priority", func(t *testing.T) {
		t.Setenv("AWS_REGION", "eu-west-1")
		t.Setenv("AWS_DEFAULT_REGION", "eu-central-1")
		if got := awsRegion("default"); got != "eu-west-1" {
			t.Errorf("awsRegion = %q, want eu-west-1", got)
		}
	})

	t.Run("AWS_DEFAULT_REGION used when AWS_REGION unset", func(t *testing.T) {
		t.Setenv("AWS_REGION", "")
		t.Setenv("AWS_DEFAULT_REGION", "ap-southeast-2")
		if got := awsRegion("default"); got != "ap-southeast-2" {
			t.Errorf("awsRegion = %q, want ap-southeast-2", got)
		}
	})

	t.Run("falls back to config file for named profile", func(t *testing.T) {
		t.Setenv("AWS_REGION", "")
		t.Setenv("AWS_DEFAULT_REGION", "")
		dir := t.TempDir()
		cfg := filepath.Join(dir, "config")
		t.Setenv("AWS_CONFIG_FILE", cfg)
		writeFixture(t, cfg, "[profile work]\nregion = ca-central-1\n")
		if got := awsRegion("work"); got != "ca-central-1" {
			t.Errorf("awsRegion(work) = %q, want ca-central-1", got)
		}
	})

	t.Run("default profile section is [default], not [profile default]", func(t *testing.T) {
		t.Setenv("AWS_REGION", "")
		t.Setenv("AWS_DEFAULT_REGION", "")
		dir := t.TempDir()
		cfg := filepath.Join(dir, "config")
		t.Setenv("AWS_CONFIG_FILE", cfg)
		writeFixture(t, cfg, "[default]\nregion = sa-east-1\n[profile work]\nregion = eu-north-1\n")
		if got := awsRegion("default"); got != "sa-east-1" {
			t.Errorf("awsRegion(default) = %q, want sa-east-1", got)
		}
		if got := awsRegion("work"); got != "eu-north-1" {
			t.Errorf("awsRegion(work) = %q, want eu-north-1", got)
		}
	})

	t.Run("falls back to us-east-1 when nothing matches", func(t *testing.T) {
		t.Setenv("AWS_REGION", "")
		t.Setenv("AWS_DEFAULT_REGION", "")
		dir := t.TempDir()
		cfg := filepath.Join(dir, "config")
		t.Setenv("AWS_CONFIG_FILE", cfg)
		writeFixture(t, cfg, "[profile other]\nregion = us-west-2\n")
		if got := awsRegion("work"); got != "us-east-1" {
			t.Errorf("awsRegion(work) = %q, want us-east-1 default", got)
		}
	})

	t.Run("missing config file falls back to us-east-1", func(t *testing.T) {
		t.Setenv("AWS_REGION", "")
		t.Setenv("AWS_DEFAULT_REGION", "")
		t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "does-not-exist"))
		if got := awsRegion("default"); got != "us-east-1" {
			t.Errorf("awsRegion = %q, want us-east-1", got)
		}
	})
}

func TestSplitKV(t *testing.T) {
	cases := []struct {
		name   string
		line   string
		wantK  string
		wantV  string
		wantOK bool
	}{
		{"simple", "key = value", "key", "value", true},
		{"no spaces", "key=value", "key", "value", true},
		{"no delimiter", "justastring", "", "", false},
		{"empty string", "", "", "", false},
		{"empty value", "key=", "key", "", true},
		{"empty key", "=value", "", "value", true},
		{"value contains equals", "key=a=b=c", "key", "a=b=c", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k, v, ok := splitKV(c.line)
			if k != c.wantK || v != c.wantV || ok != c.wantOK {
				t.Errorf("splitKV(%q) = (%q, %q, %v), want (%q, %q, %v)",
					c.line, k, v, ok, c.wantK, c.wantV, c.wantOK)
			}
		})
	}
}

func TestRedactMiddle(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"short (<=8) fully masked", "abcd1234", "********"},
		{"exactly 9 chars", "abcd12345", "abcd***45"},
		{"long key id", "ZKEYIDLONGVALUEZZZZZ", "ZKEY**************ZZ"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := redactMiddle(c.in); got != c.want {
				t.Errorf("redactMiddle(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestShannonEntropy(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantLow bool // true if we expect ~0 (or clearly low) entropy
	}{
		{"empty string is zero entropy", "", true},
		{"single repeated char is zero entropy", "aaaaaaaaaa", true},
		{"low-cardinality repetition stays low", "abababababab", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := shannonEntropy(c.in)
			if c.wantLow && got > 1.5 {
				t.Errorf("shannonEntropy(%q) = %v, want low", c.in, got)
			}
		})
	}

	high := shannonEntropy("Zk9fQ2pVw7eR1tY3xM8nL2qP")
	low := shannonEntropy("aaaaaaaaaaaaaaaaaaaaaaaa")
	if high <= low {
		t.Errorf("expected high-diversity string entropy (%v) > repeated-char entropy (%v)", high, low)
	}
}

// TestEnvScannerMalformedInput proves the env scanner tolerates malformed/edge
// .env content instead of erroring or panicking: blank lines, comments, bare
// keys with no '=', quoted-empty values, and export prefixes.
func TestEnvScannerMalformedInput(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeFixture(t, filepath.Join(dir, ".env"),
		"\n# a comment\nNOEQUALSHERE\nEMPTY_SECRET_TOKEN=\nQUOTED_EMPTY_PASSWORD=\"\"\nexport TOKEN=short\n")

	v := vault.New()
	defer v.Purge()
	creds, err := (&envScanner{}).Scan(context.Background(), v)
	if err != nil {
		t.Fatalf("Scan malformed .env: %v", err)
	}
	for _, c := range creds {
		if strings.Contains(c.Identity, "NOEQUALSHERE") {
			t.Errorf("line without '=' should have been skipped, got %+v", c)
		}
		if strings.Contains(c.Identity, "EMPTY_SECRET_TOKEN") {
			t.Errorf("bare-empty-value line should have been skipped, got %+v", c)
		}
		// QUOTED_EMPTY_PASSWORD ("" -> empty after quote-trim) is NOT skipped:
		// the key name alone ("password") satisfies looksSecret regardless of
		// the (now-empty) value — documenting this key-name-wins quirk rather
		// than asserting the value gets filtered.
		if strings.Contains(c.Identity, "QUOTED_EMPTY_PASSWORD") {
			if got := openSecret(t, v, c); got != "" {
				t.Errorf("QUOTED_EMPTY_PASSWORD secret = %q, want empty", got)
			}
		}
	}
}

// TestAWSScannerMalformedInput proves the aws scanner tolerates a malformed
// credentials file (stray keys with no '=', an access key with no matching
// secret, sections with no keys) without erroring.
func TestAWSScannerMalformedInput(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "credentials")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", p)
	writeFixture(t, p,
		"garbage line with no equals\n"+
			"[incomplete]\n"+
			"aws_access_key_id = AKIAINCOMPLETEXXXX\n"+ // no matching secret key -> never flushed
			"[default]\n"+
			"aws_secret_access_key = orphan-secret-no-key-id\n") // secret with no key id -> flush no-ops

	v := vault.New()
	defer v.Purge()
	creds, err := (&awsScanner{}).Scan(context.Background(), v)
	if err != nil {
		t.Fatalf("Scan malformed credentials: %v", err)
	}
	if len(creds) != 0 {
		t.Fatalf("want 0 creds from incomplete profiles, got %d: %+v", len(creds), creds)
	}
}

// TestDockerScannerMalformedJSON proves a corrupt config.json surfaces an
// error rather than panicking or silently returning wrong data.
func TestDockerScannerMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DOCKER_CONFIG", dir)
	writeFixture(t, filepath.Join(dir, "config.json"), `{not valid json`)

	v := vault.New()
	defer v.Purge()
	if _, err := (&dockerScanner{}).Scan(context.Background(), v); err == nil {
		t.Error("Scan malformed config.json: want error, got nil")
	}
}

// TestDockerScannerEmptyAuthsSkipsEntries proves an entry with neither auth
// nor identitytoken is skipped rather than producing an empty-secret credential.
func TestDockerScannerEmptyAuthsSkipsEntries(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DOCKER_CONFIG", dir)
	writeFixture(t, filepath.Join(dir, "config.json"), `{"auths":{"empty.example.com":{}}}`)

	v := vault.New()
	defer v.Purge()
	creds, err := (&dockerScanner{}).Scan(context.Background(), v)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(creds) != 0 {
		t.Fatalf("want 0 creds for an empty auth entry, got %d: %+v", len(creds), creds)
	}
}

// TestKubeScannerMalformedYAML proves corrupt YAML surfaces an error.
func TestKubeScannerMalformedYAML(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config")
	t.Setenv("KUBECONFIG", p)
	writeFixture(t, p, "users: [this is not: valid yaml structure\n")

	v := vault.New()
	defer v.Purge()
	if _, err := (&kubeScanner{}).Scan(context.Background(), v); err == nil {
		t.Error("Scan malformed kubeconfig: want error, got nil")
	}
}

// TestKubeScannerEmptyUsersReturnsEmpty proves a well-formed but user-less
// kubeconfig yields zero creds without error.
func TestKubeScannerEmptyUsersReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config")
	t.Setenv("KUBECONFIG", p)
	writeFixture(t, p, "apiVersion: v1\n")

	v := vault.New()
	defer v.Purge()
	creds, err := (&kubeScanner{}).Scan(context.Background(), v)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(creds) != 0 {
		t.Fatalf("want 0 creds, got %d: %+v", len(creds), creds)
	}
}

// TestTeaScannerMalformedYAML proves corrupt YAML surfaces an error.
func TestTeaScannerMalformedYAML(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	p := filepath.Join(home, ".config", "tea", "config.yml")
	writeFixture(t, p, "logins: [this is not: valid\n")

	v := vault.New()
	defer v.Purge()
	if _, err := (&teaScanner{}).Scan(context.Background(), v); err == nil {
		t.Error("Scan malformed tea config: want error, got nil")
	}
}

// TestTeaScannerSkipsInvalidURL proves a login with an unparsable/hostless URL
// is skipped rather than producing a broken credential.
func TestTeaScannerSkipsInvalidURL(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	writeFixture(t, filepath.Join(home, ".config", "tea", "config.yml"),
		"logins:\n"+
			"- name: bad\n"+
			"  url: \"not a url\"\n"+
			"  user: alice\n"+
			"  token: teaSECREThostless\n")

	v := vault.New()
	defer v.Purge()
	creds, err := (&teaScanner{}).Scan(context.Background(), v)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(creds) != 0 {
		t.Fatalf("want 0 creds for a hostless URL, got %d: %+v", len(creds), creds)
	}
}

// TestNetrcScannerMissingFilesReturnsEmpty proves the netrc scanner treats
// both files being absent as "nothing found," not an error.
func TestNetrcScannerMissingFilesReturnsEmpty(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	v := vault.New()
	defer v.Purge()
	creds, err := (&netrcScanner{}).Scan(context.Background(), v)
	if err != nil {
		t.Fatalf("Scan with no netrc files: %v", err)
	}
	if len(creds) != 0 {
		t.Fatalf("want 0 creds, got %d: %+v", len(creds), creds)
	}
}

// TestNetrcScannerMalformedTokensDoesNotPanic proves truncated directives
// (a "machine"/"login"/"password" keyword with no following value token) are
// tolerated rather than panicking on an out-of-range index.
func TestNetrcScannerMalformedTokensDoesNotPanic(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeFixture(t, filepath.Join(home, ".netrc"), "machine")

	v := vault.New()
	defer v.Purge()
	creds, err := (&netrcScanner{}).Scan(context.Background(), v)
	if err != nil {
		t.Fatalf("Scan truncated .netrc: %v", err)
	}
	if len(creds) != 0 {
		t.Fatalf("want 0 creds (no password), got %d: %+v", len(creds), creds)
	}
}

// TestGitScannerMalformedLinesSkipped proves lines that aren't parseable URLs,
// or that carry no userinfo/password, are skipped rather than erroring.
func TestGitScannerMalformedLinesSkipped(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeFixture(t, filepath.Join(home, ".git-credentials"),
		"\n# comment\nnot a url at all with spaces and \x7f control char\nhttps://user-no-password@example.com\n")

	v := vault.New()
	defer v.Purge()
	creds, err := (&gitScanner{}).Scan(context.Background(), v)
	if err != nil {
		t.Fatalf("Scan malformed .git-credentials: %v", err)
	}
	if len(creds) != 0 {
		t.Fatalf("want 0 creds, got %d: %+v", len(creds), creds)
	}
}
