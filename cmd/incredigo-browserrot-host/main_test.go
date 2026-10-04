package main

import (
	"io"
	"strings"
	"testing"
)

// fakeEnv builds a getenv func over a map, so config resolution is tested without
// touching the real process environment.
func fakeEnv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestBuildConfig_defaultsFromEnv(t *testing.T) {
	cfg, err := buildConfig(fakeEnv(map[string]string{
		"INCREDIGO_SITE_BASE": "https://git.example.org",
		"INCREDIGO_SITE_USER": "alice",
		"HOME":                "/home/alice",
	}), overrides{})
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	if cfg.SiteBase != "https://git.example.org" || cfg.SiteUser != "alice" {
		t.Fatalf("site not carried through: %+v", cfg)
	}
	if cfg.Recipe != "gitea" {
		t.Errorf("recipe default = %q, want gitea", cfg.Recipe)
	}
	if cfg.StorePath != "gitea/login-creds" {
		t.Errorf("store path default = %q, want gitea/login-creds", cfg.StorePath)
	}
	if !cfg.LoginBeforeChange {
		t.Errorf("login-before-change default should be true")
	}
	if !strings.HasPrefix(cfg.BackupDir, "/home/alice/") {
		t.Errorf("backup dir = %q, want under HOME", cfg.BackupDir)
	}
}

func TestBuildConfig_prefixJoinsCredentialKey(t *testing.T) {
	cfg, err := buildConfig(fakeEnv(map[string]string{
		"INCREDIGO_SITE_BASE":    "https://git.example.org",
		"INCREDIGO_SITE_USER":    "bob",
		"INCREDIGO_STORE_PREFIX": "imported/",
		"INCREDIGO_CREDENTIAL":   "gitea/login-creds",
	}), overrides{})
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	if cfg.StorePath != "imported/gitea/login-creds" {
		t.Errorf("store path = %q, want imported/gitea/login-creds", cfg.StorePath)
	}
}

func TestBuildConfig_requiresSite(t *testing.T) {
	if _, err := buildConfig(fakeEnv(map[string]string{"INCREDIGO_SITE_USER": "x"}), overrides{}); err == nil {
		t.Fatal("expected error when SITE_BASE missing")
	}
	if _, err := buildConfig(fakeEnv(map[string]string{"INCREDIGO_SITE_BASE": "https://x"}), overrides{}); err == nil {
		t.Fatal("expected error when SITE_USER missing")
	}
}

func TestBuildConfig_unknownRecipeRejected(t *testing.T) {
	_, err := buildConfig(fakeEnv(map[string]string{
		"INCREDIGO_SITE_BASE": "https://git.example.org",
		"INCREDIGO_SITE_USER": "alice",
		"INCREDIGO_RECIPE":    "nope",
	}), overrides{})
	if err == nil || !strings.Contains(err.Error(), "unknown recipe") {
		t.Fatalf("expected unknown-recipe error, got %v", err)
	}
}

func TestBuildConfig_loginBeforeChangeEnvFalsey(t *testing.T) {
	cfg, err := buildConfig(fakeEnv(map[string]string{
		"INCREDIGO_SITE_BASE":           "https://git.example.org",
		"INCREDIGO_SITE_USER":           "alice",
		"INCREDIGO_LOGIN_BEFORE_CHANGE": "false",
	}), overrides{})
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	if cfg.LoginBeforeChange {
		t.Errorf("login-before-change should be false when env is 'false'")
	}
}

func TestBuildConfig_flagOverridesEnv(t *testing.T) {
	base := "https://flag.example.org"
	cfg, err := buildConfig(fakeEnv(map[string]string{
		"INCREDIGO_SITE_BASE": "https://env.example.org",
		"INCREDIGO_SITE_USER": "alice",
	}), overrides{siteBase: &base})
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	if cfg.SiteBase != base {
		t.Errorf("flag override not applied: %q", cfg.SiteBase)
	}
}

func TestParseFlags_help(t *testing.T) {
	_, showHelp, _, err := parseFlags([]string{"-h"}, io.Discard)
	if err != nil {
		t.Fatalf("-h should not error, got %v", err)
	}
	if !showHelp {
		t.Fatal("-h should request help")
	}
}

func TestParseFlags_version(t *testing.T) {
	_, _, showVersion, err := parseFlags([]string{"-version"}, io.Discard)
	if err != nil || !showVersion {
		t.Fatalf("-version: showVersion=%v err=%v", showVersion, err)
	}
}

func TestParseFlags_onlySetFlagsBecomeOverrides(t *testing.T) {
	ov, _, _, err := parseFlags([]string{"-site-user", "carol"}, io.Discard)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if ov.siteUser == nil || *ov.siteUser != "carol" {
		t.Fatalf("site-user override not captured: %+v", ov)
	}
	if ov.siteBase != nil {
		t.Errorf("unset site-base should stay nil (env falls through)")
	}
}

func TestParseFlags_chromeArgvTolerated(t *testing.T) {
	// Chrome spawns the host with the extension origin as a positional arg. flag stops
	// at the first non-flag and returns no error, leaving env resolution intact.
	ov, showHelp, showVersion, err := parseFlags([]string{"chrome-extension://abcdef/"}, io.Discard)
	if err != nil || showHelp || showVersion {
		t.Fatalf("chrome argv should be tolerated: err=%v help=%v ver=%v", err, showHelp, showVersion)
	}
	if ov.siteBase != nil || ov.siteUser != nil {
		t.Errorf("no overrides expected from a bare positional arg")
	}
}

func TestJoinStore(t *testing.T) {
	cases := []struct{ prefix, cred, want string }{
		{"", "gitea/login-creds", "gitea/login-creds"},
		{"imported/", "gitea/login-creds", "imported/gitea/login-creds"},
		{"/imported", "/gitea/login", "imported/gitea/login"},
		{"imported", "", "imported"},
	}
	for _, c := range cases {
		if got := joinStore(c.prefix, c.cred); got != c.want {
			t.Errorf("joinStore(%q,%q) = %q, want %q", c.prefix, c.cred, got, c.want)
		}
	}
}
