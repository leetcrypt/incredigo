package discover

import (
	"context"
	"net/url"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"incredigo/internal/vault"
)

func init() { Register(&teaScanner{}) }

// teaScanner reads the Gitea `tea` CLI config (~/.config/tea/config.yml), which
// stores one or more logins as {name, url, user, token}. Because this file is
// unambiguously Gitea, entries are tagged Source "gitea" so the gitea rotation
// driver Detects them directly.
//
// The emitted secret is the driver-ready single-line blob
// "<scheme>://<user>:<token>@<host>/" (see internal/rotate/gitea.go). The token
// name is unknown from tea config, so it is omitted — RevokeOld then degrades to
// the guided worklist for the old-token deletion, which is the correct behavior.
// Read-only.
type teaScanner struct{}

func (t *teaScanner) Name() string { return "gitea" }

func (t *teaScanner) path() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "tea", "config.yml")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "tea", "config.yml")
}

func (t *teaScanner) Available() bool {
	_, err := os.Stat(t.path())
	return err == nil
}

func (t *teaScanner) Scan(ctx context.Context, v *vault.Vault) ([]Credential, error) {
	p := t.path()
	b, err := os.ReadFile(p) // read-only
	if err != nil {
		return nil, err
	}
	fi, _ := os.Stat(p)

	var cfg struct {
		Logins []struct {
			Name  string `yaml:"name"`
			URL   string `yaml:"url"`
			User  string `yaml:"user"`
			Token string `yaml:"token"`
		} `yaml:"logins"`
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}

	var creds []Credential
	for _, l := range cfg.Logins {
		if l.Token == "" || l.URL == "" {
			continue
		}
		u, err := url.Parse(l.URL)
		if err != nil || u.Host == "" {
			continue
		}
		user := l.User
		if user == "" {
			user = l.Name
		}
		scheme := u.Scheme
		if scheme == "" {
			scheme = "https"
		}
		// Driver-ready blob; the token lives only here (and the vault).
		blob := (&url.URL{
			Scheme: scheme,
			Host:   u.Host,
			User:   url.UserPassword(user, l.Token),
			Path:   "/",
		}).String()

		creds = append(creds, Credential{
			Source:   t.Name(),
			Kind:     KindToken,
			Identity: user + " @ " + u.Host,
			Location: p,
			Modified: fi.ModTime(),
			Secret:   v.Store([]byte(blob)),
		})
	}
	return creds, nil
}
