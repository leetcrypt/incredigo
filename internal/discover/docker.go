package discover

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"incredigo/internal/vault"
)

func init() { Register(&dockerScanner{}) }

// dockerScanner reads ~/.docker/config.json. Each auths entry holds a base64
// user:pass in "auth" (or an "identitytoken"). Read-only.
type dockerScanner struct{}

func (d *dockerScanner) Name() string { return "docker" }

func (d *dockerScanner) path() string {
	if p := os.Getenv("DOCKER_CONFIG"); p != "" {
		return filepath.Join(p, "config.json")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".docker", "config.json")
}

func (d *dockerScanner) Available() bool {
	_, err := os.Stat(d.path())
	return err == nil
}

func (d *dockerScanner) Scan(ctx context.Context, v *vault.Vault) ([]Credential, error) {
	p := d.path()
	b, err := os.ReadFile(p) // read-only
	if err != nil {
		return nil, err
	}
	fi, _ := os.Stat(p)

	var cfg struct {
		Auths map[string]struct {
			Auth          string `json:"auth"`
			IdentityToken string `json:"identitytoken"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}

	registries := make([]string, 0, len(cfg.Auths))
	for r := range cfg.Auths {
		registries = append(registries, r)
	}
	sort.Strings(registries) // deterministic order

	var creds []Credential
	for _, registry := range registries {
		a := cfg.Auths[registry]
		secret, kind := a.Auth, KindPassword
		if secret == "" && a.IdentityToken != "" {
			secret, kind = a.IdentityToken, KindToken
		}
		if secret == "" {
			continue
		}
		creds = append(creds, Credential{
			Source:   d.Name(),
			Kind:     kind,
			Identity: registry,
			Location: p,
			Modified: fi.ModTime(),
			Secret:   v.Store([]byte(secret)),
		})
	}
	return creds, nil
}
