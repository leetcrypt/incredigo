package discover

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"incredigo/internal/vault"
)

func init() { Register(&kubeScanner{}) }

// kubeScanner reads ~/.kube/config (YAML) and emits a credential per user that
// carries a static secret: a bearer token, a client key, or a basic-auth
// password. Dynamic exec/auth-provider users (no embedded secret) are skipped.
// Read-only.
type kubeScanner struct{}

func (k *kubeScanner) Name() string { return "kube" }

func (k *kubeScanner) path() string {
	if p := os.Getenv("KUBECONFIG"); p != "" {
		// KUBECONFIG may be a colon-separated list; use the first entry.
		return strings.SplitN(p, ":", 2)[0]
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".kube", "config")
}

func (k *kubeScanner) Available() bool {
	_, err := os.Stat(k.path())
	return err == nil
}

func (k *kubeScanner) Scan(ctx context.Context, v *vault.Vault) ([]Credential, error) {
	p := k.path()
	b, err := os.ReadFile(p) // read-only
	if err != nil {
		return nil, err
	}
	fi, _ := os.Stat(p)

	var cfg struct {
		Users []struct {
			Name string `yaml:"name"`
			User struct {
				Token         string `yaml:"token"`
				Password      string `yaml:"password"`
				ClientKeyData string `yaml:"client-key-data"`
			} `yaml:"user"`
		} `yaml:"users"`
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}

	var creds []Credential
	for _, u := range cfg.Users {
		var secret string
		kind := KindToken
		switch {
		case u.User.Token != "":
			secret, kind = u.User.Token, KindToken
		case u.User.ClientKeyData != "":
			secret, kind = u.User.ClientKeyData, KindPrivateKey
		case u.User.Password != "":
			secret, kind = u.User.Password, KindPassword
		default:
			continue // dynamic credential (exec/auth-provider) — nothing static to take
		}
		creds = append(creds, Credential{
			Source:   k.Name(),
			Kind:     kind,
			Identity: u.Name,
			Location: p,
			Modified: fi.ModTime(),
			Secret:   v.Store([]byte(secret)),
		})
	}
	return creds, nil
}
