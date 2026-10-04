package discover

import (
	"bufio"
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"incredigo/internal/vault"
)

func init() { Register(&gitScanner{}) }

// gitScanner reads ~/.git-credentials, whose lines are URLs with embedded
// credentials, e.g. https://user:ghp_xxx@github.com. The userinfo password is the
// secret. Read-only.
type gitScanner struct{}

func (g *gitScanner) Name() string { return "git" }

func (g *gitScanner) path() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".git-credentials")
}

func (g *gitScanner) Available() bool {
	_, err := os.Stat(g.path())
	return err == nil
}

func (g *gitScanner) Scan(ctx context.Context, v *vault.Vault) ([]Credential, error) {
	p := g.path()
	f, err := os.Open(p) // read-only
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, _ := f.Stat()

	var creds []Credential
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		u, err := url.Parse(line)
		if err != nil || u.User == nil {
			continue
		}
		pass, ok := u.User.Password()
		if !ok || pass == "" {
			continue
		}
		id := u.Host
		if user := u.User.Username(); user != "" {
			id = user + " @ " + u.Host
		}
		creds = append(creds, Credential{
			Source:   g.Name(),
			Kind:     KindToken,
			Identity: id,
			Location: p,
			Modified: fi.ModTime(),
			Secret:   v.Store([]byte(pass)),
		})
	}
	return creds, sc.Err()
}
