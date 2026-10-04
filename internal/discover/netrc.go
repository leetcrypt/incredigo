package discover

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"

	"incredigo/internal/vault"
)

func init() { Register(&netrcScanner{}) }

// netrcScanner reads ~/.netrc and ~/.authinfo (whitespace-delimited
// machine/login/password tokens). Read-only.
type netrcScanner struct{}

func (n *netrcScanner) Name() string { return "netrc" }

func (n *netrcScanner) paths() []string {
	home, _ := os.UserHomeDir()
	return []string{
		filepath.Join(home, ".netrc"),
		filepath.Join(home, ".authinfo"),
	}
}

func (n *netrcScanner) Available() bool {
	for _, p := range n.paths() {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

func (n *netrcScanner) Scan(ctx context.Context, v *vault.Vault) ([]Credential, error) {
	var creds []Credential
	for _, p := range n.paths() {
		f, err := os.Open(p) // read-only
		if err != nil {
			continue // a missing alternate file is fine
		}
		fi, _ := f.Stat()
		toks := tokenizeWords(f)
		f.Close()

		var machine, login, password string
		flush := func() {
			if machine != "" && password != "" {
				id := machine
				if login != "" {
					id = login + " @ " + machine
				}
				creds = append(creds, Credential{
					Source:   n.Name(),
					Kind:     KindPassword,
					Identity: id,
					Location: p,
					Modified: fi.ModTime(),
					Secret:   v.Store([]byte(password)),
				})
			}
			machine, login, password = "", "", ""
		}

		for i := 0; i < len(toks); i++ {
			switch toks[i] {
			case "machine":
				flush()
				if i+1 < len(toks) {
					machine = toks[i+1]
					i++
				}
			case "default":
				flush()
				machine = "default"
			case "login":
				if i+1 < len(toks) {
					login = toks[i+1]
					i++
				}
			case "password":
				if i+1 < len(toks) {
					password = toks[i+1]
					i++
				}
			case "account", "macdef":
				if i+1 < len(toks) { // skip the value token
					i++
				}
			}
		}
		flush()
	}
	return creds, nil
}

// tokenizeWords splits an io.Reader into whitespace-delimited tokens.
func tokenizeWords(r io.Reader) []string {
	sc := bufio.NewScanner(r)
	sc.Split(bufio.ScanWords)
	var t []string
	for sc.Scan() {
		t = append(t, sc.Text())
	}
	return t
}
