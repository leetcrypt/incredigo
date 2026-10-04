package discover

import (
	"bufio"
	"context"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"incredigo/internal/vault"
)

func init() { Register(&envScanner{}) }

// envScanner reads .env files in the current working directory. It keeps only
// values that look secret-ish: the key name matches a sensitive pattern OR the
// value has high Shannon entropy. This avoids hoovering up PORT=8080 etc.
type envScanner struct{}

func (e *envScanner) Name() string { return "env" }

func (e *envScanner) files() []string {
	matches, _ := filepath.Glob(".env")
	more, _ := filepath.Glob(".env.*")
	return append(matches, more...)
}

func (e *envScanner) Available() bool { return len(e.files()) > 0 }

var sensitiveHints = []string{
	"secret", "token", "passwd", "password", "apikey", "api_key",
	"private", "key", "credential", "auth", "access",
}

func (e *envScanner) Scan(ctx context.Context, v *vault.Vault) ([]Credential, error) {
	var creds []Credential
	for _, p := range e.files() {
		f, err := os.Open(p) // read-only
		if err != nil {
			return creds, err
		}
		fi, _ := f.Stat()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			line = strings.TrimPrefix(line, "export ")
			k, val, ok := splitKV(line)
			if !ok || val == "" {
				continue
			}
			val = strings.Trim(val, `"'`)
			// A connection-string value (DATABASE_URL, REDIS_URL, …) is tagged with
			// the rotation driver's Source so it becomes driver-ready, and is kept
			// regardless of the secret-ish heuristic: a weak/empty DB password is
			// exactly the kind of leak we must not miss.
			source, kind := e.Name(), Kind(KindToken)
			secretBlob := val
			if dbSrc := dbSourceForURL(val); dbSrc != "" {
				source, kind = dbSrc, KindPassword
			} else if appSigningKey(k) && len(val) >= 12 {
				// An app SIGNING secret (Django SECRET_KEY, Rails secret_key_base, a
				// JWT signing secret, …) lives in this very file; tag it Source=
				// "appsecret" with a self-contained blob carrying the value AND its
				// file path so the local in-place rotator is driver-ready.
				source = "appsecret"
				secretBlob = "appsecret://local/?" + url.Values{
					"key": {k}, "val": {val}, "path": {p},
				}.Encode()
			} else if !looksSecret(k, val) {
				continue
			}
			// For a generic env token (not a driver-ready DB URL / appsecret), record
			// a non-secret service hint when the value carries a well-known provider
			// prefix, so the worklist can offer a guided change-password page.
			var meta map[string]string
			if source == e.Name() {
				if svc := ServiceForSecret([]byte(val)); svc != "" {
					meta = map[string]string{MetaService: svc}
				}
			}
			creds = append(creds, Credential{
				Source:   source,
				Kind:     kind,
				Identity: filepath.Base(p) + " / " + k,
				Location: p,
				Modified: fi.ModTime(),
				Secret:   v.Store([]byte(secretBlob)),
				Meta:     meta,
			})
		}
		f.Close()
		if err := sc.Err(); err != nil {
			return creds, err
		}
	}
	return creds, nil
}

// dbSourceForURL maps a value that is a database connection URL to the rotation
// driver Source that can rotate it ("postgres"/"mysql"/"redis"), or "" if the value
// is not a recognised DB URL. It requires a user:password authority so a bare
// "redis://localhost" (nothing to rotate) is not mis-tagged.
func dbSourceForURL(val string) string {
	u, err := url.Parse(val)
	if err != nil || u.User == nil {
		return ""
	}
	if _, hasPw := u.User.Password(); !hasPw && u.User.Username() == "" {
		return ""
	}
	switch strings.ToLower(u.Scheme) {
	case "postgres", "postgresql":
		return "postgres"
	case "mysql", "mariadb":
		return "mysql"
	case "redis", "rediss":
		return "redis"
	}
	return ""
}

// appSigningKeys are the env-var names that denote a local application SIGNING secret
// — the kind the appsecret rotator can regenerate in place. Matched case-insensitively
// and exactly (so STRIPE_API_KEY / DB_PASSWORD stay generic env secrets, not appsecrets).
var appSigningKeys = map[string]bool{
	"secret_key":        true, // Django / Flask
	"secret_key_base":   true, // Rails
	"django_secret_key": true,
	"flask_secret_key":  true,
	"app_key":           true, // Laravel
	"app_secret":        true,
	"jwt_secret":        true,
	"session_secret":    true,
	"nextauth_secret":   true,
	"rails_secret":      true,
}

func appSigningKey(key string) bool { return appSigningKeys[strings.ToLower(key)] }

func looksSecret(key, val string) bool {
	lk := strings.ToLower(key)
	for _, h := range sensitiveHints {
		if strings.Contains(lk, h) {
			return true
		}
	}
	// Fallback: long, high-entropy values are probably secrets.
	return len(val) >= 16 && shannonEntropy(val) >= 3.5
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}
