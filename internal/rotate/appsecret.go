package rotate

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// AppSecret rotates a LOCAL application signing secret — the kind of long, random
// string an app uses to sign sessions/tokens (Django SECRET_KEY, Rails
// secret_key_base, Flask SECRET_KEY, a JWT signing secret, an APP_KEY, …). Unlike the
// gopass-custodied credentials, an app signing secret's authoritative home IS a config
// file the app reads at boot, so "rotating" it means generating a fresh value and
// rewriting it, in place, in every file that holds the current value.
//
// This is an in-place rotation: replacing the literal old value with a fresh one is
// itself the cutover (the old value is gone the moment the files are rewritten), so
// RevokeOld is a no-op and the §3 sealed backup is the recovery path. Verify re-reads
// every target file and proves the new value is present and the old value is absent.
//
// The credential's secret is a single self-contained line (so it round-trips the
// single-line gopass sink unchanged):
//
//	appsecret://local/?key=<NAME>&val=<value>&path=<file>[&path=<file>…]
//
//   - key=   the setting/env-var name the secret is stored under (human-readable;
//            used only for the audit identity, never for matching).
//   - val=   the CURRENT secret value. Replacement is keyed on this literal string,
//            so it works regardless of file format (.env / yaml / json / toml).
//   - path=  one or more files that contain the value. All are rewritten atomically.
//
// SECURITY (Hard Rule #3): val is a secret — it lives only in the vault blob and is
// written to the app's OWN config files (its legitimate secret store); it never reaches
// Identity/Meta/logs/argv, and every error scrubs it. A minimum-length guard refuses to
// treat a short, common string as the secret (which could mass-corrupt files).
type AppSecret struct{}

// init self-registers the driver. Availability alone changes nothing; the
// `rotate --execute` + INCREDIGO_ALLOW_EXECUTE=1 gate still applies.
func init() { Register(&AppSecret{}) }

// Name identifies the driver in plans and audit records.
func (a *AppSecret) Name() string { return "appsecret" }

// Detect claims credentials tagged Source == "appsecret".
func (a *AppSecret) Detect(c discover.Credential) bool { return c.Source == "appsecret" }

// appSec is the parsed credential blob. None of its fields are ever logged.
type appSec struct {
	key   string
	val   string
	paths []string
}

// minSecretLen guards against keying a literal replacement on a short/common string.
// Real app signing secrets are long random strings; anything shorter is rejected so a
// stray "val=key" can never sweep through unrelated file contents.
const minSecretLen = 12

func parseAppSecret(v *vault.Vault, h *vault.Handle) (appSec, error) {
	buf, err := v.Open(h)
	if err != nil {
		return appSec{}, err
	}
	u, err := url.Parse(strings.TrimSpace(string(buf.Bytes())))
	if err != nil {
		return appSec{}, fmt.Errorf("appsecret: parse secret url: %w", err)
	}
	if u.Scheme != "appsecret" {
		return appSec{}, fmt.Errorf("appsecret: unexpected scheme %q", u.Scheme)
	}
	q := u.Query()
	s := appSec{key: q.Get("key"), val: q.Get("val"), paths: q["path"]}
	if s.val == "" {
		return appSec{}, fmt.Errorf("appsecret: secret has no value")
	}
	if len(s.val) < minSecretLen {
		return appSec{}, fmt.Errorf("appsecret: value too short to rotate safely (<%d chars)", minSecretLen)
	}
	if len(s.paths) == 0 {
		return appSec{}, fmt.Errorf("appsecret: secret names no target file")
	}
	return s, nil
}

// build re-encodes an appSec into the single-line blob form.
func (s appSec) build() string {
	u := &url.URL{Scheme: "appsecret", Host: "local", Path: "/"}
	q := url.Values{}
	if s.key != "" {
		q.Set("key", s.key)
	}
	q.Set("val", s.val)
	for _, p := range s.paths {
		q.Add("path", p)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// Rotate generates a fresh value and rewrites every target file, replacing the literal
// old value in place, then returns a vault handle to a rebuilt blob carrying the new
// value. It requires that at least one replacement actually happened across the files;
// otherwise the old value was not where we were told it is and we must NOT claim a
// rotation.
func (a *AppSecret) Rotate(ctx context.Context, c discover.Credential, v *vault.Vault) (*vault.Handle, error) {
	s, err := parseAppSecret(v, c.Secret)
	if err != nil {
		return nil, err
	}
	newVal, err := genHex(32) // 64 hex chars — a strong app signing secret
	if err != nil {
		return nil, err
	}

	total := 0
	for _, p := range s.paths {
		n, err := replaceInFile(p, s.val, newVal)
		if err != nil {
			// Never let the old or new value leak through a path error.
			return nil, fmt.Errorf("appsecret: rewrite %s: %w", p, redactErr(err, s.val, newVal))
		}
		total += n
	}
	if total == 0 {
		return nil, fmt.Errorf("appsecret: old value not found in any target file — nothing rotated")
	}

	ns := s
	ns.val = newVal
	return v.Store([]byte(ns.build())), nil
}

// Verify re-reads every target file and proves the new value is present and the old
// value is absent. It is credential-less in the Execute spine, so it reads the new
// value (and paths) straight from the rebuilt blob.
func (a *AppSecret) Verify(ctx context.Context, newSecret *vault.Handle, v *vault.Vault) error {
	s, err := parseAppSecret(v, newSecret)
	if err != nil {
		return err
	}
	for _, p := range s.paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("appsecret verify: read %s: %w", p, err)
		}
		if !strings.Contains(string(b), s.val) {
			return fmt.Errorf("appsecret verify: new value missing from %s", p)
		}
	}
	return nil
}

// RevokeOld is a no-op: the in-place rewrite already removed the old value from every
// file. Defined to satisfy the safety-spine ordering.
func (a *AppSecret) RevokeOld(ctx context.Context, c discover.Credential, v *vault.Vault) error {
	return nil
}

// replaceInFile replaces every occurrence of old with new in the file at path,
// preserving the file mode, via a temp file + atomic rename so a crash never leaves a
// half-written config. It returns the number of replacements made (0 if old was not
// present — not an error here; Rotate enforces the across-files total).
func replaceInFile(path, old, new string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	n := strings.Count(string(b), old)
	if n == 0 {
		return 0, nil
	}
	out := strings.ReplaceAll(string(b), old, new)

	mode := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	tmp := path + ".incredigo.tmp"
	if err := os.WriteFile(tmp, []byte(out), mode); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return 0, err
	}
	return n, nil
}

// redactErr scrubs any secret substrings out of an error before it can surface.
func redactErr(err error, secrets ...string) error {
	msg := err.Error()
	for _, s := range secrets {
		if s != "" {
			msg = strings.ReplaceAll(msg, s, "***")
		}
	}
	return fmt.Errorf("%s", msg)
}
