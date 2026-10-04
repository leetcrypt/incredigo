package rotate

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/box"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// GHActions rotates the VALUE of a GitHub Actions repository secret in place:
//
//	GET  /repos/{owner}/{repo}/actions/secrets/public-key   -> {key_id, key}
//	PUT  /repos/{owner}/{repo}/actions/secrets/{name}        <- {encrypted_value, key_id}
//
// GitHub stores Actions secrets sealed to the repo's libsodium public key; the only
// way to write one is to encrypt with crypto_box_seal (NaCl "sealed box"). PUT to an
// existing secret name OVERWRITES its value, so the previous value is dead the moment
// the PUT returns — this is an in-place rotation like the DB drivers: RevokeOld is a
// no-op and the §3 sealed backup is the recovery path.
//
// Note on what is being rotated: the rotated material is the SECRET VALUE consumed by
// workflows (val=), NOT the PAT used to authenticate the API call (pat=). The PAT is a
// long-lived management credential carried in the blob; it is unchanged by a roll.
//
// The credential's secret is a single self-contained line (so it round-trips the
// single-line gopass sink unchanged):
//
//	ghactions://<host>/?owner=<o>&repo=<r>&name=<secret-name>&pat=<token>&val=<value>
//
//   - scheme    "ghactions" maps to https; "http"/"https" are accepted so a test can
//               point at a loopback emulator.
//   - <host>    the API host; "api" (or empty) defaults to api.github.com.
//   - owner/repo the repository whose secret is rolled.
//   - name=     the Actions secret name (stable; the roll keeps name/visibility).
//   - pat=      the management PAT (Bearer auth; repo+secrets scope). Not rotated here.
//   - val=      the secret value being rotated. GitHub never returns it, so we keep
//               the plaintext we generated in the rebuilt blob; the wire only ever
//               carries the sealed-box ciphertext.
//
// SECURITY: neither pat nor val ever reaches Identity/Meta/logs/argv. val is generated
// locally, sealed straight into the request body, and otherwise lives only in the
// vault blob. Verify can only prove the secret EXISTS (GitHub never discloses values),
// so it asserts a 200 on the secret's metadata endpoint, not a value match.
type GHActions struct {
	// HTTPClient is injectable for tests / custom TLS. Defaults to a 15s-timeout
	// client using http.DefaultTransport.
	HTTPClient *http.Client
}

// init self-registers the driver. Availability alone changes nothing; the
// `rotate --execute` + INCREDIGO_ALLOW_EXECUTE=1 gate still applies.
func init() { Register(&GHActions{}) }

// Name identifies the driver in plans and audit records.
func (g *GHActions) Name() string { return "ghactions" }

// Detect claims credentials tagged Source == "ghactions".
func (g *GHActions) Detect(c discover.Credential) bool { return c.Source == "ghactions" }

func (g *GHActions) client() *http.Client {
	if g.HTTPClient != nil {
		return g.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// ghaSecret is the parsed credential blob. None of its fields are ever logged.
type ghaSecret struct {
	base  string // scheme://host
	owner string
	repo  string
	name  string
	pat   string
	val   string
}

func parseGHASecret(v *vault.Vault, h *vault.Handle) (ghaSecret, error) {
	buf, err := v.Open(h)
	if err != nil {
		return ghaSecret{}, err
	}
	u, err := url.Parse(strings.TrimSpace(string(buf.Bytes())))
	if err != nil {
		return ghaSecret{}, fmt.Errorf("ghactions: parse secret url: %w", err)
	}
	if u.Scheme != "ghactions" && u.Scheme != "http" && u.Scheme != "https" {
		return ghaSecret{}, fmt.Errorf("ghactions: unexpected scheme %q", u.Scheme)
	}
	scheme := u.Scheme
	host := u.Host
	if scheme == "ghactions" {
		scheme = "https"
	}
	if host == "" || host == "api" {
		host = "api.github.com"
	}
	q := u.Query()
	s := ghaSecret{
		base:  scheme + "://" + host,
		owner: q.Get("owner"),
		repo:  q.Get("repo"),
		name:  q.Get("name"),
		pat:   q.Get("pat"),
		val:   q.Get("val"),
	}
	if s.owner == "" || s.repo == "" {
		return ghaSecret{}, fmt.Errorf("ghactions: secret has no owner/repo")
	}
	if s.name == "" {
		return ghaSecret{}, fmt.Errorf("ghactions: secret has no secret name")
	}
	if s.pat == "" {
		return ghaSecret{}, fmt.Errorf("ghactions: secret has no management pat")
	}
	return s, nil
}

// build re-encodes a ghaSecret into the single-line blob form (scheme normalised back
// to "ghactions" so the in-vault form stays stable).
func (s ghaSecret) build() string {
	host := hostOf(s.base)
	if host == "api.github.com" {
		host = "api"
	}
	u := &url.URL{Scheme: "ghactions", Host: host, Path: "/"}
	q := url.Values{}
	q.Set("owner", s.owner)
	q.Set("repo", s.repo)
	q.Set("name", s.name)
	q.Set("pat", s.pat)
	q.Set("val", s.val)
	u.RawQuery = q.Encode()
	return u.String()
}

func (g *GHActions) authReq(ctx context.Context, method, url, pat string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+pat)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	return req, nil
}

// Rotate generates a fresh value, seals it to the repo's libsodium public key, PUTs it
// over the existing secret name (overwriting the old value), and returns a vault handle
// to a rebuilt blob carrying the new plaintext value.
func (g *GHActions) Rotate(ctx context.Context, c discover.Credential, v *vault.Vault) (*vault.Handle, error) {
	s, err := parseGHASecret(v, c.Secret)
	if err != nil {
		return nil, err
	}

	// 1) fetch the repo's public key for Actions secrets.
	keyURL := fmt.Sprintf("%s/repos/%s/%s/actions/secrets/public-key",
		s.base, url.PathEscape(s.owner), url.PathEscape(s.repo))
	req, err := g.authReq(ctx, http.MethodGet, keyURL, s.pat, nil)
	if err != nil {
		return nil, err
	}
	resp, err := g.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("ghactions: fetch public-key: %w", err)
	}
	var pk struct {
		KeyID string `json:"key_id"`
		Key   string `json:"key"`
	}
	if err := decodeJSON(resp, &pk); err != nil {
		return nil, fmt.Errorf("ghactions: public-key: %w", err)
	}
	if pk.KeyID == "" || pk.Key == "" {
		return nil, fmt.Errorf("ghactions: public-key response incomplete")
	}
	rawKey, err := base64.StdEncoding.DecodeString(pk.Key)
	if err != nil {
		return nil, fmt.Errorf("ghactions: decode public-key: %w", err)
	}
	if len(rawKey) != 32 {
		return nil, fmt.Errorf("ghactions: public-key wrong length %d", len(rawKey))
	}

	// 2) generate the new secret value and seal it (crypto_box_seal).
	newVal, err := genHex(24)
	if err != nil {
		return nil, err
	}
	var recipient [32]byte
	copy(recipient[:], rawKey)
	sealed, err := box.SealAnonymous(nil, []byte(newVal), &recipient, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ghactions: seal value: %w", err)
	}

	// 3) PUT the sealed value over the existing secret name.
	putBody, _ := json.Marshal(map[string]string{
		"encrypted_value": base64.StdEncoding.EncodeToString(sealed),
		"key_id":          pk.KeyID,
	})
	putURL := fmt.Sprintf("%s/repos/%s/%s/actions/secrets/%s",
		s.base, url.PathEscape(s.owner), url.PathEscape(s.repo), url.PathEscape(s.name))
	preq, err := g.authReq(ctx, http.MethodPut, putURL, s.pat, bytes.NewReader(putBody))
	if err != nil {
		return nil, err
	}
	preq.Header.Set("Content-Type", "application/json")
	presp, err := g.client().Do(preq)
	if err != nil {
		return nil, fmt.Errorf("ghactions: put secret: %w", err)
	}
	defer func() { io.Copy(io.Discard, presp.Body); presp.Body.Close() }()
	// GitHub returns 201 (created) or 204 (updated).
	if presp.StatusCode != http.StatusCreated && presp.StatusCode != http.StatusNoContent {
		return nil, fmt.Errorf("ghactions: put secret: unexpected status %s", presp.Status)
	}

	ns := s
	ns.val = newVal
	return v.Store([]byte(ns.build())), nil
}

// Verify proves the secret exists under the (rebuilt) blob's coordinates. GitHub never
// returns Actions secret values, so this is an existence/authorization check (200), not
// a value match — the value's correctness was guaranteed at seal time.
func (g *GHActions) Verify(ctx context.Context, newSecret *vault.Handle, v *vault.Vault) error {
	s, err := parseGHASecret(v, newSecret)
	if err != nil {
		return err
	}
	getURL := fmt.Sprintf("%s/repos/%s/%s/actions/secrets/%s",
		s.base, url.PathEscape(s.owner), url.PathEscape(s.repo), url.PathEscape(s.name))
	req, err := g.authReq(ctx, http.MethodGet, getURL, s.pat, nil)
	if err != nil {
		return err
	}
	resp, err := g.client().Do(req)
	if err != nil {
		return fmt.Errorf("ghactions verify: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ghactions verify: status %s", resp.Status)
	}
	var meta struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return fmt.Errorf("ghactions verify: decode: %w", err)
	}
	if !strings.EqualFold(meta.Name, s.name) {
		return fmt.Errorf("ghactions verify: secret name mismatch")
	}
	return nil
}

// RevokeOld is a no-op: the PUT overwrote the previous value in place, so there is no
// separate old credential to retire. Defined to satisfy the safety-spine ordering.
func (g *GHActions) RevokeOld(ctx context.Context, c discover.Credential, v *vault.Vault) error {
	return nil
}

// decodeJSON drains+closes the response and decodes a 200 body, returning a status
// error otherwise.
func decodeJSON(resp *http.Response, out any) error {
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %s", resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
