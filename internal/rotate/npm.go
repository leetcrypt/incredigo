package rotate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// NPM rotates an npm registry access token via the registry token API by CREATING a
// new token, verifying it, then DELETING the old one — the canonical provider-API
// rotation pattern (create-new → verify → revoke-old):
//
//	POST   /-/npm/v1/tokens            (Bearer old) -> {token, key}
//	GET    /-/whoami                   (Bearer new) -> {username}
//	DELETE /-/npm/v1/tokens/token/<key>(Bearer old)
//
// The registry deletes tokens by their KEY (a sha512 id); the token VALUE cannot be
// mapped back to a key, so the key is recorded in the blob (incredigo writes the new
// key on every rotation, keeping the chain self-sustaining). A bare discovered token
// with no key degrades to the guided worklist for the old-token deletion.
//
// The credential's secret is a single self-contained line:
//
//	npm://<host>/?user=<user>&token=<token>&key=<key>
//
//   - scheme    "npm" maps to https; "http"/"https" are accepted so a test can point
//               at a loopback emulator.
//   - <host>    the registry host; "registry" (or empty) defaults to registry.npmjs.org.
//   - token=    the access token being rotated (Bearer auth).
//   - key=      the token's registry key/id — required to DELETE the old token.
//   - user=     optional username (Verify checks /-/whoami matches it when present).
//
// SECURITY: the token lives only in the vault blob and the Bearer header; it never
// reaches Identity/Meta/logs/argv. Response bodies carrying the new token are decoded
// straight into the rebuilt blob.
type NPM struct {
	// HTTPClient is injectable for tests / custom TLS. Defaults to a 15s-timeout
	// client using http.DefaultTransport.
	HTTPClient *http.Client
}

// init self-registers the driver. Availability alone changes nothing; the
// `rotate --execute` + INCREDIGO_ALLOW_EXECUTE=1 gate still applies.
func init() { Register(&NPM{}) }

// Name identifies the driver in plans and audit records.
func (n *NPM) Name() string { return "npm" }

// Detect claims credentials tagged Source == "npm".
func (n *NPM) Detect(c discover.Credential) bool { return c.Source == "npm" }

func (n *NPM) client() *http.Client {
	if n.HTTPClient != nil {
		return n.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// npmSecret is the parsed credential blob. None of its fields are ever logged.
type npmSecret struct {
	base  string // scheme://host
	user  string
	token string
	key   string
}

func parseNPMSecret(v *vault.Vault, h *vault.Handle) (npmSecret, error) {
	buf, err := v.Open(h)
	if err != nil {
		return npmSecret{}, err
	}
	u, err := url.Parse(strings.TrimSpace(string(buf.Bytes())))
	if err != nil {
		return npmSecret{}, fmt.Errorf("npm: parse secret url: %w", err)
	}
	if u.Scheme != "npm" && u.Scheme != "http" && u.Scheme != "https" {
		return npmSecret{}, fmt.Errorf("npm: unexpected scheme %q", u.Scheme)
	}
	scheme := u.Scheme
	host := u.Host
	if scheme == "npm" {
		scheme = "https"
	}
	if host == "" || host == "registry" {
		host = "registry.npmjs.org"
	}
	q := u.Query()
	s := npmSecret{base: scheme + "://" + host, user: q.Get("user"), token: q.Get("token"), key: q.Get("key")}
	if s.token == "" {
		return npmSecret{}, fmt.Errorf("npm: secret has no token")
	}
	return s, nil
}

// build re-encodes an npmSecret into the single-line blob form (scheme normalised back
// to "npm" so the in-vault form stays stable).
func (s npmSecret) build() string {
	host := hostOf(s.base)
	if host == "registry.npmjs.org" {
		host = "registry"
	}
	u := &url.URL{Scheme: "npm", Host: host, Path: "/"}
	q := url.Values{}
	if s.user != "" {
		q.Set("user", s.user)
	}
	q.Set("token", s.token)
	if s.key != "" {
		q.Set("key", s.key)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// Rotate creates a NEW registry token (authenticating with the old token) and returns
// a vault handle to a rebuilt blob carrying the new token + new key. It does not revoke
// the old token.
func (n *NPM) Rotate(ctx context.Context, c discover.Credential, v *vault.Vault) (*vault.Handle, error) {
	s, err := parseNPMSecret(v, c.Secret)
	if err != nil {
		return nil, err
	}
	// readonly:false, no cidr restriction — a like-for-like automation token.
	body, _ := json.Marshal(map[string]any{"readonly": false, "cidr_whitelist": []string{}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+"/-/npm/v1/tokens", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.token)

	resp, err := n.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("npm: create token: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("npm: create token: unexpected status %s", resp.Status)
	}
	var created struct {
		Token string `json:"token"`
		Key   string `json:"key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return nil, fmt.Errorf("npm: decode created token: %w", err)
	}
	if created.Token == "" {
		return nil, fmt.Errorf("npm: create token: empty token in response")
	}

	ns := s
	ns.token = created.Token
	ns.key = created.Key
	return v.Store([]byte(ns.build())), nil
}

// Verify proves the newly minted token authenticates by calling GET /-/whoami with it.
func (n *NPM) Verify(ctx context.Context, newSecret *vault.Handle, v *vault.Vault) error {
	s, err := parseNPMSecret(v, newSecret)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base+"/-/whoami", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := n.client().Do(req)
	if err != nil {
		return fmt.Errorf("npm verify: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("npm verify: /-/whoami status %s", resp.Status)
	}
	var who struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&who); err != nil {
		return fmt.Errorf("npm verify: decode whoami: %w", err)
	}
	if who.Username == "" {
		return fmt.Errorf("npm verify: token did not resolve to a user")
	}
	if s.user != "" && !strings.EqualFold(who.Username, s.user) {
		return fmt.Errorf("npm verify: token authenticates as %q, expected %q", who.Username, s.user)
	}
	return nil
}

// RevokeOld deletes the OLD token by key. The old token is still valid at this point
// (revoke runs only after the new token is stored+verified), so it authenticates its
// own deletion.
func (n *NPM) RevokeOld(ctx context.Context, c discover.Credential, v *vault.Vault) error {
	s, err := parseNPMSecret(v, c.Secret)
	if err != nil {
		return err
	}
	if s.key == "" {
		return fmt.Errorf("npm revoke: old token has no recorded key — delete it manually (guided)")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		s.base+"/-/npm/v1/tokens/token/"+url.PathEscape(s.key), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := n.client().Do(req)
	if err != nil {
		return fmt.Errorf("npm revoke: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("npm revoke: delete token status %s", resp.Status)
	}
	return nil
}
