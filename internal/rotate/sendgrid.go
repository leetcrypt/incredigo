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

// SendGrid rotates a SendGrid API key via the REST API by CREATING a new key with the
// SAME scopes as the old one, verifying it, then DELETING the old one — the provider-API
// rotation pattern (create-new → verify → revoke-old):
//
//	GET    /v3/api_keys/<old-id>  (Bearer old-key) -> {scopes:[…]}      (clone scopes)
//	POST   /v3/api_keys           (Bearer old-key) -> {api_key, api_key_id}
//	GET    /v3/scopes             (Bearer new-key) -> {scopes:[…]}      (auth proof)
//	DELETE /v3/api_keys/<old-id>  (Bearer old-key)
//
// SendGrid returns the api_key secret only once, at create time, alongside its
// api_key_id; revoking the OLD key needs that id, so the credential carries it. The
// new key is created with the old key's scopes so the rotation is a faithful
// replacement, not a privilege downgrade. The credential's secret is a single
// self-contained line:
//
//	sendgrid://<host>/?id=<api-key-id>&secret=<SG.token>
//
//   - scheme  "sendgrid" maps to https; "http"/"https" are accepted so a test can point
//             at a loopback emulator.
//   - <host>  API host; "sendgrid" (or empty) defaults to api.sendgrid.com.
//   - id=     the api_key_id (non-secret) — names the GET/DELETE paths.
//   - secret= the API key token (Bearer credential, rotated).
//
// SECURITY: the token lives only in the vault blob and the Bearer header; it never
// reaches Identity/Meta/logs/argv. The new token is decoded straight from the create
// response into the rebuilt blob.
type SendGrid struct {
	// HTTPClient is injectable for tests / custom TLS. Defaults to a 15s-timeout client.
	HTTPClient *http.Client
}

// init self-registers the driver. Availability alone changes nothing; the
// `rotate --execute` + INCREDIGO_ALLOW_EXECUTE=1 gate still applies.
func init() { Register(&SendGrid{}) }

// Name identifies the driver in plans and audit records.
func (sg *SendGrid) Name() string { return "sendgrid" }

// Detect claims credentials tagged Source == "sendgrid".
func (sg *SendGrid) Detect(c discover.Credential) bool { return c.Source == "sendgrid" }

func (sg *SendGrid) client() *http.Client {
	if sg.HTTPClient != nil {
		return sg.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// sendgridSecret is the parsed credential blob. None of its fields are ever logged.
type sendgridSecret struct {
	base   string // scheme://host
	id     string // api_key_id (non-secret)
	secret string // SG.* Bearer token
}

func parseSendGridSecret(v *vault.Vault, h *vault.Handle) (sendgridSecret, error) {
	buf, err := v.Open(h)
	if err != nil {
		return sendgridSecret{}, err
	}
	u, err := url.Parse(strings.TrimSpace(string(buf.Bytes())))
	if err != nil {
		return sendgridSecret{}, fmt.Errorf("sendgrid: parse secret url: %w", err)
	}
	if u.Scheme != "sendgrid" && u.Scheme != "http" && u.Scheme != "https" {
		return sendgridSecret{}, fmt.Errorf("sendgrid: unexpected scheme %q", u.Scheme)
	}
	scheme := u.Scheme
	host := u.Host
	if scheme == "sendgrid" {
		scheme = "https"
	}
	if host == "" || host == "sendgrid" {
		host = "api.sendgrid.com"
	}
	q := u.Query()
	s := sendgridSecret{base: scheme + "://" + host, id: q.Get("id"), secret: q.Get("secret")}
	if s.secret == "" {
		return sendgridSecret{}, fmt.Errorf("sendgrid: secret missing token")
	}
	return s, nil
}

// build re-encodes a sendgridSecret into the single-line blob form (scheme normalised
// back to "sendgrid").
func (s sendgridSecret) build() string {
	host := hostOf(s.base)
	if host == "api.sendgrid.com" {
		host = "sendgrid"
	}
	u := &url.URL{Scheme: "sendgrid", Host: host, Path: "/"}
	q := url.Values{}
	q.Set("id", s.id)
	q.Set("secret", s.secret)
	u.RawQuery = q.Encode()
	return u.String()
}

func (s sendgridSecret) keysURL(id string) string {
	base := s.base + "/v3/api_keys"
	if id != "" {
		return base + "/" + url.PathEscape(id)
	}
	return base
}

// oldScopes reads the scopes of the existing key so the new key can clone them. A
// failure here is non-fatal: rotation proceeds with no explicit scopes rather than
// blocking (SendGrid then mints a key with the account-default scope set).
func (sg *SendGrid) oldScopes(ctx context.Context, s sendgridSecret) []string {
	if s.id == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.keysURL(s.id), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+s.secret)
	resp, err := sg.client().Do(req)
	if err != nil {
		return nil
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var got struct {
		Scopes []string `json:"scopes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		return nil
	}
	return got.Scopes
}

// Rotate creates a NEW API key (authenticated by the OLD key) carrying the old key's
// scopes, and returns a vault handle to a rebuilt blob with the new id + token. It does
// not delete the old key.
func (sg *SendGrid) Rotate(ctx context.Context, c discover.Credential, v *vault.Vault) (*vault.Handle, error) {
	s, err := parseSendGridSecret(v, c.Secret)
	if err != nil {
		return nil, err
	}
	payload := map[string]any{"name": "incredigo-rotated"}
	if scopes := sg.oldScopes(ctx, s); len(scopes) > 0 {
		payload["scopes"] = scopes
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.keysURL(""), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.secret)
	resp, err := sg.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("sendgrid: create key: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sendgrid: create key: unexpected status %s", resp.Status)
	}
	var created struct {
		APIKey   string `json:"api_key"`
		APIKeyID string `json:"api_key_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return nil, fmt.Errorf("sendgrid: decode created key: %w", err)
	}
	if created.APIKey == "" || created.APIKeyID == "" {
		return nil, fmt.Errorf("sendgrid: create key: empty api_key or api_key_id in response")
	}
	ns := s
	ns.id = created.APIKeyID
	ns.secret = created.APIKey
	return v.Store([]byte(ns.build())), nil
}

// Verify proves the newly minted key authenticates by GETting /v3/scopes with it (the
// scopes endpoint succeeds for any valid key regardless of its permission set).
func (sg *SendGrid) Verify(ctx context.Context, newSecret *vault.Handle, v *vault.Vault) error {
	s, err := parseSendGridSecret(v, newSecret)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base+"/v3/scopes", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.secret)
	resp, err := sg.client().Do(req)
	if err != nil {
		return fmt.Errorf("sendgrid verify: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sendgrid verify: get scopes status %s", resp.Status)
	}
	return nil
}

// RevokeOld deletes the OLD API key by its id. The old key is still valid at this
// point (revoke runs only after the new key is stored+verified), so it authenticates
// its own deletion.
func (sg *SendGrid) RevokeOld(ctx context.Context, c discover.Credential, v *vault.Vault) error {
	s, err := parseSendGridSecret(v, c.Secret)
	if err != nil {
		return err
	}
	if s.id == "" {
		return fmt.Errorf("sendgrid revoke: credential has no api_key_id")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.keysURL(s.id), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.secret)
	resp, err := sg.client().Do(req)
	if err != nil {
		return fmt.Errorf("sendgrid revoke: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("sendgrid revoke: delete key status %s", resp.Status)
	}
	return nil
}
