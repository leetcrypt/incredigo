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

// Resend rotates a Resend API key (re_...) via the REST API by CREATING a new key,
// verifying it, then DELETING the old one — the provider-API rotation pattern
// (create-new → verify → revoke-old):
//
//	POST   /api-keys            (Bearer old-key) -> {id, token}
//	GET    /api-keys            (Bearer new-key) -> {data:[{id,...}]}   (auth + membership proof)
//	DELETE /api-keys/<old-id>   (Bearer old-key)
//
// A Resend key authenticates as `Authorization: Bearer re_...`; the token is returned
// by Resend only once, at create time, alongside its id. Revoking the OLD key needs
// that key's id, so the credential carries it. The credential's secret is a single
// self-contained line:
//
//	resend://<host>/?id=<key-id>&secret=<re_token>
//
//   - scheme  "resend" maps to https; "http"/"https" are accepted so a test can point
//             at a loopback emulator.
//   - <host>  API host; "resend" (or empty) defaults to api.resend.com.
//   - id=     the API key id (non-secret) — names the DELETE path for revoke-old.
//   - secret= the API key token (Bearer credential, rotated).
//
// SECURITY: the token lives only in the vault blob and the Bearer header; it never
// reaches Identity/Meta/logs/argv. The new token is decoded straight from the create
// response into the rebuilt blob.
type Resend struct {
	// HTTPClient is injectable for tests / custom TLS. Defaults to a 15s-timeout client.
	HTTPClient *http.Client
}

// init self-registers the driver. Availability alone changes nothing; the
// `rotate --execute` + INCREDIGO_ALLOW_EXECUTE=1 gate still applies.
func init() { Register(&Resend{}) }

// Name identifies the driver in plans and audit records.
func (re *Resend) Name() string { return "resend" }

// Detect claims credentials tagged Source == "resend".
func (re *Resend) Detect(c discover.Credential) bool { return c.Source == "resend" }

func (re *Resend) client() *http.Client {
	if re.HTTPClient != nil {
		return re.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// resendSecret is the parsed credential blob. None of its fields are ever logged.
type resendSecret struct {
	base   string // scheme://host
	id     string // key id (non-secret)
	secret string // re_... Bearer token
}

func parseResendSecret(v *vault.Vault, h *vault.Handle) (resendSecret, error) {
	buf, err := v.Open(h)
	if err != nil {
		return resendSecret{}, err
	}
	u, err := url.Parse(strings.TrimSpace(string(buf.Bytes())))
	if err != nil {
		return resendSecret{}, fmt.Errorf("resend: parse secret url: %w", err)
	}
	if u.Scheme != "resend" && u.Scheme != "http" && u.Scheme != "https" {
		return resendSecret{}, fmt.Errorf("resend: unexpected scheme %q", u.Scheme)
	}
	scheme := u.Scheme
	host := u.Host
	if scheme == "resend" {
		scheme = "https"
	}
	if host == "" || host == "resend" {
		host = "api.resend.com"
	}
	q := u.Query()
	s := resendSecret{base: scheme + "://" + host, id: q.Get("id"), secret: q.Get("secret")}
	if s.secret == "" {
		return resendSecret{}, fmt.Errorf("resend: secret missing token")
	}
	return s, nil
}

// build re-encodes a resendSecret into the single-line blob form (scheme normalised
// back to "resend").
func (s resendSecret) build() string {
	host := hostOf(s.base)
	if host == "api.resend.com" {
		host = "resend"
	}
	u := &url.URL{Scheme: "resend", Host: host, Path: "/"}
	q := url.Values{}
	q.Set("id", s.id)
	q.Set("secret", s.secret)
	u.RawQuery = q.Encode()
	return u.String()
}

func (s resendSecret) keysURL(id string) string {
	base := s.base + "/api-keys"
	if id != "" {
		return base + "/" + url.PathEscape(id)
	}
	return base
}

// Rotate creates a NEW API key (authenticated by the OLD key) and returns a vault
// handle to a rebuilt blob carrying the new id + token. It does not delete the old key.
func (re *Resend) Rotate(ctx context.Context, c discover.Credential, v *vault.Vault) (*vault.Handle, error) {
	s, err := parseResendSecret(v, c.Secret)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string]string{"name": "incredigo-rotated", "permission": "full_access"})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.keysURL(""), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.secret)
	resp, err := re.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("resend: create key: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("resend: create key: unexpected status %s", resp.Status)
	}
	var created struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return nil, fmt.Errorf("resend: decode created key: %w", err)
	}
	if created.ID == "" || created.Token == "" {
		return nil, fmt.Errorf("resend: create key: empty id or token in response")
	}
	ns := s
	ns.id = created.ID
	ns.secret = created.Token
	return v.Store([]byte(ns.build())), nil
}

// Verify proves the newly minted key authenticates by listing keys with it and
// confirming the new id is present (auth success + the key really exists).
func (re *Resend) Verify(ctx context.Context, newSecret *vault.Handle, v *vault.Vault) error {
	s, err := parseResendSecret(v, newSecret)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.keysURL(""), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.secret)
	resp, err := re.client().Do(req)
	if err != nil {
		return fmt.Errorf("resend verify: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("resend verify: list keys status %s", resp.Status)
	}
	var got struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		return fmt.Errorf("resend verify: decode keys: %w", err)
	}
	for _, k := range got.Data {
		if k.ID == s.id {
			return nil
		}
	}
	return fmt.Errorf("resend verify: new key id not present in account")
}

// RevokeOld deletes the OLD API key by its id. The old key is still valid at this
// point (revoke runs only after the new key is stored+verified), so it authenticates
// its own deletion.
func (re *Resend) RevokeOld(ctx context.Context, c discover.Credential, v *vault.Vault) error {
	s, err := parseResendSecret(v, c.Secret)
	if err != nil {
		return err
	}
	if s.id == "" {
		return fmt.Errorf("resend revoke: credential has no key id")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.keysURL(s.id), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.secret)
	resp, err := re.client().Do(req)
	if err != nil {
		return fmt.Errorf("resend revoke: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("resend revoke: delete key status %s", resp.Status)
	}
	return nil
}
