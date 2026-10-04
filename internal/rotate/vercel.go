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

// Vercel rotates a Vercel access token via the REST API by CREATING a new token,
// verifying it, then DELETING the old one — the provider-API rotation pattern
// (create-new → verify → revoke-old):
//
//	POST   /v3/user/tokens        (Bearer old-token) -> {token:{id}, bearerToken}
//	GET    /v3/user/tokens        (Bearer new-token) -> {tokens:[{id,...}]}  (auth + membership)
//	DELETE /v3/user/tokens/<old-id> (Bearer old-token)
//
// Vercel returns the bearer secret only once, at create time, alongside the token's id;
// revoking the OLD token needs that id, so the credential carries it. The credential's
// secret is a single self-contained line:
//
//	vercel://<host>/?id=<token-id>&secret=<bearer>
//
//   - scheme  "vercel" maps to https; "http"/"https" are accepted so a test can point
//             at a loopback emulator.
//   - <host>  API host; "vercel" (or empty) defaults to api.vercel.com.
//   - id=     the token id (non-secret) — names the DELETE path for revoke-old.
//   - secret= the bearer token (rotated).
//
// SECURITY: the token lives only in the vault blob and the Bearer header; it never
// reaches Identity/Meta/logs/argv. The new token is decoded straight from the create
// response into the rebuilt blob.
type Vercel struct {
	// HTTPClient is injectable for tests / custom TLS. Defaults to a 15s-timeout client.
	HTTPClient *http.Client
}

// init self-registers the driver. Availability alone changes nothing; the
// `rotate --execute` + INCREDIGO_ALLOW_EXECUTE=1 gate still applies.
func init() { Register(&Vercel{}) }

// Name identifies the driver in plans and audit records.
func (ve *Vercel) Name() string { return "vercel" }

// Detect claims credentials tagged Source == "vercel".
func (ve *Vercel) Detect(c discover.Credential) bool { return c.Source == "vercel" }

func (ve *Vercel) client() *http.Client {
	if ve.HTTPClient != nil {
		return ve.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// vercelSecret is the parsed credential blob. None of its fields are ever logged.
type vercelSecret struct {
	base   string // scheme://host
	id     string // token id (non-secret)
	secret string // bearer token
}

func parseVercelSecret(v *vault.Vault, h *vault.Handle) (vercelSecret, error) {
	buf, err := v.Open(h)
	if err != nil {
		return vercelSecret{}, err
	}
	u, err := url.Parse(strings.TrimSpace(string(buf.Bytes())))
	if err != nil {
		return vercelSecret{}, fmt.Errorf("vercel: parse secret url: %w", err)
	}
	if u.Scheme != "vercel" && u.Scheme != "http" && u.Scheme != "https" {
		return vercelSecret{}, fmt.Errorf("vercel: unexpected scheme %q", u.Scheme)
	}
	scheme := u.Scheme
	host := u.Host
	if scheme == "vercel" {
		scheme = "https"
	}
	if host == "" || host == "vercel" {
		host = "api.vercel.com"
	}
	q := u.Query()
	s := vercelSecret{base: scheme + "://" + host, id: q.Get("id"), secret: q.Get("secret")}
	if s.secret == "" {
		return vercelSecret{}, fmt.Errorf("vercel: secret missing bearer token")
	}
	return s, nil
}

// build re-encodes a vercelSecret into the single-line blob form (scheme normalised
// back to "vercel").
func (s vercelSecret) build() string {
	host := hostOf(s.base)
	if host == "api.vercel.com" {
		host = "vercel"
	}
	u := &url.URL{Scheme: "vercel", Host: host, Path: "/"}
	q := url.Values{}
	q.Set("id", s.id)
	q.Set("secret", s.secret)
	u.RawQuery = q.Encode()
	return u.String()
}

func (s vercelSecret) tokensURL(id string) string {
	base := s.base + "/v3/user/tokens"
	if id != "" {
		return base + "/" + url.PathEscape(id)
	}
	return base
}

// Rotate creates a NEW access token (authenticated by the OLD token) and returns a
// vault handle to a rebuilt blob carrying the new id + token. It does not delete the old.
func (ve *Vercel) Rotate(ctx context.Context, c discover.Credential, v *vault.Vault) (*vault.Handle, error) {
	s, err := parseVercelSecret(v, c.Secret)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string]string{"name": "incredigo-rotated"})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokensURL(""), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.secret)
	resp, err := ve.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("vercel: create token: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vercel: create token: unexpected status %s", resp.Status)
	}
	var created struct {
		Token struct {
			ID string `json:"id"`
		} `json:"token"`
		BearerToken string `json:"bearerToken"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return nil, fmt.Errorf("vercel: decode created token: %w", err)
	}
	if created.Token.ID == "" || created.BearerToken == "" {
		return nil, fmt.Errorf("vercel: create token: empty id or bearerToken in response")
	}
	ns := s
	ns.id = created.Token.ID
	ns.secret = created.BearerToken
	return v.Store([]byte(ns.build())), nil
}

// Verify proves the newly minted token authenticates by listing tokens with it and
// confirming the new id is present (auth success + the token really exists).
func (ve *Vercel) Verify(ctx context.Context, newSecret *vault.Handle, v *vault.Vault) error {
	s, err := parseVercelSecret(v, newSecret)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.tokensURL(""), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.secret)
	resp, err := ve.client().Do(req)
	if err != nil {
		return fmt.Errorf("vercel verify: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vercel verify: list tokens status %s", resp.Status)
	}
	var got struct {
		Tokens []struct {
			ID string `json:"id"`
		} `json:"tokens"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		return fmt.Errorf("vercel verify: decode tokens: %w", err)
	}
	for _, tkn := range got.Tokens {
		if tkn.ID == s.id {
			return nil
		}
	}
	return fmt.Errorf("vercel verify: new token id not present in account")
}

// RevokeOld deletes the OLD access token by its id. The old token is still valid at
// this point (revoke runs only after the new token is stored+verified), so it
// authenticates its own deletion.
func (ve *Vercel) RevokeOld(ctx context.Context, c discover.Credential, v *vault.Vault) error {
	s, err := parseVercelSecret(v, c.Secret)
	if err != nil {
		return err
	}
	if s.id == "" {
		return fmt.Errorf("vercel revoke: credential has no token id")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.tokensURL(s.id), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.secret)
	resp, err := ve.client().Do(req)
	if err != nil {
		return fmt.Errorf("vercel revoke: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("vercel revoke: delete token status %s", resp.Status)
	}
	return nil
}
