package rotate

import (
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

// Cloudflare rotates a Cloudflare API token by ROLLING its value:
//
//	PUT /client/v4/user/tokens/{id}/value
//
// Cloudflare regenerates the secret value of the SAME token id and returns the new
// value; the previous value is invalidated immediately. Because the roll IS the
// cutover (same id, fresh value, old value dead), this is an in-place rotation like
// the DB drivers: RevokeOld is a no-op and the §3 sealed backup is the recovery
// path. Rolling the value (rather than create-new + delete-old) keeps every API
// token's id/policies/name stable, so nothing that references the token by id breaks.
//
// The credential's secret is a single self-contained line (so it round-trips the
// single-line gopass sink unchanged):
//
//	cloudflare://<host>/?id=<token-id>&token=<token-value>
//
//   - scheme    "cloudflare" maps to https; "http"/"https" are accepted so a test
//               can point at a loopback emulator.
//   - <host>    the API host; "api" (or empty) defaults to api.cloudflare.com.
//   - id=       the token id — required to address the roll endpoint; the value
//               cannot be mapped back to an id.
//   - token=    the token value being rotated (Bearer auth).
//
// SECURITY: the token value lives only in the vault blob and the Bearer header; it
// never reaches Identity/Meta/logs/argv. Response bodies carrying the new value are
// decoded straight into the rebuilt blob.
type Cloudflare struct {
	// HTTPClient is injectable for tests / custom TLS. Defaults to a 15s-timeout
	// client using http.DefaultTransport.
	HTTPClient *http.Client
}

// init self-registers the driver. Availability alone changes nothing; the
// `rotate --execute` + INCREDIGO_ALLOW_EXECUTE=1 gate still applies.
func init() { Register(&Cloudflare{}) }

// Name identifies the driver in plans and audit records.
func (c *Cloudflare) Name() string { return "cloudflare" }

// Detect claims credentials tagged Source == "cloudflare".
func (c *Cloudflare) Detect(cr discover.Credential) bool { return cr.Source == "cloudflare" }

func (c *Cloudflare) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// cfSecret is the parsed credential blob. None of its fields are ever logged.
type cfSecret struct {
	base  string // scheme://host
	id    string
	token string
}

func parseCFSecret(v *vault.Vault, h *vault.Handle) (cfSecret, error) {
	buf, err := v.Open(h)
	if err != nil {
		return cfSecret{}, err
	}
	u, err := url.Parse(strings.TrimSpace(string(buf.Bytes())))
	if err != nil {
		return cfSecret{}, fmt.Errorf("cloudflare: parse secret url: %w", err)
	}
	if u.Scheme != "cloudflare" && u.Scheme != "http" && u.Scheme != "https" {
		return cfSecret{}, fmt.Errorf("cloudflare: unexpected scheme %q", u.Scheme)
	}
	scheme := u.Scheme
	host := u.Host
	if scheme == "cloudflare" {
		scheme = "https"
	}
	if host == "" || host == "api" {
		host = "api.cloudflare.com"
	}
	q := u.Query()
	s := cfSecret{base: scheme + "://" + host, id: q.Get("id"), token: q.Get("token")}
	if s.token == "" {
		return cfSecret{}, fmt.Errorf("cloudflare: secret has no token")
	}
	if s.id == "" {
		return cfSecret{}, fmt.Errorf("cloudflare: secret has no token id")
	}
	return s, nil
}

// build re-encodes a cfSecret into the single-line blob form (scheme normalised back
// to "cloudflare" so the in-vault form stays stable).
func (s cfSecret) build() string {
	host := hostOf(s.base)
	if host == "api.cloudflare.com" {
		host = "api"
	}
	u := &url.URL{Scheme: "cloudflare", Host: host, Path: "/"}
	q := url.Values{}
	q.Set("id", s.id)
	q.Set("token", s.token)
	u.RawQuery = q.Encode()
	return u.String()
}

// cfResult is the standard Cloudflare envelope; only the fields we use are decoded.
type cfRollResult struct {
	Result  string `json:"result"`
	Success bool   `json:"success"`
}

// Rotate rolls the token value and returns a vault handle to a rebuilt blob carrying
// the new value (same id). The old value is dead the moment Cloudflare responds.
func (c *Cloudflare) Rotate(ctx context.Context, cr discover.Credential, v *vault.Vault) (*vault.Handle, error) {
	s, err := parseCFSecret(v, cr.Secret)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		s.base+"/client/v4/user/tokens/"+url.PathEscape(s.id)+"/value", strings.NewReader("{}"))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.token)

	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: roll token: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cloudflare: roll token: unexpected status %s", resp.Status)
	}
	var rolled cfRollResult
	if err := json.NewDecoder(resp.Body).Decode(&rolled); err != nil {
		return nil, fmt.Errorf("cloudflare: decode rolled token: %w", err)
	}
	if !rolled.Success || rolled.Result == "" {
		return nil, fmt.Errorf("cloudflare: roll token: empty value in response")
	}

	ns := s
	ns.token = rolled.Result
	return v.Store([]byte(ns.build())), nil
}

// Verify proves the new token value authenticates and is active via the token
// verify endpoint.
func (c *Cloudflare) Verify(ctx context.Context, newSecret *vault.Handle, v *vault.Vault) error {
	s, err := parseCFSecret(v, newSecret)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base+"/client/v4/user/tokens/verify", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare verify: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cloudflare verify: status %s", resp.Status)
	}
	var verified struct {
		Success bool `json:"success"`
		Result  struct {
			Status string `json:"status"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&verified); err != nil {
		return fmt.Errorf("cloudflare verify: decode: %w", err)
	}
	if !verified.Success || verified.Result.Status != "active" {
		return fmt.Errorf("cloudflare verify: token not active")
	}
	return nil
}

// RevokeOld is a no-op: rolling the value already invalidated the previous token.
// Defined to satisfy the safety-spine ordering.
func (c *Cloudflare) RevokeOld(ctx context.Context, cr discover.Credential, v *vault.Vault) error {
	return nil
}
