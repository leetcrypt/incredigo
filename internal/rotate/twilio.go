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

// Twilio rotates a Twilio API Key (SK...) via the REST API by CREATING a new key,
// verifying it, then DELETING the old one — the provider-API rotation pattern
// (create-new → verify → revoke-old):
//
//	POST   /2010-04-01/Accounts/<AC>/Keys.json       (Basic old-key) -> {sid, secret}
//	GET    /2010-04-01/Accounts/<AC>/Keys/<new>.json (Basic new-key) -> {sid}
//	DELETE /2010-04-01/Accounts/<AC>/Keys/<old>.json (Basic old-key)
//
// A Twilio API key authenticates as Basic auth username=<KeySid> password=<KeySecret>;
// the secret is returned by Twilio only once at create time. The credential's secret is
// a single self-contained line:
//
//	twilio://<host>/?account=<AC...>&sid=<SK...>&secret=<secret>[&endpoint=<url>]
//
//   - scheme   "twilio" maps to https; "http"/"https" are accepted so a test can point
//              at a loopback emulator.
//   - <host>   API host; "twilio" (or empty) defaults to api.twilio.com.
//   - account= the Account SID (AC...) — non-secret, names the URL path.
//   - sid=     the API Key SID (SK...) — non-secret Basic-auth username.
//   - secret=  the API Key secret — Basic-auth password (rotated).
//
// SECURITY: the secret lives only in the vault blob and the Basic-auth header; it never
// reaches Identity/Meta/logs/argv. The new secret is decoded straight from the create
// response into the rebuilt blob.
type Twilio struct {
	// HTTPClient is injectable for tests / custom TLS. Defaults to a 15s-timeout client.
	HTTPClient *http.Client
}

// init self-registers the driver. Availability alone changes nothing; the
// `rotate --execute` + INCREDIGO_ALLOW_EXECUTE=1 gate still applies.
func init() { Register(&Twilio{}) }

// Name identifies the driver in plans and audit records.
func (tw *Twilio) Name() string { return "twilio" }

// Detect claims credentials tagged Source == "twilio".
func (tw *Twilio) Detect(c discover.Credential) bool { return c.Source == "twilio" }

func (tw *Twilio) client() *http.Client {
	if tw.HTTPClient != nil {
		return tw.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// twilioSecret is the parsed credential blob. None of its fields are ever logged.
type twilioSecret struct {
	base    string // scheme://host
	account string // AC...
	sid     string // SK...
	secret  string
}

func parseTwilioSecret(v *vault.Vault, h *vault.Handle) (twilioSecret, error) {
	buf, err := v.Open(h)
	if err != nil {
		return twilioSecret{}, err
	}
	u, err := url.Parse(strings.TrimSpace(string(buf.Bytes())))
	if err != nil {
		return twilioSecret{}, fmt.Errorf("twilio: parse secret url: %w", err)
	}
	if u.Scheme != "twilio" && u.Scheme != "http" && u.Scheme != "https" {
		return twilioSecret{}, fmt.Errorf("twilio: unexpected scheme %q", u.Scheme)
	}
	scheme := u.Scheme
	host := u.Host
	if scheme == "twilio" {
		scheme = "https"
	}
	if host == "" || host == "twilio" {
		host = "api.twilio.com"
	}
	q := u.Query()
	s := twilioSecret{base: scheme + "://" + host, account: q.Get("account"), sid: q.Get("sid"), secret: q.Get("secret")}
	if s.account == "" {
		return twilioSecret{}, fmt.Errorf("twilio: secret has no account sid")
	}
	if s.sid == "" || s.secret == "" {
		return twilioSecret{}, fmt.Errorf("twilio: secret missing key sid or secret")
	}
	return s, nil
}

// build re-encodes a twilioSecret into the single-line blob form (scheme normalised
// back to "twilio").
func (s twilioSecret) build() string {
	host := hostOf(s.base)
	if host == "api.twilio.com" {
		host = "twilio"
	}
	u := &url.URL{Scheme: "twilio", Host: host, Path: "/"}
	q := url.Values{}
	q.Set("account", s.account)
	q.Set("sid", s.sid)
	q.Set("secret", s.secret)
	u.RawQuery = q.Encode()
	return u.String()
}

func (s twilioSecret) keysURL(sid string) string {
	base := s.base + "/2010-04-01/Accounts/" + url.PathEscape(s.account) + "/Keys"
	if sid != "" {
		return base + "/" + url.PathEscape(sid) + ".json"
	}
	return base + ".json"
}

// Rotate creates a NEW API key (authenticated by the OLD key) and returns a vault
// handle to a rebuilt blob carrying the new sid + secret. It does not delete the old key.
func (tw *Twilio) Rotate(ctx context.Context, c discover.Credential, v *vault.Vault) (*vault.Handle, error) {
	s, err := parseTwilioSecret(v, c.Secret)
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("FriendlyName", "incredigo-rotated")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.keysURL(""), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(s.sid, s.secret)
	resp, err := tw.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("twilio: create key: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("twilio: create key: unexpected status %s", resp.Status)
	}
	var created struct {
		Sid    string `json:"sid"`
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return nil, fmt.Errorf("twilio: decode created key: %w", err)
	}
	if created.Sid == "" || created.Secret == "" {
		return nil, fmt.Errorf("twilio: create key: empty sid or secret in response")
	}
	ns := s
	ns.sid = created.Sid
	ns.secret = created.Secret
	return v.Store([]byte(ns.build())), nil
}

// Verify proves the newly minted key authenticates by GETting its own Key resource.
func (tw *Twilio) Verify(ctx context.Context, newSecret *vault.Handle, v *vault.Vault) error {
	s, err := parseTwilioSecret(v, newSecret)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.keysURL(s.sid), nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(s.sid, s.secret)
	resp, err := tw.client().Do(req)
	if err != nil {
		return fmt.Errorf("twilio verify: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("twilio verify: get key status %s", resp.Status)
	}
	var got struct {
		Sid string `json:"sid"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		return fmt.Errorf("twilio verify: decode key: %w", err)
	}
	if got.Sid != s.sid {
		return fmt.Errorf("twilio verify: key sid mismatch")
	}
	return nil
}

// RevokeOld deletes the OLD API key by its sid. The old key is still valid at this
// point (revoke runs only after the new key is stored+verified), so it authenticates
// its own deletion.
func (tw *Twilio) RevokeOld(ctx context.Context, c discover.Credential, v *vault.Vault) error {
	s, err := parseTwilioSecret(v, c.Secret)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.keysURL(s.sid), nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(s.sid, s.secret)
	resp, err := tw.client().Do(req)
	if err != nil {
		return fmt.Errorf("twilio revoke: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("twilio revoke: delete key status %s", resp.Status)
	}
	return nil
}
