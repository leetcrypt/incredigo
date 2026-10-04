package rotate

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// Mullvad rotates a Mullvad WireGuard device key via the Mullvad app API — the
// provider-API rotation pattern (create-new → verify → revoke-old). A Mullvad
// account holds up to N "devices", each a WireGuard keypair; rotation mints a fresh
// keypair, REGISTERS it as a new device, verifies it, then DELETES the old device.
//
// The credential's secret is a single self-contained line (so it round-trips through
// the single-line gopass sink unchanged):
//
//	mullvad://<account_number>@<api-host>/?device=<device_id>&privkey=<base64-privkey>
//
//   - <account_number> the Mullvad account number — the sole auth secret. Exchanged
//                      for a short-lived access token (POST /auth/v1/token); the
//                      account number itself never goes in a Bearer header.
//   - <device_id>      the device this credential represents (DELETE target on
//                      revoke; the new credential carries the NEW device's id).
//   - privkey=         the device's WireGuard PRIVATE key (base64). Only the derived
//                      PUBLIC key is ever sent to the API; the private key stays in
//                      the vault blob.
//
// SECURITY: account number, private key, and access token live only in the vault and
// in-process; none reach Identity/Meta/logs/argv. This driver is unit-tested against
// an httptest emulator only — it never authenticates to api.mullvad.net in tests
// (that needs a real paid account).
type Mullvad struct {
	// HTTPClient is injectable for tests / custom TLS. Defaults to a 15s-timeout
	// client using http.DefaultTransport.
	HTTPClient *http.Client
}

// init self-registers the driver. Availability alone changes nothing; the
// `rotate --execute` + INCREDIGO_ALLOW_EXECUTE=1 gate still applies.
func init() { Register(&Mullvad{}) }

// Name identifies the driver in plans and audit records.
func (m *Mullvad) Name() string { return "mullvad" }

// Detect claims credentials tagged Source == "mullvad".
func (m *Mullvad) Detect(c discover.Credential) bool { return c.Source == "mullvad" }

func (m *Mullvad) client() *http.Client {
	if m.HTTPClient != nil {
		return m.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// mullvadSecret is the parsed credential blob. None of its fields are ever logged.
type mullvadSecret struct {
	base    string // scheme://host
	account string
	device  string
	privB64 string
}

func parseMullvadSecret(v *vault.Vault, h *vault.Handle) (mullvadSecret, error) {
	buf, err := v.Open(h)
	if err != nil {
		return mullvadSecret{}, err
	}
	u, err := url.Parse(strings.TrimSpace(string(buf.Bytes())))
	if err != nil {
		return mullvadSecret{}, fmt.Errorf("mullvad: parse secret url: %w", err)
	}
	if u.Scheme != "mullvad" && u.Scheme != "http" && u.Scheme != "https" {
		return mullvadSecret{}, fmt.Errorf("mullvad: unexpected scheme %q", u.Scheme)
	}
	if u.User == nil || u.User.Username() == "" {
		return mullvadSecret{}, fmt.Errorf("mullvad: secret has no account number")
	}
	q := u.Query()
	scheme := u.Scheme
	if scheme == "mullvad" {
		scheme = "https"
	}
	s := mullvadSecret{
		base:    scheme + "://" + u.Host,
		account: u.User.Username(),
		device:  q.Get("device"),
		privB64: q.Get("privkey"),
	}
	if s.privB64 == "" {
		return mullvadSecret{}, fmt.Errorf("mullvad: secret has no privkey")
	}
	return s, nil
}

// build re-encodes a mullvadSecret into the single-line blob form (preserving the
// original scheme as "mullvad" so the in-vault form stays stable).
func (s mullvadSecret) build() string {
	u := &url.URL{
		Scheme: "mullvad",
		Host:   hostOf(s.base),
		User:   url.User(s.account),
		Path:   "/",
	}
	q := url.Values{}
	q.Set("device", s.device)
	q.Set("privkey", s.privB64)
	u.RawQuery = q.Encode()
	return u.String()
}

// accessToken exchanges the account number for a short-lived API access token.
func (m *Mullvad) accessToken(ctx context.Context, s mullvadSecret) (string, error) {
	body, _ := json.Marshal(map[string]string{"account_number": s.account})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+"/auth/v1/token", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("mullvad: auth: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("mullvad: auth: status %s", resp.Status)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", fmt.Errorf("mullvad: decode auth: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("mullvad: auth: empty access token")
	}
	return tok.AccessToken, nil
}

// Rotate mints a new WireGuard keypair, registers it as a NEW device, and returns a
// vault handle to a rebuilt blob carrying the new device id + new private key. It
// does not delete the old device.
func (m *Mullvad) Rotate(ctx context.Context, c discover.Credential, v *vault.Vault) (*vault.Handle, error) {
	s, err := parseMullvadSecret(v, c.Secret)
	if err != nil {
		return nil, err
	}
	token, err := m.accessToken(ctx, s)
	if err != nil {
		return nil, err
	}

	newPriv, newPub, err := genWGKey()
	if err != nil {
		return nil, fmt.Errorf("mullvad: generate key: %w", err)
	}
	newPrivB64 := base64.StdEncoding.EncodeToString(newPriv)
	zeroBytes(newPriv)

	body, _ := json.Marshal(map[string]string{"pubkey": newPub})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+"/accounts/v1/devices", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := m.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("mullvad: create device: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mullvad: create device: status %s", resp.Status)
	}
	var dev struct {
		ID     string `json:"id"`
		Pubkey string `json:"pubkey"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&dev); err != nil {
		return nil, fmt.Errorf("mullvad: decode device: %w", err)
	}
	if dev.ID == "" {
		return nil, fmt.Errorf("mullvad: create device: empty device id")
	}

	ns := s // carry base/account forward; swap device + key
	ns.device = dev.ID
	ns.privB64 = newPrivB64
	return v.Store([]byte(ns.build())), nil
}

// Verify proves the new device exists carrying the public key derived from the new
// private key.
func (m *Mullvad) Verify(ctx context.Context, newSecret *vault.Handle, v *vault.Vault) error {
	s, err := parseMullvadSecret(v, newSecret)
	if err != nil {
		return err
	}
	wantPub, err := pubFromPrivB64(s.privB64)
	if err != nil {
		return fmt.Errorf("mullvad verify: %w", err)
	}
	token, err := m.accessToken(ctx, s)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base+"/accounts/v1/devices/"+url.PathEscape(s.device), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := m.client().Do(req)
	if err != nil {
		return fmt.Errorf("mullvad verify: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mullvad verify: get device status %s", resp.Status)
	}
	var dev struct {
		Pubkey string `json:"pubkey"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&dev); err != nil {
		return fmt.Errorf("mullvad verify: decode device: %w", err)
	}
	if dev.Pubkey != wantPub {
		return fmt.Errorf("mullvad verify: device pubkey does not match the new key")
	}
	return nil
}

// RevokeOld deletes the OLD device. The new device is already registered+verified, so
// removing the old one closes its WireGuard key.
func (m *Mullvad) RevokeOld(ctx context.Context, c discover.Credential, v *vault.Vault) error {
	s, err := parseMullvadSecret(v, c.Secret)
	if err != nil {
		return err
	}
	if s.device == "" {
		return fmt.Errorf("mullvad revoke: old credential has no device id — remove it manually (guided)")
	}
	token, err := m.accessToken(ctx, s)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.base+"/accounts/v1/devices/"+url.PathEscape(s.device), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := m.client().Do(req)
	if err != nil {
		return fmt.Errorf("mullvad revoke: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mullvad revoke: delete device status %s", resp.Status)
	}
	return nil
}

// pubFromPrivB64 derives a base64 Curve25519 public key from a base64 private key,
// keeping the private bytes out of any retained string.
func pubFromPrivB64(privB64 string) (string, error) {
	priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privB64))
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}
	if len(priv) != 32 {
		zeroBytes(priv)
		return "", fmt.Errorf("private key is %d bytes, want 32", len(priv))
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	zeroBytes(priv)
	if err != nil {
		return "", fmt.Errorf("derive public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}
