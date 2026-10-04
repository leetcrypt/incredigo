package rotate

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// GCP rotates a Google Cloud service-account KEY via the IAM API by CREATING a new
// key, verifying it authenticates, then DELETING the old one — the provider-API
// rotation pattern (create-new → verify → revoke-old).
//
// The credential's secret is the service-account JSON key file. To round-trip through
// the single-line gopass sink, the compact JSON is base64-wrapped in a one-line blob:
//
//	gcp://<host>/?sa=<base64url(compact-sa-json)>[&endpoint=<iam-base-url>]
//
//   - sa=       the FULL service-account JSON (project_id, client_email,
//               private_key_id, private_key PEM, token_uri) base64url-encoded.
//   - endpoint= OPTIONAL override of the IAM API base (for a self-hosted emulator in
//               testing). Absent → real GCP (https://iam.googleapis.com).
//
// AUTH: every IAM call is made with an OAuth2 access token that the driver mints by
// signing an RS256 JWT with the service account's OWN private key and exchanging it at
// the token endpoint (the standard service-account self-auth — the SA needs
// iam.serviceAccountKeys.create/delete on itself). The new key's privateKeyData is
// returned by GCP only once in the CreateServiceAccountKey response; it is decoded
// straight into the vault and never logged. The private key never reaches argv.
type GCP struct {
	// HTTPClient is injectable for tests / custom TLS. Defaults to a 15s-timeout client.
	HTTPClient *http.Client
	// now is injectable so tests can pin the JWT iat/exp; defaults to time.Now.
	now func() time.Time
}

// init self-registers the driver. Availability alone changes nothing; the
// `rotate --execute` + INCREDIGO_ALLOW_EXECUTE=1 gate still applies.
func init() { Register(&GCP{}) }

// Name identifies the driver in plans and audit records.
func (g *GCP) Name() string { return "gcp" }

// Detect claims credentials tagged Source == "gcp".
func (g *GCP) Detect(c discover.Credential) bool { return c.Source == "gcp" }

func (g *GCP) client() *http.Client {
	if g.HTTPClient != nil {
		return g.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (g *GCP) clock() time.Time {
	if g.now != nil {
		return g.now()
	}
	return time.Now()
}

// gcpSA mirrors the fields of a service-account JSON key the driver needs. None of
// these are ever logged.
type gcpSA struct {
	ProjectID    string `json:"project_id"`
	ClientEmail  string `json:"client_email"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	TokenURI     string `json:"token_uri"`
}

// gcpSecret is the parsed credential blob.
type gcpSecret struct {
	raw      []byte // the compact SA JSON exactly as stored (round-trips via build)
	sa       gcpSA
	endpoint string // "" = real GCP IAM
}

func parseGCPSecret(v *vault.Vault, h *vault.Handle) (gcpSecret, error) {
	buf, err := v.Open(h)
	if err != nil {
		return gcpSecret{}, err
	}
	u, err := url.Parse(strings.TrimSpace(string(buf.Bytes())))
	if err != nil {
		return gcpSecret{}, fmt.Errorf("gcp: parse secret url: %w", err)
	}
	if u.Scheme != "gcp" {
		return gcpSecret{}, fmt.Errorf("gcp: unexpected scheme %q", u.Scheme)
	}
	q := u.Query()
	raw, err := base64.URLEncoding.DecodeString(q.Get("sa"))
	if err != nil {
		return gcpSecret{}, fmt.Errorf("gcp: decode sa json: %w", err)
	}
	var sa gcpSA
	if err := json.Unmarshal(raw, &sa); err != nil {
		return gcpSecret{}, fmt.Errorf("gcp: parse sa json: %w", err)
	}
	if sa.ClientEmail == "" || sa.PrivateKey == "" {
		return gcpSecret{}, fmt.Errorf("gcp: sa json missing client_email or private_key")
	}
	return gcpSecret{raw: raw, sa: sa, endpoint: q.Get("endpoint")}, nil
}

// build re-encodes a gcpSecret into the single-line blob form.
func (s gcpSecret) build() string {
	u := &url.URL{Scheme: "gcp", Host: "gcp", Path: "/"}
	q := url.Values{}
	q.Set("sa", base64.URLEncoding.EncodeToString(s.raw))
	if s.endpoint != "" {
		q.Set("endpoint", s.endpoint)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func (s gcpSecret) iamBase() string {
	if s.endpoint != "" {
		return strings.TrimRight(s.endpoint, "/")
	}
	return "https://iam.googleapis.com"
}

func (s gcpSecret) tokenURI() string {
	if s.sa.TokenURI != "" {
		return s.sa.TokenURI
	}
	return "https://oauth2.googleapis.com/token"
}

// keysURL builds the .../serviceAccounts/{email}/keys collection or member URL.
func (s gcpSecret) keysURL(keyID string) string {
	base := s.iamBase() + "/v1/projects/" + url.PathEscape(s.sa.ProjectID) +
		"/serviceAccounts/" + url.PathEscape(s.sa.ClientEmail) + "/keys"
	if keyID != "" {
		base += "/" + url.PathEscape(keyID)
	}
	return base
}

// b64url is RFC 7515 base64url without padding (JWT segment encoding).
func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// accessToken mints an OAuth2 access token by signing an RS256 JWT with the SA's
// private key and exchanging it at the token endpoint. The private key is parsed
// transiently and never logged.
func (g *GCP) accessToken(ctx context.Context, s gcpSecret) (string, error) {
	key, err := parseRSAPrivateKey(s.sa.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("gcp: parse private key: %w", err)
	}
	now := g.clock().UTC()
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": s.sa.PrivateKeyID}
	claims := map[string]any{
		"iss":   s.sa.ClientEmail,
		"sub":   s.sa.ClientEmail,
		"aud":   s.tokenURI(),
		"scope": "https://www.googleapis.com/auth/cloud-platform",
		"iat":   now.Unix(),
		"exp":   now.Add(10 * time.Minute).Unix(),
	}
	hj, _ := json.Marshal(header)
	cj, _ := json.Marshal(claims)
	signingInput := b64url(hj) + "." + b64url(cj)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("gcp: sign jwt: %w", err)
	}
	assertion := signingInput + "." + b64url(sig)

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", assertion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenURI(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := g.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("gcp: token exchange: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gcp: token exchange: status %s", resp.Status)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", fmt.Errorf("gcp: decode token: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("gcp: token exchange: empty access_token")
	}
	return tok.AccessToken, nil
}

// parseRSAPrivateKey parses a PEM private key (PKCS#8, as GCP emits, or PKCS#1).
func parseRSAPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA key")
		}
		return rk, nil
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// Rotate creates a NEW service-account key (authenticated by the OLD key) and returns
// a vault handle to the rebuilt blob carrying the new key JSON. It does not delete the
// old key.
func (g *GCP) Rotate(ctx context.Context, c discover.Credential, v *vault.Vault) (*vault.Handle, error) {
	s, err := parseGCPSecret(v, c.Secret)
	if err != nil {
		return nil, err
	}
	token, err := g.accessToken(ctx, s)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]string{
		"privateKeyType": "TYPE_GOOGLE_CREDENTIALS_FILE",
		"keyAlgorithm":   "KEY_ALG_RSA_2048",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.keysURL(""), strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("gcp: create key: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("gcp: create key: status %s", resp.Status)
	}
	var created struct {
		Name           string `json:"name"`
		PrivateKeyData string `json:"privateKeyData"` // base64 of the new SA JSON
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return nil, fmt.Errorf("gcp: decode created key: %w", err)
	}
	newRaw, err := base64.StdEncoding.DecodeString(created.PrivateKeyData)
	if err != nil {
		return nil, fmt.Errorf("gcp: decode new key data: %w", err)
	}
	var newSA gcpSA
	if err := json.Unmarshal(newRaw, &newSA); err != nil {
		return nil, fmt.Errorf("gcp: parse new key json: %w", err)
	}
	if newSA.PrivateKey == "" {
		return nil, fmt.Errorf("gcp: create key: new key carries no private_key")
	}
	ns := gcpSecret{raw: newRaw, sa: newSA, endpoint: s.endpoint}
	return v.Store([]byte(ns.build())), nil
}

// Verify proves the freshly minted key authenticates by minting an access token with
// it and GETting the service-account resource from the IAM API.
func (g *GCP) Verify(ctx context.Context, newSecret *vault.Handle, v *vault.Vault) error {
	s, err := parseGCPSecret(v, newSecret)
	if err != nil {
		return err
	}
	token, err := g.accessToken(ctx, s)
	if err != nil {
		return fmt.Errorf("gcp verify: %w", err)
	}
	saURL := s.iamBase() + "/v1/projects/" + url.PathEscape(s.sa.ProjectID) +
		"/serviceAccounts/" + url.PathEscape(s.sa.ClientEmail)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, saURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := g.client().Do(req)
	if err != nil {
		return fmt.Errorf("gcp verify: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gcp verify: get serviceAccount status %s", resp.Status)
	}
	return nil
}

// RevokeOld deletes the OLD key by its private_key_id. The old key is still valid at
// this point (revoke runs only after the new key is stored+verified), so it
// authenticates its own deletion.
func (g *GCP) RevokeOld(ctx context.Context, c discover.Credential, v *vault.Vault) error {
	s, err := parseGCPSecret(v, c.Secret)
	if err != nil {
		return err
	}
	if s.sa.PrivateKeyID == "" {
		return fmt.Errorf("gcp revoke: old key has no recorded private_key_id — delete it manually (guided)")
	}
	token, err := g.accessToken(ctx, s)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.keysURL(s.sa.PrivateKeyID), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := g.client().Do(req)
	if err != nil {
		return fmt.Errorf("gcp revoke: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("gcp revoke: delete key status %s", resp.Status)
	}
	return nil
}
