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

// GitLab rotates a GitLab personal access token (PAT) via GitLab's first-party
// self-rotate endpoint:
//
//	POST /api/v4/personal_access_tokens/self/rotate
//
// GitLab issues a NEW token and, in the same call, REVOKES the token that
// authenticated the request. Because the rotate IS the revocation, this is an
// in-place rotation (like the DB drivers): RevokeOld is a no-op and the §3 sealed
// backup is the recovery path. Verify-before-revoke is still honoured by the spine
// — the new token is verified and stored before the (no-op) revoke step — and the
// old token is already dead the instant Rotate returns.
//
// The credential's secret is a single self-contained line (so it round-trips the
// single-line gopass sink unchanged):
//
//	gitlab://<host>[:port]/?tok=<token>
//
//   - scheme    "gitlab" maps to https; "http"/"https" are accepted so a test can
//               point at a loopback emulator.
//   - <host>    the GitLab API host (gitlab.com or a self-managed host).
//   - tok=      the PAT being rotated. No username is needed — GitLab authenticates
//               the PAT itself via the PRIVATE-TOKEN header, and self/rotate targets
//               whichever token signed the request.
//
// SECURITY: the token lives only in the vault blob and the PRIVATE-TOKEN header; it
// never reaches Identity/Meta/logs/argv. Response bodies carrying the new token are
// decoded straight into the rebuilt blob, not stringified elsewhere.
type GitLab struct {
	// HTTPClient is injectable for tests / custom TLS. Defaults to a 15s-timeout
	// client using http.DefaultTransport.
	HTTPClient *http.Client
}

// init self-registers the driver. Availability alone changes nothing; the
// `rotate --execute` + INCREDIGO_ALLOW_EXECUTE=1 gate still applies.
func init() { Register(&GitLab{}) }

// Name identifies the driver in plans and audit records.
func (g *GitLab) Name() string { return "gitlab" }

// Detect claims credentials tagged Source == "gitlab".
func (g *GitLab) Detect(c discover.Credential) bool { return c.Source == "gitlab" }

func (g *GitLab) client() *http.Client {
	if g.HTTPClient != nil {
		return g.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// gitlabSecret is the parsed credential blob. None of its fields are ever logged.
type gitlabSecret struct {
	base  string // scheme://host[:port]
	token string
}

func parseGitLabSecret(v *vault.Vault, h *vault.Handle) (gitlabSecret, error) {
	buf, err := v.Open(h)
	if err != nil {
		return gitlabSecret{}, err
	}
	u, err := url.Parse(strings.TrimSpace(string(buf.Bytes())))
	if err != nil {
		return gitlabSecret{}, fmt.Errorf("gitlab: parse secret url: %w", err)
	}
	if u.Scheme != "gitlab" && u.Scheme != "http" && u.Scheme != "https" {
		return gitlabSecret{}, fmt.Errorf("gitlab: unexpected scheme %q", u.Scheme)
	}
	scheme := u.Scheme
	if scheme == "gitlab" {
		scheme = "https"
	}
	tok := u.Query().Get("tok")
	if tok == "" {
		// tolerate a userinfo form (gitlab://_:<token>@host/) too.
		if u.User != nil {
			tok, _ = u.User.Password()
		}
	}
	if tok == "" {
		return gitlabSecret{}, fmt.Errorf("gitlab: secret has no token")
	}
	if u.Host == "" {
		return gitlabSecret{}, fmt.Errorf("gitlab: secret has no host")
	}
	return gitlabSecret{base: scheme + "://" + u.Host, token: tok}, nil
}

// build re-encodes a gitlabSecret into the single-line blob form (scheme normalised
// back to "gitlab" so the in-vault form stays stable).
func (s gitlabSecret) build() string {
	u := &url.URL{Scheme: "gitlab", Host: hostOf(s.base), Path: "/"}
	q := url.Values{}
	q.Set("tok", s.token)
	u.RawQuery = q.Encode()
	return u.String()
}

// Rotate calls self/rotate with the old token and returns a vault handle to a
// rebuilt blob carrying the new token. GitLab revokes the old token as part of this
// call, so nothing further is needed to retire it.
func (g *GitLab) Rotate(ctx context.Context, c discover.Credential, v *vault.Vault) (*vault.Handle, error) {
	s, err := parseGitLabSecret(v, c.Secret)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.base+"/api/v4/personal_access_tokens/self/rotate", bytes.NewReader([]byte("{}")))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("PRIVATE-TOKEN", s.token)

	resp, err := g.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("gitlab: rotate token: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("gitlab: rotate token: unexpected status %s", resp.Status)
	}
	var rotated struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rotated); err != nil {
		return nil, fmt.Errorf("gitlab: decode rotated token: %w", err)
	}
	if rotated.Token == "" {
		return nil, fmt.Errorf("gitlab: rotate token: empty token in response")
	}

	ns := s
	ns.token = rotated.Token
	return v.Store([]byte(ns.build())), nil
}

// Verify proves the new token authenticates by calling GET /api/v4/user with it.
func (g *GitLab) Verify(ctx context.Context, newSecret *vault.Handle, v *vault.Vault) error {
	s, err := parseGitLabSecret(v, newSecret)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base+"/api/v4/user", nil)
	if err != nil {
		return err
	}
	req.Header.Set("PRIVATE-TOKEN", s.token)
	resp, err := g.client().Do(req)
	if err != nil {
		return fmt.Errorf("gitlab verify: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gitlab verify: GET /user status %s", resp.Status)
	}
	var who struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&who); err != nil {
		return fmt.Errorf("gitlab verify: decode user: %w", err)
	}
	if who.Username == "" {
		return fmt.Errorf("gitlab verify: token did not resolve to a user")
	}
	return nil
}

// RevokeOld is a no-op: self/rotate already revoked the previous token. Defined to
// satisfy the safety-spine ordering.
func (g *GitLab) RevokeOld(ctx context.Context, c discover.Credential, v *vault.Vault) error {
	return nil
}
