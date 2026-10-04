package rotate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// Gitea rotates a Gitea personal access token (PAT) via the Gitea API by
// CREATING a new token, verifying it, then DELETING the old one — the canonical
// provider-API rotation pattern (create-new → verify → revoke-old), and the first
// driver whose RevokeOld is a real destructive API call.
//
// The credential's secret is a single self-contained line (so it round-trips
// through the existing single-line gopass sink unchanged):
//
//	https://<user>:<token>@<host>[:port]/?name=<token-name>[&pw=<mgmt-password>]
//
//   - <token>     the PAT being rotated (the userinfo password).
//   - <user>      the Gitea username (userinfo user).
//   - scheme+host the API base (http for the loopback sandbox; https in prod).
//   - name=       the token's Gitea NAME — required to DELETE it (the API deletes
//                 by name/id, and the token VALUE can't be mapped back to a name).
//                 incredigo writes the new name on every rotation, so the chain is
//                 self-sustaining; a bare discovered token with no name degrades to
//                 the guided worklist for the old-token deletion.
//   - pw=         OPTIONAL Gitea account password. Gitea historically requires
//                 BASIC auth (password) to create/delete tokens; if present it is
//                 used for those management calls. If absent, the driver tries
//                 token auth (works on Gitea versions that allow a scoped token to
//                 manage tokens). Verify always uses the token itself.
//
// SECURITY: the token (and optional mgmt password) live only in the vault and the
// query string of the in-vault secret; they never reach Identity/Meta/logs. HTTP
// bodies carrying the new token are drained into the vault, not stringified beyond
// the unavoidable JSON decode.
type Gitea struct {
	// HTTPClient is injectable for tests / custom TLS. Defaults to a 15s-timeout
	// client using http.DefaultTransport.
	HTTPClient *http.Client
}

// init self-registers the driver. Availability alone changes nothing; the
// `rotate --execute` + INCREDIGO_ALLOW_EXECUTE=1 gate still applies.
func init() { Register(&Gitea{}) }

// Name identifies the driver in plans and audit records.
func (g *Gitea) Name() string { return "gitea" }

// Detect claims credentials tagged Source == "gitea".
func (g *Gitea) Detect(c discover.Credential) bool { return c.Source == "gitea" }

func (g *Gitea) client() *http.Client {
	if g.HTTPClient != nil {
		return g.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// giteaSecret is the parsed credential blob. None of its fields are ever logged.
type giteaSecret struct {
	base  string   // scheme://host[:port]
	user  string   // Gitea username
	token string   // the PAT being rotated
	name  string   // token name (for DELETE)
	pw    string   // optional mgmt password (basic auth)
	refs  []string // optional on-disk files that embed the token literally (multi-reference cutover)
}

// minGiteaTokenLen guards the literal on-disk reference rewrite: the old token is the
// search key we ReplaceAll across .git-credentials / git remotes / tea config, so a
// too-short token could sweep through unrelated file contents. Real Gitea PATs are
// 40 hex chars; refuse to rewrite references keyed on anything implausibly short.
const minGiteaTokenLen = 20

// parseGiteaSecret reads the single-line blob from the vault and decomposes it.
func parseGiteaSecret(v *vault.Vault, h *vault.Handle) (giteaSecret, error) {
	buf, err := v.Open(h)
	if err != nil {
		return giteaSecret{}, err
	}
	u, err := url.Parse(strings.TrimSpace(string(buf.Bytes())))
	if err != nil {
		return giteaSecret{}, fmt.Errorf("gitea: parse secret url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return giteaSecret{}, fmt.Errorf("gitea: unexpected scheme %q", u.Scheme)
	}
	if u.User == nil {
		return giteaSecret{}, fmt.Errorf("gitea: secret has no user:token")
	}
	tok, _ := u.User.Password()
	if tok == "" {
		return giteaSecret{}, fmt.Errorf("gitea: secret has no token")
	}
	q := u.Query()
	return giteaSecret{
		base:  u.Scheme + "://" + u.Host,
		user:  u.User.Username(),
		token: tok,
		name:  q.Get("name"),
		pw:    q.Get("pw"),
		refs:  q["ref"],
	}, nil
}

// build re-encodes a giteaSecret into the single-line blob form.
func (s giteaSecret) build() string {
	u := &url.URL{
		Scheme: schemeOf(s.base),
		Host:   hostOf(s.base),
		User:   url.UserPassword(s.user, s.token),
		Path:   "/",
	}
	q := url.Values{}
	q.Set("name", s.name)
	if s.pw != "" {
		q.Set("pw", s.pw)
	}
	for _, r := range s.refs {
		q.Add("ref", r)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func schemeOf(base string) string {
	if i := strings.Index(base, "://"); i >= 0 {
		return base[:i]
	}
	return "https"
}

func hostOf(base string) string {
	if i := strings.Index(base, "://"); i >= 0 {
		return base[i+3:]
	}
	return base
}

// Rotate creates a NEW token at the Gitea API (authenticating with the old token
// or, if a mgmt password is present, basic auth), and returns a vault handle to a
// rebuilt blob carrying the new token + new name. It does not revoke the old token.
func (g *Gitea) Rotate(ctx context.Context, c discover.Credential, v *vault.Vault) (*vault.Handle, error) {
	s, err := parseGiteaSecret(v, c.Secret)
	if err != nil {
		return nil, err
	}
	newName := fmt.Sprintf("incredigo-rotated-%d", time.Now().Unix())
	body, _ := json.Marshal(map[string]any{
		"name":   newName,
		"scopes": []string{"write:user", "read:user"}, // enough to manage tokens on Gitea ≥1.19; ignored by older
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.base+"/api/v1/users/"+url.PathEscape(s.user)+"/tokens", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	g.authManage(req, s)

	resp, err := g.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("gitea: create token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gitea: create token: unexpected status %s", resp.Status)
	}
	var created struct {
		Name string `json:"name"`
		SHA1 string `json:"sha1"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return nil, fmt.Errorf("gitea: decode created token: %w", err)
	}
	if created.SHA1 == "" {
		return nil, fmt.Errorf("gitea: create token: empty token in response")
	}

	ns := s // carry base/user/pw/refs forward
	ns.token = created.SHA1
	ns.name = created.Name
	if ns.name == "" {
		ns.name = newName
	}

	// Multi-reference cutover: rewrite the old token → new token, in place, in every
	// on-disk file that embeds it (git-credentials, embedded git-remote URLs, tea
	// config). This is what lets a real IN-USE token rotate without breaking git auth.
	//
	// SAFETY ORDERING: we do this ONLY after proving the new token authenticates, so a
	// dead token is never written into a git config; both the old and new tokens stay
	// valid until RevokeOld (run last by the spine), so any later failure leaves every
	// reference pointing at a working token. The replacement is keyed on the old token
	// literal (a 40-hex string), atomic per file (temp+rename), and length-guarded.
	if len(ns.refs) > 0 {
		if len(s.token) < minGiteaTokenLen {
			return nil, fmt.Errorf("gitea: token too short to rewrite references safely (<%d chars)", minGiteaTokenLen)
		}
		if err := g.tokenAuthenticates(ctx, ns.base, ns.user, ns.token); err != nil {
			return nil, fmt.Errorf("gitea: new token failed pre-rewrite auth check: %w", err)
		}
		for _, ref := range ns.refs {
			if _, err := replaceInFile(ref, s.token, ns.token); err != nil {
				return nil, fmt.Errorf("gitea: rewrite ref %s: %w", ref, redactErr(err, s.token, ns.token))
			}
		}
	}
	return v.Store([]byte(ns.build())), nil
}

// tokenAuthenticates proves a token is live by calling GET /api/v1/user with it and
// (when a username is known) checking the returned login matches. Shared by Rotate's
// pre-rewrite gate and Verify.
func (g *Gitea) tokenAuthenticates(ctx context.Context, base, user, token string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/user", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "token "+token)
	resp, err := g.client().Do(req)
	if err != nil {
		return fmt.Errorf("gitea verify: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gitea verify: GET /user status %s", resp.Status)
	}
	var who struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&who); err != nil {
		return fmt.Errorf("gitea verify: decode user: %w", err)
	}
	if user != "" && who.Login != "" && !strings.EqualFold(who.Login, user) {
		return fmt.Errorf("gitea verify: token authenticates as %q, expected %q", who.Login, user)
	}
	return nil
}

// Verify proves the newly minted token authenticates (GET /api/v1/user, login match)
// AND that the multi-reference cutover landed: the new token is present in every
// on-disk reference file. Reading a ref that is missing the new token means the
// rewrite did not take, so Verify fails and the spine short-circuits before RevokeOld
// (old token stays live — no breakage).
func (g *Gitea) Verify(ctx context.Context, newSecret *vault.Handle, v *vault.Vault) error {
	s, err := parseGiteaSecret(v, newSecret)
	if err != nil {
		return err
	}
	if err := g.tokenAuthenticates(ctx, s.base, s.user, s.token); err != nil {
		return err
	}
	for _, ref := range s.refs {
		b, err := os.ReadFile(ref)
		if err != nil {
			return fmt.Errorf("gitea verify: read ref %s: %w", ref, err)
		}
		if !strings.Contains(string(b), s.token) {
			return fmt.Errorf("gitea verify: new token missing from ref %s", ref)
		}
	}
	return nil
}

// RevokeOld deletes the OLD token by name. The old token is still valid at this
// point (revoke runs only after the new token is stored+verified), so it is used
// to authenticate its own deletion unless a mgmt password is configured.
func (g *Gitea) RevokeOld(ctx context.Context, c discover.Credential, v *vault.Vault) error {
	s, err := parseGiteaSecret(v, c.Secret)
	if err != nil {
		return err
	}
	if s.name == "" {
		return fmt.Errorf("gitea revoke: old token has no recorded name — delete it manually (guided)")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		s.base+"/api/v1/users/"+url.PathEscape(s.user)+"/tokens/"+url.PathEscape(s.name), nil)
	if err != nil {
		return err
	}
	g.authManage(req, s)
	resp, err := g.client().Do(req)
	if err != nil {
		return fmt.Errorf("gitea revoke: %w", err)
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gitea revoke: delete token status %s", resp.Status)
	}
	return nil
}

// authManage sets auth for token-management calls (create/delete): basic auth with
// the mgmt password if present (Gitea's historical requirement), else token auth.
func (g *Gitea) authManage(req *http.Request, s giteaSecret) {
	if s.pw != "" {
		req.SetBasicAuth(s.user, s.pw)
		return
	}
	req.Header.Set("Authorization", "token "+s.token)
}
