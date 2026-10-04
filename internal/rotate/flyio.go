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

// Flyio rotates a Fly.io app-scoped DEPLOY TOKEN via the GraphQL API by CREATING a new
// limited-access token, verifying it, then DELETING the old one — the provider-API
// rotation pattern (create-new → verify → revoke-old).
//
// A deploy token is itself too limited to mint or delete tokens, so rotation is driven
// by a separate MANAGING token (a personal/org access token). The credential blob
// therefore carries both — the managing token (auth=, NOT rotated) and the deploy token
// being rotated (token=, with its id= for deletion) — the same "auth rotates a value"
// shape as the GitHub-Actions secret driver:
//
//	flyio://<host>/?org=<orgId>&app=<appId>&auth=<managing-token>&id=<tok-id>&token=<deploy-token>
//
//   - scheme   "flyio" maps to https; "http"/"https" are accepted for a loopback emulator.
//   - <host>   API host; "flyio" (or empty) defaults to api.fly.io.
//   - org=/app= the organization and app the deploy token is scoped to (createLimited...).
//   - auth=    the managing token (Bearer for create/delete) — non-secret to the rotation
//              of the deploy token in that it is preserved, but still kept vault-only.
//   - id=      the deploy token's limited-access-token id — required to DELETE the old one.
//   - token=   the deploy token value being rotated.
//
// SECURITY: both tokens live only in the vault blob and Bearer headers; neither reaches
// Identity/Meta/logs/argv. The new deploy token is decoded straight from the create
// response into the rebuilt blob.
type Flyio struct {
	// HTTPClient is injectable for tests / custom TLS. Defaults to a 15s-timeout client.
	HTTPClient *http.Client
}

// init self-registers the driver. Availability alone changes nothing; the
// `rotate --execute` + INCREDIGO_ALLOW_EXECUTE=1 gate still applies.
func init() { Register(&Flyio{}) }

// Name identifies the driver in plans and audit records.
func (f *Flyio) Name() string { return "flyio" }

// Detect claims credentials tagged Source == "flyio".
func (f *Flyio) Detect(c discover.Credential) bool { return c.Source == "flyio" }

func (f *Flyio) client() *http.Client {
	if f.HTTPClient != nil {
		return f.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// flyioSecret is the parsed credential blob. None of its fields are ever logged.
type flyioSecret struct {
	base  string // scheme://host
	org   string
	app   string
	auth  string // managing token
	id    string // deploy token id (for delete)
	token string // deploy token value (rotated)
}

func parseFlyioSecret(v *vault.Vault, h *vault.Handle) (flyioSecret, error) {
	buf, err := v.Open(h)
	if err != nil {
		return flyioSecret{}, err
	}
	u, err := url.Parse(strings.TrimSpace(string(buf.Bytes())))
	if err != nil {
		return flyioSecret{}, fmt.Errorf("flyio: parse secret url: %w", err)
	}
	if u.Scheme != "flyio" && u.Scheme != "http" && u.Scheme != "https" {
		return flyioSecret{}, fmt.Errorf("flyio: unexpected scheme %q", u.Scheme)
	}
	scheme := u.Scheme
	host := u.Host
	if scheme == "flyio" {
		scheme = "https"
	}
	if host == "" || host == "flyio" {
		host = "api.fly.io"
	}
	q := u.Query()
	s := flyioSecret{
		base:  scheme + "://" + host,
		org:   q.Get("org"),
		app:   q.Get("app"),
		auth:  q.Get("auth"),
		id:    q.Get("id"),
		token: q.Get("token"),
	}
	if s.auth == "" {
		return flyioSecret{}, fmt.Errorf("flyio: secret has no managing token (auth=)")
	}
	if s.token == "" {
		return flyioSecret{}, fmt.Errorf("flyio: secret has no deploy token")
	}
	return s, nil
}

// build re-encodes a flyioSecret into the single-line blob form (scheme normalised
// back to "flyio").
func (s flyioSecret) build() string {
	host := hostOf(s.base)
	if host == "api.fly.io" {
		host = "flyio"
	}
	u := &url.URL{Scheme: "flyio", Host: host, Path: "/"}
	q := url.Values{}
	if s.org != "" {
		q.Set("org", s.org)
	}
	if s.app != "" {
		q.Set("app", s.app)
	}
	q.Set("auth", s.auth)
	if s.id != "" {
		q.Set("id", s.id)
	}
	q.Set("token", s.token)
	u.RawQuery = q.Encode()
	return u.String()
}

// gql POSTs a GraphQL request authenticated by the given Bearer token and decodes the
// data envelope into out. A non-2xx status or a non-empty errors array is an error.
func (f *Flyio) gql(ctx context.Context, base, bearer, query string, vars map[string]any, out any) error {
	body, _ := json.Marshal(map[string]any{"query": query, "variables": vars})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/graphql", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := f.client().Do(req)
	if err != nil {
		return err
	}
	defer func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("graphql status %s", resp.Status)
	}
	var env struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return fmt.Errorf("decode graphql: %w", err)
	}
	if len(env.Errors) > 0 {
		return fmt.Errorf("graphql error: %s", env.Errors[0].Message)
	}
	if out != nil {
		if err := json.Unmarshal(env.Data, out); err != nil {
			return fmt.Errorf("decode graphql data: %w", err)
		}
	}
	return nil
}

const flyCreateMutation = `mutation($org:ID!,$app:ID!,$name:String!){createLimitedAccessToken(input:{name:$name,organizationId:$org,profile:"deploy",profileParams:{app_id:$app}}){limitedAccessToken{id,token}}}`

const flyDeleteMutation = `mutation($id:ID!){deleteLimitedAccessToken(input:{id:$id}){token}}`

const flyAppQuery = `query($n:String!){app(name:$n){id,name}}`

// Rotate creates a NEW deploy token (authenticated by the managing token) and returns
// a vault handle to a rebuilt blob carrying the new token + id. It does not delete the
// old deploy token.
func (f *Flyio) Rotate(ctx context.Context, c discover.Credential, v *vault.Vault) (*vault.Handle, error) {
	s, err := parseFlyioSecret(v, c.Secret)
	if err != nil {
		return nil, err
	}
	var out struct {
		Create struct {
			Tok struct {
				ID    string `json:"id"`
				Token string `json:"token"`
			} `json:"limitedAccessToken"`
		} `json:"createLimitedAccessToken"`
	}
	vars := map[string]any{"org": s.org, "app": s.app, "name": "incredigo-rotated"}
	if err := f.gql(ctx, s.base, s.auth, flyCreateMutation, vars, &out); err != nil {
		return nil, fmt.Errorf("flyio: create token: %w", err)
	}
	if out.Create.Tok.Token == "" {
		return nil, fmt.Errorf("flyio: create token: empty token in response")
	}
	ns := s
	ns.id = out.Create.Tok.ID
	ns.token = out.Create.Tok.Token
	return v.Store([]byte(ns.build())), nil
}

// Verify proves the newly minted deploy token authenticates by running the app query
// with it as the Bearer token.
func (f *Flyio) Verify(ctx context.Context, newSecret *vault.Handle, v *vault.Vault) error {
	s, err := parseFlyioSecret(v, newSecret)
	if err != nil {
		return err
	}
	var out struct {
		App struct {
			ID string `json:"id"`
		} `json:"app"`
	}
	if err := f.gql(ctx, s.base, s.token, flyAppQuery, map[string]any{"n": s.app}, &out); err != nil {
		return fmt.Errorf("flyio verify: %w", err)
	}
	if out.App.ID == "" {
		return fmt.Errorf("flyio verify: deploy token did not resolve the app")
	}
	return nil
}

// RevokeOld deletes the OLD deploy token by id, authenticated by the managing token.
func (f *Flyio) RevokeOld(ctx context.Context, c discover.Credential, v *vault.Vault) error {
	s, err := parseFlyioSecret(v, c.Secret)
	if err != nil {
		return err
	}
	if s.id == "" {
		return fmt.Errorf("flyio revoke: old token has no recorded id — delete it manually (guided)")
	}
	if err := f.gql(ctx, s.base, s.auth, flyDeleteMutation, map[string]any{"id": s.id}, nil); err != nil {
		return fmt.Errorf("flyio revoke: %w", err)
	}
	return nil
}
