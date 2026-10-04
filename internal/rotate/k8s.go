package rotate

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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

// K8s rotates a Kubernetes ServiceAccount token (the legacy, individually-revocable
// kind backed by a Secret of type kubernetes.io/service-account-token) by CREATING a
// new token Secret, verifying the minted token authenticates, then DELETING the old
// Secret — the provider-API rotation pattern (create-new → verify → revoke-old).
//
// Bound TokenRequest tokens cannot be revoked individually, so rotation targets the
// Secret-backed token whose deletion immediately invalidates it. The credential blob:
//
//	k8s://<host:port>/?ns=<namespace>&sa=<serviceaccount>&secret=<secret-name>&token=<token>
//
//   - scheme   "k8s" maps to https; "http"/"https" are accepted for a loopback emulator.
//   - <host>   the apiserver host:port.
//   - ns=      the namespace holding the SA + token Secret.
//   - sa=      the ServiceAccount name (the new Secret is annotated to it).
//   - secret=  the token Secret's name — required to DELETE the old token.
//   - token=   the bearer token value (rotated).
//   - ca=      OPTIONAL base64(std) of the cluster CA PEM bundle. A real apiserver
//              serves a self-signed cert, so the driver pins this CA as the only
//              trusted root for the TLS handshake. Omit for a loopback emulator.
//   - insecure=1  OPTIONAL escape hatch: skip TLS verification entirely (lab only).
//
// AUTH: every call authenticates with a token Bearer header against the apiserver. The
// rotating SA needs RBAC to create/delete Secrets in its namespace. The new token is
// read (base64) from the controller-populated Secret straight into the vault; it never
// reaches Identity/Meta/logs/argv.
type K8s struct {
	// HTTPClient is injectable for tests / custom CA. A real apiserver needs a client
	// configured with the cluster CA; defaults to a 15s-timeout client otherwise.
	HTTPClient *http.Client
}

// init self-registers the driver. Availability alone changes nothing; the
// `rotate --execute` + INCREDIGO_ALLOW_EXECUTE=1 gate still applies.
func init() { Register(&K8s{}) }

// Name identifies the driver in plans and audit records.
func (k *K8s) Name() string { return "k8s" }

// Detect claims credentials tagged Source == "k8s".
func (k *K8s) Detect(c discover.Credential) bool { return c.Source == "k8s" }

// clientFor returns the HTTP client for a given credential. An injected client
// (tests / explicit CA config) always wins. Otherwise it builds a 15s client whose
// TLS trust is pinned to the credential's ca= bundle (a real apiserver's self-signed
// cert), or with verification disabled when insecure=1 is set (lab only).
func (k *K8s) clientFor(cr k8sCred) (*http.Client, error) {
	if k.HTTPClient != nil {
		return k.HTTPClient, nil
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case cr.insecure:
		tlsCfg.InsecureSkipVerify = true
	case cr.ca != "":
		pem, err := base64.StdEncoding.DecodeString(cr.ca)
		if err != nil {
			return nil, fmt.Errorf("k8s: decode ca bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("k8s: ca bundle contained no usable certificates")
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

// k8sCred is the parsed credential blob. None of its fields are ever logged.
type k8sCred struct {
	base     string // scheme://host:port
	ns       string
	sa       string
	secret   string // token Secret name
	token    string
	ca       string // base64(std) cluster CA PEM bundle (optional)
	insecure bool   // skip TLS verification (lab only)
}

func parseK8sCred(v *vault.Vault, h *vault.Handle) (k8sCred, error) {
	buf, err := v.Open(h)
	if err != nil {
		return k8sCred{}, err
	}
	u, err := url.Parse(strings.TrimSpace(string(buf.Bytes())))
	if err != nil {
		return k8sCred{}, fmt.Errorf("k8s: parse secret url: %w", err)
	}
	if u.Scheme != "k8s" && u.Scheme != "http" && u.Scheme != "https" {
		return k8sCred{}, fmt.Errorf("k8s: unexpected scheme %q", u.Scheme)
	}
	scheme := u.Scheme
	if scheme == "k8s" {
		scheme = "https"
	}
	if u.Host == "" {
		return k8sCred{}, fmt.Errorf("k8s: secret has no apiserver host")
	}
	q := u.Query()
	c := k8sCred{base: scheme + "://" + u.Host, ns: q.Get("ns"), sa: q.Get("sa"), secret: q.Get("secret"), token: q.Get("token"), ca: q.Get("ca"), insecure: q.Get("insecure") == "1"}
	if c.ns == "" || c.sa == "" {
		return k8sCred{}, fmt.Errorf("k8s: secret missing namespace or serviceaccount")
	}
	if c.token == "" {
		return k8sCred{}, fmt.Errorf("k8s: secret has no token")
	}
	return c, nil
}

// build re-encodes a k8sCred into the single-line blob form (scheme normalised back
// to "k8s").
func (c k8sCred) build() string {
	u := &url.URL{Scheme: "k8s", Host: hostPortOf(c.base), Path: "/"}
	q := url.Values{}
	q.Set("ns", c.ns)
	q.Set("sa", c.sa)
	if c.secret != "" {
		q.Set("secret", c.secret)
	}
	q.Set("token", c.token)
	if c.ca != "" {
		q.Set("ca", c.ca)
	}
	if c.insecure {
		q.Set("insecure", "1")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// hostPortOf strips the scheme from a scheme://host:port base.
func hostPortOf(base string) string {
	if i := strings.Index(base, "://"); i >= 0 {
		return base[i+3:]
	}
	return base
}

// k8sSecretObj is the subset of a core/v1 Secret the driver reads or writes.
type k8sSecretObj struct {
	Metadata struct {
		Name        string            `json:"name"`
		Annotations map[string]string `json:"annotations,omitempty"`
	} `json:"metadata"`
	Type string            `json:"type,omitempty"`
	Data map[string]string `json:"data,omitempty"`
}

// do issues an authenticated apiserver request and returns the body. The credential
// carries the TLS trust config (ca=/insecure=) used to build the client.
func (k *K8s) do(ctx context.Context, cr k8sCred, method, urlStr string, body []byte) ([]byte, int, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, urlStr, r)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+cr.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	cl, err := k.clientFor(cr)
	if err != nil {
		return nil, 0, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return rb, resp.StatusCode, nil
}

func (c k8sCred) secretsURL(name string) string {
	base := c.base + "/api/v1/namespaces/" + url.PathEscape(c.ns) + "/secrets"
	if name != "" {
		return base + "/" + url.PathEscape(name)
	}
	return base
}

// Rotate creates a NEW token Secret for the SA (authenticated by the OLD token), waits
// for the controller to populate its token, and returns a vault handle to the rebuilt
// blob carrying the new Secret name + token. It does not delete the old Secret.
func (k *K8s) Rotate(ctx context.Context, c discover.Credential, v *vault.Vault) (*vault.Handle, error) {
	cr, err := parseK8sCred(v, c.Secret)
	if err != nil {
		return nil, err
	}
	suffix, err := genHex(4)
	if err != nil {
		return nil, err
	}
	newName := cr.sa + "-token-" + suffix
	obj := k8sSecretObj{Type: "kubernetes.io/service-account-token"}
	obj.Metadata.Name = newName
	obj.Metadata.Annotations = map[string]string{"kubernetes.io/service-account.name": cr.sa}
	body, _ := json.Marshal(obj)

	_, code, err := k.do(ctx, cr, http.MethodPost, cr.secretsURL(""), body)
	if err != nil {
		return nil, fmt.Errorf("k8s: create token secret: %w", err)
	}
	if code != http.StatusCreated && code != http.StatusOK {
		return nil, fmt.Errorf("k8s: create token secret: status %d", code)
	}

	// Wait for the token-controller to populate .data.token.
	token, err := k.awaitToken(ctx, cr, newName)
	if err != nil {
		return nil, err
	}
	nc := cr
	nc.secret = newName
	nc.token = token
	return v.Store([]byte(nc.build())), nil
}

// awaitToken polls the new Secret until its .data.token is present, decoding it.
func (k *K8s) awaitToken(ctx context.Context, cr k8sCred, name string) (string, error) {
	for attempt := 0; attempt < 10; attempt++ {
		rb, code, err := k.do(ctx, cr, http.MethodGet, cr.secretsURL(name), nil)
		if err != nil {
			return "", fmt.Errorf("k8s: read token secret: %w", err)
		}
		if code == http.StatusOK {
			var got k8sSecretObj
			if err := json.Unmarshal(rb, &got); err != nil {
				return "", fmt.Errorf("k8s: decode token secret: %w", err)
			}
			if enc := got.Data["token"]; enc != "" {
				tok, err := base64.StdEncoding.DecodeString(enc)
				if err != nil {
					return "", fmt.Errorf("k8s: decode token data: %w", err)
				}
				return string(tok), nil
			}
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return "", fmt.Errorf("k8s: token secret never populated a token")
}

// Verify proves the new token authenticates by GETting the ServiceAccount with it.
func (k *K8s) Verify(ctx context.Context, newSecret *vault.Handle, v *vault.Vault) error {
	cr, err := parseK8sCred(v, newSecret)
	if err != nil {
		return err
	}
	saURL := cr.base + "/api/v1/namespaces/" + url.PathEscape(cr.ns) + "/serviceaccounts/" + url.PathEscape(cr.sa)
	_, code, err := k.do(ctx, cr, http.MethodGet, saURL, nil)
	if err != nil {
		return fmt.Errorf("k8s verify: %w", err)
	}
	if code != http.StatusOK {
		return fmt.Errorf("k8s verify: get serviceaccount status %d", code)
	}
	return nil
}

// RevokeOld deletes the OLD token Secret, which invalidates the old token. The old
// token is still valid at this point (revoke runs only after the new token is
// stored+verified), so it authenticates its own Secret's deletion.
func (k *K8s) RevokeOld(ctx context.Context, c discover.Credential, v *vault.Vault) error {
	cr, err := parseK8sCred(v, c.Secret)
	if err != nil {
		return err
	}
	if cr.secret == "" {
		return fmt.Errorf("k8s revoke: old token has no recorded secret name — delete it manually (guided)")
	}
	_, code, err := k.do(ctx, cr, http.MethodDelete, cr.secretsURL(cr.secret), nil)
	if err != nil {
		return fmt.Errorf("k8s revoke: %w", err)
	}
	if code != http.StatusOK && code != http.StatusNoContent {
		return fmt.Errorf("k8s revoke: delete token secret status %d", code)
	}
	return nil
}
