package rotate

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// gcpEmu emulates the GCP token endpoint + IAM service-account keys API and ENFORCES
// key validity: it verifies the RS256 JWT signature against the public key recorded
// for the JWT's kid, so a token only mints while its key exists — and DELETE makes the
// key (and therefore its self-auth) stop working. This proves a real cutover and that
// the driver's JWT signing is genuine, not stubbed.
type gcpEmu struct {
	mu       sync.Mutex
	pubByKid map[string]*rsa.PublicKey
	tokens   map[string]bool // issued access tokens
	email    string
	project  string
	srv      *httptest.Server
}

func newGCPEmu(t *testing.T, project, email, seedKid string, seedPub *rsa.PublicKey) *gcpEmu {
	e := &gcpEmu{
		pubByKid: map[string]*rsa.PublicKey{seedKid: seedPub},
		tokens:   map[string]bool{},
		email:    email,
		project:  project,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", e.handleToken)
	mux.HandleFunc("/v1/", e.handleIAM)
	e.srv = httptest.NewTLSServer(mux)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *gcpEmu) handleToken(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	assertion := r.Form.Get("assertion")
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	hdrBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var hdr struct {
		Kid string `json:"kid"`
	}
	json.Unmarshal(hdrBytes, &hdr)

	e.mu.Lock()
	pub, ok := e.pubByKid[hdr.Kid]
	e.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig) != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	raw := make([]byte, 16)
	rand.Read(raw)
	tok := "ya29." + hex.EncodeToString(raw)
	e.mu.Lock()
	e.tokens[tok] = true
	e.mu.Unlock()
	json.NewEncoder(w).Encode(map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": 3600})
}

func (e *gcpEmu) bearerOK(r *http.Request) bool {
	tok := bearer(r) // reuses helper from npm_test.go
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.tokens[tok]
}

func (e *gcpEmu) handleIAM(w http.ResponseWriter, r *http.Request) {
	if !e.bearerOK(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// Find the "keys" segment, if any.
	keysIdx := -1
	for i, p := range parts {
		if p == "keys" {
			keysIdx = i
		}
	}
	switch {
	case r.Method == http.MethodPost && keysIdx == len(parts)-1:
		e.createKey(w)
	case r.Method == http.MethodDelete && keysIdx == len(parts)-2:
		kid := parts[len(parts)-1]
		e.mu.Lock()
		delete(e.pubByKid, kid)
		e.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
	case r.Method == http.MethodGet && keysIdx == -1:
		// GET the serviceAccount resource.
		json.NewEncoder(w).Encode(map[string]any{"email": e.email, "projectId": e.project})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (e *gcpEmu) createKey(w http.ResponseWriter) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	kidRaw := make([]byte, 12)
	rand.Read(kidRaw)
	kid := hex.EncodeToString(kidRaw)
	e.mu.Lock()
	e.pubByKid[kid] = &priv.PublicKey
	e.mu.Unlock()

	saJSON, _ := json.Marshal(map[string]string{
		"type":           "service_account",
		"project_id":     e.project,
		"private_key_id": kid,
		"private_key":    pkcs8PEM(priv),
		"client_email":   e.email,
		"token_uri":      e.srv.URL + "/token",
	})
	json.NewEncoder(w).Encode(map[string]any{
		"name":           "projects/" + e.project + "/serviceAccounts/" + e.email + "/keys/" + kid,
		"privateKeyData": base64.StdEncoding.EncodeToString(saJSON),
	})
}

func pkcs8PEM(k *rsa.PrivateKey) string {
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// seedBlob builds the initial gcp:// blob carrying the seed SA JSON.
func gcpSeedBlob(t *testing.T, emu *gcpEmu, kid string, priv *rsa.PrivateKey) string {
	t.Helper()
	saJSON, _ := json.Marshal(map[string]string{
		"type":           "service_account",
		"project_id":     emu.project,
		"private_key_id": kid,
		"private_key":    pkcs8PEM(priv),
		"client_email":   emu.email,
		"token_uri":      emu.srv.URL + "/token",
	})
	return (gcpSecret{raw: saJSON, endpoint: emu.srv.URL}).build()
}

func TestGCPDetect(t *testing.T) {
	g := &GCP{}
	if !g.Detect(discover.Credential{Source: "gcp"}) {
		t.Error("should detect Source=gcp")
	}
	if g.Detect(discover.Credential{Source: "aws"}) {
		t.Error("should not detect Source=aws")
	}
}

func TestGCPRotateRealCutover(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	ctx := context.Background()

	const project, email = "lab-proj", "labsa@lab-proj.iam.gserviceaccount.com"
	seedPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	seedKid := "seedkid000111222"
	emu := newGCPEmu(t, project, email, seedKid, &seedPriv.PublicKey)

	oldBlob := gcpSeedBlob(t, emu, seedKid, seedPriv)
	cred := discover.Credential{
		Source:   "gcp",
		Kind:     discover.KindToken,
		Identity: email + " @ gcp",
		Location: "imported/gcp/labsa",
		Secret:   v.Store([]byte(oldBlob)),
	}
	g := &GCP{HTTPClient: emu.srv.Client()}

	// 1. Rotate — create a new key (old still valid).
	newH, err := g.Rotate(ctx, cred, v)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	ns, err := parseGCPSecret(v, newH)
	if err != nil {
		t.Fatalf("parse new secret: %v", err)
	}
	if ns.sa.PrivateKeyID == seedKid {
		t.Fatal("new key id equals old — rotation minted nothing")
	}
	if ns.sa.PrivateKey == "" || strings.Contains(ns.sa.PrivateKey, pkcs8PEM(seedPriv)) {
		t.Fatal("new secret must carry a fresh private key")
	}

	// 2. Verify(new) authenticates against the IAM API.
	if err := g.Verify(ctx, newH, v); err != nil {
		t.Fatalf("Verify(new): %v", err)
	}
	// old key still authenticates before revoke.
	if err := g.Verify(ctx, cred.Secret, v); err != nil {
		t.Fatalf("old key must authenticate before revoke: %v", err)
	}

	// 3. RevokeOld — delete the old key.
	if err := g.RevokeOld(ctx, cred, v); err != nil {
		t.Fatalf("RevokeOld: %v", err)
	}

	// Cutover: old key can no longer mint a token, new key still works.
	if err := g.Verify(ctx, cred.Secret, v); err == nil {
		t.Fatal("old key must fail to authenticate after revoke")
	}
	if err := g.Verify(ctx, newH, v); err != nil {
		t.Fatalf("new key must still authenticate after revoke: %v", err)
	}

	// Leak check: the private key PEM must not appear in non-secret fields.
	for _, f := range []string{cred.Identity, cred.Source, cred.Location, string(cred.Kind)} {
		if strings.Contains(f, "PRIVATE KEY") || strings.Contains(f, ns.sa.PrivateKey) {
			t.Errorf("key material leaked into non-secret field %q", f)
		}
	}
}

func TestGCPRejectsBadSecret(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	g := &GCP{}
	// sa json missing private_key
	bad, _ := json.Marshal(map[string]string{"client_email": "x@y.iam"})
	blob := (gcpSecret{raw: bad}).build()
	cred := discover.Credential{Source: "gcp", Secret: v.Store([]byte(blob))}
	if _, err := g.Rotate(context.Background(), cred, v); err == nil {
		t.Error("Rotate should reject a sa json with no private_key")
	}
}
