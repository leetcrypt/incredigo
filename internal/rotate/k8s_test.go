package rotate

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// k8sEmu emulates the relevant slice of the kube-apiserver and ENFORCES token
// validity: a token authenticates only while its backing Secret exists. Creating a
// token Secret immediately populates a fresh token (acting as the token-controller);
// deleting a token Secret invalidates its token — so a test can prove a real cutover.
type k8sEmu struct {
	mu      sync.Mutex
	ns      string
	sa      string
	secrets map[string]string // secret name -> token value
	valid   map[string]bool   // token value -> alive
	srv     *httptest.Server
}

func newK8sEmu(t *testing.T, ns, sa, seedSecret, seedToken string) *k8sEmu {
	e := &k8sEmu{
		ns:      ns,
		sa:      sa,
		secrets: map[string]string{seedSecret: seedToken},
		valid:   map[string]bool{seedToken: true},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/namespaces/"+ns+"/secrets", e.handleSecrets)
	mux.HandleFunc("/api/v1/namespaces/"+ns+"/secrets/", e.handleSecret)
	mux.HandleFunc("/api/v1/namespaces/"+ns+"/serviceaccounts/", e.handleSA)
	e.srv = httptest.NewTLSServer(mux)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *k8sEmu) tokenOK(r *http.Request) bool {
	tok := bearer(r)
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.valid[tok]
}

// handleSecrets serves POST .../secrets (create token Secret + populate token).
func (e *k8sEmu) handleSecrets(w http.ResponseWriter, r *http.Request) {
	if !e.tokenOK(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var obj map[string]any
	json.NewDecoder(r.Body).Decode(&obj)
	meta, _ := obj["metadata"].(map[string]any)
	name, _ := meta["name"].(string)
	raw := make([]byte, 24)
	rand.Read(raw)
	tok := "eyJ" + hex.EncodeToString(raw) // pseudo-JWT-looking token
	e.mu.Lock()
	e.secrets[name] = tok
	e.valid[tok] = true
	e.mu.Unlock()
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"name": name}})
}

// handleSecret serves GET/DELETE .../secrets/<name>.
func (e *k8sEmu) handleSecret(w http.ResponseWriter, r *http.Request) {
	if !e.tokenOK(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	name := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	switch r.Method {
	case http.MethodGet:
		e.mu.Lock()
		tok, ok := e.secrets[name]
		e.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"metadata": map[string]any{"name": name},
			"data":     map[string]string{"token": base64.StdEncoding.EncodeToString([]byte(tok))},
		})
	case http.MethodDelete:
		e.mu.Lock()
		if tok, ok := e.secrets[name]; ok {
			delete(e.valid, tok)
			delete(e.secrets, name)
		}
		e.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (e *k8sEmu) handleSA(w http.ResponseWriter, r *http.Request) {
	if !e.tokenOK(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"name": e.sa, "namespace": e.ns}})
}

func (e *k8sEmu) tokenValid(tok string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.valid[tok]
}

func TestK8sDetect(t *testing.T) {
	k := &K8s{}
	if !k.Detect(discover.Credential{Source: "k8s"}) {
		t.Error("should detect Source=k8s")
	}
	if k.Detect(discover.Credential{Source: "gcp"}) {
		t.Error("should not detect Source=gcp")
	}
}

func TestK8sRotateRealCutover(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	ctx := context.Background()

	const ns, sa, seedSecret, oldTok = "labns", "labsa", "labsa-token-seed", "eyJold0123456789"
	emu := newK8sEmu(t, ns, sa, seedSecret, oldTok)

	host := strings.TrimPrefix(emu.srv.URL, "https://")
	oldBlob := "k8s://" + host + "/?ns=" + ns + "&sa=" + sa + "&secret=" + seedSecret + "&token=" + oldTok
	cred := discover.Credential{
		Source:   "k8s",
		Kind:     discover.KindToken,
		Identity: sa + " @ k8s",
		Location: "imported/k8s/labsa",
		Secret:   v.Store([]byte(oldBlob)),
	}
	k := &K8s{HTTPClient: emu.srv.Client()}

	if !emu.tokenValid(oldTok) {
		t.Fatal("seed token should be valid at start")
	}

	// 1. Rotate.
	newH, err := k.Rotate(ctx, cred, v)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	nc, err := parseK8sCred(v, newH)
	if err != nil {
		t.Fatalf("parse new secret: %v", err)
	}
	if nc.token == oldTok {
		t.Fatal("new token equals old — rotation minted nothing")
	}
	if nc.secret == "" || nc.secret == seedSecret {
		t.Fatalf("new secret must carry a fresh token-secret name, got %q", nc.secret)
	}
	if !emu.tokenValid(oldTok) {
		t.Fatal("old token must remain valid before revoke")
	}
	if !emu.tokenValid(nc.token) {
		t.Fatal("new token must be valid after create")
	}

	// 2. Verify(new).
	if err := k.Verify(ctx, newH, v); err != nil {
		t.Fatalf("Verify(new): %v", err)
	}

	// 3. RevokeOld.
	if err := k.RevokeOld(ctx, cred, v); err != nil {
		t.Fatalf("RevokeOld: %v", err)
	}
	if emu.tokenValid(oldTok) {
		t.Fatal("old token must be invalid after revoke")
	}
	if err := k.Verify(ctx, newH, v); err != nil {
		t.Fatalf("new token must still authenticate after revoke: %v", err)
	}

	// Leak check.
	for _, f := range []string{cred.Identity, cred.Source, cred.Location, string(cred.Kind)} {
		if strings.Contains(f, oldTok) || strings.Contains(f, nc.token) {
			t.Errorf("token leaked into non-secret field %q", f)
		}
	}
}

func TestK8sRevokeRequiresSecretName(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	k := &K8s{}
	cred := discover.Credential{
		Source: "k8s",
		Secret: v.Store([]byte("k8s://10.0.0.1:6443/?ns=n&sa=s&token=t")),
	}
	err := k.RevokeOld(context.Background(), cred, v)
	if err == nil || !strings.Contains(err.Error(), "no recorded secret name") {
		t.Fatalf("expected revoke-without-secret error, got %v", err)
	}
}

// TestK8sTLSTrust proves the ca=/insecure= plumbing actually drives the TLS
// handshake when no client is injected (the real-apiserver path). The httptest
// server serves a self-signed cert, so a default client rejects it; pinning its CA
// or setting insecure=1 must make the same request succeed.
func TestK8sTLSTrust(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	ctx := context.Background()
	const ns, sa, tok = "labns", "labsa", "eyJtls0123"

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/namespaces/"+ns+"/serviceaccounts/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"name": sa}})
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	caB64 := base64.StdEncoding.EncodeToString(caPEM)

	verifyWith := func(blob string) error {
		k := &K8s{} // NO injected client — exercises clientFor's real TLS path
		h := v.Store([]byte(blob))
		return k.Verify(ctx, h, v)
	}

	base := "k8s://" + host + "/?ns=" + ns + "&sa=" + sa + "&token=" + tok

	if err := verifyWith(base); err == nil {
		t.Error("untrusted self-signed cert should fail without ca=/insecure=")
	}
	if err := verifyWith(base + "&insecure=1"); err != nil {
		t.Errorf("insecure=1 should skip verification: %v", err)
	}
	if err := verifyWith(base + "&ca=" + url.QueryEscape(caB64)); err != nil {
		t.Errorf("pinned ca= should trust the server cert: %v", err)
	}

	// Blob round-trip: ca=/insecure= survive build()->parse().
	cr := k8sCred{base: "https://" + host, ns: ns, sa: sa, token: tok, ca: caB64, insecure: true}
	got, err := parseK8sCred(v, v.Store([]byte(cr.build())))
	if err != nil {
		t.Fatalf("round-trip parse: %v", err)
	}
	if got.ca != caB64 || !got.insecure {
		t.Errorf("ca/insecure did not round-trip: ca-match=%v insecure=%v", got.ca == caB64, got.insecure)
	}
}

func TestK8sRejectsBadSecret(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	k := &K8s{}
	// missing namespace/sa
	cred := discover.Credential{Source: "k8s", Secret: v.Store([]byte("k8s://10.0.0.1:6443/?token=t"))}
	if _, err := k.Rotate(context.Background(), cred, v); err == nil {
		t.Error("Rotate should reject a secret with no namespace/sa")
	}
}
