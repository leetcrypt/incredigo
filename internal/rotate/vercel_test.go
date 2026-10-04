package rotate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// vercelEmu emulates the Vercel /v3/user/tokens resource and ENFORCES token validity
// via the Bearer header: a token authenticates only while it exists, POST mints a new
// one, DELETE makes a token stop working — so a test can prove a real cutover.
type vercelEmu struct {
	mu      sync.Mutex
	secrets map[string]string // id -> bearer
	srv     *httptest.Server
}

func newVercelEmu(t *testing.T, seedID, seedToken string) *vercelEmu {
	e := &vercelEmu{secrets: map[string]string{seedID: seedToken}}
	mux := http.NewServeMux()
	mux.HandleFunc("/v3/user/tokens", e.handleCollection)
	mux.HandleFunc("/v3/user/tokens/", e.handleItem)
	e.srv = httptest.NewTLSServer(mux)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *vercelEmu) authed(r *http.Request) bool {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, t := range e.secrets {
		if t == tok && tok != "" {
			return true
		}
	}
	return false
}

func (e *vercelEmu) handleCollection(w http.ResponseWriter, r *http.Request) {
	if !e.authed(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodPost:
		raw := make([]byte, 8)
		rand.Read(raw)
		id := "tok_" + hex.EncodeToString(raw)
		bRaw := make([]byte, 16)
		rand.Read(bRaw)
		bearer := hex.EncodeToString(bRaw)
		e.mu.Lock()
		e.secrets[id] = bearer
		e.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{"token": map[string]any{"id": id, "name": "incredigo-rotated"}, "bearerToken": bearer})
	case http.MethodGet:
		e.mu.Lock()
		var toks []map[string]any
		for id := range e.secrets {
			toks = append(toks, map[string]any{"id": id, "name": "t"})
		}
		e.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"tokens": toks})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (e *vercelEmu) handleItem(w http.ResponseWriter, r *http.Request) {
	if !e.authed(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v3/user/tokens/")
	switch r.Method {
	case http.MethodDelete:
		e.mu.Lock()
		delete(e.secrets, id)
		e.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{"tokenId": id})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (e *vercelEmu) valid(token string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, t := range e.secrets {
		if t == token {
			return true
		}
	}
	return false
}

func TestVercelDetect(t *testing.T) {
	ve := &Vercel{}
	if !ve.Detect(discover.Credential{Source: "vercel"}) {
		t.Error("should detect Source=vercel")
	}
	if ve.Detect(discover.Credential{Source: "resend"}) {
		t.Error("should not detect Source=resend")
	}
}

func TestVercelRotateRealCutover(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	ctx := context.Background()

	const seedID, oldToken = "tok_seed01234567", "oldbearer0123456789abcdef"
	emu := newVercelEmu(t, seedID, oldToken)

	host := strings.TrimPrefix(emu.srv.URL, "https://")
	oldBlob := "vercel://" + host + "/?id=" + seedID + "&secret=" + oldToken
	cred := discover.Credential{
		Source:   "vercel",
		Kind:     discover.KindToken,
		Identity: "vercel access token",
		Location: "imported/vercel/labtoken",
		Secret:   v.Store([]byte(oldBlob)),
	}
	ve := &Vercel{HTTPClient: emu.srv.Client()}

	if !emu.valid(oldToken) {
		t.Fatal("seed token should be valid at start")
	}

	newH, err := ve.Rotate(ctx, cred, v)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	ns, err := parseVercelSecret(v, newH)
	if err != nil {
		t.Fatalf("parse new secret: %v", err)
	}
	if ns.id == seedID || ns.secret == oldToken {
		t.Fatal("new token equals old — rotation minted nothing")
	}
	if !emu.valid(oldToken) {
		t.Fatal("old token must remain valid before revoke")
	}
	if !emu.valid(ns.secret) {
		t.Fatal("new token must be valid after create")
	}

	if err := ve.Verify(ctx, newH, v); err != nil {
		t.Fatalf("Verify(new): %v", err)
	}

	if err := ve.RevokeOld(ctx, cred, v); err != nil {
		t.Fatalf("RevokeOld: %v", err)
	}
	if emu.valid(oldToken) {
		t.Fatal("old token must be invalid after revoke")
	}
	if err := ve.Verify(ctx, newH, v); err != nil {
		t.Fatalf("new token must still authenticate after revoke: %v", err)
	}

	for _, f := range []string{cred.Identity, cred.Source, cred.Location, string(cred.Kind)} {
		if strings.Contains(f, oldToken) || strings.Contains(f, ns.secret) {
			t.Errorf("secret leaked into non-secret field %q", f)
		}
	}
}

func TestVercelRejectsBadSecret(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	ve := &Vercel{}
	cred := discover.Credential{Source: "vercel", Secret: v.Store([]byte("vercel://api.vercel.com/?id=tok_x"))}
	if _, err := ve.Rotate(context.Background(), cred, v); err == nil {
		t.Error("Rotate should reject a secret with no bearer token")
	}
}

func TestVercelRevokeNeedsID(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	ve := &Vercel{}
	cred := discover.Credential{Source: "vercel", Secret: v.Store([]byte("vercel://api.vercel.com/?secret=abc"))}
	if err := ve.RevokeOld(context.Background(), cred, v); err == nil {
		t.Error("RevokeOld should fail when the credential carries no token id")
	}
}
