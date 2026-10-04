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

// resendEmu emulates the Resend /api-keys resource and ENFORCES key validity via the
// Bearer token: a key authenticates only while it exists, POST mints a new key, and
// DELETE makes a key stop working — so a test can prove a real cutover.
type resendEmu struct {
	mu      sync.Mutex
	secrets map[string]string // id -> token
	srv     *httptest.Server
}

func newResendEmu(t *testing.T, seedID, seedToken string) *resendEmu {
	e := &resendEmu{secrets: map[string]string{seedID: seedToken}}
	mux := http.NewServeMux()
	mux.HandleFunc("/api-keys", e.handleCollection)
	mux.HandleFunc("/api-keys/", e.handleItem)
	e.srv = httptest.NewTLSServer(mux)
	t.Cleanup(e.srv.Close)
	return e
}

// bearer returns the id whose token matches the request's Bearer header, or "".
func (e *resendEmu) bearer(r *http.Request) string {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, t := range e.secrets {
		if t == tok && tok != "" {
			return id
		}
	}
	return ""
}

func (e *resendEmu) handleCollection(w http.ResponseWriter, r *http.Request) {
	if e.bearer(r) == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodPost:
		raw := make([]byte, 8)
		rand.Read(raw)
		id := "key_" + hex.EncodeToString(raw)
		tokRaw := make([]byte, 16)
		rand.Read(tokRaw)
		token := "re_" + hex.EncodeToString(tokRaw)
		e.mu.Lock()
		e.secrets[id] = token
		e.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"id": id, "token": token})
	case http.MethodGet:
		e.mu.Lock()
		var data []map[string]any
		for id := range e.secrets {
			data = append(data, map[string]any{"id": id, "name": "k"})
		}
		e.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"data": data})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (e *resendEmu) handleItem(w http.ResponseWriter, r *http.Request) {
	if e.bearer(r) == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api-keys/")
	switch r.Method {
	case http.MethodDelete:
		e.mu.Lock()
		delete(e.secrets, id)
		e.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (e *resendEmu) valid(token string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, t := range e.secrets {
		if t == token {
			return true
		}
	}
	return false
}

func TestResendDetect(t *testing.T) {
	re := &Resend{}
	if !re.Detect(discover.Credential{Source: "resend"}) {
		t.Error("should detect Source=resend")
	}
	if re.Detect(discover.Credential{Source: "twilio"}) {
		t.Error("should not detect Source=twilio")
	}
}

func TestResendRotateRealCutover(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	ctx := context.Background()

	const seedID, oldToken = "key_seed01234567", "re_old0123456789abcdef"
	emu := newResendEmu(t, seedID, oldToken)

	host := strings.TrimPrefix(emu.srv.URL, "https://")
	oldBlob := "resend://" + host + "/?id=" + seedID + "&secret=" + oldToken
	cred := discover.Credential{
		Source:   "resend",
		Kind:     discover.KindToken,
		Identity: "resend api key",
		Location: "imported/resend/labkey",
		Secret:   v.Store([]byte(oldBlob)),
	}
	re := &Resend{HTTPClient: emu.srv.Client()}

	if !emu.valid(oldToken) {
		t.Fatal("seed key should be valid at start")
	}

	// 1. Rotate.
	newH, err := re.Rotate(ctx, cred, v)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	ns, err := parseResendSecret(v, newH)
	if err != nil {
		t.Fatalf("parse new secret: %v", err)
	}
	if ns.id == seedID || ns.secret == oldToken {
		t.Fatal("new key equals old — rotation minted nothing")
	}
	if !emu.valid(oldToken) {
		t.Fatal("old key must remain valid before revoke")
	}
	if !emu.valid(ns.secret) {
		t.Fatal("new key must be valid after create")
	}

	// 2. Verify(new).
	if err := re.Verify(ctx, newH, v); err != nil {
		t.Fatalf("Verify(new): %v", err)
	}

	// 3. RevokeOld.
	if err := re.RevokeOld(ctx, cred, v); err != nil {
		t.Fatalf("RevokeOld: %v", err)
	}
	if emu.valid(oldToken) {
		t.Fatal("old key must be invalid after revoke")
	}
	if err := re.Verify(ctx, newH, v); err != nil {
		t.Fatalf("new key must still authenticate after revoke: %v", err)
	}

	// Leak check.
	for _, f := range []string{cred.Identity, cred.Source, cred.Location, string(cred.Kind)} {
		if strings.Contains(f, oldToken) || strings.Contains(f, ns.secret) {
			t.Errorf("secret leaked into non-secret field %q", f)
		}
	}
}

func TestResendRejectsBadSecret(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	re := &Resend{}
	// missing token
	cred := discover.Credential{Source: "resend", Secret: v.Store([]byte("resend://api.resend.com/?id=key_x"))}
	if _, err := re.Rotate(context.Background(), cred, v); err == nil {
		t.Error("Rotate should reject a secret with no token")
	}
}

func TestResendRevokeNeedsID(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	re := &Resend{}
	cred := discover.Credential{Source: "resend", Secret: v.Store([]byte("resend://api.resend.com/?secret=re_x"))}
	if err := re.RevokeOld(context.Background(), cred, v); err == nil {
		t.Error("RevokeOld should fail when the credential carries no key id")
	}
}
