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

// sendgridEmu emulates the SendGrid /v3/api_keys resource and ENFORCES key validity
// via the Bearer token: a key authenticates only while it exists, POST mints a new key
// (cloning whatever scopes were requested), GET /v3/api_keys/<id> returns a key's
// scopes, GET /v3/scopes proves auth, and DELETE makes a key stop working — so a test
// can prove a real cutover.
type sendgridEmu struct {
	mu      sync.Mutex
	secrets map[string]string   // id -> token
	scopes  map[string][]string // id -> scopes
	srv     *httptest.Server
}

func newSendGridEmu(t *testing.T, seedID, seedToken string, seedScopes []string) *sendgridEmu {
	e := &sendgridEmu{
		secrets: map[string]string{seedID: seedToken},
		scopes:  map[string][]string{seedID: seedScopes},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v3/api_keys", e.handleCollection)
	mux.HandleFunc("/v3/api_keys/", e.handleItem)
	mux.HandleFunc("/v3/scopes", e.handleScopes)
	e.srv = httptest.NewTLSServer(mux)
	t.Cleanup(e.srv.Close)
	return e
}

// bearer returns the id whose token matches the request's Bearer header, or "".
func (e *sendgridEmu) bearer(r *http.Request) string {
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

func (e *sendgridEmu) handleCollection(w http.ResponseWriter, r *http.Request) {
	if e.bearer(r) == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodPost:
		var in struct {
			Name   string   `json:"name"`
			Scopes []string `json:"scopes"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		raw := make([]byte, 8)
		rand.Read(raw)
		id := "sgid_" + hex.EncodeToString(raw)
		tokRaw := make([]byte, 16)
		rand.Read(tokRaw)
		token := "SG." + hex.EncodeToString(tokRaw)
		e.mu.Lock()
		e.secrets[id] = token
		e.scopes[id] = in.Scopes
		e.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"api_key": token, "api_key_id": id, "name": in.Name, "scopes": in.Scopes})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (e *sendgridEmu) handleItem(w http.ResponseWriter, r *http.Request) {
	if e.bearer(r) == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v3/api_keys/")
	switch r.Method {
	case http.MethodGet:
		e.mu.Lock()
		sc, ok := e.scopes[id]
		e.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"api_key_id": id, "scopes": sc})
	case http.MethodDelete:
		e.mu.Lock()
		delete(e.secrets, id)
		delete(e.scopes, id)
		e.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// handleScopes is the auth proof endpoint: any valid key gets 200 + its scope list.
func (e *sendgridEmu) handleScopes(w http.ResponseWriter, r *http.Request) {
	id := e.bearer(r)
	if id == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	e.mu.Lock()
	sc := e.scopes[id]
	e.mu.Unlock()
	json.NewEncoder(w).Encode(map[string]any{"scopes": sc})
}

func (e *sendgridEmu) valid(token string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, t := range e.secrets {
		if t == token {
			return true
		}
	}
	return false
}

func (e *sendgridEmu) scopesOf(token string) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, t := range e.secrets {
		if t == token {
			return e.scopes[id]
		}
	}
	return nil
}

func TestSendGridDetect(t *testing.T) {
	sg := &SendGrid{}
	if !sg.Detect(discover.Credential{Source: "sendgrid"}) {
		t.Error("should detect Source=sendgrid")
	}
	if sg.Detect(discover.Credential{Source: "resend"}) {
		t.Error("should not detect Source=resend")
	}
}

func TestSendGridRotateRealCutover(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	ctx := context.Background()

	const seedID, oldToken = "sgid_seed01234567", "SG.old0123456789abcdef"
	wantScopes := []string{"mail.send", "templates.read"}
	emu := newSendGridEmu(t, seedID, oldToken, wantScopes)

	host := strings.TrimPrefix(emu.srv.URL, "https://")
	oldBlob := "sendgrid://" + host + "/?id=" + seedID + "&secret=" + oldToken
	cred := discover.Credential{
		Source:   "sendgrid",
		Kind:     discover.KindToken,
		Identity: "sendgrid api key",
		Location: "imported/sendgrid/labkey",
		Secret:   v.Store([]byte(oldBlob)),
	}
	sg := &SendGrid{HTTPClient: emu.srv.Client()}

	if !emu.valid(oldToken) {
		t.Fatal("seed key should be valid at start")
	}

	// 1. Rotate.
	newH, err := sg.Rotate(ctx, cred, v)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	ns, err := parseSendGridSecret(v, newH)
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
	// The new key must clone the old key's scopes (faithful replacement, not a downgrade).
	gotScopes := emu.scopesOf(ns.secret)
	if strings.Join(gotScopes, ",") != strings.Join(wantScopes, ",") {
		t.Errorf("new key scopes = %v, want cloned %v", gotScopes, wantScopes)
	}

	// 2. Verify(new).
	if err := sg.Verify(ctx, newH, v); err != nil {
		t.Fatalf("Verify(new): %v", err)
	}

	// 3. RevokeOld.
	if err := sg.RevokeOld(ctx, cred, v); err != nil {
		t.Fatalf("RevokeOld: %v", err)
	}
	if emu.valid(oldToken) {
		t.Fatal("old key must be invalid after revoke")
	}
	if err := sg.Verify(ctx, newH, v); err != nil {
		t.Fatalf("new key must still authenticate after revoke: %v", err)
	}

	// Leak check.
	for _, f := range []string{cred.Identity, cred.Source, cred.Location, string(cred.Kind)} {
		if strings.Contains(f, oldToken) || strings.Contains(f, ns.secret) {
			t.Errorf("secret leaked into non-secret field %q", f)
		}
	}
}

func TestSendGridRejectsBadSecret(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	sg := &SendGrid{}
	// missing token
	cred := discover.Credential{Source: "sendgrid", Secret: v.Store([]byte("sendgrid://api.sendgrid.com/?id=sgid_x"))}
	if _, err := sg.Rotate(context.Background(), cred, v); err == nil {
		t.Error("Rotate should reject a secret with no token")
	}
}

func TestSendGridRevokeNeedsID(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	sg := &SendGrid{}
	cred := discover.Credential{Source: "sendgrid", Secret: v.Store([]byte("sendgrid://api.sendgrid.com/?secret=SG.x"))}
	if err := sg.RevokeOld(context.Background(), cred, v); err == nil {
		t.Error("RevokeOld should fail when the credential carries no api_key_id")
	}
}
