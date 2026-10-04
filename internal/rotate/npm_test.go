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

// npmEmu is a minimal npm registry token API emulator that ENFORCES token validity:
// a token authenticates (whoami) only while it exists, POST mints a new token+key,
// and DELETE-by-key makes a token stop working — so a test can prove a real cutover
// (old token dead, new token alive).
type npmEmu struct {
	mu       sync.Mutex
	byKey    map[string]string // key -> token value
	byValue  map[string]string // token value -> key
	user     string
	srv      *httptest.Server
}

func newNPMEmu(t *testing.T, user, seedKey, seedValue string) *npmEmu {
	e := &npmEmu{
		byKey:   map[string]string{seedKey: seedValue},
		byValue: map[string]string{seedValue: seedKey},
		user:    user,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/-/whoami", e.handleWhoami)
	mux.HandleFunc("/-/npm/v1/tokens", e.handleCreate)
	mux.HandleFunc("/-/npm/v1/tokens/token/", e.handleDelete)
	e.srv = httptest.NewTLSServer(mux)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *npmEmu) valid(token string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.byValue[token]
	return ok
}

// bearer returns the token from an "Authorization: Bearer <v>" header.
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

func (e *npmEmu) handleWhoami(w http.ResponseWriter, r *http.Request) {
	if !e.valid(bearer(r)) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"username": e.user})
}

func (e *npmEmu) handleCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !e.valid(bearer(r)) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	raw := make([]byte, 20)
	rand.Read(raw)
	val := "npm_" + hex.EncodeToString(raw)
	keyRaw := make([]byte, 16)
	rand.Read(keyRaw)
	key := hex.EncodeToString(keyRaw)
	e.mu.Lock()
	e.byKey[key] = val
	e.byValue[val] = key
	e.mu.Unlock()
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{"token": val, "key": key})
}

func (e *npmEmu) handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !e.valid(bearer(r)) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	key := parts[len(parts)-1]
	e.mu.Lock()
	if v, ok := e.byKey[key]; ok {
		delete(e.byValue, v)
		delete(e.byKey, key)
	}
	e.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func TestNPMDetect(t *testing.T) {
	n := &NPM{}
	if !n.Detect(discover.Credential{Source: "npm"}) {
		t.Error("should detect Source=npm")
	}
	if n.Detect(discover.Credential{Source: "gitea"}) {
		t.Error("should not detect Source=gitea")
	}
}

func TestNPMRotateRealCutover(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	ctx := context.Background()

	const user, seedKey, oldTok = "labpub", "seedkey0123456789", "npm_0123456789abcdef0123456789abcdef01234567"
	emu := newNPMEmu(t, user, seedKey, oldTok)

	host := strings.TrimPrefix(emu.srv.URL, "https://")
	// npm:// scheme normalises to https, matching the TLS emulator; the rebuilt blob
	// (which Verify re-parses) uses the same npm→https mapping.
	oldBlob := "npm://" + host + "/?user=" + user + "&token=" + oldTok + "&key=" + seedKey
	cred := discover.Credential{
		Source:   "npm",
		Kind:     discover.KindToken,
		Identity: user + " @ npm",
		Location: "imported/npm/labpub",
		Secret:   v.Store([]byte(oldBlob)),
	}
	n := &NPM{HTTPClient: emu.srv.Client()}

	if !emu.valid(oldTok) {
		t.Fatal("seed token should be valid at start")
	}

	// 1. Rotate — create a new token (old still valid).
	newH, err := n.Rotate(ctx, cred, v)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	ns, err := parseNPMSecret(v, newH)
	if err != nil {
		t.Fatalf("parse new secret: %v", err)
	}
	if ns.token == oldTok {
		t.Fatal("new token equals old — rotation minted nothing")
	}
	if ns.key == "" || ns.key == seedKey {
		t.Fatalf("new secret must carry a fresh key, got %q", ns.key)
	}
	if !emu.valid(oldTok) {
		t.Fatal("old token must remain valid before revoke")
	}
	if !emu.valid(ns.token) {
		t.Fatal("new token must be valid after create")
	}

	// 2. Verify(new) via the driver.
	if err := n.Verify(ctx, newH, v); err != nil {
		t.Fatalf("Verify(new): %v", err)
	}

	// 3. RevokeOld — delete the old token by key.
	if err := n.RevokeOld(ctx, cred, v); err != nil {
		t.Fatalf("RevokeOld: %v", err)
	}

	// Cutover assertions: old dead, new alive.
	if emu.valid(oldTok) {
		t.Fatal("old token must be invalid after revoke")
	}
	if err := n.Verify(ctx, newH, v); err != nil {
		t.Fatalf("new token must still authenticate after revoke: %v", err)
	}

	// Leak check: token values must not appear in non-secret credential fields.
	for _, f := range []string{cred.Identity, cred.Source, cred.Location, string(cred.Kind)} {
		if strings.Contains(f, oldTok) || strings.Contains(f, ns.token) {
			t.Errorf("token leaked into non-secret field %q", f)
		}
	}
}

func TestNPMRevokeRequiresKey(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	n := &NPM{}
	// Blob with token but no key= → RevokeOld must refuse (guided), not silently pass.
	cred := discover.Credential{
		Source: "npm",
		Secret: v.Store([]byte("npm://registry.npmjs.org/?user=bob&token=npm_abc123")),
	}
	err := n.RevokeOld(context.Background(), cred, v)
	if err == nil || !strings.Contains(err.Error(), "no recorded key") {
		t.Fatalf("expected revoke-without-key error, got %v", err)
	}
}

func TestNPMRejectsBadSecret(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	n := &NPM{}
	// no token
	cred := discover.Credential{Source: "npm", Secret: v.Store([]byte("npm://registry.npmjs.org/?user=bob"))}
	if _, err := n.Rotate(context.Background(), cred, v); err == nil {
		t.Error("Rotate should reject a secret with no token")
	}
}
