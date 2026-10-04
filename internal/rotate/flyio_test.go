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

// flyioEmu emulates the Fly.io GraphQL token API and ENFORCES token validity: the
// managing token is always valid and may create/delete; a deploy token authenticates
// the app query only while it exists, and deleteLimitedAccessToken makes it stop
// working — so a test can prove a real cutover.
type flyioEmu struct {
	mu       sync.Mutex
	managing string
	app      string
	tokens   map[string]string // deploy token id -> token value
	valid    map[string]bool   // deploy token value -> alive
	srv      *httptest.Server
}

func newFlyioEmu(t *testing.T, managing, app, seedID, seedToken string) *flyioEmu {
	e := &flyioEmu{
		managing: managing,
		app:      app,
		tokens:   map[string]string{seedID: seedToken},
		valid:    map[string]bool{seedToken: true},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/graphql", e.handle)
	e.srv = httptest.NewTLSServer(mux)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *flyioEmu) handle(w http.ResponseWriter, r *http.Request) {
	bear := bearer(r)
	var body struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	json.NewDecoder(r.Body).Decode(&body)

	switch {
	case strings.Contains(body.Query, "createLimitedAccessToken"):
		if bear != e.managing {
			gqlErr(w, "unauthorized: create requires managing token")
			return
		}
		idRaw := make([]byte, 8)
		rand.Read(idRaw)
		id := "lat_" + hex.EncodeToString(idRaw)
		tRaw := make([]byte, 16)
		rand.Read(tRaw)
		tok := "FlyV1_" + hex.EncodeToString(tRaw)
		e.mu.Lock()
		e.tokens[id] = tok
		e.valid[tok] = true
		e.mu.Unlock()
		gqlData(w, map[string]any{
			"createLimitedAccessToken": map[string]any{
				"limitedAccessToken": map[string]any{"id": id, "token": tok},
			},
		})
	case strings.Contains(body.Query, "deleteLimitedAccessToken"):
		if bear != e.managing {
			gqlErr(w, "unauthorized: delete requires managing token")
			return
		}
		id, _ := body.Variables["id"].(string)
		e.mu.Lock()
		if v, ok := e.tokens[id]; ok {
			delete(e.valid, v)
			delete(e.tokens, id)
		}
		e.mu.Unlock()
		gqlData(w, map[string]any{"deleteLimitedAccessToken": map[string]any{"token": "deleted"}})
	case strings.Contains(body.Query, "app(name"):
		e.mu.Lock()
		ok := e.valid[bear]
		e.mu.Unlock()
		if !ok {
			gqlErr(w, "unauthorized: unknown or revoked token")
			return
		}
		gqlData(w, map[string]any{"app": map[string]any{"id": "app_123", "name": e.app}})
	default:
		gqlErr(w, "unknown query")
	}
}

func gqlData(w http.ResponseWriter, data map[string]any) {
	json.NewEncoder(w).Encode(map[string]any{"data": data})
}

func gqlErr(w http.ResponseWriter, msg string) {
	json.NewEncoder(w).Encode(map[string]any{"errors": []map[string]any{{"message": msg}}})
}

func (e *flyioEmu) tokenValid(tok string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.valid[tok]
}

func TestFlyioDetect(t *testing.T) {
	f := &Flyio{}
	if !f.Detect(discover.Credential{Source: "flyio"}) {
		t.Error("should detect Source=flyio")
	}
	if f.Detect(discover.Credential{Source: "gcp"}) {
		t.Error("should not detect Source=gcp")
	}
}

func TestFlyioRotateRealCutover(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	ctx := context.Background()

	const managing, app, seedID, oldTok = "FlyV1_managing0123", "labapp", "lat_seed01", "FlyV1_old0123456789"
	emu := newFlyioEmu(t, managing, app, seedID, oldTok)

	host := strings.TrimPrefix(emu.srv.URL, "https://")
	oldBlob := "flyio://" + host + "/?org=orglab&app=" + app + "&auth=" + managing + "&id=" + seedID + "&token=" + oldTok
	cred := discover.Credential{
		Source:   "flyio",
		Kind:     discover.KindToken,
		Identity: app + " @ flyio",
		Location: "imported/flyio/labapp",
		Secret:   v.Store([]byte(oldBlob)),
	}
	f := &Flyio{HTTPClient: emu.srv.Client()}

	if !emu.tokenValid(oldTok) {
		t.Fatal("seed deploy token should be valid at start")
	}

	// 1. Rotate.
	newH, err := f.Rotate(ctx, cred, v)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	ns, err := parseFlyioSecret(v, newH)
	if err != nil {
		t.Fatalf("parse new secret: %v", err)
	}
	if ns.token == oldTok {
		t.Fatal("new deploy token equals old — rotation minted nothing")
	}
	if ns.id == "" || ns.id == seedID {
		t.Fatalf("new secret must carry a fresh token id, got %q", ns.id)
	}
	if ns.auth != managing {
		t.Fatal("managing token must be preserved across rotation")
	}
	if !emu.tokenValid(oldTok) {
		t.Fatal("old deploy token must remain valid before revoke")
	}
	if !emu.tokenValid(ns.token) {
		t.Fatal("new deploy token must be valid after create")
	}

	// 2. Verify(new).
	if err := f.Verify(ctx, newH, v); err != nil {
		t.Fatalf("Verify(new): %v", err)
	}

	// 3. RevokeOld.
	if err := f.RevokeOld(ctx, cred, v); err != nil {
		t.Fatalf("RevokeOld: %v", err)
	}
	if emu.tokenValid(oldTok) {
		t.Fatal("old deploy token must be invalid after revoke")
	}
	if err := f.Verify(ctx, newH, v); err != nil {
		t.Fatalf("new deploy token must still authenticate after revoke: %v", err)
	}

	// Leak check.
	for _, fld := range []string{cred.Identity, cred.Source, cred.Location, string(cred.Kind)} {
		if strings.Contains(fld, oldTok) || strings.Contains(fld, ns.token) || strings.Contains(fld, managing) {
			t.Errorf("token leaked into non-secret field %q", fld)
		}
	}
}

func TestFlyioRevokeRequiresID(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	f := &Flyio{}
	cred := discover.Credential{
		Source: "flyio",
		Secret: v.Store([]byte("flyio://api.fly.io/?app=a&auth=mgmt&token=deploytok")),
	}
	err := f.RevokeOld(context.Background(), cred, v)
	if err == nil || !strings.Contains(err.Error(), "no recorded id") {
		t.Fatalf("expected revoke-without-id error, got %v", err)
	}
}

func TestFlyioRejectsBadSecret(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	f := &Flyio{}
	// no managing token
	cred := discover.Credential{Source: "flyio", Secret: v.Store([]byte("flyio://api.fly.io/?app=a&token=deploytok"))}
	if _, err := f.Rotate(context.Background(), cred, v); err == nil {
		t.Error("Rotate should reject a secret with no managing token")
	}
}
