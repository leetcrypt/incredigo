package rotate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// cfEmu is an in-process Cloudflare API emulator for one token id: it tracks the
// currently-valid value, rolls it on PUT .../value, and verifies a Bearer token.
type cfEmu struct {
	mu     sync.Mutex
	id     string
	cur    string // currently-valid token value
	minted int
}

func (e *cfEmu) bearer(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

func (e *cfEmu) valid(tok string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return tok != "" && tok == e.cur
}

func (e *cfEmu) roll() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.minted++
	e.cur = "cf-rolled-value-" + itoa(e.minted)
	return e.cur
}

func (e *cfEmu) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/client/v4/user/tokens/"+e.id+"/value", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || !e.valid(e.bearer(r)) {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{"success": false})
			return
		}
		newVal := e.roll()
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": newVal})
	})
	mux.HandleFunc("/client/v4/user/tokens/verify", func(w http.ResponseWriter, r *http.Request) {
		if !e.valid(e.bearer(r)) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"success": false})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"result":  map[string]any{"id": e.id, "status": "active"},
		})
	})
	return mux
}

func TestCloudflareDetect(t *testing.T) {
	c := &Cloudflare{}
	if !c.Detect(discover.Credential{Source: "cloudflare"}) {
		t.Error("should detect Source=cloudflare")
	}
	if c.Detect(discover.Credential{Source: "aws"}) {
		t.Error("should not detect Source=aws")
	}
}

func TestCloudflareRotateRealCutover(t *testing.T) {
	emu := &cfEmu{id: "tok123", cur: "cf-seed-value-0001"}
	srv := httptest.NewTLSServer(emu.handler())
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")

	v := vault.New()
	defer v.Purge()
	oldVal := emu.cur
	cred := discover.Credential{
		Source:   "cloudflare",
		Identity: "cloudflare api token",
		Secret:   v.Store([]byte("cloudflare://" + host + "/?id=" + emu.id + "&token=" + url.QueryEscape(oldVal))),
	}
	c := &Cloudflare{HTTPClient: srv.Client()}
	ctx := context.Background()

	newH, err := c.Rotate(ctx, cred, v)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	nb, _ := v.Open(newH)
	nu, _ := url.Parse(strings.TrimSpace(string(nb.Bytes())))
	newVal := nu.Query().Get("token")
	if newVal == "" || newVal == oldVal {
		t.Fatalf("blob carries no fresh token value (got %q)", newVal)
	}
	if nu.Query().Get("id") != emu.id {
		t.Errorf("token id changed: want %q got %q", emu.id, nu.Query().Get("id"))
	}

	if err := c.Verify(ctx, newH, v); err != nil {
		t.Errorf("Verify(new) should pass: %v", err)
	}

	// CUTOVER: the old value is dead after the roll.
	if err := c.Verify(ctx, cred.Secret, v); err == nil {
		t.Error("Verify(old) must fail after rotation — old value should be invalid")
	} else if strings.Contains(err.Error(), newVal) {
		t.Error("error leaked the new token value")
	}

	if err := c.RevokeOld(ctx, cred, v); err != nil {
		t.Errorf("RevokeOld (no-op) returned: %v", err)
	}
}

func TestCloudflareRejectsBadSecret(t *testing.T) {
	c := &Cloudflare{}
	v := vault.New()
	defer v.Purge()
	// missing id
	cred := discover.Credential{Source: "cloudflare", Secret: v.Store([]byte("cloudflare://api/?token=abc"))}
	if _, err := c.Rotate(context.Background(), cred, v); err == nil {
		t.Error("Rotate should reject a secret with no token id")
	}
}
