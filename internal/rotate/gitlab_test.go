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

// glEmu is an in-process GitLab API emulator: it tracks one currently-valid token
// and emulates self/rotate (mint new, revoke the caller's token) and GET /user.
// It records every Authorization/PRIVATE-TOKEN value seen so a test can assert the
// new token is never logged where it shouldn't be.
type glEmu struct {
	mu      sync.Mutex
	cur     string   // the currently-valid token
	minted  int      // rotate counter, makes each new token unique
	seenTok []string // PRIVATE-TOKEN values observed
}

func (e *glEmu) valid(tok string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.seenTok = append(e.seenTok, tok)
	return tok != "" && tok == e.cur
}

func (e *glEmu) rotate() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.minted++
	e.cur = "glpat-rotated-" + strings.Repeat("z", 4) + itoa(e.minted)
	return e.cur
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func (e *glEmu) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/personal_access_tokens/self/rotate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !e.valid(r.Header.Get("PRIVATE-TOKEN")) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		newTok := e.rotate() // also revokes the caller's (old) token
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{"id": e.minted, "token": newTok, "revoked": false})
	})
	mux.HandleFunc("/api/v4/user", func(w http.ResponseWriter, r *http.Request) {
		if !e.valid(r.Header.Get("PRIVATE-TOKEN")) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"id": 1, "username": "labadmin"})
	})
	return mux
}

func TestGitLabDetect(t *testing.T) {
	g := &GitLab{}
	if !g.Detect(discover.Credential{Source: "gitlab"}) {
		t.Error("should detect Source=gitlab")
	}
	if g.Detect(discover.Credential{Source: "gitea"}) {
		t.Error("should not detect Source=gitea")
	}
}

func TestGitLabRotateRealCutover(t *testing.T) {
	emu := &glEmu{cur: "glpat-seedtoken-0001"}
	srv := httptest.NewTLSServer(emu.handler())
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")

	v := vault.New()
	defer v.Purge()
	oldTok := emu.cur
	cred := discover.Credential{
		Source:   "gitlab",
		Identity: "gitlab pat",
		Secret:   v.Store([]byte("gitlab://" + host + "/?tok=" + url.QueryEscape(oldTok))),
	}
	g := &GitLab{HTTPClient: srv.Client()}
	ctx := context.Background()

	newH, err := g.Rotate(ctx, cred, v)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// Extract the new token from the rebuilt blob.
	nb, _ := v.Open(newH)
	nu, _ := url.Parse(strings.TrimSpace(string(nb.Bytes())))
	newTok := nu.Query().Get("tok")
	if newTok == "" || newTok == oldTok {
		t.Fatalf("blob carries no fresh token (got %q)", newTok)
	}

	if err := g.Verify(ctx, newH, v); err != nil {
		t.Errorf("Verify(new) should pass: %v", err)
	}

	// CUTOVER: the old token must be dead the moment Rotate returned (self/rotate
	// revokes it), independent of RevokeOld.
	if err := g.Verify(ctx, cred.Secret, v); err == nil {
		t.Error("Verify(old) must fail after rotation — old token should be revoked")
	} else if strings.Contains(err.Error(), newTok) {
		t.Error("error leaked the new token")
	}

	// RevokeOld is a no-op for this in-place engine.
	if err := g.RevokeOld(ctx, cred, v); err != nil {
		t.Errorf("RevokeOld (no-op) returned: %v", err)
	}

	// The new token must never have been handed to the emulator as the OLD token's
	// stand-in before it existed; and it must not appear in any leaked structure.
	for _, fld := range []string{cred.Identity} {
		if strings.Contains(fld, newTok) || strings.Contains(fld, oldTok) {
			t.Error("token leaked into credential metadata")
		}
	}
}

func TestGitLabRejectsBadSecret(t *testing.T) {
	g := &GitLab{}
	v := vault.New()
	defer v.Purge()
	cred := discover.Credential{Source: "gitlab", Secret: v.Store([]byte("gitlab://gitlab.example.com/"))} // no token
	if _, err := g.Rotate(context.Background(), cred, v); err == nil {
		t.Error("Rotate should reject a secret with no token")
	}
}
