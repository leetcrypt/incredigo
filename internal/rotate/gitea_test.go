package rotate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// giteaEmu is a minimal Gitea API emulator that ENFORCES token validity: a token
// authenticates only while it exists, and DELETE makes it stop working — so the
// test can prove a real cutover (old token dead, new token alive).
type giteaEmu struct {
	mu       sync.Mutex
	byName   map[string]string // name -> token value
	byValue  map[string]string // token value -> name
	user     string
	srv      *httptest.Server
	createOK func(r *http.Request) bool // auth gate for create/delete
}

func newGiteaEmu(t *testing.T, user, seedName, seedValue string) *giteaEmu {
	e := &giteaEmu{
		byName:  map[string]string{seedName: seedValue},
		byValue: map[string]string{seedValue: seedName},
		user:    user,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/user", e.handleUser)
	mux.HandleFunc("/api/v1/users/", e.handleTokens)
	e.srv = httptest.NewServer(mux)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *giteaEmu) valid(token string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.byValue[token]
	return ok
}

// presentedToken returns the bearer token from an "Authorization: token <v>" header.
func presentedToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "token ") {
		return strings.TrimPrefix(h, "token ")
	}
	return ""
}

func (e *giteaEmu) handleUser(w http.ResponseWriter, r *http.Request) {
	if !e.valid(presentedToken(r)) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"login": e.user, "id": 1})
}

func (e *giteaEmu) handleTokens(w http.ResponseWriter, r *http.Request) {
	// Authorize management calls: a valid token (token auth) or any basic auth.
	authed := e.valid(presentedToken(r))
	if u, _, ok := r.BasicAuth(); ok && u == e.user {
		authed = true
	}
	if e.createOK != nil {
		authed = e.createOK(r)
	}
	if !authed {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	switch r.Method {
	case http.MethodPost:
		var body struct {
			Name string `json:"name"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		raw := make([]byte, 20)
		rand.Read(raw)
		val := hex.EncodeToString(raw)
		e.mu.Lock()
		e.byName[body.Name] = val
		e.byValue[val] = body.Name
		e.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"id": 2, "name": body.Name, "sha1": val})
	case http.MethodDelete:
		// path: /api/v1/users/{user}/tokens/{name}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		name := parts[len(parts)-1]
		e.mu.Lock()
		if v, ok := e.byName[name]; ok {
			delete(e.byValue, v)
			delete(e.byName, name)
		}
		e.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func TestGiteaRotateRealCutover(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	ctx := context.Background()

	const user, seedName, oldTok = "alice", "seed", "0123456789abcdef0123456789abcdef01234567"
	emu := newGiteaEmu(t, user, seedName, oldTok)

	oldBlob := emu.srv.URL + "/?name=" + seedName // becomes http://host/?name=seed with userinfo below
	// Build the blob with userinfo: http://alice:oldtok@host/?name=seed
	oldBlob = strings.Replace(emu.srv.URL, "http://", "http://"+user+":"+oldTok+"@", 1) + "/?name=" + seedName

	cred := discover.Credential{
		Source:   "gitea",
		Kind:     discover.KindToken,
		Identity: user + " @ gitea",
		Location: "imported/gitea/alice",
		Secret:   v.Store([]byte(oldBlob)),
	}

	g := &Gitea{}

	// Baseline: the seeded token authenticates.
	if !emu.valid(oldTok) {
		t.Fatal("seed token should be valid at start")
	}

	// 1. Rotate — create a new token (old still valid).
	newH, err := g.Rotate(ctx, cred, v)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	ns, err := parseGiteaSecret(v, newH)
	if err != nil {
		t.Fatalf("parse new secret: %v", err)
	}
	if ns.token == oldTok {
		t.Fatal("new token equals old — rotation minted nothing")
	}
	if !emu.valid(oldTok) {
		t.Fatal("old token must remain valid before revoke")
	}
	if !emu.valid(ns.token) {
		t.Fatal("new token must be valid after create")
	}

	// 2. Verify(new) via the driver.
	if err := g.Verify(ctx, newH, v); err != nil {
		t.Fatalf("Verify(new): %v", err)
	}

	// 3. RevokeOld — delete the old token by name.
	if err := g.RevokeOld(ctx, cred, v); err != nil {
		t.Fatalf("RevokeOld: %v", err)
	}

	// Cutover assertions: old dead, new alive.
	if emu.valid(oldTok) {
		t.Fatal("old token must be invalid after revoke")
	}
	if err := g.Verify(ctx, newH, v); err != nil {
		t.Fatalf("new token must still authenticate after revoke: %v", err)
	}

	// Leak check: token values must not appear in non-secret credential fields.
	for _, f := range []string{cred.Identity, cred.Source, cred.Location, string(cred.Kind)} {
		if strings.Contains(f, oldTok) || strings.Contains(f, ns.token) {
			t.Errorf("token leaked into non-secret field %q", f)
		}
	}
}

// giteaRefBlob builds the single-line blob with userinfo + name= + one ref= per file.
func giteaRefBlob(srvURL, user, tok, name string, refs ...string) string {
	b := strings.Replace(srvURL, "http://", "http://"+user+":"+tok+"@", 1) + "/?name=" + name
	for _, r := range refs {
		b += "&ref=" + r
	}
	return b
}

// TestGiteaMultiReferenceCutover proves the blast-and-cutover: the old token literal,
// embedded verbatim in several on-disk reference files (a .git-credentials line, an
// embedded git-remote URL, a tea config), is rewritten to the freshly minted token in
// EVERY file after Rotate — and Verify confirms the new token is present in each.
func TestGiteaMultiReferenceCutover(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	ctx := context.Background()

	const user, seedName = "alice", "seed"
	const oldTok = "0123456789abcdef0123456789abcdef01234567" // 40-hex, > minGiteaTokenLen
	emu := newGiteaEmu(t, user, seedName, oldTok)

	dir := t.TempDir()
	// Three distinct real-world shapes, all embedding the old token verbatim.
	gitCreds := filepath.Join(dir, ".git-credentials")
	gitConfig := filepath.Join(dir, "config") // embedded git remote URL
	teaConfig := filepath.Join(dir, "tea.yml")
	host := strings.TrimPrefix(emu.srv.URL, "http://")
	writeFile(t, gitCreds, "http://"+user+":"+oldTok+"@"+host+"\n")
	writeFile(t, gitConfig, "[remote \"origin\"]\n\turl = http://"+user+":"+oldTok+"@"+host+"/alice/repo.git\n")
	writeFile(t, teaConfig, "logins:\n  - name: gitea\n    token: "+oldTok+"\n")

	oldBlob := giteaRefBlob(emu.srv.URL, user, oldTok, seedName, gitCreds, gitConfig, teaConfig)
	cred := discover.Credential{
		Source:   "gitea",
		Kind:     discover.KindToken,
		Identity: user + " @ gitea",
		Location: "imported/gitea/alice",
		Secret:   v.Store([]byte(oldBlob)),
	}

	g := &Gitea{}
	newH, err := g.Rotate(ctx, cred, v)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	ns, err := parseGiteaSecret(v, newH)
	if err != nil {
		t.Fatalf("parse new secret: %v", err)
	}
	if ns.token == oldTok || !emu.valid(ns.token) {
		t.Fatalf("expected a fresh valid token, got %q", ns.token)
	}

	// Every reference file must now hold the NEW token and NOT the old one.
	for _, ref := range []string{gitCreds, gitConfig, teaConfig} {
		b, err := os.ReadFile(ref)
		if err != nil {
			t.Fatalf("read %s: %v", ref, err)
		}
		if strings.Contains(string(b), oldTok) {
			t.Errorf("old token still present in %s after cutover", ref)
		}
		if !strings.Contains(string(b), ns.token) {
			t.Errorf("new token missing from %s after cutover", ref)
		}
	}

	// Verify(new) must pass now that every ref holds the new token.
	if err := g.Verify(ctx, newH, v); err != nil {
		t.Fatalf("Verify(new): %v", err)
	}

	// RevokeOld deletes the old token — refs already point at the new one, so nothing breaks.
	if err := g.RevokeOld(ctx, cred, v); err != nil {
		t.Fatalf("RevokeOld: %v", err)
	}
	if emu.valid(oldTok) {
		t.Fatal("old token must be dead after revoke")
	}
}

// TestGiteaVerifyFailsWhenRefMissingToken proves Verify short-circuits the spine (before
// RevokeOld) if a reference file does not contain the new token — e.g. an external edit
// clobbered it. The old token must stay live in that case.
func TestGiteaVerifyFailsWhenRefMissingToken(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	ctx := context.Background()

	const user, seedName = "alice", "seed"
	const oldTok = "0123456789abcdef0123456789abcdef01234567"
	emu := newGiteaEmu(t, user, seedName, oldTok)

	dir := t.TempDir()
	ref := filepath.Join(dir, ".git-credentials")
	host := strings.TrimPrefix(emu.srv.URL, "http://")
	writeFile(t, ref, "http://"+user+":"+oldTok+"@"+host+"\n")

	oldBlob := giteaRefBlob(emu.srv.URL, user, oldTok, seedName, ref)
	cred := discover.Credential{Source: "gitea", Secret: v.Store([]byte(oldBlob))}

	g := &Gitea{}
	newH, err := g.Rotate(ctx, cred, v)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	// Simulate an external clobber: wipe the ref so the new token is no longer present.
	writeFile(t, ref, "http://"+user+":deadbeef@"+host+"\n")
	if err := g.Verify(ctx, newH, v); err == nil {
		t.Fatal("Verify must fail when a ref no longer holds the new token")
	}
	// Old token is untouched — spine would leave it live.
	if !emu.valid(oldTok) {
		t.Fatal("old token must remain live when Verify fails pre-revoke")
	}
}

// TestGiteaRefRewriteRejectsShortToken proves the length guard: a too-short old token
// (below minGiteaTokenLen) is refused before any file is touched, so a short literal can
// never sweep through unrelated file contents.
func TestGiteaRefRewriteRejectsShortToken(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	ctx := context.Background()

	const user, seedName = "alice", "seed"
	const shortTok = "abc123" // < minGiteaTokenLen
	emu := newGiteaEmu(t, user, seedName, shortTok)

	dir := t.TempDir()
	ref := filepath.Join(dir, ".git-credentials")
	host := strings.TrimPrefix(emu.srv.URL, "http://")
	const orig = "http://" + user + ":" + shortTok + "@HOST\n"
	writeFile(t, ref, strings.Replace(orig, "HOST", host, 1))

	oldBlob := giteaRefBlob(emu.srv.URL, user, shortTok, seedName, ref)
	cred := discover.Credential{Source: "gitea", Secret: v.Store([]byte(oldBlob))}

	g := &Gitea{}
	if _, err := g.Rotate(ctx, cred, v); err == nil || !strings.Contains(err.Error(), "too short") {
		t.Fatalf("expected too-short refusal, got %v", err)
	}
	// The ref file must be untouched (still holds the original short-token line).
	b, _ := os.ReadFile(ref)
	if !strings.Contains(string(b), shortTok) {
		t.Fatal("ref file was modified despite the length guard")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestGiteaRevokeRequiresName(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	g := &Gitea{}
	// Blob with no name= query → RevokeOld must refuse (guided), not silently pass.
	cred := discover.Credential{
		Source: "gitea",
		Secret: v.Store([]byte("https://bob:tok123@gitea.example.com/")),
	}
	err := g.RevokeOld(context.Background(), cred, v)
	if err == nil || !strings.Contains(err.Error(), "no recorded name") {
		t.Fatalf("expected revoke-without-name error, got %v", err)
	}
}
