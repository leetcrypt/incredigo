package rotate

import (
	"crypto/rand"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/nacl/box"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// ghaEmu is an in-process GitHub Actions API emulator for ONE repo secret. It owns a
// libsodium (NaCl) box keypair, serves the public key, and on PUT decrypts the sealed
// value with the private key so a test can assert the value the driver actually wrote.
type ghaEmu struct {
	mu        sync.Mutex
	pub       [32]byte
	priv      [32]byte
	keyID     string
	pat       string // the only accepted Bearer token
	secret    string // decrypted current secret value (after a PUT)
	hasSecret bool
}

func newGHAEmu(pat string) *ghaEmu {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return &ghaEmu{pub: *pub, priv: *priv, keyID: "kid-123", pat: pat}
}

func (e *ghaEmu) auth(r *http.Request) bool {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") == e.pat
}

func (e *ghaEmu) handler() http.Handler {
	mux := http.NewServeMux()
	const base = "/repos/octo/lab/actions/secrets"

	mux.HandleFunc(base+"/public-key", func(w http.ResponseWriter, r *http.Request) {
		if !e.auth(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"key_id": e.keyID,
			"key":    base64.StdEncoding.EncodeToString(e.pub[:]),
		})
	})

	// PUT writes (seals) the value; GET returns metadata only (never the value).
	mux.HandleFunc(base+"/DEPLOY_TOKEN", func(w http.ResponseWriter, r *http.Request) {
		if !e.auth(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodPut:
			var body struct {
				Encrypted string `json:"encrypted_value"`
				KeyID     string `json:"key_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.KeyID != e.keyID {
				w.WriteHeader(http.StatusUnprocessableEntity)
				return
			}
			sealed, err := base64.StdEncoding.DecodeString(body.Encrypted)
			if err != nil {
				w.WriteHeader(http.StatusUnprocessableEntity)
				return
			}
			plain, ok := box.OpenAnonymous(nil, sealed, &e.pub, &e.priv)
			if !ok {
				w.WriteHeader(http.StatusUnprocessableEntity)
				return
			}
			e.mu.Lock()
			e.secret = string(plain)
			e.hasSecret = true
			e.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			e.mu.Lock()
			has := e.hasSecret
			e.mu.Unlock()
			if !has {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"name": "DEPLOY_TOKEN"})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	return mux
}

func (e *ghaEmu) stored() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.secret
}

func TestGHActionsDetect(t *testing.T) {
	g := &GHActions{}
	if !g.Detect(discover.Credential{Source: "ghactions"}) {
		t.Error("should detect Source=ghactions")
	}
	if g.Detect(discover.Credential{Source: "gitlab"}) {
		t.Error("should not detect Source=gitlab")
	}
}

func TestGHActionsRotateSealsRealValue(t *testing.T) {
	emu := newGHAEmu("ghp_managementPAT0001")
	srv := httptest.NewTLSServer(emu.handler())
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")

	v := vault.New()
	defer v.Purge()
	oldVal := "old-deploy-value-0000"
	blob := "ghactions://" + host + "/?" + url.Values{
		"owner": {"octo"}, "repo": {"lab"}, "name": {"DEPLOY_TOKEN"},
		"pat": {emu.pat}, "val": {oldVal},
	}.Encode()
	cred := discover.Credential{
		Source:   "ghactions",
		Identity: "github actions secret DEPLOY_TOKEN",
		Secret:   v.Store([]byte(blob)),
	}
	g := &GHActions{HTTPClient: srv.Client()}
	ctx := context.Background()

	newH, err := g.Rotate(ctx, cred, v)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// The rebuilt blob must carry a fresh value (different from the old one).
	nb, _ := v.Open(newH)
	nu, _ := url.Parse(strings.TrimSpace(string(nb.Bytes())))
	newVal := nu.Query().Get("val")
	if newVal == "" || newVal == oldVal {
		t.Fatalf("blob carries no fresh value (got %q)", newVal)
	}
	if nu.Query().Get("name") != "DEPLOY_TOKEN" {
		t.Errorf("secret name changed: %q", nu.Query().Get("name"))
	}

	// CUTOVER PROOF: the value GitHub actually received (decrypted from the sealed
	// box) must equal the new plaintext in the rebuilt blob — proving the roll wrote
	// the real new value, not a simulation.
	if got := emu.stored(); got != newVal {
		t.Fatalf("server stored %q, blob says %q — sealed value mismatch", got, newVal)
	}
	if emu.stored() == oldVal {
		t.Error("old value still stored after rotation")
	}

	if err := g.Verify(ctx, newH, v); err != nil {
		t.Errorf("Verify(new) should pass: %v", err)
	}

	if err := g.RevokeOld(ctx, cred, v); err != nil {
		t.Errorf("RevokeOld (no-op) returned: %v", err)
	}

	// Leak-check: neither the management PAT nor any secret value may appear in the
	// credential's non-secret metadata.
	for _, fld := range []string{cred.Identity} {
		if strings.Contains(fld, emu.pat) || strings.Contains(fld, newVal) || strings.Contains(fld, oldVal) {
			t.Error("secret material leaked into credential metadata")
		}
	}
}

func TestGHActionsRejectsBadSecret(t *testing.T) {
	g := &GHActions{}
	v := vault.New()
	defer v.Purge()
	// missing owner/repo
	cred := discover.Credential{Source: "ghactions",
		Secret: v.Store([]byte("ghactions://api/?name=X&pat=abc&val=y"))}
	if _, err := g.Rotate(context.Background(), cred, v); err == nil {
		t.Error("Rotate should reject a secret with no owner/repo")
	}
}
