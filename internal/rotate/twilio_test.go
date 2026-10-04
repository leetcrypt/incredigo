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

// twilioEmu emulates the Twilio API Keys resource and ENFORCES key validity via Basic
// auth: a key (sid+secret) authenticates only while it exists, POST mints a new key,
// and DELETE makes a key stop working — so a test can prove a real cutover.
type twilioEmu struct {
	mu      sync.Mutex
	secrets map[string]string // sid -> secret
	account string
	srv     *httptest.Server
}

func newTwilioEmu(t *testing.T, account, seedSid, seedSecret string) *twilioEmu {
	e := &twilioEmu{
		secrets: map[string]string{seedSid: seedSecret},
		account: account,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/2010-04-01/Accounts/", e.handle)
	e.srv = httptest.NewTLSServer(mux)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *twilioEmu) authed(r *http.Request) bool {
	u, p, ok := r.BasicAuth()
	if !ok {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	s, exists := e.secrets[u]
	return exists && s == p
}

func (e *twilioEmu) handle(w http.ResponseWriter, r *http.Request) {
	if !e.authed(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// Path: /2010-04-01/Accounts/<AC>/Keys[.json | /<sid>.json]
	tail := strings.TrimSuffix(r.URL.Path[strings.Index(r.URL.Path, "/Keys"):], ".json")
	switch {
	case r.Method == http.MethodPost && tail == "/Keys":
		raw := make([]byte, 16)
		rand.Read(raw)
		sid := "SK" + hex.EncodeToString(raw)
		secRaw := make([]byte, 16)
		rand.Read(secRaw)
		secret := hex.EncodeToString(secRaw)
		e.mu.Lock()
		e.secrets[sid] = secret
		e.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"sid": sid, "secret": secret, "friendly_name": "incredigo-rotated"})
	case r.Method == http.MethodGet && strings.HasPrefix(tail, "/Keys/"):
		sid := strings.TrimPrefix(tail, "/Keys/")
		e.mu.Lock()
		_, ok := e.secrets[sid]
		e.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"sid": sid, "friendly_name": "incredigo-rotated"})
	case r.Method == http.MethodDelete && strings.HasPrefix(tail, "/Keys/"):
		sid := strings.TrimPrefix(tail, "/Keys/")
		e.mu.Lock()
		delete(e.secrets, sid)
		e.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (e *twilioEmu) valid(sid, secret string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	s, ok := e.secrets[sid]
	return ok && s == secret
}

func TestTwilioDetect(t *testing.T) {
	tw := &Twilio{}
	if !tw.Detect(discover.Credential{Source: "twilio"}) {
		t.Error("should detect Source=twilio")
	}
	if tw.Detect(discover.Credential{Source: "aws"}) {
		t.Error("should not detect Source=aws")
	}
}

func TestTwilioRotateRealCutover(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	ctx := context.Background()

	const account, seedSid, oldSecret = "AClab0123456789", "SKseed0123456789", "oldsecret0123456789abcdef"
	emu := newTwilioEmu(t, account, seedSid, oldSecret)

	host := strings.TrimPrefix(emu.srv.URL, "https://")
	oldBlob := "twilio://" + host + "/?account=" + account + "&sid=" + seedSid + "&secret=" + oldSecret
	cred := discover.Credential{
		Source:   "twilio",
		Kind:     discover.KindToken,
		Identity: account + " @ twilio",
		Location: "imported/twilio/labkey",
		Secret:   v.Store([]byte(oldBlob)),
	}
	tw := &Twilio{HTTPClient: emu.srv.Client()}

	if !emu.valid(seedSid, oldSecret) {
		t.Fatal("seed key should be valid at start")
	}

	// 1. Rotate.
	newH, err := tw.Rotate(ctx, cred, v)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	ns, err := parseTwilioSecret(v, newH)
	if err != nil {
		t.Fatalf("parse new secret: %v", err)
	}
	if ns.sid == seedSid || ns.secret == oldSecret {
		t.Fatal("new key equals old — rotation minted nothing")
	}
	if !emu.valid(seedSid, oldSecret) {
		t.Fatal("old key must remain valid before revoke")
	}
	if !emu.valid(ns.sid, ns.secret) {
		t.Fatal("new key must be valid after create")
	}

	// 2. Verify(new).
	if err := tw.Verify(ctx, newH, v); err != nil {
		t.Fatalf("Verify(new): %v", err)
	}

	// 3. RevokeOld.
	if err := tw.RevokeOld(ctx, cred, v); err != nil {
		t.Fatalf("RevokeOld: %v", err)
	}
	if emu.valid(seedSid, oldSecret) {
		t.Fatal("old key must be invalid after revoke")
	}
	if err := tw.Verify(ctx, newH, v); err != nil {
		t.Fatalf("new key must still authenticate after revoke: %v", err)
	}

	// Leak check.
	for _, f := range []string{cred.Identity, cred.Source, cred.Location, string(cred.Kind)} {
		if strings.Contains(f, oldSecret) || strings.Contains(f, ns.secret) {
			t.Errorf("secret leaked into non-secret field %q", f)
		}
	}
}

func TestTwilioRejectsBadSecret(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	tw := &Twilio{}
	// missing account
	cred := discover.Credential{Source: "twilio", Secret: v.Store([]byte("twilio://api.twilio.com/?sid=SKx&secret=y"))}
	if _, err := tw.Rotate(context.Background(), cred, v); err == nil {
		t.Error("Rotate should reject a secret with no account")
	}
}
