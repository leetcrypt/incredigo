package rotate

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// mullvadEmu is a minimal in-memory stand-in for the Mullvad app API: it exchanges a
// known account number for an access token, and stores per-account devices keyed by
// id with their registered (PUBLIC) key. It NEVER receives a private key — a leak
// check in the test asserts that.
type mullvadEmu struct {
	mu      sync.Mutex
	account string
	devices map[string]string // device id -> pubkey
	bodies  []string          // every request body seen (for leak inspection)
}

func (e *mullvadEmu) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// auth: exchange account number for a token.
		if r.Method == http.MethodPost && r.URL.Path == "/auth/v1/token" {
			var in struct {
				AccountNumber string `json:"account_number"`
			}
			json.NewDecoder(r.Body).Decode(&in)
			if in.AccountNumber != e.account {
				http.Error(w, "bad account", http.StatusUnauthorized)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"access_token": "tok-" + in.AccountNumber})
			return
		}
		// everything else needs Bearer tok-<account>.
		if r.Header.Get("Authorization") != "Bearer tok-"+e.account {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/accounts/v1/devices":
			var in struct {
				Pubkey string `json:"pubkey"`
			}
			raw, _ := io.ReadAll(r.Body)
			body := string(raw)
			e.mu.Lock()
			e.bodies = append(e.bodies, body)
			json.Unmarshal(raw, &in)
			id := "dev-new"
			e.devices[id] = in.Pubkey
			e.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"id": id, "pubkey": in.Pubkey})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/accounts/v1/devices/"):
			id := strings.TrimPrefix(r.URL.Path, "/accounts/v1/devices/")
			e.mu.Lock()
			pub, ok := e.devices[id]
			e.mu.Unlock()
			if !ok {
				http.Error(w, "no device", http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"pubkey": pub})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/accounts/v1/devices/"):
			id := strings.TrimPrefix(r.URL.Path, "/accounts/v1/devices/")
			e.mu.Lock()
			_, ok := e.devices[id]
			delete(e.devices, id)
			e.mu.Unlock()
			if !ok {
				http.Error(w, "no device", http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}
}

func TestMullvadDetect(t *testing.T) {
	m := &Mullvad{}
	if !m.Detect(discover.Credential{Source: "mullvad"}) {
		t.Error("should detect Source=mullvad")
	}
	if m.Detect(discover.Credential{Source: "wireguard"}) {
		t.Error("should not detect Source=wireguard")
	}
}

func TestMullvadRotateRealCutover(t *testing.T) {
	const account = "1234567890123456"
	oldPriv, oldPub, err := genWGKey()
	if err != nil {
		t.Fatal(err)
	}
	oldPrivB64 := base64.StdEncoding.EncodeToString(oldPriv)

	emu := &mullvadEmu{account: account, devices: map[string]string{"dev-old": oldPub}}
	srv := httptest.NewTLSServer(emu.handler())
	defer srv.Close()

	// Seed the credential pointing at the TLS test server (https scheme), carrying
	// the old device + old private key.
	su, _ := url.Parse(srv.URL)
	su.User = url.User(account)
	su.Path = "/"
	q := url.Values{}
	q.Set("device", "dev-old")
	q.Set("privkey", oldPrivB64)
	su.RawQuery = q.Encode()

	m := &Mullvad{HTTPClient: srv.Client()}
	v := vault.New()
	defer v.Purge()
	cred := discover.Credential{Source: "mullvad", Identity: "mullvad-device", Secret: v.Store([]byte(su.String()))}
	ctx := context.Background()

	newH, err := m.Rotate(ctx, cred, v)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	nb, err := v.Open(newH)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(nb.Bytes()), "dev-old") {
		t.Error("new credential should point at the new device, not dev-old")
	}

	if err := m.Verify(ctx, newH, v); err != nil {
		t.Errorf("Verify(new) should pass: %v", err)
	}

	// Leak checks: the API only ever saw PUBLIC keys; the old private key must not
	// appear in any request body nor in any stored device pubkey.
	for _, body := range emu.bodies {
		if strings.Contains(body, oldPrivB64) {
			t.Error("a private key leaked into a request body")
		}
	}
	for _, pub := range emu.devices {
		if pub == oldPrivB64 {
			t.Error("a private key was stored as a device pubkey")
		}
	}

	// Cutover: revoke the OLD device, then Verify against the old credential must
	// fail (its device is gone).
	if err := m.RevokeOld(ctx, cred, v); err != nil {
		t.Fatalf("RevokeOld: %v", err)
	}
	if err := m.Verify(ctx, cred.Secret, v); err == nil {
		t.Error("Verify(old) must fail after RevokeOld — old device should be deleted")
	} else if strings.Contains(err.Error(), oldPrivB64) || strings.Contains(err.Error(), account) {
		t.Error("error leaked the account number or private key")
	}
}

func TestMullvadRejectsBadSecret(t *testing.T) {
	m := &Mullvad{HTTPClient: http.DefaultClient}
	v := vault.New()
	defer v.Purge()
	cred := discover.Credential{Source: "mullvad", Secret: v.Store([]byte("mullvad://acct@api/?device=d"))} // no privkey
	if _, err := m.Rotate(context.Background(), cred, v); err == nil {
		t.Error("Rotate should reject a secret with no privkey")
	}
}
