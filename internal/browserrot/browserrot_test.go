package browserrot

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"incredigo/internal/discover"
	"incredigo/internal/links"
	"incredigo/internal/pwgen"
	"incredigo/internal/rotate"
	"incredigo/internal/vault"
)

// assertSecretUnchanged is the fail-safe assertion: after a failed Rotate/RevokeOld,
// the credential's ORIGINAL vault entry must still open to exactly `want` — the spine
// never committed a partial/unverified change.
func assertSecretUnchanged(t *testing.T, v *vault.Vault, c discover.Credential, want string) {
	t.Helper()
	buf, err := v.Open(c.Secret)
	if err != nil {
		t.Fatalf("old secret handle no longer opens: %v", err)
	}
	if string(buf.Bytes()) != want {
		t.Fatalf("old secret changed: got %q, want unchanged %q", string(buf.Bytes()), want)
	}
}

// erroringDriver always fails to open a session — models a browser launch failure
// (e.g. Chromium missing/crashed) so Rotate/Verify's fail-safe path can be exercised
// without a real browser.
type erroringDriver struct{ err error }

func (d *erroringDriver) Name() string                          { return "erroring" }
func (d *erroringDriver) Open(context.Context) (Session, error) { return nil, d.err }

// ---- fake Driver: records the SEQUENCE of ops and the field LENGTHS, never the
// secret bytes, so tests can assert order + leak-freedom without a browser. -------

type fakeOp struct {
	kind string // "goto" | "fill" | "click" | "text"
	arg  string // url / selector
	n    int    // secret length for fill (never the value)
}

type fakeSession struct {
	mu       *sync.Mutex
	ops      *[]fakeOp
	seen     *[]byte // every secret byte the driver was handed (for leak assertions)
	fields   map[string]string
	success  string // text returned by Text()
	failFill string // selector to error on, if any
}

func (s *fakeSession) Goto(_ context.Context, url string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	*s.ops = append(*s.ops, fakeOp{kind: "goto", arg: url})
	return url, nil
}
func (s *fakeSession) Fill(_ context.Context, sel string, secret []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sel == s.failFill {
		return fmt.Errorf("fake: forced fill error on %s", sel)
	}
	*s.ops = append(*s.ops, fakeOp{kind: "fill", arg: sel, n: len(secret)})
	*s.seen = append(*s.seen, secret...)
	s.fields[sel] = string(secret) // the fake may look; the PRODUCTION path may not
	return nil
}
func (s *fakeSession) Click(_ context.Context, sel string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	*s.ops = append(*s.ops, fakeOp{kind: "click", arg: sel})
	return nil
}
func (s *fakeSession) Text(_ context.Context, sel string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	*s.ops = append(*s.ops, fakeOp{kind: "text", arg: sel})
	return s.success, nil
}
func (s *fakeSession) Close() error { return nil }

type fakeDriver struct {
	mu       sync.Mutex
	ops      []fakeOp
	seen     []byte
	success  string
	failFill string
	fields   map[string]string
}

func (d *fakeDriver) Name() string { return "fake" }
func (d *fakeDriver) Open(context.Context) (Session, error) {
	if d.fields == nil {
		d.fields = map[string]string{}
	}
	return &fakeSession{
		mu: &d.mu, ops: &d.ops, seen: &d.seen, fields: d.fields,
		success: d.success, failFill: d.failFill,
	}, nil
}

// gitHubPAT builds a credential whose derived host is github.com (via the service
// hint), matching a Site{Host: "github.com"}.
func gitHubPAT(t *testing.T, v *vault.Vault, secret string) discover.Credential {
	t.Helper()
	return discover.Credential{
		Source:   "env",
		Identity: ".env / GITHUB_TOKEN",
		Location: "imported/env/GITHUB_TOKEN",
		Secret:   v.Store([]byte(secret)),
		Meta:     map[string]string{discover.MetaService: "github", "username": "octocat"},
	}
}

func testSite() Site {
	return Site{
		Host: "github.com",
		Form: Form{
			CurrentSel: "#current", NewSel: "#new", ConfirmSel: "#confirm",
			SubmitSel: "#submit", SuccessSel: "#result", SuccessText: "SUCCESS",
		},
		Proof: rotate.ProofMockOnly,
	}
}

func TestRotate_spineOrderAndNoLeak(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	const oldPW = "OLD-corr3ct-horse"
	c := gitHubPAT(t, v, oldPW)

	drv := &fakeDriver{success: "SUCCESS"}
	r := New(testSite(), drv, pwgen.DefaultPolicy())

	newH, err := r.Rotate(context.Background(), c, v)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// Ops must be: goto → fill current → fill new → fill confirm → click → text.
	want := []string{"goto:https://github.com/settings/tokens", "fill:#current", "fill:#new", "fill:#confirm", "click:#submit", "text:#result"}
	var got []string
	for _, o := range drv.ops {
		got = append(got, o.kind+":"+o.arg)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("op order:\n got %v\nwant %v", got, want)
	}

	// The old secret was injected into #current; a fresh (different) secret into #new.
	if drv.fields["#current"] != oldPW {
		t.Fatalf("current field got %q, want old password", drv.fields["#current"])
	}
	if drv.fields["#new"] == oldPW || drv.fields["#new"] == "" {
		t.Fatalf("new field must be a freshly minted, non-empty, different secret")
	}
	if drv.fields["#new"] != drv.fields["#confirm"] {
		t.Fatalf("confirm must equal new")
	}

	// Leak check: the OLD secret must never appear anywhere except as the value we
	// deliberately handed to #current — assert it is not in an unexpected field, and
	// that the Rotator's Name()/error surface never carries a secret.
	if strings.Contains(r.Name(), oldPW) || strings.Contains(r.Name(), drv.fields["#new"]) {
		t.Fatalf("driver name leaked a secret: %q", r.Name())
	}
	v.Forget(newH)
}

func TestRotate_failWhenSiteRejects(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	const oldPW = "OLD"
	c := gitHubPAT(t, v, oldPW)

	drv := &fakeDriver{success: "REJECTED: wrong current password"}
	r := New(testSite(), drv, pwgen.DefaultPolicy())

	newH, err := r.Rotate(context.Background(), c, v)
	if err == nil {
		t.Fatal("expected Rotate to fail when the site does not confirm success")
	} else if !strings.Contains(err.Error(), "did not confirm") {
		t.Fatalf("unexpected error: %v", err)
	}
	// Fail-safe: a failed submit must leave the credential UNCHANGED — no handle
	// returned, and the original vault entry still holds the old value.
	if newH != nil {
		t.Fatalf("failed Rotate must not return a usable handle, got %v", newH)
	}
	assertSecretUnchanged(t, v, c, oldPW)
}

// TestRotate_failSafe_loginBeforeChangeFailure covers the fail-safe path one step
// EARLIER than a submit rejection: when LoginBeforeChange cannot even clear the
// pre-change login wall (wrong old secret / MFA), Rotate must fail before ever
// minting or filling a new secret, and the old credential must be untouched.
func TestRotate_failSafe_loginBeforeChangeFailure(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	const oldPW = "OLD-pw"
	c := gitHubPAT(t, v, oldPW)

	site := testSite()
	site.LoginBeforeChange = true
	site.Login = Login{
		URL: "https://github.com/login", UserSel: "#u", PassSel: "#p",
		SubmitSel: "#go", SuccessSel: "#welcome", SuccessText: "SUCCESS",
	}
	drv := &fakeDriver{success: "DENIED"} // never matches the Login.SuccessText
	r := New(site, drv, pwgen.DefaultPolicy())

	newH, err := r.Rotate(context.Background(), c, v)
	if err == nil {
		t.Fatal("expected Rotate to fail when the pre-change login does not succeed")
	} else if !strings.Contains(err.Error(), "pre-change login did not succeed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if newH != nil {
		t.Fatalf("failed pre-change login must not return a handle, got %v", newH)
	}
	assertSecretUnchanged(t, v, c, oldPW)
	// Must never reach the change page at all — only the login goto should appear.
	for _, o := range drv.ops {
		if o.kind == "goto" && o.arg != site.Login.URL {
			t.Fatalf("must not navigate past a failed pre-change login, got goto %q", o.arg)
		}
	}
}

// TestRotate_driverOpenFails covers a browser-launch failure (Chromium missing/
// crashed): Rotate must fail cleanly and leave the credential untouched.
func TestRotate_driverOpenFails(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	const oldPW = "OLD"
	c := gitHubPAT(t, v, oldPW)

	drv := &erroringDriver{err: errors.New("chromium: exec failed")}
	r := New(testSite(), drv, pwgen.DefaultPolicy())

	newH, err := r.Rotate(context.Background(), c, v)
	if err == nil {
		t.Fatal("expected Rotate to fail when the driver cannot open a session")
	} else if !strings.Contains(err.Error(), "open browser") {
		t.Fatalf("unexpected error: %v", err)
	}
	if newH != nil {
		t.Fatalf("failed Rotate must not return a handle, got %v", newH)
	}
	assertSecretUnchanged(t, v, c, oldPW)
}

// TestRotate_missingChangeURL covers a Site with neither a curated ChangeURL nor a
// derivable Host: Rotate must refuse up front rather than navigate anywhere.
func TestRotate_missingChangeURL(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	const oldPW = "OLD"
	c := gitHubPAT(t, v, oldPW)

	site := Site{Host: "", Form: testSite().Form} // no Host, no ChangeURL override
	drv := &fakeDriver{success: "SUCCESS"}
	r := New(site, drv, pwgen.DefaultPolicy())

	newH, err := r.Rotate(context.Background(), c, v)
	if err == nil {
		t.Fatal("expected Rotate to fail when no change-password URL can be derived")
	} else if !strings.Contains(err.Error(), "no change-password URL") {
		t.Fatalf("unexpected error: %v", err)
	}
	if newH != nil {
		t.Fatalf("failed Rotate must not return a handle, got %v", newH)
	}
	if len(drv.ops) != 0 {
		t.Fatalf("must not perform any browser ops without a change URL, got %v", drv.ops)
	}
	assertSecretUnchanged(t, v, c, oldPW)
}

// TestRevokeOld_isNoop documents the intentional contract: website rotation never
// controls old/new ordering at the site, so RevokeOld always succeeds and never
// touches the credential.
func TestRevokeOld_isNoop(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	const oldPW = "OLD"
	c := gitHubPAT(t, v, oldPW)
	r := New(testSite(), &fakeDriver{}, pwgen.DefaultPolicy())

	if err := r.RevokeOld(context.Background(), c, v); err != nil {
		t.Fatalf("RevokeOld must always succeed, got %v", err)
	}
	assertSecretUnchanged(t, v, c, oldPW)
}

// TestDetect covers both the match and no-match paths, including the explicit
// guard against an empty Site.Host matching an equally-empty derived host.
func TestDetect(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	r := New(testSite(), &fakeDriver{}, pwgen.DefaultPolicy())

	match := gitHubPAT(t, v, "x")
	if !r.Detect(match) {
		t.Fatal("Detect should match a credential whose derived host equals the site host")
	}

	other := discover.Credential{
		Source: "env", Identity: ".env / STRIPE_KEY", Location: "imported/env/STRIPE_KEY",
		Secret: v.Store([]byte("y")),
		Meta:   map[string]string{discover.MetaService: "stripe"}, // derives stripe.com
	}
	if r.Detect(other) {
		t.Fatal("Detect should not match a credential for a different host")
	}

	unhosted := New(Site{Host: ""}, &fakeDriver{}, pwgen.DefaultPolicy())
	if unhosted.Detect(match) {
		t.Fatal("Detect must reject an empty Site.Host even if it equals the derived host")
	}
}

func TestVerify_refusesWithoutLoginFlow(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	drv := &fakeDriver{success: "SUCCESS"}
	r := New(testSite(), drv, pwgen.DefaultPolicy()) // Site has no Login flow
	h := v.Store([]byte("whatever"))
	if err := r.Verify(context.Background(), h, v); err == nil {
		t.Fatal("Verify must REFUSE when the site has no browser verify path (hard rule 2)")
	}
}

func TestVerify_loginFlowAuthenticates(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	site := testSite()
	site.Login = Login{
		URL: "https://github.com/login", UserSel: "#u", PassSel: "#p",
		SubmitSel: "#go", SuccessSel: "#welcome", SuccessText: "SUCCESS",
	}
	drv := &fakeDriver{success: "SUCCESS"}
	r := New(site, drv, pwgen.DefaultPolicy())
	r.username = "octocat"
	if err := r.Verify(context.Background(), v.Store([]byte("newpw")), v); err != nil {
		t.Fatalf("Verify should pass when login succeeds: %v", err)
	}
}

// TestVerify_failsWhenNewDoesNotAuthenticate covers the branch that must trigger
// when a site accepted the change but the new secret still can't log back in
// (proof of the "verify new before revoke old" hard rule).
func TestVerify_failsWhenNewDoesNotAuthenticate(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	site := testSite()
	site.Login = Login{
		URL: "https://github.com/login", UserSel: "#u", PassSel: "#p",
		SubmitSel: "#go", SuccessSel: "#welcome", SuccessText: "SUCCESS",
	}
	drv := &fakeDriver{success: "DENIED"}
	r := New(site, drv, pwgen.DefaultPolicy())
	r.username = "octocat"

	h := v.Store([]byte("newpw"))
	if err := r.Verify(context.Background(), h, v); err == nil {
		t.Fatal("Verify must fail when the new password does not authenticate")
	} else if !strings.Contains(err.Error(), "did NOT authenticate") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// The Rotator must satisfy the shared contract AND flow through the proof gate: a
// MOCK-ONLY site is skipped by Execute unless the operator opts in.
func TestProofGate_mockOnlySkippedByDefault(t *testing.T) {
	r := New(testSite(), &fakeDriver{}, pwgen.DefaultPolicy())
	if got := r.Proof(); got != rotate.ProofMockOnly {
		t.Fatalf("proof: got %v want MOCK-ONLY", got)
	}
	if r.Proof() >= rotate.MinExecuteProof {
		t.Fatal("a MOCK-ONLY browser site must be below the execute gate")
	}
}

// ---- LIVE-VM integration: real Chromium against a real local form. -------------
// Skipped unless CHROME_BIN points at a usable Chromium (set by lab-provision-browserrot.sh).

func TestIntegration_realBrowserRotation(t *testing.T) {
	bin := os.Getenv("CHROME_BIN")
	if bin == "" {
		t.Skip("set CHROME_BIN to a Chromium executable to run the LIVE-VM browser proof")
	}
	runLiveRotationProof(t, &RodDriver{Bin: bin, Headless: true, Timeout: 30 * time.Second})
}

// runLiveRotationProof drives one Driver through the full LIVE-VM proof: it stands up a
// throwaway change-password + login website in-process, then asserts
// discover→inject→submit→verify(new)→old-rejected. Both the go-rod and node-sidecar
// drivers run this identical harness, so "parity" is a literal shared test. Optional
// mutators tweak the Site before the run (e.g. to rot a selector for a self-heal proof).
// It returns the Rotator so callers can assert post-run state (Healed(), HealedSite()).
func runLiveRotationProof(t *testing.T, drv Driver, mutators ...func(*Site)) *Rotator {
	t.Helper()

	const oldPW = "OLD-corr3ct-horse-battery"
	var mu sync.Mutex
	stored := oldPW
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/change-password", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/account/security/password", http.StatusSeeOther)
	})
	mux.HandleFunc("/account/security/password", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.ParseForm()
			mu.Lock()
			ok := r.FormValue("current") == stored
			if ok {
				stored = r.FormValue("new")
			}
			mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, `<h1 id="result">REJECTED</h1>`)
				return
			}
			fmt.Fprint(w, `<h1 id="result">SUCCESS</h1>`)
			return
		}
		fmt.Fprint(w, `<!doctype html><meta charset=utf-8><form method=POST>
		  <input id=current name=current type=password>
		  <input id=new name=new type=password>
		  <button id=submit type=submit>Change</button></form>`)
	})
	// login-verify endpoint
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.ParseForm()
			mu.Lock()
			ok := r.FormValue("p") == stored
			mu.Unlock()
			if ok {
				fmt.Fprint(w, `<h1 id="welcome">SUCCESS</h1>`)
			} else {
				fmt.Fprint(w, `<h1 id="welcome">DENIED</h1>`)
			}
			return
		}
		fmt.Fprint(w, `<!doctype html><meta charset=utf-8><form method=POST>
		  <input id=p name=p type=password><button id=go type=submit>Login</button></form>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://") // 127.0.0.1:PORT

	site := Site{
		Host:      host,
		ChangeURL: srv.URL + "/.well-known/change-password", // exercise RFC 8615 redirect
		Form: Form{
			CurrentSel: "#current", NewSel: "#new",
			SubmitSel: "#submit", SuccessSel: "#result", SuccessText: "SUCCESS",
		},
		Login: Login{
			URL: srv.URL + "/login", PassSel: "#p", SubmitSel: "#go",
			SuccessSel: "#welcome", SuccessText: "SUCCESS",
		},
		Proof: rotate.ProofLiveVM,
	}
	for _, m := range mutators {
		m(&site)
	}

	v := vault.New()
	defer v.Purge()
	c := discover.Credential{
		Source: "file", Identity: host + " / cred", Location: "imported/file/x",
		Secret: v.Store([]byte(oldPW)),
		// host has no curated entry, so links.For falls back to well-known on this host.
		Meta: map[string]string{},
	}
	// Point HostFor at our ephemeral host via the git-style "user @ host" identity.
	c.Identity = "acct @ " + host

	r := New(site, drv, pwgen.DefaultPolicy())

	if !r.Detect(c) {
		t.Fatalf("Detect should match host %q (HostFor=%q)", host, hostForDebug(c))
	}

	ctx := context.Background()
	newH, err := r.Rotate(ctx, c, v)
	if err != nil {
		t.Fatalf("Rotate against real browser: %v", err)
	}
	if err := r.Verify(ctx, newH, v); err != nil {
		t.Fatalf("Verify (new pw must authenticate): %v", err)
	}
	// old must no longer authenticate — prove the rotation was real, not a no-op.
	mu.Lock()
	oldStillWorks := stored == oldPW
	mu.Unlock()
	if oldStillWorks {
		t.Fatal("old password still stored — rotation did not take effect")
	}
	if err := r.RevokeOld(ctx, c, v); err != nil {
		t.Fatalf("RevokeOld: %v", err)
	}
	t.Log("LIVE-VM browser rotation proof passed: discover→inject→submit→verify(new)→old-rejected")
	return r
}

func hostForDebug(c discover.Credential) string { return links.HostFor(c) }

func TestGiteaSite_recipeShape(t *testing.T) {
	s := GiteaSite("https://gitea.example.com/", "trilltechnician")
	if s.Host != "gitea.example.com" {
		t.Fatalf("host: got %q", s.Host)
	}
	if s.ChangeURL != "https://gitea.example.com/user/settings/account" {
		t.Fatalf("changeURL: got %q", s.ChangeURL)
	}
	if !s.LoginBeforeChange {
		t.Fatal("Gitea account page is auth-gated; LoginBeforeChange must be true")
	}
	if s.Login.URL == "" || s.Form.CurrentSel == "" || s.Form.NewSel == "" || s.Form.SubmitSel == "" {
		t.Fatalf("recipe has empty required selectors: %+v", s)
	}
	// Promoted to LIVE-REAL: the recipe drove a real self-owned Gitea password
	// rotation on 2026-07-21 (lab/rung4-gitea-browser, M-B4). Proof-as-data.
	if s.Proof != rotate.ProofLiveReal {
		t.Fatalf("GiteaSite recipe should be ProofLiveReal after the M-B4 live-fire, got %v", s.Proof)
	}
}

// TestIntegration_loginBeforeChangeRotation proves the Site.LoginBeforeChange path against
// a real Chromium: the change page is reachable ONLY inside an authenticated session (a
// Gitea-style cookie gate — 302 → /login when unauthenticated). Rotate must log in with the
// OLD secret first, carry the cookie into the change page, rotate, and then Verify re-logs-in
// with the NEW secret. This is the engine change M-B4 needs for real account-settings pages.
func TestIntegration_loginBeforeChangeRotation(t *testing.T) {
	bin := os.Getenv("CHROME_BIN")
	if bin == "" {
		t.Skip("set CHROME_BIN to a Chromium executable to run the LIVE-VM login-gated proof")
	}

	const oldPW = "OLD-corr3ct-horse-battery"
	const user = "trilltechnician"
	var mu sync.Mutex
	stored := oldPW
	const cookie = "sess=authok"

	authed := func(r *http.Request) bool {
		c, err := r.Cookie("sess")
		return err == nil && c.Value == "authok"
	}

	mux := http.NewServeMux()
	// /login: GET renders the form; POST checks the CURRENT stored password and, on
	// success, sets the session cookie (this is what gates the settings page).
	mux.HandleFunc("/user/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.ParseForm()
			mu.Lock()
			ok := r.FormValue("user_name") == user && r.FormValue("password") == stored
			mu.Unlock()
			if ok {
				http.SetCookie(w, &http.Cookie{Name: "sess", Value: "authok", Path: "/"})
				fmt.Fprint(w, `<h1 id="dash">Dashboard SUCCESS</h1>`)
				return
			}
			fmt.Fprint(w, `<h1 id="dash">DENIED</h1>`)
			return
		}
		fmt.Fprint(w, `<!doctype html><meta charset=utf-8><form method=POST>
		  <input id=user_name name=user_name>
		  <input id=password name=password type=password>
		  <button id=signin type=submit>Sign In</button></form>`)
	})
	// /user/settings/account: the change-password page, gated behind the cookie.
	mux.HandleFunc("/user/settings/account", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			http.Redirect(w, r, "/user/login", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost {
			r.ParseForm()
			mu.Lock()
			ok := r.FormValue("old_password") == stored
			if ok {
				stored = r.FormValue("password")
			}
			mu.Unlock()
			if !ok {
				fmt.Fprint(w, `<div id="flash">error: incorrect old password</div>`)
				return
			}
			fmt.Fprint(w, `<div id="flash">Your password has been updated.</div>`)
			return
		}
		fmt.Fprint(w, `<!doctype html><meta charset=utf-8><form method=POST>
		  <input id=old_password name=old_password type=password>
		  <input id=new_password name=password type=password>
		  <input id=retype name=retype type=password>
		  <button id=save type=submit>Update Password</button></form>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	site := Site{
		Host:      host,
		ChangeURL: srv.URL + "/user/settings/account",
		Form: Form{
			CurrentSel: "#old_password", NewSel: "#new_password", ConfirmSel: "#retype",
			SubmitSel: "#save", SuccessSel: "#flash", SuccessText: "has been updated",
		},
		Login: Login{
			URL: srv.URL + "/user/login", UserSel: "#user_name", PassSel: "#password",
			SubmitSel: "#signin", SuccessSel: "#dash", SuccessText: "SUCCESS",
		},
		LoginBeforeChange: true,
		Proof:             rotate.ProofLiveVM,
	}

	v := vault.New()
	defer v.Purge()
	c := discover.Credential{
		Source: "file", Identity: user + " @ " + host, Location: "imported/file/x",
		Secret: v.Store([]byte(oldPW)),
		Meta:   map[string]string{"username": user},
	}

	drv := &RodDriver{Bin: bin, Headless: true, Timeout: 30 * time.Second}
	r := New(site, drv, pwgen.DefaultPolicy())

	ctx := context.Background()
	newH, err := r.Rotate(ctx, c, v)
	if err != nil {
		t.Fatalf("Rotate (login-before-change): %v", err)
	}
	if err := r.Verify(ctx, newH, v); err != nil {
		t.Fatalf("Verify (new pw must authenticate): %v", err)
	}
	mu.Lock()
	oldStillWorks := stored == oldPW
	mu.Unlock()
	if oldStillWorks {
		t.Fatal("old password still stored — rotation did not take effect")
	}
	t.Log("LIVE-VM login-before-change proof passed: login(old)→settings→rotate→verify(new)→old-rejected")
}

// TestRotate_loginBeforeChangeOrder asserts (no browser) that LoginBeforeChange makes
// Rotate hit the login flow BEFORE the change page, using the fake driver's op log.
func TestRotate_loginBeforeChangeOrder(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	c := gitHubPAT(t, v, "OLD-pw")

	site := testSite()
	site.ChangeURL = "https://github.com/settings/password"
	site.Login = Login{
		URL: "https://github.com/login", UserSel: "#u", PassSel: "#p",
		SubmitSel: "#go", SuccessSel: "#welcome", SuccessText: "SUCCESS",
	}
	site.LoginBeforeChange = true

	drv := &fakeDriver{success: "SUCCESS"}
	r := New(site, drv, pwgen.DefaultPolicy())

	newH, err := r.Rotate(context.Background(), c, v)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	defer v.Forget(newH)

	// The first op must be the login goto, and the login submit must precede the change goto.
	var seq []string
	for _, o := range drv.ops {
		seq = append(seq, o.kind+":"+o.arg)
	}
	joined := strings.Join(seq, ",")
	loginGoto := "goto:https://github.com/login"
	changeGoto := "goto:https://github.com/settings/password"
	if seq[0] != loginGoto {
		t.Fatalf("first op must be the login goto, got %q (seq=%v)", seq[0], seq)
	}
	if strings.Index(joined, loginGoto) > strings.Index(joined, changeGoto) {
		t.Fatalf("login must precede change navigation: %v", seq)
	}
	// The OLD secret authenticates the pre-change login (fill #p before the change goto).
	if drv.fields["#p"] != "OLD-pw" {
		t.Fatalf("pre-change login must use the OLD secret, got %q", drv.fields["#p"])
	}
}
