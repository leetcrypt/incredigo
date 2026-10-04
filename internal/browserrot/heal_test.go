package browserrot

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"incredigo/internal/pwgen"
	"incredigo/internal/rotate"
	"incredigo/internal/vault"
)

// healingFake is a browser-free Session+Healer: it FAILS any fill/click/text whose
// selector is not in `good`, and its Heal maps a field description to the correct
// selector — modeling a recipe whose selectors have rotted and a Tier-2 heal fixing them.
// It records every Heal description so a test can prove no secret is ever passed to heal.
type healingFake struct {
	mu        sync.Mutex
	good      map[string]bool // selectors that "exist" on the page
	healMap   map[string]string
	healSeen  []string // descriptions passed to Heal (never a secret, by contract)
	healCalls int
	secrets   [][]byte // secret bytes handed to Fill (for leak assertions)
	success   string
}

func (h *healingFake) Name() string { return "healing-fake" }
func (h *healingFake) Open(context.Context) (Session, error) {
	return h, nil
}
func (h *healingFake) Goto(context.Context, string) (string, error) { return "about:blank", nil }
func (h *healingFake) Fill(_ context.Context, sel string, secret []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.good[sel] {
		return fmt.Errorf("healing-fake: no element for %q", sel)
	}
	h.secrets = append(h.secrets, append([]byte(nil), secret...))
	return nil
}
func (h *healingFake) Click(_ context.Context, sel string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.good[sel] {
		return fmt.Errorf("healing-fake: no element for %q", sel)
	}
	return nil
}
func (h *healingFake) Text(_ context.Context, sel string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.good[sel] {
		return "", fmt.Errorf("healing-fake: no element for %q", sel)
	}
	return h.success, nil
}
func (h *healingFake) Close() error { return nil }

func (h *healingFake) Heal(_ context.Context, description string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.healCalls++
	h.healSeen = append(h.healSeen, description)
	for kw, sel := range h.healMap {
		if strings.Contains(description, kw) {
			return sel, nil
		}
	}
	return "", fmt.Errorf("healing-fake: cannot heal %q", description)
}

var _ Healer = (*healingFake)(nil)

// The engine must: (1) heal a missed selector via Tier-2, (2) rewrite the recipe in
// memory, (3) never pass a secret to Heal. Then the healed recipe must PERSIST so a
// second run needs NO heal (Tier-1 again) — the whole "learn once" loop.
func TestHeal_engineRetriesRewritesAndPersists(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	const oldPW = "OLD-corr3ct-horse"
	c := gitHubPAT(t, v, oldPW)

	// Recipe with a ROTTED current-password selector; every other selector is correct.
	site := Site{
		Host: "github.com",
		Form: Form{
			CurrentSel: "#stale-current", NewSel: "#new", ConfirmSel: "#confirm",
			SubmitSel: "#submit", SuccessSel: "#result", SuccessText: "SUCCESS",
		},
		Proof: rotate.ProofMockOnly,
	}
	fake := &healingFake{
		good: map[string]bool{
			"#current": true, "#new": true, "#confirm": true, "#submit": true, "#result": true,
		},
		healMap: map[string]string{"current password": "#current"},
		success: "SUCCESS",
	}

	r := New(site, fake, pwgen.DefaultPolicy())
	newH, err := r.Rotate(context.Background(), c, v)
	if err != nil {
		t.Fatalf("Rotate with heal: %v", err)
	}
	if !r.Healed() {
		t.Fatal("expected Healed() == true after a selector miss was healed")
	}
	if got := r.HealedSite().Form.CurrentSel; got != "#current" {
		t.Fatalf("healed recipe CurrentSel = %q, want #current", got)
	}
	if fake.healCalls != 1 {
		t.Fatalf("expected exactly 1 heal call, got %d", fake.healCalls)
	}
	// Leak check: no description handed to Heal may contain either secret.
	newPW := mustReveal(t, v, newH)
	for _, d := range fake.healSeen {
		if strings.Contains(d, oldPW) || strings.Contains(d, newPW) {
			t.Fatalf("LEAK: a secret reached a heal description: %q", d)
		}
	}
	v.Forget(newH)

	// Persist the healed recipe, reload it, and run again with a FRESH healing fake whose
	// heal would fail — proving the second run is Tier-1 (no heal needed).
	path := filepath.Join(t.TempDir(), "recipes.json")
	rb := &RecipeBook{Sites: map[string]Site{}}
	rb.Put(r.HealedSite())
	if err := rb.Save(path); err != nil {
		t.Fatalf("Save recipes: %v", err)
	}
	rb2, err := LoadRecipes(path)
	if err != nil {
		t.Fatalf("Load recipes: %v", err)
	}
	learned, ok := rb2.Get("github.com")
	if !ok {
		t.Fatal("healed recipe not found after reload")
	}
	if learned.Form.CurrentSel != "#current" {
		t.Fatalf("persisted CurrentSel = %q, want #current", learned.Form.CurrentSel)
	}

	fake2 := &healingFake{
		good: map[string]bool{
			"#current": true, "#new": true, "#confirm": true, "#submit": true, "#result": true,
		},
		healMap: map[string]string{}, // heal would FAIL if called
		success: "SUCCESS",
	}
	c2 := gitHubPAT(t, v, oldPW)
	r2 := New(learned, fake2, pwgen.DefaultPolicy())
	newH2, err := r2.Rotate(context.Background(), c2, v)
	if err != nil {
		t.Fatalf("second run (should be Tier-1) failed: %v", err)
	}
	if r2.Healed() {
		t.Fatal("second run should NOT heal — the recipe was already learned")
	}
	if fake2.healCalls != 0 {
		t.Fatalf("second run must need 0 heals, got %d", fake2.healCalls)
	}
	v.Forget(newH2)
}

// If a selector misses and the Session cannot heal (no Healer), the engine fails closed.
func TestHeal_failsClosedWithoutHealer(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	c := gitHubPAT(t, v, "OLD")
	site := testSite()
	site.Form.CurrentSel = "#missing"
	// plain fakeDriver does NOT implement Healer, and its Fill never errors — so to force
	// the miss we use a driver whose Fill fails on the missing selector.
	drv := &fakeDriver{success: "SUCCESS", failFill: "#missing"}
	r := New(site, drv, pwgen.DefaultPolicy())
	if _, err := r.Rotate(context.Background(), c, v); err == nil {
		t.Fatal("expected fail-closed when a selector misses and no healer exists")
	} else if !strings.Contains(err.Error(), "cannot self-heal") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestHeal_healerErrorsFailsClosed covers the OTHER fail-closed branch: a Healer
// IS present but cannot relocate the field (Heal itself errors). The engine must
// fail closed and leave the credential unchanged, same as having no Healer at all.
func TestHeal_healerErrorsFailsClosed(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	const oldPW = "OLD-corr3ct-horse"
	c := gitHubPAT(t, v, oldPW)

	site := Site{
		Host: "github.com",
		Form: Form{
			CurrentSel: "#stale-current", NewSel: "#new", ConfirmSel: "#confirm",
			SubmitSel: "#submit", SuccessSel: "#result", SuccessText: "SUCCESS",
		},
		Proof: rotate.ProofMockOnly,
	}
	fake := &healingFake{
		good:    map[string]bool{"#new": true, "#confirm": true, "#submit": true, "#result": true},
		healMap: map[string]string{}, // no keyword matches -> Heal always errors
		success: "SUCCESS",
	}

	r := New(site, fake, pwgen.DefaultPolicy())
	newH, err := r.Rotate(context.Background(), c, v)
	if err == nil {
		t.Fatal("expected fail-closed when the Healer cannot relocate the field")
	} else if !strings.Contains(err.Error(), "heal") || !strings.Contains(err.Error(), "failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if newH != nil {
		t.Fatalf("failed heal must not return a handle, got %v", newH)
	}
	buf, err := v.Open(c.Secret)
	if err != nil {
		t.Fatalf("old secret handle no longer opens: %v", err)
	}
	if string(buf.Bytes()) != oldPW {
		t.Fatalf("old secret changed: got %q, want unchanged %q", string(buf.Bytes()), oldPW)
	}
}

func TestRecipes_roundTripAndMissingFile(t *testing.T) {
	// Missing file -> empty book, no error.
	rb, err := LoadRecipes(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if len(rb.Sites) != 0 {
		t.Fatalf("missing file should yield empty book, got %d", len(rb.Sites))
	}

	path := filepath.Join(t.TempDir(), "r.json")
	rb.Put(Site{Host: "a.com", Form: Form{CurrentSel: "#c"}, Proof: rotate.ProofLiveVM})
	rb.Put(Site{Host: "b.com", Form: Form{NewSel: "#n"}})
	if err := rb.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := LoadRecipes(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got.Sites) != 2 {
		t.Fatalf("want 2 recipes, got %d", len(got.Sites))
	}
	if s, _ := got.Get("a.com"); s.Form.CurrentSel != "#c" || s.Proof != rotate.ProofLiveVM {
		t.Fatalf("round-trip lost data for a.com: %+v", s)
	}
}

// mustReveal reads a handle's plaintext for a test-only leak assertion.
func mustReveal(t *testing.T, v *vault.Vault, h *vault.Handle) string {
	t.Helper()
	buf, err := v.Open(h)
	if err != nil {
		t.Fatalf("open handle: %v", err)
	}
	return string(buf.Bytes())
}
