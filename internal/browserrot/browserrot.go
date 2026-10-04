// Package browserrot is incredigo's Phase A-tier-1 site-side rotation engine: it
// drives a real browser to change a password AT A WEBSITE, then verifies the new
// password authenticates before the safe spine commits it (docs/BROWSER-ROTATION.md
// §9). It is the deterministic tier — NO language model is in this loop; a curated
// per-site selector table tells the harness exactly which fields to fill, and the
// harness injects the secret directly over CDP. The AI/vision fallback (Tier-2) is
// a separate future Driver, kept out of this deterministic path (CLAUDE.md rule).
//
// It plugs into the SAME safety spine as the API/DB rotation drivers: a Rotator
// here implements rotate.Rotator, so rotate.Snapshot (mandatory backup), the
// verify-new-before-revoke-old ordering in rotate.Execute, and the proof gate all
// apply unchanged. Website password change is inherently "verify then the site
// invalidates the old itself", so RevokeOld is a no-op (see below).
//
// SECURITY SEAMS (documented honestly, mirroring the pwstore argv caveats):
//   - A browser field is filled with a plaintext value. The vault hands out bytes;
//     the ONE unavoidable plaintext-as-string moment is at the CDP boundary inside
//     the Driver implementation (rod.go), localized there and never logged, never
//     written to disk, never sent to a model.
//   - MFA / CAPTCHA / confirmation-email are NEVER bypassed. A site that presents
//     one makes SuccessText not match, Rotate fails cleanly, and the old secret is
//     kept — the human is handed the change-URL by the existing worklist.
package browserrot

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"incredigo/internal/discover"
	"incredigo/internal/links"
	"incredigo/internal/pwgen"
	"incredigo/internal/rotate"
	"incredigo/internal/vault"
)

// Session drives one browser tab against one site. Secrets cross this interface as
// []byte and are converted to the browser's required string only inside the Driver
// implementation, so the core engine never holds a secret as a Go string. A Session
// MUST NOT log field values.
type Session interface {
	// Goto navigates to url (following redirects, e.g. RFC 8615
	// /.well-known/change-password → the real change page) and returns the final URL.
	Goto(ctx context.Context, url string) (finalURL string, err error)
	// Fill sets the value of the element matched by selector. secret is treated as
	// ephemeral and never logged.
	Fill(ctx context.Context, selector string, secret []byte) error
	// Click activates the element matched by selector.
	Click(ctx context.Context, selector string) error
	// Text waits for the element matched by selector to be present and returns its
	// visible text — used to read the site's success/error signal.
	Text(ctx context.Context, selector string) (string, error)
	// Close releases the tab/browser.
	Close() error
}

// Driver opens browser sessions. go-rod is the default (rod.go); playwright-go and
// a Tier-2 AI driver are swap-ins that satisfy the same interface.
type Driver interface {
	Name() string
	Open(ctx context.Context) (Session, error)
}

// Healer is the OPTIONAL Tier-2 capability a Session may implement: relocate a field the
// deterministic recipe could not find, by NATURAL-LANGUAGE description, and return a fresh
// selector. Note the signature — Heal takes only a description and returns a selector, so
// a secret CANNOT be passed to the healer (and thus never reaches a model). The engine
// calls Heal only when a Tier-1 selector misses, then re-persists the healed selector so
// the next run is deterministic again ("learn once"). A Session that does not implement
// Healer simply fails closed on a selector miss (Tier-1 only).
type Healer interface {
	Heal(ctx context.Context, description string) (selector string, err error)
}

// Form describes a site's change-password form: the CSS selectors to fill and the
// element whose text signals the outcome.
type Form struct {
	CurrentSel  string // selector for the "current password" field
	NewSel      string // selector for the "new password" field
	ConfirmSel  string // selector for a "confirm new password" field ("" if none)
	SubmitSel   string // selector for the submit control
	SuccessSel  string // selector for the element carrying the result text
	SuccessText string // substring in SuccessSel's text that means the change succeeded
}

// Login is an OPTIONAL re-login flow used to VERIFY the new password actually
// authenticates (hard rule 2). A zero Login (URL == "") disables browser verify —
// in that case Verify refuses, so the spine keeps the old value and flags the human
// rather than committing an unverified rotation.
type Login struct {
	URL         string
	UserSel     string // "" for a password-only verify form
	PassSel     string
	SubmitSel   string
	SuccessSel  string
	SuccessText string
}

// Site is one curated target: its host, the change form, an optional verify login,
// and how the ENGINE against this site has been validated (proof-as-data, mirroring
// rotate/proofs.go). A real provider's selector table stays ProofUnproven until it
// has actually been run against that real site; the local-form lab target is
// ProofLiveVM because a real browser + real HTTP form proved the mechanism.
type Site struct {
	Host string
	// ChangeURL overrides the derived change-password URL. Leave "" to use the
	// curated/well-known URL from internal/links (the normal path); set it for a
	// site whose change page is not derivable, or for a local-form proof.
	ChangeURL string
	Form      Form
	Login     Login
	// LoginBeforeChange makes Rotate authenticate through the Login flow (with the
	// OLD secret) BEFORE navigating to the change page. Real account settings pages
	// (Gitea /user/settings/account, most dashboards) are reachable only inside an
	// authenticated session; a directly-served change form (the lab target, or a
	// public reset link) does not need it. Requires a non-empty Login.
	LoginBeforeChange bool
	Proof             rotate.ProofLevel
}

// Rotator drives one Site. Unlike the stateless API drivers, a browser Rotator is
// created PER credential: Rotate records the account's username so the later Verify
// can re-login. Construct one with New.
type Rotator struct {
	site   Site
	drv    Driver
	policy pwgen.Policy

	username string // captured in Rotate, used by Verify's login (non-secret)
	healed   bool   // set true if a Tier-2 heal rewrote any selector this run

	// Post-submit result read: the submit usually navigates, so the result element may be
	// briefly unreachable while the next page loads. 0 means the defaults below.
	readAttempts int
	readBackoff  time.Duration
}

const (
	defaultReadAttempts = 10
	defaultReadBackoff  = 500 * time.Millisecond
)

// ErrOutcomeUnknown means the change form WAS submitted but the engine could not establish
// whether the site applied it: the result was unreadable and neither the new nor the old
// password could be proven by a login probe. Rotate then returns the NEW secret's handle
// TOGETHER with this error — the site may already accept only that password, so discarding
// it could lock the account. Callers MUST persist that handle somewhere that does not
// overwrite the old secret (e.g. "<path>.pending") and hand the human both.
var ErrOutcomeUnknown = errors.New("browserrot: change submitted but outcome unknown")

// New builds a Rotator for a Site backed by drv, minting new passwords with policy.
func New(site Site, drv Driver, policy pwgen.Policy) *Rotator {
	return &Rotator{site: site, drv: drv, policy: policy}
}

// Name identifies the driver in plans/audit: "browser:<host>".
func (r *Rotator) Name() string { return "browser:" + r.site.Host }

// Proof exposes this Site's validation level so callers can apply the same
// execute-time proof gate the API drivers use (rotate.MinExecuteProof).
func (r *Rotator) Proof() rotate.ProofLevel { return r.site.Proof }

// Detect reports whether this credential's derived web host matches the Site.
func (r *Rotator) Detect(c discover.Credential) bool {
	return links.HostFor(c) == r.site.Host && r.site.Host != ""
}

// Rotate opens the change-password page (via the curated/well-known URL), fills the
// OLD secret and a freshly minted NEW secret over CDP, submits, and confirms the
// site reported success. It returns the new secret's vault handle. It does NOT
// revoke the old credential (the Rotator contract) and does NOT touch disk.
//
// Once the submit has been clicked the site may have applied the change, so from that point
// the new secret is forgotten ONLY when the site definitely did not take it: the result was
// read and lacks the success marker, or a login probe shows the old password still works.
// Anything less certain returns (newH, ErrOutcomeUnknown) — see resolveOutcome.
func (r *Rotator) Rotate(ctx context.Context, c discover.Credential, v *vault.Vault) (*vault.Handle, error) {
	r.username = c.Meta["username"] // non-secret; "" is fine for password-only verify

	changeURL := r.site.ChangeURL
	if changeURL == "" {
		changeURL = links.For(r.site.Host).URL
	}
	if changeURL == "" {
		return nil, fmt.Errorf("browserrot: no change-password URL for %q", r.site.Host)
	}

	sess, err := r.drv.Open(ctx)
	if err != nil {
		return nil, fmt.Errorf("browserrot: open browser: %w", err)
	}
	defer sess.Close()

	// Sites whose change page lives behind auth (Gitea /user/settings/account, most
	// dashboards) must be logged in first, using the OLD secret. The same login flow
	// Verify uses; here the session's cookies then carry into the change-page fetch.
	if r.site.LoginBeforeChange {
		oldBuf, err := v.Open(c.Secret)
		if err != nil {
			return nil, fmt.Errorf("browserrot: open old secret (pre-change login): %w", err)
		}
		txt, err := r.login(ctx, sess, oldBuf.Bytes())
		if err != nil {
			return nil, fmt.Errorf("browserrot: pre-change login: %w", err)
		}
		if !strings.Contains(txt, r.site.Login.SuccessText) {
			// A login wall we could not clear with the old secret is also where MFA
			// would appear: the marker won't match. Keep the old secret, flag the human.
			return nil, fmt.Errorf("browserrot: pre-change login did not succeed (needs human / MFA?): got %q", strings.TrimSpace(txt))
		}
	}

	if _, err := sess.Goto(ctx, changeURL); err != nil {
		return nil, fmt.Errorf("browserrot: goto change page: %w", err)
	}

	// Mint the new secret in the vault BEFORE filling, so both old and new stay as
	// vault-backed bytes for the duration of the fills.
	newH, err := pwgen.Generate(v, r.policy)
	if err != nil {
		return nil, fmt.Errorf("browserrot: generate: %w", err)
	}

	if err := r.fillForm(ctx, sess, c.Secret, newH, v); err != nil {
		v.Forget(newH) // nothing submitted yet: never keep a new secret whose change did not land
		return nil, err
	}

	// SUBMIT — from here the site may have applied the change. A click error can be the reply
	// lost to the navigation the submit itself triggered, so it is ambiguous, not a failure.
	if err := r.click(ctx, sess, &r.site.Form.SubmitSel, "the submit / save-changes button"); err != nil {
		return r.resolveOutcome(ctx, c, newH, v, fmt.Errorf("browserrot: submit: %w", err))
	}
	txt, err := r.readResult(ctx, sess)
	if err != nil {
		return r.resolveOutcome(ctx, c, newH, v, fmt.Errorf("browserrot: read result: %w", err))
	}
	if !strings.Contains(txt, r.site.Form.SuccessText) {
		v.Forget(newH)
		// This is also the MFA/CAPTCHA/confirmation wall: the success marker simply
		// did not appear. We keep the old secret and let the human finish.
		return nil, fmt.Errorf("browserrot: site did not confirm change (needs human / MFA?): got %q", strings.TrimSpace(txt))
	}
	return newH, nil
}

// readResult reads the post-submit status element. The submit usually navigates, so the
// element (or, for the extension driver, the content script) can be briefly unreachable while
// the next page loads: retry the plain read with a short backoff before the heal path, which
// would otherwise misread a page load as a selector miss.
func (r *Rotator) readResult(ctx context.Context, sess Session) (string, error) {
	attempts, backoff := r.readAttempts, r.readBackoff
	if attempts <= 0 {
		attempts = defaultReadAttempts
	}
	if backoff <= 0 {
		backoff = defaultReadBackoff
	}
	for i := 1; i < attempts; i++ {
		if txt, err := sess.Text(ctx, r.site.Form.SuccessSel); err == nil {
			return txt, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(backoff):
		}
	}
	return r.text(ctx, sess, &r.site.Form.SuccessSel, "the success or error status message")
}

// resolveOutcome decides an ambiguous post-submit state without guessing. The new secret is
// forgotten ONLY when the old password is proven to still authenticate (the change did not
// land). If the new password authenticates, the change landed and Rotate succeeds. Otherwise
// the new handle is returned with ErrOutcomeUnknown so the caller can keep it.
func (r *Rotator) resolveOutcome(ctx context.Context, c discover.Credential, newH *vault.Handle, v *vault.Vault, cause error) (*vault.Handle, error) {
	if r.site.Login.URL == "" {
		return newH, fmt.Errorf("%w (no login flow to probe): %w", ErrOutcomeUnknown, cause)
	}
	if ok, _ := r.authenticates(ctx, newH, v); ok {
		return newH, nil
	}
	if ok, _ := r.authenticates(ctx, c.Secret, v); ok {
		v.Forget(newH)
		return nil, fmt.Errorf("browserrot: change did not land (old password still authenticates): %w", cause)
	}
	return newH, fmt.Errorf("%w (neither password could be proven by login): %w", ErrOutcomeUnknown, cause)
}

// fillForm injects the old + new secrets into the form fields. Both secrets are read
// straight from the vault as bytes and handed to the Driver; they are never copied
// into a Go string in this package. Each field goes through fill, which self-heals
// on a selector miss (Tier-2) and rewrites r.site.Form so the healed recipe can persist.
// It does NOT submit — Rotate clicks submit itself, because everything after the click is
// ambiguity-handled.
func (r *Rotator) fillForm(ctx context.Context, sess Session, oldH, newH *vault.Handle, v *vault.Vault) error {
	oldBuf, err := v.Open(oldH)
	if err != nil {
		return fmt.Errorf("browserrot: open old secret: %w", err)
	}
	if err := r.fill(ctx, sess, &r.site.Form.CurrentSel, "the current password input field", oldBuf.Bytes()); err != nil {
		return err
	}
	newBuf, err := v.Open(newH)
	if err != nil {
		return fmt.Errorf("browserrot: open new secret: %w", err)
	}
	if err := r.fill(ctx, sess, &r.site.Form.NewSel, "the new password input field", newBuf.Bytes()); err != nil {
		return err
	}
	if r.site.Form.ConfirmSel != "" {
		if err := r.fill(ctx, sess, &r.site.Form.ConfirmSel, "the confirm-new-password input field", newBuf.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

// fill sets *selPtr's field to secret; on a selector miss it asks the session's Healer
// (Tier-2) to relocate the field by desc, retries, and rewrites *selPtr in place so the
// healed recipe persists. The secret is never handed to the healer (see Healer).
func (r *Rotator) fill(ctx context.Context, sess Session, selPtr *string, desc string, secret []byte) error {
	if err := sess.Fill(ctx, *selPtr, secret); err == nil {
		return nil
	} else {
		newSel, herr := r.heal(ctx, sess, desc, err)
		if herr != nil {
			return herr
		}
		if err2 := sess.Fill(ctx, newSel, secret); err2 != nil {
			return fmt.Errorf("browserrot: fill %q after heal to %q: %w", desc, newSel, err2)
		}
		*selPtr = newSel
		r.healed = true
		return nil
	}
}

// click activates *selPtr; heals + rewrites on a miss, same contract as fill.
func (r *Rotator) click(ctx context.Context, sess Session, selPtr *string, desc string) error {
	if err := sess.Click(ctx, *selPtr); err == nil {
		return nil
	} else {
		newSel, herr := r.heal(ctx, sess, desc, err)
		if herr != nil {
			return herr
		}
		if err2 := sess.Click(ctx, newSel); err2 != nil {
			return fmt.Errorf("browserrot: click %q after heal to %q: %w", desc, newSel, err2)
		}
		*selPtr = newSel
		r.healed = true
		return nil
	}
}

// text reads *selPtr's visible text; heals + rewrites on a miss, same contract as fill.
func (r *Rotator) text(ctx context.Context, sess Session, selPtr *string, desc string) (string, error) {
	if txt, err := sess.Text(ctx, *selPtr); err == nil {
		return txt, nil
	} else {
		newSel, herr := r.heal(ctx, sess, desc, err)
		if herr != nil {
			return "", herr
		}
		txt2, err2 := sess.Text(ctx, newSel)
		if err2 != nil {
			return "", fmt.Errorf("browserrot: read %q after heal to %q: %w", desc, newSel, err2)
		}
		*selPtr = newSel
		r.healed = true
		return txt2, nil
	}
}

// heal asks the session's Healer (if any) to relocate a field by natural-language desc.
// If the session cannot heal, the original miss is returned unchanged (fail closed).
func (r *Rotator) heal(ctx context.Context, sess Session, desc string, cause error) (string, error) {
	h, ok := sess.(Healer)
	if !ok {
		return "", fmt.Errorf("browserrot: selector for %s missed and driver cannot self-heal: %w", desc, cause)
	}
	newSel, err := h.Heal(ctx, desc)
	if err != nil {
		return "", fmt.Errorf("browserrot: heal %s failed: %v (original miss: %w)", desc, err, cause)
	}
	if newSel == "" {
		return "", fmt.Errorf("browserrot: heal %s returned no selector (original miss: %w)", desc, cause)
	}
	return newSel, nil
}

// Healed reports whether a Tier-2 heal rewrote any selector during the last Rotate/Verify.
// When true, the caller should persist HealedSite() so the next run is deterministic.
func (r *Rotator) Healed() bool { return r.healed }

// HealedSite returns the Site with any healed selectors folded in — the recipe to persist.
func (r *Rotator) HealedSite() Site { return r.site }

// login runs the Site's Login flow with the given password on an already-open session
// and returns the post-login status text. It is the shared core of both Rotate's
// optional pre-change auth (with the OLD secret) and Verify's re-login (with the NEW
// secret). The password crosses as []byte and is never logged; each field self-heals.
func (r *Rotator) login(ctx context.Context, sess Session, password []byte) (string, error) {
	if _, err := sess.Goto(ctx, r.site.Login.URL); err != nil {
		return "", fmt.Errorf("browserrot: goto login: %w", err)
	}
	if r.site.Login.UserSel != "" {
		if err := r.fill(ctx, sess, &r.site.Login.UserSel, "the username or email input field", []byte(r.username)); err != nil {
			return "", err
		}
	}
	if err := r.fill(ctx, sess, &r.site.Login.PassSel, "the password input field", password); err != nil {
		return "", err
	}
	if err := r.click(ctx, sess, &r.site.Login.SubmitSel, "the log-in button"); err != nil {
		return "", err
	}
	txt, err := r.text(ctx, sess, &r.site.Login.SuccessSel, "the post-login status message")
	if err != nil {
		return "", fmt.Errorf("browserrot: read login result: %w", err)
	}
	return txt, nil
}

// Verify proves the new secret authenticates by re-logging-in through the Site's
// Login flow (hard rule 2: verify-new-before-revoke-old). If the Site has no Login
// flow, Verify REFUSES — the spine then keeps the old secret and flags the human,
// never committing an unverified website rotation.
func (r *Rotator) Verify(ctx context.Context, newSecret *vault.Handle, v *vault.Vault) error {
	if r.site.Login.URL == "" {
		return errors.New("browserrot: no browser verify path for this site — keeping old (hard rule 2)")
	}
	ok, err := r.authenticates(ctx, newSecret, v)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("browserrot: new password did NOT authenticate")
	}
	return nil
}

// authenticates runs the Site's Login flow with the secret behind h in a fresh session and
// reports whether the success marker appeared. err means the probe itself could not run.
func (r *Rotator) authenticates(ctx context.Context, h *vault.Handle, v *vault.Vault) (bool, error) {
	sess, err := r.drv.Open(ctx)
	if err != nil {
		return false, fmt.Errorf("browserrot: open browser (verify): %w", err)
	}
	defer sess.Close()

	buf, err := v.Open(h)
	if err != nil {
		return false, fmt.Errorf("browserrot: open secret (verify): %w", err)
	}
	txt, err := r.login(ctx, sess, buf.Bytes())
	if err != nil {
		return false, err
	}
	return strings.Contains(txt, r.site.Login.SuccessText), nil
}

// RevokeOld is a no-op for website passwords: the site itself invalidates the old
// password the instant the new one is set (we do not control that ordering — see
// docs/BROWSER-ROTATION.md §3, rule 2). Nothing to retire, so this always succeeds.
func (r *Rotator) RevokeOld(ctx context.Context, c discover.Credential, v *vault.Vault) error {
	return nil
}

// Ensure a Rotator satisfies the shared rotation contract at compile time.
var _ rotate.Rotator = (*Rotator)(nil)
