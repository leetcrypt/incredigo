package browserrot

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"incredigo/internal/pwgen"
	"incredigo/internal/vault"
)

// siteSim is a STATEFUL fake site: it holds the account's current password, applies a change
// on submit when the current-password field matches, and answers login attempts against it.
// Faults model the post-submit race: a lost submit reply, result reads that fail while the
// next page loads, and login probes that cannot run. Fake passwords only.
type siteSim struct {
	mu            sync.Mutex
	site          Site
	current       string // the password the site accepts right now
	apply         bool   // submit actually changes the password
	submitErr     bool   // submit applies (if apply) but its reply is lost
	resultFails   int    // this many result reads fail before one succeeds
	loginBroken   bool   // login probes error out (e.g. MFA page / unreachable)
	result        string // text of the result element after submit
	resultReads   int
	loginAttempts int
}

func (d *siteSim) Name() string { return "sim" }
func (d *siteSim) Open(context.Context) (Session, error) {
	return &simSession{d: d, fields: map[string]string{}}, nil
}

type simSession struct {
	d       *siteSim
	fields  map[string]string
	loginOK bool
}

func (s *simSession) Goto(_ context.Context, url string) (string, error) { return url, nil }
func (s *simSession) Fill(_ context.Context, sel string, secret []byte) error {
	s.fields[sel] = string(secret)
	return nil
}
func (s *simSession) Click(_ context.Context, sel string) error {
	d := s.d
	d.mu.Lock()
	defer d.mu.Unlock()
	switch sel {
	case d.site.Form.SubmitSel:
		if d.apply && s.fields[d.site.Form.CurrentSel] == d.current {
			d.current = s.fields[d.site.Form.NewSel]
			d.result = "SUCCESS"
		} else {
			d.result = "REJECTED"
		}
		if d.submitErr {
			return errors.New("click: reply lost (page navigated)")
		}
	case d.site.Login.SubmitSel:
		d.loginAttempts++
		s.loginOK = s.fields[d.site.Login.PassSel] == d.current
	}
	return nil
}
func (s *simSession) Text(_ context.Context, sel string) (string, error) {
	d := s.d
	d.mu.Lock()
	defer d.mu.Unlock()
	switch sel {
	case d.site.Form.SuccessSel:
		d.resultReads++
		if d.resultFails > 0 {
			d.resultFails--
			return "", errors.New("text: content script unreachable on the session tab")
		}
		return d.result, nil
	case d.site.Login.SuccessSel:
		if d.loginBroken {
			return "", errors.New("text: login page did not load")
		}
		if s.loginOK {
			return "Signed in", nil
		}
		return "Invalid password", nil
	}
	return "", fmt.Errorf("text: no element %s", sel)
}
func (s *simSession) Close() error { return nil }

func simSiteWithLogin() Site {
	s := testSite()
	s.Login = Login{
		URL: "https://github.com/login", UserSel: "#user", PassSel: "#pass",
		SubmitSel: "#login", SuccessSel: "#flash", SuccessText: "Signed in",
	}
	return s
}

func newSimRotator(site Site, d *siteSim) *Rotator {
	d.site = site
	r := New(site, d, pwgen.DefaultPolicy())
	r.readAttempts, r.readBackoff = 5, time.Millisecond
	return r
}

func openString(t *testing.T, v *vault.Vault, h *vault.Handle) string {
	t.Helper()
	buf, err := v.Open(h)
	if err != nil {
		t.Fatalf("handle does not open: %v", err)
	}
	return string(buf.Bytes())
}

func TestRotate_postSubmit(t *testing.T) {
	const oldPW = "OLD-fake-pw"
	cases := []struct {
		name        string
		site        Site
		sim         *siteSim
		wantOK      bool // Rotate returns (newH, nil)
		wantUnknown bool // Rotate returns (newH, ErrOutcomeUnknown)
		// otherwise: (nil, err) and the old password must still be the site's password
	}{
		{"transient read failures are retried", simSiteWithLogin(),
			&siteSim{apply: true, resultFails: 2}, true, false},
		{"unreadable result, change applied: new password proven by login", simSiteWithLogin(),
			&siteSim{apply: true, resultFails: 1 << 20}, true, false},
		{"lost submit reply, change applied: new password proven by login", simSiteWithLogin(),
			&siteSim{apply: true, submitErr: true}, true, false},
		{"unreadable result, change NOT applied: old still logs in, fail safe", simSiteWithLogin(),
			&siteSim{apply: false, resultFails: 1 << 20}, false, false},
		{"unreadable result, change applied, probes impossible: new kept", simSiteWithLogin(),
			&siteSim{apply: true, resultFails: 1 << 20, loginBroken: true}, false, true},
		{"unreadable result, no login flow: new kept", testSite(),
			&siteSim{apply: true, resultFails: 1 << 20}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := vault.New()
			defer v.Purge()
			c := gitHubPAT(t, v, oldPW)
			d := tc.sim
			d.current = oldPW
			r := newSimRotator(tc.site, d)

			newH, err := r.Rotate(context.Background(), c, v)
			assertSecretUnchanged(t, v, c, oldPW)

			switch {
			case tc.wantOK:
				if err != nil {
					t.Fatalf("Rotate: %v", err)
				}
				if got := openString(t, v, newH); got != d.current {
					t.Fatal("returned secret is not the password the site now accepts")
				}
			case tc.wantUnknown:
				if !errors.Is(err, ErrOutcomeUnknown) {
					t.Fatalf("err = %v, want ErrOutcomeUnknown", err)
				}
				if newH == nil {
					t.Fatal("LOCKOUT: outcome unknown but the new secret was not returned")
				}
				// Whatever the site now accepts must be recoverable from what we kept.
				if got := openString(t, v, newH); got != d.current {
					t.Fatal("LOCKOUT: kept secret is not the password the site now accepts")
				}
			default:
				if err == nil || errors.Is(err, ErrOutcomeUnknown) {
					t.Fatalf("err = %v, want a definite failure", err)
				}
				if newH != nil {
					t.Fatalf("definite failure must not return a handle")
				}
				if d.current != oldPW {
					t.Fatal("site password changed but Rotate reported a definite failure")
				}
			}
		})
	}
}

// TestRotate_siteRejectionStaysDefinite pins the existing MFA/rejection contract: a result that
// was READ and lacks the success marker is a clean failure — no probes, no handle.
func TestRotate_siteRejectionStaysDefinite(t *testing.T) {
	v := vault.New()
	defer v.Purge()
	c := gitHubPAT(t, v, "OLD-fake-pw")
	d := &siteSim{current: "OLD-fake-pw", apply: false}
	r := newSimRotator(simSiteWithLogin(), d)

	newH, err := r.Rotate(context.Background(), c, v)
	if err == nil || errors.Is(err, ErrOutcomeUnknown) || newH != nil {
		t.Fatalf("got (%v, %v), want (nil, definite error)", newH, err)
	}
	if d.loginAttempts != 0 {
		t.Errorf("a readable rejection must not trigger login probes (got %d)", d.loginAttempts)
	}
}
