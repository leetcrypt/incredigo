// go-rod implementation of the browserrot Driver — the default deterministic
// backend (docs/BROWSER-ROTATION.md §13 chosen stack). It talks to a real Chromium
// over CDP. This file is the ONLY place a secret becomes a Go string: Fill converts
// the vault-supplied bytes to the string CDP's Input requires, at the last moment.
// The value is never logged, never persisted, never handed to a model.
package browserrot

import (
	"context"
	"fmt"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

// RodDriver launches a real headless Chromium per session. Bin points at a Chromium
// executable (e.g. the Playwright-managed chrome-for-testing) so we avoid a network
// download and, on snap systems, snap confinement. Timeout bounds each browser op.
type RodDriver struct {
	Bin      string        // chromium binary; "" lets go-rod find/download one
	Headless bool          // default true in production; false to watch it locally
	Timeout  time.Duration // per-operation timeout; defaults to 30s
	// Insecure accepts self-signed / untrusted TLS certs (Chromium
	// --ignore-certificate-errors). Needed for self-hosted targets behind a private
	// CA or a Tailscale-fronted service (e.g. a personal Gitea on 100.x). This is the
	// browser analog of `curl -k` in the rung harnesses; the connection is still TLS,
	// we just don't verify the chain. Off by default — opt in per run for a host you
	// own and whose cert you already trust out-of-band.
	Insecure bool
}

// Name identifies the backend in logs/plans.
func (d *RodDriver) Name() string { return "go-rod" }

// Open launches an isolated Chromium and returns a single-tab Session. Each Open is
// a fresh browser + fresh profile, so no cookies/state leak between accounts.
func (d *RodDriver) Open(ctx context.Context) (Session, error) {
	l := launcher.New().Headless(d.Headless).
		Set("no-sandbox").Set("disable-dev-shm-usage")
	if d.Insecure {
		// Accept the self-signed cert of a self-owned host. TLS still encrypts; only
		// chain verification is skipped. Scoped to this launched browser instance.
		l = l.Set("ignore-certificate-errors")
	}
	if d.Bin != "" {
		l = l.Bin(d.Bin)
	}
	u, err := l.Launch()
	if err != nil {
		return nil, fmt.Errorf("go-rod: launch chromium: %w", err)
	}
	b := rod.New().ControlURL(u)
	if err := b.Connect(); err != nil {
		l.Cleanup()
		return nil, fmt.Errorf("go-rod: connect: %w", err)
	}
	page, err := b.Page(proto.TargetCreateTarget{})
	if err != nil {
		b.MustClose()
		l.Cleanup()
		return nil, fmt.Errorf("go-rod: new page: %w", err)
	}
	to := d.Timeout
	if to <= 0 {
		to = 30 * time.Second
	}
	return &rodSession{browser: b, launcher: l, page: page, to: to}, nil
}

type rodSession struct {
	browser  *rod.Browser
	launcher *launcher.Launcher
	page     *rod.Page
	to       time.Duration
}

func (s *rodSession) Goto(ctx context.Context, url string) (string, error) {
	p := s.page.Timeout(s.to)
	if err := p.Navigate(url); err != nil {
		return "", err
	}
	if err := p.WaitStable(300 * time.Millisecond); err != nil {
		return "", err
	}
	info, err := p.Info()
	if err != nil {
		return "", err
	}
	return info.URL, nil
}

func (s *rodSession) Fill(ctx context.Context, selector string, secret []byte) error {
	el, err := s.page.Timeout(s.to).Element(selector)
	if err != nil {
		return err
	}
	// The one plaintext-as-string moment: CDP Input needs a string. Localized here.
	return el.Input(string(secret))
}

func (s *rodSession) Click(ctx context.Context, selector string) error {
	el, err := s.page.Timeout(s.to).Element(selector)
	if err != nil {
		return err
	}
	// A submit/login click triggers a navigation (login POST -> 302 -> dashboard,
	// change-form POST -> flash). Against a remote host that round-trip has real
	// latency, so we must wait for the NEW document to commit before returning —
	// otherwise the next Text() read resolves against the PRE-submit page (the login
	// form still showing) and mis-reports the outcome. Arm the navigation wait BEFORE
	// clicking, then block until the network is almost idle. Bounded by the page
	// timeout; if a click does not navigate this returns when the timeout elapses.
	wait := s.page.Timeout(s.to).WaitNavigation(proto.PageLifecycleEventNameNetworkAlmostIdle)
	if err := el.Click(proto.InputMouseButtonLeft, 1); err != nil {
		return err
	}
	wait()
	// Belt-and-suspenders: let any post-navigation DOM (flash render) settle.
	_ = s.page.Timeout(s.to).WaitStable(300 * time.Millisecond)
	return nil
}

func (s *rodSession) Text(ctx context.Context, selector string) (string, error) {
	el, err := s.page.Timeout(s.to).Element(selector)
	if err != nil {
		return "", err
	}
	if err := el.WaitVisible(); err != nil {
		return "", err
	}
	return el.Text()
}

func (s *rodSession) Close() error {
	if s.browser != nil {
		_ = s.browser.Close()
	}
	if s.launcher != nil {
		s.launcher.Cleanup()
	}
	return nil
}

// compile-time check that RodDriver is a Driver.
var _ Driver = (*RodDriver)(nil)
