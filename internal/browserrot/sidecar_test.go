package browserrot

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// nodeAvailable reports whether a `node` runtime is on PATH; the sidecar needs it.
func nodeAvailable(t *testing.T) bool {
	t.Helper()
	_, err := exec.LookPath("node")
	return err == nil
}

// stubSidecar writes a tiny JSON-RPC stub that mimics the real sidecar's contract but
// runs NO browser: it replies to every method and appends each raw incoming frame to a
// transcript file. This lets us assert the secret seam (base64, never plaintext) with no
// Chromium in the loop, so it runs in ordinary CI.
func stubSidecar(t *testing.T, transcript string) string {
	t.Helper()
	dir := t.TempDir()
	js := `'use strict';
const fs = require('fs');
const T = process.env.SIDECAR_TRANSCRIPT;
let buf = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', c => {
  buf += c; let nl;
  while ((nl = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, nl); buf = buf.slice(nl+1);
    if (!line.trim()) continue;
    if (T) fs.appendFileSync(T, line + '\n');
    const m = JSON.parse(line);
    let result = {ok:true};
    if (m.method === 'goto') result = {finalURL: (m.params && m.params.url) || ''};
    if (m.method === 'text') result = {text: 'SUCCESS'};
    process.stdout.write(JSON.stringify({id:m.id, result}) + '\n');
    if (m.method === 'close') process.exit(0);
  }
});
`
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte(js), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIDECAR_TRANSCRIPT", transcript)
	return dir
}

// The secret must cross the stdio boundary base64-encoded and NEVER as plaintext — this
// is the sidecar analog of rod.go's "one plaintext moment, localized" seam.
func TestSidecar_secretSeamBase64(t *testing.T) {
	if !nodeAvailable(t) {
		t.Skip("node not on PATH; sidecar needs a Node runtime")
	}
	transcript := filepath.Join(t.TempDir(), "rpc.log")
	dir := stubSidecar(t, transcript)

	drv := &SidecarDriver{ScriptDir: dir, Headless: true, Timeout: 10 * time.Second}
	ctx := context.Background()
	sess, err := drv.Open(ctx)
	if err != nil {
		t.Fatalf("Open sidecar: %v", err)
	}

	const secret = "SUPER-SECRET-do-not-log-42"
	if err := sess.Fill(ctx, "#pw", []byte(secret)); err != nil {
		t.Fatalf("Fill: %v", err)
	}
	if _, err := sess.Goto(ctx, "https://example.test/x"); err != nil {
		t.Fatalf("Goto: %v", err)
	}
	txt, err := sess.Text(ctx, "#result")
	if err != nil {
		t.Fatalf("Text: %v", err)
	}
	if txt != "SUCCESS" {
		t.Fatalf("Text got %q, want SUCCESS", txt)
	}
	_ = sess.Close()

	raw, err := os.ReadFile(transcript)
	if err != nil {
		t.Fatalf("read transcript: %v", err)
	}
	tr := string(raw)
	if strings.Contains(tr, secret) {
		t.Fatalf("LEAK: plaintext secret found in the JSON-RPC transcript:\n%s", tr)
	}
	// The base64 of the secret MUST be what crossed the wire.
	if !strings.Contains(tr, "U1VQRVItU0VDUkVULWRvLW5vdC1sb2ctNDI=") {
		t.Fatalf("expected base64-encoded secret in transcript, got:\n%s", tr)
	}
}

// LIVE-VM parity: the node sidecar drives a REAL Chromium through the identical proof the
// go-rod driver passes (runLiveRotationProof). Skipped unless CHROME_BIN + node are set,
// exactly like the go-rod integration test.
func TestIntegration_sidecarBrowserRotation(t *testing.T) {
	bin := os.Getenv("CHROME_BIN")
	if bin == "" {
		t.Skip("set CHROME_BIN to a Chromium executable to run the LIVE-VM sidecar proof")
	}
	if !nodeAvailable(t) {
		t.Skip("node not on PATH; sidecar needs a Node runtime")
	}
	// The sidecar spawns a browser per Open (Rotate + Verify), so give it headroom.
	drv := &SidecarDriver{ChromeBin: bin, Headless: true, Timeout: 60 * time.Second}
	runLiveRotationProof(t, drv)
}

// M-B3 LIVE-VM self-heal: seed a ROTTED current-password selector into the recipe, then
// prove the sidecar's Tier-2 heuristic heal relocates the real field, the rotation still
// lands, the recipe is rewritten, AND no secret ever appears in a heal request. The
// redacted IPC transcript is the leak evidence: it records every RPC (secret fields
// replaced by a byte-count) so we can assert heal frames carry no secret and no raw
// secret/base64 was written to disk.
func TestIntegration_sidecarSelfHeal(t *testing.T) {
	bin := os.Getenv("CHROME_BIN")
	if bin == "" {
		t.Skip("set CHROME_BIN to a Chromium executable to run the LIVE-VM self-heal proof")
	}
	if !nodeAvailable(t) {
		t.Skip("node not on PATH; sidecar needs a Node runtime")
	}
	transcript := filepath.Join(t.TempDir(), "rpc.log")
	t.Setenv("INCREDIGO_SIDECAR_TRANSCRIPT", transcript)

	drv := &SidecarDriver{ChromeBin: bin, Headless: true, Timeout: 60 * time.Second}
	r := runLiveRotationProof(t, drv, func(s *Site) {
		s.Form.CurrentSel = "#rotted-selector-does-not-exist"
	})

	if !r.Healed() {
		t.Fatal("expected the rotted current-password selector to be healed")
	}
	if got := r.HealedSite().Form.CurrentSel; got != "#current" {
		t.Fatalf("healed recipe CurrentSel = %q, want #current (heuristic heal)", got)
	}

	// Leak evidence from the redacted transcript.
	raw, err := os.ReadFile(transcript)
	if err != nil {
		t.Fatalf("read transcript: %v", err)
	}
	tr := string(raw)
	const oldPW = "OLD-corr3ct-horse-battery"
	oldB64 := base64.StdEncoding.EncodeToString([]byte(oldPW))
	if strings.Contains(tr, oldPW) || strings.Contains(tr, oldB64) {
		t.Fatalf("LEAK: a raw secret reached the on-disk transcript")
	}
	// A heal request must have occurred, and no heal frame may carry a secret field.
	var sawHeal bool
	for _, line := range strings.Split(tr, "\n") {
		if line == "" {
			continue
		}
		var m struct {
			Method string                 `json:"method"`
			Params map[string]interface{} `json:"params"`
		}
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		if m.Method == "heal" {
			sawHeal = true
			if _, has := m.Params["secret"]; has {
				t.Fatalf("LEAK: heal request carried a secret field: %s", line)
			}
			if _, has := m.Params["description"]; !has {
				t.Fatalf("heal request missing description: %s", line)
			}
		}
	}
	if !sawHeal {
		t.Fatal("expected at least one heal RPC in the transcript")
	}
}

// M-B2: the humanized input path (Bézier mouse + paced per-key typing) must still land a
// real rotation against the local form — proving stealth pacing doesn't break correctness.
func TestIntegration_sidecarStealthRotation(t *testing.T) {
	bin := os.Getenv("CHROME_BIN")
	if bin == "" {
		t.Skip("set CHROME_BIN to a Chromium executable to run the stealth rotation proof")
	}
	if !nodeAvailable(t) {
		t.Skip("node not on PATH; sidecar needs a Node runtime")
	}
	runLiveRotationProof(t, &SidecarDriver{ChromeBin: bin, Headless: true, Stealth: true, Timeout: 60 * time.Second})
}

// M-B2 stealth posture: with Stealth on, the patchright real-fingerprint Chromium must
// NOT expose navigator.webdriver — the single most common headless/automation tell. This
// is the "detection-signal probe" the plan calls for. (The HeadlessChrome UA is inherent
// to headless mode against chrome-for-testing and is asserted only informationally.)
func TestIntegration_sidecarStealthSignals(t *testing.T) {
	bin := os.Getenv("CHROME_BIN")
	if bin == "" {
		t.Skip("set CHROME_BIN to a Chromium executable to run the stealth-signal probe")
	}
	if !nodeAvailable(t) {
		t.Skip("node not on PATH; sidecar needs a Node runtime")
	}
	drv := &SidecarDriver{ChromeBin: bin, Headless: true, Stealth: true, Timeout: 60 * time.Second}
	ctx := context.Background()
	sess, err := drv.Open(ctx)
	if err != nil {
		t.Fatalf("Open stealth sidecar: %v", err)
	}
	defer sess.Close()
	if _, err := sess.Goto(ctx, "data:text/html,<h1>probe</h1>"); err != nil {
		t.Fatalf("Goto: %v", err)
	}
	ss, ok := sess.(*sidecarSession)
	if !ok {
		t.Fatalf("expected *sidecarSession, got %T", sess)
	}
	sig, err := ss.Probe(ctx)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	t.Logf("stealth signals via %s: %+v", sig.Driver, sig.Signals)
	if sig.Driver != "patchright" {
		t.Fatalf("stealth requires the patchright driver; got %q — run npm install patchright", sig.Driver)
	}
	if sig.Signals.Webdriver {
		t.Fatal("navigator.webdriver is TRUE — stealth posture failed (bot tell present)")
	}
}

// A sidecar Session must satisfy the Session contract at compile time.
var _ Session = (*sidecarSession)(nil)
