package browserrot

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"incredigo/internal/pwgen"
	"incredigo/internal/vault"
)

// ---- fake extension endpoint: the browser side of the native-messaging pipe, with NO
// browser. It reads command frames the driver writes, records each raw frame to a
// transcript, and replies with a matching response frame. This lets us assert the framing
// AND the secret seam (base64, never plaintext) in ordinary CI.

type fakeExtension struct {
	mu         sync.Mutex
	transcript [][]byte // every raw command frame the driver sent (JSON payloads)
	text       string   // what Text() should resolve to (the site's success/error marker)
	tabID      int      // tabId the open reply pins; 0 omits it (an unpinned, pre-fix extension)
	failMethod string   // if set, the FIRST command with this method gets an error frame...
	failMsg    string   // ...carrying this message (e.g. "fill: session tab closed")
	failed     bool
}

// serve loops reading command frames from r and writing response frames to w until r hits
// EOF, then closes w so the driver's read loop also unwinds (clean shutdown for -race).
func (f *fakeExtension) serve(r io.Reader, w io.WriteCloser) {
	defer w.Close()
	for {
		payload, err := readFrame(r)
		if err != nil {
			return // EOF when the driver side closes its writer
		}
		f.mu.Lock()
		f.transcript = append(f.transcript, append([]byte(nil), payload...))
		f.mu.Unlock()

		var cmd struct {
			ID     int            `json:"id"`
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		if err := json.Unmarshal(payload, &cmd); err != nil {
			continue
		}
		f.mu.Lock()
		fail := !f.failed && f.failMethod != "" && cmd.Method == f.failMethod
		if fail {
			f.failed = true
		}
		f.mu.Unlock()
		if fail {
			if err := writeFrame(w, map[string]any{"id": cmd.ID, "error": f.failMsg}); err != nil {
				return
			}
			continue
		}
		var result any
		switch cmd.Method {
		case "open":
			if f.tabID != 0 {
				result = map[string]any{"ok": true, "tabId": f.tabID}
			} else {
				result = map[string]any{"ok": true}
			}
		case "goto":
			url, _ := cmd.Params["url"].(string)
			result = map[string]any{"finalURL": url}
		case "text":
			result = map[string]any{"text": f.text}
		default: // open, fill, click, close
			result = map[string]any{"ok": true}
		}
		if err := writeFrame(w, map[string]any{"id": cmd.ID, "result": result}); err != nil {
			return
		}
	}
}

func (f *fakeExtension) frames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.transcript))
	for i, b := range f.transcript {
		out[i] = string(b)
	}
	return out
}

// wireFakeExtension connects an ExtensionDriver to a fakeExtension over two in-memory pipes,
// exactly mirroring the two directions of a native-messaging connection:
//
//	driver.Out --(commands)--> fake.reads
//	fake.writes --(results)--> driver.In
//
// It returns the driver, the fake, and a teardown that closes the command pipe (which
// cascades: fake sees EOF -> closes its writer -> driver read loop sees EOF -> exits).
func wireFakeExtension(t *testing.T, text string) (*ExtensionDriver, *fakeExtension, func()) {
	t.Helper()
	cmdR, cmdW := io.Pipe()   // driver writes commands here; fake reads
	respR, respW := io.Pipe() // fake writes results here; driver reads

	fake := &fakeExtension{text: text, tabID: 7}
	go fake.serve(cmdR, respW)

	drv := &ExtensionDriver{In: respR, Out: cmdW, Timeout: 5 * time.Second}
	teardown := func() {
		drv.Close()
		_ = cmdW.Close() // cascade EOF through the fake to the driver read loop
	}
	return drv, fake, teardown
}

// TestExtension_frameRoundTrip proves the 4-byte little-endian length-prefix framing is
// symmetric (writeFrame -> readFrame) and that the header is genuinely little-endian.
func TestExtension_frameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	msg := map[string]any{"id": 7, "method": "fill", "params": map[string]any{"selector": "#x"}}
	if err := writeFrame(&buf, msg); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}

	raw := buf.Bytes()
	if len(raw) < 4 {
		t.Fatalf("frame too short: %d bytes", len(raw))
	}
	// The prefix must equal the JSON length, little-endian.
	wantLen := len(raw) - 4
	if got := binary.LittleEndian.Uint32(raw[:4]); int(got) != wantLen {
		t.Fatalf("length prefix = %d, want %d", got, wantLen)
	}
	// A big-endian reader would see a wildly different (huge) length for a small body —
	// assert the bytes are NOT big-endian-equal, so we know the endianness is pinned.
	if binary.BigEndian.Uint32(raw[:4]) == uint32(wantLen) && raw[0] == raw[3] {
		t.Fatal("ambiguous endianness in test fixture; pick a length with distinct bytes")
	}

	payload, err := readFrame(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	if got["method"] != "fill" {
		t.Fatalf("round-trip lost the method: %v", got)
	}
}

// TestExtension_readFrameTruncated proves a short/truncated header or body is a clean error,
// not a panic or a hang.
func TestExtension_readFrameTruncated(t *testing.T) {
	// Only 2 of the 4 header bytes.
	if _, err := readFrame(bytes.NewReader([]byte{0x01, 0x00})); err == nil {
		t.Fatal("expected error on truncated header")
	}
	// Header claims 10 bytes but only 3 follow.
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], 10)
	short := append(hdr[:], []byte("abc")...)
	if _, err := readFrame(bytes.NewReader(short)); err == nil {
		t.Fatal("expected error on truncated body")
	}
}

// TestExtension_readFrameRejectsHugeLength proves a garbage/oversized length prefix is
// refused up front rather than driving a giant allocation.
func TestExtension_readFrameRejectsHugeLength(t *testing.T) {
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], maxFrame+1)
	if _, err := readFrame(bytes.NewReader(hdr[:])); err == nil {
		t.Fatal("expected error on oversized frame length")
	}
}

// TestExtension_sessionContractNoLeak drives the four Session verbs through the driver and the
// fake endpoint, then asserts (a) the ops framed correctly, (b) Text returns the fake's marker,
// and (c) the secret crossed the pipe base64-encoded and NEVER as plaintext — the native-
// messaging analog of rod.go's CDP seam and sidecar.go's stdio seam.
func TestExtension_sessionContractNoLeak(t *testing.T) {
	drv, fake, teardown := wireFakeExtension(t, "SUCCESS")
	defer teardown()

	ctx := context.Background()
	sess, err := drv.Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if _, err := sess.Goto(ctx, "https://example.test/settings"); err != nil {
		t.Fatalf("Goto: %v", err)
	}
	const secret = "SUPER-SECRET-do-not-log-42"
	if err := sess.Fill(ctx, "#new", []byte(secret)); err != nil {
		t.Fatalf("Fill: %v", err)
	}
	if err := sess.Click(ctx, "#submit"); err != nil {
		t.Fatalf("Click: %v", err)
	}
	txt, err := sess.Text(ctx, "#result")
	if err != nil {
		t.Fatalf("Text: %v", err)
	}
	if txt != "SUCCESS" {
		t.Fatalf("Text got %q, want SUCCESS", txt)
	}
	_ = sess.Close()

	joined := strings.Join(fake.frames(), "\n")
	if strings.Contains(joined, secret) {
		t.Fatalf("LEAK: plaintext secret found in the native-messaging transcript:\n%s", joined)
	}
	if !strings.Contains(joined, base64.StdEncoding.EncodeToString([]byte(secret))) {
		t.Fatalf("expected base64-encoded secret in transcript, got:\n%s", joined)
	}
	// The verbs must all have framed (open, goto, fill, click, text, close).
	for _, m := range []string{`"method":"open"`, `"method":"goto"`, `"method":"fill"`, `"method":"click"`, `"method":"text"`, `"method":"close"`} {
		if !strings.Contains(joined, m) {
			t.Fatalf("expected %s in transcript, got:\n%s", m, joined)
		}
	}
}

// TestExtension_rotatorSpineNoLeak runs the FULL browserrot Rotator spine (the same engine the
// go-rod and sidecar drivers use) against the ExtensionDriver + fake endpoint, with no browser.
// This proves the extension Driver is a drop-in third implementation of the Driver/Session
// contract: discover -> mint -> fill(current/new/confirm) -> submit -> read-success, and that
// neither the OLD nor the freshly minted NEW secret ever crosses the pipe as plaintext.
func TestExtension_rotatorSpineNoLeak(t *testing.T) {
	drv, fake, teardown := wireFakeExtension(t, "SUCCESS")
	defer teardown()

	v := vault.New()
	defer v.Purge()
	const oldPW = "OLD-corr3ct-horse-battery"
	c := gitHubPAT(t, v, oldPW)

	r := New(testSite(), drv, pwgen.DefaultPolicy())
	newH, err := r.Rotate(context.Background(), c, v)
	if err != nil {
		t.Fatalf("Rotate via extension driver: %v", err)
	}
	defer v.Forget(newH)

	// The new secret must authenticate the value that was actually stored: read it back and
	// prove it is non-empty and different from the old one.
	newBuf, err := v.Open(newH)
	if err != nil {
		t.Fatalf("open new handle: %v", err)
	}
	newPW := string(newBuf.Bytes())
	if newPW == "" || newPW == oldPW {
		t.Fatalf("new secret must be freshly minted and different from old")
	}

	joined := strings.Join(fake.frames(), "\n")
	if strings.Contains(joined, oldPW) {
		t.Fatalf("LEAK: OLD plaintext secret found in transcript:\n%s", joined)
	}
	if strings.Contains(joined, newPW) {
		t.Fatalf("LEAK: NEW plaintext secret found in transcript:\n%s", joined)
	}
	// Both secrets MUST appear base64-encoded (they were filled), proving the seam held.
	if !strings.Contains(joined, base64.StdEncoding.EncodeToString([]byte(oldPW))) {
		t.Fatal("expected the OLD secret base64-encoded in the fill frames")
	}
	if !strings.Contains(joined, base64.StdEncoding.EncodeToString([]byte(newPW))) {
		t.Fatal("expected the NEW secret base64-encoded in the fill frames")
	}
}

// TestExtension_rotateFailsWhenSiteRejects proves the fail-safe path through the extension
// driver: when the site does not confirm success, Rotate fails and the old secret is untouched.
func TestExtension_rotateFailsWhenSiteRejects(t *testing.T) {
	drv, _, teardown := wireFakeExtension(t, "REJECTED: wrong current password")
	defer teardown()

	v := vault.New()
	defer v.Purge()
	const oldPW = "OLD"
	c := gitHubPAT(t, v, oldPW)

	r := New(testSite(), drv, pwgen.DefaultPolicy())
	newH, err := r.Rotate(context.Background(), c, v)
	if err == nil {
		t.Fatal("expected Rotate to fail when the site does not confirm success")
	}
	if newH != nil {
		t.Fatalf("failed Rotate must not return a handle, got %v", newH)
	}
	assertSecretUnchanged(t, v, c, oldPW)
}

// TestExtension_openTimeoutWhenExtensionSilent proves a per-op timeout fires (no hang) when the
// extension never replies — e.g. the native host is connected but the content script is wedged.
func TestExtension_openTimeoutWhenExtensionSilent(t *testing.T) {
	cmdR, cmdW := io.Pipe()
	respR, _ := io.Pipe() // nothing is ever written to the driver's In
	defer cmdW.Close()
	defer cmdR.Close()

	// Drain commands so writeFrame never blocks on a full pipe, but never reply.
	go func() {
		for {
			if _, err := readFrame(cmdR); err != nil {
				return
			}
		}
	}()

	drv := &ExtensionDriver{In: respR, Out: cmdW, Timeout: 150 * time.Millisecond}
	defer drv.Close()

	_, err := drv.Open(context.Background())
	if err == nil {
		t.Fatal("expected Open to time out when the extension never replies")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected a timeout error, got: %v", err)
	}
}

// TestExtension_ctxCancelUnblocksCall proves a cancelled context unblocks an in-flight call
// rather than waiting out the full per-op timeout.
func TestExtension_ctxCancelUnblocksCall(t *testing.T) {
	cmdR, cmdW := io.Pipe()
	respR, _ := io.Pipe()
	defer cmdW.Close()
	defer cmdR.Close()
	go func() {
		for {
			if _, err := readFrame(cmdR); err != nil {
				return
			}
		}
	}()

	drv := &ExtensionDriver{In: respR, Out: cmdW, Timeout: 30 * time.Second}
	defer drv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()

	_, err := drv.Open(ctx)
	if err == nil {
		t.Fatal("expected Open to fail when ctx is cancelled")
	}
	if !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("expected a context-cancelled error, got: %v", err)
	}
}

// A compile-time reminder that the extension Session is a full Session (also asserted in
// extension.go; duplicated here so the test file stands alone as the contract witness
// alongside sidecar_test.go / browserrot_test.go).
var _ Session = (*extSession)(nil)

// TestExtension_openRequiresPinnedTab proves Open fails closed against an extension that does
// not report a pinned tab id (a pre-pinning build would follow focus between commands), and
// records the id when it does.
func TestExtension_openRequiresPinnedTab(t *testing.T) {
	drv, fake, teardown := wireFakeExtension(t, "SUCCESS")
	defer teardown()

	sess, err := drv.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got := sess.(*extSession).tabID; got != 7 {
		t.Errorf("session tabID = %d, want 7", got)
	}
	sess.Close()

	fake.mu.Lock()
	fake.tabID = 0
	fake.mu.Unlock()
	if _, err := drv.Open(context.Background()); err == nil {
		t.Fatal("Open must refuse an extension that does not pin a tab")
	}
}

// TestExtension_rotateFailsSafeWhenSessionTabLost proves that when the extension reports the
// pinned tab is gone (or a fill is refused off-origin) mid-flow, Rotate fails, returns no new
// handle, never submits, and leaves the old secret untouched.
func TestExtension_rotateFailsSafeWhenSessionTabLost(t *testing.T) {
	for _, msg := range []string{"fill: session tab closed", "fill: refused, pinned tab left the goto origin"} {
		t.Run(msg, func(t *testing.T) {
			drv, fake, teardown := wireFakeExtension(t, "SUCCESS")
			defer teardown()
			fake.failMethod, fake.failMsg = "fill", msg

			v := vault.New()
			defer v.Purge()
			const oldPW = "OLD-fake-pw"
			c := gitHubPAT(t, v, oldPW)

			r := New(testSite(), drv, pwgen.DefaultPolicy())
			newH, err := r.Rotate(context.Background(), c, v)
			if err == nil || !strings.Contains(err.Error(), msg) {
				t.Fatalf("Rotate err = %v, want it to carry %q", err, msg)
			}
			if newH != nil {
				t.Fatalf("failed Rotate must not return a handle, got %v", newH)
			}
			assertSecretUnchanged(t, v, c, oldPW)
			for _, f := range fake.frames() {
				if strings.Contains(f, `"method":"click"`) {
					t.Fatalf("submit was clicked after a refused fill: %s", f)
				}
			}
		})
	}
}
