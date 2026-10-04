// WebExtension implementation of the browserrot Driver — the THIRD backend that
// satisfies the same interface go-rod (rod.go) and the Node sidecar (sidecar.go)
// already implement ("playwright-go and a Tier-2 AI driver are swap-ins that satisfy
// the same interface" — browserrot.go). Unlike those two, which each launch a FRESH,
// empty Chromium, this driver commands the user's REAL, already-open, already-2FA'd
// browser session through an MV3 WebExtension (extension/). That is the strategic
// point: the session's own cookies mean no OLD-password re-login, the change runs
// post-2FA, and a real user profile defeats anti-bot — none of which a headless
// throwaway profile can do (docs/MARKET.md §7, the real-session reset vector).
//
// TRANSPORT — Chrome native messaging. When the extension calls
// chrome.runtime.connectNative("org.incredigo.browserrot"), Chrome SPAWNS this Go
// program as the native host and wires the native-messaging pipe to our stdio:
//
//	os.Stdin   <- frames the extension posts to us   (command RESULTS)
//	os.Stdout  -> frames Chrome delivers to the extension (COMMANDS)
//
// so, inverted from the sidecar (where Go owns the child): here Chrome owns us, we
// WRITE commands to stdout and READ results from stdin. Each frame is a 4-byte
// LITTLE-ENDIAN length prefix followed by that many bytes of JSON (the native
// messaging wire format). Both directions use identical framing.
//
// SECRET SEAM (documented honestly, like rod.go's CDP seam and sidecar.go's stdio
// seam): Fill base64-encodes the vault bytes into the `secret` field of the fill
// command and writes it once to the pipe. The extension decodes it, assigns it to the
// input's value exactly once, and drops it. The secret is NEVER logged, NEVER written
// to disk, and NEVER placed in a heal/act request to a model. MFA/CAPTCHA are never
// bypassed: a challenge makes the success marker not match, so the engine keeps the
// old secret (browserrot.go Rotate).
package browserrot

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// maxFrame bounds a single inbound frame so a garbage length prefix can't drive a huge
// allocation. Chrome caps an extension→host message at 1 MiB; we allow generous headroom.
const maxFrame = 64 * 1024 * 1024

// ExtensionDriver drives the user's real browser via the MV3 extension over a native
// messaging pipe. In production the zero value is correct: In/Out default to os.Stdin/
// os.Stdout, which Chrome has wired to the native-messaging pipe. Tests inject a pair of
// pipes plus a fake extension endpoint, so the full Session contract is exercised with no
// browser at all.
//
// Unlike RodDriver/SidecarDriver, there is exactly ONE browser (the user's) and ONE
// persistent pipe for the process lifetime, so every Open() is a logical session multiplexed
// over the same shared connection. The engine calls Rotate then Verify sequentially, so the
// shared connection is never used concurrently.
type ExtensionDriver struct {
	In      io.Reader     // frames FROM the extension; nil -> os.Stdin
	Out     io.Writer     // frames TO the extension; nil -> os.Stdout
	Timeout time.Duration // per-operation timeout; defaults to 30s

	once sync.Once
	conn *extConn
}

// Name identifies the backend in logs/plans.
func (d *ExtensionDriver) Name() string { return "webextension" }

// connect lazily builds the single shared connection and starts its read loop. It never
// performs I/O itself (the read loop does), so it cannot fail here.
func (d *ExtensionDriver) connect() *extConn {
	d.once.Do(func() {
		in := d.In
		if in == nil {
			in = os.Stdin
		}
		out := d.Out
		if out == nil {
			out = os.Stdout
		}
		to := d.Timeout
		if to <= 0 {
			to = 30 * time.Second
		}
		c := &extConn{
			out:    out,
			frames: make(chan []byte, 8),
			readEr: make(chan error, 1),
			done:   make(chan struct{}),
			to:     to,
		}
		go c.readLoop(in)
		d.conn = c
	})
	return d.conn
}

// Open handshakes with the extension, which PINS the session to the tab active right now and
// reports its id. Every later command targets that tab only, so a focus change mid-rotation
// cannot redirect a secret fill elsewhere. An extension that does not report a pinned tab
// (a pre-pinning build that follows focus per command) is refused — fail closed.
func (d *ExtensionDriver) Open(ctx context.Context) (Session, error) {
	c := d.connect()
	raw, err := c.call(ctx, "open", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("webextension: open session: %w", err)
	}
	var out struct {
		TabID *int `json:"tabId"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.TabID == nil {
		return nil, fmt.Errorf("webextension: open session: extension did not pin a tab (update the extension)")
	}
	return &extSession{conn: c, tabID: *out.TabID}, nil
}

// Close tears down the shared connection's read loop. In production the process simply exits
// when Chrome closes the pipe; Close exists so a caller (or a test) can stop the read loop
// deterministically.
func (d *ExtensionDriver) Close() error {
	if d.conn != nil {
		d.conn.shutdown()
	}
	return nil
}

// extConn owns the framed native-messaging pipe and its read loop. Calls are serialized by mu
// (the engine drives sequentially), so responses arrive in request order; call still matches on
// the frame id for robustness.
type extConn struct {
	out    io.Writer
	frames chan []byte
	readEr chan error
	done   chan struct{}
	to     time.Duration

	mu       sync.Mutex
	nextID   int
	closeOne sync.Once
}

// readLoop reads length-prefixed JSON frames from the extension and forwards them. It exits on
// EOF (Chrome closed the pipe / the fake endpoint closed its writer) or a framing error.
func (c *extConn) readLoop(r io.Reader) {
	for {
		payload, err := readFrame(r)
		if err != nil {
			if err != io.EOF {
				select {
				case c.readEr <- err:
				default:
				}
			}
			close(c.frames)
			return
		}
		select {
		case c.frames <- payload:
		case <-c.done:
			return
		}
	}
}

// call writes one command frame and waits for its matching response frame, bounded by the
// per-op timeout, ctx, and connection shutdown.
func (c *extConn) call(ctx context.Context, method string, params map[string]any) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.nextID++
	id := c.nextID
	if err := writeFrame(c.out, map[string]any{"id": id, "method": method, "params": params}); err != nil {
		return nil, fmt.Errorf("write %s: %w", method, err)
	}

	deadline := time.NewTimer(c.to)
	defer deadline.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.done:
			return nil, fmt.Errorf("%s: connection closed", method)
		case <-deadline.C:
			return nil, fmt.Errorf("%s: timed out after %s", method, c.to)
		case err := <-c.readEr:
			return nil, fmt.Errorf("%s: extension read error: %w", method, err)
		case line, ok := <-c.frames:
			if !ok {
				return nil, fmt.Errorf("%s: extension closed the pipe", method)
			}
			var resp extResp
			if err := json.Unmarshal(line, &resp); err != nil {
				// Not a well-formed frame; ignore defensively (the extension emits only frames).
				continue
			}
			if resp.ID != id {
				continue
			}
			if resp.Error != "" {
				return nil, fmt.Errorf("%s", resp.Error)
			}
			return resp.Result, nil
		}
	}
}

// shutdown stops the read loop and unblocks any in-flight call. Idempotent.
func (c *extConn) shutdown() {
	c.closeOne.Do(func() { close(c.done) })
}

type extResp struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  string          `json:"error"`
}

// extSession is one logical Session over the shared connection. tabID is the tab the extension
// pinned at open; the extension is authoritative for targeting, this copy is for diagnostics.
type extSession struct {
	conn  *extConn
	tabID int
}

func (s *extSession) Goto(ctx context.Context, url string) (string, error) {
	raw, err := s.conn.call(ctx, "goto", map[string]any{"url": url})
	if err != nil {
		return "", err
	}
	var out struct {
		FinalURL string `json:"finalURL"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	return out.FinalURL, nil
}

func (s *extSession) Fill(ctx context.Context, selector string, secret []byte) error {
	// base64 keeps the secret intact across JSON transport and marks it as sensitive. It
	// never appears in a log line or an error; the extension wipes its decoded copy.
	_, err := s.conn.call(ctx, "fill", map[string]any{
		"selector": selector,
		"secret":   base64.StdEncoding.EncodeToString(secret),
	})
	return err
}

func (s *extSession) Click(ctx context.Context, selector string) error {
	_, err := s.conn.call(ctx, "click", map[string]any{"selector": selector})
	return err
}

func (s *extSession) Text(ctx context.Context, selector string) (string, error) {
	raw, err := s.conn.call(ctx, "text", map[string]any{"selector": selector})
	if err != nil {
		return "", err
	}
	var out struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	return out.Text, nil
}

// Close tells the extension to detach from the tab. It does NOT close the shared pipe — that
// belongs to the process/Chrome lifetime (or ExtensionDriver.Close in a test).
func (s *extSession) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = s.conn.call(ctx, "close", map[string]any{})
	return nil
}

// writeFrame encodes v as JSON and writes it with a 4-byte little-endian length prefix — the
// Chrome native-messaging wire format.
func writeFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// readFrame reads one 4-byte little-endian length prefix and then that many bytes of JSON.
func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(hdr[:])
	if n > maxFrame {
		return nil, fmt.Errorf("native-messaging frame too large: %d bytes", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// compile-time checks: ExtensionDriver is a Driver and its Session satisfies the contract.
var _ Driver = (*ExtensionDriver)(nil)
var _ Session = (*extSession)(nil)
