// Node-sidecar implementation of the browserrot Driver — the swap-in the architecture
// always anticipated (browserrot.go: "playwright-go and a Tier-2 AI driver are swap-ins
// that satisfy the same interface"). It spawns a small Node program (sidecar/index.js)
// that drives a real-fingerprint Chromium (patchright) and speaks newline-delimited
// JSON-RPC over stdio. go-rod stays the default; this Driver is selected explicitly
// (NewSidecarDriver / a flag) until it reaches parity.
//
// SECRET SEAM (documented honestly, like the CDP seam in rod.go): Fill base64-encodes
// the vault bytes and hands them to the sidecar over the local stdio pipe, which types
// them into the field. The secret crosses ONE local process boundary, is never logged,
// never written to disk, and never sent to a model. Heal requests (Tier-2) carry only a
// field description + sanitized DOM — never a value.
package browserrot

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// SidecarDriver launches one Node sidecar process per session. Each Open is a fresh
// process + fresh browser context, so no cookies/state leak between accounts (parity
// with RodDriver).
type SidecarDriver struct {
	NodeBin   string        // node executable; "" -> "node" from PATH
	ScriptDir string        // dir containing index.js; "" -> resolved next to this source
	ChromeBin string        // Chromium executablePath handed to the sidecar; "" lets it decide
	Headless  bool          // default true; false to watch it locally
	Stealth   bool          // patchright real-fingerprint + human-paced typing (M-B2)
	Timeout   time.Duration // per-operation timeout; defaults to 30s
}

// Name identifies the backend in logs/plans.
func (d *SidecarDriver) Name() string { return "node-sidecar" }

// scriptDir resolves the sidecar directory: explicit field, else $INCREDIGO_SIDECAR_DIR,
// else the sidecar/ folder next to this source file.
func (d *SidecarDriver) scriptDir() string {
	if d.ScriptDir != "" {
		return d.ScriptDir
	}
	if env := os.Getenv("INCREDIGO_SIDECAR_DIR"); env != "" {
		return env
	}
	_, self, _, ok := runtime.Caller(0)
	if ok {
		return filepath.Join(filepath.Dir(self), "sidecar")
	}
	return "sidecar"
}

// Open spawns the Node sidecar, sends the `open` RPC to launch Chromium, and returns a
// Session bound to that process. The process is killed on Session.Close().
func (d *SidecarDriver) Open(ctx context.Context) (Session, error) {
	node := d.NodeBin
	if node == "" {
		node = "node"
	}
	to := d.Timeout
	if to <= 0 {
		to = 30 * time.Second
	}

	// The sidecar owns its own process lifetime (killed in Close); do NOT tie it to the
	// per-Open ctx, which may be short-lived.
	cmd := exec.Command(node, "index.js")
	cmd.Dir = d.scriptDir()
	cmd.Stderr = os.Stderr // [sidecar] diagnostics only — never a secret

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("node-sidecar: stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("node-sidecar: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("node-sidecar: start node (dir=%s): %w", cmd.Dir, err)
	}

	s := &sidecarSession{
		cmd:    cmd,
		stdin:  stdin,
		frames: make(chan []byte, 8),
		readEr: make(chan error, 1),
		to:     to,
	}
	go s.readLoop(stdout)

	if _, err := s.call(ctx, "open", map[string]any{
		"headless":       d.Headless,
		"executablePath": d.ChromeBin,
		"stealth":        d.Stealth,
		"timeoutMs":      to.Milliseconds(),
	}); err != nil {
		s.Close()
		return nil, fmt.Errorf("node-sidecar: open browser: %w", err)
	}
	return s, nil
}

type sidecarSession struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	frames chan []byte
	readEr chan error
	to     time.Duration

	mu     sync.Mutex // serializes RPCs (the engine calls sequentially anyway)
	nextID int
}

// readLoop scans stdout for newline-delimited JSON frames and forwards them. stdout is
// reserved for JSON-RPC; the sidecar sends all diagnostics to stderr.
func (s *sidecarSession) readLoop(stdout io.Reader) {
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := append([]byte(nil), sc.Bytes()...)
		s.frames <- line
	}
	if err := sc.Err(); err != nil {
		s.readEr <- err
	}
	close(s.frames)
}

type rpcResp struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  string          `json:"error"`
}

// call sends one JSON-RPC request and waits for its matching response, bounded by the
// per-op timeout and ctx. Requests are serialized, so responses arrive in order.
func (s *sidecarSession) call(ctx context.Context, method string, params map[string]any) (json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.nextID++
	id := s.nextID
	req, err := json.Marshal(map[string]any{"id": id, "method": method, "params": params})
	if err != nil {
		return nil, err
	}
	if _, err := s.stdin.Write(append(req, '\n')); err != nil {
		return nil, fmt.Errorf("write %s: %w", method, err)
	}

	deadline := time.NewTimer(s.to)
	defer deadline.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, fmt.Errorf("%s: timed out after %s", method, s.to)
		case err := <-s.readEr:
			return nil, fmt.Errorf("%s: sidecar read error: %w", method, err)
		case line, ok := <-s.frames:
			if !ok {
				return nil, fmt.Errorf("%s: sidecar closed stdout", method)
			}
			var r rpcResp
			if err := json.Unmarshal(line, &r); err != nil {
				// Not a JSON-RPC frame; ignore (defensive — sidecar should only emit frames).
				continue
			}
			if r.ID != id {
				continue
			}
			if r.Error != "" {
				return nil, fmt.Errorf("%s", r.Error)
			}
			return r.Result, nil
		}
	}
}

func (s *sidecarSession) Goto(ctx context.Context, url string) (string, error) {
	raw, err := s.call(ctx, "goto", map[string]any{"url": url})
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

func (s *sidecarSession) Fill(ctx context.Context, selector string, secret []byte) error {
	// base64 keeps the secret intact across JSON transport and marks it as sensitive.
	// It never appears in a log line or an error; the sidecar wipes its decoded copy.
	_, err := s.call(ctx, "fill", map[string]any{
		"selector": selector,
		"secret":   base64.StdEncoding.EncodeToString(secret),
	})
	return err
}

func (s *sidecarSession) Click(ctx context.Context, selector string) error {
	_, err := s.call(ctx, "click", map[string]any{"selector": selector})
	return err
}

func (s *sidecarSession) Text(ctx context.Context, selector string) (string, error) {
	raw, err := s.call(ctx, "text", map[string]any{"selector": selector})
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

// StealthSignals is a snapshot of common automation-detection signals, used by the M-B2
// lab proof to assert the stealth posture (navigator.webdriver absent under patchright).
type StealthSignals struct {
	Driver  string `json:"driver"`
	Signals struct {
		Webdriver  bool   `json:"webdriver"`
		HasChrome  bool   `json:"hasChrome"`
		Plugins    int    `json:"plugins"`
		Languages  string `json:"languages"`
		HeadlessUA bool   `json:"headlessUA"`
	} `json:"signals"`
}

// Probe reports the current page's automation-detection signals. It is sidecar-specific
// (not part of the Driver-agnostic Session contract) and reads only page globals — no
// secret is involved.
func (s *sidecarSession) Probe(ctx context.Context) (StealthSignals, error) {
	var out StealthSignals
	raw, err := s.call(ctx, "probe", nil)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(raw, &out)
	return out, err
}

// Heal implements the Tier-2 Healer: it asks the sidecar to relocate a field by
// natural-language description and returns a fresh selector. Only the description crosses
// the wire — never a secret (the RPC has no secret parameter, by construction).
func (s *sidecarSession) Heal(ctx context.Context, description string) (string, error) {
	raw, err := s.call(ctx, "heal", map[string]any{"description": description})
	if err != nil {
		return "", err
	}
	var out struct {
		Selector string `json:"selector"`
		Strategy string `json:"strategy"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	return out.Selector, nil
}

func (s *sidecarSession) Close() error {
	if s.stdin != nil {
		// Best-effort graceful close; the sidecar exits after the `close` reply.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, _ = s.call(ctx, "close", nil)
		cancel()
		_ = s.stdin.Close()
	}
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_ = s.cmd.Wait()
	}
	return nil
}

// compile-time checks: SidecarDriver is a Driver and its Session can self-heal (Tier-2).
var _ Driver = (*SidecarDriver)(nil)
var _ Healer = (*sidecarSession)(nil)
