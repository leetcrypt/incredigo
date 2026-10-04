// Package sink writes secrets out of the RAM vault. gopass is the live store
// (GPG); openssl produces portable sealed backups. Plaintext flows vault → pipe
// → external tool's stdin, and never touches the filesystem in cleartext.
package sink

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path"
	"strings"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// Gopass streams secrets into `gopass insert`. The binary path is configurable
// for testing; defaults to "gopass" on PATH.
type Gopass struct {
	Bin    string // default "gopass"
	Prefix string // default "imported/"
}

func (g *Gopass) bin() string {
	if g.Bin == "" {
		return "gopass"
	}
	return g.Bin
}

// Available reports whether gopass is usable.
func (g *Gopass) Available() bool {
	_, err := exec.LookPath(g.bin())
	return err == nil
}

// StorePath is the gopass entry path for a credential: <prefix>/<source>/<slug>.
func (g *Gopass) StorePath(c discover.Credential) string {
	prefix := g.Prefix
	if prefix == "" {
		prefix = "imported/"
	}
	return path.Join(prefix, c.Source, slug(c.Identity))
}

// Insert writes one credential's secret into gopass at its StorePath. The
// plaintext is taken from the locked vault buffer and piped directly to gopass
// stdin; we never build a plaintext string or temp file. `-f` forces overwrite;
// caller decides dedupe.
func (g *Gopass) Insert(ctx context.Context, v *vault.Vault, c discover.Credential, force bool) error {
	if err := g.InsertAt(ctx, v, g.StorePath(c), c.Secret, force); err != nil {
		return err
	}
	// Shrink the in-memory window: this secret is now safely in gopass.
	v.Forget(c.Secret)
	return nil
}

// InsertAt writes a secret handle to an exact gopass path. Used by rotation to
// store a freshly minted secret back at the same entry it came from (the credential
// path is known, not recomputed). The plaintext streams from locked memory to
// gopass stdin and is never stringified. Unlike Insert it does NOT forget the
// handle — the caller may still need it (e.g. to re-read/verify).
func (g *Gopass) InsertAt(ctx context.Context, v *vault.Vault, storePath string, secret *vault.Handle, force bool) error {
	buf, err := v.Open(secret)
	if err != nil {
		return err
	}
	args := []string{"insert", "--multiline=false"}
	if force {
		args = append(args, "-f")
	}
	args = append(args, storePath)

	cmd := exec.CommandContext(ctx, g.bin(), args...)
	// buf.Bytes() is the locked memory; gopass reads it from the pipe and GPG-
	// encrypts. The bytes are never copied into a managed Go string.
	cmd.Stdin = bytes.NewReader(buf.Bytes())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("gopass insert %q: %v: %s", storePath, err, stderr.String())
	}
	return nil
}

// Show reads one entry's secret value (`gopass show -o`) into the locked vault and
// returns a handle to it. The plaintext exists only transiently as captured output,
// which is wiped immediately after copying into the vault. Used by rotation to load
// a stored credential for in-place rotation (Mode A — rotate what's in gopass).
func (g *Gopass) Show(ctx context.Context, v *vault.Vault, storePath string) (*vault.Handle, error) {
	cmd := exec.CommandContext(ctx, g.bin(), "show", "-o", storePath)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gopass show %q: %v: %s", storePath, err, stderr.String())
	}
	b := out.Bytes()
	b = bytes.TrimRight(b, "\r\n")
	h := v.Store(b) // Store copies into locked memory and wipes b
	for i := range out.Bytes() {
		out.Bytes()[i] = 0 // belt-and-suspenders: wipe the transient capture buffer
	}
	return h, nil
}

// Remove deletes one entry (`gopass rm -f <path>`). Rotation uses it only to clear a
// "<entry>.pending" copy once the new secret is stored, re-read and re-verified at the
// primary entry. No secret crosses this call.
func (g *Gopass) Remove(ctx context.Context, storePath string) error {
	cmd := exec.CommandContext(ctx, g.bin(), "rm", "-f", storePath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("gopass rm %q: %v: %s", storePath, err, stderr.String())
	}
	return nil
}

// Exists reports whether an entry already exists (for --dedupe).
func (g *Gopass) Exists(ctx context.Context, storePath string) bool {
	cmd := exec.CommandContext(ctx, g.bin(), "ls", "--flat")
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == storePath {
			return true
		}
	}
	return false
}

func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	repl := strings.NewReplacer(" / ", "/", " ", "-", "*", "")
	s = repl.Replace(s)
	// Strip leading dots per path segment. gopass hides dot-prefixed
	// directories/leaves from `ls --flat`, so a segment like ".env" would make
	// the entry invisible to the backup gate's coverage check — silently
	// violating Hard Rule #1 (backup before rotate). See slug regression test.
	segs := strings.Split(s, "/")
	for i, seg := range segs {
		segs[i] = strings.TrimLeft(seg, ".")
	}
	return strings.Join(segs, "/")
}
