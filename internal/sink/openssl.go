package sink

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/awnumar/memguard"
)

// OpenSSL is a non-default Sealer kept for environments that have the openssl CLI
// but not age, and for hand-restorability with a one-line openssl command.
//
//	openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -in backup.enc
//
// IMPORTANT — this mode is UNAUTHENTICATED. OpenSSL 3.x's `enc` command refuses
// AEAD ciphers ("AEAD ciphers not supported"), so there is no GCM/Poly1305 tag:
// a tampered or truncated bundle will decrypt to garbage with no error. Prefer the
// age sealer (see age.go), which is authenticated, for any backup you care about.
//
// The passphrase is handed to openssl over an inherited file descriptor
// (`-pass fd:3`), never via argv (visible in `ps`) or the environment (visible in
// /proc/<pid>/environ). The bytes come straight from a locked buffer.
type OpenSSL struct {
	Bin  string // default "openssl"
	Iter int    // default 600000
}

func (o *OpenSSL) bin() string {
	if o.Bin == "" {
		return "openssl"
	}
	return o.Bin
}

func (o *OpenSSL) iter() int {
	if o.Iter == 0 {
		return 600000
	}
	return o.Iter
}

func (o *OpenSSL) Name() string { return "openssl" }

func (o *OpenSSL) run(ctx context.Context, decrypt bool, in io.Reader, out io.Writer, pass *memguard.LockedBuffer) error {
	args := []string{"enc", "-aes-256-cbc", "-pbkdf2", "-iter", fmt.Sprint(o.iter()), "-pass", "fd:3"}
	if decrypt {
		args = append(args, "-d")
	} else {
		args = append(args, "-salt")
	}
	return opensslEnc(ctx, o.bin(), args, in, out, pass)
}

func (o *OpenSSL) Seal(ctx context.Context, plaintext io.Reader, out io.Writer, pass *memguard.LockedBuffer) error {
	return o.run(ctx, false, plaintext, out, pass)
}

func (o *OpenSSL) Open(ctx context.Context, in io.Reader, out io.Writer, pass *memguard.LockedBuffer) error {
	return o.run(ctx, true, in, out, pass)
}

// opensslEnc runs `openssl <args...>` with stdin/stdout wired to in/out and the
// passphrase delivered over inherited fd 3. The caller must include
// `-pass fd:3` in args. The passphrase bytes come straight from a locked buffer —
// they never appear in argv (visible in `ps`) or the environment (visible in
// /proc/<pid>/environ). Shared by the OpenSSL and HMAC sealers.
func opensslEnc(ctx context.Context, bin string, args []string, in io.Reader, out io.Writer, pass *memguard.LockedBuffer) error {
	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = in
	cmd.Stdout = out
	cmd.ExtraFiles = []*os.File{pr} // child sees this as fd 3
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		pr.Close()
		pw.Close()
		return err
	}
	pr.Close() // the child holds its own copy of the read end

	// Feed the passphrase from locked memory, then close so openssl sees EOF.
	_, werr := pw.Write(pass.Bytes())
	pw.Close()

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%s: %v: %s", bin, err, stderr.String())
	}
	return werr
}
