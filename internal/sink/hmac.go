package sink

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/awnumar/memguard"
)

// HMACSealer is an authenticated Sealer that needs no age dependency — only the
// openssl CLI. It is encrypt-then-MAC:
//
//   - confidentiality: AES-256-CTR via `openssl enc`, key = PBKDF2(passphrase,
//     salt) (the salt rides in openssl's `Salted__` header).
//   - integrity: HMAC-SHA256 over the ciphertext, key = the passphrase bytes,
//     computed in-process.
//
// The MAC is verified BEFORE any decryption, so a tampered or corrupt bundle is
// rejected rather than silently decrypted (the property plain `openssl enc`
// can't give on OpenSSL 3.x, which refuses AEAD ciphers).
//
// Bundle layout:  HMAC-SHA256(32 bytes) || openssl-CTR-ciphertext
//
// Unlike the age sealer, the passphrase here is never a Go string: openssl gets
// the cipher key over fd 3, and the MAC key is the locked-buffer bytes.
//
// Hand recovery (also in docs/SECURITY.md):
//
//	head -c 32 bundle > mac.bin
//	tail -c +33 bundle > ct.bin
//	openssl dgst -sha256 -hmac "$PASS" -binary ct.bin | cmp - mac.bin   # integrity gate
//	openssl enc -d -aes-256-ctr -pbkdf2 -iter 600000 -pass pass:"$PASS" -in ct.bin
type HMACSealer struct {
	Bin  string // default "openssl"
	Iter int    // default 600000
}

func (h *HMACSealer) bin() string {
	if h.Bin == "" {
		return "openssl"
	}
	return h.Bin
}

func (h *HMACSealer) iter() int {
	if h.Iter == 0 {
		return 600000
	}
	return h.Iter
}

func (h *HMACSealer) Name() string { return "hmac" }

func (h *HMACSealer) cipher(ctx context.Context, decrypt bool, in io.Reader, out io.Writer, pass *memguard.LockedBuffer) error {
	args := []string{"enc", "-aes-256-ctr", "-pbkdf2", "-iter", fmt.Sprint(h.iter()), "-pass", "fd:3"}
	if decrypt {
		args = append(args, "-d")
	} else {
		args = append(args, "-salt")
	}
	return opensslEnc(ctx, h.bin(), args, in, out, pass)
}

func (h *HMACSealer) Seal(ctx context.Context, plaintext io.Reader, out io.Writer, pass *memguard.LockedBuffer) error {
	// Encrypt to a buffer (ciphertext is not secret), MAC it, then write
	// mac || ciphertext so the reader can authenticate before decrypting.
	var ct bytes.Buffer
	if err := h.cipher(ctx, false, plaintext, &ct, pass); err != nil {
		return err
	}
	mac := hmac.New(sha256.New, pass.Bytes())
	mac.Write(ct.Bytes())
	if _, err := out.Write(mac.Sum(nil)); err != nil {
		return err
	}
	_, err := out.Write(ct.Bytes())
	return err
}

func (h *HMACSealer) Open(ctx context.Context, in io.Reader, out io.Writer, pass *memguard.LockedBuffer) error {
	all, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	if len(all) < sha256.Size {
		return fmt.Errorf("hmac: bundle too short (%d bytes)", len(all))
	}
	want, ct := all[:sha256.Size], all[sha256.Size:]

	mac := hmac.New(sha256.New, pass.Bytes())
	mac.Write(ct)
	if !hmac.Equal(want, mac.Sum(nil)) {
		return fmt.Errorf("hmac: authentication failed (wrong passphrase, or tampered/corrupt bundle)")
	}
	return h.cipher(ctx, true, bytes.NewReader(ct), out, pass)
}
