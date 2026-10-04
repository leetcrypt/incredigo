package sink

import (
	"context"
	"fmt"
	"io"

	"filippo.io/age"
	"github.com/awnumar/memguard"
)

// Age is the default Sealer. It wraps the bundle in the age format
// (ChaCha20-Poly1305 payload, scrypt-derived key from the passphrase), which is
// authenticated: a corrupted or tampered backup fails to open rather than
// decrypting to silent garbage. A bundle can also be restored by hand with the
// standard `age` CLI: `age -d backup.incredigo.age`.
//
// Passphrase caveat: age's NewScrypt{Recipient,Identity} take a Go string, so the
// passphrase transits an (immutable, un-zeroable) Go string for the duration of
// the operation. The stored secrets themselves never do — they stream through as
// bytes (see bundle.go). This is the one place incredigo's RAM-only guarantee is
// reduced to "the passphrase, not the vaulted secrets."
type Age struct {
	// WorkFactor is the scrypt log2(N) cost. Default 18 (~256 MiB) — a deliberate
	// brute-force speed bump for a passphrase-protected disaster-recovery bundle.
	WorkFactor int
}

func (a *Age) Name() string { return "age" }

func (a *Age) workFactor() int {
	if a.WorkFactor == 0 {
		return 18
	}
	return a.WorkFactor
}

func (a *Age) Seal(ctx context.Context, plaintext io.Reader, out io.Writer, pass *memguard.LockedBuffer) error {
	r, err := age.NewScryptRecipient(string(pass.Bytes()))
	if err != nil {
		return fmt.Errorf("age: recipient: %w", err)
	}
	r.SetWorkFactor(a.workFactor())
	w, err := age.Encrypt(out, r)
	if err != nil {
		return fmt.Errorf("age: encrypt: %w", err)
	}
	if _, err := io.Copy(w, plaintext); err != nil {
		_ = w.Close()
		return fmt.Errorf("age: write: %w", err)
	}
	return w.Close()
}

func (a *Age) Open(ctx context.Context, in io.Reader, out io.Writer, pass *memguard.LockedBuffer) error {
	id, err := age.NewScryptIdentity(string(pass.Bytes()))
	if err != nil {
		return fmt.Errorf("age: identity: %w", err)
	}
	r, err := age.Decrypt(in, id)
	if err != nil {
		return fmt.Errorf("age: decrypt (wrong passphrase or corrupt bundle?): %w", err)
	}
	if _, err := io.Copy(out, r); err != nil {
		return fmt.Errorf("age: read: %w", err)
	}
	return nil
}
