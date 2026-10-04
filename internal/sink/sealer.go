package sink

import (
	"context"
	"io"

	"github.com/awnumar/memguard"
)

// Sealer produces and opens portable, agent-independent encrypted backup bundles.
//
// gopass already GPG-encrypts every entry, so incredigo deliberately does NOT
// double-wrap individual secrets. A Sealer instead seals the whole exported set
// into one blob that can be restored on a bare machine with nothing but this one
// tool and a passphrase — no gpg-agent, no keyring.
//
// openssl is the default implementation (see openssl.go). Because this is an
// interface, a contributor can drop in age (github.com/FiloSottile/age) without
// touching anything else in incredigo.
type Sealer interface {
	Name() string
	Seal(ctx context.Context, plaintext io.Reader, out io.Writer, pass *memguard.LockedBuffer) error
	Open(ctx context.Context, in io.Reader, out io.Writer, pass *memguard.LockedBuffer) error
}
