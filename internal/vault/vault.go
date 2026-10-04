// Package vault is the RAM-only custody core of incredigo.
//
// All decrypted secret material lives here and nowhere else. Buffers are backed
// by github.com/awnumar/memguard, which mlocks the pages (no swap), marks them
// MADV_DONTDUMP (no core dumps), surrounds them with guard pages, and zeroizes
// on Destroy. Plaintext is never returned as a Go string (strings are immutable,
// GC-managed and cannot be reliably wiped) — callers receive a Handle and must
// Open it for a short-lived locked buffer they then Destroy.
package vault

import (
	"fmt"
	"sync"

	"github.com/awnumar/memguard"
)

// Handle is an opaque reference to a secret stored in the vault. It contains no
// plaintext and is safe to pass around, log (it has no String of the secret),
// and embed in metadata records.
type Handle struct {
	id uint64
}

// Vault owns every live secret buffer for the process lifetime.
type Vault struct {
	mu   sync.Mutex
	next uint64
	bufs map[uint64]*memguard.LockedBuffer
}

// New creates a vault and installs a signal handler so secrets are purged from
// memory on SIGINT/SIGTERM as well as normal exit.
func New() *Vault {
	memguard.CatchInterrupt() // wipes all locked buffers on interrupt, then exits
	return &Vault{bufs: make(map[uint64]*memguard.LockedBuffer)}
}

// Store copies plaintext into a freshly locked buffer and wipes the caller's
// slice. The returned Handle is the only way back to the bytes.
func (v *Vault) Store(plaintext []byte) *Handle {
	v.mu.Lock()
	defer v.mu.Unlock()

	buf := memguard.NewBufferFromBytes(plaintext) // also wipes the source slice
	id := v.next
	v.next++
	v.bufs[id] = buf
	return &Handle{id: id}
}

// Open returns the locked buffer for a handle. The caller MUST treat the bytes
// as ephemeral: use them immediately (e.g. write to a pipe) and do not copy them
// into a string. The buffer is owned by the vault; do not Destroy it directly —
// use Forget or Purge.
func (v *Vault) Open(h *Handle) (*memguard.LockedBuffer, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	buf, ok := v.bufs[h.id]
	if !ok {
		return nil, fmt.Errorf("vault: unknown or already-purged handle %d", h.id)
	}
	return buf, nil
}

// Forget destroys (zeroizes + unlocks) a single secret as soon as it is no
// longer needed, shrinking the in-memory window.
func (v *Vault) Forget(h *Handle) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if buf, ok := v.bufs[h.id]; ok {
		buf.Destroy()
		delete(v.bufs, h.id)
	}
}

// Purge zeroizes and frees every secret. Call from a deferred cleanup at the top
// of every command so plaintext never outlives the run.
func (v *Vault) Purge() {
	v.mu.Lock()
	defer v.mu.Unlock()

	for id, buf := range v.bufs {
		buf.Destroy()
		delete(v.bufs, id)
	}
	memguard.Purge()
}
