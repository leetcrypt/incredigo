package rotate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// NoopRotator is a dry-run Rotator that exercises the full rotation flow —
// Detect → Rotate → Verify → RevokeOld — WITHOUT contacting any service or
// changing any real credential. It mints a random in-vault "new" secret so the
// safety spine (backup → rotate → verify → store → revoke) can be tested
// end-to-end (docs/ROTATION.md §6 build-order step 1).
//
// It is intentionally NOT registered in the global registry: the production
// `rotate` command must still report zero drivers and refuse --execute (see
// cmd/incredigo and CLAUDE.md hard rules). Wire it up explicitly in tests, or
// later behind an opt-in dry-run flag.
type NoopRotator struct {
	mu      sync.Mutex
	revoked []string // identities passed to RevokeOld, for assertions
}

// Name identifies the driver in plans and audit records.
func (r *NoopRotator) Name() string { return "noop" }

// Detect matches every credential — the dry run applies to anything.
func (r *NoopRotator) Detect(discover.Credential) bool { return true }

// Rotate mints a fresh random secret in the vault and returns its handle. It
// contacts no provider and leaves the old credential untouched, honoring the
// Rotator contract (mint new, never revoke here).
func (r *NoopRotator) Rotate(ctx context.Context, c discover.Credential, v *vault.Vault) (*vault.Handle, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	enc := make([]byte, hex.EncodedLen(len(raw)))
	hex.Encode(enc, raw)
	for i := range raw { // wipe the random source; Store wipes enc itself
		raw[i] = 0
	}
	return v.Store(enc), nil
}

// Verify confirms the freshly minted secret is in custody and non-empty. A real
// driver would authenticate it against the service; the noop only checks that
// the new value survived rotation, so verify-before-revoke ordering is testable.
func (r *NoopRotator) Verify(ctx context.Context, newSecret *vault.Handle, v *vault.Vault) error {
	buf, err := v.Open(newSecret)
	if err != nil {
		return err
	}
	if buf.Size() == 0 {
		return errors.New("noop verify: new secret is empty")
	}
	return nil
}

// RevokeOld retires nothing — there is no real provider — but records the
// identity so a test can assert revoke ran only after verify. Mirrors the
// safety-spine ordering without any destructive effect.
func (r *NoopRotator) RevokeOld(ctx context.Context, c discover.Credential, v *vault.Vault) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked = append(r.revoked, c.Identity)
	return nil
}

// Revoked returns a copy of the identities whose RevokeOld was invoked.
func (r *NoopRotator) Revoked() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.revoked...)
}
