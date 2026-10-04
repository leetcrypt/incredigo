// Package rotate is the credential-rotation scaffold.
//
// IMPORTANT — DESIGN PHASE: no Rotator that actually changes a credential at a
// service is implemented. The interface, registry, planning, and the mandatory
// backup gate (see backup.go and docs/ROTATION.md) exist so rotation can be built
// safely later. Today there are zero registered drivers, so PlanAll reports
// "(none)" for every credential and nothing can be rotated.
package rotate

import (
	"context"
	"sort"
	"sync"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// Rotator changes one class of credential at its issuing authority.
//
// Contract (docs/ROTATION.md §5): Rotate mints and returns a NEW secret but MUST
// NOT revoke the old one. RevokeOld runs only after the new value has been
// verified against the service AND stored in gopass. A backup (see Snapshot) must
// already exist before Rotate is ever called.
type Rotator interface {
	Name() string
	// Detect reports whether this driver handles the given credential.
	Detect(c discover.Credential) bool
	// Rotate mints a new secret at the provider and returns a vault handle to it.
	// It must not revoke or invalidate the old credential.
	Rotate(ctx context.Context, c discover.Credential, v *vault.Vault) (*vault.Handle, error)
	// Verify proves the newly minted secret actually authenticates.
	Verify(ctx context.Context, newSecret *vault.Handle, v *vault.Vault) error
	// RevokeOld retires the previous credential — only after verify + store. It
	// receives the vault so a driver can read the OLD secret (c.Secret) when
	// revocation needs it (e.g. SSH: derive the old public key to remove from
	// authorized_keys). In-place engines (postgres) ignore it.
	RevokeOld(ctx context.Context, c discover.Credential, v *vault.Vault) error
}

var (
	regMu    sync.Mutex
	registry []Rotator
)

// Register adds a rotation driver. (No real driver registers yet.)
func Register(r Rotator) {
	regMu.Lock()
	defer regMu.Unlock()
	registry = append(registry, r)
}

// Drivers returns the registered rotators, sorted by name.
func Drivers() []Rotator {
	regMu.Lock()
	defer regMu.Unlock()
	out := append([]Rotator(nil), registry...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// Plan is the non-destructive decision for one credential: which driver would
// handle it, or none.
type Plan struct {
	Credential discover.Credential
	Driver     string // "" when no registered driver claims the credential
}

// PlanAll classifies credentials against the registered drivers WITHOUT changing
// anything. With no drivers registered (the current state) every Plan.Driver is "".
func PlanAll(creds []discover.Credential) []Plan {
	drivers := Drivers()
	plans := make([]Plan, 0, len(creds))
	for _, c := range creds {
		p := Plan{Credential: c}
		for _, d := range drivers {
			if d.Detect(c) {
				p.Driver = d.Name()
				break
			}
		}
		plans = append(plans, p)
	}
	return plans
}
