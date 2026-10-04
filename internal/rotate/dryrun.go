package rotate

import (
	"context"

	"incredigo/internal/discover"
	"incredigo/internal/vault"
)

// DryRunResult records, without any secret, what the rotation spine did for one
// credential during a dry run.
type DryRunResult struct {
	Credential discover.Credential
	Driver     string
	Rotated    bool  // a new secret was minted in-vault
	Verified   bool  // the new secret passed Verify
	Revoked    bool  // RevokeOld was invoked (no real effect for the noop driver)
	Err        error // first error encountered for this credential, if any
}

// DryRun walks the post-backup rotation spine — Detect → Rotate → Verify →
// RevokeOld — for every credential that driver d claims, WITHOUT storing
// anything in gopass and WITHOUT persisting the minted secret (it is Forgotten
// from the vault immediately after). It exists so the full flow can be exercised
// against the noop driver (docs/ROTATION.md §6 step 1) touching no service.
//
// The MANDATORY backup gate (Snapshot) is the caller's responsibility and must
// already have succeeded; DryRun does not perform it.
func DryRun(ctx context.Context, d Rotator, creds []discover.Credential, v *vault.Vault) []DryRunResult {
	var out []DryRunResult
	for _, c := range creds {
		if !d.Detect(c) {
			continue
		}
		res := DryRunResult{Credential: c, Driver: d.Name()}

		newH, err := d.Rotate(ctx, c, v)
		if err != nil {
			res.Err = err
			out = append(out, res)
			continue
		}
		res.Rotated = true

		// Verify-before-revoke: only proceed to revoke once the new secret checks out.
		if err := d.Verify(ctx, newH, v); err != nil {
			res.Err = err
			v.Forget(newH)
			out = append(out, res)
			continue
		}
		res.Verified = true

		// A real run stores the new secret in gopass here; a dry run does not.
		if err := d.RevokeOld(ctx, c, v); err != nil {
			res.Err = err
		} else {
			res.Revoked = true
		}

		v.Forget(newH) // never persist the minted secret in a dry run
		out = append(out, res)
	}
	return out
}
