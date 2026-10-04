package rotate

import (
	"context"
	"fmt"
	"strings"
	"time"

	"incredigo/internal/discover"
	"incredigo/internal/sink"
	"incredigo/internal/vault"
)

// ExecuteResult records, without any secret, what the REAL rotation spine did for
// one credential.
type ExecuteResult struct {
	Credential discover.Credential
	Driver     string
	StorePath  string // gopass entry the new secret was written to
	Rotated    bool   // a new secret was minted at the provider
	Verified   bool   // the new secret authenticated
	Stored     bool   // the new secret was written to gopass and re-read OK
	Revoked    bool   // RevokeOld was invoked
	Skipped    bool   // gated off by the proof policy — the driver was NOT run
	SkipReason string // why it was gated (only when Skipped)
	Err        error  // first error for this credential, if any
	// PendingPath is set when a copy of the NEW secret was left at "<StorePath>.pending"
	// for the human: the rotation did not complete, and the service may accept only that
	// secret now. Empty on a clean success.
	PendingPath string
}

// PendingSuffix names the gopass entry that holds a new secret from the moment Rotate
// returns until it is stored, re-read and re-verified at the primary entry.
const PendingSuffix = ".pending"

// IsPendingPath reports whether a gopass path is a ".pending" copy (never a credential to
// rotate in its own right).
func IsPendingPath(p string) bool { return strings.HasSuffix(p, PendingSuffix) }

// storeTimeout bounds each gopass write made after the service has changed. Those writes run
// detached from the caller's ctx: once the old secret may be dead, Ctrl-C or a deadline must
// not abort saving the new one.
const storeTimeout = 2 * time.Minute

func detached(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
}

// Execute performs the REAL, destructive rotation spine for every credential a
// registered driver claims, enforcing Hard Rule #2 (verify-new-before-revoke-old):
//
//	Rotate → Verify(new) → store new in gopass → re-read + Verify(stored) → RevokeOld
//
// The old credential is revoked ONLY after the new secret authenticates, is
// persisted, and is read back and re-verified. Any failure short-circuits before
// RevokeOld.
//
// NO LOCKOUT: some drivers change the secret IN PLACE inside Rotate (postgres ALTER
// USER), so the old secret may already be dead when Rotate returns, and the sealed
// backup cannot restore a working one. So the new secret is written to
// "<StorePath>.pending" immediately after Rotate and is never discarded on a later
// failure. That copy is removed only once the primary entry holds the new secret and it
// re-verifies. Every gopass write after Rotate is detached from ctx (see detached).
//
// The MANDATORY backup gate (Snapshot) MUST already have succeeded — Execute does
// not perform it. Each credential's StorePath is taken from c.Location (the exact
// gopass path it was sourced from), so the new secret overwrites the same entry.
//
// Proof gate (Hard Rule spirit — no unattended real cutover through an unvalidated
// path): a driver runs only if its recorded proof level is ≥ MinExecuteProof
// (LIVE-VM). Drivers proven only against an emulator/mock (MOCK-ONLY) or with no
// proof at all (UNPROVEN) are SKIPPED — their Rotate/Verify/RevokeOld are never
// called — unless the caller passes allowMock, the explicit --allow-mock-proven
// opt-in. Skipped credentials leave the old secret fully intact.
func Execute(ctx context.Context, gp *sink.Gopass, creds []discover.Credential, v *vault.Vault, allowMock bool) []ExecuteResult {
	drivers := Drivers()
	var out []ExecuteResult
	for _, c := range creds {
		if ctx.Err() != nil {
			break // cancelled: start no new rotation (the one in flight was secured below)
		}
		var d Rotator
		for _, cand := range drivers {
			if cand.Detect(c) {
				d = cand
				break
			}
		}
		if d == nil {
			continue // no driver claims it — handled by the manual worklist, not here
		}
		res := ExecuteResult{Credential: c, Driver: d.Name(), StorePath: c.Location}

		// Proof gate: refuse to run a driver that has not been proven against real
		// target software, unless the operator explicitly opted in. This is checked
		// BEFORE any provider call, so a gated driver touches nothing.
		if lvl := ProofLevelOf(d.Name()); lvl < MinExecuteProof && !allowMock {
			res.Skipped = true
			res.SkipReason = fmt.Sprintf("proof %s < %s; pass --allow-mock-proven to override", lvl, MinExecuteProof)
			out = append(out, res)
			continue
		}

		newH, err := d.Rotate(ctx, c, v)
		if err != nil && newH == nil {
			res.Err = fmt.Errorf("rotate: %w", err)
			out = append(out, res)
			continue
		}
		res.Rotated = true

		// From here the service may accept ONLY the new secret. Make it durable first.
		pending := res.StorePath + PendingSuffix
		sctx, scancel := detached(ctx)
		perr := gp.InsertAt(sctx, v, pending, newH, true)
		scancel()
		if perr == nil {
			res.PendingPath = pending
		}
		// keep reports a failure that leaves the new secret with the human.
		keep := func(step string, err error) {
			if res.PendingPath != "" {
				res.Err = fmt.Errorf("%s: %w — NEW secret kept at gopass %q; the old one may no longer work", step, err, res.PendingPath)
			} else {
				res.Err = fmt.Errorf("%s: %w — NEW secret could NOT be saved (%v); check the service now", step, err, perr)
			}
			out = append(out, res)
		}
		if err != nil { // Rotate returned a handle WITH an error: outcome unknown
			keep("rotate", err)
			continue
		}
		if ctx.Err() != nil {
			keep("cancelled", ctx.Err())
			continue
		}

		// Verify the new secret authenticates BEFORE it is stored or the old revoked.
		if err := d.Verify(ctx, newH, v); err != nil {
			keep("verify(new)", err)
			continue
		}
		res.Verified = true

		// Persist the new secret at the SAME gopass path (overwrite).
		sctx, scancel = detached(ctx)
		err = gp.InsertAt(sctx, v, res.StorePath, newH, true)
		scancel()
		if err != nil {
			keep("store", err)
			continue
		}
		v.Forget(newH)

		// Re-read what was stored and prove it still authenticates. This closes the
		// gap between "Verify passed on the in-vault value" and "the bytes gopass
		// now holds are the working secret" — only then is revoke safe.
		rh, err := gp.Show(ctx, v, res.StorePath)
		if err != nil {
			keep("re-read", err)
			continue
		}
		if err := d.Verify(ctx, rh, v); err != nil {
			v.Forget(rh)
			keep("verify(stored)", err)
			continue
		}
		v.Forget(rh)
		res.Stored = true

		// The primary entry now holds a verified working secret: the pending copy is done.
		if res.PendingPath != "" {
			sctx, scancel = detached(ctx)
			if err := gp.Remove(sctx, res.PendingPath); err == nil {
				res.PendingPath = ""
			}
			scancel()
		}

		// Only now retire the old credential.
		if err := d.RevokeOld(ctx, c, v); err != nil {
			res.Err = fmt.Errorf("revoke-old: %w", err)
			out = append(out, res)
			continue
		}
		res.Revoked = true
		out = append(out, res)
	}
	return out
}
