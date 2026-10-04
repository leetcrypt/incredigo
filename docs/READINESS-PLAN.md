# Readiness plan — from "works in the lab" to "safe to run for a client" (2026-09-30)

Written after the ultrareview fixes (`docs/REVIEW-FIXES-PLAN.md`) merged at `37bbb68`.
Complements `docs/ROADMAP.md`: the roadmap orders *features*. This plan orders the *safety
and test work* that must land before incredigo touches anyone else's credentials. Same
contract as always: one objective per branch, test-first, `go test ./... -race` green,
coverage not regressed, a human reviews and merges.

| # | Item | Why it blocks client use | Branch | Status |
|---|------|--------------------------|--------|--------|
| R1 | `Execute` never forgets a new secret after the service changed | **lockout** of in-place credentials (DB users) | `fix/execute-pending-store` | fixed (awaiting review) |
| R2 | Fault-injection matrix for the spine | proves R1 and catches the next #3-class bug | `fix/execute-pending-store` | done: 11 faults × 2 modes |
| R3 | Rotation-in-flight journal + reconcile on start | a crash between Rotate and the pending store | `feat/rotate-journal` | partial: CLI holds back entries with a `.pending` |
| R4 | Run lock (one rotation run per store) | timer + manual run racing on one credential | `feat/rotate-run-lock` | planned |
| R5 | "Backup contains every rotated entry" assertion, all entry points | generalizes ultrareview #1 | `test/backup-covers-rotated` | planned |
| R6 | Secret-leak sweep: logs, audit, `--json`, errors, argv, env, server-side | client data handling | `test/no-secret-leak-sweep` | planned |
| R7 | Postgres: send a pre-hashed (SCRAM) password, not plaintext `ALTER … PASSWORD` | the server's own statement log may record the password | `fix/postgres-prehashed-password` | planned |
| R8 | CLI gate-refusal coverage (`cmd/incredigo` 44%, host 39%) | gates must be proven at the CLI | `test/cli-gate-refusals` | planned |
| R9 | Review leftovers: SSH `migrate` blob (#5), labs handle `ErrOutcomeUnknown` | known gaps | per item | backlog |
| R10 | Consumer propagation (update apps that use a rotated secret) | rotating without it = client outage | `feat/blast-propagate` | design |

---

## R1 — `Execute` keeps the new secret durable from the moment it exists

**Defect (verified):** `internal/rotate/execute.go` calls `v.Forget(newH)` when Verify or the
gopass store fails. That is safe only for create-then-revoke drivers. In-place drivers
(`postgres` runs `ALTER USER … PASSWORD` inside `Rotate`) have already killed the old secret,
so a failed store, a network blip during Verify, or Ctrl-C locks the account out. The sealed
backup cannot help, because it holds the old, now-dead password. The CLI then prints "old
credential(s) left intact", which is false in this case.

**Fix:**
1. Right after `Rotate` returns a handle, write it to `<StorePath>.pending` **before** Verify.
2. Never `Forget` the new secret on a later failure. Report `PendingPath` in `ExecuteResult`
   and name it in the error.
3. The store steps after Rotate run on `context.WithoutCancel(ctx)` with their own timeout,
   because once the service has changed, Ctrl-C must not abort saving the secret.
4. On full success (stored, re-read, re-verified), remove the `.pending` entry. If removal
   fails, the run still succeeds, but the leftover is reported.
5. A `Rotate` that returns a handle **with** an error (browserrot `ErrOutcomeUnknown`) is
   stored to `.pending` too.
6. CLI: `.pending` entries are never treated as credentials to rotate. They are listed for
   the human instead. The failure message no longer claims the old secret is intact.

## R2 — Fault-injection matrix (tests for R1)

A fake service with a current password, used in two modes (**in-place** and
**create-then-revoke**), × a fault at each step: Verify(new), store, re-read,
Verify(stored), revoke, and context cancelled mid-rotate. Invariant, asserted after every
case:

> at least one secret held in gopass (primary entry or `.pending`) authenticates at the
> service.

On full success: the primary entry holds the working secret, no `.pending` remains, and the
old secret is revoked (create-then-revoke mode).

**Landed (R1+R2):** with the old `Execute`, the matrix showed **4 real lockouts** for
in-place credentials: a Verify blip, a store failure, Ctrl-C right after Rotate, and an
outcome-unknown Rotate. All 22 cases now hold the no-lockout invariant. `Gopass.Remove`
was added for the cleanup. Coverage: rotate 79.6→81.2%, sink 94.5→94.6%, cmd 44.3→45.8%.
Side note: 19 files in `internal/rotate` are not gofmt-clean on master (pre-existing,
untouched here); a `gofmt -l` CI step would catch that.

## R3 — Journal (planned)

A secrets-free intent record (`~/.incredigo/journal/<entry>.json`: entry, driver, phase,
time), written before `Rotate` and cleared on success. On start, `rotate --execute` refuses
to touch an entry that has a journal record or a `.pending` sibling until the human
reconciles it. This closes the remaining window between `Rotate` returning and the
`.pending` write.

## R4–R10

Scopes are as in the table. Each gets its own section here when it starts.

---

## Beyond code — before offering this to a client

- **Delivery model:** run on the client's machines (managed engagement) or have them run it
  with support. Don't host client secrets yourself; that contradicts the local-first design.
- **Independent security review**, especially of the MV3 extension (`<all_urls>` +
  native messaging).
- **Signed, reproducible releases** with pinned dependencies and an SBOM (ROADMAP M5).
- **Client policy:** only LIVE-VM/LIVE-REAL drivers, a dry-run report signed off before
  every real run, and a maintenance window.
- **Runbook:** `.pending` reconciliation, restore drill, rollback, escalation contacts.
- **Business:** written per-system authorization, liability limits, E&O/cyber insurance.
