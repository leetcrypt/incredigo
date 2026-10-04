# Review-fixes plan — ultrareview of master @ c0c5b84 (2026-09-26)

Source: cloud ultrareview of `master` (32 files, +5363/−160). Four findings introduced by the
browserrot-host / extension-driver work, one pre-existing. Each fix follows the repo contract
(`CLAUDE.md`): **one objective, one branch, one worktree**, test-first, `go test ./... -race`
green, coverage on the touched package not regressed, human review + merge. Order is by safety
impact.

| # | Finding | Severity | Branch | Status |
|---|---------|----------|--------|--------|
| 1 | Backup gate hardcodes prefix `"gitea"` | **safety-rail #4** | `fix/browserrot-host-backup-prefix` | fixed (awaiting review) |
| 2 | Extension session never pins a tab id | secret mis-delivery | `fix/browserrot-ext-pin-tab` | fixed (awaiting review) |
| 3 | Post-submit `text` read races page load → new secret forgotten | **lockout** | `fix/browserrot-post-submit-wait` | fixed (awaiting review; stacked on #1 + #2) |
| 4 | `.gitea/workflows/ci.yml` deleted in working tree | CI gate lost | none (working-tree restore) | restored 2026-09-27 |
| 5 | SSH blob has no first-write producer (pre-existing) | feature gap | `fix/ssh-migrate-blob` | backlog |

---

## 1 — Backup gate must cover the credential actually rotated

**Where:** `cmd/incredigo-browserrot-host/main.go` `run()` →
`rotate.Snapshot(ctx, gp, "gitea", …)`.

**Defect:** the rotated entry is `cfg.StorePath = joinStore(INCREDIGO_STORE_PREFIX,
INCREDIGO_CREDENTIAL)`, but the backup exports only paths with the string prefix `gitea`
(`sink.Gopass.ListPaths` → `strings.HasPrefix`). With `imported/gitea/login-creds` the
credential being rotated is **not** in the sealed backup, yet the gate reports OK and rotation
proceeds. That breaks Hard Rule 1 / safety rail #4.

**Fix:**
1. Extract a `backupGate(ctx, gp, storePath, sealer, pass, out) (int, error)` helper so the
   gate can be unit-tested against a fake gopass (the same pattern as `internal/rotate/backup_test.go`).
2. Snapshot with `prefix = cfg.StorePath`, not a literal. The prefix match may also pick up
   siblings (e.g. `…/login-creds-old`). Backing up extra entries is fine; missing one is not.
3. **Fail closed:** before sealing, require that `gp.ListPaths(ctx, storePath)` contains
   `storePath` *exactly*. Otherwise refuse with "backup would not contain the rotated entry".
   Also refuse if the sealed count is 0.
4. Update the log line (`BACKUP_GATE_OK: … entr(ies) under %q`) so it no longer claims "gitea".

**Tests (table-driven, `cmd/incredigo-browserrot-host/main_test.go`):**
- default path `gitea/login-creds` → gate OK, the bundle opens and contains that path byte-equal.
- `imported/gitea/login-creds` (the regression) → gate OK and the bundle contains the entry
  (this fails on the old code).
- the entry is missing from the store → error, no bundle left on disk.
- an unrelated `gitea/other` entry is not required. Only the rotated entry is asserted.

**Done when:** new tests fail on `c0c5b84` and pass on the branch, and `go test ./... -race` is green.

## 2 — Pin the extension session to one tab

**Where:** `internal/browserrot/extension/background.js` (`open`, `activeTab`,
`gotoActiveTab`, `relayToContent`), `internal/browserrot/extension.go` (`extSession`).

**Defect:** every command re-resolves "active tab of last-focused window". If focus changes
mid-rotation, `fill` (old/new/confirm secrets) can land in an unrelated tab.

**Fix:**
1. `open` captures the active tab **once** and stores `sessionTabId` (plus `windowId`) in
   the background worker's state. It returns `{ok:true, tabId}`.
2. `goto`/`fill`/`click`/`text` operate on `sessionTabId` only. They never call `activeTab()`
   after `open`. If that tab is gone (`chrome.tabs.get` throws / `onRemoved`), the command
   errors: "session tab closed". It never falls back to whatever tab is active.
3. Optionally, `fill` asserts that the tab's URL origin still equals the origin `goto` reached.
   On a mismatch it refuses, so secrets are never typed into a different origin.
4. `close` clears `sessionTabId`. A second `open` while a session is live errors.
5. Go side: `extSession` records the returned `tabId` for logging/diagnostics only. The
   extension is authoritative.

**Tests:**
- Go: extend the fake native-messaging peer in `extension_test.go` so the `open` reply
  carries `tabId`, and assert the session surfaces an error when the peer reports "session tab
  closed". Assert that Rotate keeps the old secret (no store) on that error.
- JS: if there is no JS harness yet, add a minimal Node test (`node --test`) with a stubbed
  `chrome.tabs` that switches the active tab between `goto` and `fill`, and asserts that the
  `fill` is sent to the pinned tab id. Otherwise, document a manual check in
  `lab/extension-proof.md`.

## 3 — Wait for navigation after submit; never forget a possibly-applied secret

**Where:** `internal/browserrot/browserrot.go` `Rotate` (the post-`fillForm` `r.text`),
`background.js` `relayToContent`.

**Defect:** submit navigates and the content script is torn down. The immediate `text` read
can hit "content script unreachable". `Rotate` then calls `v.Forget(newH)` and returns an
error, **but the site may already have applied the new password**. That is a lockout: the old
secret is dead and the new one is gone. This is more severe than the review graded it.

**Fix (two layers):**
1. **Extension:** `click` with a `navigates` hint (or always, for the submit) waits for
   `tabs.onUpdated` `status:'complete'` on the pinned tab (fix #2), with a bounded timeout. A
   `text` read retries `sendMessage` briefly (e.g. 10 × 300 ms) while the content script
   re-injects.
2. **Engine (driver-agnostic):** after the submit, an **ambiguous** outcome (read error, as
   opposed to a read that returned a non-success marker) must NOT forget `newH`. Return a
   distinct `ErrOutcomeUnknown` together with `newH`. The caller then stores the new secret
   under a staging path (`<StorePath>.pending`) or re-logs in with the new secret to decide.
   It never discards it. The old secret stays in the primary entry until verification.
   Decide the exact caller contract during implementation (host `run()` and the CLI rotate path).

**Tests:**
- fake Session whose `Text` fails once post-submit then succeeds → Rotate succeeds.
- fake Session whose `Text` always fails post-submit → `ErrOutcomeUnknown`, `newH` still
  readable from the vault, and the primary store entry untouched.
- a success-marker mismatch keeps the current behaviour: forget `newH`, old kept.

## 4 — Restore CI workflow

**Where:** `.gitea/workflows/ci.yml` (deleted in the master working tree, not in a commit;
last touched in `f8e93e8`).

**Action:** confirm with the owner that the deletion is unintended, then
`git restore .gitea/workflows/ci.yml` on master. If the deletion *was* intended (e.g. moving
CI elsewhere), land the replacement in the same change instead. Re-run the ultrareview after
the restore so it sees the real tree.

## 5 — (pre-existing, backlog) SSH blob first-write

**Where:** `cmd/incredigo/main.go` `migrateCmd` → `gp.Insert`, `internal/discover/ssh.go`,
`internal/rotate/sshkey.go` `buildSSHBlob`.

**Defect:** `migrate` inserts the raw multi-line PEM with `--multiline=false`, so gopass keeps
only line 1, and `ssh_addr`/`ssh_user` are never stored. `rotate --execute` cannot use an SSH
entry that came from `migrate`.

**Fix sketch:** for `Source == ssh`, `migrate` writes `buildSSHBlob(...)`, or refuses and tells
the user to supply `ssh_addr`/`ssh_user`. Add a round-trip test: migrate → show → decode →
PEM byte-equal. Scheduled after 1–3.

---

## Implementation notes (as landed)

- **#2:** the fill origin guard is implemented (step 3). A second `open` re-pins instead of
  erroring (step 4), because the engine opens one session per Rotate/Verify/probe. The JS
  harness is `internal/browserrot/testdata/background_harness.js`, run by
  `extension_harness_test.go` (skipped without `node`).
- **#3:** instead of a caller-side staging decision, `Rotate` settles the ambiguity itself
  (`resolveOutcome`). It first retries the result read (`readResult`), then tries logging in
  with the NEW password (success means the change landed, so Rotate succeeds), then the OLD
  one (success means it did not land, so the new secret is forgotten). Only when neither is
  proven does it return `(newH, ErrOutcomeUnknown)`. A lost submit-click reply goes through
  the same path. A result that WAS read without the success marker stays a definite failure
  with no probes, which keeps the MFA contract. The host saves the new secret at
  `<entry>.pending` (`outcomeUnknown`). The extension waits for the post-click navigation
  and retries `text` (never `fill`/`click`) until the new page's content script answers.

### Follow-ups (not in #1–#3)

- `lab/browser-proof` and `lab/rung4-gitea-browser` do not handle `ErrOutcomeUnknown`: they
  report the error and drop the handle. These targets are disposable, so this is low
  priority, but mirror the host's `outcomeUnknown` if they are reused.
- `rotate.Execute` ignores a non-nil handle returned with an error. No browser rotator is
  wired into it today. Before one is, teach it the `ErrOutcomeUnknown` contract.
