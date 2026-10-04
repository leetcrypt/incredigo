# incredigo — development roadmap to a stable, valuable rotation system

Written 2026-07-14 against commit `d237098`. Current state:
[`STATE-2026-07-14.md`](STATE-2026-07-14.md). Ordering principle: **reliability of
the safety spine first, then real rotations one credential at a time, then the
headless turnover loop that is the actual product value, then Phase B.**

## Definition of done ("stable, usable, adds security value")

A user can run **one headless command** (cron/systemd-timer friendly) that:

1. discovers credential sprawl (or reads gopass — Mode A),
2. produces a **verified sealed backup** before touching anything,
3. rotates every credential a proven driver claims (verify-new-before-revoke-old),
4. emits a secrets-free guided worklist for everything else,
5. leaves a redacted audit trail and a restorable backup chain,

and every driver that can run `--execute` against a real service has a recorded
**LIVE-VM or LIVE-REAL proof** — no unproven code path can destroy a credential.

---

## M0 — Housekeeping (small, do first)

- [ ] Update `CLAUDE.md` "Where development is": 22 drivers exist, execute spine
      wired behind `INCREDIGO_ALLOW_EXECUTE=1`, 8 LIVE-VM / 14 MOCK-ONLY, Phase B
      scaffolded. The "zero drivers" claim actively misleads future sessions.
- [ ] Commit the pending `.gitignore` change; fix upstream tracking
      (`master...origin/master [gone]`) and push to gitea when authorized.
- [ ] Gitignore `incredigo-map.html` (build artifact) or regenerate per release.
- [ ] Bring `lab-provision-*.sh` into the repo under `lab/` (they contain no
      secrets — fake creds only). LIVE-VM proofs must be reproducible from a fresh
      clone. Add `lab/README.md` mapping script → driver → proof.

## M1 — Harden the safety spine (test debt on the critical path)

The backup gate is only as trustworthy as the sealers. **This blocks all real
rotation work.**

- [ ] `internal/sink` 30% → ≥85%:
  - Round-trip per sealer (age/hmac/openssl): seal → open → byte-equal.
  - Tamper tests: flip a byte in ciphertext/MAC → age & hmac MUST fail closed;
    document openssl (unauthenticated) failure mode honestly.
  - Wrong-passphrase → clean error, no partial plaintext.
  - `Gopass` wrapper vs fake binary: insert/show/list/exists, stdin streaming
    (assert no secret ever appears in argv or a temp file).
  - Bundle framing: truncated stream, oversized path, zero-record bundle.
- [ ] `cmd/incredigo` 4.3% → meaningful integration coverage (fixture HOME +
      `GOPASS_HOMEDIR` + fake gopass, pattern already exists in
      `internal/rotate/backup_test.go`):
  - scan/status/worklist happy paths; migrate --dedupe/--force.
  - export→import round-trip through the real CLI.
  - **Gate refusals**: `rotate --execute` without `INCREDIGO_ALLOW_EXECUTE=1`;
    backup-verify failure aborts before any driver runs; missing passphrase.
- [ ] `internal/policy` 65.8% / `internal/tui` 57.1% → fill parsing and view gaps.
- [ ] CI on gitea (Actions): `go build ./... && go vet ./... && go test -race
      ./...` + coverage floor per package (fail under 70%; sink/rotate/vault 85%).
- [ ] Add a `make` or `just` file: `build / test / race / cover / vm-proof
      DRIVER=x / map`.

Exit criteria: safety-critical packages ≥85%, CI green on push, gate-refusal
paths proven at the CLI level.

## M2 — First real rotations (Mode A, safe-candidate ladder)

Rule (unchanged): **one credential at a time, explicit authorization per
credential, verified backup + restore-drill first, verify-new-before-revoke-old.**

- [x] Add `ProofLiveReal` to `proofs.go` (+ docs mirror + PROOF column) so
      promotions are recorded as data. (Level added, ordered highest; no driver
      carries it yet — filled by the ladder below.)
- [x] Policy gate in `execute.go`: `--execute` only runs drivers with proof ≥
      LIVE-VM (`MinExecuteProof`); MOCK-ONLY/UNPROVEN are SKIPPED (Rotate never
      called) unless `--allow-mock-proven` is passed. Result rows carry
      `Skipped`/`SkipReason`; covered by `execute_gate_test.go`.
- [ ] Climb the ladder, promoting proofs as you go (lowest blast radius, fastest
      recovery first):
  1. **appsecret** — local file, trivially reversible.
  2. **gitea** — self-hosted, token re-issuable in seconds, we own the server.
  3. **Self-hosted DB** (postgres/redis/mongo on own infra) — LIVE-VM drivers,
     in-place ALTER, backup covers lockout.
  4. **Free-tier SaaS keys** (resend → vercel → sendgrid) — promotes MOCK-ONLY
     drivers to LIVE-REAL with disposable keys.
  5. **cloudflare / flyio / twilio / gcp** — real accounts, still revocable from
     the provider console if the driver misbehaves.
  6. **aws** — last: real IAM user with minimal policy, console as recovery path.
- [ ] Each rung: runbook entry (local ROTATION-REAL-CRED-RUNBOOK.md), audit log
      retained, proofs.go + ROTATION-PROOFS.md updated in the same commit.
- [x] Backup restore drill: before the first real rotation, prove
      `import` of a sealed backup actually restores the store (not just that the
      bundle verifies). Done two ways: `TestExportImportRoundTripCLI` (fake gopass,
      in CI) + `lab/lab-restore-drill.sh` (real gopass on the host, isolated store —
      seed → seal → destroy → restore → assert byte-equal, no plaintext leak).

Exit criteria: ≥5 drivers at LIVE-REAL, zero incidents, execute-gate enforces
proof levels.

## M3 — Headless turnover loop (the product value)

This is where incredigo stops being a toolbox and becomes "credential storage
turnover, automated."

- [x] `incredigo rotate --stale` — rotate only credentials the policy engine marks
      Warn/Stale (`rotate.SelectStale` wires `internal/policy` into plan + execute
      selection). Expiry-driven rotation is the whole point of the policy engine.
- [x] Machine-readable output: `--json` for rotate/status, meaningful exit codes
      (status: 0 = all OK, non-zero = Warn/Stale present; rotate plan/dry-run: 0 =
      nothing to do, non-zero = credentials remain) so cron/CI can react.
- [ ] Worklist emission on every headless run: automatable creds rotated,
      remainder written to `rotate-worklist.md` (+ optional notification hook).
- [ ] **Backup chain turnover**: prune/rotate `~/.incredigo/rotation-backups/`
      (keep N, verify oldest-retained still opens) — sealed backups are themselves
      credential storage and must turn over.
- [ ] Ship `contrib/systemd/incredigo-rotate.{service,timer}` + cron example using
      `INCREDIGO_PASSPHRASE` from a root-owned env file.
- [ ] End-to-end headless test in CI: fixture store → timer-style invocation →
      assert rotated + worklist + audit + backup.

Exit criteria: a weekly timer on a real machine rotates stale automatable creds
unattended and emails/writes the manual worklist. **This is the v2 "demo that
sells it."**

## M4 — Phase B: browser/password-manager turnover

Adapters and pwgen exist; wire the loop (design in BROWSER-ROTATION.md):

- [ ] `pw-plan`: backup (manager export → sealed bundle) + generate new passwords
      into staging (`~/.incredigo/pw-stage`, handles only).
- [ ] `pw-guide`: TUI walk-through per site — open change-URL, clipboard-inject the
      staged password with auto-clear (decide + document the clipboard threat
      model), human completes the site's form (never bypass MFA/CAPTCHA).
- [ ] `pw-commit`: only after human confirms the site accepted it → write back
      in-place (CLI managers) or CSV re-import (tmpfs + shred, `--allow-csv`).
- [ ] Crash-safe staging: interrupted run resumes; stale stage entries expire.
- [ ] Prove end-to-end in the VM against a throwaway KeePassXC DB and a Firefox
      CSV; record as LIVE-VM proof data (same pattern as drivers).

## M5 — Long tail (only after M3 ships)

- Browser-automation tier: go-rod driver for sites with stable change-password
  forms (self-owned accounts only; secrets injected locally, never into a model).
- AI router as a **skill/MCP layer on top** — classify unknown creds, propose the
  worklist ordering; never in the deterministic destructive hot path.
- New scanners toward the VISION.md 20-credential list: gcloud ADC, .npmrc/.pypirc,
  LLM provider keys.
- Distribution: versioned releases on gitea, `go install`, signed binaries.

---

## Ideal end-state asset inventory

**In-repo (code + data):**
- All of M1–M4; `lab/` provisioning scripts; `contrib/systemd/`; Makefile/justfile;
  CI workflow; proofs.go with a LIVE-REAL column that grows monotonically.

**Docs (ICM layering, already close):**
- L1 router: `CLAUDE.md` (kept current — M0).
- L2 mission/architecture: `VISION.md`, `DESIGN.md`, `docs/MARKET.md`.
- L3 canonical reference: `docs/ROTATION-PROOFS.md` (mirror of data),
  `docs/SECURITY.md`, `docs/ADDING_A_SCANNER.md`, this `ROADMAP.md`
  (+ local-only ROTATION.md / RUNBOOK).
- L4 journal: dated `STATE-*.md` snapshots (this pattern), FINDINGS docs,
  `incredigo-map.html` regenerated per milestone.

**Claude Code layer (keep the LLM out of the hot path):**
- A project skill (e.g. `incredigo-ops`) encoding the M2 ladder as a runbook:
  pick next candidate → provision VM proof → run gated rotation → promote
  proofs.go → update docs. Deterministic steps in Go/bash; the skill only
  orchestrates and asks for authorization.
- Optionally a `/loop`-able health check: run `incredigo status --json` and surface
  stale creds in the morning briefing.

**Infra:**
- Gitea CI runner executing the -race suite + coverage gates.
- Reproducible Multipass VM harness (`make vm-proof DRIVER=x`).
- A real machine running the M3 systemd timer — dogfooding is the proof.

## Suggested execution order (next 5 work sessions)

1. M0 entirely + sink sealer tests (biggest safety ROI).
2. CLI integration tests + CI pipeline.
3. `ProofLiveReal` + execute-gate proof policy + restore drill.
4. Ladder rungs 1–3 (appsecret, gitea, one self-hosted DB) — with per-cred
   authorization.
5. `rotate --stale` + JSON output + systemd timer → first headless turnover demo.
