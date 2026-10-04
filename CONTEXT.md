# incredigo — ICM router (dev copy)

Local-first, RAM-only, GPG/gopass-backed **credential-rotation automation**, shipped as the
`incredigo` Go CLI. No plaintext at rest; decrypted secrets live only in locked, non-swappable RAM.
Dev copy transferred to `~/coding/` 2026-09-16 from `security/church-of-malware/Trilltechnician/`.
Source of truth for *what/why*: `VISION.md`, `DESIGN.md`, `docs/ROADMAP.md`, `docs/STATE-*.md`.

## Entry points

- **CLI:** `cmd/incredigo` → the `incredigo` binary. Build/test via `Makefile` (`make build|test|race|cover`).
- **Safety spine (critical):** `internal/sink` (sealers: age/hmac/openssl + gopass wrapper) — the
  verified sealed-backup gate that must hold *before* any rotation. Test debt here blocks real work.
- **Rotation engine:** `internal/rotate` (29 src) — per-service drivers, verify-new-before-revoke-old.
- **Browser rotation:** `internal/browserrot` — headless site-side password resets (Rod driver).
  A real LIVE-REAL proof exists (self-owned Gitea login rotated end-to-end, 2026-07-21).
- **Discovery / worklist:** `internal/discover` (credential sprawl), `internal/worklist`,
  `internal/audit` (redacted trail), `internal/policy`, `internal/pwgen`, `internal/pwstore`,
  `internal/vault`, `internal/blast`, `internal/links`, `internal/tui`.
- **Lab / proofs:** `lab/` — VM-provisioning + harness scripts for LIVE-VM / LIVE-REAL driver proofs.

## Status (from docs/ROADMAP.md + OVERSEER-STATUS.md)

Early-stage but real: ~22 drivers, execute spine wired behind `INCREDIGO_ALLOW_EXECUTE=1`, first
real browser rotation proven (Gitea). **M1 = harden the safety spine's test coverage first** — it
gates everything downstream. See `docs/ROADMAP.md` for M0 (housekeeping) → M1 (sink/backup tests)
→ real rotations → headless turnover loop → Phase B.

## Working here

Read `CLAUDE.md` before changing anything — this handles **real credentials**; the safety rails
there are non-negotiable. Objectives for this repo (test-coverage first, roadmap-ordered) live in
`../automated-dev-system/fleet-media-test/` runs / the fleet backlog; review via the cockpit.
