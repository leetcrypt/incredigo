# browserrot buildout plan — Node stealth sidecar + AI self-heal (Phase A tiers 1-3)

**Status (2026-07-21):** M-B1 ✅ M-B2 ✅ M-B3 ✅ **M-B4 ✅** (first REAL self-owned site).
M-B1..B3 are LIVE-VM against the local lab form; **M-B4 is LIVE-REAL** — `GiteaSite` drove a
real password rotation of a self-owned Gitea account (`trill-technician` @
`100.117.177.50:3030`) on 2026-07-21 via `lab/rung4-gitea-browser`, backup-gated and verified
by browser re-login + API re-auth (HTTP 200). Two real-site selector fixes landed from the
live-fire (no `type=submit` attribute on Gitea buttons; `RodDriver.Click` now waits for the
post-submit navigation), plus `RodDriver.Insecure` for the self-signed/Tailscale host. The
`internal/browserrot/` suite is green + `-race` clean. M-B5 (vision) later. The Stagehand
(LLM) heal strategy is wired but UNPROVEN/opt-in; the deterministic DOM-heuristic heal is
the LIVE-VM Tier-2. See `docs/BROWSER-ROTATION.md` §9 for the proof-as-data record.
**Extends, does not replace:** [`docs/BROWSER-ROTATION.md`](BROWSER-ROTATION.md) (the design
spec) and the existing engine in [`internal/browserrot`](../internal/browserrot).
**Goal (user's words):** reset passwords for the **most sites without getting blocked**,
"do it once → reproduces forever, until the site ups bot detection."

---

## 0. Decision: Option (b) — a Node browser-sidecar

Chosen over "stay pure-Go with `playwright-go`" because the whole ecosystem that maximizes
*site coverage* and *avoids false-positive bot blocks* is Node-centric and has no Go equivalent:

- **`patchright`** (drop-in Playwright, real-fingerprint Chromium) — beats the fingerprint
  checks `playwright-go` cannot touch; more robust than JS-injected stealth plugins.
- **Stagehand** (`act`/`observe`/`extract` + **auto-caching self-heal**) — covers the long
  tail of site layouts without hand-coding every selector; this IS the "record once, replay
  forever, re-learn on break" paradigm.
- **Playwright codegen** — records a real human run into a starter recipe.

`playwright-go` would give a driver but none of the above. The runtime cost of (b) is one
Node dependency, isolated behind an interface and a local socket.

> **The architecture already anticipated this.** `internal/browserrot/browserrot.go`:
> *"go-rod is the default; playwright-go and a Tier-2 AI driver are swap-ins that satisfy
> the same interface."* The sidecar is just a new `Driver`. **No spine change, no new hard-rule
> surface** — `rotate.Snapshot` (backup), verify-new-before-revoke-old, and the proof gate all
> apply unchanged because a browser `Rotator` already implements `rotate.Rotator`.

---

## 1. Non-negotiable reframe (carry into every task)

incredigo is **not** a bot-bypass/scraping tool. Per CLAUDE.md Hard Rule 5:
- **Authorized principals only** — self-owned, or a client's delegated + *recorded* consent.
  The invariant is provable, per-credential, auditable authorization, not operator ownership;
  managed client rotation is in scope on that basis.
- **Never bypass, harvest, auto-submit, or simulate any second factor** (MFA / CAPTCHA /
  OTP / push / email-confirm) — when one appears, the success marker simply doesn't match,
  `Rotate` fails cleanly, the OLD secret is kept, and the challenge is handed to the **live
  account holder** to complete before the flow resumes. (Already how `Rotate` behaves,
  browserrot.go:175-180.) The two primitives a takeover/stuffing kit needs — unauthorized
  scale + an automated second-factor defeat — are structurally absent and must stay absent.
- "Stealth" here = **do not get false-flagged as a bot while doing a legitimate self-login**,
  NOT defeating a challenge. For a user logging into their own account from their own machine,
  most of the anti-bot arms race is already moot (real IP, real device, real user).
- **Hard Rule 6:** the self-heal LLM may see **page structure only** to locate fields; it
  **never receives a secret**. incredigo still fills fields itself, over CDP, with vault bytes.

---

## 2. Target architecture — three tiers, graceful degrade (mirrors rotate → worklist)

```
Tier 1  deterministic replay of the recorded recipe (Site/Form selectors)   ← no LLM, no secret to model
        engine driver = go-rod (exists) OR node-sidecar (new)
   │ selector miss / Text() or Fill() fails
   ▼
Tier 2  AI self-heal: Stagehand observe/act re-locates the field by NL       ← LLM sees DOM structure only
        description → new selector → incredigo fills with vault bytes →         (never the secret)
        PERSIST the healed recipe so the next run is Tier-1 again
   │ hostile/opaque markup, canvas, etc.
   ▼
Tier 3  vision fallback (Anthropic Computer Use) — secrets injected locally    ← later; keep out of default path
   │ MFA / CAPTCHA / email-confirm at ANY tier
   ▼
HUMAN   worklist handoff (change-URL + guide TUI) — existing internal/worklist
```

The **recipe** = the existing `Site{Host, ChangeURL, Form, Login, Proof}`. Tier-2 healing
*rewrites the recipe's selectors* and re-persists it; that is the entire "learn once" loop.

---

## 3. The Node sidecar (new component)

- **Process:** a small Node program (`browserrot/sidecar/`), Playwright + `patchright` +
  `@browserbasehq/stagehand`. Launches a real headed-ish Chromium with real fingerprint.
- **IPC:** newline-delimited **JSON-RPC over stdio** (Go spawns it as a child; simplest, no
  port, dies with the parent). Methods map 1:1 to the Go `Session` interface:
  `open`, `goto`, `fill`, `click`, `text`, `close`, plus Tier-2: `heal` (NL field description
  → selector) and (Tier-3 later) `act`.
- **Secret seam (document honestly, like the CDP seam in rod.go):** `fill` carries the secret
  bytes over the local stdio pipe to the sidecar, which types them into the field. The secret
  crosses ONE local process boundary, is **never logged, never written to disk, never sent to
  an LLM**. Heal/act requests carry **only** a field description + sanitized DOM, never a value.
- **Go side:** `internal/browserrot/sidecar.go` = a new `Driver`+`Session` impl that speaks the
  JSON-RPC. Selected via a driver flag/env; go-rod stays the default until the sidecar reaches
  parity.
- **Lifecycle:** Go owns spawn/teardown; `Session.Close()` → `close` RPC → kill child. Timeouts
  and a hard context deadline on every RPC.

---

## 4. Recording a recipe once ("manual once")

- `incredigo browser record --host <site>` → drives Playwright **codegen** in the sidecar; the
  human performs the change-password + re-login flow once; incredigo captures the selectors into
  a `Site` recipe (Form + Login), **redacting any typed secret** (store selectors, never values).
- Persist recipes as a curated table in-repo for public sites (no secrets) and/or a local
  user file for private ones. This is the browser analog of the rotate driver's ref-map.

---

## 5. Stealth posture (deliberately minimal)

- Use **`patchright`'s real-fingerprint Chromium**; avoid JS-injected stealth plugins (more
  fragile, more detectable).
- **Human-paced input:** simple Bézier mouse paths + randomized typing delays. Research shows
  GAN/diffusion mouse-trajectory models are often *more* detectable than plain Bézier+jitter
  (DMTG discriminators ~80-90%) — so **do NOT build ML trajectory generation**; it is cost with
  negative return for a self-owned login.
- No proxies, no residential-IP rotation — the user's own IP is correct and legitimate.

---

## 6. Proof ladder (DATA, mirrors rotate/proofs.go & BROWSER-ROTATION.md §8)

Per-`Site` `Proof`:
- Local lab HTTP form → **LIVE-VM** (real browser + real form proved the mechanism) — exists.
- Each **real self-owned site** stays **UNPROVEN** until actually run against it, then promotes
  to **LIVE-REAL** for that host (same discipline as the gitea rung). No blanket "works on all
  sites" claim ever.

---

## 7. Milestones (execute in order; each ends green + a lab proof)

- **M-B1 — sidecar parity.** Node sidecar + `sidecar.go` Driver passing the EXISTING
  `browserrot_test.go` against the local lab form (`lab/lab-provision-browserrot.sh`), at
  parity with go-rod. Deliverable: `go test ./internal/browserrot` green with driver=sidecar.
- **M-B2 — stealth + human input.** patchright fingerprint + Bézier/typing pacing. Re-run lab;
  add a detection-signal probe (navigator.webdriver etc. absent).
- **M-B3 — self-heal + persistence.** Tier-2 `heal` RPC (Stagehand observe) triggered on
  selector miss → rewrite + persist the recipe → next run is Tier-1. Test: seed a *broken*
  selector, assert one run heals it and the second run needs no LLM. Assert **no secret** in any
  heal request (leak-check the IPC transcript).
- **M-B4 — record command + first REAL site. ✅ DONE (2026-07-21, rotation half).** Pointed the
  engine at ONE real self-owned account (self-hosted Gitea, no MFA), rotated + re-login-verified,
  promoted `GiteaSite` to LIVE-REAL. Harness: `lab/rung4-gitea-browser` (env-only secrets,
  isolated to the real gopass entry `gitea/login-creds`, `MODE=probe|live`, `GITEA_INSECURE=1`
  for the self-signed host). Backup-gated (Hard Rule 1). The `incredigo browser record` codegen
  command is still TODO — this run used the curated `GiteaSite` recipe, not a recorded one.
- **M-B5 (optional/later) — vision fallback.** Tier-3 Computer Use for hostile markup; secrets
  injected locally, never to the model.

---

## 8. Files to add / change

- **add** `internal/browserrot/sidecar/` — Node sidecar (package.json, index.js, stealth+heal).
- **add** `internal/browserrot/sidecar.go` — Go Driver/Session over JSON-RPC (+ `sidecar_test.go`).
- **add** recipe persistence (`recipes.go` or extend the curated `Site` table) + record command
  in `cmd/incredigo`.
- **add** `lab/lab-provision-browserrot-real.sh` (M-B4) — real-site LIVE target harness.
- **edit** `docs/BROWSER-ROTATION.md` §8 validation table + §9 roadmap as tiers land.
- **edit** driver selection (flag/env) so go-rod stays default until sidecar parity.
- **unchanged:** the rotate spine, hard-rule gates, `Session`/`Driver`/`Rotator` interfaces.

---

## 9. Open decisions / risks to confirm before/while building

1. **Node runtime dependency** — acceptable for the browser layer only? (Go core stays pure;
   sidecar is optional, spawned on demand.) → assume yes; keep go-rod as the no-Node fallback.
2. **Stagehand LLM provider + key** — which model, and where the key lives (env, never in a
   recipe). LLM sees DOM structure only.
3. **Recipe distribution** — curated public-site table in-repo (no secrets) vs. per-user local
   file for private hosts. Likely both.
4. **ToS/legal** — automating even your own-account login can breach a site's ToS; the
   self-owned + human-handoff-on-challenge framing is the mitigation, state it in the docs.
5. **Per-site fragility** — accept that recipes rot; the self-heal tier + record command are the
   maintenance story, not a promise of permanence ("until the site ups bot detection").

---

## 10. What this plan explicitly does NOT do

- Does not put an LLM in the deterministic destructive path (Tier-1 is pure).
- Does not send any secret to any model, ever.
- Does not bypass MFA/CAPTCHA — those degrade to the human worklist.
- Does not build ML mouse-trajectory generation (negative ROI, see §5).
- Does not change the rotate spine, the backup gate, or any hard rule.
