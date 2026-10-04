# Browser / password-manager rotation — design spec

This is the design for incredigo's **secondary-persona** path: rotating the passwords a
non-technical user has reused across dozens of sites and saved in a browser or password
manager. It extends the same safe spine as the developer-credential drivers (discover →
custody → **mandatory backup** → rotate/verify/commit → guide) — it is *not* a new product.

Status: **Phase B (propagation engine) — built.** `pwgen` + `pwstore` (CLI adapters +
the generic `csvManager` covering chrome/firefox/edge/brave/safari/lastpass/dashlane/
protonpass/nordpass/roboform/enpass) + the sealed staged-list + the
`incredigo passwords scan|plan|guide|commit` surface are implemented and tested
(bitwarden + keepassxc + chrome/firefox staging are LIVE-VM proven; 1password and the
CSV-manager column layouts are MOCK-ONLY — see §8). Phases
A-tier-1 / A-tier-2 (site automation) are specified here but **not yet built**. Nothing in this
doc changes a password **at a website** automatically — the human still performs the site
change + MFA; incredigo only propagates the new value into the *manager* afterward.

---

## 1. The reframe: two sub-problems, very different difficulty

A naïve "automate browser password rotation" conflates two jobs. Keeping them separate is the
whole reason this design is tractable where Dashlane's was not.

| | **A — the site-side change** | **B — the manager-side propagation** |
|---|---|---|
| What | Go to each *website*, authenticate, find the change-password form, submit old→new | Update the *password manager's* stored entry with the new value |
| Why hard | MFA, CAPTCHA, email/SMS confirmation, per-site DOM variance, lockout risk | Mostly a solved problem via the manager's CLI/API |
| Automatable? | Partially, with a hard human-handoff ceiling | Yes, safely |

The throughput of the whole pipeline is capped by **A**, not B. So Phase B builds B
end-to-end (high value, safe) with the **human** as the site+MFA actor, and later phases chip
away at A behind explicit opt-in. We never let B's success imply A is solved.

---

## 2. The user-visible model: "everything up to MFA, then make MFA easy"

incredigo does every safe, deterministic step and then hands a *ready-to-finish* task to the
human at exactly the MFA wall:

1. **Ingest** the existing store (manager CLI/API or browser CSV) into the RAM vault.
2. **Backup** (mandatory, verified, sealed) the old store before anything changes.
3. **Generate** a fresh strong password per account → the **staged "separate list"** (held in
   the vault, never written to disk in plaintext).
4. **Guided handoff** — for each account present: the change-password **link**, the **new
   password** (revealed/copied locally on demand), and per-site **MFA instructions**. The
   human performs the site change + completes MFA/CAPTCHA. incredigo never bypasses either.
5. **Commit/merge** — only *after* the change succeeds, write the new password back into the
   manager: **in-place by item ID** for CLI managers; **CSV re-import** (flag-gated) for
   browser stores.

In Phase B step 4 is fully manual (incredigo opens the link + reveals the new password). In
later phases step 4 is automated *up to* the MFA wall, where it still hands off to the human.

---

## 3. Hard-rule reconciliation (this path touches real passwords)

The project's hard rules constrain this design tightly. The collisions and resolutions:

### Rule 3 — "No plaintext secrets on disk. Ever." (escape hatch: flag-gated raw export)

- **CLI managers (Bitwarden `bw`, 1Password `op`, KeePassXC `keepassxc-cli`)** read and write
  individual items over **stdin/stdout** — secrets stream as bytes into the RAM vault and back
  out per item by ID. **No plaintext file is ever created.** This is the preferred path.
- **Browser-native stores (Chrome, Firefox)** have *no* import API; the only path is a
  plaintext CSV the browser reads off disk. This is the one unavoidable plaintext-on-disk
  moment, so it is:
  - **flag-gated + loudly warned** (rule 3's sanctioned escape hatch),
  - materialized on **tmpfs (`/dev/shm`)** so it never lands on stable storage,
  - **securely shredded** (random+zero overwrite → fsync → unlink) the instant the browser
    finishes, with the window kept as narrow as possible,
  - **audited** (the act, never the value).
  - Honesty note: shred is best-effort on SSD/journaling/CoW filesystems; tmpfs avoids the
    durability problem entirely, which is why we prefer it.
- The staged "separate list" of *new* passwords lives only in the vault for the session. If it
  must survive an interactive session it is **sealed** with the existing `Sealer` (age), never
  written as plaintext — same rule as backups.
- The **worklist `.md` stays secrets-free** (site, username, link, status only). New passwords
  appear only in the interactive TUI / clipboard, never in any file.

### Rule 1 — backup before rotate

The mandatory `rotate.Snapshot` gate runs over the ingested store **before** any commit. No
verified sealed backup → no commit. The backup is also the rollback if a half-rotation occurs.

### Rule 2 — verify-new-before-revoke-old, and the browser-specific lockout hazard

For website passwords the *site itself* invalidates the old password the instant the new one
is set — we don't control that ordering. So the safe sequence per account is:

```
change at site → re-login with NEW pw in the same session to verify → only then commit to manager
```

If the change can't be verified (MFA loop, confirmation email, ambiguous result) incredigo
**keeps the old value in the manager and flags "needs human"** — it never leaves an account
half-rotated, and never risks locking the user out (do-no-harm, rule 5/6). In Phase B the
human asserts success explicitly ("the site accepted it") before commit.

### Rule 5/6 — self-owned only, never bypass MFA/CAPTCHA, audited, reversible

Only the user's own accounts, with their authorization. MFA/CAPTCHA are always a human
handoff. Every action is dry-run-able and audited (redacted).

---

## 4. Package layout (one-file-each, mirrors `discover`/`sink`)

```
internal/pwgen/        strong password generator (crypto/rand, policy, vault-native)
  pwgen.go

internal/pwstore/      password-manager adapters + the propagation engine
  pwstore.go           Manager interface, Account, registry, CSV + shred + redaction helpers
  bitwarden.go         bw  CLI  — in-place UpdatePassword by item id
  onepassword.go       op  CLI  — in-place UpdatePassword by item id
  keepassxc.go         keepassxc-cli — in-place UpdatePassword by entry path
  chromecsv.go         Chrome CSV ingest-and-shred (BulkImporter)
  firefoxcsv.go        Firefox CSV ingest-and-shred (BulkImporter)
```

### The `Manager` contract

```go
// Account is a single login. The password is a vault handle — never plaintext.
type Account struct {
    ID       string            // manager-native item id / entry path ("" for CSV rows)
    Site     string            // hostname used for the change-password link
    URL      string            // full login URL if the store has one
    Username string
    Secret   *vault.Handle     // OLD password, in the RAM vault
    Meta     map[string]string // non-secret extras (folder, note title, …)
}

type Manager interface {
    Name() string
    Available() bool // is the CLI installed / the export present?
    // Export reads all logins into the vault, passwords as handles.
    Export(ctx context.Context, v *vault.Vault) ([]Account, error)
}

// In-place updaters (CLI managers) implement this — the safe, no-plaintext-file path.
type ItemUpdater interface {
    UpdatePassword(ctx context.Context, v *vault.Vault, acct Account, newPassword *vault.Handle) error
}

// Bulk importers (browser CSV stores) implement this instead — flag-gated, shredded.
type BulkImporter interface {
    Import(ctx context.Context, v *vault.Vault, accts []Account) error
}
```

Every adapter takes an injectable `Bin` (CLI managers) or `Path` (CSV stores) so it is unit
tested against a **fake binary** / **temp CSV** — identical to the `sink.Gopass{Bin:…}` and
driver `HTTPClient` test pattern. Adapters contain **only real code**; validation status
(does this work against the real `bw`/`op`/Chrome?) is tracked as data, exactly like the
rotation drivers' `proofs.go`.

### The generator

```go
type Policy struct {
    Length           int    // default 20
    Upper, Lower     bool   // default true
    Digits, Symbols  bool   // default true
    ExcludeAmbiguous bool   // drop O/0/l/1/I to survive hand-retyping
    SymbolSet        string // override per-site (some sites reject specific symbols)
}
// Generate builds a password with crypto/rand (rejection sampling, no modulo bias),
// guarantees ≥1 char from each enabled class, and stores it straight into the vault —
// it never returns the plaintext as a Go string.
func Generate(v *vault.Vault, p Policy) (*vault.Handle, error)
```

---

## 5. Command surface (implemented)

```
incredigo passwords scan      # list logins (redacted) + change-link per account; no secrets, no commit
incredigo passwords plan      # ingest + verified backup + generate + seal staged list (--stage-out) + secrets-free worklist (--worklist-out)
incredigo passwords guide     # interactive (TTY): per account → link + reveal new pw + MFA handoff → confirm → commit
incredigo passwords commit    # headless: open sealed --stage-in, re-verify backup, commit --verified <1,2,…|all>
```

Shared flags: `--manager` selects the backend — in-place CLI managers
`bitwarden|1password|keepassxc`, or CSV import/export stores
`chrome|firefox|edge|brave|safari|lastpass|dashlane|protonpass|nordpass|roboform|enpass`
(all share one generic `csvManager`, differing only by import column layout);
`--export-path <csv>` feeds every CSV manager; `--kdbx <db>` feeds keepassxc (passphrase from
`$INCREDIGO_KDBX_PASSPHRASE` or a no-echo prompt); `--allow-csv` is the loud opt-in required
for the browser-CSV plaintext path; `--length/--exclude-ambiguous/--symbols` tune the generator;
`$INCREDIGO_PASSPHRASE` enables the headless (no-TTY) backup/seal flows.

Both the **backup** (`pwBackupGate`) and the **staged new-password list** are sealed with the
existing `Sealer` (age by default) and round-trip-verified — they are the only artifacts that
persist across the plan→commit gap, and they are never plaintext on disk. `--verified` indexes
are 1-based and match the worklist row numbers / the staged-list order from the same `plan`.

---

## 6. Audit

New redacted `audit.Entry.Action` values: `pw-scan`, `pw-export`, `pw-stage`, `pw-commit`,
`pw-import`. `Identity` is the redacted `site / us…@…`. No password, ever. The CSV-path
entries additionally record that a flag-gated plaintext file was created **and shredded**.

---

## 7. Honest ceiling (carried from the strategy discussion)

- **MFA is on every account that matters** → the realistic *fully-automated* set (later
  phases) is low-value, no-MFA, simple-form sites. Phase B sidesteps this by keeping the human
  in the loop for the site change.
- **Chrome CSV import duplicates rather than updates** (it appends), so the browser-CSV merge
  produces dupes a human must reconcile; the clean in-place merge is the CLI-manager path.
  This is documented, not hidden.
- **Fully-silent mass browser rotation stays a non-goal** (VISION) — the known Dashlane tar
  pit. incredigo automates up to the MFA wall and *guides* the rest.

---

## 8. Validation status (DATA, mirrors `rotate/proofs.go` philosophy)

The adapters contain ONLY real CLI/CSV code — no test branches. What differs is how each
write path has been *validated*. **1password** is still **MOCK-ONLY** (exercised against a
fake `op` binary — it genuinely needs a real account, no self-host). **bitwarden is LIVE-VM** —
proven end to end (`scan → plan → commit → restore-from-backup`) against the genuine `bw 2026.5.0`
CLI driving a self-hosted **Vaultwarden 1.36** (`lab-provision-bitwarden.sh`, fake account minted
via real registration crypto). **keepassxc is LIVE-VM** — proven end to end against the genuine
`keepassxc-cli 2.7.6` (`lab-provision-keepass.sh`). **chrome / firefox** are **LIVE-VM for the staging machinery**
(real `/dev/shm` tmpfs + secure shred, correct per-browser layout) via
`lab-provision-browsercsv.sh`; only the final human re-import is unproven (see note ²). All in
the `incredigo-sbx` sandbox VM.

Three more **in-place CLI adapters** are **MOCK-ONLY** (unit-validated via injected fake
binaries; no LIVE-VM POC yet): **pass / gopass** (the user's own password-store as a rotation
source — off-argv write, full body piped to `<bin> insert -m -f`, metadata preserved across the
swap), and **keychain** (macOS `security` CLI — darwin-only at runtime, argv write caveat ³).

The **CSV-manager family** (edge/brave/safari/lastpass/dashlane/protonpass/nordpass/roboform/
enpass) shares the chrome/firefox staging machinery via one generic `csvManager`, so its
security-critical path (tmpfs + correct per-manager import layout + shred, `--allow-csv` gated)
is the *same proven code*; what is **MOCK-ONLY** for each is the per-manager column mapping,
validated by unit tests (`csvmanagers_test.go`) against representative real-world export/import
headers — there is no LIVE-VM round-trip into the actual managers yet. `enpass` imports via JSON
(not CSV) so it is **read/guide-only**: it parses an export for the worklist but refuses
`ImportStaged`, pointing the human at `incredigo passwords guide`.

| Adapter   | Write shape            | Secret path off-argv? | Validated against |
|-----------|------------------------|-----------------------|-------------------|
| bitwarden | `bw edit item` (stdin) | **yes** — base64 on stdin | **real bw 2026.5.0 + Vaultwarden 1.36 (LIVE-VM)** |
| keepassxc | `keepassxc-cli edit -p`| **yes** — db+new pass on stdin | **real keepassxc-cli 2.7.6 (LIVE-VM)** |
| 1password | `op item edit pw=…`    | **no** — argv assignment¹ | fake `op` (MOCK-ONLY) |
| pass / gopass | `<bin> insert -m -f` (stdin) | **yes** — full body on stdin | fake `pass`/`gopass` bin (MOCK-ONLY) |
| keychain  | `security add-internet-password -w` | **no** — argv assignment³ | fake `security` bin (MOCK-ONLY) |
| chrome    | tmpfs CSV → human re-import | n/a (no live secret to a child) | **real /dev/shm + shred (LIVE-VM²)** |
| firefox   | tmpfs CSV → human re-import | n/a | **real /dev/shm + shred (LIVE-VM²)** |
| edge / brave | tmpfs CSV (chrome layout) → re-import | n/a | shared staging code (LIVE-VM²); layout MOCK-ONLY (unit) |
| safari    | tmpfs CSV (macOS Passwords layout) → re-import | n/a | shared staging code (LIVE-VM²); layout MOCK-ONLY (unit) |
| lastpass  | tmpfs CSV (Generic CSV layout) → re-import | n/a | shared staging code (LIVE-VM²); layout MOCK-ONLY (unit) |
| dashlane  | tmpfs CSV (Dashlane layout) → re-import | n/a | shared staging code (LIVE-VM²); layout MOCK-ONLY (unit) |
| protonpass| tmpfs CSV (Proton layout) → re-import | n/a | shared staging code (LIVE-VM²); layout MOCK-ONLY (unit) |
| nordpass  | tmpfs CSV (NordPass layout) → re-import | n/a | shared staging code (LIVE-VM²); layout MOCK-ONLY (unit) |
| roboform  | tmpfs CSV (RoboForm layout) → re-import | n/a | shared staging code (LIVE-VM²); layout MOCK-ONLY (unit) |
| enpass    | read/guide-only (JSON import, no CSV) | n/a | export parse only (unit); `ImportStaged` refuses |

² **chrome/firefox LIVE-VM scope:** there is no real browser to re-import into, so what is
proven LIVE-VM (`lab-provision-browsercsv.sh` + `csv-commit-probe.py`) is the security-critical
*staging* machinery that runs unattended: `commit --allow-csv` writes the new-password CSV to a
real **tmpfs** (`/dev/shm`, confirmed `stat -f`), in the correct per-browser column layout
(chrome `name,url,username,password,note`; firefox `url,username,password`), carrying the staged
strong passwords with the OLD ones absent, and the file is **securely shredded** (unlinked) once
the human confirms — while the user's own export CSV is left untouched. The final re-import into
Chrome/Firefox itself is still a human step (no programmatic import API exists). The probe drives
commit under a real pty so it pauses at the shred prompt long enough to inspect the file.

**keepassxc LIVE-VM finding:** the CSV `Group` column is the FULL group path *including* the
root group name (the default DB names its root `Passwords`), but `keepassxc-cli` addresses
entries *relative to root* — a top-level entry is `/GitHub`, not `/Passwords/GitHub`. The
mock CSV (root group `Root`) never exposed this; the real CLI 404'd until `kpEntryPath` was
fixed to drop the leading root segment. The recoverability leg (feeding the sealed `backup.age`
back through `commit --stage-in`) restored both original passwords, proving the backup is a
usable restore artifact, not just a sealed blob.

¹ **1Password argv caveat:** `op item edit` has no stdin-per-field path (only `op item create`
does), and the JSON-template alternative would write plaintext to disk (hard rule 3). The
remaining real path is `op item edit <id> password=<new>`, so the new value is visible to
**same-uid** processes via `/proc/<pid>/cmdline` for the brief op exec. This is strictly weaker
than the Bitwarden/KeePassXC stdin paths; it is in-RAM, transient, and never touches disk. The
choice is documented here rather than hidden in the driver. Promoting any adapter to a
real-binary proof level requires a sandbox-VM POC against the genuine CLI / browser import.

³ **Keychain argv caveat:** the macOS `security` CLI has no in-place edit and no stdin path
for writing — `add-internet-password -w <new>` takes the secret on argv, so it is briefly
visible to **same-uid** processes via `ps`/`/proc`-equivalent, exactly like the 1Password
caveat (¹). The read side stays off argv (`find-internet-password -w` prints to stdout into the
vault). Update is delete-then-add (no atomic replace). Bulk export is also inherently
prompt-heavy on a real Mac (`find-internet-password -w` triggers a keychain-access prompt per
item unless the ACL already trusts the caller); incredigo skips items it cannot read rather than
aborting. Keychain is **darwin-only at runtime** — `Available()` is false off macOS — but the
adapter is pure-exec Go, so it is unit-validated cross-platform via an injected fake `security`.

## 9. Roadmap

- **Phase B (now):** `pwgen` + `pwstore` (interface + Bitwarden/1Password/KeePassXC in-place +
  Chrome/Firefox CSV ingest-and-shred) + the staged-list propagation engine + `passwords`
  commands. Human does the site change + MFA; incredigo does everything else.
- **Phase A-tier-1 (engine built):** `internal/browserrot` — a deterministic `go-rod` driver
  (behind a browser-agnostic `Driver`/`Session` interface so `playwright-go` and a Tier-2 AI
  driver are swap-ins) that discovers the change page via `internal/links` (curated table +
  RFC 8615), injects OLD + a freshly-minted NEW password over CDP with **no model in the loop**,
  submits, and **re-logs-in to verify the new password before commit** (hard rule 2). A `Rotator`
  here implements `rotate.Rotator`, so `rotate.Snapshot` (backup), the verify-before-revoke
  ordering, and the proof gate all apply unchanged; `RevokeOld` is a no-op because the site
  invalidates the old password itself. Proof-as-data per `Site`: the **ENGINE is LIVE-VM**
  (real headless Chromium against a real local change-password form —
  `lab-provision-browserrot.sh` / `TestIntegration_realBrowserRotation`); a **specific real-site
  selector table stays UNPROVEN** until run against that real site. **First real-site promotion
  done: `GiteaSite` is LIVE-REAL** — it drove a real password rotation of a self-owned Gitea
  account (`trill-technician` @ `100.117.177.50:3030`) on 2026-07-21 via
  `lab/rung4-gitea-browser` (M-B4): backup-gated (Hard Rule 1, 3 entries sealed+verified),
  pre-change login with the OLD secret, change-form submit, then the NEW secret verified by
  browser re-login AND independent API re-auth (HTTP 200). Two real-site selector fixes fell out
  of the live-fire and are now in `sites.go`: (1) Gitea's login **and** "Update Password" buttons
  carry no `type=submit` *attribute* (only the default DOM property), so CSS `[type=submit]`
  misses — select by class / by the account form's sole button instead; (2) `RodDriver.Click`
  now waits for the post-submit navigation to settle (a remote round-trip, unlike the instant
  in-process test) before the success text is read. `RodDriver.Insecure` was added for the
  self-signed/Tailscale host (browser analog of `curl -k`). No production `rotate` wiring
  auto-enables browser rotation yet (still gated behind per-credential authorization; the
  live-fire is a dedicated harness). Still to do: build out the curated selector table for other
  real high-frequency no-MFA sites and measure the real success rate before promising anything.
- **Phase A-tier-1.5 — Node stealth sidecar (built + LIVE-VM):** an optional swap-in
  `Driver` (`internal/browserrot/sidecar.go` + `internal/browserrot/sidecar/`) that speaks
  newline-delimited JSON-RPC over stdio to a small Node program driving a **patchright**
  real-fingerprint Chromium. go-rod stays the default; the sidecar reaches **parity** through
  the *identical* LIVE-VM harness (`runLiveRotationProof` runs both drivers —
  `TestIntegration_sidecarBrowserRotation`). Stealth posture is **LIVE-VM**: patchright
  removes `navigator.webdriver` (`TestIntegration_sidecarStealthSignals`), and humanized input
  (cubic-Bézier mouse paths + randomized per-key typing, **no ML trajectory generation**) still
  lands a real rotation (`TestIntegration_sidecarStealthRotation`). The secret seam is honest:
  `fill` carries the vault bytes **base64** over ONE local stdio boundary, never logged, never
  on disk, never to a model (`TestSidecar_secretSeamBase64` + a redacted IPC transcript).
- **Phase A-tier-2 — self-heal + recipe persistence (built + LIVE-VM for the heuristic
  strategy):** on a Tier-1 selector miss the engine calls an optional `Healer` (a Session
  capability) to relocate the field by **natural-language description**, retries, and rewrites
  the recipe; `RecipeBook` (`recipes.go`) persists the healed `Site` so the next run is Tier-1
  again ("learn once"). The `Heal` signature takes only a description — a secret **cannot**
  reach the healer by construction (`TestHeal_engineRetriesRewritesAndPersists`,
  `TestIntegration_sidecarSelfHeal` with a redacted-transcript leak-check). The sidecar's
  **deterministic DOM-heuristic** heal (attributes/labels/aria only, never field values) is the
  **LIVE-VM-proven** Tier-2; the **Stagehand `observe` (LLM) strategy** is real but **UNPROVEN**
  and strictly opt-in (`INCREDIGO_HEAL_STRATEGY=stagehand`) — it needs Stagehand to own the
  browser, still to be wired. A specific real-site recipe stays **UNPROVEN** until run against
  that site; no production `rotate` wiring auto-enables it (per-credential authorization).
- **Phase A-tier-3:** Computer-Use / AI-in-browser vision fallback for hostile DOM variance,
  with **secrets kept out of the model loop** (the model decides navigation; the Go harness
  injects the actual password via CDP, redacted from the screenshot stream). Opt-in, measured.
