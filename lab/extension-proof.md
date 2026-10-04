# extension-proof — live headless-Chromium proof of the MV3 extension driver (STAGED / human-gated)

This is the **C1** analog of `lab/browser-proof.sh` (D1, PASS) for the **third** browserrot
driver: the MV3 WebExtension + Go native-messaging host (`internal/browserrot/extension.go`
+ `internal/browserrot/extension/`). D1 proved the go-rod driver end-to-end against a
disposable, containerized Gitea. This document specifies the equivalent proof for the
extension path **and states honestly why it cannot run unattended here.**

## What is already PROVEN (unattended, this commit)

`internal/browserrot/extension_test.go` — `go test ./internal/browserrot -race`:

- The native-messaging **framing** (4-byte little-endian length prefix + JSON) round-trips,
  is pinned little-endian, and rejects truncated/oversized frames.
- The full **Session contract** (`open/goto/fill/click/text/close`) drives through the driver
  against a **fake extension endpoint** with no browser.
- The full **`Rotator` spine** (discover → mint → fill current/new/confirm → submit →
  read-success) runs on the `ExtensionDriver`, proving it is a drop-in third `Driver`.
- The **secret seam**: both the OLD and the freshly minted NEW secret cross the pipe
  **base64-encoded, never as plaintext** (the extension analog of rod.go's CDP seam and
  sidecar.go's stdio seam). Fail-safe on site rejection leaves the old secret untouched.

That is the same class of guarantee `sidecar_test.go`'s `TestSidecar_secretSeamBase64` gives
the sidecar driver without a browser.

## Why the LIVE headless-extension leg is human-gated (not run here)

Two hard blockers, both requiring **host mutation** or an unreliable path — the safety rails
say report honestly rather than fake it:

1. **Native messaging requires a host manifest installed in a fixed OS location.** Chrome only
   spawns a native host named in `~/.config/google-chrome/NativeMessagingHosts/` (or
   `~/.config/chromium/NativeMessagingHosts/`). Writing there is **host mutation** — outside
   the isolated temp `HOME` the loop is allowed to touch — so it must be a human step, not an
   unattended one. (See `native-host-manifest.template.json`.)
2. **MV3 service-worker native messaging under headless Chromium is unreliable.** Old headless
   loaded no extensions at all; `--headless=new` loads them but background service-worker
   lifetime + `connectNative` is flaky and version-dependent. A green run cannot be asserted
   as a stable proof from a scripted headless launch on this box.

The **LIVE-REAL** tier (the extension driving a rotation on a *real* site with a *real*
already-logged-in account) is a separate, explicitly human-gated tier — never run by the loop.

## The proof a human runs (headed, isolated, disposable) — recipe

Mirrors `browser-proof.sh`'s isolation spine; only the driver and the browser-launch differ.

1. **Disposable target** — reuse `browser-proof.sh` steps 1–2 verbatim: a `--rm` Gitea
   container on `127.0.0.1:<port>`, one throwaway account, an isolated temp `HOME` + gopass
   store holding only that one credential, and the `verify_isolation` asserts BEFORE anything
   mutating. Nothing about the target changes for the extension path.
2. **Build the native host** — `cmd/incredigo-browserrot-host/main.go` constructs
   `&browserrot.ExtensionDriver{}` (zero value → os.Stdin/os.Stdout, which Chrome wires to the
   native-messaging pipe) and runs the same spine as `lab/browser-proof/main.go`
   (backup gate → `Rotate` → store → `Verify`). Build it from the repo root:
   ```
   go build -o incredigo-browserrot-host ./cmd/incredigo-browserrot-host
   ```
   It reads its target from the environment — no hardcoded site: `INCREDIGO_SITE_BASE`,
   `INCREDIGO_SITE_USER`, `INCREDIGO_RECIPE` (default `gitea`), `INCREDIGO_STORE_PREFIX` +
   `INCREDIGO_CREDENTIAL` (the gopass entry with the OLD password, default key `gitea/login-creds`),
   `INCREDIGO_PASSPHRASE` (backup-gate seal), and `INCREDIGO_LOGIN_BEFORE_CHANGE` (see step 5).
   For the disposable Gitea, point these at the throwaway account/store from step 1. Run
   `incredigo-browserrot-host -h` for the full list; run interactively (no pipe) it prints
   guidance and exits 0 instead of blocking on the native-messaging read.
3. **Install the host manifest (HOST MUTATION — human)** — copy
   `extension/native-host-manifest.template.json` to the browser's `NativeMessagingHosts/`
   dir with `<PATH>` → the host binary and `<EXTENSION_ID>` → the unpacked extension's id.
4. **Launch a HEADED, disposable-profile Chromium** with the extension loaded:
   `chromium --user-data-dir="$ISO_HOME/.chrome" --load-extension="$PWD/internal/browserrot/extension"`.
   Log the throwaway account in **by hand** (this is the whole point — a real, post-2FA
   session). Navigate the active tab to the Gitea account page.
5. **Trigger the rotation** — the extension connects the native host, which runs the spine and
   commands `fill/click/text` against the logged-in tab. Because the session cookie already
   exists, the pre-change login is unnecessary for this driver (contrast the go-rod path); set
   `INCREDIGO_LOGIN_BEFORE_CHANGE=false` (or `-login-before-change=false`) so the host skips it
   and operates purely inside the already-authenticated session.
   The session is pinned to the tab that is active when the host opens it: keep that tab
   focused at trigger time. After that you may switch tabs freely, because commands follow the
   pinned tab id, not focus. Closing the tab aborts the rotation and keeps the old secret.
6. **Independent ground truth** — reuse `browser-proof.sh` step 4 exactly: a direct Gitea API
   basic-auth check that the NEW password authenticates and the OLD one returns 401/403. That
   API check — not the extension's self-report — is the verdict.

## Exit criteria (when a human runs it)

- Backup gate ran, `Rotate` reported the site confirmed the change, the new secret is stored.
- Gitea API: NEW password → 200, OLD password → 401/403.
- No secret in any log, transcript, or on disk in plaintext (the base64 seam holds, as the
  unattended `extension_test.go` already proves at the framing layer).
