# browserrot MV3 extension — real-session password rotation

This is the **third** browserrot `Driver` (after go-rod `rod.go` and the Node sidecar
`sidecar.go`). Unlike those two — which each launch a **fresh, empty** Chromium — this one
commands the user's **real, already-open, already-2FA'd** browser session. That is the
strategic point (docs/MARKET.md §7, docs/BROWSER-ROTATION.md):

- **Session/cookie reuse** → no OLD-password re-login; operate *inside* the logged-in session.
- **Post-2FA** → the change runs after the human already cleared the second factor.
- **Real profile** → defeats the anti-bot heuristics a throwaway headless profile trips.

MFA/CAPTCHA are still **never bypassed**: this actuator only fills the fields the recipe
names; a challenge makes the site's success marker not match and the Go engine keeps the old
secret (fail-safe, same as every other driver).

## Files

| File | Role |
|------|------|
| `manifest.json` | MV3 manifest — `nativeMessaging` + `tabs`, a content script on `<all_urls>`, a background service worker. |
| `background.js` | Connects to the native host (`org.incredigo.browserrot`), relays `open/goto/fill/click/text/close` commands: `open` pins the session to the tab active at that moment (reported as `tabId`); `goto` navigates that pinned tab and the DOM verbs go to its content actuator — never to whichever tab is focused later. A closed pinned tab is an error, and a `fill` is refused unless the tab is still on the origin `goto` reached. Harness: `../testdata/background_harness.js`. |
| `content.js` | Locates the change-password fields **by the same CSS selector** the recipe uses (`Site.Form`) and fills/clicks/reads them. The secret arrives base64, is set through the native value setter (React-safe), and is dropped. |
| `native-host-manifest.template.json` | Template for the Chrome native-messaging host manifest a human installs. |

The **native host binary** Chrome spawns lives outside this dir at `cmd/incredigo-browserrot-host/`
(`../../../cmd/incredigo-browserrot-host/main.go`). Build it from the repo root:

```
go build -o incredigo-browserrot-host ./cmd/incredigo-browserrot-host
```

It constructs a zero-value `&browserrot.ExtensionDriver{}` (In/Out default to os.Stdin/os.Stdout —
the pipe Chrome wires) and runs the SAME safety spine as `lab/browser-proof/main.go`: mandatory
verified backup gate → `Rotate` (over the extension, against the open tab) → store → `Verify`. It
takes its target entirely from the **environment** (never hardcoded) — run `incredigo-browserrot-host -h`
for the full list; the essentials:

| Env | Meaning |
|-----|---------|
| `INCREDIGO_SITE_BASE` | scheme+host of the target, e.g. `https://git.example.org` (required) |
| `INCREDIGO_SITE_USER` | account login for that site (required) |
| `INCREDIGO_RECIPE` | curated recipe: `gitea` (default; selectable) |
| `INCREDIGO_STORE_PREFIX` + `INCREDIGO_CREDENTIAL` | gopass prefix + credential key of the OLD password (default key `gitea/login-creds`) |
| `INCREDIGO_PASSPHRASE` | seal passphrase for the mandatory backup gate (required) |
| `INCREDIGO_LOGIN_BEFORE_CHANGE` | `0`/`false` to skip the pre-change login (the real tab is already authenticated) |

Run interactively (no pipe on stdin) it prints guidance and exits cleanly instead of blocking; it
only speaks native messaging when Chrome spawns it with the pipe. The secret is never logged, never
written to disk in plaintext, and never placed on os.Stdout (the command pipe).

## How it wires to Go (`../extension.go`)

Chrome native messaging is a **length-prefixed 4-byte little-endian JSON** pipe. When the
extension calls `chrome.runtime.connectNative("org.incredigo.browserrot")`, Chrome **spawns**
the Go native host and wires the pipe to its stdio:

```
host os.Stdout  --command frames-->  Chrome  -->  background.js port.onMessage
background.js port.postMessage  -->  Chrome  -->  host os.Stdin (result frames)
```

`ExtensionDriver` writes commands to `os.Stdout` and reads results from `os.Stdin` (framing in
`extension.go`). Every command is `{id, method, params}`; every reply is `{id, result}` or
`{id, error}`. The secret crosses only in a `fill` command's base64 `secret` field — never
logged, never persisted, never sent to a model (the seam is asserted in `extension_test.go`).

## Proof status

- **PROVEN (unattended, no browser):** framing + the full `Rotator` Session contract against a
  fake extension endpoint — `../extension_test.go`. `go test ./internal/browserrot -race`.
- **PENDING (human-gated):** the live headless-Chromium `--load-extension` rotation against the
  disposable Gitea. Native messaging requires installing a host manifest into
  `~/.config/chromium/NativeMessagingHosts/` (host mutation) and MV3 service-worker native
  messaging is unreliable under headless Chromium. See `lab/extension-proof.md` for the exact
  human steps. The LIVE-REAL run (a real site, a real account) is a separate human-gated tier.
