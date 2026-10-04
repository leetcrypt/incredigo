#!/usr/bin/env bash
# LIVE-VM proof for the Phase A-tier-1 site-side rotation ENGINE (internal/browserrot),
# inside the sandbox VM. FAKE credential only, against a throwaway in-process website —
# nothing real is touched.
#
# What this proves is the deterministic browser-drive machinery that would run against a
# real change-password page:
#
#   * discover the change page via RFC 8615 /.well-known/change-password (real redirect)
#   * inject the OLD + a freshly-minted NEW password into the form over CDP, with NO
#     language model in the loop
#   * submit and read the site's SUCCESS marker
#   * VERIFY the new password authenticates by re-logging-in (hard rule 2), and confirm
#     the OLD password no longer works (the rotation is real, not a no-op)
#
# The engine is exercised by the CHROME_BIN-gated integration test
# (TestIntegration_realBrowserRotation) driving a REAL headless Chromium. This is what
# earns browserrot's LIVE-VM proof level for the ENGINE; a specific real-site selector
# table stays UNPROVEN until it is run against that real site.
#
# It does NOT rotate any real account: only the user's own accounts, with explicit
# per-credential authorization, may ever be driven against a real provider.
set -euo pipefail
export PATH=/usr/local/bin:$PATH

# Locate a usable, NON-snap Chromium (snap chromium fights CDP + can't read /tmp).
find_chrome() {
  for c in \
    "${CHROME_BIN:-}" \
    "$HOME"/.cache/ms-playwright/chromium-*/chrome-linux64/chrome \
    "$HOME"/.cache/ms-playwright/chromium-*/chrome-linux/chrome \
    /usr/bin/google-chrome /usr/bin/chromium /opt/google/chrome/chrome ; do
    [ -n "$c" ] && [ -x "$c" ] && { echo "$c"; return 0; }
  done
  return 1
}

CHROME_BIN="$(find_chrome || true)"
if [ -z "${CHROME_BIN:-}" ]; then
  echo "FAIL: no usable Chromium found. Install Chrome-for-Testing / google-chrome, or"
  echo "      set CHROME_BIN to a chromium executable (a Playwright-managed one is ideal)."
  echo "      hint: npx playwright install chromium"
  exit 1
fi
echo "== using Chromium: $CHROME_BIN"
"$CHROME_BIN" --version 2>/dev/null | sed 's/^/   /' || true

# Run from the repo root (the dir containing go.mod).
cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel 2>/dev/null || echo "$(dirname "$0")/..")"

# The Node sidecar (patchright real-fingerprint Chromium) is an OPTIONAL swap-in Driver
# that must reach parity with go-rod. If a `node` runtime + the sidecar deps are present,
# prove BOTH drivers through the identical harness; otherwise prove go-rod only.
SIDECAR_DIR="internal/browserrot/sidecar"
have_sidecar() {
  command -v node >/dev/null 2>&1 && [ -d "$SIDECAR_DIR/node_modules/playwright-core" ]
}

echo "== running the LIVE-VM browser-rotation proof (go-rod) =="
CHROME_BIN="$CHROME_BIN" go test -run TestIntegration_realBrowserRotation -v ./internal/browserrot/

if have_sidecar; then
  echo
  echo "== running the LIVE-VM browser-rotation proof (node-sidecar, parity) =="
  node --version | sed 's/^/   node /'
  CHROME_BIN="$CHROME_BIN" go test -run TestIntegration_sidecarBrowserRotation -v ./internal/browserrot/

  if [ -d "$SIDECAR_DIR/node_modules/patchright" ]; then
    echo
    echo "== M-B2 stealth: patchright fingerprint + humanized input =="
    CHROME_BIN="$CHROME_BIN" go test -run 'TestIntegration_sidecarStealth' -v ./internal/browserrot/
  else
    echo
    echo "== M-B2 stealth SKIPPED (patchright not installed) =="
    echo "   to enable: (cd $SIDECAR_DIR && npm install patchright)"
  fi

  echo
  echo "== M-B3 self-heal: rotted selector -> Tier-2 heal -> rewrite recipe (no secret to heal) =="
  CHROME_BIN="$CHROME_BIN" go test -run 'TestIntegration_sidecarSelfHeal' -v ./internal/browserrot/
else
  echo
  echo "== node-sidecar SKIPPED (no node runtime or deps not installed) =="
  echo "   to enable: (cd $SIDECAR_DIR && PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm install)"
fi

echo
echo "== secret-seam leak guard (browser-free) =="
go test -run TestSidecar_secretSeamBase64 -v ./internal/browserrot/

echo
echo "LIVE-VM BROWSER-ROTATION ENGINE PROOF PASSED"
