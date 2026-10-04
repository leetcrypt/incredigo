#!/usr/bin/env bash
# lab-restore-drill.sh — prove the sealed backup is a REAL recovery path, on the host,
# against REAL gopass, before any real rotation trusts it as the only rollback.
#
# The CLI test (cmd/incredigo TestExportImportRoundTripCLI) already proves the export→
# import LOGIC against a FAKE gopass binary. This drill proves the same thing end-to-end
# against a genuinely installed gopasspw/gopass in an ISOLATED throwaway store: seed →
# seal → DESTROY the entries → restore from the sealed bundle → assert every value is
# back byte-for-byte. It is the safety net for drivers whose RevokeOld is a no-op (e.g.
# appsecret), where the sealed .age backup is the ONLY way back.
#
# Safety: isolated GOPASS_HOMEDIR + GNUPGHOME (no-protection throwaway key) + FAKE creds.
# It CANNOT touch the real ~/.password-store or a real GPG key. Nothing real is rotated.
set -euo pipefail
export PATH=/usr/local/bin:$PATH
export GOPASS_HOMEDIR="${GOPASS_HOMEDIR:-$HOME/.drill-gopass}"
export GNUPGHOME="${GNUPGHOME:-$HOME/.drill-gnupg}"
export GOPASS_NO_NOTIFY=true
export INCREDIGO_PASSPHRASE="${INCREDIGO_PASSPHRASE:-drill-seal-pass}"

# --- locate incredigo (prefer an installed/staged binary, else build from the repo) ---
if [ -n "${INCREDIGO_BIN:-}" ] && [ -x "${INCREDIGO_BIN}" ]; then
  INC="$INCREDIGO_BIN"
elif command -v incredigo >/dev/null 2>&1; then
  INC="$(command -v incredigo)"
else
  ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel 2>/dev/null || echo "$(dirname "$0")/..")"
  INC="$(mktemp -d)/incredigo"
  echo "== building incredigo from $ROOT =="
  ( cd "$ROOT" && CGO_ENABLED=0 go build -o "$INC" ./cmd/incredigo )
fi
echo "== incredigo: $INC"

command -v gopass >/dev/null 2>&1 || { echo "FAIL: gopass not on PATH (install gopasspw/gopass)"; exit 1; }

# --- clean isolated store + throwaway key ---
rm -rf "$GOPASS_HOMEDIR" "$GNUPGHOME"
mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
mkdir -p "$GOPASS_HOMEDIR"

echo "== throwaway GPG key =="
cat > "$GNUPGHOME/key.batch" <<'EOF'
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Subkey-Type: ecdh
Subkey-Curve: cv25519
Name-Real: Incredigo Drill
Name-Email: drill@incredigo.local
Expire-Date: 0
%commit
EOF
gpg --batch --generate-key "$GNUPGHOME/key.batch" 2>/dev/null
FPR=$(gpg --list-keys --with-colons drill@incredigo.local | awk -F: '/^fpr:/{print $10; exit}')
echo "key: $FPR"

echo "== gopass init (isolated) =="
gopass init --crypto gpg --storage fs "$FPR" </dev/null 2>&1 | tail -2 || gopass init "$FPR" </dev/null 2>&1 | tail -2

# --- seed FAKE entries and remember their values ---
declare -A SEED=(
  [imported/aws/default]='wJalrFAKEsecretKEYwJalrFAKEsecretKEY0001'
  [imported/env/api]='tok-末-value-FAKE-0001'
  [imported/db/postgres]='lab-db-PASSWORD-0001'
)
echo "== seed store =="
for p in "${!SEED[@]}"; do
  printf '%s\n' "${SEED[$p]}" | gopass insert --multiline=false -f "$p"
done
gopass ls --flat

# --- seal (the same bundle the Snapshot backup gate produces) ---
BUNDLE="$(mktemp -d)/restore-drill.age"
echo "== export → sealed bundle: $BUNDLE =="
"$INC" export --out "$BUNDLE" --prefix imported/
[ -s "$BUNDLE" ] || { echo "FAIL: bundle missing/empty"; exit 1; }

# the sealed bundle must NOT contain any plaintext secret
for p in "${!SEED[@]}"; do
  if grep -aqF "${SEED[$p]}" "$BUNDLE"; then
    echo "FAIL: sealed bundle leaked plaintext for $p"; exit 1
  fi
done
echo "   bundle holds no plaintext secret ✓"

# --- simulate LOSS: destroy every entry ---
echo "== DESTROY all entries (simulate loss/corruption) =="
for p in "${!SEED[@]}"; do gopass rm -f "$p" >/dev/null; done
REMAIN=$(gopass ls --flat | grep -c 'imported/' || true)
[ "$REMAIN" -eq 0 ] || { echo "FAIL: store not empty after destroy ($REMAIN left)"; exit 1; }
echo "   store emptied ✓"

# --- restore from the sealed bundle ---
echo "== import → restore =="
"$INC" import --in "$BUNDLE" --force

# --- assert every value is back, byte-for-byte ---
echo "== verify restoration =="
fail=0
for p in "${!SEED[@]}"; do
  got="$(gopass show -o "$p" 2>/dev/null || true)"
  if [ "$got" = "${SEED[$p]}" ]; then
    echo "   $p restored ✓"
  else
    echo "   $p MISMATCH: got '$got' want '${SEED[$p]}'"; fail=1
  fi
done
[ "$fail" -eq 0 ] || { echo "RESTORE_DRILL_FAIL"; exit 1; }

echo
echo "RESTORE_DRILL_OK — sealed backup is a proven recovery path (real gopass, isolated)"
