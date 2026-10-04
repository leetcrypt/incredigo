#!/usr/bin/env bash
# lab-rung1-appsecret-host.sh — RUNG 1 of the safe-candidate ladder, on the HOST.
#
# The first end-to-end run of the REAL rotate --execute spine on the host toolchain
# (real gopass, real backup gate, real audit log, real INCREDIGO_PASSPHRASE seal flow)
# — but against a THROWAWAY "scratch app" (dummy .env + config.yml) so no credential
# that matters is at risk. This is the dress rehearsal before a real dev DB / Gitea PAT.
#
# What it walks (docs/ROTATION-REAL-CRED-RUNBOOK.md Part B):
#   1. stage a self-contained appsecret credential in an ISOLATED gopass store
#   2. --dry-run           (noop spine, touches nothing)
#   3. --blast             (map which files consume the secret, read-only)
#   4. --execute           (backup gate → rotate files in place → verify → store → revoke-noop)
#   5. assert: old value gone from both files, one identical NEW value in both,
#              the stored blob carries the new value, a sealed backup exists
#   6. recovery: import the sealed backup and show the OLD signing value is recoverable
#
# Safety: isolated GOPASS_HOMEDIR + GNUPGHOME (no-protection throwaway key), a scratch
# app dir under $HOME, FAKE secret. It CANNOT touch the real store or a real GPG key.
set -euo pipefail
export PATH=/usr/local/bin:$PATH
export GOPASS_HOMEDIR="${GOPASS_HOMEDIR:-$HOME/.rung1-gopass}"
export GNUPGHOME="${GNUPGHOME:-$HOME/.rung1-gnupg}"
export GOPASS_NO_NOTIFY=true
export INCREDIGO_PASSPHRASE="${INCREDIGO_PASSPHRASE:-rung1-seal-pass}"

SCRATCH="${SCRATCH:-$HOME/incredigo-scratch-app}"
PREFIX="rotation-test/"
ENTRY="rotation-test/appsecret/scratchapp"

# --- locate incredigo (prefer installed/staged, else build from the repo) ---
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
command -v gopass >/dev/null 2>&1 || { echo "FAIL: gopass not on PATH"; exit 1; }

# --- clean isolated store + throwaway key ---
rm -rf "$GOPASS_HOMEDIR" "$GNUPGHOME" "$SCRATCH"
mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
mkdir -p "$GOPASS_HOMEDIR" "$SCRATCH"

echo "== throwaway GPG key =="
cat > "$GNUPGHOME/key.batch" <<'EOF'
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Subkey-Type: ecdh
Subkey-Curve: cv25519
Name-Real: Incredigo Rung1
Name-Email: rung1@incredigo.local
Expire-Date: 0
%commit
EOF
gpg --batch --generate-key "$GNUPGHOME/key.batch" 2>/dev/null
FPR=$(gpg --list-keys --with-colons rung1@incredigo.local | awk -F: '/^fpr:/{print $10; exit}')
gopass init --crypto gpg --storage fs "$FPR" </dev/null 2>&1 | tail -1 || gopass init "$FPR" </dev/null 2>&1 | tail -1

# --- scratch app: two files sharing one signing secret (FAKE) ---
OLD="$(openssl rand -hex 32)"   # 64 hex chars — stands in for a Django SECRET_KEY etc.
cat > "$SCRATCH/.env" <<EOF
APP_ENV=development
SECRET_KEY=$OLD
PORT=8080
EOF
cat > "$SCRATCH/config.yml" <<EOF
app:
  name: scratch
  secret_key_base: $OLD
EOF
echo "== scratch app seeded with SECRET_KEY (old, fake): ${OLD:0:8}…"

# --- stage the appsecret credential in the isolated store ---
# self-contained blob: key + current value + every file that holds it
BLOB="appsecret://local/?key=SECRET_KEY&val=${OLD}&path=${SCRATCH}/.env&path=${SCRATCH}/config.yml"
printf '%s\n' "$BLOB" | gopass insert --multiline=false -f "$ENTRY"
echo "== staged $ENTRY (Source=appsecret so the appsecret driver Detects it)"

cd "$SCRATCH"   # so --blast defaults to searching here
BKDIR="$(mktemp -d)"   # keep every backup out of the real ~/.incredigo

# NOTE: --dry-run / --blast run a read-only host DISCOVERY scan (ScanAll), so they list
# every credential found on the host (ssh/git/netrc/…) alongside the staged entry —
# nothing is touched (noop driver). The destructive --execute path below is different:
# it sources ONLY gopass entries under --prefix, so it can rotate nothing but the scratch
# entry regardless of what discovery sees.

echo
echo "===== 2) DRY RUN (noop spine — touches nothing) ====="
"$INC" rotate --dry-run --prefix "$PREFIX" --backup-out "$BKDIR/dryrun.age"

echo
echo "===== 3) BLAST RADIUS (read-only — which files consume it) ====="
"$INC" rotate --prefix "$PREFIX" --blast --blast-root "$SCRATCH" --backup-out "$BKDIR/blast.age" || true

echo
echo "===== 4) EXECUTE (backup gate → rotate in place → verify → store → revoke) ====="
BK="$BKDIR/rung1-backup.age"
INCREDIGO_ALLOW_EXECUTE=1 "$INC" rotate --execute --prefix "$PREFIX" --backup-out "$BK"

echo
echo "===== 5) ASSERT the cutover ====="
NEW_ENV="$(grep -E '^SECRET_KEY=' "$SCRATCH/.env" | cut -d= -f2)"
NEW_YML="$(grep -E 'secret_key_base:' "$SCRATCH/config.yml" | awk '{print $2}')"
fail=0
grep -qF "$OLD" "$SCRATCH/.env"        && { echo "  ✗ old value still in .env"; fail=1; }        || echo "  ✓ old value gone from .env"
grep -qF "$OLD" "$SCRATCH/config.yml"  && { echo "  ✗ old value still in config.yml"; fail=1; }  || echo "  ✓ old value gone from config.yml"
[ -n "$NEW_ENV" ] && [ "$NEW_ENV" = "$NEW_YML" ] && [ "$NEW_ENV" != "$OLD" ] \
  && echo "  ✓ both files rewritten to one new value: ${NEW_ENV:0:8}…" \
  || { echo "  ✗ files not consistently rewritten (env=${NEW_ENV:0:8} yml=${NEW_YML:0:8})"; fail=1; }
STORED_BLOB="$(gopass show -o "$ENTRY")"
case "$STORED_BLOB" in
  *"val=$NEW_ENV"*) echo "  ✓ stored blob carries the new value" ;;
  *)                echo "  ✗ stored blob does not carry the new value"; fail=1 ;;
esac
[ -s "$BK" ] && echo "  ✓ sealed backup written: $BK" || { echo "  ✗ no sealed backup"; fail=1; }

echo
echo "===== 6) RECOVERY — the OLD signing value is recoverable from the sealed backup ====="
# import the backup into a scratch store slot and read the old value back out
"$INC" import --in "$BK" --force >/dev/null
RECOVERED_BLOB="$(gopass show -o "$ENTRY")"
case "$RECOVERED_BLOB" in
  *"val=$OLD"*) echo "  ✓ restored blob carries the OLD value — file rewrite is reversible from backup" ;;
  *)            echo "  ✗ backup did not carry the old value"; fail=1 ;;
esac

echo
[ "$fail" -eq 0 ] && echo "RUNG1_APPSECRET_OK — real host rotate --execute spine walked on a scratch app" \
                  || { echo "RUNG1_APPSECRET_FAIL"; exit 1; }
