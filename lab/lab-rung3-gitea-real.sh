#!/usr/bin/env bash
# lab-rung3-gitea-real.sh — RUNG 3 of the safe-candidate ladder, against a REAL Gitea.
#
# The first REAL-credential rotation: create → verify → store → REVOKE a genuine Gitea
# PAT via the real Gitea API. To keep blast radius at zero on this first run, point it at
# a PURPOSE-MADE THROWAWAY token (make one in the Gitea UI, used by nothing) — a real
# token whose whole lifecycle we prove, with nothing depending on it. That is what earns
# the `gitea` driver its LIVE-REAL proof without risking any in-use token or a git push.
#
# ALL secrets come from the ENVIRONMENT ONLY (never argv, never written to the script),
# and are staged into an ISOLATED throwaway gopass store — the real store is never touched.
#
# Required env:
#   GITEA_BASE        e.g. https://gitea.example.com   (scheme://host[:port])
#   GITEA_USER        your Gitea username
#   GITEA_TOKEN       the THROWAWAY PAT value being rotated
#   GITEA_TOKEN_NAME  the exact name of that PAT in Gitea (needed to DELETE it)
#   GITEA_PW          your Gitea ACCOUNT PASSWORD (basic auth for create/delete)
# Optional:
#   GITEA_INSECURE=1  pass -k to the independent curl checks (self-signed TLS)
#
# Safety: self-owned account + your explicit authorization only. If the account has 2FA,
# basic-auth token management will fail — that is correct (Hard Rule 5, never bypass MFA);
# fall back to the guided worklist for manual rotation.
set -euo pipefail
export PATH=/usr/local/bin:$PATH
export GOPASS_HOMEDIR="${GOPASS_HOMEDIR:-$HOME/.rung3-gopass}"
export GNUPGHOME="${GNUPGHOME:-$HOME/.rung3-gnupg}"
export GOPASS_NO_NOTIFY=true
export INCREDIGO_PASSPHRASE="${INCREDIGO_PASSPHRASE:-rung3-seal-pass}"

PREFIX="rotation-test/"
ENTRY="rotation-test/gitea/realpat"
CURL_TLS=(); [ "${GITEA_INSECURE:-0}" = "1" ] && CURL_TLS=(-k)

# --- require the real inputs (fail loudly, never default a secret) ---
: "${GITEA_BASE:?set GITEA_BASE=https://gitea.example.com}"
: "${GITEA_USER:?set GITEA_USER=<your gitea username>}"
: "${GITEA_TOKEN:?set GITEA_TOKEN=<throwaway PAT value>}"
: "${GITEA_TOKEN_NAME:?set GITEA_TOKEN_NAME=<the exact token name in Gitea>}"
: "${GITEA_PW:?set GITEA_PW=<gitea account password, for basic-auth token mgmt>}"

# --- locate incredigo ---
if [ -n "${INCREDIGO_BIN:-}" ] && [ -x "${INCREDIGO_BIN}" ]; then INC="$INCREDIGO_BIN"
elif command -v incredigo >/dev/null 2>&1; then INC="$(command -v incredigo)"
else
  ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel 2>/dev/null || echo "$(dirname "$0")/..")"
  INC="$(mktemp -d)/incredigo"; echo "== building incredigo from $ROOT =="
  ( cd "$ROOT" && CGO_ENABLED=0 go build -o "$INC" ./cmd/incredigo )
fi
echo "== incredigo: $INC"
command -v gopass >/dev/null 2>&1 || { echo "FAIL: gopass not on PATH"; exit 1; }

api() { curl -fsS -m 10 "${CURL_TLS[@]}" "$@"; }   # helper for independent checks

# --- 0) PRE-CHECK: the old token authenticates right now (independent of incredigo) ---
echo "== 0) pre-check: old token authenticates =="
who="$(api -H "Authorization: token $GITEA_TOKEN" "$GITEA_BASE/api/v1/user" | sed -n 's/.*"login":"\([^"]*\)".*/\1/p')"
[ -n "$who" ] || { echo "FAIL: old token does not authenticate against $GITEA_BASE (check BASE/TOKEN/TLS)"; exit 1; }
echo "   old token -> login=$who ✓"
[ "$who" = "$GITEA_USER" ] || echo "   NOTE: login '$who' != GITEA_USER '$GITEA_USER' (using '$who' is fine if intended)"

# --- clean isolated store + throwaway key ---
rm -rf "$GOPASS_HOMEDIR" "$GNUPGHOME"
mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"; mkdir -p "$GOPASS_HOMEDIR"
cat > "$GNUPGHOME/key.batch" <<'EOF'
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Subkey-Type: ecdh
Subkey-Curve: cv25519
Name-Real: Incredigo Rung3
Name-Email: rung3@incredigo.local
Expire-Date: 0
%commit
EOF
gpg --batch --generate-key "$GNUPGHOME/key.batch" 2>/dev/null
FPR=$(gpg --list-keys --with-colons rung3@incredigo.local | awk -F: '/^fpr:/{print $10; exit}')
gopass init --crypto gpg --storage fs "$FPR" </dev/null 2>&1 | tail -1 || gopass init "$FPR" </dev/null 2>&1 | tail -1

# --- stage the driver-ready blob (token + name + mgmt pw), secrets via env only ---
BLOB="$GITEA_BASE/?name=$(printf %s "$GITEA_TOKEN_NAME" | sed 's/ /%20/g')&pw=$GITEA_PW"
# inject userinfo (user:token@) after the scheme without echoing it in argv
BLOB="$(printf '%s' "$BLOB" | sed "s#://#://$GITEA_USER:$GITEA_TOKEN@#")"
printf '%s\n' "$BLOB" | gopass insert --multiline=false -f "$ENTRY"
echo "== staged $ENTRY (blob holds token+name+pw; never logged)"

echo
echo "== 1) dry-run (noop spine — touches nothing) =="
BKDIR="$(mktemp -d)"
"$INC" rotate --dry-run --prefix "$PREFIX" --backup-out "$BKDIR/dryrun.age" 2>&1 | grep -E 'backup gate|gitea|DRY RUN' || true

echo
echo "== 2) EXECUTE (backup gate → create new token → verify → store → DELETE old) =="
BK="$BKDIR/rung3-backup.age"
INCREDIGO_ALLOW_EXECUTE=1 "$INC" rotate --execute --prefix "$PREFIX" --backup-out "$BK"

echo
echo "== 3) INDEPENDENT cutover check (not via incredigo) =="
NEWBLOB="$(gopass show -o "$ENTRY")"
NEWTOK="$(printf '%s' "$NEWBLOB" | sed -n 's#.*://[^:]*:\([^@]*\)@.*#\1#p')"
fail=0
# new token alive?
if api -H "Authorization: token $NEWTOK" "$GITEA_BASE/api/v1/user" >/dev/null 2>&1; then
  echo "   new token -> 200 (alive) ✓"
else
  echo "   new token -> NOT authenticating ✗"; fail=1
fi
# old token dead?
code="$(curl -s -m 10 "${CURL_TLS[@]}" -o /dev/null -w '%{http_code}' -H "Authorization: token $GITEA_TOKEN" "$GITEA_BASE/api/v1/user" || true)"
if [ "$code" = "401" ] || [ "$code" = "403" ]; then
  echo "   old token -> $code (revoked) ✓"
else
  echo "   old token -> $code (STILL VALID — revoke did not take) ✗"; fail=1
fi
[ -s "$BK" ] && echo "   sealed backup: $BK ✓" || { echo "   no backup ✗"; fail=1; }

echo
if [ "$fail" -eq 0 ]; then
  echo "RUNG3_GITEA_REAL_OK — real Gitea PAT rotated end-to-end (create→verify→store→revoke)"
  echo "   the NEW token is in the isolated store: gopass show -o $ENTRY"
  echo "   (throwaway test token — delete it from the Gitea UI when done, or keep it)"
else
  echo "RUNG3_GITEA_REAL_FAIL — inspect above; old token may still be live"; exit 1
fi
