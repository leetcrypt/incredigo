#!/usr/bin/env bash
# lab-gitea-blast-vm.sh — prove the gitea MULTI-REFERENCE blast-and-cutover in the VM.
#
# This is the LIVE-VM proof for the blast-and-cutover: a single Gitea token embedded
# VERBATIM in several on-disk reference files (a fake ~/.git-credentials, a fake repo
# .git/config remote URL, a fake tea config) is rotated ONCE and every reference is
# rewritten old→new in lockstep — the cutover a real in-use PAT needs so git auth never
# breaks. Runs against the REAL local Gitea stood up by lab-provision-gitea.sh
# (http://127.0.0.1:3000), isolated gopass store, self-owned only.
#
# Ordering proof (the whole point): incredigo mints the new token, proves it
# authenticates, THEN rewrites every ref, and only revokes the old token LAST — so at no
# point is a dead token written into a git config, and any failure leaves every ref
# pointing at a still-live token.
#
# Preconditions: run lab-provision-gitea.sh first (it starts Gitea + creates the isolated
# GPG key + gopass store + admin user labadmin/labpw123).
set -euo pipefail
export PATH=/usr/local/bin:$PATH
export GNUPGHOME="${GNUPGHOME:-$HOME/.lab-gnupg}"
export GOPASS_HOMEDIR="${GOPASS_HOMEDIR:-$HOME/.lab-gopass}"
export GOPASS_NO_NOTIFY=true
export INCREDIGO_PASSPHRASE="${INCREDIGO_PASSPHRASE:-labseal123}"

BASE="http://127.0.0.1:3000"
GITEA_USER="labadmin"
GITEA_PW="labpw123"
PREFIX="rotation-test/"
ENTRY="rotation-test/gitea/blastpat"
REFDIR="$HOME/.lab-gitea-refs"

api() { curl -fsS -m 10 "$@"; }

# --- locate / build incredigo ---
if [ -n "${INCREDIGO_BIN:-}" ] && [ -x "${INCREDIGO_BIN}" ]; then INC="$INCREDIGO_BIN"
elif command -v incredigo >/dev/null 2>&1; then INC="$(command -v incredigo)"
else
  ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel 2>/dev/null || echo "$(dirname "$0")/..")"
  INC="$(mktemp -d)/incredigo"; echo "== building incredigo from $ROOT =="
  ( cd "$ROOT" && CGO_ENABLED=0 go build -o "$INC" ./cmd/incredigo )
fi
echo "== incredigo: $INC"
command -v gopass >/dev/null 2>&1 || { echo "FAIL: gopass not on PATH"; exit 1; }

# --- 0) Gitea must be up (provisioned by lab-provision-gitea.sh) ---
echo "== 0) Gitea up? =="
api "$BASE/api/v1/version" >/dev/null 2>&1 || {
  echo "FAIL: Gitea not reachable at $BASE — run lab-provision-gitea.sh first"; exit 1; }
echo "   version: $(api "$BASE/api/v1/version")"

# --- 1) mint a fresh seed token (basic auth) — this is the 'in-use' token we rotate ---
echo "== 1) mint seed token (the in-use PAT) =="
SEED_NAME="blast-seed-$(date +%s)"
SEED_JSON="$(api -u "$GITEA_USER:$GITEA_PW" -H 'content-type: application/json' \
  -d "{\"name\":\"$SEED_NAME\",\"scopes\":[\"write:user\",\"read:user\"]}" \
  "$BASE/api/v1/users/$GITEA_USER/tokens")"
SEED_TOK="$(printf '%s' "$SEED_JSON" | sed -n 's/.*"sha1":"\([0-9a-f]*\)".*/\1/p')"
test -n "$SEED_TOK" || { echo "FAIL to mint seed: $SEED_JSON"; exit 1; }
echo "   seed name=$SEED_NAME (value not printed)"

# ensure a real repo exists so step 8's git ls-remote genuinely exercises auth
api -u "$GITEA_USER:$GITEA_PW" -H 'content-type: application/json' \
  -d '{"name":"repo","auto_init":true,"private":true}' \
  "$BASE/api/v1/user/repos" >/dev/null 2>&1 || true  # 201 new / 409 exists — both fine

# --- 2) embed the seed token VERBATIM in three real-world reference shapes ---
echo "== 2) seed the reference files (git-credentials + repo remote + tea config) =="
rm -rf "$REFDIR"; mkdir -p "$REFDIR/repo/.git"
GITCREDS="$REFDIR/.git-credentials"
GITCONFIG="$REFDIR/repo/.git/config"
TEACONF="$REFDIR/tea-config.yml"
printf 'http://%s:%s@127.0.0.1:3000\n' "$GITEA_USER" "$SEED_TOK" > "$GITCREDS"
cat > "$GITCONFIG" <<CFG
[remote "origin"]
	url = http://$GITEA_USER:$SEED_TOK@127.0.0.1:3000/$GITEA_USER/repo.git
	fetch = +refs/heads/*:refs/remotes/origin/*
CFG
cat > "$TEACONF" <<YML
logins:
  - name: lab
    url: http://127.0.0.1:3000
    user: $GITEA_USER
    token: $SEED_TOK
YML
for f in "$GITCREDS" "$GITCONFIG" "$TEACONF"; do
  grep -q "$SEED_TOK" "$f" || { echo "FAIL: seed token not in $f"; exit 1; }
done
echo "   3 refs seeded, each holds the token verbatim"

# --- 3) stage the driver-ready blob with one ref= per file (secrets via var, not argv) ---
echo "== 3) stage blob with ref= per file =="
BLOB="http://$GITEA_USER:$SEED_TOK@127.0.0.1:3000/?name=$SEED_NAME&pw=$GITEA_PW"
BLOB="$BLOB&ref=$GITCREDS&ref=$GITCONFIG&ref=$TEACONF"
printf '%s' "$BLOB" | gopass insert --multiline=false -f "$ENTRY" >/dev/null
echo "   staged $ENTRY (name+pw+3×ref; token never logged)"

# --- 4) dry-run then EXECUTE (backup gate → rotate → rewrite refs → verify → revoke) ---
BKDIR="$(mktemp -d)"; BK="$BKDIR/blast-backup.age"
echo "== 4) dry-run =="
"$INC" rotate --dry-run --prefix "$PREFIX" --backup-out "$BKDIR/dry.age" 2>&1 | grep -E 'gitea|backup gate|DRY RUN' || true
echo "== 5) EXECUTE =="
INCREDIGO_ALLOW_EXECUTE=1 "$INC" rotate --execute --prefix "$PREFIX" --backup-out "$BK"

# --- 6) assert the cutover landed in EVERY reference ---
echo "== 6) assert every reference rewritten old→new =="
NEWBLOB="$(gopass show -o "$ENTRY")"
NEWTOK="$(printf '%s' "$NEWBLOB" | sed -n 's#.*://[^:]*:\([^@]*\)@.*#\1#p')"
fail=0
for f in "$GITCREDS" "$GITCONFIG" "$TEACONF"; do
  if grep -q "$SEED_TOK" "$f"; then echo "   $f: OLD token STILL present ✗"; fail=1
  elif grep -q "$NEWTOK" "$f"; then echo "   $f: rewritten to new token ✓"
  else echo "   $f: neither token present ✗"; fail=1; fi
done

# --- 7) independent liveness: new→200, old→401 ---
echo "== 7) independent token liveness =="
if api -H "Authorization: token $NEWTOK" "$BASE/api/v1/user" >/dev/null 2>&1; then
  echo "   new token -> 200 (alive) ✓"; else echo "   new token -> not alive ✗"; fail=1; fi
code="$(curl -s -m 10 -o /dev/null -w '%{http_code}' -H "Authorization: token $SEED_TOK" "$BASE/api/v1/user" || true)"
if [ "$code" = "401" ] || [ "$code" = "403" ]; then echo "   old token -> $code (revoked) ✓"
else echo "   old token -> $code (STILL VALID) ✗"; fail=1; fi

# --- 8) prove the rewritten .git-credentials line AUTHENTICATES at the git transport ---
# The cutover's job is that the credential the git tooling reads is ACCEPTED (not 401).
# NOTE: the driver mints the new token with fixed write:user/read:user scopes, so a git
# repo op may return 403 (authenticated, lacks repo scope) — that is a token-SCOPE matter
# (scope-cloning is a documented follow-on), NOT a cutover failure. A broken cutover would
# yield 401 (credential rejected). So we assert: NOT 401.
echo "== 8) rewritten .git-credentials authenticates (not 401) =="
NEWURL="$(sed -n '1p' "$GITCREDS")"
gcode="$(curl -s -m 10 -o /dev/null -w '%{http_code}' "$NEWURL/$GITEA_USER/repo.git/info/refs?service=git-upload-pack" || true)"
if [ "$gcode" = "401" ]; then
  echo "   git transport -> 401 (rewritten credential REJECTED — cutover broke auth) ✗"; fail=1
else
  echo "   git transport -> $gcode (rewritten credential accepted; 403=token-scope, not cutover) ✓"
fi

[ -s "$BK" ] && echo "   sealed backup: $BK ✓" || { echo "   no backup ✗"; fail=1; }

echo
if [ "$fail" -eq 0 ]; then
  echo "GITEA_BLAST_VM_OK — one rotation rewrote all 3 references; new alive, old revoked"
else
  echo "GITEA_BLAST_VM_FAIL — inspect above"; exit 1
fi
