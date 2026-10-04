#!/usr/bin/env bash
# browser-proof.sh — prove incredigo's BROWSER (site-side) password rotation driver
# end-to-end against a DISPOSABLE, containerized Gitea, with zero risk to the host.
#
# This is the browser analog of lab/podman-proof.sh (the API/DB-driver proof). It stands
# up a throwaway Gitea in a `--rm` container, seeds ONE throwaway account, points the
# browserrot engine at an ISOLATED temp HOME + gopass store holding ONLY that one
# credential, then drives browserrot.GiteaSite HEADLESS through the REAL rotation spine:
#   mandatory backup gate -> Rotate (change the password IN THE BROWSER) -> store ->
#   Verify (re-login with the NEW password).
# Finally it INDEPENDENTLY confirms — via a direct Gitea API basic-auth check, NOT
# incredigo's self-report — that the NEW password logs in and the OLD one no longer does.
#
# SAFETY SPINE (do not weaken), mirroring podman-proof.sh:
#   * ONLY the disposable container's throwaway account is ever rotated.
#   * HOME/GNUPGHOME/GOPASS_HOMEDIR are all under a fresh mktemp dir, so incredigo
#     CANNOT read the real ~/.password-store, ~/.incredigo, gopass, ~/.ssh, etc.
#   * Isolation is ASSERTED (verify_isolation) BEFORE the browser rotation is ever run.
#   * The target is always http://127.0.0.1:<container-port> — a loopback disposable.
#   * The container is `--rm`, throwaway-named, and torn down in an EXIT trap.
#   * The headless Chromium is go-rod's own auto-downloaded build (no system package
#     install, no sudo). Its binary cache lives in the REAL ~/.cache/rod (user-local,
#     safe to persist) via a symlink; every SECRET/crypto store stays isolated.
#   * Secrets cross as bytes only — never logged, never persisted in plaintext.
#
# Usage:   INCREDIGO=<worktree-root> lab/browser-proof.sh
# Requires: podman, gopass, gpg, curl on PATH; a Go toolchain to build the tiny
#           lab/browser-proof harness. No host chromium/psql/etc needed.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# INCREDIGO may point at the worktree root to build from (the loop passes it). An
# executable regular file there would be a prebuilt CLI binary we don't need; we only
# need the source tree for the browser harness, so treat a dir as the source root.
if [[ -n "${INCREDIGO:-}" && -d "$INCREDIGO" ]]; then
  REPO_ROOT="$(cd "$INCREDIGO" && pwd -P)"
fi

# The REAL home. Rootless podman derives its storage/state from $HOME, so EVERY podman
# op must run against this home — never the isolated one — or a container created here
# would be invisible to teardown. incredigo's isolation comes from GNUPGHOME/
# GOPASS_HOMEDIR + a per-call HOME override (run_incy), NOT from mutating ambient HOME.
REAL_HOME="$HOME"

IMAGE="${INCY_GITEA_IMAGE:-docker.io/gitea/gitea:1.25}"
STORE_PATH="gitea/login-creds"
GITEA_USER="labadmin"

# ---- throwaway identifiers (nothing real, nothing reused) -------------------
rand()  { head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
PORT="$(( (RANDOM % 20000) + 40000 ))"
OLD_PW="throwaway-$(rand)"           # >=8 chars, unique per run
CTR="incy-gitea-browser-proof-$$"
BINDIR="$(mktemp -d)"                # harness binary + sealed backup + probe scratch
ISO_HOME="$(mktemp -d)"              # isolated HOME for incredigo (NOT the real one)
PASS=0; FAIL=0
ok()   { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
note() { echo; echo "==== $* ===="; }

# ---- teardown trap: always fires, even on error/interrupt -------------------
cleanup() {
  local rc=$?
  podman rm -f "$CTR" >/dev/null 2>&1 || true
  # Remove the browser-cache symlink (never the real cache it points at).
  [[ -L "$ISO_HOME/.cache/rod" ]] && rm -f "$ISO_HOME/.cache/rod" 2>/dev/null || true
  rm -rf "$BINDIR" "$ISO_HOME" 2>/dev/null || true
  return $rc
}
trap cleanup EXIT INT TERM

# ---- 0. build the browser-proof harness -------------------------------------
note "0. build the headless browser-rotation harness (lab/browser-proof)"
export PATH="$HOME/.local/go/bin:$PATH"
command -v go >/dev/null 2>&1 || { echo "go toolchain not on PATH"; exit 1; }
HARNESS="$BINDIR/browser-proof-harness"
( cd "$REPO_ROOT" && go build -o "$HARNESS" ./lab/browser-proof ) \
  && ok "harness built from $REPO_ROOT" || { bad "harness build failed"; exit 1; }

# ---- 1. disposable Gitea container + throwaway account ----------------------
note "1. disposable Gitea container ($IMAGE) on 127.0.0.1:$PORT"
podman run --rm -d --name "$CTR" \
  -e GITEA__security__INSTALL_LOCK=true \
  -e GITEA__security__PASSWORD_COMPLEXITY=off \
  -e GITEA__server__ROOT_URL="http://127.0.0.1:${PORT}/" \
  -e GITEA__server__HTTP_PORT=3000 \
  -e GITEA__database__DB_TYPE=sqlite3 \
  -e GITEA__service__DISABLE_REGISTRATION=true \
  -e GITEA__log__LEVEL=warn \
  -p "127.0.0.1:${PORT}:3000" "$IMAGE" >/dev/null \
  || { echo "container start failed"; exit 1; }

for i in $(seq 1 60); do
  curl -fsS "http://127.0.0.1:${PORT}/api/v1/version" >/dev/null 2>&1 && break
  sleep 1
done
GITEA_VER="$(curl -fsS "http://127.0.0.1:${PORT}/api/v1/version" 2>/dev/null)"
[[ -n "$GITEA_VER" ]] && ok "gitea ready ($GITEA_VER)" || { bad "gitea never became ready"; exit 1; }

# ONE throwaway admin account — the credential we rotate. Created via the in-container
# CLI as the git user (the image's runtime user).
podman exec -u git "$CTR" gitea admin user create \
  --admin --username "$GITEA_USER" --password "$OLD_PW" \
  --email lab@incredigo.invalid --must-change-password=false >/dev/null 2>&1 \
  && ok "throwaway account '$GITEA_USER' created" || { bad "account create failed"; exit 1; }

# INDEPENDENT ground-truth probe: Gitea API basic-auth with the ACCOUNT PASSWORD (no
# token, no incredigo). rc 0 == that password authenticates.
auth() { # auth <password>
  curl -fsS -u "${GITEA_USER}:$1" "http://127.0.0.1:${PORT}/api/v1/user" >/dev/null 2>&1
}
auth_code() { # auth_code <password> -> prints the HTTP status
  curl -s -o /dev/null -w '%{http_code}' -u "${GITEA_USER}:$1" \
    "http://127.0.0.1:${PORT}/api/v1/user" 2>/dev/null
}
auth "$OLD_PW" && ok "OLD password authenticates (baseline, via Gitea API)" || { bad "baseline auth failed"; exit 1; }

# ---- 2. isolated HOME + gopass store (incredigo cannot see any real cred) ----
note "2. isolated HOME + gopass store"
export GNUPGHOME="$ISO_HOME/.gnupg"
export GOPASS_HOMEDIR="$ISO_HOME/.gopass"
export GOPASS_NO_NOTIFY=true
export INCREDIGO_PASSPHRASE="lab-browser-proof-$(rand)"
mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"; mkdir -p "$GOPASS_HOMEDIR"
# run_incy: run any incredigo/gopass/gpg command with the ISOLATED home so nothing it
# does can touch the real user's dotfiles/credential stores.
run_incy() { HOME="$ISO_HOME" "$@"; }

# Share ONLY the go-rod Chromium binary cache with the real, user-local ~/.cache/rod
# (DefaultBrowserDir = $HOME/.cache/rod/browser). This is a browser binary, not a
# secret; persisting it across runs is explicitly fine and avoids re-downloading
# ~150MB each run. All secret/crypto stores remain under $ISO_HOME.
mkdir -p "$REAL_HOME/.cache/rod" "$ISO_HOME/.cache"
ln -s "$REAL_HOME/.cache/rod" "$ISO_HOME/.cache/rod"

cat > "$BINDIR/key.batch" <<'EOF'
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Subkey-Type: ecdh
Subkey-Curve: cv25519
Name-Real: Incredigo Browser Proof
Name-Email: proof@incredigo.invalid
Expire-Date: 0
%commit
EOF
run_incy gpg --batch --generate-key "$BINDIR/key.batch" >/dev/null 2>&1
FPR="$(run_incy gpg --list-keys --with-colons proof@incredigo.invalid | awk -F: '/^fpr:/{print $10; exit}')"
run_incy gopass init --crypto gpg --storage fs "$FPR" </dev/null >/dev/null 2>&1
# seed EXACTLY ONE entry: the throwaway account password (line 1).
printf '%s' "$OLD_PW" | run_incy gopass insert --multiline=false -f "$STORE_PATH" >/dev/null 2>&1
ok "seeded $STORE_PATH (throwaway account password)"

# ---- isolation asserts (MUST pass before the browser rotation) --------------
note "ISOLATION ASSERTS (block execute unless all pass)"
verify_isolation() {
  local iso_ok=1
  local realhome; realhome="$(getent passwd "$(id -u)" | cut -d: -f6)"
  [[ "$ISO_HOME" == /tmp/* && "$ISO_HOME" != "$realhome"* ]] \
    && ok "incredigo HOME is a temp dir outside the real home" || { bad "HOME not isolated"; iso_ok=0; }
  [[ "$GNUPGHOME" != "$realhome"* && "$GOPASS_HOMEDIR" != "$realhome"* ]] \
    && ok "GNUPGHOME + GOPASS_HOMEDIR are outside the real home" || { bad "store dir under real home"; iso_ok=0; }
  local entries; entries="$(run_incy gopass ls --flat 2>/dev/null)"
  if [[ "$entries" == "$STORE_PATH" ]]; then
    ok "gopass store holds ONLY the one throwaway entry (no real creds visible)"
  else
    bad "gopass store has unexpected entries: $entries"; iso_ok=0
  fi
  if [[ -d "$realhome/.password-store" ]]; then
    [[ -z "$(run_incy gopass ls --flat 2>/dev/null | grep -vx "$STORE_PATH")" ]] \
      && ok "real ~/.password-store exists but is NOT visible to incredigo" \
      || { bad "real password-store leaked into incredigo view"; iso_ok=0; }
  else
    ok "no real ~/.password-store on this host (nothing to leak)"
  fi
  # the stored secret must be exactly our throwaway seed, nothing borrowed from a real store.
  local got; got="$(run_incy gopass show -o "$STORE_PATH" 2>/dev/null)"
  [[ "$got" == "$OLD_PW" ]] \
    && ok "stored credential is our throwaway seed (loopback container target)" \
    || { bad "unexpected stored credential"; iso_ok=0; }
  return $((1 - iso_ok))
}
if ! verify_isolation; then
  echo; echo "ISOLATION FAILED — refusing to run the browser rotation. Aborting." >&2
  exit 1
fi

# ---- 3. REAL browser rotation via the browserrot spine ----------------------
note "3. headless browser rotation (backup gate -> Rotate -> store -> Verify)"
# CHROME_BIN intentionally UNSET: go-rod auto-downloads Chromium into ~/.cache/rod
# (shared via the symlink above). BACKUP_DIR is the temp scratch, cleaned on exit.
HARNESS_OUT="$(GITEA_BASE="http://127.0.0.1:${PORT}" \
  GITEA_USER="$GITEA_USER" \
  GITEA_STORE_PATH="$STORE_PATH" \
  BACKUP_DIR="$BINDIR/backups" \
  run_incy "$HARNESS" 2>&1)"
echo "$HARNESS_OUT"
grep -q 'BACKUP_GATE_OK' <<<"$HARNESS_OUT" && ok "mandatory backup gate ran" || bad "no backup gate"
grep -q 'ROTATE_OK' <<<"$HARNESS_OUT" && ok "browser change-password confirmed by the site" || bad "rotate did not confirm"
grep -q 'BROWSER_ROT_HARNESS_OK' <<<"$HARNESS_OUT" \
  && ok "spine reported backup+rotate+store+verify success" || bad "spine did not complete"

# ---- 4. INDEPENDENT verification (ground truth, not incredigo's word) --------
note "4. independent auth checks (the actual proof, via Gitea API)"
NEW_PW="$(run_incy gopass show -o "$STORE_PATH" 2>/dev/null)"
if [[ -n "$NEW_PW" && "$NEW_PW" != "$OLD_PW" ]]; then ok "stored password changed"; else bad "password unchanged in store"; fi
if auth "$NEW_PW"; then
  ok "new-works: NEW password authenticates (Gitea API 200)"
else
  bad "new-works: NEW password does NOT authenticate"
fi
OLD_CODE="$(auth_code "$OLD_PW")"
if [[ "$OLD_CODE" == "401" || "$OLD_CODE" == "403" ]]; then
  ok "old-rejected: OLD password rejected (Gitea API $OLD_CODE)"
else
  bad "old-rejected: OLD password still returns $OLD_CODE (cutover incomplete)"
fi

# ---- summary ----------------------------------------------------------------
note "SUMMARY"
echo "  image=$IMAGE  port=$PORT  user=$GITEA_USER  PASS=$PASS  FAIL=$FAIL"
if [[ "$FAIL" -eq 0 ]]; then
  echo "  VERDICT: BROWSER PROOF PASSED — incredigo rotated the disposable Gitea login in a real headless browser, end-to-end."
  echo "BROWSER_PROOF_OK rc=0"
  exit 0
else
  echo "  VERDICT: FAILED ($FAIL check(s)) — see output above."
  echo "BROWSER_PROOF_FAIL rc=$FAIL"
  exit "$FAIL"
fi
