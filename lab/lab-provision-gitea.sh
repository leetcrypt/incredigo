#!/usr/bin/env bash
# Provision the incredigo Gitea-PAT-rotation POC inside the sandbox VM.
# FAKE/self-owned local Gitea only, isolated gopass store. Idempotent-ish.
set -euo pipefail

export GNUPGHOME="$HOME/.lab-gnupg"
export GOPASS_HOMEDIR="$HOME/.lab-gopass"
GITEA_DIR="$HOME/gitea-lab"
GITEA_USER="labadmin"
GITEA_PW="labpw123"
ENTRY="imported/gitea/labtoken"
OLDTOK_FILE="$HOME/.lab-gitea-oldtoken"

echo "== 1. stop any prior gitea, reset work dir =="
pkill -f 'gitea web' 2>/dev/null || true
sleep 1
rm -rf "$GITEA_DIR"
mkdir -p "$GITEA_DIR/data" "$GITEA_DIR/repos" "$GITEA_DIR/custom/conf"

cat > "$GITEA_DIR/custom/conf/app.ini" <<INI
APP_NAME = incredigo-lab
RUN_USER = $(whoami)
RUN_MODE = prod
WORK_PATH = $GITEA_DIR

[server]
PROTOCOL = http
HTTP_ADDR = 127.0.0.1
HTTP_PORT = 3000
ROOT_URL = http://127.0.0.1:3000/
DISABLE_SSH = true
OFFLINE_MODE = true

[database]
DB_TYPE = sqlite3
PATH = $GITEA_DIR/data/gitea.db

[repository]
ROOT = $GITEA_DIR/repos

[security]
INSTALL_LOCK = true
SECRET_KEY = labsecretkeylabsecretkey
PASSWORD_HASH_ALGO = argon2

[service]
DISABLE_REGISTRATION = true

[log]
MODE = console
LEVEL = warn
INI

export GITEA_WORK_DIR="$GITEA_DIR"
CONF="$GITEA_DIR/custom/conf/app.ini"

echo "== 2. migrate db + create admin user ($GITEA_USER) =="
gitea -c "$CONF" migrate >/dev/null 2>&1
gitea -c "$CONF" admin user create \
  --admin --username "$GITEA_USER" --password "$GITEA_PW" \
  --email lab@incredigo.invalid --must-change-password=false >/dev/null 2>&1

echo "== 3. start gitea (http://127.0.0.1:3000) =="
nohup gitea -c "$CONF" web >"$GITEA_DIR/gitea.log" 2>&1 &
for i in $(seq 1 30); do
  curl -fsS http://127.0.0.1:3000/api/v1/version >/dev/null 2>&1 && break
  sleep 1
done
echo "   version: $(curl -fsS http://127.0.0.1:3000/api/v1/version)"

echo "== 4. create initial (seed) token via basic auth =="
SEED_NAME="seed-$(date +%s)"
SEED_JSON=$(curl -fsS -u "$GITEA_USER:$GITEA_PW" \
  -H 'content-type: application/json' \
  -d "{\"name\":\"$SEED_NAME\",\"scopes\":[\"write:user\",\"read:user\"]}" \
  http://127.0.0.1:3000/api/v1/users/$GITEA_USER/tokens)
SEED_TOK=$(printf '%s' "$SEED_JSON" | sed -n 's/.*"sha1":"\([0-9a-f]*\)".*/\1/p')
test -n "$SEED_TOK" || { echo "FAILED to mint seed token: $SEED_JSON"; exit 1; }
printf '%s' "$SEED_TOK" > "$OLDTOK_FILE"
echo "   seed token name=$SEED_NAME (value saved to $OLDTOK_FILE for the cutover check)"

echo "== 5. isolated GNUPGHOME + no-protection GPG key =="
rm -rf "$GNUPGHOME" "$GOPASS_HOMEDIR"
mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
cat > /tmp/keyparams <<EOF
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Subkey-Type: ecdh
Subkey-Curve: cv25519
Name-Real: incredigo lab
Name-Email: lab@incredigo.invalid
Expire-Date: 0
%commit
EOF
gpg --batch --gen-key /tmp/keyparams >/dev/null 2>&1
rm -f /tmp/keyparams
KEYID=$(gpg --list-keys --with-colons lab@incredigo.invalid | awk -F: '/^pub/{print $5; exit}')
echo "   key: $KEYID"

echo "== 6. isolated gopass store =="
gopass init --storage fs "$KEYID" >/dev/null 2>&1 || gopass init "$KEYID" >/dev/null 2>&1
gopass ls >/dev/null 2>&1 || true

echo "== 7. seed driver-ready blob into gopass (token + mgmt pw in query) =="
# Blob: http://user:token@host/?name=<tokenname>&pw=<mgmt-password>
BLOB="http://$GITEA_USER:$SEED_TOK@127.0.0.1:3000/?name=$SEED_NAME&pw=$GITEA_PW"
printf '%s' "$BLOB" | gopass insert --multiline=false -f "$ENTRY" >/dev/null
echo "   stored $ENTRY:"
gopass ls --flat | sed 's/^/     /'

echo "== 8. prove the seed token authenticates now =="
curl -fsS -H "Authorization: token $SEED_TOK" http://127.0.0.1:3000/api/v1/user \
  | sed -n 's/.*"login":"\([^"]*\)".*/   GET \/user -> login=\1/p'

echo "DONE. Run: GNUPGHOME=$GNUPGHOME GOPASS_HOMEDIR=$GOPASS_HOMEDIR \\"
echo "  INCREDIGO_PASSPHRASE=labseal123 INCREDIGO_ALLOW_EXECUTE=1 incredigo rotate --execute"
