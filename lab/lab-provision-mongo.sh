#!/usr/bin/env bash
# Live cutover POC for the MongoDB in-place rotation driver, inside the sandbox VM.
# FAKE creds only, isolated gopass store. Installs REAL mongod + mongosh (MongoDB
# 8.0 from the official apt repo), creates labapp@admin owning labdb, seeds the
# driver-ready mongodb URI blob, runs `rotate --execute`, and asserts the OLD
# password stops authenticating while the NEW one (read back from gopass) works.
#
# This promotes the mongo driver from MOCK-ONLY to LIVE-VM: the real mongod (not the
# fake-mongosh stub) validates the changeUserPassword cutover.
set -euo pipefail

export GNUPGHOME="$HOME/.lab-gnupg"
export GOPASS_HOMEDIR="$HOME/.lab-gopass"
export INCREDIGO_PASSPHRASE='lab-seal-passphrase-001'
MONGO_PW="oldmg$(date +%s | tail -c 5)"

echo "== 0. ensure real mongod + mongosh are installed (MongoDB 8.0 official repo) =="
if ! command -v mongod >/dev/null 2>&1 || ! command -v mongosh >/dev/null 2>&1; then
  . /etc/os-release
  curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc \
    | sudo gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg --dearmor --yes
  echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] https://repo.mongodb.org/apt/ubuntu ${VERSION_CODENAME}/mongodb-org/8.0 multiverse" \
    | sudo tee /etc/apt/sources.list.d/mongodb-org-8.0.list >/dev/null
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq mongodb-org >/dev/null
fi
mongod --version | head -1
mongosh --version

echo "== 1. start mongod (auth DISABLED for the initial user bootstrap) =="
# Run with a clean conf, no auth yet, so we can create the bootstrap user.
sudo sed -i 's/^\(\s*\)authorization:.*/\1authorization: disabled/' /etc/mongod.conf 2>/dev/null || true
sudo systemctl restart mongod
for i in $(seq 1 30); do
  mongosh --quiet --norc 127.0.0.1:27017/admin --eval 'db.runCommand({ping:1}).ok' >/dev/null 2>&1 && break
  sleep 1
done
mongosh --quiet --norc 127.0.0.1:27017/admin --eval 'db.runCommand({ping:1})' >/dev/null

echo "== 2. isolated GNUPGHOME + no-protection GPG key + gopass store =="
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
gopass init --storage fs "$KEYID" >/dev/null 2>&1 || gopass init "$KEYID" >/dev/null 2>&1

echo "== 3. create labapp in admin (can change its own pw), starting pw=$MONGO_PW =="
# Drop any prior user, recreate. userAdminAnyDatabase lets labapp run
# changeUserPassword on itself (the driver's cutover). Script on STDIN — no argv secret.
cat <<JS | mongosh --quiet --norc 127.0.0.1:27017/admin
try { db.getSiblingDB("admin").dropUser("labapp"); } catch (e) {}
db.getSiblingDB("admin").createUser({
  user: "labapp",
  pwd: "$MONGO_PW",
  roles: [ { role: "userAdminAnyDatabase", db: "admin" }, { role: "readWrite", db: "labdb" } ]
});
print("USER-CREATED");
JS

echo "== 4. ENABLE auth and restart mongod =="
if grep -q '^\s*security:' /etc/mongod.conf; then
  sudo sed -i 's/^\(\s*\)authorization:.*/\1authorization: enabled/' /etc/mongod.conf
  grep -q 'authorization:' /etc/mongod.conf || printf '\nsecurity:\n  authorization: enabled\n' | sudo tee -a /etc/mongod.conf >/dev/null
else
  printf '\nsecurity:\n  authorization: enabled\n' | sudo tee -a /etc/mongod.conf >/dev/null
fi
sudo systemctl restart mongod
for i in $(seq 1 30); do
  mongosh --quiet --norc 127.0.0.1:27017/admin --eval 'db.runCommand({ping:1}).ok' >/dev/null 2>&1 && break
  sleep 1
done

# Helper: prints AUTH-OK / AUTH-FAIL for a given password (script on stdin, no argv).
# Real mongosh echoes its "labdb> " prompt to stdout on a pipe, so filter to the token.
mongo_auth() {
  cat <<JS | mongosh --quiet --norc 127.0.0.1:27017/labdb 2>/dev/null | grep -Eo 'AUTH-OK|AUTH-FAIL' | head -n1
try { var ok = db.getSiblingDB("admin").auth("labapp","$1"); print(ok ? "AUTH-OK" : "AUTH-FAIL"); }
catch (e) { print("AUTH-FAIL"); }
JS
}

echo "   prove starting mongo pw authenticates (auth now enforced):"
ok=0
for i in $(seq 1 15); do
  if [ "$(mongo_auth "$MONGO_PW")" = "AUTH-OK" ]; then ok=1; break; fi
  sleep 1
done
[ "$ok" = 1 ] || { echo "   FAIL: starting pw did not authenticate"; exit 1; }
echo "      OK"

echo "== 5. seed driver-ready blob into gopass (no plaintext on disk) =="
printf 'mongodb://labapp:%s@127.0.0.1:27017/labdb?authSource=admin' "$MONGO_PW" \
  | gopass insert --multiline=false -f imported/mongo/labapp >/dev/null
gopass ls --flat | sed 's/^/     /'

echo "== 6. rotate --execute (MANDATORY backup gate runs first) =="
INCREDIGO_ALLOW_EXECUTE=1 incredigo rotate --execute --prefix imported/ 2>&1 | sed 's/^/   /'

echo "== 7. CUTOVER ASSERTIONS =="
NEW_URI=$(gopass show -o imported/mongo/labapp)
NEW_PW=$(printf '%s' "$NEW_URI" | sed -E 's#.*://[^:]*:([^@]*)@.*#\1#')

fail=0
echo "   [mongo] OLD pw must now FAIL:"
if [ "$(mongo_auth "$MONGO_PW")" = "AUTH-OK" ]; then
  echo "      FAIL: old mongo pw still authenticates"; fail=1
else echo "      OK: old mongo pw rejected"; fi
echo "   [mongo] NEW pw must WORK:"
if [ "$(mongo_auth "$NEW_PW")" = "AUTH-OK" ]; then
  echo "      OK: new mongo pw authenticates"; else echo "      FAIL: new mongo pw rejected"; fail=1; fi
echo "   [leak] new password must NOT equal old:"
[ "$NEW_PW" != "$MONGO_PW" ] && echo "      OK: password actually changed" || { echo "      FAIL: pw unchanged"; fail=1; }

echo
if [ "$fail" = 0 ]; then echo "ALL MONGO CUTOVER ASSERTIONS PASSED"; else echo "SOME ASSERTIONS FAILED"; exit 1; fi
