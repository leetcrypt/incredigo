#!/usr/bin/env bash
# Live cutover POC for the LOCAL app-signing-secret rotation driver (appsecret), inside
# the sandbox VM. FAKE secret only, isolated gopass store. Writes two real config files
# that share one SECRET_KEY value, seeds a driver-ready appsecret:// blob (carrying the
# value AND both file paths) into gopass, runs `rotate --execute`, and asserts BOTH
# files were rewritten in place with a fresh value and the old value is gone everywhere.
set -euo pipefail

export GNUPGHOME="$HOME/.lab-gnupg"
export GOPASS_HOMEDIR="$HOME/.lab-gopass"
export INCREDIGO_PASSPHRASE='lab-seal-passphrase-001'

OLD_VAL="django-insecure-oldval-0123456789abcdef"   # fake starting signing secret
APPDIR="$HOME/labapp"
WRKDIR="$HOME/labworker"
ENV_FILE="$APPDIR/.env"
YML_FILE="$WRKDIR/config.yaml"
ENTRY="imported/appsecret/secret_key"

echo "== 1. two real config files sharing one SECRET_KEY value =="
mkdir -p "$APPDIR" "$WRKDIR"
cat > "$ENV_FILE" <<EOF
PORT=8080
DEBUG=false
SECRET_KEY=$OLD_VAL
EOF
chmod 600 "$ENV_FILE"
cat > "$YML_FILE" <<EOF
service:
  name: worker
  secret_key: $OLD_VAL
EOF
chmod 644 "$YML_FILE"
echo "   $ENV_FILE (0600), $YML_FILE (0644) both seeded with OLD_VAL"

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

echo "== 3. seed the driver-ready appsecret blob (value + BOTH paths) into gopass =="
# Raw slashes are valid inside a query value, so the absolute paths need no escaping.
BLOB="appsecret://local/?key=SECRET_KEY&val=${OLD_VAL}&path=${ENV_FILE}&path=${YML_FILE}"
printf '%s' "$BLOB" | gopass insert --multiline=false -f "$ENTRY" >/dev/null
gopass ls --flat | sed 's/^/     /'

echo "== 4. rotate --execute (MANDATORY backup gate runs first) =="
# prefix is the imported/ ROOT so Mode A derives Source=appsecret from the first segment.
INCREDIGO_ALLOW_EXECUTE=1 incredigo rotate --execute --prefix imported/ 2>&1 | sed 's/^/   /'

echo "== 5. CUTOVER ASSERTIONS =="
NEW_BLOB=$(gopass show -o "$ENTRY")
# pull val= out of the rebuilt blob (between 'val=' and the next '&').
NEW_VAL=$(printf '%s' "$NEW_BLOB" | sed -n 's/.*[?&]val=\([^&]*\).*/\1/p')
echo "   new val (from gopass blob): $NEW_VAL"

fail=0
[ -n "$NEW_VAL" ] && [ "$NEW_VAL" != "$OLD_VAL" ] && echo "   OK: signing value changed" || { echo "   FAIL: value unchanged"; fail=1; }
for f in "$ENV_FILE" "$YML_FILE"; do
  grep -qF "$NEW_VAL" "$f" && echo "   OK: $f holds NEW value" || { echo "   FAIL: $f missing NEW value"; fail=1; }
  grep -qF "$OLD_VAL" "$f" && { echo "   FAIL: $f still holds OLD value"; fail=1; } || echo "   OK: $f dropped OLD value"
done
grep -qF "PORT=8080" "$ENV_FILE" && echo "   OK: unrelated .env line preserved" || { echo "   FAIL: unrelated line lost"; fail=1; }
# mode preserved on the 0644 file
MODE=$(stat -c '%a' "$YML_FILE")
[ "$MODE" = "644" ] && echo "   OK: config.yaml mode preserved (644)" || { echo "   FAIL: mode changed to $MODE"; fail=1; }

echo
if [ "$fail" = 0 ]; then echo "ALL APPSECRET CUTOVER ASSERTIONS PASSED"; else echo "SOME ASSERTIONS FAILED"; exit 1; fi
