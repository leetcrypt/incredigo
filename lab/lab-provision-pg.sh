#!/usr/bin/env bash
# Provision the incredigo postgres-rotation POC inside the sandbox VM.
# FAKE creds only, isolated gopass store. Idempotent-ish (drops/recreates role+db).
set -euo pipefail

export GNUPGHOME="$HOME/.lab-gnupg"
export GOPASS_HOMEDIR="$HOME/.lab-gopass"
INIT_PW="oldpw$(date +%s | tail -c 4)"   # fake starting password
ENTRY="imported/postgres/labapp"

echo "== 1. isolated GNUPGHOME + no-protection GPG key =="
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

echo "== 2. isolated gopass store =="
gopass init --storage fs "$KEYID" >/dev/null 2>&1 || gopass init "$KEYID" >/dev/null 2>&1
gopass ls >/dev/null 2>&1 || true

echo "== 3. postgres role + db (labapp owns labdb), starting pw=$INIT_PW =="
sudo -u postgres psql -v ON_ERROR_STOP=1 <<SQL >/dev/null
DROP DATABASE IF EXISTS labdb;
DROP ROLE IF EXISTS labapp;
CREATE ROLE labapp LOGIN PASSWORD '$INIT_PW';
CREATE DATABASE labdb OWNER labapp;
SQL

echo "== 4. prove the starting password authenticates over TCP =="
PGPASSWORD="$INIT_PW" psql -X -w -h 127.0.0.1 -p 5432 -U labapp -d labdb -tAc 'SELECT 1;'

echo "== 5. seed the DSN into gopass (no plaintext file on disk) =="
printf 'postgres://labapp:%s@127.0.0.1:5432/labdb' "$INIT_PW" \
  | gopass insert --multiline=false -f "$ENTRY" >/dev/null
echo "   stored $ENTRY:"
gopass ls --flat | sed 's/^/     /'

echo "DONE. starting pw recorded only in gopass; rotation will replace it."
