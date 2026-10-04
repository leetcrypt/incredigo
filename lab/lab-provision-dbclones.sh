#!/usr/bin/env bash
# Live cutover POC for the MySQL and Redis in-place rotation drivers, inside the
# sandbox VM. FAKE creds only, isolated gopass store. Installs real mariadb-server +
# redis-server, seeds driver-ready blobs, runs `rotate --execute`, and asserts the
# OLD password stops authenticating while the NEW one (read back from gopass) works.
set -euo pipefail

export GNUPGHOME="$HOME/.lab-gnupg"
export GOPASS_HOMEDIR="$HOME/.lab-gopass"
export INCREDIGO_PASSPHRASE='lab-seal-passphrase-001'
MYSQL_PW="oldmy$(date +%s | tail -c 4)"
REDIS_PW="oldrd$(date +%s | tail -c 4)"

echo "== 0. ensure mariadb-server + redis-server + clients are installed =="
need_install=0
command -v mysql       >/dev/null 2>&1 || need_install=1
command -v redis-cli   >/dev/null 2>&1 || need_install=1
command -v redis-server>/dev/null 2>&1 || need_install=1
command -v mariadbd     >/dev/null 2>&1 || command -v mysqld >/dev/null 2>&1 || need_install=1
if [ "$need_install" = 1 ]; then
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    mariadb-server mariadb-client redis-server redis-tools >/dev/null
fi
# The driver invokes `mysql`; on 24.04 it may only ship `mariadb`.
command -v mysql >/dev/null 2>&1 || sudo ln -sf "$(command -v mariadb)" /usr/local/bin/mysql

echo "== 1. start services (restart redis to clear any prior runtime requirepass) =="
sudo service mariadb start  >/dev/null 2>&1 || sudo service mysql start >/dev/null 2>&1 || true
sudo service redis-server restart >/dev/null 2>&1 || sudo service redis-server start >/dev/null 2>&1 || true
sleep 2

echo "== 2. isolated GNUPGHOME + no-protection GPG key =="
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

echo "== 3. MariaDB: labapp@127.0.0.1 owns labdb, starting pw=$MYSQL_PW =="
ADMIN_CLI="$(command -v mariadb || command -v mysql)"
SQL="DROP DATABASE IF EXISTS labdb;
DROP USER IF EXISTS 'labapp'@'127.0.0.1';
DROP USER IF EXISTS 'labapp'@'localhost';
CREATE DATABASE labdb;
CREATE USER 'labapp'@'127.0.0.1' IDENTIFIED BY '$MYSQL_PW';
CREATE USER 'labapp'@'localhost' IDENTIFIED BY '$MYSQL_PW';
GRANT ALL ON labdb.* TO 'labapp'@'127.0.0.1';
GRANT ALL ON labdb.* TO 'labapp'@'localhost';
FLUSH PRIVILEGES;"
printf '%s\n' "$SQL" | sudo "$ADMIN_CLI" >/dev/null
echo "   prove starting mysql pw authenticates over TCP:"
MYSQL_PWD="$MYSQL_PW" mysql --batch --skip-column-names -h 127.0.0.1 -u labapp -D labdb -e 'SELECT 1;'

echo "== 4. Redis: set starting requirepass=$REDIS_PW =="
redis-cli CONFIG SET requirepass "$REDIS_PW" >/dev/null
echo "   prove starting redis pw authenticates:"
REDISCLI_AUTH="$REDIS_PW" redis-cli PING

echo "== 5. seed driver-ready blobs into gopass (no plaintext on disk) =="
printf 'mysql://labapp:%s@127.0.0.1:3306/labdb' "$MYSQL_PW" \
  | gopass insert --multiline=false -f imported/mysql/labapp >/dev/null
printf 'redis://:%s@127.0.0.1:6379' "$REDIS_PW" \
  | gopass insert --multiline=false -f imported/redis/local >/dev/null
gopass ls --flat | sed 's/^/     /'

echo "== 6. rotate --execute (MANDATORY backup gate runs first) =="
INCREDIGO_ALLOW_EXECUTE=1 incredigo rotate --execute --prefix imported/ 2>&1 | sed 's/^/   /'

echo "== 7. CUTOVER ASSERTIONS =="
NEW_MYSQL=$(gopass show -o imported/mysql/labapp)
NEW_REDIS=$(gopass show -o imported/redis/local)
NEW_MYSQL_PW=$(printf '%s' "$NEW_MYSQL" | sed -E 's#.*://[^:]*:([^@]*)@.*#\1#')
NEW_REDIS_PW=$(printf '%s' "$NEW_REDIS" | sed -E 's#.*://:([^@]*)@.*#\1#')

fail=0
echo "   [mysql] OLD pw must now FAIL:"
if MYSQL_PWD="$MYSQL_PW" mysql --batch --skip-column-names -h 127.0.0.1 -u labapp -D labdb -e 'SELECT 1;' >/dev/null 2>&1; then
  echo "      FAIL: old mysql pw still authenticates"; fail=1
else echo "      OK: old mysql pw rejected"; fi
echo "   [mysql] NEW pw must WORK:"
if MYSQL_PWD="$NEW_MYSQL_PW" mysql --batch --skip-column-names -h 127.0.0.1 -u labapp -D labdb -e 'SELECT 1;' >/dev/null 2>&1; then
  echo "      OK: new mysql pw authenticates"; else echo "      FAIL: new mysql pw rejected"; fail=1; fi

echo "   [redis] OLD pw must now FAIL:"
if [ "$(REDISCLI_AUTH="$REDIS_PW" redis-cli PING 2>&1)" = "PONG" ]; then
  echo "      FAIL: old redis pw still authenticates"; fail=1
else echo "      OK: old redis pw rejected"; fi
echo "   [redis] NEW pw must WORK:"
if [ "$(REDISCLI_AUTH="$NEW_REDIS_PW" redis-cli PING 2>&1)" = "PONG" ]; then
  echo "      OK: new redis pw authenticates"; else echo "      FAIL: new redis pw rejected"; fail=1; fi

echo
if [ "$fail" = 0 ]; then echo "ALL DB-CLONE CUTOVER ASSERTIONS PASSED"; else echo "SOME ASSERTIONS FAILED"; exit 1; fi
