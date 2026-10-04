#!/usr/bin/env bash
# Live-VM POC for the Bitwarden adapter (Phase B `passwords` engine) against a self-hosted
# Vaultwarden — no real bitwarden.com account, fully scripted. FAKE logins only.
#
#   1. self-signed TLS + run real Vaultwarden 1.36 (sqlite, signups on, web-vault off)
#   2. register a fake account via vw-register.py (real Bitwarden registration crypto)
#   3. real `bw` CLI: config server + login + seed 2 weak-pw login items
#   4. incredigo passwords scan -> plan -> commit  (real `bw list/get/edit item`)
#   5. ASSERT both item passwords cut over (OLD gone), then RESTORE from the sealed backup
set -euo pipefail
export PATH=/snap/bin:/usr/local/bin:$PATH
export NODE_TLS_REJECT_UNAUTHORIZED=0           # accept the lab self-signed cert (bw is Node)
export INCREDIGO_PASSPHRASE='lab-seal-passphrase-001'

URL='https://127.0.0.1:8000'
EMAIL='labuser@incredigo.invalid'
MASTER='lab-master-pass-001'
OLD1='weakpw-github-0001'
OLD2='weakpw-gitlab-0002'
WORK="$HOME/bw-work"; rm -rf "$WORK"; mkdir -p "$WORK"
STAGE="$WORK/stage.age"; BACKUP="$WORK/backup.age"; WORKLIST="$WORK/worklist.md"; AUDIT="$WORK/audit.jsonl"
fail=0

echo "== 1. self-signed cert + Vaultwarden (TLS) =="
mkdir -p ~/vwtls
openssl req -x509 -newkey rsa:2048 -nodes -keyout ~/vwtls/key.pem -out ~/vwtls/cert.pem \
  -days 7 -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1
sudo docker rm -f vw >/dev/null 2>&1 || true
sudo docker run -d --name vw \
  -e SIGNUPS_ALLOWED=true -e WEB_VAULT_ENABLED=false \
  -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e ROCKET_PORT=8000 \
  -e 'ROCKET_TLS={certs="/tls/cert.pem",key="/tls/key.pem"}' \
  -v ~/vwtls:/tls:ro \
  -p 127.0.0.1:8000:8000 \
  vaultwarden/server:latest >/dev/null
for i in $(seq 1 60); do
  curl -fsSk "$URL/alive" >/dev/null 2>&1 && { echo "   vaultwarden up after ${i}s"; break; }
  sleep 1
done

echo "== 2. register fake account (real registration crypto) =="
~/moto-venv/bin/python ~/vw-register.py "$EMAIL" "$MASTER" "Lab User" "$URL" | sed 's/^/   /'

echo "== 3. bw login + seed 2 login items =="
bw config server "$URL" >/dev/null
BW_SESSION="$(bw login "$EMAIL" "$MASTER" --raw)"; export BW_SESSION
for pair in "GitHub|alice@example.com|$OLD1|https://github.com/" "GitLab|bob@example.com|$OLD2|https://gitlab.com/"; do
  IFS='|' read -r nm us pw url <<< "$pair"
  json=$(printf '{"type":1,"name":"%s","login":{"username":"%s","password":"%s","uris":[{"uri":"%s"}]}}' "$nm" "$us" "$pw" "$url")
  printf '%s' "$json" | bw encode | bw create item >/dev/null
  echo "   seeded $nm"
done
bw sync >/dev/null

echo "== 4. passwords scan (no secrets) =="
incredigo passwords --manager bitwarden scan --audit-log "$AUDIT" 2>&1 | sed 's/^/   /'

echo "== 5. passwords plan (verified backup + staged new pws + worklist) =="
incredigo passwords --manager bitwarden plan \
  --backup-out "$BACKUP" --stage-out "$STAGE" --worklist-out "$WORKLIST" \
  --audit-log "$AUDIT" 2>&1 | sed 's/^/   /'
for blob in "$STAGE" "$BACKUP"; do
  if grep -qaF "$OLD1" "$blob" || grep -qaF "$OLD2" "$blob"; then
    echo "   FAIL: plaintext password in $blob"; fail=1
  else echo "   OK: $(basename "$blob") carries no plaintext old password"; fi
done

echo "== 6. passwords commit --verified all (real bw edit item, in place) =="
incredigo passwords --manager bitwarden commit \
  --stage-in "$STAGE" --verified all --backup-out "$WORK/commit-backup.age" \
  --audit-log "$AUDIT" 2>&1 | sed 's/^/   /'

echo "== 7. CUTOVER ASSERTIONS (re-read the live vault) =="
bw sync >/dev/null
read_pw() { bw list items | python3 -c "import sys,json,os; n=os.environ['N']; print(next((i['login']['password'] for i in json.load(sys.stdin) if i['name']==n),''))"; }
NEW1=$(N=GitHub read_pw); NEW2=$(N=GitLab read_pw)
echo "   GitHub new pw len=${#NEW1}  GitLab new pw len=${#NEW2}"
[ -n "$NEW1" ] && [ "$NEW1" != "$OLD1" ] && echo "   OK: GitHub password changed" || { echo "   FAIL: GitHub unchanged"; fail=1; }
[ -n "$NEW2" ] && [ "$NEW2" != "$OLD2" ] && echo "   OK: GitLab password changed" || { echo "   FAIL: GitLab unchanged"; fail=1; }
[ "$NEW1" = "$OLD1" ] && { echo "   FAIL: GitHub OLD pw still set"; fail=1; } || echo "   OK: GitHub OLD pw gone"
[ "${#NEW1}" -ge 16 ] && echo "   OK: GitHub new pw is strong (len ${#NEW1})" || { echo "   FAIL: new pw too short"; fail=1; }

echo "== 8. RECOVERABILITY: restore OLD passwords from the sealed backup =="
incredigo passwords --manager bitwarden commit \
  --stage-in "$BACKUP" --verified all --backup-out "$WORK/restore-backup.age" \
  --audit-log "$AUDIT" 2>&1 | sed 's/^/   /'
bw sync >/dev/null
R1=$(N=GitHub read_pw); R2=$(N=GitLab read_pw)
[ "$R1" = "$OLD1" ] && echo "   OK: GitHub OLD pw restored from backup" || { echo "   FAIL: GitHub not restored ($R1)"; fail=1; }
[ "$R2" = "$OLD2" ] && echo "   OK: GitLab OLD pw restored from backup" || { echo "   FAIL: GitLab not restored"; fail=1; }

echo "== 9. cleanup =="
bw logout >/dev/null 2>&1 || true
sudo docker rm -f vw >/dev/null 2>&1 || true
echo "   vaultwarden container removed"

echo
if [ "$fail" = 0 ]; then echo "ALL BITWARDEN CUTOVER ASSERTIONS PASSED"; else echo "SOME ASSERTIONS FAILED"; exit 1; fi
