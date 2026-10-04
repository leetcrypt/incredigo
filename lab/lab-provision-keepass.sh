#!/usr/bin/env bash
# Live-VM POC for the KeePassXC password-manager adapter (Phase B `passwords` engine),
# inside the sandbox VM. FAKE logins only, throwaway .kdbx database.
#
# Flow proven here:
#   1. install the REAL keepassxc-cli
#   2. create a throwaway .kdbx (known master pass) + seed 2 login entries (weak pws)
#   3. incredigo passwords scan     -> lists 2 logins + change links (no secrets)
#   4. incredigo passwords plan      -> MANDATORY verified sealed backup + staged new
#                                       strong passwords (.age) + secrets-free worklist
#   5. incredigo passwords commit    -> in-place edit of BOTH entries via keepassxc-cli
#   6. ASSERT: both entry passwords changed, OLD gone; backup .age decrypts to OLD values
set -euo pipefail
export PATH=/usr/local/bin:$PATH

# Seal passphrase (age backup/stage) and the kdbx master — both env-driven => headless.
export INCREDIGO_PASSPHRASE='lab-seal-passphrase-001'
export INCREDIGO_KDBX_PASSPHRASE='db-master-pass-001'

DB="$HOME/lab.kdbx"
OLD1='weakpw-github-0001'      # fake starting passwords
OLD2='weakpw-gitlab-0002'
WORK="$HOME/kp-work"; rm -rf "$WORK"; mkdir -p "$WORK"
STAGE="$WORK/stage.age"
BACKUP="$WORK/backup.age"
WORKLIST="$WORK/worklist.md"
AUDIT="$WORK/audit.jsonl"

echo "== 0. install keepassxc-cli (real tool) =="
if ! command -v keepassxc-cli >/dev/null 2>&1; then
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq keepassxc >/dev/null 2>&1 || \
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq keepassxc-cli >/dev/null 2>&1
fi
keepassxc-cli --version | sed 's/^/   keepassxc-cli /'

echo "== 1. throwaway .kdbx + 2 fake login entries =="
rm -f "$DB"
# db-create: stdin carries master pass then its confirmation.
printf '%s\n%s\n' "$INCREDIGO_KDBX_PASSPHRASE" "$INCREDIGO_KDBX_PASSPHRASE" \
  | keepassxc-cli db-create -p "$DB" >/dev/null 2>&1
# add -p: stdin carries the unlock pass then the new entry password.
printf '%s\n%s\n' "$INCREDIGO_KDBX_PASSPHRASE" "$OLD1" \
  | keepassxc-cli add --username 'alice@example.com' --url 'https://github.com/' -p "$DB" 'GitHub' >/dev/null 2>&1
printf '%s\n%s\n' "$INCREDIGO_KDBX_PASSPHRASE" "$OLD2" \
  | keepassxc-cli add --username 'bob@example.com' --url 'https://gitlab.com/' -p "$DB" 'GitLab' >/dev/null 2>&1
echo "   entries in db:"
printf '%s\n' "$INCREDIGO_KDBX_PASSPHRASE" | keepassxc-cli ls "$DB" 2>/dev/null | sed 's/^/     /'

echo "== 2. passwords scan (no secrets, commits nothing) =="
incredigo passwords --manager keepassxc --kdbx "$DB" scan --audit-log "$AUDIT" 2>&1 | sed 's/^/   /'

echo "== 3. passwords plan (verified sealed backup + staged new pws + worklist) =="
incredigo passwords --manager keepassxc --kdbx "$DB" plan \
  --backup-out "$BACKUP" --stage-out "$STAGE" --worklist-out "$WORKLIST" \
  --audit-log "$AUDIT" 2>&1 | sed 's/^/   /'
echo "   --- worklist (must be secrets-free) ---"
sed 's/^/     /' "$WORKLIST"

echo "== 4. ASSERT staged + backup bundles are NOT plaintext =="
fail=0
for blob in "$STAGE" "$BACKUP"; do
  if grep -qaF "$OLD1" "$blob" || grep -qaF "$OLD2" "$blob"; then
    echo "   FAIL: plaintext password found in $blob"; fail=1
  else
    echo "   OK: $(basename "$blob") carries no plaintext old password"
  fi
done

echo "== 5. passwords commit --verified all (in-place edit of both entries) =="
incredigo passwords --manager keepassxc --kdbx "$DB" commit \
  --stage-in "$STAGE" --verified all --backup-out "$WORK/backup2.age" \
  --audit-log "$AUDIT" 2>&1 | sed 's/^/   /'

echo "== 6. CUTOVER ASSERTIONS (re-export the live db) =="
CSV=$(printf '%s\n' "$INCREDIGO_KDBX_PASSPHRASE" | keepassxc-cli export -f csv "$DB" 2>/dev/null)
NEW1=$(printf '%s' "$CSV" | awk -F',' 'NR>1 && /GitHub/ {gsub(/"/,"",$4); print $4; exit}')
NEW2=$(printf '%s' "$CSV" | awk -F',' 'NR>1 && /GitLab/ {gsub(/"/,"",$4); print $4; exit}')
echo "   GitHub new pw len=${#NEW1}  GitLab new pw len=${#NEW2}"

[ -n "$NEW1" ] && [ "$NEW1" != "$OLD1" ] && echo "   OK: GitHub password changed" || { echo "   FAIL: GitHub unchanged"; fail=1; }
[ -n "$NEW2" ] && [ "$NEW2" != "$OLD2" ] && echo "   OK: GitLab password changed" || { echo "   FAIL: GitLab unchanged"; fail=1; }
printf '%s' "$CSV" | grep -qaF "$OLD1" && { echo "   FAIL: GitHub OLD pw still present"; fail=1; } || echo "   OK: GitHub OLD pw gone"
printf '%s' "$CSV" | grep -qaF "$OLD2" && { echo "   FAIL: GitLab OLD pw still present"; fail=1; } || echo "   OK: GitLab OLD pw gone"
# strong (length 20 default)
[ "${#NEW1}" -ge 16 ] && echo "   OK: GitHub new pw is strong (len ${#NEW1})" || { echo "   FAIL: GitHub new pw too short"; fail=1; }

echo "== 7. RECOVERABILITY: restore OLD passwords from the sealed backup =="
# The plan-stage backup.age is itself a staged list whose Secret = the OLD password.
# Feeding it back through `commit --stage-in` proves the backup is a usable restore
# artifact: it should re-write both entries back to their original values.
incredigo passwords --manager keepassxc --kdbx "$DB" commit \
  --stage-in "$BACKUP" --verified all --backup-out "$WORK/backup3.age" \
  --audit-log "$AUDIT" 2>&1 | sed 's/^/   /'
CSV2=$(printf '%s\n' "$INCREDIGO_KDBX_PASSPHRASE" | keepassxc-cli export -f csv "$DB" 2>/dev/null)
printf '%s' "$CSV2" | grep -qaF "$OLD1" && echo "   OK: GitHub OLD pw restored from backup" || { echo "   FAIL: GitHub not restored"; fail=1; }
printf '%s' "$CSV2" | grep -qaF "$OLD2" && echo "   OK: GitLab OLD pw restored from backup" || { echo "   FAIL: GitLab not restored"; fail=1; }
printf '%s' "$CSV2" | grep -qaF "$NEW1" && { echo "   FAIL: post-restore still has NEW pw"; fail=1; } || echo "   OK: NEW pw gone after restore"

echo
if [ "$fail" = 0 ]; then echo "ALL KEEPASSXC CUTOVER ASSERTIONS PASSED"; else echo "SOME ASSERTIONS FAILED"; exit 1; fi
