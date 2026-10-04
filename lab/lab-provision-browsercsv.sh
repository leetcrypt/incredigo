#!/usr/bin/env bash
# Live-VM POC for the Chrome/Firefox browser-CSV adapters (Phase B `passwords` engine),
# inside the sandbox VM. FAKE logins only. There is NO real browser to re-import into,
# so what this proves is the security-critical machinery that DOES run unattended:
#
#   * scan/plan read a real browser export CSV and seal a verified backup + staged new
#     passwords (.age) — never plaintext on disk
#   * commit --allow-csv writes the NEW-password CSV to a REAL tmpfs (/dev/shm), in the
#     correct per-browser column layout, carrying the staged strong passwords (OLD gone)
#   * the file is SECURELY SHREDDED (unlinked) once the human confirms re-import
#   * the user's OWN export CSV is never touched
#
# To inspect the tmpfs CSV before it is shredded, commit is driven under a pty (`script`)
# so it pauses at the "press Enter to shred" prompt; a FIFO releases it after inspection.
set -euo pipefail
export PATH=/usr/local/bin:$PATH
export INCREDIGO_PASSPHRASE='lab-seal-passphrase-001'

OLD1='weakpw-github-0001'
OLD2='weakpw-gitlab-0002'
WORK="$HOME/csv-work"; rm -rf "$WORK"; mkdir -p "$WORK"
AUDIT="$WORK/audit.jsonl"
fail=0

run_browser() {
  local mgr="$1" exp_header="$2" want_header="$3"
  echo
  echo "############################################################"
  echo "## $mgr"
  echo "############################################################"
  local dir="$WORK/$mgr"; mkdir -p "$dir"
  local EXPORT="$dir/export.csv"
  local STAGE="$dir/stage.age" BACKUP="$dir/backup.age" WORKLIST="$dir/worklist.md"

  echo "== 1. browser export CSV (user-provided, $exp_header) =="
  {
    echo "$exp_header"
    if [ "$mgr" = "chrome" ]; then
      echo "GitHub,https://github.com/,alice@example.com,$OLD1,"
      echo "GitLab,https://gitlab.com/,bob@example.com,$OLD2,"
    else
      echo "https://github.com/,alice@example.com,$OLD1"
      echo "https://gitlab.com/,bob@example.com,$OLD2"
    fi
  } > "$EXPORT"
  sed 's/^/   /' "$EXPORT"

  echo "== 2. passwords scan =="
  incredigo passwords --manager "$mgr" --export-path "$EXPORT" scan --audit-log "$AUDIT" 2>&1 | sed 's/^/   /'

  echo "== 3. passwords plan (verified backup + staged new pws + worklist) =="
  incredigo passwords --manager "$mgr" --export-path "$EXPORT" plan \
    --backup-out "$BACKUP" --stage-out "$STAGE" --worklist-out "$WORKLIST" \
    --audit-log "$AUDIT" 2>&1 | sed 's/^/   /'

  echo "== 4. ASSERT staged + backup bundles are NOT plaintext =="
  for blob in "$STAGE" "$BACKUP"; do
    if grep -qaF "$OLD1" "$blob" || grep -qaF "$OLD2" "$blob"; then
      echo "   FAIL: plaintext password in $blob"; fail=1
    else
      echo "   OK: $(basename "$blob") carries no plaintext old password"
    fi
  done

  echo "== 5. commit --allow-csv (pty probe: inspect tmpfs CSV, then shred) =="
  rm -rf /dev/shm/incredigo
  local PWCOL=4; [ "$mgr" = "firefox" ] && PWCOL=3
  if python3 /home/ubuntu/csv-commit-probe.py \
       "$mgr" "$EXPORT" "$STAGE" "$dir/commit-backup.age" "$AUDIT" \
       "$OLD1" "$OLD2" "$want_header" "$PWCOL"; then
    :
  else
    fail=1
  fi
  # (e) user's own export CSV untouched
  grep -qaF "$OLD1" "$EXPORT" && echo "   OK: user's export.csv left untouched" || { echo "   FAIL: user export.csv was modified"; fail=1; }
}

#          manager   export-header                         written-header
run_browser chrome  "name,url,username,password,note"      "name,url,username,password,note"
run_browser firefox "url,username,password"                "url,username,password"

echo
if [ "$fail" = 0 ]; then echo "ALL BROWSER-CSV ASSERTIONS PASSED"; else echo "SOME ASSERTIONS FAILED"; exit 1; fi
