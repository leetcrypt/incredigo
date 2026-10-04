#!/usr/bin/env bash
# Assert the AWS cutover after `incredigo rotate --execute`.
set -euo pipefail
export GNUPGHOME="$HOME/.lab-gnupg"
export GOPASS_HOMEDIR="$HOME/.lab-gopass"
VENV="$HOME/moto-venv"
EP="http://127.0.0.1:5000"
OLD=$(cat "$HOME/.lab-aws-oldkey")
ENTRY="imported/aws/labkey"

# New key id from the rotated gopass blob (strip userinfo: between :// and first @,
# the id is before the first ':').
NEWBLOB=$(gopass show -o "$ENTRY")
NEW=$(printf '%s' "$NEWBLOB" | sed -E 's#^aws://([^:]+):.*#\1#')

echo "OLD AccessKeyId: $OLD"
echo "NEW AccessKeyId: $NEW"

"$VENV/bin/python" - "$EP" "$OLD" "$NEW" <<'PY'
import sys, boto3
ep, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
a = boto3.client("iam", endpoint_url=ep, region_name="us-east-1",
                 aws_access_key_id="admin", aws_secret_access_key="admin")
keys = [k["AccessKeyId"] for k in a.list_access_keys(UserName="labapp")["AccessKeyMetadata"]]
print("labapp keys after rotate:", keys)
ok = True
if old in keys:
    print("FAIL: old key still present"); ok = False
else:
    print("PASS: old key deleted at provider")
if new not in keys:
    print("FAIL: new key absent"); ok = False
else:
    print("PASS: new key present at provider")
if old == new:
    print("FAIL: old == new"); ok = False
else:
    print("PASS: old != new")
sys.exit(0 if ok else 1)
PY

echo "-- audit-log leak check (no key material) --"
AUD="$HOME/rotate-audit.jsonl"
if [ -f "$AUD" ]; then
  if grep -qF "$OLD" "$AUD" || grep -qF "$NEW" "$AUD"; then
    echo "FAIL: AccessKeyId found in audit log"; exit 1
  fi
  # secret material check: pull the new secret from the blob and grep
  NSEC=$(printf '%s' "$NEWBLOB" | sed -E 's#^aws://[^:]+:([^@]+)@.*#\1#' | python3 -c 'import sys,urllib.parse;print(urllib.parse.unquote(sys.stdin.read()))')
  if [ -n "$NSEC" ] && grep -qF "$NSEC" "$AUD"; then
    echo "FAIL: SecretAccessKey found in audit log"; exit 1
  fi
  echo "PASS: audit log carries no key id or secret"
else
  echo "note: no audit log at $AUD"
fi
echo "ALL CUTOVER ASSERTIONS PASSED"
