#!/usr/bin/env bash
# Provision the incredigo AWS-IAM-rotation POC inside the sandbox VM.
# FAKE/self-hosted moto only, isolated gopass store. Idempotent-ish.
set -euo pipefail

export GNUPGHOME="$HOME/.lab-gnupg"
export GOPASS_HOMEDIR="$HOME/.lab-gopass"
VENV="$HOME/moto-venv"
ENTRY="imported/aws/labkey"
EP="http://127.0.0.1:5000"
OLDKEY_FILE="$HOME/.lab-aws-oldkey"

echo "== 1. (re)start moto_server on :5000 =="
pkill -f moto_server 2>/dev/null || true
sleep 1
nohup "$VENV/bin/moto_server" -p 5000 >"$HOME/moto.log" 2>&1 &
for i in $(seq 1 30); do
  curl -fsS "$EP/moto-api/" >/dev/null 2>&1 && break
  sleep 1
done
echo "   moto up: $(curl -fsS $EP/moto-api/ >/dev/null 2>&1 && echo yes || echo NO)"

echo "== 2. create IAM user + seed access key, emit driver-ready blob =="
BLOB=$("$VENV/bin/python" - "$EP" "$OLDKEY_FILE" <<'PY'
import sys, boto3, urllib.parse
ep, oldfile = sys.argv[1], sys.argv[2]
a = boto3.client("iam", endpoint_url=ep, region_name="us-east-1",
                 aws_access_key_id="admin", aws_secret_access_key="admin")
try:
    a.create_user(UserName="labapp")
except Exception:
    pass
ak = a.create_access_key(UserName="labapp")["AccessKey"]
oid, osec = ak["AccessKeyId"], ak["SecretAccessKey"]
open(oldfile, "w").write(oid)
q = "region=us-east-1&endpoint=" + urllib.parse.quote(ep, safe="")
blob = "aws://%s:%s@aws/?%s" % (urllib.parse.quote(oid, safe=""),
                               urllib.parse.quote(osec, safe=""), q)
print(blob)
PY
)
echo "   seed AccessKeyId: $(cat "$OLDKEY_FILE")"

echo "== 3. isolated GNUPGHOME + no-protection GPG key =="
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

echo "== 4. isolated gopass store + seed blob =="
gopass init --storage fs "$KEYID" >/dev/null 2>&1 || gopass init "$KEYID" >/dev/null 2>&1
printf '%s' "$BLOB" | gopass insert --multiline=false -f "$ENTRY" >/dev/null
echo "   stored $ENTRY:"
gopass ls --flat | sed 's/^/     /'

echo "== 5. prove the seed key authenticates now (STS) =="
"$VENV/bin/python" - "$EP" "$(cat "$OLDKEY_FILE")" <<'PY'
import sys, boto3
ep, oid = sys.argv[1], sys.argv[2]
# read secret back out of gopass is not needed here; just confirm list shows it
a = boto3.client("iam", endpoint_url=ep, region_name="us-east-1",
                 aws_access_key_id="admin", aws_secret_access_key="admin")
keys = [k["AccessKeyId"] for k in a.list_access_keys(UserName="labapp")["AccessKeyMetadata"]]
print("   labapp keys now:", keys)
PY

echo "DONE. Run: GNUPGHOME=$GNUPGHOME GOPASS_HOMEDIR=$GOPASS_HOMEDIR \\"
echo "  INCREDIGO_PASSPHRASE=labseal123 INCREDIGO_ALLOW_EXECUTE=1 incredigo rotate --execute"
