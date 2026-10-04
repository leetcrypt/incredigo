#!/usr/bin/env bash
# incredigo controlled-environment test harness. Self-contained + repeatable:
# re-provisions a FRESH isolated gopass store and fake inputs for all 8 scanners,
# then runs every command with PASS/FAIL assertions + a global secret-leak canary.
# FAKE creds only. Never touches a real store.
set -uo pipefail
export PATH=/usr/local/bin:$PATH
export GOPASS_HOMEDIR="$HOME/.lab-gopass"
export GNUPGHOME="$HOME/.lab-gnupg"
export GOPASS_NO_NOTIFY=true
export INCREDIGO_PASSPHRASE='lab-seal-passphrase-001'

LAB="$HOME/lab"
MASTER="$HOME/lab-master.log"
: > "$MASTER"
PASS=0; FAIL=0; FAILED=()

note(){ echo; echo "==== $* ===="; }
# check NAME : asserts that the last captured $OUT matches a grep -E pattern
check(){ local name="$1" pat="$2"; if grep -Eq "$pat" <<<"$OUT"; then echo "  PASS  $name"; PASS=$((PASS+1)); else echo "  FAIL  $name (want /$pat/)"; FAIL=$((FAIL+1)); FAILED+=("$name"); fi; }
checkno(){ local name="$1" pat="$2"; if grep -Eq "$pat" <<<"$OUT"; then echo "  FAIL  $name (unwanted /$pat/)"; FAIL=$((FAIL+1)); FAILED+=("$name"); else echo "  PASS  $name"; PASS=$((PASS+1)); fi; }
# run CMD...  -> captures combined output into $OUT and appends to MASTER
run(){ OUT="$("$@" 2>&1)"; printf '\n### %s\n%s\n' "$*" "$OUT" >> "$MASTER"; }

############################ provision (fresh) ############################
note "PROVISION fresh isolated store + fake inputs"
rm -rf "$GOPASS_HOMEDIR" "$GNUPGHOME" "$LAB" "$HOME/.aws" "$HOME/.docker" "$HOME/.kube" \
       "$HOME/.ssh" "$HOME/.netrc" "$HOME/.git-credentials" "$HOME/.incredigo"
mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"; mkdir -p "$GOPASS_HOMEDIR"
cat > /tmp/key.batch <<'EOF'
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Subkey-Type: ecdh
Subkey-Curve: cv25519
Name-Real: Incredigo Lab
Name-Email: lab@incredigo.local
Expire-Date: 0
%commit
EOF
gpg --batch --generate-key /tmp/key.batch 2>/dev/null
FPR=$(gpg --list-keys --with-colons lab@incredigo.local | awk -F: '/^fpr:/{print $10; exit}')
gopass init --crypto gpg --storage fs "$FPR" </dev/null >/dev/null 2>&1

# --- fake inputs (every secret carries a unique CANARY token for leak-checks) ---
mkdir -p "$LAB" "$LAB/k8s" "$LAB/extra" "$HOME/.aws" "$HOME/.docker" "$HOME/.kube" "$HOME/.ssh"
cd "$LAB"
cat > .env <<'EOF'
API_TOKEN=tok_CANARYenv01_4f9c2a7e8b1d6033
DATABASE_URL=postgres://app:CANARYdb01pw@db.lab.local:5432/app
SENDGRID_API_KEY=SG.CANARYsg01.aaaaaaaaaaaaaaaaaaaa
PORT=8080
EOF
cat > "$HOME/.aws/credentials" <<'EOF'
[default]
aws_access_key_id = AKIALAB000000FAKE0001
aws_secret_access_key = wJalrCANARYaws01secretKEYwJalr0001
EOF
cat > "$HOME/.netrc" <<'EOF'
machine api.lab.local login labuser password CANARYnetrc01pw
EOF
cat > "$HOME/.git-credentials" <<'EOF'
https://gituser:CANARYgit01tok@github.com
EOF
DOCKER_AUTH=$(printf 'dockeruser:CANARYdocker01pw' | base64)
cat > "$HOME/.docker/config.json" <<EOF
{ "auths": { "registry.lab.local": { "auth": "$DOCKER_AUTH" } } }
EOF
cat > "$HOME/.kube/config" <<'EOF'
apiVersion: v1
kind: Config
users:
- name: lab-admin
  user:
    token: CANARYkube01token
EOF
cat > "$HOME/.ssh/id_ed25519" <<'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
CANARYssh01keybodyb3BlbnNzaC1rZXktdjEAAAAABG5vbmU
-----END OPENSSH PRIVATE KEY-----
EOF
chmod 600 "$HOME/.ssh/id_ed25519"
cat > "$LAB/extra/service-account.json" <<'EOF'
{"type":"service_account","private_key":"CANARYfile01blob"}
EOF
# consumer files for the blast-radius map (reference markers, not secrets)
cat > docker-compose.yml <<'EOF'
services:
  app:
    environment:
      - API_TOKEN=${API_TOKEN}
      - DATABASE_URL=${DATABASE_URL}
EOF
cat > k8s/deploy.yaml <<'EOF'
env:
  - name: API_TOKEN
    valueFrom: { secretKeyRef: { name: app, key: API_TOKEN } }
  - name: SENDGRID_API_KEY
    valueFrom: { secretKeyRef: { name: app, key: SENDGRID_API_KEY } }
EOF

# the canary strings that must NEVER appear in any command output
SECRETS=( CANARYenv01 CANARYdb01pw CANARYsg01 wJalrCANARYaws01 CANARYnetrc01pw
          CANARYgit01tok "$DOCKER_AUTH" CANARYkube01token CANARYssh01keybody CANARYfile01blob )

############################ T1 scan (all 8 sources) ############################
note "T1 scan --path extra (all sources)"
run incredigo scan --path "$LAB/extra"
echo "$OUT"
for s in aws env netrc ssh docker kube git file; do check "scan lists '$s'" "(^|[[:space:]])$s([[:space:]])"; done

############################ T2 status ############################
note "T2 status"
run incredigo status; check "status header" "STATE"

############################ T3 migrate (fresh store) ############################
note "T3 migrate --path extra --dedupe"
run incredigo migrate --path "$LAB/extra" --dedupe
echo "$OUT"
check "migrate reports count" "migrated [1-9]"
OUT="$(gopass ls --flat 2>&1)"; check "store has imported/ entries" "imported/"

############################ T4/T5 age export+import roundtrip ############################
note "T4 export (age)"
run incredigo export --prefix imported/ --out "$LAB/backup.age"; check "age sealed" "sealed [0-9]+ entr"
note "T5 age roundtrip into a clean prefix"
printf 'roundtrip-CANARYrt01\n' | gopass insert --multiline=false -f rt/alpha >/dev/null 2>&1
run incredigo export --prefix rt/ --out "$LAB/rt.age"; check "rt export" "sealed 1 entr"
gopass rm -f rt/alpha >/dev/null 2>&1
run incredigo import --in "$LAB/rt.age" --force; check "rt import restored" "restored 1 entr"
OUT="$(gopass show -o rt/alpha 2>&1)"; check "rt value matches" "^roundtrip-CANARYrt01$"

############################ T6 hmac sealer roundtrip ############################
note "T6 hmac sealer roundtrip"
run incredigo export --prefix rt/ --sealer hmac --out "$LAB/rt.hmac"; check "hmac sealed" "sealed 1 entr"
gopass rm -f rt/alpha >/dev/null 2>&1
run incredigo import --in "$LAB/rt.hmac" --sealer hmac --force; check "hmac import" "restored 1 entr"
OUT="$(gopass show -o rt/alpha 2>&1)"; check "hmac value matches" "^roundtrip-CANARYrt01$"

############################ T7 openssl sealer roundtrip ############################
note "T7 openssl sealer roundtrip"
if command -v openssl >/dev/null; then
  run incredigo export --prefix rt/ --sealer openssl --out "$LAB/rt.ossl"; check "openssl sealed" "sealed 1 entr"
  gopass rm -f rt/alpha >/dev/null 2>&1
  run incredigo import --in "$LAB/rt.ossl" --sealer openssl --force; check "openssl import" "restored 1 entr"
  OUT="$(gopass show -o rt/alpha 2>&1)"; check "openssl value matches" "^roundtrip-CANARYrt01$"
else echo "  SKIP  openssl not installed"; fi

############################ T8 rotate --dry-run ############################
note "T8 rotate --dry-run"
run incredigo rotate --prefix imported/ --dry-run
echo "$OUT"
check "backup gate ran"   "backup gate: [0-9]+ entr"
check "spine completed"   "DRY RUN complete"
check "noop rotated"      "noop"

############################ T8b backup-gate COVERAGE (independent ground truth) ############################
# Regression guard for the 2026-06-16 lapse: the gate's sealed==verified check is
# self-referential (both counts come from `gopass ls --flat`), so a path hidden from
# `ls --flat` (e.g. a ".env" dot-segment) is dropped from BOTH sides and the gate
# passes while under-covering the store. Here we count the on-disk *.gpg files
# directly (independent of `ls --flat`) and assert the gate sealed exactly that many.
note "T8b backup gate covers EVERY store entry (independent .gpg count)"
GATE_N=$(grep -Eo 'backup gate: [0-9]+ entr' <<<"$OUT" | grep -Eo '[0-9]+' | head -1)
DISK_N=$(find "$GOPASS_HOMEDIR" -name '*.gpg' -path '*/imported/*' 2>/dev/null | wc -l | tr -d ' ')
printf '\n### T8b coverage gate=%s disk=%s\n' "$GATE_N" "$DISK_N" >> "$MASTER"
OUT="gate=$GATE_N disk=$DISK_N"; echo "  $OUT"
check "gate count parsed"          "gate=[0-9]+ "
check "backup covers ALL entries"  "gate=${DISK_N} disk=${DISK_N}"

############################ T9 rotate --blast ############################
note "T9 rotate --blast"
run incredigo rotate --prefix imported/ --dry-run --blast --blast-root "$LAB"
echo "$OUT"
check "blast CONSUMERS col" "CONSUMERS"
check "API_TOKEN -> 2 files" "API_TOKEN.*2 file"
check "blast radius listed"  "blast radius"

############################ T10 worklist ############################
note "T10 worklist"
run incredigo worklist; check "worklist table" "change-password link"

############################ T11 negative: --execute refused ############################
note "T11 rotate --execute must be refused"
run incredigo rotate --execute; check "execute refused" "refused"

############################ T12 negative: empty passphrase ############################
note "T12 empty INCREDIGO_PASSPHRASE rejected"
OUT="$(INCREDIGO_PASSPHRASE='' incredigo export --prefix imported/ --out /tmp/should-not-exist.age 2>&1)"
printf '\n### empty-pass\n%s\n' "$OUT" >> "$MASTER"
check "empty passphrase error" "empty"

############################ T13 GLOBAL leak canary ############################
note "T13 GLOBAL leak-check across ALL command output"
LEAKED=0
for s in "${SECRETS[@]}"; do
  if grep -Fq "$s" "$MASTER"; then echo "  FAIL  secret leaked: $s"; LEAKED=$((LEAKED+1)); fi
done
if grep -Fq "PRIVATE KEY" "$MASTER"; then echo "  FAIL  'PRIVATE KEY' material in output"; LEAKED=$((LEAKED+1)); fi
if [ "$LEAKED" -eq 0 ]; then echo "  PASS  no secret canary in any output ($MASTER)"; PASS=$((PASS+1));
else echo "  FAIL  $LEAKED leak(s) detected"; FAIL=$((FAIL+1)); FAILED+=("leak-check"); fi

############################ summary ############################
echo; echo "================= SUMMARY ================="
echo "  PASS=$PASS  FAIL=$FAIL"
[ "$FAIL" -gt 0 ] && printf '  failed: %s\n' "${FAILED[*]}"
echo "HARNESS_DONE rc=$FAIL"
exit 0
