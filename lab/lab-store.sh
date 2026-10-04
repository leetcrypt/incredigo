#!/usr/bin/env bash
# incredigo sandbox — gopass store + fake creds (real gopasspw/gopass already installed)
set -euo pipefail
export PATH=/usr/local/bin:$PATH
export GOPASS_HOMEDIR="$HOME/.lab-gopass"
export GNUPGHOME="$HOME/.lab-gnupg"
export GOPASS_NO_NOTIFY=true

rm -rf "$GOPASS_HOMEDIR" "$GNUPGHOME"
mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
mkdir -p "$GOPASS_HOMEDIR"

echo "== throwaway GPG key =="
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
echo "key: $FPR"

echo "== gopass init (isolated) =="
gopass init --crypto gpg --storage fs "$FPR" </dev/null 2>&1 | tail -3 || gopass init "$FPR" </dev/null 2>&1 | tail -3

echo "== seed fake imported/ entries =="
printf 'wJalrFAKEsecretKEYwJalrFAKEsecretKEY0001\n' | gopass insert --multiline=false -f imported/aws/default
printf 'ghp_FAKEtoken000000000000000000000001\n'    | gopass insert --multiline=false -f imported/github/pat
printf 'lab-db-PASSWORD-0001\n'                      | gopass insert --multiline=false -f imported/db/postgres
echo "store now holds:"; gopass ls --flat

echo "== sample on-disk creds (fake) =="
LAB="$HOME/lab"; mkdir -p "$LAB"; cd "$LAB"
cat > .env <<'EOF'
API_TOKEN=tok_FAKE_4f9c2a7e8b1d6033aa55ee
DATABASE_URL=postgres://app:lab-db-PASSWORD-0001@db.lab.local:5432/app
SENDGRID_API_KEY=SG.FAKE0001.aaaaaaaaaaaaaaaaaaaaaa
PORT=8080
EOF
mkdir -p "$HOME/.aws"
cat > "$HOME/.aws/credentials" <<'EOF'
[default]
aws_access_key_id = AKIALAB000000FAKE0001
aws_secret_access_key = wJalrFAKEsecretKEYwJalrFAKEsecretKEY0001
EOF
cat > docker-compose.yml <<'EOF'
services:
  app:
    environment:
      - API_TOKEN=${API_TOKEN}
      - DATABASE_URL=${DATABASE_URL}
EOF
mkdir -p k8s
cat > k8s/deploy.yaml <<'EOF'
env:
  - name: API_TOKEN
    valueFrom: { secretKeyRef: { name: app, key: API_TOKEN } }
  - name: SENDGRID_API_KEY
    valueFrom: { secretKeyRef: { name: app, key: SENDGRID_API_KEY } }
EOF
echo "lab dir: $LAB"; ls -la "$LAB"
echo "STORE_OK"
