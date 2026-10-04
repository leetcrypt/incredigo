#!/usr/bin/env bash
# incredigo sandbox provisioning — FAKE creds only, throwaway VM.
set -euo pipefail

echo "== installing gopass + gnupg =="
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gnupg gopass >/dev/null 2>&1 \
  || { echo "apt gopass failed; trying snap/manual"; sudo snap install gopass --classic || true; }
command -v gopass >/dev/null || { echo "FATAL: gopass not installed"; exit 1; }
gopass --version | head -1

# Isolate gopass entirely (rule 4): throwaway homedir + throwaway GNUPGHOME.
export GOPASS_HOMEDIR="$HOME/.lab-gopass"
export GNUPGHOME="$HOME/.lab-gnupg"
mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
mkdir -p "$GOPASS_HOMEDIR"

echo "== generating throwaway (no-protection) GPG key =="
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

echo "== initialising isolated gopass store =="
gopass init --storage fs "$FPR" >/dev/null 2>&1 || gopass init "$FPR" >/dev/null 2>&1
gopass ls || true

echo "== seeding gopass 'imported/' entries (fake) =="
printf 'AKIALAB000000FAKE0001:wJalrFAKEsecretKEYwJalrFAKEsecretKEY0001\n' | gopass insert -f imported/aws/default >/dev/null
printf 'ghp_FAKEtoken000000000000000000000001\n'                         | gopass insert -f imported/github/pat >/dev/null
printf 'lab-db-PASSWORD-0001\n'                                          | gopass insert -f imported/db/postgres >/dev/null
echo "seeded: $(gopass ls --flat | wc -l) entries"

echo "== creating sample on-disk creds (fake) =="
LAB="$HOME/lab"; mkdir -p "$LAB"; cd "$LAB"
cat > .env <<'EOF'
# fake lab secrets — NOT real
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
# consumer files for the blast-radius map (reference markers, not secrets)
cat > docker-compose.yml <<'EOF'
services:
  app:
    image: example/app
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
echo "PROVISION_OK"
