#!/usr/bin/env bash
# Live cutover POC for the Kubernetes legacy-ServiceAccount-token rotation driver,
# inside the sandbox VM. FAKE/self-owned single-node k3s only, isolated gopass store.
#
# Installs REAL k3s, creates a namespace + ServiceAccount (labsa) + a legacy
# kubernetes.io/service-account-token Secret (the controller populates its token),
# and an RBAC Role/RoleBinding letting labsa create/delete/get Secrets + get its own
# ServiceAccount (the driver's create-new -> verify -> revoke-old cutover). Seeds the
# driver-ready k8s:// blob (with the apiserver CA pinned via ca=), runs
# `rotate --execute`, then asserts the OLD token stops authenticating against the REAL
# apiserver while the NEW one (read back from gopass) works.
#
# This promotes the k8s driver from MOCK-ONLY to LIVE-VM: the real kube-apiserver +
# token controller (not the httptest emulator) validate the Secret create/delete cutover.
set -euo pipefail

export GNUPGHOME="$HOME/.lab-gnupg"
export GOPASS_HOMEDIR="$HOME/.lab-gopass"
export INCREDIGO_PASSPHRASE='lab-seal-passphrase-001'
NS="labns"
SA="labsa"
SEED_SECRET="labsa-token-seed"
APISERVER="https://127.0.0.1:6443"
CA_FILE="$HOME/.lab-k8s-ca.crt"

KC() { sudo k3s kubectl "$@"; }

echo "== 0. ensure real k3s is installed and the apiserver is up =="
if ! command -v k3s >/dev/null 2>&1; then
  curl -sfL https://get.k3s.io | sudo INSTALL_K3S_EXEC="--write-kubeconfig-mode 644" sh - >/dev/null 2>&1
fi
sudo systemctl is-active --quiet k3s || sudo systemctl start k3s
for i in $(seq 1 60); do
  KC get --raw='/readyz' >/dev/null 2>&1 && break
  sleep 1
done
KC version --short 2>/dev/null | sed 's/^/   /' || KC version | sed 's/^/   /'

echo "== 1. namespace + serviceaccount + legacy token Secret =="
KC create namespace "$NS" --dry-run=client -o yaml | KC apply -f - >/dev/null
KC -n "$NS" create serviceaccount "$SA" --dry-run=client -o yaml | KC apply -f - >/dev/null
# Manually-created Secret of the legacy type, annotated to the SA. The token
# controller populates .data.token — exactly the credential the driver rotates.
cat <<YAML | KC apply -f - >/dev/null
apiVersion: v1
kind: Secret
metadata:
  name: $SEED_SECRET
  namespace: $NS
  annotations:
    kubernetes.io/service-account.name: $SA
type: kubernetes.io/service-account-token
YAML

echo "== 2. RBAC: let $SA manage Secrets + read its ServiceAccount in $NS =="
cat <<YAML | KC apply -f - >/dev/null
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ${SA}-rotator
  namespace: $NS
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["create","delete","get","list"]
- apiGroups: [""]
  resources: ["serviceaccounts"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ${SA}-rotator
  namespace: $NS
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: ${SA}-rotator
subjects:
- kind: ServiceAccount
  name: $SA
  namespace: $NS
YAML

echo "== 3. wait for the token controller to populate the seed token =="
SEED_TOK=""
for i in $(seq 1 30); do
  enc=$(KC -n "$NS" get secret "$SEED_SECRET" -o jsonpath='{.data.token}' 2>/dev/null || true)
  if [ -n "$enc" ]; then SEED_TOK=$(printf '%s' "$enc" | base64 -d); break; fi
  sleep 1
done
[ -n "$SEED_TOK" ] || { echo "   FAIL: seed token never populated"; exit 1; }
echo "   seed token populated (${#SEED_TOK} bytes)"

echo "== 4. extract the apiserver CA (base64 PEM) from the k3s kubeconfig =="
CA_B64=$(sudo awk -F': ' '/certificate-authority-data:/{print $2; exit}' /etc/rancher/k3s/k3s.yaml | tr -d ' \r')
[ -n "$CA_B64" ] || { echo "   FAIL: could not read CA from k3s.yaml"; exit 1; }
printf '%s' "$CA_B64" | base64 -d > "$CA_FILE"
echo "   CA written to $CA_FILE ($(wc -c < "$CA_FILE") bytes PEM)"

# Helper: HTTP status of a serviceaccounts GET against the REAL apiserver with a token.
k8s_auth() {
  curl -s -o /dev/null -w '%{http_code}' --cacert "$CA_FILE" \
    -H "Authorization: Bearer $1" \
    "$APISERVER/api/v1/namespaces/$NS/serviceaccounts/$SA"
}

echo "   prove seed token authenticates against the real apiserver:"
code=$(k8s_auth "$SEED_TOK")
[ "$code" = 200 ] || { echo "   FAIL: seed token got HTTP $code (expected 200)"; exit 1; }
echo "      OK (HTTP 200)"

echo "== 5. isolated GNUPGHOME + no-protection GPG key + gopass store =="
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

echo "== 6. seed driver-ready blob into gopass (CA pinned via ca=) =="
# Blob: k8s://host/?ns&sa&secret&token&ca   — single line, no plaintext on disk.
BLOB="k8s://127.0.0.1:6443/?ns=$NS&sa=$SA&secret=$SEED_SECRET&token=$SEED_TOK&ca=$CA_B64"
printf '%s' "$BLOB" | gopass insert --multiline=false -f imported/k8s/labsa >/dev/null
gopass ls --flat | sed 's/^/     /'

echo "== 7. rotate --execute (MANDATORY backup gate runs first) =="
INCREDIGO_ALLOW_EXECUTE=1 incredigo rotate --execute --prefix imported/ 2>&1 | sed 's/^/   /'

echo "== 8. CUTOVER ASSERTIONS =="
NEW_BLOB=$(gopass show -o imported/k8s/labsa)
NEW_TOK=$(printf '%s' "$NEW_BLOB" | sed -E 's/.*[?&]token=([^&]*).*/\1/')

fail=0
# The kube-apiserver caches SUCCESSFUL token authentications for ~10s
# (cachedTokenAuthenticator). The seed token authenticated at step 4, so the
# Secret deletion only takes effect once that cache entry expires. Poll up to 30s.
echo "   [k8s] OLD token must now FAIL against the real apiserver (waiting out the ~10s auth cache):"
old_dead=0
for i in $(seq 1 30); do
  code=$(k8s_auth "$SEED_TOK")
  if [ "$code" != 200 ]; then old_dead=1; echo "      OK: old token rejected (HTTP $code after ${i}s)"; break; fi
  sleep 1
done
[ "$old_dead" = 1 ] || { echo "      FAIL: old token still authenticates after 30s"; fail=1; }
echo "   [k8s] NEW token must WORK:"
code=$(k8s_auth "$NEW_TOK")
if [ "$code" = 200 ]; then echo "      OK: new token authenticates (HTTP 200)"
else echo "      FAIL: new token got HTTP $code"; fail=1; fi
echo "   [leak] new token must NOT equal old:"
[ "$NEW_TOK" != "$SEED_TOK" ] && echo "      OK: token actually changed" || { echo "      FAIL: token unchanged"; fail=1; }

echo
if [ "$fail" = 0 ]; then echo "ALL K8S CUTOVER ASSERTIONS PASSED"; else echo "SOME ASSERTIONS FAILED"; exit 1; fi
