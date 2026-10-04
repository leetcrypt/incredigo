#!/usr/bin/env bash
# Live cutover POC for the WireGuard self-hosted rotation driver, inside the sandbox
# VM. FAKE keys only, isolated gopass store. Sets up two local wg interfaces (wg0 =
# ours, wg1 = the peer that trusts us), seeds wg0's old private key into gopass, runs
# `rotate --execute`, and asserts the peer now trusts the NEW public key (and only it),
# AND that wg0's live interface public key equals the public key our Go code derived —
# i.e. our in-process Curve25519 derivation matches real `wg pubkey`.
set -euo pipefail

export GNUPGHOME="$HOME/.lab-gnupg"
export GOPASS_HOMEDIR="$HOME/.lab-gopass"
export INCREDIGO_PASSPHRASE='lab-seal-passphrase-001'

echo "== 0. install wireguard-tools =="
command -v /usr/bin/wg >/dev/null 2>&1 || {
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard-tools >/dev/null
}

echo "== 1. sudo wrapper so incredigo (as ubuntu) can drive wg with root =="
echo 'ubuntu ALL=(root) NOPASSWD: /usr/bin/wg' | sudo tee /etc/sudoers.d/incredigo-wg >/dev/null
sudo tee /usr/local/bin/wg >/dev/null <<'EOF'
#!/bin/sh
exec sudo -n /usr/bin/wg "$@"
EOF
sudo chmod 755 /usr/local/bin/wg
hash -r

echo "== 2. mint old (wg0) + peer (wg1) keys; bring up interfaces =="
OLD_PRIV=$(/usr/bin/wg genkey)
OLD_PUB=$(printf '%s' "$OLD_PRIV" | /usr/bin/wg pubkey)
PEER_PRIV=$(/usr/bin/wg genkey)
for IF in wg0 wg1; do sudo ip link del "$IF" 2>/dev/null || true; sudo ip link add "$IF" type wireguard; done
printf '%s' "$OLD_PRIV"  | sudo /usr/bin/wg set wg0 private-key /dev/stdin
printf '%s' "$PEER_PRIV" | sudo /usr/bin/wg set wg1 private-key /dev/stdin
# wg1 (peer) trusts wg0's OLD public key with some allowed-ips.
sudo /usr/bin/wg set wg1 peer "$OLD_PUB" allowed-ips 10.0.0.1/32
echo "   wg1 trusts (before): $(sudo /usr/bin/wg show wg1 peers)"
echo "   wg0 iface pubkey (before): $(sudo /usr/bin/wg show wg0 public-key)  [== OLD_PUB? $OLD_PUB]"

echo "== 3. isolated GNUPGHOME + no-protection GPG key + gopass store =="
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

echo "== 4. seed wg0's old private key into gopass (driver-ready blob) =="
printf '%s' "$OLD_PRIV" | gopass insert --multiline=false -f imported/wireguard/wg0 >/dev/null
gopass ls --flat | sed 's/^/     /'

echo "== 5. rotate --execute (MANDATORY backup gate runs first) =="
# NOTE: prefix must be the imported/ ROOT — Mode A derives the driver Source from the
# FIRST path segment after the prefix (imported/<source>/<slug>). Narrowing to
# imported/wireguard/ would make Source="wg0" and no driver would Detect it.
INCREDIGO_ALLOW_EXECUTE=1 incredigo rotate --execute --prefix imported/ 2>&1 | sed 's/^/   /'

echo "== 6. CUTOVER ASSERTIONS =="
NEW_PRIV=$(gopass show -o imported/wireguard/wg0)
NEW_PUB=$(printf '%s' "$NEW_PRIV" | /usr/bin/wg pubkey)
PEERS_AFTER=$(sudo /usr/bin/wg show wg1 peers)
IFACE_PUB=$(sudo /usr/bin/wg show wg0 public-key)
echo "   wg1 trusts (after): $PEERS_AFTER"
echo "   wg0 iface pubkey (after): $IFACE_PUB"

fail=0
[ "$NEW_PRIV" != "$OLD_PRIV" ] && echo "   OK: private key changed" || { echo "   FAIL: private key unchanged"; fail=1; }
echo "$PEERS_AFTER" | grep -qF "$NEW_PUB" && echo "   OK: peer trusts NEW pubkey" || { echo "   FAIL: peer missing NEW pubkey"; fail=1; }
echo "$PEERS_AFTER" | grep -qF "$OLD_PUB" && { echo "   FAIL: peer still trusts OLD pubkey"; fail=1; } || echo "   OK: peer dropped OLD pubkey"
[ "$IFACE_PUB" = "$NEW_PUB" ] && echo "   OK: wg0 live pubkey == Go-derived NEW pubkey (curve25519 matches real wg)" || { echo "   FAIL: wg0 pubkey != derived"; fail=1; }

echo
if [ "$fail" = 0 ]; then echo "ALL WIREGUARD CUTOVER ASSERTIONS PASSED"; else echo "SOME ASSERTIONS FAILED"; exit 1; fi
