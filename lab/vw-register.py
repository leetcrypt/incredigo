#!/usr/bin/env python3
# Programmatically register a Bitwarden account on a self-hosted Vaultwarden, replicating
# the client-side registration crypto so the `bw` CLI can later log in and DECRYPT items.
# Run with the moto-venv python (has `cryptography`). FAKE lab account only.
#
# argv: email password name base_url
#
# Bitwarden registration (PBKDF2-SHA256 KDF):
#   masterKey            = PBKDF2(password, email, iters, 32)
#   masterPasswordHash   = b64(PBKDF2(masterKey, password, 1, 32))
#   stretched enc/mac    = HKDF-Expand(masterKey, "enc"/"mac", 32)
#   userKey (64B random) = 32B enc || 32B mac    (the account symmetric key)
#   "key"                = EncString(userKey, stretched.enc, stretched.mac)   (type 2)
#   RSA keypair          = encryptedPrivateKey EncString(PKCS8, userKey.enc, userKey.mac)
import base64, json, os, ssl, sys, urllib.request, urllib.error
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric import rsa

email, password, name, base_url = sys.argv[1].lower(), sys.argv[2], sys.argv[3], sys.argv[4].rstrip("/")
ITERS = 600000

def pbkdf2(pw, salt, iterations, length=32):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt, iterations=iterations).derive(pw)

def hkdf_expand(prk, info, length=32):
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info.encode()).derive(prk)

def enc_string(plaintext, enc_key, mac_key):
    iv = os.urandom(16)
    p = PKCS7(128).padder()
    data = p.update(plaintext) + p.finalize()
    enc = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ct = enc.update(data) + enc.finalize()
    h = hmac.HMAC(mac_key, hashes.SHA256()); h.update(iv + ct); mac = h.finalize()
    return "2.%s|%s|%s" % (base64.b64encode(iv).decode(),
                           base64.b64encode(ct).decode(),
                           base64.b64encode(mac).decode())

master_key = pbkdf2(password.encode(), email.encode(), ITERS, 32)
master_password_hash = base64.b64encode(pbkdf2(master_key, password.encode(), 1, 32)).decode()
s_enc, s_mac = hkdf_expand(master_key, "enc"), hkdf_expand(master_key, "mac")

user_key = os.urandom(64)
protected_key = enc_string(user_key, s_enc, s_mac)

priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
priv_der = priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
pub_der = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
enc_priv = enc_string(priv_der, user_key[:32], user_key[32:])

payload = {
    "email": email, "name": name, "masterPasswordHash": master_password_hash,
    "masterPasswordHint": "", "key": protected_key, "kdf": 0, "kdfIterations": ITERS,
    "keys": {"publicKey": base64.b64encode(pub_der).decode(), "encryptedPrivateKey": enc_priv},
}
body = json.dumps(payload).encode()
# Lab Vaultwarden uses a self-signed cert — accept it (throwaway, loopback only).
ctx = ssl._create_unverified_context() if base_url.startswith("https") else None

for path in ("/identity/accounts/register", "/api/accounts/register"):
    req = urllib.request.Request(base_url + path, data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            print("registered via %s (HTTP %s)" % (path, r.status)); sys.exit(0)
    except urllib.error.HTTPError as e:
        print("HTTP %s %s -> %s" % (e.code, path, e.read().decode(errors="replace")[:400]), file=sys.stderr)
    except Exception as e:
        print("ERR %s -> %r" % (path, e), file=sys.stderr)
sys.exit(1)
