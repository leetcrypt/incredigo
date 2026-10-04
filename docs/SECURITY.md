# Security model

incredigo's job is to *minimize the footprint and lifetime* of plaintext secrets.
It is not a substitute for a trustworthy machine.

## Guarantees

| Threat | Mitigation |
|---|---|
| Plaintext leaks to disk | Never written. gopass GPG blobs or sealed bundles (age/hmac/openssl) only; no temp files. |
| Plaintext leaks via swap | `mlock` on every secret buffer (memguard). |
| Plaintext via core dump / process snapshot | `MADV_DONTDUMP`, guard pages, zeroize on drop; `memguard.CatchInterrupt`. |
| Source files corrupted by the tool | Scanners are strictly read-only (`O_RDONLY`). |
| Old cred destroyed before replacement verified | v1 deletes nothing. (v2 rotation verifies-new before revoke-old.) |
| New cred lost after an in-place change (lockout) | The new secret is written to `<entry>.pending` the moment `Rotate` returns, never discarded on a later failure, and removed only after the primary entry re-verifies. Writes after Rotate ignore Ctrl-C. Entries with a `.pending` are held back from the next run. |
| Secrets in logs | Audit log records only redacted metadata; identities are pre-redacted by scanners. |
| Secrets in `ps`/argv | Secrets are piped via stdin (gopass); the backup passphrase reaches openssl over an inherited fd (`-pass fd:3`). Never argv, never env. |
| Network exfiltration | No network calls in v1. |

## Honest limits

- incredigo cannot protect plaintext from a **compromised OS/kernel** or a malicious
  **gpg-agent** while it runs — those already see your secrets in normal use.
- The sealed bundle's strength is its **passphrase**. Use a strong one; the KDF is
  scrypt (`age`, default) or PBKDF2 @ 600k iterations (`hmac`/`openssl`), but a weak
  passphrase is still a weak passphrase.
- Go's runtime can in principle copy bytes during GC compaction. memguard buffers
  live outside the Go heap to avoid this; do not copy secret bytes into Go
  `string`s or heap `[]byte` that outlive immediate use. One documented exception:
  the `age` sealer's library API takes the passphrase as a `string` (the `hmac`
  sealer does not). The vaulted secrets themselves never become strings.

## Restoring a bundle by hand

If `incredigo` itself is unavailable, a bundle is recoverable with standard tools.
The decrypted stream is the length-prefixed record format in
`internal/sink/bundle.go` (`uint16 pathLen | path | uint32 chunkLen | chunk | …`).

**age (default):**

```sh
age -d backup.incredigo.age > bundle.bin      # prompts for the passphrase
```

**hmac (`--sealer hmac`)** — verify integrity *before* decrypting:

```sh
head -c 32 backup.incredigo.age > mac.bin     # bundle = HMAC-SHA256(32) || ciphertext
tail -c +33 backup.incredigo.age > ct.bin
openssl dgst -sha256 -hmac "$PASS" -binary ct.bin | cmp - mac.bin   # must match
openssl enc -d -aes-256-ctr -pbkdf2 -iter 600000 -pass pass:"$PASS" -in ct.bin > bundle.bin
```

**openssl (`--sealer openssl`, unauthenticated):**

```sh
openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -in backup.incredigo.age > bundle.bin
```

## Reporting

Report vulnerabilities privately to the maintainer (do not open a public issue).
