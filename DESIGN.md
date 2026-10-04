# incredigo — local-first credential rotation & custody

`incredigo` discovers credentials scattered across the common places developers and
operators leave them, migrates them into a [gopass](https://www.gopass.pw/)
(GPG-backed) store **without ever writing plaintext to disk**, and tracks their age
so you know what is stale. It is **local-first, encrypted, and RAM-only** by design.

> **Status:** v1 design. v1 scope is **discover + migrate + expiry tracking**.
> Provider-driven rotation (issue-new / verify / revoke-old) is explicitly **out of
> scope for v1** and lives behind a stable interface so it can be added later
> without reshaping the tool.

---

## 1. Why this exists (prior art & the gap)

| Tool | What it does | Why it isn't this |
|---|---|---|
| [pass-import](https://github.com/roddhjav/pass-import) | Imports from ~60 password managers into pass/gopass | Import-only, and only from *other managers*. Doesn't discover creds sitting in `~/.aws/credentials`, `.netrc`, `.env`, kubeconfig, etc. No expiry tracking. |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) / gitleaks | Scan repos/filesystems for high-entropy secrets | Detection, not custody. Finds strings; doesn't normalize, encrypt-migrate, or track. Repo-centric. |
| [Infisical](https://github.com/Infisical/infisical) / HashiCorp Vault | Full secrets platforms with rotation | Server-based (Postgres/Redis, network daemons). The opposite of local-first / RAM-only. |
| Keeper Commander | Open rotation plugin framework | SaaS-coupled, account-bound. |
| gopass | GPG-backed store + `git-credential` helper | The *destination*, not the discovery/custody/expiry layer. |

**The gap:** nothing does *local discovery of dev/OS credential stores → RAM-only
normalization → encrypted migration into gopass → expiry tracking* as a single
offline tool. That is what `incredigo` is.

---

## 2. Design principles

1. **Local-first.** No server, no daemon, no account. Everything runs on your
   machine against your own files.
2. **Encrypted at rest, always.** Disk only ever holds GPG blobs (gopass) or
   openssl-sealed backup bundles. Plaintext is never written to disk — no temp
   files, no swap, no core dumps.
3. **RAM-only plaintext.** Decrypted secret material lives only in a locked,
   non-swappable, non-dumpable memory arena and is zeroized the moment it is no
   longer needed.
4. **Read-only discovery.** Scanners never modify the files they read.
5. **Offline by default.** v1 makes zero network calls.
6. **Built to be extended.** Adding a new source (a scanner) or a new backup format
   (a sealer) is a single self-contained file implementing one interface.
7. **Auditable, not clever.** No custom crypto. We compose GPG (via gopass) and
   OpenSSL. The whole pipeline can be reproduced by hand with standard CLI tools.

---

## 3. Architecture

```
 DISCOVER ─────────────▶ CUSTODY ──────────────▶ SINK
 read-only scanners      RAM vault (memguard,     gopass insert  (live store, GPG)
 (aws/env/netrc/ssh/     mlock, DONTDUMP,         openssl-sealed bundle (backup)
  docker/kube/git/...)   zeroize-on-drop)
                              │
                              ▼
                         EXPIRY TRACKER
                         (age policy → status report;
                          flags stale; NO API calls in v1)
```

Three decoupled stages connected by the RAM vault. Each stage is independently
testable and independently extensible.

### 3.1 Discover

Pluggable, strictly read-only scanners. Each scanner understands exactly one
location/format and emits normalized `Credential` records.

Implemented in v1: ✅ — others are roadmap.

| Scanner | Location(s) | Parsed | v1 |
|---|---|---|---|
| `aws` | `~/.aws/credentials` (`AWS_SHARED_CREDENTIALS_FILE`) | INI sections → access key id / secret | ✅ |
| `env` | `.env`, `.env.*` in CWD | `KEY=value`, keyword + entropy filtered | ✅ |
| `netrc` | `~/.netrc`, `~/.authinfo` | machine / login / password | ✅ |
| `ssh` | `~/.ssh/id_*` (not `.pub`) | private keys, `encrypted` flag (best-effort) | ✅ |
| `docker` | `~/.docker/config.json` (`DOCKER_CONFIG`) | `auths[].auth`, `identitytoken` | ✅ |
| `kube` | `~/.kube/config` (`KUBECONFIG`) | user `token` / `client-key-data` / `password` | ✅ |
| `git` | `~/.git-credentials` | URL-embedded tokens | ✅ |
| `file` | any file/dir via `--path` (recursive) | whole file = one secret; PEM → `private_key` | ✅ |
| `gcloud` | `~/.config/gcloud/*` | ADC / legacy credentials | — |
| `npm` / `pypi` | `.npmrc`, `.pypirc` | `_authToken`, repo creds | — |

A scanner returns metadata records; **the secret value is a handle into the RAM
vault, never a copied plaintext string.** See §4.

```go
// internal/discover/discover.go
type Kind string // "aws_key", "token", "password", "private_key", ...

type Credential struct {
    Source    string         // scanner name, e.g. "aws"
    Kind      Kind
    Identity  string         // non-secret label, e.g. "default / AKIA...redacted"
    Location  string         // file path it came from
    Modified  time.Time      // file mtime — input to expiry policy
    Secret    *vault.Handle  // opaque handle; resolves to locked memory only
    Meta      map[string]string
}

type Scanner interface {
    Name() string
    Available() bool                 // is this source present on the box?
    Scan(ctx context.Context, v *vault.Vault) ([]Credential, error)
}
```

Scanners self-register in an `init()` so adding one is a single new file:

```go
func init() { discover.Register(&awsScanner{}) }
```

### 3.2 Custody — the RAM-only core

This is the security heart of the tool.

- Plaintext secrets live **only** in a locked memory arena backed by
  [`memguard`](https://github.com/awnumar/memguard):
  - `mlock(2)` — pages never swap to disk.
  - `MADV_DONTDUMP` — excluded from core dumps.
  - Guard pages + canaries around buffers.
  - **Explicit zeroization** on drop (`LockedBuffer.Destroy()`), and a global
    `memguard.CatchInterrupt()` / `Purge()` so secrets are wiped on SIGINT/panic.
- A `vault.Handle` is an opaque reference; callers must `Open()` it to get a
  short-lived `*memguard.LockedBuffer`, use it, and `Destroy()` it. Plaintext is
  never returned as a Go `string` (strings are immutable, GC-managed, and cannot be
  reliably zeroized).

```go
// internal/vault/vault.go
type Vault struct { /* registry of LockedBuffers */ }
type Handle struct { id uint64 }

func (v *Vault) Store(plaintext []byte) *Handle      // copies into locked mem, wipes caller's slice
func (v *Vault) Open(h *Handle) (*memguard.LockedBuffer, error)
func (v *Vault) Purge()                              // destroy everything; called on exit
```

### 3.3 Sink

Two sinks, two clearly separated jobs:

**a) gopass — the live store (GPG).**
Migration streams the secret straight into `gopass insert <path>` over the
process's **stdin pipe**. gopass performs GPG encryption to your key. Plaintext
flows RAM-vault → pipe → gopass's GPG layer; **it never touches the filesystem.**

```
incredigo ──(os.Pipe, locked buffer)──▶ gopass insert imported/aws/default ──▶ GPG blob on disk
```

Path convention: `<prefix>/<source>/<identity>` (default prefix `imported/`),
e.g. `imported/aws/default`, `imported/docker/registry.example.com`.

**b) the sealed backup/transport bundle.**
gopass already GPG-encrypts every entry, so we do **not** double-wrap individual
secrets. Instead a `Sealer` produces a single portable, **agent-independent** bundle
for disaster recovery / moving to a fresh machine where no gpg-agent or keyring
exists yet. One passphrase restores everything.

The bundle's plaintext side is a flat, length-prefixed record stream
(`uint16 pathLen | path | chunk* | end`, see `internal/sink/bundle.go`); secrets
stream `gopass show` → frame → Sealer and back, so a whole secret is never held in
one buffer or turned into a Go string. The `Sealer` then wraps that stream:

```go
// internal/sink/sealer.go
type Sealer interface {
    Name() string
    Seal(ctx context.Context, plaintext io.Reader, out io.Writer, pass *memguard.LockedBuffer) error
    Open(ctx context.Context, in io.Reader, out io.Writer, pass *memguard.LockedBuffer) error
}
```

**Default: `age`** (`--sealer age`). OpenSSL 3.x's `enc` command **refuses AEAD
ciphers** outright (`enc: AEAD ciphers not supported`), so the originally-planned
`openssl enc -aes-256-gcm` cannot authenticate a bundle on a modern box — a tampered
or corrupt backup would decrypt to silent garbage. We therefore default to
[`age`](https://github.com/FiloSottile/age) (ChaCha20-Poly1305 + scrypt), which is
authenticated and hand-restorable with the standard `age` CLI. Three sealers ship,
all behind the one interface:

| `--sealer` | Authenticated | Mechanism | Hand-restore |
|---|---|---|---|
| `age` (default) | ✅ | age format (ChaCha20-Poly1305, scrypt) | `age -d backup.incredigo.age` |
| `hmac` | ✅ | `openssl enc -aes-256-ctr` + in-process HMAC-SHA256 (encrypt-then-MAC, verified before decrypt) | `openssl dgst -hmac` then `openssl enc -d` (see SECURITY.md) |
| `openssl` | ❌ | `openssl enc -aes-256-cbc -pbkdf2` | `openssl enc -d -aes-256-cbc -pbkdf2` |

> The passphrase is delivered to openssl over an inherited fd (`-pass fd:3`), never
> argv or env. For `age` it transits a Go string (the library's API takes a
> `string`); for `hmac` it never does (the MAC key is locked-buffer bytes). The
> `openssl` sealer is a last-resort fallback only: it is **unauthenticated**.

### 3.4 Expiry tracker

A pure-local policy engine. No network in v1. Reads `Modified` (and any
provider-known max-age) and reports against thresholds.

```yaml
# ~/.config/incredigo/policy.yaml
defaults: { warn_after: 60d, stale_after: 90d }
overrides:
  aws_key:     { warn_after: 30d, stale_after: 90d }
  private_key: { warn_after: 180d }
```

`incredigo status` prints a table: identity, source, age, state (`ok`/`warn`/`stale`).
No secrets are ever printed.

---

## 4. Threat model & guarantees

| Threat | Mitigation |
|---|---|
| Plaintext leaks to disk | Never written. gopass GPG blobs or openssl bundles only. No temp files. |
| Plaintext leaks via swap | `mlock` on all secret buffers. |
| Plaintext leaks via core dump / `/proc/<pid>/mem` snapshot | `MADV_DONTDUMP`; `memguard` guard pages; zeroize on drop. |
| Source files corrupted by the tool | Scanners are strictly read-only (open `O_RDONLY`). |
| Old cred destroyed before replacement verified | v1 never deletes anything. (Rotation, when added, verifies-new before revoke-old.) |
| Secrets in logs | Append-only audit log redacts all secret material; `Identity` fields are pre-redacted. |
| Network exfiltration | No network calls in v1; future rotation adapters are per-provider, explicit, opt-in. |

**Out of scope / honest limits:** `incredigo` cannot protect against a compromised
machine while it runs (a kernel-level attacker or a malicious gpg-agent can see
plaintext in use). It minimizes the *window* and the *footprint*, not the
fundamental trust in your own OS and GPG key.

---

## 5. CLI surface (v1)

```
incredigo scan    [--source aws,env,...] [--path FILE|DIR ...] [--json]   # discover (NO secrets printed)
incredigo migrate [--prefix imported/] [--dedupe] [--force] [--source ...] [--path ...]
incredigo status  [--source ...] [--path ...]            # expiry/age report against policy
incredigo export  [--sealer age|hmac|openssl] --out backup.incredigo.age   # sealed bundle of the prefix
incredigo import  [--sealer age|hmac|openssl] --in  backup.incredigo.age   # restore a bundle into gopass
```

Global flags: `--dry-run`, `--audit-log <path>`, `--config <path>`,
`--sealer <age|hmac|openssl>`. `--path` (repeatable) harvests an arbitrary file or
directory via the `file` scanner. The export/import passphrase is read from a
no-echo prompt or `$INCREDIGO_PASSPHRASE` into locked memory.

Typical first run:
```
incredigo scan --dry-run            # see what's out there
incredigo migrate --prefix imported/ --dedupe
incredigo status                    # what's already stale
incredigo export --out ~/incredigo-backup.age   # authenticated (age) by default
```

---

## 6. Repository layout

```
incredigo/
  cmd/incredigo/          # cobra entrypoint: scan|migrate|status|export|import
  internal/vault/       # memguard arena: Store/Open/Purge, zeroize, SIGINT handler
  internal/discover/    # registry + Scanner interface + one file per scanner
    aws.go env.go netrc.go ssh.go docker.go kube.go git.go file.go
  internal/sink/
    gopass.go           # streaming writer over gopass insert stdin
    bundle.go           # plaintext record framing: gopass <-> Sealer
    sealer.go           # Sealer interface
    age.go              # default sealer (authenticated)
    hmac.go             # authenticated openssl-only sealer (encrypt-then-MAC)
    openssl.go          # unauthenticated fallback sealer (AES-256-CBC)
  internal/policy/      # expiry rules, age thresholds, policy.yaml loader
  internal/audit/       # redacted append-only log
  docs/
    ADDING_A_SCANNER.md
    SECURITY.md         # threat model (mirror of §4) + responsible disclosure
  DESIGN.md             # this file
  README.md
  go.mod
```

The two extension points — **the scanner registry** and **the `Sealer` interface**
— are what make `incredigo` easy for others to build on.

---

## 7. Roadmap beyond v1

- **v2 — rotation adapters** behind a `Rotator` interface: `aws iam create-access-key`
  → verify → `delete-access-key`; GitHub/GitLab PAT via API; SSH keygen + push to
  `authorized_keys`. Verify-new-before-revoke-old, always.
- **v2 — guided manual rotation** for creds with no automatable path (DB passwords).
- **Later** — TUI for review/approve of discovered creds; gopass mount/git sync hooks.
