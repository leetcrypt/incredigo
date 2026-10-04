# lab/ — reproduce the rotation proofs (FAKE creds only)

These scripts stand up **real** target software in a throwaway VM and drive
`incredigo rotate --execute` against **fake** credentials in an **isolated** gopass
store. They are how the `LIVE-VM` proof levels in
[`../internal/rotate/proofs.go`](../internal/rotate/proofs.go) /
[`../docs/ROTATION-PROOFS.md`](../docs/ROTATION-PROOFS.md) were earned, and let anyone
reproduce them from a clean machine.

> **Safety:** every script uses `GNUPGHOME=$HOME/.lab-gnupg` + `GOPASS_HOMEDIR=$HOME/.lab-gopass`
> (a no-protection throwaway key) and fake creds. Nothing here can touch a real gopass
> store or a real provider. Run them in a disposable VM anyway.

## Quick start (Multipass, Ubuntu 24.04)

```sh
multipass launch 24.04 --name incredigo-sbx --disk 15G --memory 4G
# build a static binary and install it in the VM:
CGO_ENABLED=0 go build -o /tmp/incredigo ./cmd/incredigo
multipass transfer /tmp/incredigo incredigo-sbx:/home/ubuntu/incredigo
multipass exec incredigo-sbx -- sudo install -m755 /home/ubuntu/incredigo /usr/local/bin/incredigo
# install the real gopass release (NOT Ubuntu's apt 'gopass', which is a pass clone):
#   https://github.com/gopasspw/gopass/releases  -> /usr/local/bin/gopass

# copy the lab dir in and run a proof, e.g. postgres:
multipass transfer -r lab incredigo-sbx:/home/ubuntu/lab
multipass exec incredigo-sbx -- bash -lc 'cd lab && INCREDIGO_BIN=/usr/local/bin/incredigo bash lab-provision-pg.sh'
multipass exec incredigo-sbx -- bash -lc '
  export GNUPGHOME=$HOME/.lab-gnupg GOPASS_HOMEDIR=$HOME/.lab-gopass
  export INCREDIGO_PASSPHRASE=lab-seal-pass INCREDIGO_ALLOW_EXECUTE=1
  incredigo rotate --execute --prefix imported/'
```

## LIVE-VM provisioners (real target software)

| Script | Proves driver | Target |
|---|---|---|
| `lab-provision-pg.sh` | `postgres` | real PostgreSQL |
| `lab-provision-dbclones.sh` | `mysql`, `redis` | real MariaDB + redis-server (self-asserting cutover) |
| `lab-provision-wg.sh` | `wireguard` | real `wireguard-tools` |
| `lab-provision-gitea.sh` | `gitea` | real Gitea 1.25 (self-owned PAT) |
| `lab-provision-appsec.sh` | `appsecret` | real local config files |
| `lab-provision-mongo.sh` | `mongo` | real mongod/mongosh 8.0 |
| `lab-provision-k8s.sh` | `k8s` | real k3s v1.35 |

## MOCK-ONLY provisioners (emulator / mock — same code path, not the real provider)

| Script | Driver | Emulator |
|---|---|---|
| `lab-provision-aws.sh` + `lab-verify-aws.sh` + `moto-probe.py` | `aws` | moto (mock AWS) |

## Phase-B `passwords` engine POCs

| Script | Manager |
|---|---|
| `lab-provision-keepass.sh` | KeePassXC (`keepassxc-cli`) |
| `lab-provision-bitwarden.sh` + `vw-register.py` | Vaultwarden + `bw` CLI |
| `lab-provision-browsercsv.sh` + `csv-commit-probe.py` | Chrome/Firefox CSV (staging only) |
| `lab-provision-browserrot.sh` | Phase A-tier-1 site-side rotation engine (`internal/browserrot`) — real headless Chromium against a throwaway local change-password form (fake cred) |
| `tui-probe.py` | drives the `guide` Bubble Tea TUI under a pty |

## Multi-reference blast-and-cutover (gitea)

| Script | Proves | Depends on |
|---|---|---|
| `lab-gitea-blast-vm.sh` | the gitea **blast-and-cutover** — one rotation rewrites the token in **every** on-disk reference in lockstep | `lab-provision-gitea.sh` (real local Gitea) |

`lab-gitea-blast-vm.sh` is the LIVE-VM proof for the cutover a real *in-use* Gitea PAT
needs: it embeds one seed token verbatim in three real-world reference shapes (a fake
`~/.git-credentials` line, an embedded git-remote URL in a repo `.git/config`, and a
`tea` config), stages a driver-ready blob carrying one `ref=<file>` per reference, runs
`rotate --execute`, then asserts **every** reference was rewritten old→new, the new token
is alive (`200`), the old is revoked (`401`), and the rewritten `.git-credentials` still
authenticates at the git transport (not `401`). Ordering is the point: incredigo mints
the new token, proves it authenticates, **then** rewrites the refs, and revokes the old
one **last** — so a dead token is never written into a git config.

Run it after the provisioner:
```sh
multipass exec incredigo-sbx -- bash /home/ubuntu/lab/lab-provision-gitea.sh
multipass exec incredigo-sbx -- bash /home/ubuntu/lab/lab-gitea-blast-vm.sh   # -> GITEA_BLAST_VM_OK
```

> **Two documented follow-ons** (surfaced by this proof, not yet built):
> 1. **gopass-entry-sync** — the same PAT also lives in *other* gopass entries; the driver
>    rewrites only files named in `ref=`, so a spine hook is needed to pass old+new token
>    to a gopass-sweep step. Surface in the blast report; do not auto-rewrite yet.
> 2. **token-scope-cloning** — the driver mints the new token with fixed
>    `write:user`/`read:user` scopes; a token used for git operations needs its repo scopes
>    preserved (clone the old token's scopes on create, like the `sendgrid` driver).

## Custody / smoke

- `lab-rung1-appsecret-host.sh` — **safe-candidate ladder rung 1**, the host dress
  rehearsal: the first end-to-end run of the real `rotate --execute` spine on the host
  toolchain (real gopass, backup gate, audit, seal flow) against a **throwaway scratch
  app** (dummy `.env` + `config.yml`, fake secret). Walks dry-run → blast → execute →
  asserts the in-place cutover (old gone, one new value in both files, stored blob
  updated) → shows the old value is recoverable from the sealed backup. Isolated store,
  zero real-cred risk. `appsecret` stays LIVE-VM — a real-cred rotation is what earns
  LIVE-REAL. (ROADMAP M2 rung 1.)
- `lab-restore-drill.sh` — proves the sealed `.age` backup is a **real recovery path** on
  the host against real gopass (isolated throwaway store, fake creds): seed → seal →
  destroy every entry → `import` → assert byte-equal restoration + no plaintext in the
  bundle. The safety net for no-op-`RevokeOld` drivers (e.g. `appsecret`), where the
  backup is the only rollback. Prerequisite for the first real rotation (ROADMAP M2).
- `lab-store.sh` — throwaway key + gopass store + fake `.env`/`.aws`/consumer files.
- `lab-run.sh` — scan→status→migrate→export→import→`rotate --dry-run --blast`→worklist.
- `lab-harness.sh`, `incredigo-lab-setup.sh` — older combined harness variants.

## Notes carried over

- Ubuntu apt `gopass` is the **wrong tool** (a `pass` clone). Install gopasspw/gopass.
- Multipass snap **cannot read `/tmp`** — stage under `$HOME` before `multipass transfer`.
- `rotate --prefix` must be the `imported/` **root** (source = first path segment after it).
- Headless runs need `INCREDIGO_PASSPHRASE` (seal/backup passphrase, separate from GPG).
