# Rotation cutover proofs

This file is the **human-facing mirror** of `internal/rotate/proofs.go`. That Go table is
the single source of truth (`incredigo rotate` surfaces it as the **PROOF** column); this
document explains what each level *means* and records the basis for every driver's level.
Keep the two in sync — if you change one, change the other.

## Why this exists

Every `Rotator` in `internal/rotate` contains **only real rotation code**: it talks to a
real service (HTTP API, DB client, SSH, local files). None of them contain simulation
branches or test awareness — the only thing a test injects is an endpoint / `HTTPClient` /
binary path, which a real deployment also configures.

What differs between drivers is **how their real-cutover path has been validated**. That is
*data, not behaviour*, so it lives in one table (here + `proofs.go`) instead of as prose
scattered through — and easily confused with — the driver code. This is the guardrail that
stops a mock-only driver from ever being mistaken for a live one.

## Levels

Ordered lowest → highest (a higher level is a strictly stronger cutover proof):

| Level | Meaning |
|-----------|---------|
| **UNPROVEN** | No cutover proof recorded (e.g. the dry-run noop helper). |
| **MOCK-ONLY** | Cutover proven only against an **emulator** — our own `httptest` / in-process SSH server, **or a third-party mock** (e.g. `moto` for AWS). **NOT** proven against the real target service. |
| **LIVE-VM** | Cutover proven against the **real target software** running in the sandbox VM (real PostgreSQL / MariaDB / Redis / `wg` / Gitea / local files). |
| **LIVE-REAL** | Cutover proven against a **real, host-owned credential at the real provider** (not the VM, not an emulator) — recorded only after an authorized per-credential rotation on the safe-candidate ladder (ROADMAP M2). |

> **Honesty note:** running in the VM does **not** automatically make a driver LIVE-VM.
> AWS ran in the VM but only against **moto** (a mock AWS), so it is **MOCK-ONLY**. LIVE-VM
> means the *real* target software validated the cutover.

### Execute-time proof gate

`rotate --execute` runs a driver **only if its proof is ≥ LIVE-VM** (`MinExecuteProof`
in `proofs.go`). MOCK-ONLY and UNPROVEN drivers are **skipped** — their
`Rotate`/`Verify`/`RevokeOld` are never called, so the old secret is left fully intact —
unless the operator passes the explicit **`--allow-mock-proven`** opt-in. This closes the
last structural gap where a driver proven only against an emulator could touch a real
credential unattended.

## Current status

### LIVE-REAL — proven against a real, host-owned credential at the real provider

| Driver | Real credential | Proof |
|------------|-----------------|-------|
| `gitea` | real Gitea PAT on `gitea.example.com` (self-owned, no 2FA) | `lab-rung3-gitea-real.sh` — full `create → verify → store → revoke` against a purpose-made throwaway token (2026-07-19). Independent cutover check: new token → `200`, old token → `401`; sealed backup verified; the driver-minted token deleted afterwards, leaving the account clean. |

> **Ladder note (ROADMAP M2 rung 3):** this is the **first real credential rotation**. The
> throwaway token was chosen so the driver's real lifecycle earns LIVE-REAL at **zero blast
> radius** — a genuine in-use PAT is referenced in `~/.git-credentials`, embedded git-remote
> URLs and `~/.config/tea/config.yml` as well as gopass, so rotating one safely first requires
> the multi-reference **blast-and-cutover**, not just the single-blob driver.

#### Multi-reference blast-and-cutover — proven LIVE-VM

The cutover a real *in-use* Gitea PAT needs is now built and proven against real local
Gitea (1.25.0) in the VM (`lab-gitea-blast-vm.sh` → `GITEA_BLAST_VM_OK`). The credential
blob carries one `ref=<file>` per on-disk reference; `Rotate` mints the new token, proves
it authenticates (`GET /user`), **then** rewrites the old→new token literal in **every**
reference file atomically, and `Verify` asserts the new token is present in each before the
spine revokes the old one **last**. Proof run: one rotation rewrote a fake `~/.git-credentials`
line, an embedded git-remote URL, and a `tea` config in lockstep; new token → `200`, old
token → `401`; the rewritten `.git-credentials` still authenticates at the git transport.
The old→new replacement is keyed on the 40-hex token literal, length-guarded
(`minGiteaTokenLen`), and atomic per file (temp+rename) — the same pattern the `appsecret`
driver uses. Enumerating the reference set is `internal/rotate/gitea_refs.go` (read-only).

> **Two documented follow-ons** (surfaced by the proof, deliberately out of this iteration):
> - **gopass-entry-sync** — the PAT also lives in *other* gopass entries; the driver rewrites
>   only files named in `ref=`. A spine hook passing old+new token to a gopass-sweep step is
>   needed before an in-use PAT that is duplicated across gopass entries can rotate cleanly.
> - **token-scope-cloning** — the new token is minted with fixed `write:user`/`read:user`
>   scopes (enough to manage tokens); a token used for **git operations** needs its repo
>   scopes preserved, i.e. clone the old token's scopes on create (as the `sendgrid` driver
>   clones API-key scopes). Until then a rotated git-auth PAT authenticates but may `403` on
>   repo ops — a token-scope matter, not a cutover failure.

### LIVE-VM — proven against real target software in the sandbox VM

| Driver | Real target | Provisioner |
|------------|-------------|-------------|
| `postgres` | real PostgreSQL | `lab-provision-pg.sh` |
| `mysql` | real MariaDB | `lab-provision-dbclones.sh` |
| `redis` | real `redis-server` | `lab-provision-dbclones.sh` |
| `wireguard` | real kernel WireGuard (`wireguard-tools`, disposable rootless-unprivileged container) | `lab/podman-proof.sh wireguard` (`--cap-add NET_ADMIN` only, own netns; wg0 interface-key rotation + wg1 peer create→verify→revoke, independently proven by a real WireGuard handshake from a throwaway probe interface — new key handshakes, old key rejected; also `lab-provision-wg.sh` on host `wg`) |
| `appsecret` | real local config files | `lab/podman-proof.sh appsecret` (no-container temp-dir variant; also `lab-provision-appsec.sh`) |
| `mongo` | real `mongod` 8.0 | `lab-provision-mongo.sh` |
| `k8s` | real k3s kube-apiserver + token controller | `lab/podman-proof.sh k8s` (disposable rootless-unprivileged k3s control plane, `--disable-agent`; also `lab-provision-k8s.sh` on host k3s) |
| `ssh` | real OpenSSH `sshd` (disposable podman container) | `lab/podman-proof.sh sshkey` |

> **k8s live-POC note (auth-cache timing):** the real kube-apiserver caches *successful*
> token authentications for ~10s (`cachedTokenAuthenticator`). After `RevokeOld` deletes the
> legacy token Secret, the old token keeps authenticating until that cache entry expires — so
> the POC polls the old token for up to 30s and asserts it flips to `401` (it does, ~7s). The
> `httptest` emulator invalidates instantly, so this delay only surfaced against real k3s —
> exactly what a live POC is for. The driver needed real-CA TLS to talk to the apiserver, so
> the blob gained `ca=` (base64 PEM, pinned as the only trusted root) and an `insecure=1`
> lab-only escape hatch; neither is test-awareness — a real deployment configures the same CA.

> **wireguard live-POC note (safe kernel handshake):** the WireGuard driver rotates a real
> kernel interface's private key (`wg set <iface> private-key`) and re-points the peer, so the
> proof needs *real* kernel WireGuard — but never a privileged container or any host mutation.
> The POC runs everything inside a disposable rootless container started with **`--cap-add
> NET_ADMIN` only** (not `--privileged`): that capability is confined to the container's **own
> network namespace**, so it cannot touch host networking (the host's real `proton0` WireGuard
> interface is provably untouched — incredigo dials `wg` through a `podman exec <ctr> wg` shim,
> so every call lands in the container's netns). The independent ground truth is a genuine
> WireGuard handshake: a throwaway probe interface loaded with the candidate private key drives
> a handshake against the peer over the container's loopback transport (`persistent-keepalive`
> forces the handshake without needing tunnel-IP data routing, which the same-netns kernel would
> otherwise short-circuit via local delivery). A non-zero `wg show <probe> latest-handshakes`
> means the peer cryptographically accepted that static key — so after `RevokeOld` the old key's
> handshake never completes (peer entry gone) while the new key's does: new-works / old-rejected,
> wholly independent of incredigo's self-report.

### MOCK-ONLY — proven only against an emulator / mock

| Driver | Emulator | Why not (yet) LIVE-VM |
|--------------|----------|------------------------|
| `aws` | `moto` mock AWS in VM | real AWS never hit |
| `openwrt` | in-process SSH server | live QEMU deferred |
| `mullvad` | `httptest` emulator | needs a paid account |
| `cloudflare` | `httptest` emulator | no self-host |
| `ghactions` | `httptest` emulator (holds the libsodium box keypair, decrypts the sealed PUT) | no self-host |
| `gitlab` | `httptest` emulator | GitLab CE too heavy for the VM |
| `npm` | `httptest` registry emulator | real registry never hit (see caveat below) |
| `gcp` | `httptest` IAM emulator (verifies the driver's RS256 JWT against the key's public key) | no self-host |
| `twilio` | `httptest` emulator (Basic-auth Keys resource) | no self-host |
| `flyio` | `httptest` GraphQL emulator | no self-host |
| `resend` | `httptest` emulator (Bearer `/api-keys` resource) | no self-host |
| `vercel` | `httptest` emulator (Bearer `/v3/user/tokens` resource) | no self-host |
| `sendgrid` | `httptest` emulator (Bearer `/v3/api_keys` resource, scope clone + `/v3/scopes` auth proof) | no self-host |

## What the MOCK-ONLY emulators actually prove

The emulators are **not** stubs that rubber-stamp success — each enforces the real
protocol so the test exercises the driver's true cutover logic:

- **gitlab** — `self/rotate` mints a new PAT *and revokes the caller's old one*; the test
  asserts `Verify(old)` fails after `Rotate`, proving the revoke really happened.
- **cloudflare** — `PUT .../value` rolls the value for the same token id and invalidates
  the previous value; the test asserts the id is unchanged and `Verify(old)` fails.
- **ghactions** — the emulator owns a real NaCl `box` keypair, serves the public key, and
  on `PUT` **decrypts the sealed value** and stores the plaintext; the test asserts the
  decrypted value equals the new value the driver put in the rebuilt blob — proving the
  sealed-box encryption is correct, not simulated.
- **npm / twilio / resend / vercel** — each emulator enforces credential validity (a
  token/key authenticates only while it exists) and the test asserts the old credential is
  dead after `RevokeOld` while the new one still authenticates — proving the
  create→verify→revoke cutover really happened. (Resend and Vercel additionally prove
  `Verify(new)` by listing keys/tokens with the new Bearer token and asserting the new id
  is present — auth success *and* the credential exists.)
- **sendgrid** — the emulator enforces Bearer validity *and* records each key's scopes; the
  driver clones the old key's scopes onto the new one (`GET /v3/api_keys/<id>` → reuse on
  `POST /v3/api_keys`) so rotation is a faithful replacement, not a privilege downgrade. The
  test asserts the minted key carries the seeded scopes, that `Verify(new)` (a `GET /v3/scopes`
  auth proof) succeeds, and that the old key stops authenticating after `RevokeOld` while the
  new key still does — old key dead, new one alive with the same scopes.
- **gcp** — the emulator **verifies the RS256 JWT signature** the driver mints against the
  public key recorded for the key's `kid`; it only issues an access token for a JWT that
  actually verifies, and `DELETE` removes the key — so the test proves real service-account
  self-auth (genuine `crypto/rsa` signing) *and* the cutover (revoked key can no longer mint
  a token).
- **flyio** — a managing token mints/deletes the deploy token over GraphQL; the deploy token
  authenticates the app query only while it exists, so the test proves the managing-token →
  deploy-token rotation and that the revoked deploy token stops working.

> **npm caveat (why it is not just "pending a VM run"):** the public `registry.npmjs.org`
> is not self-hostable, and the classic `POST /-/npm/v1/tokens` create-token call on real
> npm **requires the account password in the request body** (it is the non-interactive form
> of `npm token create`, which prompts for your password). The driver authenticates the
> create with the *old token* as Bearer only, which the emulator accepts but real npmjs does
> not. So `npm` stays MOCK-ONLY pending either (a) a self-hosted registry that implements the
> token API faithfully, or (b) adding password-in-body support to the create call. This is
> exactly the kind of contract gap a live-POC attempt is meant to surface.

Promoting the rest to LIVE-VM only requires standing up the real service (a self-hosted
GitLab CE / a real Cloudflare token / a throwaway GitHub repo) and re-running the same
driver against it — no driver code changes. (`k8s` and `mongo` have already made this jump;
see the LIVE-VM table above.)
