# incredigo — Vision

## Catch vibe-coding security disasters before they happen.

You build an app in a weekend with Claude, OpenClaw, Hermes, Cursor. By Sunday night you've
accumulated three dozen credentials — an Anthropic key, a Stripe `sk_live`, a `DATABASE_URL`, a
GitHub PAT, an AWS access key, a Supabase `service_role` — each **generated once, pasted into a
`.env`, and forgotten.** Maybe it got committed. Maybe it's in your shell history. Maybe it's in
eight places. You'll "deal with security later."

**incredigo is the safety net for later-that-never-comes.** It finds every credential sprawled
across your machine, locks them in a RAM-only vault, takes a verified backup, **rotates the ones
a script can rotate**, and hands you a **guided, ranked checklist** for the ones that need a human
— all local-first: no cloud, no server, no SaaS, one binary. The forgotten `sk_live` gets rotated
*before* it becomes a breach disclosure.

> **One line:** *The local-first credential rotator that saves fast-moving AI-assisted builders
> from the security debt they're accumulating in real time.*

---

## The problem

The "vibe coder" — the AI-assisted builder who ships fast and worries about security after the
fact — is the fastest-growing developer cohort, and the one accruing credential risk fastest:

- **Secrets sprawl is exploding.** GitGuardian's *State of Secrets Sprawl 2026*: **29M new
  hardcoded secrets in 2025, +34% YoY**, with each live secret appearing in **~8 locations on
  the same machine** (`.env`, shell history, IDE configs, cached tokens, build artifacts).
- **Generate-once, rotate-never.** AI codegen mints keys on demand and pastes them inline. They
  are rarely scoped, rarely rotated, often duplicated, and frequently committed.
- **No tool serves the cleanup.** Enterprise PAM/secrets platforms (CyberArk, Vault, Doppler)
  rotate *what already lives in their hub*; they don't go discover the mess on your laptop. The
  one consumer attempt at automating the long tail (Dashlane) gave up as "too brittle."

That gap — **discover the sprawl on this machine, then rotate it, self-custody, no cloud** — is
incredigo's reason to exist. (Full competitive analysis: [`docs/MARKET.md`](docs/MARKET.md).)

---

## Who this is for

**Primary — the security-literate-enough vibe coder.** OpenClaw / Hermes / Claude-Code / Cursor
builders who move fast and accumulate credentials across `.env`, `~/.aws`, `~/.netrc`, `~/.ssh`,
`~/.docker`, `~/.kube`, `docker-compose.yml`, plus a gopass store. They distrust (or can't legally
use) a SaaS secret hub, live on the CLI, and want **headless rotation in CI *and* an interactive
TUI**. Job-to-be-done: *"Find every credential I have, back them up, rotate what's automatable,
and give me a clean checklist for the rest — without anything leaving my machine."*

**Secondary — the non-technical password reuser.** People who never change their passwords, reuse
weak ones, and let the browser remember everything. The *same engine* (discover → back up →
rotate / guide), with a friendlier face: point it at the browser's saved-login store, and it
produces a ranked, deduplicated worklist with a direct **change-password link** per site — never a
plaintext password dump, never bypassing MFA. The bridge from "developer tool" to "anyone with a
password problem."

---

## The 20 credentials a vibe coder accumulates

The target surface. Each maps to how incredigo handles it: **[DB]** in-place database rotation
driver · **[API]** provider-API rotation driver · **[LOCAL]** self-generated secret incredigo can
regenerate + propagate · **[GUIDE]** no rotation API → guided worklist + change-URL (human in the
loop, never bypassing MFA/CAPTCHA).

| # | Credential | Where it lives | Why it bites vibe coders | Handling |
|---|---|---|---|---|
| 1 | **LLM API keys** (Anthropic, OpenAI, Gemini, Groq, OpenRouter, Mistral, HuggingFace) | `.env`, shell rc, `~/.config` | The defining vibe-coder key; minted constantly, pasted inline, billed by usage | GUIDE → API |
| 2 | **AI infra keys** (Pinecone/Qdrant/Weaviate, Replicate/Fal/ElevenLabs/Stability) | `.env` | Spun up per experiment, never cleaned up | GUIDE |
| 3 | **MCP / agent-gateway tokens** (OpenClaw/Hermes/Claude MCP server configs) | `~/.claude.json`, MCP config files | Grant broad tool/host access; rarely scoped or rotated | GUIDE / LOCAL |
| 4 | **AWS access keys** | `~/.aws/credentials`, `.env` | Long-lived, over-privileged, leak to GitHub constantly | **API (IAM)** |
| 5 | **GCP service-account JSON** | `~/.config/gcloud`, `.env` | Whole-key files copied around | API |
| 6 | **Cloudflare API token / global key** | `.env`, `~/.cloudflared` | Global key = account-wide; pasted into scripts | GUIDE / API |
| 7 | **Deploy-platform tokens** (Vercel, Netlify, Railway, Render, Fly.io) | `.env`, `~/.vercel` | One token = full deploy control | GUIDE / API |
| 8 | **Postgres DSN** | `.env` `DATABASE_URL`, `docker-compose.yml` | Default/weak passwords, reused across envs | **DB ✅** |
| 9 | **MySQL / MariaDB DSN** | same | same | DB |
| 10 | **Redis URL / password** | `.env`, compose | Often no password at all | DB |
| 11 | **Managed-DB keys** (Supabase `service_role`, Neon, PlanetScale, Mongo Atlas) | `.env` | `service_role` bypasses row-level security — catastrophic if leaked | GUIDE / API |
| 12 | **Git platform PATs** (GitHub, GitLab, Gitea, Bitbucket) | `~/.netrc`, `~/.config/gh`, git credential store | Broad-scope `repo` tokens; rarely expire | **API** |
| 13 | **Package-registry tokens** (npm `~/.npmrc`, PyPI, crates.io) | home configs | Publish rights → supply-chain risk | GUIDE |
| 14 | **Container-registry creds** (Docker Hub, GHCR) | `~/.docker/config.json` | Base64 "auth" mistaken for encryption | GUIDE |
| 15 | **CI/CD secrets** (GitHub Actions secrets, workflow env) | repo settings, `.github/workflows` | 59% of leaked-secret machines are CI runners | API / GUIDE |
| 16 | **SSH private keys / deploy keys** | `~/.ssh/id_*` | Unencrypted keys, shared deploy keys, never rotated | **driver: regen + `authorized_keys`** |
| 17 | **Kubeconfig tokens / client certs** | `~/.kube/config` | Cluster-admin creds in a dotfile | GUIDE |
| 18 | **Payment / auth / messaging keys** (Stripe `sk_live`, Clerk/Auth0/Firebase, Twilio, SendGrid/Resend, Slack/Discord, webhook signing secrets) | `.env` | Money + identity + spam blast radius | GUIDE / API |
| 19 | **App signing / session secrets** (Django `SECRET_KEY`, NextAuth secret, Rails `master.key`, JWT secrets) | `.env`, config | Self-generated randoms — easy to rotate, easy to forget | **LOCAL: regenerate + propagate** |
| 20 | **Browser-saved passwords + manager exports** | Chrome/Firefox login DB, CSV | Reused, weak, never changed (the secondary market) | **GUIDE: worklist + change-URL** |

This list is the **driver-ladder roadmap** and the **scanner roadmap** at once: every `[DB]`/`[API]`/
`[LOCAL]` row is a future one-file `Rotator`; every row is a discovery surface.

### Secondary-persona extension: network credentials (VPN + router)

The 20 above are the **primary (vibe-coder)** surface and remain the centre of gravity. Two
adjacent credential classes serve the **secondary persona** ("anyone with a password problem")
and are deliberately added — they reuse the same safe spine, not a new product:

- **VPN keys/credentials.** *Self-hosted WireGuard* rotates exactly like SSH (`[LOCAL]`:
  regenerate the keypair in RAM, propagate the new public key to the peer, verify the handshake,
  drop the old). *Mullvad* is the one mainstream consumer VPN with a real device-key rotation API
  (`[API]`, account-number auth). Commercial account passwords (Nord/Express/Proton) have no
  rotation API → `[GUIDE]`.
- **Router admin password.** *OpenWrt* (and other SSH/`ubus`-exposing prosumer firmware) is
  programmatically rotatable (`[API/LOCAL]` via `uci`/`ubus`). Generic consumer routers
  (TP-Link/Netgear/Asus web-UI) have no stable API → `[GUIDE]` / browser long-tail.

These stay within the non-goals below (self-owned only, never an attack tool, never bypass
MFA/CAPTCHA); they do **not** pull incredigo toward enterprise network/PAM management.

---

## How incredigo answers it

The same safe spine for every credential, automatable or not:

1. **Discover** — scan the machine's credential surface (`.env`, `~/.aws`, `~/.netrc`, `~/.ssh`,
   `~/.docker`, `~/.kube`, git, `--path`, browser export).
2. **Custody** — load secrets into a RAM-only memguard vault (mlock/DONTDUMP); plaintext never
   hits disk.
3. **Backup (mandatory)** — a sealed, **verified** snapshot before anything changes. No backup,
   no rotation. Non-negotiable.
4. **Rotate** — drivers change the automatable ones in place (verify-new-before-revoke-old), and
   close the blast radius by guiding consumer updates (`.env`, CI vars, k8s).
5. **Guide** — for the no-API long tail, emit a ranked, deduplicated worklist with per-site
   change-password links; the human acts, MFA/CAPTCHA are never bypassed.

Headless for CI (`$INCREDIGO_PASSPHRASE`, no TTY) or interactive via the TUI. The PGP passphrase
is the single root of trust — back up the key, use a strong passphrase.

---

## Non-goals

- **Not enterprise PAM.** No fight with CyberArk/Vault/Delinea over machine-identity-at-scale,
  compliance certifications, or a managed cloud service. (See `docs/MARKET.md`.)
- **Not a SaaS secret hub.** No server, no daemon, no telemetry, nothing leaves the machine.
- **Not an attack tool.** Self-owned accounts only, with the owner's authorization. Never resembles
  credential stuffing or account takeover; never bypasses MFA/CAPTCHA — it hands off to the human.
- **Not "auto-change everything."** Fully-silent browser rotation is a known tar pit (Dashlane).
  incredigo rotates what's scriptable and *guides* the rest.

See [`DESIGN.md`](DESIGN.md) for architecture + threat model and [`docs/MARKET.md`](docs/MARKET.md)
for the competitive landscape.
