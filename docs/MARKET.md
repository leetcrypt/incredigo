# incredigo — Market Analysis & Positioning (2026-06-16)

Research into the credential/secret **rotation** market: who sells it, who buys it, where
the white space is, and who incredigo should be built for. Sourced web research (2025–2026);
treat market-size figures as analyst-dependent and the academic adoption numbers as
directional (see Caveats).

---

## TL;DR

- The **money** is in enterprise **PAM** (~$4.3–5.6B, ~22% CAGR) and **machine-identity**
  rotation — and it is consolidating fast: **CyberArk → Palo Alto Networks (~$25B, Jul 2025)**,
  **HashiCorp Vault → IBM ($6.4B, Feb 2025)**. That is not a fight a local-first CLI wins.
- **Three credible white-space wedges incredigo already targets:**
  1. **Local-file secret discovery + rotation** for solo devs / small teams (sprawl is
     exploding: **+34% YoY**, secrets appear in **~8 places per machine**). Incumbents assume
     you've *already* migrated into their hub — nobody owns "find the mess on this laptop, then
     rotate it." → incredigo **Mode B**.
  2. **Local-first / RAM-only / no-cloud / no-server.** OpenBao/Infisical/Bitwarden prove the
     no-cloud demand, but every one is a **server/daemon**. A **single RAM-only binary** is
     genuinely differentiated.
  3. **The manual/browser "long tail"** of accounts with no rotation API. Every incumbent —
     enterprise PAM *and* consumer password managers — explicitly refuses this. The one serious
     consumer attempt (**Dashlane**) **publicly gave up** as "too brittle." → incredigo's
     **guided worklist + change-URL** layer.
- **RFC 8615 `.well-known/change-password` is a thin primitive** (~12% top-site adoption, often
  unhelpful redirects). It confirms "auto-change everything" is unrealistic and validates
  incredigo's split: **rotate what's automatable, guide the human through the rest.**

---

## 1. Vendors — who sells rotation, and to whom

### Enterprise secrets platforms

| Vendor | Rotation story | Pricing | Typical client |
|---|---|---|---|
| **HashiCorp Vault** (now **IBM**, $6.4B, closed Feb 27 2025) | Core = **dynamic short-lived secrets** + static rotation. Moved to **BSL** license (2023) → OpenBao fork. **HCP Vault Secrets SaaS sunset** (EOS Jun 30 2025, EOL Jul 1 2026). | Community Edition free (self-host); HCP Vault Dedicated ~$1.58/hr | Large enterprise, platform/DevOps |
| **CyberArk** (incl. **Conjur**) — **being acquired by Palo Alto Networks (~$25B, announced Jul 30 2025)** | PAM market leader; automated rotation + deep audit. Conjur = machine/DevOps secrets. | Conjur OSS free; enterprise ~$1,000–1,500 / identity / yr | Large/regulated enterprise |
| **Akeyless** | Vaultless SaaS, JIT access + automated rotation ("Distributed Fragments Cryptography") | Custom / contact sales | Mid-large enterprise (**78% of revenue from public corps**, 2 Fortune-5) |
| **Doppler** | Fully automated rotation, broad integrations (AWS/GCP/CI/KMS) | From **$3/user/mo** | Dev/DevOps teams, startup→midmarket |
| **Infisical** (OSS, MIT) | Rotation for Postgres/MySQL/AWS IAM; **flagged for limited retry/failure guidance** | Cloud from $8/user/mo; self-host free | Developers, OSS-leaning, self-host shops |
| **Phase** | Automated rotation + keeps deployments in sync; cloud or self-host | — | Dev/DevOps, compliance-driven |

### Cloud-native (rotation = "you write the Lambda/Function")

| Vendor | Rotation story | Pricing |
|---|---|---|
| **AWS Secrets Manager** | Native rotation for **RDS/Redshift/DocumentDB only**; others need custom Lambda. re:Invent 2025: "zero-touch rotation" for some 3rd-party secrets. | $0.40/secret/mo + $0.05/10k calls |
| **Azure Key Vault** | Microsoft-centric; FIPS/gov favored | $0.03/10k ops |
| **GCP Secret Manager** | Rotation = schedule → Pub/Sub → **Cloud Function you author** | $0.06/secret version/mo |

### PAM specialists

- **Delinea** — PAM + password rotation, **mid-market** (fast deploy, low TCO); 2024 Gartner MQ Leader.
- **BeyondTrust** — PAM + credential rotation, **enterprise**; Gartner MQ Leader ×6, 2025 Forrester Wave Leader (PIM).
- **Teleport** (w/ StrongDM, HashiCorp Boundary) — **certificate/ephemeral-access**, cloud-native/DevOps; ephemeral certs reduce the *need* to rotate long-lived secrets.

### Password managers w/ rotation crossover

- **1Password** — Business $7.99/user/mo; Secrets Automation via self-hosted Connect Server.
- **Bitwarden** — OSS, client-side crypto, self-hostable; Secrets Manager for devs; business from $4/user/mo; $100M Series B (2022).
- **Keeper** — KeeperPAM: automated rotation + session recording + discovery; business from $6/user/mo.

**Pattern:** every vendor rotates **what has an API** (databases, cloud IAM, AD) and assumes
secrets are **already centralized in their store**. None of them owns *discovery of sprawl on a
local machine* or *the no-API long tail*.

---

## 2. PAM market — size & leaders

- **Size 2025→2026:** Mordor **$4.25B → $5.17B**; Fortune Business Insights **$4.51B → $5.58B**.
- **Growth:** Mordor → **$13.83B by 2031 (~21.7% CAGR)**; Precedence → up to ~$30B by 2034 (~23.8%).
- **Leaders:** CyberArk, BeyondTrust, Delinea, One Identity, ARCON, Wallix, ManageEngine, Okta.
- **Why rotation matters here:** automated rotation/vaulting is a **core PAM primitive**, now
  driven by **machine identities outnumbering humans ~40:1**.

**Implication for incredigo:** do not compete in PAM. Be the tool that serves the people PAM
is too heavy/expensive/cloud-bound to serve.

---

## 3. Consumer auto-password-change — a graveyard

- **Dashlane** removed its automatic Password Changer in **early 2022** — officially "an
  extremely complex feature that was prone to breaking." (Also killed its free plan Sept 16 2025.)
  This is the canonical cautionary tale.
- **Chrome / Google Password Manager** — announced **Automated Password Change** at I/O 2025;
  navigates the site and fills the change form **with per-change user approval** (no silent
  action). Rollout late 2025, **limited English-language cooperative sites only**.
- **Apple** — no general web auto-changer; leans into **passkeys** + a change-password URL quirk.
- **Academic verdict (arxiv 2511.10111, Nov 2025, 111 Tranco sites):** *"no popular third-party
  or browser-embedded password manager supports automated website password updates."* Sites use
  **diverse, confusing** flows, often **break autocomplete**, and some **deliberately block
  automation**. The industry's real answer is **passkeys**, not auto-change.

**Implication:** fully-automatic browser rotation is a known tar pit. incredigo's **guided,
human-in-the-loop worklist** (rotate what's scriptable; hand the human a ranked, linked
checklist for the rest; never bypass MFA/CAPTCHA) is the *pragmatic* shape that survives where
"automate everything" died. This matches Hard Rule #5 (self-owned only) and #6 (dry-run default).

---

## 4. RFC 8615 `.well-known/change-password`

- W3C "A Well-Known URL for Changing Passwords" lets tools deep-link to a site's change page.
- **Adoption (Tranco top 200, 2025):** ~**12.2%** support the W3C path; ~**33.8%** support
  Apple's competing URL-quirk. Adopters incl. Google, GitHub, WordPress, Facebook, X. **Most
  redirects land on a generic security page, not the change form.**
- Consumed by Chrome and Safari; Bitwarden has open community requests.

**Implication:** good enough to power incredigo's **offline change-URL generation** (already
built: curated table + RFC 8615 well-known + host fallback), but thin enough that it can't be
the whole answer — reinforcing the rotate-vs-guide split.

---

## 5. Underserved segments (the white space)

**A. Solo devs & small teams with local secret sprawl.**
- **GitGuardian State of Secrets Sprawl 2026:** **29M new hardcoded secrets in 2025, +34% YoY**;
  each live secret appeared in **~8 locations on the same machine** (.env, shell history, IDE
  configs, cached tokens, build artifacts); **59% of compromised machines were CI/CD runners**.
- **Snyk:** ~28M credentials leaked on GitHub in 2025.
- No major vendor owns **discover-then-rotate of sprawl already on the box** (.aws/.netrc/ssh/
  docker/kube) — they start *after* migration into their hub. → **incredigo Mode B.**

**B. Privacy-conscious / no-cloud.**
- HashiCorp's BSL relicense spawned **OpenBao** (LF/MPL-2.0 fork of Vault 1.14, joined OpenSSF
  Jun 2025). Infisical (MIT) and Bitwarden Secrets Manager also serve no-cloud.
- **But all are servers/daemons.** A **local-first, RAM-only, single binary** with no
  infrastructure is unoccupied ground. → **incredigo's core architecture.**

**C. The no-API "long tail."**
- *"Password managers won't rotate your bank login, email recovery keys, or IoT device admin
  panels unless you manually initiate each one."* Enterprise PAM rotates what has an API; the
  manual long tail is **explicitly out of scope**; the one consumer attempt (Dashlane) failed.
  → **incredigo's guided worklist.**

**D. OSS rotation specifically (not storage).** Even among OSS tools rotation is the weak spot
(Infisical retry/failure gaps; GCP "write your own function"; AWS native only first-party DBs).

---

## 6. Who incredigo should be tailored for

**Primary persona — "the security-literate solo dev / small-team lead."**
- Has secrets scattered across `.env`, `~/.aws`, `~/.netrc`, `~/.ssh`, `docker-compose.yml`,
  `k8s/*.yaml`, plus a gopass store.
- Distrusts (or can't afford / can't legally use) a SaaS secrets hub. Wants self-custody.
- Comfortable on the CLI; wants **headless automation in CI** *and* an interactive TUI.
- Job-to-be-done: *"Find every credential I have, back them up safely, rotate the ones a script
  can rotate, and give me a clean checklist for the rest — without anything ever leaving my
  machine."*

**Secondary personas:**
- **Privacy/sovereignty buyers** (journalists, activists, infosec consultants, regulated EU
  shops who can't ship secrets to US clouds) — value RAM-only / no-cloud + the PGP-as-root-of-trust model.
- **Homelab / self-hosted operators** — rotate Postgres/Redis/SSH/router/NAS creds with one tool.
- **Incident responders / pentest cleanup** — after a leak, *discover + mass-rotate + audit* on a
  host quickly. (Aligns with the GitGuardian "8 copies per secret" reality.)

**Explicit non-targets (for now):** Fortune-500 PAM, machine-identity-at-scale, compliance-cert
checkboxes (SOC2/FedRAMP managed service). Those are the incumbents' moats.

**Positioning line:** *"The local-first credential rotator: discover the secrets sprawled across
your machine, back them up, rotate what's automatable, and get a guided worklist for the rest —
RAM-only, no cloud, no server, one binary."*

---

## 7. Extension vectors (ranked by leverage vs. white space)

Tied to the gaps above, not feature-for-feature parity with PAM.

1. **Breadth of self-hostable rotation drivers** (the credibility multiplier). After postgres:
   **MySQL/MariaDB, Redis, SSH `authorized_keys`, Gitea/GitHub/GitLab PATs, AWS IAM access keys
   (moto-tested), HTTP basic-auth / reverse-proxy htpasswd, S3-compatible keys.** Each is a
   self-contained `Rotator` — exactly the homelab/solo-dev surface incumbents skip.
2. **Consumer-grade reset-flow engine** (the highest-leverage *category* move): a generalized,
   declarative **"email/OTP reset-flow" runner** for the long tail — site recipe = change-URL +
   form selectors + (human-supplied) OTP step. Human-in-the-loop, never bypasses MFA. This is the
   space Dashlane vacated and Chrome only half-fills.
3. **"Eliminate, don't rotate" recommender.** Where a credential *can* be replaced by something
   that needs no rotation (passkeys, OIDC/SSO, short-lived certs, SSH certificates, cloud
   workload identity), **recommend the elimination** instead of rotating. This rides the
   industry's actual direction (passkeys) and is a differentiator no rotator markets.
4. **Consumer propagation / blast-radius closeout.** After rotating a secret, update the places
   that consume it (.env, CI variables, k8s secrets) — the read-only `blast` map already finds
   them; the next step is *guided* (not silent) propagation.
5. **GitOps / IaC rotation** — rotate a secret and open a PR that updates the encrypted value
   (SOPS/age) in the repo. Serves the "59% of leaks are in CI/CD runners" reality.
6. **Standards plumbing** — RFC 7009 token revocation, RFC 8693 token exchange, SCIM for
   user-store rotation, ACME for TLS cert rotation. Each widens automatable coverage.

**Recommended next two:** finish the **driver ladder** (#1 — proves the core works broadly and is
low-risk) and prototype the **reset-flow engine** (#2 — the actual unoccupied market). #3
(eliminate-don't-rotate) is the cheapest *positioning* win and worth a small advisory module.

---

## Caveats on data quality

- **PAM market sizes differ materially by analyst** (Mordor vs Fortune vs Precedence) — cite the
  firm with each figure.
- The **`.well-known` adoption (12.2% / 33.8%)** and **111-site automation study** come from
  **arxiv 2511.10111**; some per-metric numbers in the HTML preprint were redacted — treat the
  fine-grained automation percentages as **directional** and verify against the final PDF before
  quoting precisely.
- **Doppler's funding/valuation** was not found in public trackers; needs a dedicated dig if required.
- Acquisition values/dates (CyberArk/PANW, HashiCorp/IBM) are as announced in 2025; confirm close
  status before citing as completed.

## Sources

- IBM/HashiCorp: https://www.hashicorp.com/en/blog/hashicorp-officially-joins-the-ibm-family · https://siliconangle.com/2025/02/27/ibm-completes-6-4b-hashicorp-acquisition-following-regulatory-approvals/
- Vault pricing/license: https://infisical.com/blog/hashicorp-vault-pricing · https://envmanager.com/blog/hashicorp-vault-pricing
- CyberArk/PANW: https://www.paloaltonetworks.com/company/press/2025/palo-alto-networks-announces-agreement-to-acquire-cyberark--the-identity-security-leader · Conjur pricing: https://infisical.com/blog/cyberark-conjur-pricing
- Akeyless: https://www.akeyless.io/secrets-management/ · https://www.prnewswire.com/news-releases/akeyless-raises-65m-to-provide-secrets-management-as-a-service-for-devops-and-multi-cloud-environments-301679894.html
- Doppler/Infisical: https://www.doppler.com/blog/infisical-doppler-secrets-management-comparison-2025 · https://securityboulevard.com/2025/06/infisical-vs-doppler-secrets-management-comparison-for-2025/
- AWS/Azure/GCP: https://www.pulumi.com/blog/secrets-management-tools-guide/ · https://www.techleague.io/blog/security/aws-secrets-manager-vs-azure-key-vault-vs-gcp-secret-manager-2026/ · https://dev.to/kazuya_dev/aws-reinvent-2025-zero-touch-secret-rotation-now-available-for-your-third-party-secrets-sec230-fne
- PAM market: https://www.mordorintelligence.com/industry-reports/privileged-access-management-pam-market · https://www.fortunebusinessinsights.com/privileged-access-management-market-112360 · https://www.precedenceresearch.com/privileged-access-management-market
- PAM leaders: https://techcloudpro.com/blog/cyberark-vs-delinea-vs-beyondtrust-pam-comparison/ · https://www.beyondtrust.com/resources/competitor-comparisons/delinea-alternative
- Consumer auto-change: https://www.cloudwards.net/dashlane-review/ · https://thehackernews.com/2025/05/google-chrome-can-now-auto-change.html · https://developer.chrome.com/docs/identity/automated-password-change
- Academic study: https://arxiv.org/abs/2511.10111 (HTML: https://arxiv.org/html/2511.10111v2)
- RFC 8615 / change-password URL: https://www.rfc-editor.org/rfc/rfc8615.html · https://www.w3.org/TR/change-password-url/ · https://web.dev/articles/change-password-url
- Secrets sprawl: https://thehackernews.com/2026/03/the-state-of-secrets-sprawl-2026-9.html · https://snyk.io/articles/state-of-secrets/ · https://www.doppler.com/blog/what-is-secrets-sprawl-and-how-to-prevent-it-in-2025
- OSS/no-cloud: https://openssf.org/blog/2025/06/17/openbao-joins-the-openssf-to-advance-secure-secrets-management-in-open-source/ · https://infisical.com/blog/open-source-secrets-management-devops
- Long tail: https://lifetips.alibaba.com/tech-efficiency/automated-password-rotation-for-personal-accounts
