package rotate

// Proof tracking — DATA, deliberately kept OUT of the driver code.
//
// Every Rotator in this package contains ONLY real rotation code: it talks to a
// real service (HTTP API, DB client, SSH, local files). None of them contain
// simulation branches or test awareness — the only thing a test injects is an
// endpoint/HTTPClient, which the real deployment also configures.
//
// What differs between drivers is HOW their real-cutover path has been *validated*.
// That validation status is data, not behavior, so it lives here in one table
// rather than as prose scattered through (and easily confused with) the drivers.
// docs/ROTATION-PROOFS.md is the human-facing mirror of this same data; `incredigo
// rotate` surfaces it so a mock-only driver can never be mistaken for a live one.

// ProofLevel records how a driver's real-cutover behaviour has been validated.
type ProofLevel int

// Ordered lowest→highest: a higher level is a strictly stronger cutover proof.
// The execute-time gate (see execute.go) compares against ProofLiveVM.
const (
	// ProofUnproven: no cutover proof recorded (e.g. the dry-run noop helper).
	ProofUnproven ProofLevel = iota
	// ProofMockOnly: cutover proven only against an emulator — our own httptest /
	// in-process SSH server, OR a third-party mock (e.g. moto for AWS). NOT proven
	// against the real target service.
	ProofMockOnly
	// ProofLiveVM: cutover proven against the REAL target software running in the
	// sandbox VM (real PostgreSQL/MariaDB/Redis/wireguard-tools/Gitea/local files).
	ProofLiveVM
	// ProofLiveReal: cutover proven against a REAL, host-owned credential at the
	// real provider (not the VM, not an emulator) — the highest level, recorded
	// only after an authorized per-credential rotation on the safe-candidate ladder
	// (ROADMAP M2). No driver carries this yet; promotions land here as data.
	ProofLiveReal
)

// MinExecuteProof is the minimum proof level a driver must carry to run under
// `rotate --execute` WITHOUT the explicit --allow-mock-proven opt-in. Anything
// below this (MOCK-ONLY, UNPROVEN) is gated off by default so a driver never
// proven against real target software cannot touch a real credential unattended.
const MinExecuteProof = ProofLiveVM

// String renders the level as the token shown in the CLI and the manifest.
func (p ProofLevel) String() string {
	switch p {
	case ProofLiveReal:
		return "LIVE-REAL"
	case ProofLiveVM:
		return "LIVE-VM"
	case ProofMockOnly:
		return "MOCK-ONLY"
	default:
		return "UNPROVEN"
	}
}

// proofLevels maps a driver's Name() to how its real-cutover path was validated.
// This is the single source of truth; keep docs/ROTATION-PROOFS.md in sync.
//
// IMPORTANT honesty note: a driver running in the VM is NOT automatically LIVE-VM.
// AWS ran in the VM but only against moto (a mock AWS), so it is MOCK-ONLY. LIVE-VM
// means the real target software validated the cutover.
var proofLevels = map[string]ProofLevel{
	// proven against a REAL, host-owned credential at the real provider (safe-candidate
	// ladder, ROADMAP M2 — the highest level):
	"gitea": ProofLiveReal, // real Gitea PAT on gitea.example.com, create→verify→store→revoke
	//                         end-to-end against a purpose-made throwaway token (lab-rung3-gitea-real.sh, 2026-07-19)

	// proven against the real target software in the sandbox VM:
	"postgres":  ProofLiveVM, // real PostgreSQL  (lab-provision-pg.sh)
	"mysql":     ProofLiveVM, // real MariaDB     (lab-provision-dbclones.sh)
	"redis":     ProofLiveVM, // real redis-server(lab-provision-dbclones.sh)
	"wireguard": ProofLiveVM, // real kernel WireGuard (wireguard-tools) in a disposable,
	//                          rootless-UNprivileged podman container (--cap-add NET_ADMIN
	//                          only, own netns): wg0 interface-key rotation + wg1 peer
	//                          create-new->verify->revoke-old, independently proven by a real
	//                          WireGuard handshake from a throwaway probe iface — new key
	//                          handshakes, old key rejected (lab/podman-proof.sh wireguard,
	//                          2026-09-22; also lab-provision-wg.sh on host wg)
	"appsecret": ProofLiveVM, // real local config files, in-place literal-value cutover
	//                          (lab/podman-proof.sh appsecret — no-container temp-dir
	//                          variant, grep-verified new-present/old-absent, 2026-09-22;
	//                          also lab-provision-appsec.sh)
	"mongo":     ProofLiveVM, // real mongod 8.0  (lab-provision-mongo.sh)
	"k8s":       ProofLiveVM, // real k3s kube-apiserver + token controller in a disposable,
	//                          rootless-UNprivileged podman container (--disable-agent): legacy
	//                          SA-token Secret create->verify->revoke, curl-verified new-200 /
	//                          old-401 after the ~10s auth-cache (lab/podman-proof.sh k8s,
	//                          2026-09-22; also lab-provision-k8s.sh on host k3s)
	"ssh":       ProofLiveVM, // real OpenSSH sshd in a disposable podman container,
	//                          live authorized_keys cutover (lab/podman-proof.sh sshkey,
	//                          2026-09-21). NOTE the driver's Name() is "ssh"; the prior
	//                          "sshkey" key here never matched it (so it read UNPROVEN).

	// proven only against an emulator / mock:
	"aws":        ProofMockOnly, // moto mock AWS in VM; real AWS never hit
	"openwrt":    ProofMockOnly, // in-process SSH server; live QEMU deferred
	"mullvad":    ProofMockOnly, // httptest emulator; needs a paid account
	"cloudflare": ProofMockOnly, // httptest emulator; no self-host
	"ghactions":  ProofMockOnly, // httptest emulator; no self-host
	"gitlab":     ProofMockOnly, // httptest emulator; GitLab CE too heavy for the VM
	"npm":        ProofMockOnly, // httptest emulator; real registry never hit
	"gcp":        ProofMockOnly, // httptest emulator (real RS256 JWT signing); no self-host
	"twilio":     ProofMockOnly, // httptest emulator; no self-host
	"flyio":      ProofMockOnly, // httptest GraphQL emulator; no self-host
	"resend":     ProofMockOnly, // httptest emulator; no self-host (real key needs a paid-ish account)
	"vercel":     ProofMockOnly, // httptest emulator; no self-host
	"sendgrid":   ProofMockOnly, // httptest emulator; no self-host
}

// ProofLevelOf returns the recorded proof level for a driver name. Unknown or
// proofless drivers (e.g. the noop dry-run helper) report ProofUnproven.
func ProofLevelOf(name string) ProofLevel { return proofLevels[name] }
