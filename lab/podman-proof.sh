#!/usr/bin/env bash
# podman-proof.sh — prove ONE incredigo rotation driver end-to-end against a
# DISPOSABLE podman container, with zero risk to the host.
#
# This is the per-driver step of the overnight LIVE-VM proof loop. It stands up a
# throwaway service in a `--rm` container, points incredigo at an ISOLATED temp
# HOME + gopass store seeded with ONE throwaway credential, runs the REAL rotation
# spine (backup gate → rotate → verify-new → store → re-read → revoke-old), then
# proves the NEW password authenticates and the OLD password no longer does.
#
# SAFETY SPINE (do not weaken):
#   * ONLY the disposable container's throwaway credential is ever rotated.
#   * HOME/GNUPGHOME/GOPASS_HOMEDIR are all under a fresh mktemp dir, so incredigo
#     CANNOT read the real ~/.password-store, ~/.incredigo, gopass, ~/.ssh, etc.
#   * Isolation is ASSERTED (see verify_isolation) BEFORE execute is ever enabled.
#   * INCREDIGO_ALLOW_EXECUTE=1 is scoped to a 127.0.0.1:<container-port> target.
#   * The container is `--rm`, throwaway-named, and torn down in an EXIT trap.
#
# Usage:  lab/podman-proof.sh [postgres|redis|mysql|mongo|sshkey|appsecret|k8s|wireguard]  (default: postgres)
# Requires: podman, gopass, gpg on PATH; a built incredigo binary (INCREDIGO=..,
#           else it is `go build`-t into a temp dir). No host psql/redis-cli/mysql/
#           mongosh/age needed — the DB client is routed through a client container;
#           age sealing is pure-Go. The `sshkey` driver additionally uses the host
#           `ssh`/`ssh-keygen` (as the INDEPENDENT ground-truth probe) and builds a
#           tiny disposable OpenSSH-server image; incredigo itself dials in-process.
#           The `appsecret` driver needs NO container at all — it rewrites LOCAL config
#           files in place, so the "disposable service" is a throwaway temp dir of
#           config files seeded with ONE throwaway secret; the ground-truth probe is a
#           plain grep of the on-disk files (does the value literally appear?).
#           The `k8s` driver stands up a disposable single-node k3s CONTROL PLANE
#           (`--disable-agent` ⇒ no kubelet ⇒ no cpuset cgroup ⇒ runs rootless AND
#           UNprivileged); incredigo dials the real apiserver in-process. The
#           INDEPENDENT probe is host `curl` against the apiserver (CA-pinned), and
#           the old token's rejection is polled because the apiserver caches a
#           successful auth ~10s (cachedTokenAuthenticator).
#           The `wireguard` driver stands up a disposable rootless container
#           (`--cap-add NET_ADMIN` ONLY — NOT `--privileged`; the capability is
#           confined to the container's OWN network namespace and cannot touch host
#           networking) running the REAL kernel WireGuard via wireguard-tools. Two
#           real wg interfaces (wg0 the local interface whose key we rotate, wg1 the
#           peer that must trust it) live in that netns; incredigo dials `wg` through
#           a shim that runs `podman exec <ctr> wg`, so it can never touch host
#           wireguard. The INDEPENDENT probe drives a real WireGuard handshake from a
#           throwaway probe interface using the candidate private key (a non-zero
#           `wg show <probe> latest-handshakes` == the key cryptographically authed).
set -uo pipefail

DRIVER="${1:-postgres}"
# The rotation driver's registered Name() usually equals the CLI arg, but sshkey's
# driver registers as "ssh" — the proof-manifest row and proof-level lookup key on
# Name(), so the success grep must use ROTNAME, not the CLI arg.
ROTNAME="$DRIVER"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# The REAL home. Rootless podman derives its storage/state from $HOME (XDG_DATA_HOME
# unset here), so EVERY podman op must run against this home — never the isolated one
# — or a container created here would be invisible to teardown. incredigo's isolation
# comes from GNUPGHOME/GOPASS_HOMEDIR + a per-call HOME override, NOT from mutating the
# ambient HOME (see run_incy / the client shim, both below).
REAL_HOME="$HOME"

# ---- per-driver knobs (image + client binary; everything else is shared) ----
# CLIENT_BIN is the exact binary the driver execs from PATH; we shim it to a client
# container so incredigo genuinely connects over TCP to the published loopback port.
case "$DRIVER" in
  postgres)
    IMAGE="${INCY_PG_IMAGE:-docker.io/library/postgres:16-alpine}"
    CLIENT_BIN="psql"
    ;;
  redis)
    IMAGE="${INCY_REDIS_IMAGE:-docker.io/library/redis:7-alpine}"
    CLIENT_BIN="redis-cli"
    ;;
  mysql)
    IMAGE="${INCY_MYSQL_IMAGE:-docker.io/library/mariadb:11}"
    CLIENT_BIN="mysql"   # driver execs `mysql`; the shim routes to the image's `mariadb`
    ;;
  mongo)
    IMAGE="${INCY_MONGO_IMAGE:-docker.io/library/mongo:7}"
    CLIENT_BIN="mongosh" # driver execs `mongosh`; the mongo:7 image ships it
    ;;
  sshkey)
    # Locally-built minimal OpenSSH-server image (built on demand in step 1). The
    # ssh driver dials in-process (golang.org/x/crypto/ssh), so there is NO client
    # shim — the DB-style CLIENT_BIN is unused for this driver.
    IMAGE="${INCY_SSHD_IMAGE:-localhost/incy-sshd-proof:v1}"
    CLIENT_BIN=""
    ;;
  appsecret)
    # No container: the driver rewrites LOCAL config files in a throwaway temp dir.
    # IMAGE/CLIENT_BIN are unused (kept set for uniform logging).
    IMAGE="(none — local config files)"
    CLIENT_BIN=""
    ;;
  k8s)
    # Disposable single-node k3s CONTROL PLANE. `--disable-agent` drops the kubelet
    # (the only component that needs a cpuset cgroup, which is not delegated here), so
    # k3s runs rootless AND unprivileged. The driver dials the apiserver in-process
    # over HTTPS; there is no client shim, so CLIENT_BIN is unused.
    IMAGE="${INCY_K3S_IMAGE:-docker.io/rancher/k3s:v1.31.5-k3s1}"
    CLIENT_BIN=""
    ;;
  wireguard)
    # Locally-built minimal wireguard-tools + iproute2 image (built on demand in
    # step 1). The driver dials `wg` through a shim into a disposable rootless
    # container (--cap-add NET_ADMIN only, NOT privileged); there is no DB client shim.
    IMAGE="${INCY_WG_IMAGE:-localhost/incy-wg-proof:v1}"
    CLIENT_BIN=""
    ;;
  *)
    echo "podman-proof: only 'postgres', 'redis', 'mysql', 'mongo', 'sshkey', 'appsecret', 'k8s' and 'wireguard' are provable by this script today" >&2
    exit 2
    ;;
esac

# ---- throwaway identifiers (nothing real, nothing reused) -------------------
rand()  { head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
PORT="$(( (RANDOM % 20000) + 40000 ))"
OLD_PW="throwaway-$(rand)"
CTR="incy-${DRIVER}-probe-$$"
BINDIR="$(mktemp -d)"        # holds the DB-client shim
ISO_HOME="$(mktemp -d)"      # isolated HOME for incredigo (NOT the real one)
PASS=0; FAIL=0
# Seconds to poll for a revoked credential to actually stop authenticating. 0 == the
# revocation is effective immediately (every DB / file / ssh driver). The k8s branch
# raises this because the kube-apiserver caches a SUCCESSFUL token auth ~10s
# (cachedTokenAuthenticator), so a just-deleted token keeps working until that cache
# entry expires — see the OLD-token check in step 5.
OLD_REVOKE_SETTLE=0
ok()   { echo "  PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
note() { echo; echo "==== $* ===="; }

# ---- teardown trap: always fires, even on error/interrupt -------------------
cleanup() {
  local rc=$?
  podman rm -f "$CTR" >/dev/null 2>&1 || true
  rm -rf "$BINDIR" "$ISO_HOME" 2>/dev/null || true
  return $rc
}
trap cleanup EXIT INT TERM

# ---- 0. build (or reuse) the incredigo binary -------------------------------
# INCREDIGO may be (a) unset, (b) a prebuilt binary to reuse, or (c) a repo/worktree
# root to build from (the loop passes the worktree path). Only an EXECUTABLE regular
# file is reused verbatim; anything else (empty, a directory) is built from source.
INCREDIGO="${INCREDIGO:-}"
if [[ -d "$INCREDIGO" ]]; then
  REPO_ROOT="$(cd "$INCREDIGO" && pwd -P)"   # treat it as the source tree to build
  INCREDIGO=""
fi
if [[ -z "$INCREDIGO" || ! -x "$INCREDIGO" ]]; then
  INCREDIGO="$BINDIR/incredigo"
  ( cd "$REPO_ROOT" && go build -o "$INCREDIGO" ./cmd/incredigo ) || { echo "build failed"; exit 1; }
fi

# ---- 1. disposable service + throwaway credential ---------------------------
# Each branch: (a) starts a `--rm` container on 127.0.0.1:$PORT, (b) waits until
# it answers, (c) seeds ONE throwaway login, and (d) sets SEED_PATH (the gopass
# entry — its 2nd path segment IS the driver Source that routes to the driver) and
# EXPECT_DSN (the exact seeded secret, used by the isolation assert). It also
# defines auth() — an INDEPENDENT ground-truth probe over the client shim — and
# pw_from_dsn() to extract the password from a stored DSN for the final proof.
#
# TARGET_DESC is the human label the isolation assert uses for the rotation target;
# container drivers point at a loopback port, appsecret at a throwaway temp dir.
TARGET_DESC="127.0.0.1:${PORT} (our disposable container)"
if [[ "$DRIVER" == "appsecret" ]]; then
  note "1. disposable throwaway config files (no container — local-file driver)"
else
  note "1. disposable $DRIVER container ($IMAGE) on 127.0.0.1:$PORT"
fi

if [[ "$DRIVER" == "postgres" ]]; then
  podman run --rm -d --name "$CTR" \
    -e POSTGRES_PASSWORD="$OLD_PW" \
    -p "127.0.0.1:${PORT}:5432" "$IMAGE" >/dev/null || { echo "container start failed"; exit 1; }
  for i in $(seq 1 30); do
    podman exec "$CTR" pg_isready -U postgres >/dev/null 2>&1 && break
    sleep 1
  done
  podman exec "$CTR" pg_isready -U postgres >/dev/null 2>&1 && ok "postgres ready" || { bad "postgres never ready"; exit 1; }

  # A non-superuser LOGIN role that owns its own DB — proves a role rotating ITS
  # OWN password (the realistic app-credential case), not a superuser shortcut.
  podman exec -e PGPASSWORD="$OLD_PW" -i "$CTR" \
    psql -v ON_ERROR_STOP=1 -X -w -U postgres -d postgres >/dev/null 2>&1 <<SQL
CREATE ROLE labapp LOGIN PASSWORD '$OLD_PW';
CREATE DATABASE labdb OWNER labapp;
SQL
  [[ $? -eq 0 ]] && ok "labapp role + labdb created" || bad "role/db setup"

  # The driver execs `psql` from PATH. Route it through a throwaway client
  # container on the host network so it genuinely connects over TCP to the
  # published loopback port with args/stdin/PGPASSWORD forwarded verbatim.
  # HOME is forced back to the REAL home so this shim (spawned BY incredigo, which
  # runs under the isolated HOME) uses the SAME podman store as the server container.
  cat > "$BINDIR/psql" <<EOF
#!/usr/bin/env bash
exec env HOME="$REAL_HOME" podman run --rm -i --network=host -e PGPASSWORD "$IMAGE" psql "\$@"
EOF
  chmod +x "$BINDIR/psql"

  # a direct auth probe using the same shim (ground truth, independent of incredigo)
  auth() { # auth <password> ; rc 0 == authenticates
    PGPASSWORD="$1" "$BINDIR/psql" -X -w -h 127.0.0.1 -p "$PORT" -U labapp -d labdb -tAc 'SELECT 1;' >/dev/null 2>&1
  }
  SEED_PATH="imported/postgres/labapp"
  EXPECT_DSN="postgres://labapp:${OLD_PW}@127.0.0.1:${PORT}/labdb"
  SEED_DSN="$EXPECT_DSN"
  pw_from_dsn() { sed -E 's#^postgres://labapp:([^@]*)@.*#\1#'; }

elif [[ "$DRIVER" == "redis" ]]; then
  # Server-wide requirepass, no user/db setup — this is the legacy default-user
  # password that vibe coders actually leak in REDIS_URL. The driver rotates it via
  # `CONFIG SET requirepass <new>` over the OLD (authenticated) connection.
  podman run --rm -d --name "$CTR" \
    -p "127.0.0.1:${PORT}:6379" "$IMAGE" \
    redis-server --requirepass "$OLD_PW" >/dev/null || { echo "container start failed"; exit 1; }
  for i in $(seq 1 30); do
    podman exec -e REDISCLI_AUTH="$OLD_PW" "$CTR" redis-cli ping 2>/dev/null | grep -q PONG && break
    sleep 1
  done
  podman exec -e REDISCLI_AUTH="$OLD_PW" "$CTR" redis-cli ping 2>/dev/null | grep -q PONG \
    && ok "redis ready (requirepass set)" || { bad "redis never ready"; exit 1; }

  # The driver execs `redis-cli` from PATH. Route it through a throwaway client
  # container on the host network so it genuinely connects over TCP to the
  # published loopback port with args/stdin/REDISCLI_AUTH forwarded verbatim.
  # HOME is forced back to the REAL home so this shim (spawned BY incredigo, which
  # runs under the isolated HOME) uses the SAME podman store as the server container.
  cat > "$BINDIR/redis-cli" <<EOF
#!/usr/bin/env bash
exec env HOME="$REAL_HOME" podman run --rm -i --network=host -e REDISCLI_AUTH "$IMAGE" redis-cli "\$@"
EOF
  chmod +x "$BINDIR/redis-cli"

  # a direct auth probe using the same shim (ground truth, independent of incredigo)
  auth() { # auth <password> ; rc 0 == authenticates (PING -> PONG only when authed)
    REDISCLI_AUTH="$1" "$BINDIR/redis-cli" -h 127.0.0.1 -p "$PORT" ping 2>/dev/null | grep -q PONG
  }
  # legacy single requirepass => no username in the URL (default user).
  SEED_PATH="imported/redis/labredis"
  EXPECT_DSN="redis://:${OLD_PW}@127.0.0.1:${PORT}"
  SEED_DSN="$EXPECT_DSN"
  pw_from_dsn() { sed -E 's#^redis://:([^@]*)@.*#\1#'; }

elif [[ "$DRIVER" == "mysql" ]]; then
  # MariaDB 11. Root password seeds the server; a NON-admin app user (labapp)
  # scoped to ONE schema (GRANT ALL ON labdb.*) is the throwaway credential we
  # rotate. That user cannot ALTER USER on MariaDB, so the driver falls through
  # to SET PASSWORD self-service — exactly the vibe-coder persona.
  podman run --rm -d --name "$CTR" \
    -e MARIADB_ROOT_PASSWORD="$OLD_PW" \
    -p "127.0.0.1:${PORT}:3306" "$IMAGE" >/dev/null || { echo "container start failed"; exit 1; }
  for i in $(seq 1 40); do
    podman exec -e MYSQL_PWD="$OLD_PW" "$CTR" mariadb -uroot -e 'SELECT 1;' >/dev/null 2>&1 && break
    sleep 1
  done
  podman exec -e MYSQL_PWD="$OLD_PW" "$CTR" mariadb -uroot -e 'SELECT 1;' >/dev/null 2>&1 \
    && ok "mariadb ready" || { bad "mariadb never ready"; exit 1; }

  # host '%' because rootless podman port-publishing presents the client from the
  # container gateway, not loopback — the grant tuple must not pin to 127.0.0.1.
  podman exec -e MYSQL_PWD="$OLD_PW" -i "$CTR" mariadb -uroot >/dev/null 2>&1 <<SQL
CREATE DATABASE labdb;
CREATE USER 'labapp'@'%' IDENTIFIED BY '$OLD_PW';
GRANT ALL ON labdb.* TO 'labapp'@'%';
SQL
  [[ $? -eq 0 ]] && ok "labapp user + labdb created" || bad "user/db setup"

  # The driver execs `mysql` from PATH. mariadb:11 ships no `mysql` symlink, so the
  # shim invokes the image's `mariadb` client instead — over the host network so it
  # genuinely connects over TCP to the published loopback port with
  # args/stdin/MYSQL_PWD forwarded verbatim. HOME is forced back to the REAL home so
  # this shim (spawned BY incredigo, which runs under the isolated HOME) uses the
  # SAME podman store as the server container.
  cat > "$BINDIR/mysql" <<EOF
#!/usr/bin/env bash
exec env HOME="$REAL_HOME" podman run --rm -i --network=host -e MYSQL_PWD "$IMAGE" mariadb "\$@"
EOF
  chmod +x "$BINDIR/mysql"

  # a direct auth probe using the same shim (ground truth, independent of incredigo)
  auth() { # auth <password> ; rc 0 == authenticates
    MYSQL_PWD="$1" "$BINDIR/mysql" --batch --skip-column-names \
      -h 127.0.0.1 -P "$PORT" -u labapp -D labdb -e 'SELECT 1;' >/dev/null 2>&1
  }
  SEED_PATH="imported/mysql/labapp"
  EXPECT_DSN="mysql://labapp:${OLD_PW}@127.0.0.1:${PORT}/labdb"
  SEED_DSN="$EXPECT_DSN"
  pw_from_dsn() { sed -E 's#^mysql://labapp:([^@]*)@.*#\1#'; }

elif [[ "$DRIVER" == "mongo" ]]; then
  # mongo:7 started with --auth (MONGO_INITDB_ROOT_* seeds a root user AND enables
  # auth). A NON-admin app user (labapp) whose authentication DB is labdb, holding
  # dbOwner on labdb, is the throwaway credential we rotate. dbOwner => userAdmin on
  # labdb, so labapp can change its OWN password (db.changeUserPassword) — the exact
  # in-place self-service cutover the driver performs, and the realistic vibe-coder
  # persona (an app user scoped to one DB, not the root superuser).
  ROOT_PW="throwaway-root-$(rand)"   # admin bootstrap only; NOT the rotated credential
  podman run --rm -d --name "$CTR" \
    -e MONGO_INITDB_ROOT_USERNAME=root \
    -e MONGO_INITDB_ROOT_PASSWORD="$ROOT_PW" \
    -p "127.0.0.1:${PORT}:27017" "$IMAGE" >/dev/null || { echo "container start failed"; exit 1; }
  # Ready only once auth is ENABLED and root can authenticate (the image starts a
  # temporary no-auth mongod to run init, then restarts with --auth; authenticating
  # as root proves we are past that restart, not talking to the transient instance).
  ready=0
  for i in $(seq 1 60); do
    if podman exec "$CTR" mongosh --quiet -u root -p "$ROOT_PW" --authenticationDatabase admin \
         --eval 'db.runCommand({ping:1}).ok' 2>/dev/null | grep -q 1; then ready=1; break; fi
    sleep 1
  done
  [[ "$ready" -eq 1 ]] && ok "mongo ready (auth enabled)" || { bad "mongo never ready"; exit 1; }

  # Create the throwaway app user (authenticated as root). Its auth DB is labdb.
  podman exec -i "$CTR" mongosh --quiet -u root -p "$ROOT_PW" --authenticationDatabase admin >/dev/null 2>&1 <<JS
db.getSiblingDB("labdb").createUser({user:"labapp", pwd:"$OLD_PW", roles:[{role:"dbOwner", db:"labdb"}]});
JS
  [[ $? -eq 0 ]] && ok "labapp user (dbOwner@labdb) created" || bad "user setup"

  # The driver execs `mongosh` from PATH. Route it through a throwaway client
  # container on the host network so it genuinely connects over TCP to the published
  # loopback port with args/stdin forwarded verbatim. HOME is forced back to the REAL
  # home so this shim (spawned BY incredigo, which runs under the isolated HOME) uses
  # the SAME podman store as the server container.
  cat > "$BINDIR/mongosh" <<EOF
#!/usr/bin/env bash
exec env HOME="$REAL_HOME" podman run --rm -i --network=host "$IMAGE" mongosh "\$@"
EOF
  chmod +x "$BINDIR/mongosh"

  # a direct auth probe using the same shim (ground truth, independent of incredigo).
  # db.auth throws on a bad password (no AUTH-OK printed); a match on AUTH-OK is the
  # pass condition. labapp's password is hex / "throwaway-<hex>": both are
  # JS-string-safe inside the single quotes, no escaping needed. NOTE: the output is
  # CAPTURED first, then grepped — piping mongosh straight into `grep -q` races
  # under `set -o pipefail` (grep closes the pipe on match, mongosh takes SIGPIPE on
  # its trailing prompt and exits non-zero, poisoning the pipeline status). Capturing
  # decouples the probe result from mongosh's exit code.
  auth() { # auth <password> ; rc 0 == authenticates
    local out
    out="$(echo "var ok=db.getSiblingDB('labdb').auth('labapp','$1'); if(ok){print('AUTH-OK');}" \
      | "$BINDIR/mongosh" --quiet --norc "mongodb://127.0.0.1:${PORT}/labdb" 2>/dev/null)" || true
    grep -q AUTH-OK <<<"$out"
  }
  # authSource=labdb: the user is defined in (and authenticates against) labdb, so the
  # driver's authSourceOf() resolves to labdb and changeUserPassword runs there.
  SEED_PATH="imported/mongo/labapp"
  EXPECT_DSN="mongodb://labapp:${OLD_PW}@127.0.0.1:${PORT}/labdb?authSource=labdb"
  SEED_DSN="$EXPECT_DSN"
  pw_from_dsn() { sed -E 's#^mongodb://labapp:([^@]*)@.*#\1#'; }

elif [[ "$DRIVER" == "sshkey" ]]; then
  # The ssh driver mints a NEW keypair and swaps which PUBLIC key an authorized_keys
  # file trusts. The realistic app-credential case: a NON-root app user whose ONE
  # authorized_keys line is the throwaway key we rotate. incredigo edits the host
  # authorized_keys file directly (in-process) and dials the sshd in-process; the
  # host `ssh` client is the INDEPENDENT ground-truth probe.
  ROTNAME="ssh"   # the driver registers as Name()=="ssh" (internal/rotate/sshkey.go)

  # Build the disposable OpenSSH-server image on demand. AuthorizedKeysFile is an
  # ABSOLUTE, bind-mounted path so incredigo's edits to the host file are exactly
  # what sshd reads live; StrictModes off stops file-mode checks from blocking auth
  # on this throwaway box. We authenticate as ROOT: incredigo's RevokeOld rewrites
  # authorized_keys mode 0600 (the correct, secure mode for a real user-owned file),
  # and sshd reads authorized_keys AS the target user — under rootless podman the
  # host operator (who owns the bind-mounted file) maps to the container's root, so
  # only root can read that 0600 file. PermitRootLogin prohibit-password allows the
  # pubkey login while keeping passwords off; root is given a password ONLY to unlock
  # the account (a locked account makes sshd reject even a valid pubkey).
  if ! podman image exists "$IMAGE" >/dev/null 2>&1; then
    BUILDCTX="$(mktemp -d)"
    cat > "$BUILDCTX/Containerfile" <<'DOCKER'
FROM docker.io/library/alpine:3.20
RUN apk add --no-cache openssh \
 && ssh-keygen -A \
 && echo 'root:incy-unused-pw-unlock' | chpasswd \
 && mkdir -p /authkeys
RUN printf 'Port 22\nAuthorizedKeysFile /authkeys/authorized_keys\nStrictModes no\nPubkeyAuthentication yes\nPasswordAuthentication no\nPermitRootLogin prohibit-password\nSubsystem sftp internal-sftp\n' > /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd","-D","-e"]
DOCKER
    if podman build -t "$IMAGE" -f "$BUILDCTX/Containerfile" "$BUILDCTX" >/dev/null 2>&1; then
      ok "built disposable sshd image ($IMAGE)"
    else
      bad "sshd image build failed"; rm -rf "$BUILDCTX"; exit 1
    fi
    rm -rf "$BUILDCTX"
  else
    ok "reusing disposable sshd image ($IMAGE)"
  fi

  # base64url (padding-free) helpers — the self-contained ssh blob carries the PEM in
  # a URL fragment, so it must use the URL-safe, unpadded alphabet.
  b64url_enc() { base64 -w0 | tr '+/' '-_' | tr -d '='; }
  b64url_dec() {
    local d pad; d="$(cat | tr '_-' '/+')"; pad=$(( (4 - ${#d} % 4) % 4 ))
    case "$pad" in 1) d="${d}=";; 2) d="${d}==";; 3) d="${d}===";; esac
    printf '%s' "$d" | base64 -d
  }

  # Shared host-side authorized_keys dir: incredigo edits the file; the container's
  # sshd reads the SAME file via the :z-labeled bind mount (Fedora SELinux enforcing).
  SSHDIR="$BINDIR/authkeys"
  mkdir -m 755 -p "$SSHDIR"

  # Throwaway OLD keypair (the credential we rotate); seed its pubkey as the ONE
  # trusted line.
  ssh-keygen -t ed25519 -N '' -q -f "$BINDIR/oldkey" -C "incy-old-$$" </dev/null
  cat "$BINDIR/oldkey.pub" > "$SSHDIR/authorized_keys"
  chmod 644 "$SSHDIR/authorized_keys"

  podman run --rm -d --name "$CTR" \
    -v "$SSHDIR:/authkeys:rw,z" \
    -p "127.0.0.1:${PORT}:22" "$IMAGE" >/dev/null || { echo "container start failed"; exit 1; }

  # auth <base64url-privkey>: INDEPENDENT ground truth via the host ssh client.
  # Materialises the key to a 0600 temp file and dials root@127.0.0.1:PORT with ONLY
  # publickey auth. rc 0 == authenticates.
  auth() {
    local kf rc; kf="$(mktemp "$BINDIR/probe.XXXXXX")"
    printf '%s' "$1" | b64url_dec > "$kf" 2>/dev/null; chmod 600 "$kf"
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes \
        -o PreferredAuthentications=publickey -o PubkeyAuthentication=yes \
        -o ConnectTimeout=5 -i "$kf" -p "$PORT" root@127.0.0.1 'true' >/dev/null 2>&1
    rc=$?; rm -f "$kf"; return $rc
  }

  OLD_PW="$(b64url_enc < "$BINDIR/oldkey")"   # the "password" == the private-key material
  for i in $(seq 1 30); do auth "$OLD_PW" && break; sleep 1; done
  auth "$OLD_PW" && ok "sshd ready (accepts OLD key)" || { bad "sshd never ready"; exit 1; }

  # Self-contained credential blob: targeting + OLD private key on ONE line, so it
  # round-trips the single-line gopass sink (which drops Meta and truncates a
  # multi-line PEM). authorized_keys is the ABSOLUTE host file both sides share.
  SEED_PATH="imported/ssh/labkey"
  EXPECT_DSN="ssh://root@127.0.0.1:${PORT}${SSHDIR}/authorized_keys#${OLD_PW}"
  SEED_DSN="$EXPECT_DSN"
  pw_from_dsn() { sed -E 's/^ssh:[^#]*#//'; }   # extract the key material (fragment)

elif [[ "$DRIVER" == "appsecret" ]]; then
  # No container: the appsecret driver rotates a LOCAL application signing secret by
  # rewriting the literal value, in place, in every config file that holds it (the
  # realistic Django/Rails/Flask SECRET_KEY case). The "disposable service" is a
  # throwaway temp dir under $BINDIR holding TWO files that share one secret (an app
  # .env and a worker config.yaml), each seeded with ONE throwaway value. incredigo
  # mints a fresh value and swaps it in atomically; the OLD value is gone the moment
  # the files are rewritten (in-place cutover, RevokeOld is a no-op).
  ROTNAME="appsecret"
  APPDIR="$BINDIR/appsecret"          # under $BINDIR ⇒ torn down by the EXIT trap
  mkdir -p "$APPDIR"
  ENVFILE="$APPDIR/.env"
  YMLFILE="$APPDIR/config.yaml"
  # Long random value so it clears the driver's minSecretLen guard and can never be a
  # substring of unrelated config (rand()+rand() = 64 hex chars).
  OLD_PW="throwaway-signing-$(rand)$(rand)"
  printf 'PORT=8080\nSECRET_KEY=%s\nDEBUG=false\n' "$OLD_PW" > "$ENVFILE"
  printf 'service:\n  secret_key: %s\n' "$OLD_PW" > "$YMLFILE"
  chmod 600 "$ENVFILE"; chmod 644 "$YMLFILE"
  ok "seeded 2 throwaway config files with one shared app secret"

  # auth <value>: INDEPENDENT ground truth — rc 0 iff the value literally appears in
  # EVERY target file (presence == the app would read that secret at boot). This is a
  # plain grep of the on-disk files, wholly independent of incredigo's self-report.
  auth() {
    local val="$1" f
    for f in "$ENVFILE" "$YMLFILE"; do
      grep -Fq -- "$val" "$f" || return 1
    done
    return 0
  }

  # Single-line self-contained blob (round-trips the single-line gopass sink). Path
  # segment after the prefix ("appsecret") IS the driver Source. Unencoded slashes in
  # a query value are legal, so url.Parse recovers key/val/path intact.
  SEED_PATH="imported/appsecret/labsecret"
  EXPECT_DSN="appsecret://local/?key=SECRET_KEY&val=${OLD_PW}&path=${ENVFILE}&path=${YMLFILE}"
  SEED_DSN="$EXPECT_DSN"
  TARGET_DESC="throwaway config files under ${APPDIR} (temp dir, no real host file)"
  pw_from_dsn() { sed -E 's/.*[?&]val=([^&]*).*/\1/'; }   # extract the val= query param

elif [[ "$DRIVER" == "k8s" ]]; then
  # Disposable single-node k3s = a REAL kube-apiserver + kube-controller-manager (the
  # token controller) in a throwaway container. The driver rotates a legacy
  # kubernetes.io/service-account-token Secret: CREATE a new token Secret → the token
  # controller populates .data.token → VERIFY it authenticates → DELETE the old Secret,
  # whose removal makes the apiserver's legacy-token authenticator reject the old token.
  # `--disable-agent` runs the CONTROL PLANE ONLY (no kubelet ⇒ no cpuset cgroup ⇒
  # rootless + unprivileged); we schedule no pods, we only need the apiserver + token
  # controller + legacy-token authenticator.
  NS="labns"; SA="labsa"; SEED_SECRET="labsa-token-seed"
  CA_FILE="$BINDIR/k3s-ca.crt"
  OLD_REVOKE_SETTLE=30   # wait out the apiserver's ~10s successful-auth cache

  podman run --rm -d --name "$CTR" \
    -p "127.0.0.1:${PORT}:6443" "$IMAGE" server \
    --disable-agent \
    --disable traefik,servicelb,metrics-server,local-storage \
    --disable-network-policy --disable-helm-controller --disable-cloud-controller \
    --tls-san 127.0.0.1 >/dev/null || { echo "container start failed"; exit 1; }

  # kc: kubectl INSIDE the disposable container (the k3s image bundles it). Used ONLY
  # to provision the throwaway namespace/SA/Secret/RBAC — NOT for any proof assertion.
  kc() { podman exec -i "$CTR" kubectl "$@"; }
  ready=0
  for i in $(seq 1 90); do
    kc get --raw='/readyz' >/dev/null 2>&1 && { ready=1; break; }
    sleep 1
  done
  [[ "$ready" -eq 1 ]] && ok "k3s apiserver ready" || { bad "k3s never ready"; exit 1; }

  # namespace + ServiceAccount + a manually-created legacy token Secret (annotated to
  # the SA so the token controller populates it) + RBAC letting labsa manage Secrets
  # and read its own ServiceAccount — exactly the create-new → verify → revoke-old path.
  kc apply -f - >/dev/null 2>&1 <<YAML
apiVersion: v1
kind: Namespace
metadata: { name: $NS }
---
apiVersion: v1
kind: ServiceAccount
metadata: { name: $SA, namespace: $NS }
---
apiVersion: v1
kind: Secret
metadata:
  name: $SEED_SECRET
  namespace: $NS
  annotations: { kubernetes.io/service-account.name: $SA }
type: kubernetes.io/service-account-token
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: { name: ${SA}-rotator, namespace: $NS }
rules:
- { apiGroups: [""], resources: ["secrets"], verbs: ["create","delete","get","list"] }
- { apiGroups: [""], resources: ["serviceaccounts"], verbs: ["get"] }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: { name: ${SA}-rotator, namespace: $NS }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: Role, name: ${SA}-rotator }
subjects: [{ kind: ServiceAccount, name: $SA, namespace: $NS }]
YAML
  [[ $? -eq 0 ]] && ok "namespace + SA + legacy token Secret + RBAC applied" || bad "k8s object setup"

  # wait for the token controller to populate the seed Secret's token
  SEED_TOK=""
  for i in $(seq 1 30); do
    enc="$(kc -n "$NS" get secret "$SEED_SECRET" -o jsonpath='{.data.token}' 2>/dev/null || true)"
    [[ -n "$enc" ]] && { SEED_TOK="$(printf '%s' "$enc" | base64 -d)"; break; }
    sleep 1
  done
  [[ -n "$SEED_TOK" ]] && ok "token controller populated the seed token" || { bad "seed token never populated"; exit 1; }

  # Pin the apiserver CA (base64 PEM from the in-container kubeconfig) so the
  # INDEPENDENT probe verifies TLS against the real self-signed cluster CA.
  CA_B64="$(podman exec "$CTR" sh -c "awk -F': ' '/certificate-authority-data:/{print \$2; exit}' /etc/rancher/k3s/k3s.yaml" | tr -d ' \r')"
  [[ -n "$CA_B64" ]] && ok "extracted apiserver CA" || { bad "could not read apiserver CA"; exit 1; }
  printf '%s' "$CA_B64" | base64 -d > "$CA_FILE"

  # auth <token>: INDEPENDENT ground truth — host `curl` GETs the ServiceAccount from
  # the REAL apiserver with the token, pinning the cluster CA. rc 0 == HTTP 200. This
  # is wholly independent of incredigo's self-report.
  auth() {
    local code
    code="$(curl -s -o /dev/null -w '%{http_code}' --cacert "$CA_FILE" \
      -H "Authorization: Bearer $1" \
      "https://127.0.0.1:${PORT}/api/v1/namespaces/${NS}/serviceaccounts/${SA}" 2>/dev/null)"
    [[ "$code" == "200" ]]
  }
  OLD_PW="$SEED_TOK"   # the "password" IS the bearer token

  # url-encode the CA so std-base64 '+'/'/'/'=' survive as a query-value: Go's
  # url.Query() decodes a literal '+' to a space, which would corrupt the PEM.
  urlenc() {
    local s="$1" o="" c i h
    for ((i=0; i<${#s}; i++)); do
      c="${s:i:1}"
      case "$c" in [a-zA-Z0-9.~_-]) o+="$c";; *) printf -v h '%%%02X' "'$c"; o+="$h";; esac
    done
    printf '%s' "$o"
  }
  SEED_PATH="imported/k8s/labsa"
  EXPECT_DSN="k8s://127.0.0.1:${PORT}/?ns=${NS}&sa=${SA}&secret=${SEED_SECRET}&token=${SEED_TOK}&ca=$(urlenc "$CA_B64")"
  SEED_DSN="$EXPECT_DSN"
  pw_from_dsn() { sed -E 's/.*[?&]token=([^&]*).*/\1/'; }   # extract the token= query param

elif [[ "$DRIVER" == "wireguard" ]]; then
  # Real kernel WireGuard in a DISPOSABLE rootless container (--cap-add NET_ADMIN ONLY,
  # NOT --privileged): NET_ADMIN is confined to the container's OWN network namespace,
  # so it cannot touch host networking. Two real wg interfaces live inside it:
  #   wg0 — the LOCAL interface whose private key incredigo rotates (the credential);
  #   wg1 — the PEER ("server") that must trust wg0's public key (create-new → verify →
  #         revoke-old is exactly what the driver does to wg1's peer list).
  # incredigo execs `wg` through a shim that runs `podman exec <ctr> wg`, so every wg
  # call lands in the container's netns — incredigo can NEVER touch host wireguard.
  #
  # INDEPENDENT ground truth (auth()): stand up a THROWAWAY probe interface using the
  # candidate private key and drive a REAL WireGuard handshake against wg1 over the
  # container's loopback transport (persistent-keepalive forces the handshake without
  # needing tunnel-IP data routing). A non-zero `wg show <probe> latest-handshakes` for
  # the server peer == the candidate key cryptographically authenticated to wg1. wg1
  # completes the handshake only for a static pubkey it trusts, so after RevokeOld the
  # OLD key's handshake never completes — the exact new-works / old-rejected proof,
  # wholly independent of incredigo's self-report.
  ROTNAME="wireguard"
  PA=51820; PB=51821          # wg listen ports INSIDE the disposable container's netns

  # Build the disposable wireguard image on demand (wireguard-tools + iproute2).
  if ! podman image exists "$IMAGE" >/dev/null 2>&1; then
    BUILDCTX="$(mktemp -d)"
    cat > "$BUILDCTX/Containerfile" <<'DOCKER'
FROM docker.io/library/alpine:3.20
RUN apk add --no-cache wireguard-tools iproute2
CMD ["sleep","infinity"]
DOCKER
    if podman build -t "$IMAGE" -f "$BUILDCTX/Containerfile" "$BUILDCTX" >/dev/null 2>&1; then
      ok "built disposable wireguard image ($IMAGE)"
    else
      bad "wireguard image build failed"; rm -rf "$BUILDCTX"; exit 1
    fi
    rm -rf "$BUILDCTX"
  else
    ok "reusing disposable wireguard image ($IMAGE)"
  fi

  # wgc: run a command INSIDE the disposable container. HOME is forced to the REAL home
  # so rootless podman targets the same store that started $CTR.
  wgc() { env HOME="$REAL_HOME" podman exec -i "$CTR" "$@"; }

  podman run --rm -d --name "$CTR" --cap-add NET_ADMIN "$IMAGE" sleep infinity >/dev/null \
    || { echo "container start failed"; exit 1; }
  for i in $(seq 1 30); do wgc true >/dev/null 2>&1 && break; sleep 1; done
  wgc true >/dev/null 2>&1 && ok "wireguard container up (NET_ADMIN, unprivileged, own netns)" \
    || { bad "container never ready"; exit 1; }

  # Throwaway keypairs, minted inside the container by the real `wg`. The OLD interface
  # key is the credential we rotate; SRV is the peer/"server" key.
  OLD_PRIV="$(wgc wg genkey)"
  OLD_PUB="$(printf '%s' "$OLD_PRIV" | wgc wg pubkey)"
  SRV_PRIV="$(wgc wg genkey)"
  SRV_PUB="$(printf '%s' "$SRV_PRIV" | wgc wg pubkey)"
  [[ -n "$OLD_PRIV" && -n "$OLD_PUB" && -n "$SRV_PUB" ]] \
    && ok "minted throwaway wg keypairs" || { bad "key mint failed"; exit 1; }

  # Stand up the two REAL interfaces. wg0 holds the OLD key; wg1 (server) trusts wg0's
  # OLD public key with allowed-ips 10.0.0.1/32 (the driver carries these over onto the
  # new pubkey on rotation). Private keys reach `wg` on stdin, never argv.
  wgc sh -c '
    set -e
    OLD_PRIV="$1"; SRV_PRIV="$2"; OLD_PUB="$3"; PA="$4"; PB="$5"
    ip link add wg0 type wireguard
    ip link add wg1 type wireguard
    printf "%s" "$OLD_PRIV" | wg set wg0 private-key /dev/stdin listen-port "$PA"
    printf "%s" "$SRV_PRIV" | wg set wg1 private-key /dev/stdin listen-port "$PB"
    wg set wg1 peer "$OLD_PUB" allowed-ips 10.0.0.1/32
    ip addr add 10.0.0.1/24 dev wg0
    ip addr add 10.0.0.2/24 dev wg1
    ip link set wg1 up
    ip link set wg0 up
  ' _ "$OLD_PRIV" "$SRV_PRIV" "$OLD_PUB" "$PA" "$PB" \
    && ok "created real wg0 + wg1 (peer trusts OLD pubkey)" || { bad "wg interface setup failed"; exit 1; }

  # incredigo execs `wg` from PATH; route it into the disposable container so every
  # `wg set`/`wg show` lands in the container's netns — incredigo can never reach host
  # wireguard. HOME is forced to the REAL home so the exec targets the same container.
  cat > "$BINDIR/wg" <<EOF
#!/usr/bin/env bash
exec env HOME="$REAL_HOME" podman exec -i "$CTR" wg "\$@"
EOF
  chmod +x "$BINDIR/wg"

  # auth <base64-privkey>: INDEPENDENT ground truth. Bring up a throwaway probe iface
  # with the candidate key, force a real handshake against wg1 (persistent-keepalive),
  # and report success iff wg1 completed the handshake (=> it trusts the candidate
  # pubkey). wgP has exactly ONE peer, so `latest-handshakes | cut -f2` is its timestamp.
  auth() {
    local out
    out="$(wgc sh -c '
      set -u
      PRIV="$1"; SRV_PUB="$2"; PB="$3"
      ip link del wgP 2>/dev/null || true
      ip link add wgP type wireguard
      printf "%s" "$PRIV" | wg set wgP private-key /dev/stdin \
        peer "$SRV_PUB" endpoint 127.0.0.1:"$PB" persistent-keepalive 1 allowed-ips 10.0.0.2/32
      ip addr add 10.0.0.100/32 dev wgP
      ip link set wgP up
      ok=0
      for i in $(seq 1 12); do
        hs="$(wg show wgP latest-handshakes | cut -f2)"
        if [ -n "$hs" ] && [ "${hs:-0}" -gt 0 ]; then ok=1; break; fi
        sleep 0.5
      done
      ip link del wgP 2>/dev/null || true
      echo "RESULT:$ok"
    ' _ "$1" "$SRV_PUB" "$PB" 2>/dev/null)"
    grep -q "RESULT:1" <<<"$out"
  }

  # Single-line self-contained blob: the stored secret IS the base64 interface private
  # key (path segment after the prefix == the driver Source "wireguard"). Meta is
  # dropped by the single-line gopass sink, so the driver uses its wg0/wg1 defaults —
  # exactly the interfaces named above.
  SEED_PATH="imported/wireguard/labwg"
  EXPECT_DSN="$OLD_PRIV"
  SEED_DSN="$OLD_PRIV"
  OLD_PW="$OLD_PRIV"
  TARGET_DESC="real wg0/wg1 in the disposable container (127.0.0.1:${PA}/${PB} loopback transport)"
  pw_from_dsn() { cat; }   # the stored value already IS the private key
fi

auth "$OLD_PW" && ok "OLD password authenticates (baseline)" || bad "baseline auth failed"

# ---- 3. ISOLATED incredigo environment --------------------------------------
note "3. isolated HOME + gopass store (incredigo cannot see any real cred)"
# Absolute, isolated crypto/secret stores. Because GNUPGHOME + GOPASS_HOMEDIR are
# explicit AND every incredigo/gopass/gpg call runs with HOME overridden to
# $ISO_HOME (run_incy), incredigo can reach NO real ~/.password-store, ~/.incredigo,
# ~/.config/gopass, ~/.gnupg, ~/.ssh, etc. The ambient HOME is left REAL so podman
# stays consistent (see REAL_HOME note above).
export GNUPGHOME="$ISO_HOME/.gnupg"
export GOPASS_HOMEDIR="$ISO_HOME/.gopass"
export GOPASS_NO_NOTIFY=true
export INCREDIGO_PASSPHRASE="lab-podman-proof-$(rand)"
export PATH="$BINDIR:$PATH"   # our client shim wins
mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"; mkdir -p "$GOPASS_HOMEDIR"
# run_incy: run any incredigo/gopass/gpg command with the ISOLATED home so nothing
# it does can touch the real user's dotfiles/credential stores.
run_incy() { HOME="$ISO_HOME" "$@"; }

cat > "$BINDIR/key.batch" <<'EOF'
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Subkey-Type: ecdh
Subkey-Curve: cv25519
Name-Real: Incredigo Podman Proof
Name-Email: proof@incredigo.invalid
Expire-Date: 0
%commit
EOF
run_incy gpg --batch --generate-key "$BINDIR/key.batch" >/dev/null 2>&1
FPR="$(run_incy gpg --list-keys --with-colons proof@incredigo.invalid | awk -F: '/^fpr:/{print $10; exit}')"
run_incy gopass init --crypto gpg --storage fs "$FPR" </dev/null >/dev/null 2>&1
# seed EXACTLY ONE entry: the throwaway DSN. Path segment after prefix == driver.
printf '%s' "$SEED_DSN" | run_incy gopass insert --multiline=false -f "$SEED_PATH" >/dev/null 2>&1
ok "seeded $SEED_PATH (throwaway DSN)"

# ---- isolation asserts (MUST pass before execute) ---------------------------
note "ISOLATION ASSERTS (block execute unless all pass)"
verify_isolation() {
  local iso_ok=1
  local realhome; realhome="$(getent passwd "$(id -u)" | cut -d: -f6)"
  # incredigo's effective HOME (and thus ~/.incredigo state) is the temp dir.
  [[ "$ISO_HOME" == /tmp/* && "$ISO_HOME" != "$realhome"* ]] \
    && ok "incredigo HOME is a temp dir outside the real home" || { bad "HOME not isolated"; iso_ok=0; }
  # crypto + secret stores live outside the real home — no path into real creds.
  [[ "$GNUPGHOME" != "$realhome"* && "$GOPASS_HOMEDIR" != "$realhome"* ]] \
    && ok "GNUPGHOME + GOPASS_HOMEDIR are outside the real home" || { bad "store dir under real home"; iso_ok=0; }
  # incredigo could not read a real store even if pointed at one: the isolated
  # gopass store holds ONLY our one throwaway entry (proves no real store bleed-through).
  local entries; entries="$(run_incy gopass ls --flat 2>/dev/null)"
  if [[ "$entries" == "$SEED_PATH" ]]; then
    ok "gopass store holds ONLY the one throwaway entry (no real creds visible)"
  else
    bad "gopass store has unexpected entries: $entries"; iso_ok=0
  fi
  # belt-and-suspenders: a real password-store, if present, must be unreachable.
  if [[ -d "$realhome/.password-store" ]]; then
    [[ -z "$(run_incy gopass ls --flat 2>/dev/null | grep -vx "$SEED_PATH")" ]] \
      && ok "real ~/.password-store exists but is NOT visible to incredigo" \
      || { bad "real password-store leaked into incredigo view"; iso_ok=0; }
  else
    ok "no real ~/.password-store on this host (nothing to leak)"
  fi
  # the DSN target must be exactly the throwaway we seeded (a loopback container port,
  # or — for appsecret — files under our temp dir), never a real/discovered credential.
  local dsn; dsn="$(run_incy gopass show -o "$SEED_PATH" 2>/dev/null)"
  [[ "$dsn" == "$EXPECT_DSN" ]] \
    && ok "rotation target is ${TARGET_DESC}" \
    || { bad "unexpected rotation target"; iso_ok=0; }
  # appsecret writes to real local files, so additionally PROVE every target path is
  # under our disposable temp dir — never a real host config the driver could corrupt.
  if [[ "$DRIVER" == "appsecret" ]]; then
    if [[ "$ENVFILE" == /tmp/* && "$YMLFILE" == /tmp/* && "$APPDIR" == "$BINDIR"/* ]]; then
      ok "appsecret target files are under a temp dir (no real host file in scope)"
    else
      bad "appsecret target files are NOT confined to a temp dir"; iso_ok=0
    fi
  fi
  return $((1 - iso_ok))
}
if ! verify_isolation; then
  echo; echo "ISOLATION FAILED — refusing to enable execute. Aborting." >&2
  exit 1
fi

# ---- 4. REAL rotation via incredigo -----------------------------------------
note "4. incredigo rotate --execute (REAL cutover, scoped to the container)"
ROT_OUT="$(INCREDIGO_ALLOW_EXECUTE=1 run_incy "$INCREDIGO" rotate --execute --prefix imported/ 2>&1)"
echo "$ROT_OUT"
grep -Eq 'backup gate: [0-9]+ entr' <<<"$ROT_OUT" && ok "mandatory backup gate ran" || bad "no backup gate"
grep -Eq "${ROTNAME}[[:space:]]+LIVE-VM.*true[[:space:]]+true[[:space:]]+true" <<<"$ROT_OUT" \
  && ok "spine reported rotate+verify+store true" || bad "spine did not report full success"

# ---- 5. INDEPENDENT verification (ground truth, not incredigo's word) --------
note "5. independent auth checks (the actual proof)"
NEW_DSN="$(run_incy gopass show -o "$SEED_PATH" 2>/dev/null)"
NEW_PW="$(pw_from_dsn <<<"$NEW_DSN")"
if [[ "$NEW_PW" != "$OLD_PW" && -n "$NEW_PW" ]]; then ok "stored password changed"; else bad "password unchanged in store"; fi
if auth "$NEW_PW"; then ok "NEW password authenticates"; else bad "NEW password does NOT authenticate"; fi
# OLD must be rejected. Some providers cache a successful auth briefly (k8s: the
# apiserver's ~10s cachedTokenAuthenticator), so poll up to OLD_REVOKE_SETTLE seconds
# for the rejection to take effect; 0 == check exactly once (every other driver).
old_rejected=0
for _s in $(seq 0 "$OLD_REVOKE_SETTLE"); do
  if auth "$OLD_PW"; then
    [[ "$OLD_REVOKE_SETTLE" -gt 0 ]] && sleep 1 || true
  else
    old_rejected=1; break
  fi
done
if [[ "$old_rejected" -eq 1 ]]; then ok "OLD password rejected (revoked)"; else bad "OLD password STILL authenticates (cutover incomplete)"; fi

# ---- summary ----------------------------------------------------------------
note "SUMMARY"
echo "  driver=$DRIVER  image=$IMAGE  port=$PORT  PASS=$PASS  FAIL=$FAIL"
if [[ "$FAIL" -eq 0 ]]; then
  echo "  VERDICT: LIVE-VM PROOF PASSED — incredigo rotated the disposable $DRIVER end-to-end."
else
  echo "  VERDICT: FAILED ($FAIL check(s)) — see output above."
fi
echo "PODMAN_PROOF_DONE rc=$FAIL"
exit "$FAIL"
