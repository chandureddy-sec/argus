#!/usr/bin/env bash
# Argus / ThreatLens launcher for Linux and macOS.
#
#   ./start.sh              # start the stack; create .env on first run
#   ./start.sh --build      # rebuild images before starting (after code changes)
#   ./start.sh --no-pull    # skip the Docker Hub preflight (offline / air-gapped)
#   ./start.sh --help
#
# Safe to re-run: .env, Postgres and Redis volumes are preserved.
# Published ports bind to 127.0.0.1 only. Put a TLS reverse proxy in front
# before exposing Argus to a network.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" && pwd)"
cd "$SCRIPT_DIR"

# ─── colours (disabled when stdout is not a TTY) ────────────────────────────
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RED=$'\033[31m'; C_YELLOW=$'\033[33m'; C_GREEN=$'\033[32m'
    C_CYAN=$'\033[36m'; C_DIM=$'\033[2m'; C_RESET=$'\033[0m'
else
    C_RED=""; C_YELLOW=""; C_GREEN=""; C_CYAN=""; C_DIM=""; C_RESET=""
fi
info()  { printf '%s\n' "$*"; }
step()  { printf '%s==>%s %s\n' "$C_CYAN" "$C_RESET" "$*"; }
warn()  { printf '%swarning:%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
err()   { printf '%serror:%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
ok()    { printf '%s✓%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
dim()   { printf '%s%s%s\n' "$C_DIM" "$*" "$C_RESET"; }

# ─── arguments ──────────────────────────────────────────────────────────────
BUILD_FLAG=""
SKIP_PULL=""
for arg in "$@"; do
    case "$arg" in
        --build)    BUILD_FLAG="--build" ;;
        --no-pull)  SKIP_PULL="1" ;;
        -h|--help)
            sed -n '2,11p' "$0" | sed 's/^#\{0,1\} \{0,1\}//'
            exit 0 ;;
        *)
            err "unknown option: $arg (try --help)"
            exit 2 ;;
    esac
done

# ─── locate the compose file; refuse to run from the wrong directory ────────
if [ ! -f docker-compose.yml ] || [ ! -f .env.example ]; then
    err "run this script from the 'threatlens' directory (missing docker-compose.yml or .env.example here)."
    err "try: cd \"\$(git rev-parse --show-toplevel)\"/threatlens && ./start.sh"
    exit 1
fi

# ─── prerequisite: docker and compose plugin ────────────────────────────────
if ! command -v docker >/dev/null 2>&1; then
    err "docker is not installed or not on PATH."
    info "  Install Docker Engine: https://docs.docker.com/engine/install/"
    info "  Or Docker Desktop:     https://docs.docker.com/desktop/"
    exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
    err "the Docker Compose plugin is missing (needs: docker compose, not docker-compose)."
    info "  Install: https://docs.docker.com/compose/install/linux/"
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    err "docker daemon is not reachable. Start Docker, then re-run."
    info "  Linux:   sudo systemctl start docker   (and: sudo usermod -aG docker \$USER   then re-login)"
    info "  macOS:   open -a Docker"
    exit 1
fi
ok "docker and compose plugin available"

# ─── secret generation (openssl → /dev/urandom fallback) ────────────────────
new_secret() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n'
    elif [ -r /dev/urandom ]; then
        # base64 chars only; strip padding and newlines
        head -c 48 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n' | cut -c1-43
    else
        err "no openssl and no /dev/urandom; cannot generate a random secret."
        exit 1
    fi
}

# ─── .env creation (idempotent) ─────────────────────────────────────────────
PLACEHOLDER_PW='change-me-to-a-long-random-string'
if [ ! -f .env ]; then
    step "creating .env from .env.example with fresh secrets"
    PASS="$(new_secret)"
    SECRET="$(new_secret)"
    # Replace POSTGRES_PASSWORD and append TL_SECRET_KEY (not in the template).
    # Use awk so we don't depend on GNU sed -i (BSD sed on macOS differs).
    awk -v pw="$PASS" '
        /^POSTGRES_PASSWORD=/ { print "POSTGRES_PASSWORD=" pw; next }
        { print }
    ' .env.example > .env.tmp
    printf 'TL_SECRET_KEY=%s\n' "$SECRET" >> .env.tmp
    mv .env.tmp .env
    chmod 600 .env
    ok ".env created (git-ignored; mode 600)"
else
    dim ".env already present; keeping existing secrets"
    # Add TL_SECRET_KEY if an older .env is missing it.
    if ! grep -q '^TL_SECRET_KEY=' .env; then
        step "adding missing TL_SECRET_KEY to .env"
        printf '\nTL_SECRET_KEY=%s\n' "$(new_secret)" >> .env
    fi
    # Refuse to proceed with the shipped placeholder password.
    if grep -q "^POSTGRES_PASSWORD=${PLACEHOLDER_PW}\$" .env; then
        err ".env still has the placeholder POSTGRES_PASSWORD."
        info "  Fix: edit threatlens/.env and set a long random value (e.g.: openssl rand -base64 32)."
        info "  Or:  rm .env  and  ./start.sh   (regenerates with a random password)."
        exit 1
    fi
fi

# ─── preflight: Docker Hub reachability + TLS trust ─────────────────────────
# docker pull is where corporate-CA / proxy failures normally surface. We probe
# with a quiet pull of the smallest base image we need and parse the error if
# any; this catches TLS trust issues before 'compose build/up' spends minutes.
preflight_pull() {
    local image="postgres:16-alpine" out rc
    step "preflight: verifying Docker Hub is reachable"
    if docker image inspect "$image" >/dev/null 2>&1; then
        ok "base image '$image' is already present locally"
        return 0
    fi
    set +e
    out="$(docker pull --quiet "$image" 2>&1)"
    rc=$?
    set -e
    if [ $rc -eq 0 ]; then
        ok "pulled '$image' from Docker Hub"
        return 0
    fi
    err "docker pull failed:"
    printf '%s\n' "$out" | sed 's/^/    /' >&2
    case "$out" in
        *"x509"*|*"certificate signed by unknown authority"*|*"certificate signer not trusted"*|*"tls:"*)
            cat >&2 <<EOF

${C_YELLOW}TLS certificate trust problem.${C_RESET} The Docker daemon could not verify the
certificate presented by Docker Hub (auth.docker.io / registry-1.docker.io).

This almost always means your network is behind a corporate proxy or TLS-
inspection appliance that re-signs HTTPS traffic with its own root CA, and
that CA is not installed on the host where the Docker daemon runs.

What to try (ask your network admin which applies here):

  1. Obtain the corporate root CA from your IT team. Verify its fingerprint
     with them before installing it; never pull a 'root CA' off a chat.
  2. Install it in the host OS trust store:
       Debian/Ubuntu:  sudo cp corp-root.crt /usr/local/share/ca-certificates/
                       sudo update-ca-certificates
       RHEL/Fedora:    sudo cp corp-root.crt /etc/pki/ca-trust/source/anchors/
                       sudo update-ca-trust
       macOS:          sudo security add-trusted-cert -d -r trustRoot \\
                       -k /Library/Keychains/System.keychain corp-root.crt
  3. Restart the Docker daemon (Linux: sudo systemctl restart docker;
     Docker Desktop: Quit then re-open).
  4. If you use Docker Desktop with WSL2, also install the CA inside the
     WSL distro, not only Windows.

Argus will NOT disable TLS verification for you. Doing so (insecure-registries,
--tlsverify=false) silently exposes every image pull to tampering.
EOF
            ;;
        *"dial tcp"*|*"no such host"*|*"Temporary failure in name resolution"*)
            cat >&2 <<EOF

${C_YELLOW}DNS or network reachability problem.${C_RESET} The Docker daemon could not
reach Docker Hub. Check:
  * 'docker run --rm alpine ping -c1 1.1.1.1'   (basic egress)
  * '/etc/resolv.conf' or your corporate VPN DNS
  * HTTP_PROXY / HTTPS_PROXY in /etc/systemd/system/docker.service.d/http-proxy.conf
EOF
            ;;
        *"unauthorized"*|*"authentication required"*|*"toomanyrequests"*|*"rate limit"*)
            cat >&2 <<EOF

${C_YELLOW}Docker Hub authentication / rate-limit problem.${C_RESET}
  * Anonymous pulls are rate-limited; try 'docker login'.
  * On shared NAT (office, lab), you may have hit the shared quota;
    wait or sign in with a Docker ID.
EOF
            ;;
        *)
            info "If this is a corporate network, see the Troubleshooting section in README.md"
            ;;
    esac
    exit 1
}

if [ -z "$SKIP_PULL" ]; then
    preflight_pull
else
    warn "--no-pull: skipping Docker Hub preflight"
fi

# ─── port conflict check (soft warning only) ────────────────────────────────
# docker-compose binds 5432/6379/8000 on 127.0.0.1. If a host service already
# listens there, 'compose up' fails late with an opaque bind error.
check_port() {
    local port="$1" name="$2"
    # Prefer ss, fall back to lsof. Both may be missing on minimal images; a
    # missing probe is fine — compose will still refuse to bind and we'll report.
    if command -v ss >/dev/null 2>&1; then
        if ss -ltn "sport = :$port" 2>/dev/null | grep -q "LISTEN"; then
            warn "port $port is already in use (needed for $name)."
            return 1
        fi
    elif command -v lsof >/dev/null 2>&1; then
        if lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
            warn "port $port is already in use (needed for $name)."
            return 1
        fi
    fi
    return 0
}
PORT_WARN=0
check_port 5432 "PostgreSQL (compose db)" || PORT_WARN=1
check_port 6379 "Redis (compose redis)"   || PORT_WARN=1
check_port 8000 "Argus API"               || PORT_WARN=1
if [ $PORT_WARN -eq 1 ]; then
    info "  If a host service owns these ports, stop it, or set TL_DB_PORT /"
    info "  TL_REDIS_PORT / TL_API_PORT in threatlens/.env to free host ports."
    info "  (The containers themselves always use 5432 / 6379 / 8000.)"
fi

# ─── build + start ──────────────────────────────────────────────────────────
step "starting the stack (first run builds images; this takes a few minutes)"
# --wait blocks until every service is healthy; --wait-timeout bounds it.
# Pulling and build still run in the foreground so the user sees progress.
if ! docker compose up -d --wait --wait-timeout 300 $BUILD_FLAG; then
    err "'docker compose up' did not reach a healthy state."
    info "  Service status:"
    docker compose ps --format "table {{.Service}}\t{{.Status}}" || true
    info "  Dig deeper:"
    info "    docker compose logs --tail 100 api worker"
    info "    docker compose logs --tail 100 db redis"
    exit 1
fi

docker compose ps --format "table {{.Service}}\t{{.Status}}"

# ─── readiness probe (API /readyz) ──────────────────────────────────────────
step "waiting for the API to answer /readyz"
READY_URL="http://127.0.0.1:${TL_API_PORT:-8000}/readyz"
for i in $(seq 1 30); do
    if command -v curl >/dev/null 2>&1; then
        body="$(curl -fsS -m 3 "$READY_URL" 2>/dev/null || true)"
    else
        body="$(python3 -c "import urllib.request,sys;print(urllib.request.urlopen('$READY_URL',timeout=3).read().decode())" 2>/dev/null || true)"
    fi
    if [ -n "$body" ]; then
        ok "API is ready"
        printf '  %s\n' "$body"
        break
    fi
    sleep 2
    [ "$i" = 30 ] && warn "API did not respond at $READY_URL within 60s; run: docker compose logs api"
done

# ─── success banner / next steps ────────────────────────────────────────────
cat <<EOF

$(ok "Argus is up.")
  Open:          http://127.0.0.1:${TL_API_PORT:-8000}/app/
  Create admin:  docker compose exec worker threatlens users create "your name" --role admin
  Health:        curl $READY_URL
  Follow logs:   docker compose logs -f api worker
  Stop:          ./stop.sh                 (data is kept)
  Clean stop:    ./stop.sh --volumes       (DELETES Postgres, Redis and feed volumes)

EOF
