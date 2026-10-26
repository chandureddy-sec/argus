#!/usr/bin/env bash
# Stop the Argus / ThreatLens stack.
#
#   ./stop.sh              # stop and remove containers; Postgres, Redis and
#                          # feed volumes are PRESERVED. Re-run ./start.sh to
#                          # resume with the same data.
#   ./stop.sh --volumes    # also delete the named volumes
#                          # (pgdata, redisdata, rawdata, recondata).
#                          # IRREVERSIBLE: wipes every user, scan, indicator,
#                          # case and feed snapshot. Requires confirmation.
#   ./stop.sh --help

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" && pwd)"
cd "$SCRIPT_DIR"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RED=$'\033[31m'; C_YELLOW=$'\033[33m'; C_RESET=$'\033[0m'
else
    C_RED=""; C_YELLOW=""; C_RESET=""
fi

WIPE_VOLUMES=0
FORCE=0
for arg in "$@"; do
    case "$arg" in
        --volumes|-v) WIPE_VOLUMES=1 ;;
        --yes|-y)     FORCE=1 ;;
        -h|--help)
            sed -n '2,10p' "$0" | sed 's/^#\{0,1\} \{0,1\}//'
            exit 0 ;;
        *)
            printf 'error: unknown option: %s (try --help)\n' "$arg" >&2
            exit 2 ;;
    esac
done

if [ ! -f docker-compose.yml ]; then
    printf 'error: run this from the threatlens directory (no docker-compose.yml here).\n' >&2
    exit 1
fi

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
    printf 'error: docker + compose plugin not available.\n' >&2
    exit 1
fi

if [ "$WIPE_VOLUMES" -eq 1 ]; then
    printf '%sWARNING:%s --volumes will DELETE every named volume for this stack:\n' "$C_RED" "$C_RESET"
    printf '  threatlens_pgdata     (PostgreSQL: users, indicators, cases, feeds)\n'
    printf '  threatlens_redisdata  (Redis: queues, rate limits, caches)\n'
    printf '  threatlens_rawdata    (raw feed documents)\n'
    printf '  threatlens_recondata  (ReconX reports, monitors, keys)\n'
    printf 'This is %sirreversible%s. .env is kept.\n\n' "$C_YELLOW" "$C_RESET"
    if [ "$FORCE" -ne 1 ]; then
        printf 'Type DELETE to continue: '
        read -r confirm
        if [ "${confirm:-}" != "DELETE" ]; then
            printf 'aborted; no changes made.\n'
            exit 1
        fi
    fi
    docker compose down -v
    printf 'stack and volumes removed.\n'
else
    docker compose down
    printf 'stack stopped. Data volumes preserved. Resume with: ./start.sh\n'
fi
