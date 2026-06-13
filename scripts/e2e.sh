#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

COMPOSE=(docker compose -f docker/docker-compose.yml -f docker/docker-compose.e2e.yml)

if [ -f docker/.env ]; then
  set -a; . docker/.env; set +a
fi
: "${VAULT_LOCAL_MASTER_KEY:?set VAULT_LOCAL_MASTER_KEY (see docker/.env.example)}"

cleanup() { "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

if [ "${1:-}" != "--no-build" ]; then
  echo "== building images (requires PG_REPLICA_IMAGE, default pg-replica-paradedb:local) =="
  "${COMPOSE[@]}" build || { echo "build FAILED"; exit 1; }
fi

echo "== starting cluster + api =="
"${COMPOSE[@]}" up -d node1 node2 node3 api1 api2 api3

echo "== running e2e suite =="
"${COMPOSE[@]}" run --rm runner bash scripts/e2e/run-all.sh
status=$?

echo "e2e exit status: $status"
exit "$status"
