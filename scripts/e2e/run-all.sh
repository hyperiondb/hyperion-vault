#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")"

. ./lib.sh

echo "== waiting for cluster + api =="
wait_db || { echo "node1 not ready in time"; exit 1; }
for h in api1 api2 api3; do
    wait_api "$h" || { echo "$h not ready in time"; exit 1; }
done

echo "== bootstrapping vault (extension, service role, admin token) =="
bootstrap

for t in test-crud test-auth test-replica test-rotation; do
    echo "================ $t ================"
    . "./$t.sh"
done

echo
echo "==================== SUMMARY ===================="
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
