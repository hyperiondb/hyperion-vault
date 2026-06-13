PASS=0
FAIL=0

export PGPASSWORD="${SU_PASSWORD:-pgr_super_pw}"
SU="postgres"
DB="${APP_DB:-postgres}"
SVC_USER="${VAULT_SERVICE_USER:-vault_service}"
SVC_PW="${VAULT_SERVICE_PASSWORD:-vault_service_pw}"
ADMIN_TOKEN="${VAULT_ADMIN_TOKEN:-dev-admin-token-change-me}"

psql_node1() {
    psql -h node1 -U "$SU" -d "$DB" -v ON_ERROR_STOP=1 -tAc "$1"
}

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

check() {
    local name="$1"
    shift
    if "$@"; then pass "$name"; else fail "$name (got rc=$?)"; fi
}

wait_db() {
    for _ in $(seq 1 120); do
        psql_node1 'SELECT 1' >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

wait_api() {
    local host="$1"
    for _ in $(seq 1 120); do
        curl -fsS "http://${host}:8200/healthz" >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

bootstrap() {
    psql_node1 "CREATE EXTENSION IF NOT EXISTS hyperion_vault" >/dev/null
    psql_node1 "DO \$\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='${SVC_USER}') THEN CREATE ROLE ${SVC_USER} LOGIN PASSWORD '${SVC_PW}'; END IF; END \$\$" >/dev/null
    psql_node1 "SELECT vault.grant_service_role('${SVC_USER}')" >/dev/null
    psql_node1 "INSERT INTO vault.admin_tokens(name, token_sha256) VALUES('e2e-admin', sha256('${ADMIN_TOKEN}'::bytea)) ON CONFLICT (name) DO NOTHING" >/dev/null
}

admin_post() {
    curl -fsS -X POST "http://$1:8200$2" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H 'content-type: application/json' -d "$3"
}

admin_put() {
    curl -fsS -X PUT "http://$1:8200$2" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H 'content-type: application/json' -d "$3"
}

read_get() {
    curl -fsS "http://$1:8200$2"
}

verify_value() {
    curl -fsS -X POST "http://$1:8200$2/verify" \
        -H 'content-type: application/json' -d "{\"value\":$(jq -Rn --arg v "$3" '$v')}"
}

status_get() {
    curl -s -o /dev/null -w '%{http_code}' "http://$1:8200$2"
}

status_post_auth() {
    curl -s -o /dev/null -w '%{http_code}' -X POST "http://$1:8200$2" \
        -H "Authorization: Bearer $3" -H 'content-type: application/json' -d "$4"
}

status_delete_auth() {
    curl -s -o /dev/null -w '%{http_code}' -X DELETE "http://$1:8200$2" \
        -H "Authorization: Bearer $ADMIN_TOKEN"
}

jget() { echo "$1" | jq -r "$2"; }
