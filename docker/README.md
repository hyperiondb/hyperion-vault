# Docker

The compose stack runs a **3-node `pg_replica` cluster** with the
`hyperion_vault` extension on every node and a `hyperion-vault-api` sidecar per
node (`api1`→`node1`, `api2`→`node2`, `api3`→`node3`), using the **local** key
wrapper (no AWS). It mirrors `pg_replica`'s own docker topology.

## Prerequisites

The node image is built **on top of the `pg_replica` cluster image**. Build that
first (from the sibling repo), then point this stack at it:

```bash
# in ../pg_replica
docker compose -f docker/docker-compose.yml build      # produces pg-replica-paradedb:local
```

Set `PG_REPLICA_IMAGE` if the tag differs (default `pg-replica-paradedb:local`).

## Run the cluster

```bash
cp .env.example .env          # throwaway dev master key + admin token
docker compose up --build
```

- APIs: `localhost:8200` (node1), `:8201` (node2), `:8202` (node3)
- Postgres: `localhost:5432/5433/5434`
- Dev admin token: `$VAULT_ADMIN_TOKEN` (default `dev-admin-token-change-me`)
- `VAULT_ALLOWED_IPS` defaults to `0.0.0.0/0` **for dev only** — restrict it for real use.

The first time, create the extension + service grants + an admin token on the
primary (these replicate to every node):

```bash
docker compose exec node1 psql -U postgres -c "CREATE EXTENSION IF NOT EXISTS hyperion_vault"
docker compose exec node1 psql -U postgres -c "SELECT vault.grant_service_role('vault_service')"
docker compose exec node1 psql -U postgres \
  -c "INSERT INTO vault.admin_tokens(name, token_sha256) VALUES('admin', sha256('dev-admin-token-change-me'::bytea))"
```

(The e2e runner does this automatically — see below.)

Each Postgres node runs with `log_statement=none` and
`log_parameter_max_length=0` so secret values never reach the server log
(see [`postgresql.vault.conf`](postgresql.vault.conf) for the full reference
config including `shared_preload_libraries`).

## End-to-end tests

```bash
bash ../scripts/e2e.sh          # or: make e2e
```

This builds the images, brings up the cluster + APIs, and runs the suite in a
`runner` container (`docker-compose.e2e.yml`): CRUD, admin-token auth,
cross-node replicated reads (write via `api2`, read via `api1`/`api3`), and
rotation with the grace window.

## Admin access over WireGuard (optional)

To reach the APIs only over a mutually-authenticated, encrypted tunnel (no
public API surface), add the WireGuard overlay:

```bash
WG_ENDPOINT=vault.example.com:51820 bash ../scripts/wireguard/gen-keys.sh admin1
docker compose -f docker-compose.yml -f docker-compose.wireguard.yml up --build
```

This adds a kernel `wg-quick` gateway (UDP `51820`), pins the cluster network to
`172.30.0.0/24`, and gates reads to tunnel traffic via `VAULT_ALLOWED_IPS`. See
[`../docs/WIREGUARD.md`](../docs/WIREGUARD.md) for the topology, peer
management, and production hardening.

## Production

Use `VAULT_KMS_MODE=aws` + `VAULT_KMS_KEY_ID`, give every API the same KMS key,
set `VAULT_ALLOWED_IPS` to the real read clients, enable TLS to Postgres, and
add `hyperion_vault` to `shared_preload_libraries` to run the autonomous
rotation supervisor. The API's writer pool reaches the current primary from any
node and follows failover automatically.
