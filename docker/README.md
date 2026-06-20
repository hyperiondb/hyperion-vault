# Docker

The compose stack runs a **3-node hyperion-vault Raft cluster** (`vault1`,
`vault2`, `vault3`) — each a single Rust binary with its own embedded redb store,
using the **local** KMS key wrapper (no AWS). Nodes replicate via openraft.

## Run the cluster

```bash
cp .env.example .env          # throwaway dev master key
docker compose up --build
```

- APIs: `localhost:8200` (vault1), `:8201` (vault2), `:8202` (vault3)
- Raft RPC: internal `:7400` on each node (not published)
- `VAULT_ALLOWED_IPS` defaults to `0.0.0.0/0` **for dev only** — restrict it for real use.

The cluster bootstraps itself: node 1 initializes the Raft membership from
`VAULT_PEERS` on first start; the others join automatically.

## First admin token

Management calls need an admin bearer token. Seed one by setting
`VAULT_BOOTSTRAP_TOKEN` (the same value on every node) — it creates a
`bootstrap-admin` token mapped to the built-in `admin` role:

```bash
VAULT_BOOTSTRAP_TOKEN=dev-admin-token-change-me docker compose up --build
```

Rotate it after issuing real per-service tokens via `POST /v1/tokens`.

## End-to-end tests

```bash
bash ../scripts/e2e.sh
```

Brings up the cluster and runs the suite in a `runner` container
(`docker-compose.e2e.yml`): CRUD, admin-token auth, cross-node replicated reads
(write via `vault2`, read via `vault1`/`vault3`), and rotation with the grace
window. The overlay seeds `VAULT_BOOTSTRAP_TOKEN` so the runner can authenticate.

## Admin access over WireGuard (optional)

To reach the APIs only over an encrypted tunnel (no public API surface), add the
WireGuard overlay:

```bash
WG_ENDPOINT=vault.example.com:51820 bash ../scripts/wireguard/gen-keys.sh admin1
docker compose -f docker-compose.yml -f docker-compose.wireguard.yml up --build
```

This adds a kernel `wg-quick` gateway (UDP `51820`), pins the cluster network to
`172.30.0.0/24`, and gates reads to tunnel traffic via `VAULT_ALLOWED_IPS`. See
[`../docs/WIREGUARD.md`](../docs/WIREGUARD.md).

## Production

Use `VAULT_KMS_MODE=aws` + `VAULT_KMS_KEY_ID` (the same key on every node), set
`VAULT_ALLOWED_IPS` to the real read clients, run an odd number of nodes (3 or 5)
for Raft quorum, and put each node's redb file on durable storage. The leader
accepts writes and runs the rotation worker; followers forward writes and follow
failover automatically.
