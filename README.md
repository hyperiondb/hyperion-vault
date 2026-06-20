# HyperionDB Vault (`hyperion-vault`)

A **self-contained, replicated secrets vault**: a single Rust binary that stores
secrets **encrypted at rest** on local disk and exposes a **REST API** to
create, read, update, delete, verify, and **automatically rotate** them.

Secrets are sealed with **envelope encryption** — a per-secret data key (DEK)
protected by **AWS KMS**, with the secret bytes sealed under
**XChaCha20-Poly1305**. Only ciphertext, the wrapped DEK, and a nonce are ever
written to disk; plaintext never lands on disk.

Storage is an embedded **[redb](https://github.com/cberner/redb)** key-value
store (one file per node). High availability comes from **[openraft](https://github.com/databendlabs/openraft)**:
the vault runs as a Raft cluster, writes go through consensus to the leader and
replicate to a quorum, and reads are served locally from any node. There is no
external database to operate.

Comparable to [supabase/vault](https://github.com/supabase/vault) and
[OpenBao](https://openbao.org/) (KMS-backed envelope encryption + API +
rotation) — this project packages that model as a small, dependency-free,
self-replicating cluster.

Status: **in progress**

---

## Features

- **Encryption at rest, KMS-backed.** Envelope encryption: AWS KMS wraps a
  256-bit data key (via `GenerateDataKey`/`Decrypt`); the secret is sealed with
  XChaCha20-Poly1305. Disk stores only `{wrapped_dek, nonce, ciphertext, aad}`.
- **Embedded storage (redb).** Each node owns a single redb file — no Postgres,
  no external services. The Raft log, snapshots, and the secret state all live
  in that one embedded store.
- **Raft replication & failover (openraft).** Writes are committed through Raft
  to the leader and replicated to a quorum; leader election provides automatic
  failover. Reads are served from the local node (optionally linearizable
  through the leader via `VAULT_READ_CONSISTENCY=linearizable`).
- **Two secret kinds.**
  - **`manual`** — set and changed explicitly through the API.
  - **`automatic`** — rotated on a schedule by a background worker (running only
    on the leader). Old versions stay valid for a configurable **grace period**.
- **REST API.** `POST/GET/PUT/DELETE /v1/secrets`, plus `/rotate` and a
  constant-time `/verify` endpoint for grace-window validation.
- **IP allowlist for reads.** Secret reads are permitted only from an
  IPv4/CIDR allowlist (`VAULT_ALLOWED_IPS`). **Fail-closed**: an empty allowlist
  denies all reads.
- **Role-based access control (RBAC).** `create/update/delete/rotate` and
  role/token administration require a bearer token. Each token maps to a
  **role** whose rules are `action × secret-path glob` (e.g. a `payment` role
  scoped to `stripe/*`), with a built-in `admin` superuser role. Tokens are
  stored only as SHA-256 fingerprints and checked in constant time.
- **Brute-force lockout.** Auth/authz failures are counted per client IP
  (per node); after `VAULT_AUTH_MAX_FAILURES` the IP is locked out (HTTP `429`)
  for `VAULT_AUTH_LOCKOUT_SECS`.
- **KMS-outage resilience.** Unwrapped data keys are cached in memory for
  `VAULT_DEK_CACHE_TTL_SECS`, and KMS calls are retried with exponential backoff
  up to `VAULT_KMS_MAX_RETRIES`.
- **Audit log.** Every operation is recorded (actor, client IP, action,
  outcome) in a local `audit_log` table per node.
- **Defense in depth.** Application-enforced access invariants, version-bound
  AEAD associated data (a ciphertext can't be replayed under another secret name
  or version), and zeroized key material in memory.

---

## Workspace layout

| Crate / dir | Kind | Purpose |
|-------------|------|---------|
| `crates/hyperion-vault-core` | lib | Pure-Rust security core: AEAD envelope, IP allowlist, token auth, rotation policy. No storage, no network. |
| `crates/hyperion-vault-api` | bin | The REST API service (`axum`): handlers, IP/token guards, the redb store (`store/`), the Raft layer (`raft/`), KMS, rotation worker. |
| `crates/hyperion-vault` | lib | Umbrella crate re-exporting the security core. |
| `docs/` | — | Architecture, decisions, threat model, API and security docs. |
| `docker/` | — | Single-binary node image + N-node Raft cluster compose + WireGuard overlay + e2e overlay. |

The storage layer is built around a **ports & adapters** seam: the service layer
depends only on the `VaultReader` / `VaultWriter` traits (`store/ports.rs`). The
single-node `RedbStore` and the Raft-backed `RaftStore` are interchangeable
adapters; both funnel every mutation through one deterministic `apply_command`.
See [`docs/DECISIONS.md`](docs/DECISIONS.md).

---

## Architecture

```
          ┌─ vault1 ─┐   ┌─ vault2 ─┐   ┌─ vault3 ─┐
client ──>│  API     │   │  API     │   │  API     │   reads: local redb
          │  redb    │<=>│  redb    │<=>│  redb    │   writes: Raft → leader
          └──────────┘   └──────────┘   └──────────┘            → quorum → apply
                    openraft consensus (HTTP RPC)
```

- The **leader** is the equivalent of a primary: it accepts writes, replicates
  the log to followers, and runs the rotation worker. A follower transparently
  forwards writes to the current leader.
- Each node persists everything to its own redb file (`VAULT_DB_PATH`).
- Nodes find each other through `VAULT_PEERS` (an `id=host:port` cluster map,
  identical on every node); a node's own identity is `NODE_ID`.

---

## Quick start (local dev, no AWS)

```bash
# Build + test the security core and store (no cluster needed)
cargo test --workspace

# Bring up a 3-node Raft cluster (KMS in local dev mode)
cd docker && cp .env.example .env && docker compose up --build
```

APIs listen on `localhost:8200` (vault1), `:8201` (vault2), `:8202` (vault3);
Raft RPC runs on the internal `:7400` of each node. See
[`docs/API.md`](docs/API.md) for full request/response examples.

```bash
# Mint a first admin token by setting VAULT_BOOTSTRAP_TOKEN on the nodes,
# then use it (the dev compose seeds 'dev-admin-token-change-me' via the e2e overlay):
TOKEN=dev-admin-token-change-me

# Create a manual secret
curl -sS -X POST localhost:8200/v1/secrets \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name":"db/password","kind":"manual","value":"s3cr3t"}'

# Read it back (must come from an allowlisted IP)
curl -sS localhost:8200/v1/secrets/db/password

# Create an auto-rotating secret with a 24h interval and 1h grace
curl -sS -X POST localhost:8200/v1/secrets \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name":"svc/api-key","kind":"automatic","rotation_interval_secs":86400,"grace_period_secs":3600}'
```

---

## Configuration (environment)

| Variable | Default | Description |
|----------|---------|-------------|
| `NODE_ID` | `1` | This node's id (Raft node id + audit label). The only value that differs per node. |
| `VAULT_PEERS` | *(empty)* | Cluster map `id=host:port,…` of the **Raft** addresses, identical on every node. One entry (or empty) ⇒ single-node, Raft disabled; two or more ⇒ replicated cluster. |
| `VAULT_API_PORT` | `8200` | Public REST API bind port (`0.0.0.0:PORT`). The external address is whatever your load balancer / port mapping exposes. |
| `VAULT_DB_PATH` | `vault.redb` | Path to this node's redb file. |
| `VAULT_BOOTSTRAP_TOKEN` | — | If set, seeds a `bootstrap-admin` token (mapped to the built-in `admin` role) on startup. Set the same value on every node for a fresh cluster, then rotate it. |
| `VAULT_ALLOWED_IPS` | *(empty → deny all reads)* | Comma-separated IPv4 / CIDR allowed to **read** secrets. |
| `VAULT_TRUST_PROXY` | `false` | Trust `X-Forwarded-For` for the client IP (only behind a trusted proxy). |
| `VAULT_READ_CONSISTENCY` | `local` | `local` (read from this node) or `linearizable` (route reads through the leader). |
| `VAULT_KMS_MODE` | `aws` | `aws` (production) or `local` (dev only). |
| `VAULT_KMS_KEY_ID` | — | AWS KMS key id/ARN (required for `aws`). |
| `VAULT_LOCAL_MASTER_KEY` | — | base64 32-byte master key for `local` mode. |
| `VAULT_ROTATION_POLL_SECS` | `15` | How often the leader scans for due rotations. |
| `VAULT_DEK_CACHE_TTL_SECS` | `300` | TTL of the in-memory decrypted-DEK cache. `0` disables. |
| `VAULT_KMS_MAX_RETRIES` | `5` | Retry KMS calls up to N times with exponential backoff. `0` disables. |
| `VAULT_AUTH_MAX_FAILURES` | `5` | Failed auth/authz attempts (per client IP) before lockout. `0` disables. |
| `VAULT_AUTH_LOCKOUT_SECS` | `900` | How long a locked-out IP stays locked. |
| `VAULT_AUTH_WINDOW_SECS` | `300` | Window over which failures accumulate. |

For AWS mode, AWS credentials and region come from the standard AWS SDK
environment (`AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, or an
instance role) — not from `VAULT_*` variables. The key's IAM policy needs only
`kms:GenerateDataKey` and `kms:Decrypt`.

---

## Security

This is security-critical software. Read [`docs/SECURITY.md`](docs/SECURITY.md)
and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) before deploying.

## Docs

- [docs/DECISIONS.md](docs/DECISIONS.md) - decisions
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - architecture
- [docs/SECURITY.md](docs/SECURITY.md) - security
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) - threat model
- [docs/API.md](docs/API.md) - REST API
- [docs/WIREGUARD.md](docs/WIREGUARD.md) - optional admin access over WireGuard

## License

GPL-3.0-or-later. See [`LICENCE`](LICENCE).
