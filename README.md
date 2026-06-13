# HyperionDB Vault (`hyperion-vault`)

A **PostgreSQL secrets vault** for HyperionDB clusters: a `CREATE EXTENSION`
that stores secrets **encrypted at rest** plus a co-located **REST API** to
create, read, update, delete, and **automatically rotate** them.

Secrets are sealed with **envelope encryption** — a per-secret data key (DEK)
protected by **AWS KMS**, with the secret bytes sealed under
**XChaCha20-Poly1305**. PostgreSQL only ever stores
ciphertext, the wrapped DEK, and a nonce; plaintext never touches disk or WAL.

Built to run **on every member of a [`hyperiondb`](https://github.com/hyperiondb/hyperiondb) cluster**:
reads are served locally from any node, while writes are transparently routed
to the current primary and replicated byte-for-byte to the rest.

Comparable to [supabase/vault](https://github.com/supabase/vault) (in-database
secrets) and [OpenBao](https://openbao.org/) (KMS-backed envelope encryption +
API + rotation) — this project combines both models for a replicated Postgres
cluster.

Status: **in progress**

---

## Features

- **Encryption at rest, KMS-backed.** Envelope encryption: AWS KMS wraps a
  256-bit data key (via `GenerateDataKey`/`Decrypt`); the secret is sealed with
  XChaCha20-Poly1305. Postgres stores only `{wrapped_dek, nonce, ciphertext}`.
- **Two secret kinds.**
  - **`manual`** — set and changed explicitly through the API.
  - **`automatic`** — rotated on a schedule by a background worker. Old
    versions stay valid for a configurable **grace period**, so dependent
    services can keep authenticating with the previous secret during cutover.
- **REST API.** `POST/GET/PUT/DELETE /v1/secrets`, plus `/rotate` and a
  constant-time `/verify` endpoint for grace-window validation.
- **Cluster-native (works with `hyperiondb`).** The API runs on every node.
  **Reads** (`GET`, `verify`) are served from the local node; **writes**
  (create/update/delete/rotate) are routed to the **current primary** via a
  multi-host libpq pool with `target_session_attrs=read-write`, so they work
  from *any* member and follow failover automatically.
- **IP allowlist for reads.** Secret reads are permitted only from an
  IPv4/CIDR allowlist supplied via `VAULT_ALLOWED_IPS`. **Fail-closed**: an
  empty allowlist denies all reads.
- **Admin token auth for management.** `create/update/delete/rotate` require an
  admin bearer token. Tokens are stored only as SHA-256 fingerprints and
  checked in constant time.
- **Automatic rotation.** An in-database background worker (running only on the
  primary) enqueues due rotations and `NOTIFY`s; the API's rotation worker
  performs the re-encryption and expires superseded versions after grace.
- **Audit log.** Every operation is recorded (actor, client IP, action,
  outcome) in `vault.audit_log`.
- **Defense in depth.** Row-level security on every table, a dedicated service
  role, version-bound AEAD associated data (a ciphertext can't be replayed
  under another secret name or version), and zeroized key material in memory.
- **Extensive security tests.** The `hyperion-vault-core` crate carries a
  property-style security suite (tamper detection, nonce uniqueness, AAD
  binding, fail-closed allowlist, constant-time tokens, grace-window
  correctness); a Docker-based end-to-end suite covers the API and cluster.

---

## Workspace layout

| Crate / dir | Kind | Purpose |
|-------------|------|---------|
| `crates/hyperion-vault-core` | lib | Pure-Rust security core: AEAD envelope, IP allowlist, token auth, rotation policy. No DB, no network — fully unit-testable. |
| `crates/hyperion-vault-api` | bin | The REST API service (`axum`): handlers, IP/token guards, dual DB pools, KMS, rotation worker. |
| `crates/hyperion-vault` | lib | Umbrella crate re-exporting the security core as a single dependency. |
| `extension/` (`hyperion_vault`) | cdylib | The pgrx PostgreSQL extension: `vault` schema, RLS, helper functions, rotation supervisor background worker. |
| `docs/` | — | Architecture, decisions, threat model, API and security docs. |
| `docker/` | — | Dockerfile + 3-node `pg_replica` + vault compose stack. |
| `scripts/` | — | Test and security-test entrypoints. |

The encryption algorithm choice (XChaCha20-Poly1305), the application-layer
(vs in-database) encryption decision, and the primary-routing strategy are
documented in [`docs/DECISIONS.md`](docs/DECISIONS.md).

---

## How it fits with `pg_replica`

`pg_replica` (HyperionDB) provides **physical streaming replication** with
Raft-based automatic failover. Standbys are byte-for-byte copies and are
**read-only**; only the primary accepts writes. Roles, DDL, and table data all
replicate.

Vault leverages this directly:

- `CREATE EXTENSION hyperion_vault` on the primary creates the `vault` schema;
  the DDL **replicates to every node** automatically.
- Encrypted secret rows replicate like any other table → **any node can serve
  reads** (and decrypt locally via KMS).
- The API's writer pool uses `target_session_attrs=read-write`, so
  create/update/delete/rotate from **any node** land on the **current primary**
  and follow failover with no client changes.

---

## Quick start (local dev, no AWS)

```bash
# 1. Build + test the security core (no Postgres needed)
cargo test -p hyperion-vault-core

# 2. Bring up a 3-node pg_replica cluster with vault on each node
cd docker && cp .env.example .env && docker compose up --build
```

See [`docs/API.md`](docs/API.md) for full request/response examples and
[`docker/`](docker/) for the cluster topology.

```bash
# Create a manual secret (admin token required)
curl -sS -X POST localhost:8200/v1/secrets \
  -H "Authorization: Bearer $VAULT_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name":"db/password","kind":"manual","value":"s3cr3t"}'

# Read it back (must come from an allowlisted IP)
curl -sS localhost:8200/v1/secrets/db/password

# Create an auto-rotating secret with a 24h interval and 1h grace
curl -sS -X POST localhost:8200/v1/secrets \
  -H "Authorization: Bearer $VAULT_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name":"svc/api-key","kind":"automatic","rotation_interval_secs":86400,"grace_period_secs":3600}'
```

---

## Configuration (environment)

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_API_LISTEN` | `0.0.0.0:8200` | API bind address. |
| `VAULT_ALLOWED_IPS` | *(empty → deny all reads)* | Comma-separated IPv4 / CIDR allowed to **read** secrets. |
| `VAULT_TRUST_PROXY` | `false` | Trust `X-Forwarded-For` for the client IP (only behind a trusted proxy). |
| `VAULT_PG_HOSTS` | `127.0.0.1` | Comma-separated cluster hosts (multi-host libpq). |
| `VAULT_PG_PORT` | `5432` | Postgres port. |
| `VAULT_PG_USER` / `VAULT_PG_PASSWORD` / `VAULT_PG_DBNAME` | `vault_service` / — / `postgres` | Service-role connection. |
| `VAULT_KMS_MODE` | `aws` | `aws` (production) or `local` (dev only). |
| `VAULT_KMS_KEY_ID` | — | AWS KMS key id/ARN (required for `aws`). |
| `VAULT_LOCAL_MASTER_KEY` | — | base64 32-byte master key for `local` mode. |
| `VAULT_ROTATION_POLL_SECS` | `15` | How often the API worker claims rotation jobs. |

The extension is configured via GUCs: `hyperion_vault.rotation_enabled`,
`hyperion_vault.scan_interval_secs`, `hyperion_vault.database`.

---

## Security

This is security-critical software. Read [`docs/SECURITY.md`](docs/SECURITY.md)
and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) before deploying. TLS to
Postgres is **not** enabled by default in this scaffold and must be configured
for production.

## License

GPL-3.0-or-later. See [`LICENCE`](LICENCE).
