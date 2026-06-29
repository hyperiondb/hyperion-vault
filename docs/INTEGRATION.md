# Vault integration (A→Z)

How ciqadamq, pg_replica, and the Weido `server-backend` source their secrets
from hyperion-vault, and how a rotation reaches the live systems. This is the
runbook to go from the default state (secrets in env) to fully vault-managed.

## What is managed

| Secret | Format | Auto-rotates | Read by | How a rotation is applied |
| --- | --- | --- | --- | --- |
| `ciqada/api-token` | opaque | yes | ciqadamq broker + server-backend client | consumers re-read and refresh |
| `ciqada/pepper` | opaque | no (static) | ciqadamq broker | read once at boot; not rotated |
| `pg/app` | userpass | yes | server-backend DB pools | vault calls `replica.rotate_credential` on the primary |
| `pg/replicator` | userpass | **no — keep manual** | bootstrapped from `REPL_PASS` env at initdb | manual only (see [Limitations](#limitations)) |

Secret **reads** (`GET /v1/secrets/{name}`) are gated by `VAULT_ALLOWED_IPS`
only — no token. **Create/rotate** need an admin bearer token.

## How it works

**Read path.** Each consumer reads its secret(s) over the mesh by IP. There is
no bootstrap token needed to read a token — reads are network-gated.

**Rotation path (Postgres).** The vault is the source of truth and the generator.
A secret may carry a `target` (see [API.md](API.md#rotation-targets--applying-a-rotated-password-to-postgres-target)).
For a `userpass` secret with `target: pg_replica`, on rotation the leader:
1. generates the new password,
2. connects (as the `login_secret` role) to each `target.hosts` node and runs
   `SELECT replica.rotate_credential(role, new_password)` — the function no-ops
   on standbys (returns false) and runs `ALTER ROLE … PASSWORD …` on the
   primary, returning true,
3. commits the new version only after the primary accepted it.

So the vault never holds Postgres open or guesses the primary — pg_replica's
`rotate_credential` does the apply where it's writable.

**Rotation path (ciqada).** Nothing is pushed. The token rotates; ciqadamq
re-reads it from the vault on an **auth-miss** (a presented token it doesn't
recognize) and accepts the current **and** previous token during the grace
window; clients re-read on a `401`. The pepper is **static** — read once at boot,
not rotated.

**Consumer behavior.**
- **ciqadamq** — at boot (when `VAULT_ADDR` is set) reads `ciqada/api-token` and
  `ciqada/pepper`. The token refreshes on an auth-miss (re-reads from the vault
  and re-checks; accepts current+previous); the pepper is static. Falls back to
  env (`API_TOKEN` / `AUTH_PEPPER`) if the vault is unset/unreachable.
- **server-backend** — `utils/vault/creds.mts` reads `pg/app` and
  `ciqada/api-token` (cached, env fallback). The drizzle pool uses an async
  password callback; the parade pools (`hyperiondb-client`) rebuild themselves
  on an auth-failure (`28P01`) — fetch the fresh password, recreate the pool,
  retry. No polling.
- **pg_replica** — exposes `replica.rotate_credential(role, password)`. It does
  not call the vault; the vault calls in.

## From default state — step by step

Starting point: secrets live in env, the vault cluster is running, and the new
binaries are built but the integration is not yet active.

### 0. Prerequisites
- Vault reachable from every consumer; `VAULT_BOOTSTRAP_TOKEN` available for the
  provisioning call.
- `VAULT_ALLOWED_IPS` includes the ciqadamq nodes and `server-backend` (so reads
  are permitted), and the vault can reach the Postgres nodes on `:5432` (so it
  can run `ALTER ROLE`).
- The pg_replica extension build that includes `replica.rotate_credential` is
  deployed (it is a `shared_preload_libraries` extension, so this needs a
  Postgres restart).

### 1. Provision the secrets
From `server-backend`, with the current env values present (so the vault matches
what is already live), run:

```sh
yarn vault:provision      # tsx --env-file=.env ./scripts/vaultProvision.mts
```

It seeds (idempotent — existing secrets are skipped):
- `ciqada/api-token`, `ciqada/pepper` from `CIQADA_API_TOKEN` / `CIQADA_PEPPER`
- `pg/app` from `PG_USER`/`PG_PASS`, with `target: pg_replica`
- `pg/replicator` from `REPL_PASS`

`PG_DB` must be set when provisioning: it becomes `target.database`, the database
the vault connects to — it must be the DB where `CREATE EXTENSION pg_replica`
ran, or `replica.rotate_credential` will not be found.

> Provision `pg/replicator` as `manual`, not `automatic`, until passfile sync
> lands — see [Limitations](#limitations). (The script seeds it `automatic`;
> change its `kind` to `manual` or set no rotation interval.)

### 2. Configure & deploy the consumers
- **ciqadamq**: set `VAULT_ADDR=http://<vault-ip>:8205` on each broker container
  (already in the `docker-compose*.yml`). With it set, the broker reads from the
  vault; the `API_TOKEN`/`AUTH_PEPPER` env are no longer required.
- **server-backend**: keep `SERVER_PRIVATE_IP` and `VAULT_BOOTSTRAP_TOKEN`. The
  code reads `pg/app` and `ciqada/api-token` from the vault automatically. Keep
  `PG_USER`/`PG_DB` (identity, not secret) and `PG_PASS` (still feeds
  `DATABASE_URL` and is the fallback).
- **pg_replica**: nothing to configure — the function is always available once
  the extension build is deployed.

Deploy the new binaries (vault with the `target` apply, ciqadamq with the vault
client, pg_replica with `rotate_credential`, server-backend with the vault-backed
clients).

### 3. Verify
- ciqadamq logs: `api token loaded from vault secret 'ciqada/api-token'`.
- server-backend can read: `curl` an endpoint that hits ciqada / Postgres.
- In **staging**, force a rotation of `pg/app` and confirm: the vault audit shows
  `rotate ok`, a new connection authenticates, and `SELECT replica.status()`
  still reports a healthy primary.

### 4. (After verifying) drop the env fallbacks
Only once vault reads are confirmed in prod, remove the now-unused env from the
app/ciqada containers: `CIQADA_API_TOKEN` (app services), `API_TOKEN` +
`AUTH_PEPPER` (ciqada containers). **Keep** everything on the `paradedb`
container (the entrypoint requires it and it bootstraps the DB) and keep
`PG_PASS` (DATABASE_URL). Removing a fallback makes the vault a hard dependency
at boot — provision first.

## Configuration reference

| Where | Setting | Meaning |
| --- | --- | --- |
| ciqadamq | `VAULT_ADDR` | vault base URL; empty = stay on env |
| ciqadamq | `API_TOKEN`, `AUTH_PEPPER` | fallback only when the vault is unset/unreachable |
| vault | `VAULT_ALLOWED_IPS` | must include consumer IPs (reads are IP-gated) |
| server-backend | `SERVER_PRIVATE_IP`, `VAULT_BOOTSTRAP_TOKEN` | vault address + token for create/rotate |
| server-backend | `PG_USER`, `PG_DB`, `PG_PASS` | DB identity; `PG_PASS` also feeds `DATABASE_URL` and is the fallback |
| secret `target` | `hosts`, `database`, `role`, `login_secret` | how the vault reaches the pg cluster to apply a rotation |

Default rotation cadence (provisioning): interval 30 days, grace 1 day.

## Limitations

- **`pg/replicator` must not auto-rotate.** `rotate_credential` runs `ALTER ROLE`
  on the primary and `pg_authid` replicates over WAL, but each node's local
  libpq **passfile** (used by walreceiver / `pg_basebackup` / `pg_rewind`) is a
  plain file that is **not** replicated. Rotating the replicator password would
  therefore break streaming replication on the next standby reconnect. Keep it
  `manual` and coordinate passfile updates by hand, until per-node passfile sync
  is added.
- **Rare consistency window.** If `rotate_credential` succeeds but the vault's
  raft commit then fails, the vault and Postgres briefly disagree; the next
  rotation tick reconciles.
- **Manual `PUT` does not apply to Postgres.** Only rotation (scheduled or
  `POST /v1/secrets/{name}/rotate`) runs the target. To change a managed password
  by hand, rotate — don't `PUT`.
- **drizzle path** uses the vault only when `PG_HOST`/`PG_PORT` are set; otherwise
  it falls back to `DATABASE_URL`. The parade pools always use the vault.
