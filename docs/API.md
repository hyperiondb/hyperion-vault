# REST API

Base URL: `http://<node>:8200`. All bodies are JSON.

- **Reads** (`GET /v1/secrets/{name}`, `POST /v1/secrets/{name}/verify`) require
  the client IP to be in `VAULT_ALLOWED_IPS`. Reads are **not** RBAC-gated.
- **Management** (`POST/PUT/DELETE /v1/secrets`, `/rotate`), **role/token
  administration**, and **backup/restore** (`GET /v1/backup`, `POST /v1/restore`)
  require `Authorization: Bearer <token>`. Each token maps to a **role** whose
  permissions decide which actions it may take on which secret paths — see
  [Roles & access control](#roles--access-control). Backup/restore require the
  built-in `admin` role.
- Repeated auth/authz failures from an IP trigger a **lockout** (HTTP `429`).

## Errors

`{ "error": "<message>" }` with status `400` (bad request), `401`
(unauthorized), `403` (IP not allowed, or role lacks permission), `404` (not
found), `409` (name conflict), `429` (too many failed attempts — IP locked
out), `500` (internal — detail is logged, not returned).

## Secret formats

Every secret has a `format`, present in all responses:

- **`opaque`** — the original single-string `value` secret.
  Used when you send `value`, or neither `value` nor `username`. Existing
  callers need to change nothing.
- **`userpass`** — a username/password pair stored as **one** secret, so a
  service fetches both credentials in a single read/write. Selected by sending
  `username`. The pair is sealed together; on automatic rotation only the
  **password** changes — the **username is preserved** across versions.

`format` is fixed at creation: an `opaque` secret cannot later accept
`username`/`password`, and a `userpass` secret rejects `value` (`400`).

## Roles & access control

Management is **role-based**. Every bearer token belongs to a role; a role is
either a **superuser** (`is_admin`) or carries a list of permission rules.

- A **permission rule** is an `action` on a secret-path `pattern`:
  - `action` ∈ `create`, `update`, `delete`, `rotate`, or `*` (all).
  - `pattern` is an exact secret name, a prefix glob ending in `*`
    (e.g. `stripe/*`), or `*` (everything).
- `create/update/delete/rotate` on secret `name` is allowed iff the role is
  `is_admin`, **or** some rule matches both the action and `name`.
- The built-in **`admin`** role (seeded at install) is `is_admin` and is the
  **only** role allowed to call the role/token endpoints below.
- **Reads are not RBAC-gated** — `GET`/`verify` are governed solely by the IP
  allowlist. RBAC applies to writes and management.
- `GET /v1/secrets` (list) is filtered to the secrets the caller's role can act
  on (a superuser sees all).

Example: a `payment` role with rule `{ "action": "*", "path": "stripe/*" }` can
fully manage `stripe/...` secrets and nothing else.

### Lockout

There are two separate counters, both using `VAULT_AUTH_MAX_FAILURES`,
`VAULT_AUTH_WINDOW_SECS` and `VAULT_AUTH_LOCKOUT_SECS`, and both kept **per
node**. Set `VAULT_AUTH_MAX_FAILURES=0` to disable both.

| Counter | Counts | What it blocks when it trips |
| --- | --- | --- |
| Per sending address | Missing or invalid token, IP-denied read, permission denied | Every request from that address returns `429` |
| Per sending address and secret name | A value presented to `/verify` that does not match | Only `/verify` for that address and that secret returns `429` |

Both counters use the address of the TCP connection the request arrived on, not
the address in `X-Forwarded-For`, even when `VAULT_TRUST_PROXY=true`. A caller
therefore cannot charge its failures to another client, and cannot clear its own
by changing the header. The forwarded address is still what the read allowlist
and the audit log use.

The second counter exists because the value presented to `/verify` comes from
whoever is talking to the calling service, not from the caller. Wrong
presentations therefore cannot cost a service its ability to read its own
secrets.

## Secret names

A name may contain `A-Za-z0-9`, `-`, `_`, `.` and `/`, and is 1 to 255 bytes
long. A `/` is an ordinary character, not a hierarchy the vault interprets, but
it must separate two non-empty segments: a name may not start or end with `/`,
and no segment may be empty, `.` or `..`. So `db/password` is accepted and
`a//b`, `a/./b`, `a/../b`, `/a` and `a/` are refused with `400`.

A name containing `/` is used verbatim in its own URL —
`GET /v1/secrets/db/password` works. Percent-encoding the slash
(`db%2Fpassword`) also works and means the same thing.

## Endpoints

### `POST /v1/secrets` — create *(admin)*

**Opaque** — a single value:

```json
{
  "name": "db/password",
  "kind": "manual",
  "value": "s3cr3t",
  "description": "primary db password"
}
```

Automatic opaque secret (value optional; generated if omitted):

```json
{
  "name": "svc/api-key",
  "kind": "automatic",
  "rotation_interval_secs": 86400,
  "grace_period_secs": 3600
}
```

**Username/password** — an *optional alternative* to `value`; the opaque form
above still works exactly as before. Sending `username` makes this one secret a
`userpass` pair:

```json
{
  "name": "db/app",
  "kind": "manual",
  "username": "app",
  "password": "s3cr3t"
}
```

Automatic pair — `password` is optional (generated if omitted) and is the field
that rotates; `username` is kept across rotations:

```json
{
  "name": "svc/db-user",
  "kind": "automatic",
  "username": "svc",
  "rotation_interval_secs": 86400,
  "grace_period_secs": 3600
}
```

A value must not be empty: `"value": ""` is refused with `400`, and so is an
empty `username` or `password`.

`201 Created` returns the value (opaque) or the pair (userpass):

```json
{ "name": "svc/api-key", "kind": "automatic", "format": "opaque", "version": 1, "value": "f3q...", "created_at": "2026-06-13T12:00:00+00:00" }
```

```json
{ "name": "db/app", "kind": "manual", "format": "userpass", "version": 1, "username": "app", "password": "s3cr3t", "created_at": "..." }
```

#### Rotation targets — applying a rotated password to Postgres (`target`)

An optional `target` on a `userpass` secret makes the vault **apply the new
password to an external system on every rotation**, so the rotated credential is
not just stored but actually takes effect. The only target type today is
`pg_replica`: on rotation the leader connects to the cluster's **writable
primary** (it tries each `hosts` entry; `ALTER ROLE` only succeeds on the
primary) and runs `ALTER ROLE "<role>" PASSWORD '<new>'`, **then** commits the
new version. If the `ALTER ROLE` fails the rotation is aborted and retried, so
the vault and Postgres never silently diverge. The superseded version stays
valid for `grace_period_secs` so readers can pick up the new password.

On rotation the new version is committed to the vault **first** and applied to
Postgres second. If the apply fails, the vault holds a password Postgres has not
accepted yet, the call returns `500`, and the secret is scheduled for another
attempt about a minute later instead of waiting a full interval. The next
attempt authenticates with the previous stored password, so give a secret with a
target a `grace_period_secs` large enough to keep that previous version around —
with a grace of `0` the previous version is removed on the next worker tick and
the vault can no longer authenticate to fix the mismatch.

`target` fields:

| field | meaning |
| --- | --- |
| `type` | `"pg_replica"` (required) |
| `hosts` | `["host:port", …]` of the Postgres nodes; the primary is auto-detected |
| `database` | database to connect to (default `postgres`) |
| `role` | role whose password to set (default: the secret's `username`). A non-admin token may only name the secret's own `username`; an admin token may name any role. |
| `login_secret` | a vault `userpass` secret to authenticate the `ALTER ROLE` connection; omit to authenticate as the rotating secret itself. The calling token's role must cover this secret's path, otherwise the create returns `403`. |

Three limits apply to every `pg_replica` target, because the vault sends the
`login_secret` credential in plaintext to the host named in the target:

- **Host allowlist.** Every entry in `hosts` must appear in the operator's
  `VAULT_PG_TARGET_HOSTS` (comma-separated `host:port`; a missing port means
  `5432`). A target with any other host is rejected with `400` at create time and
  refused again at rotation time. When `VAULT_PG_TARGET_HOSTS` is not set, the
  node seeds the allowlist at startup from the hosts already used by stored
  targets — so an upgraded node keeps rotating the secrets it already had, while
  a target naming a new host is still refused.
- **Authorization of `login_secret`.** The token creating the secret must hold a
  permission rule whose path covers `login_secret`. A token with
  `{"action":"create","path":"myapp/*"}` cannot point `login_secret` at
  `db/root`. A non-admin token also may not set `role` to anything other than the
  secret's own `username`.
- **TLS.** `VAULT_PG_TARGET_TLS` controls the connection: `verify-full` requires
  TLS and verifies the server certificate chain and hostname (against the system
  trust store, or `VAULT_PG_TARGET_CA_FILE`); `prefer` (the default) uses TLS
  when the Postgres server offers it and plaintext when it does not; `disable`
  always connects in plaintext. Use `verify-full` unless the network itself is
  trusted, such as the WireGuard overlay.

The **app/superuser role** authenticates as itself (omit `login_secret`):

```json
{
  "name": "pg/app",
  "kind": "automatic",
  "username": "app",
  "password": "<current password>",
  "rotation_interval_secs": 2592000,
  "grace_period_secs": 86400,
  "target": {
    "type": "pg_replica",
    "hosts": ["10.98.0.3:5432", "10.98.0.2:5432", "10.98.0.4:5432"],
    "database": "postgres"
  }
}
```

The **replicator role** is altered by authenticating as the superuser
(`login_secret`); each node's `pg_replica` rewrites its local passfile:

```json
{
  "name": "pg/replicator",
  "kind": "automatic",
  "username": "replicator",
  "password": "<current REPL_PASS>",
  "rotation_interval_secs": 2592000,
  "grace_period_secs": 86400,
  "target": {
    "type": "pg_replica",
    "hosts": ["10.98.0.3:5432", "10.98.0.2:5432", "10.98.0.4:5432"],
    "database": "postgres",
    "role": "replicator",
    "login_secret": "pg/app"
  }
}
```

> Seed `password` with the role's **current** password so the vault and Postgres
> agree from the start; the first rotation then generates fresh material. Targets
> apply on **rotation** (scheduled or `POST /rotate`), not on a manual `PUT`.

#### CiqadaMQ secrets (no target)

CiqadaMQ's secrets are plain rotating `opaque` secrets — no target; ciqadamq and
its clients read them and refresh on their own (the broker accepts the current
and previous token across the grace window, and the pepper change self-heals via
the argon2 fallback):

```json
{ "name": "ciqada/api-token", "kind": "automatic", "rotation_interval_secs": 2592000, "grace_period_secs": 86400 }
```

```json
{ "name": "ciqada/pepper", "kind": "automatic", "value": "<current pepper>", "rotation_interval_secs": 2592000, "grace_period_secs": 86400 }
```

All four are also created in one shot by `scripts/vaultProvision.mts` in the
server-backend repo (seeds from the current environment).

### `GET /v1/secrets/{name}` — read current value *(reader, IP-allowlisted)*

Opaque:

```json
{ "name": "db/password", "kind": "manual", "format": "opaque", "version": 1, "value": "s3cr3t", "created_at": "..." }
```

Userpass — both credentials in one read:

```json
{ "name": "db/app", "kind": "manual", "format": "userpass", "version": 1, "username": "app", "password": "s3cr3t", "created_at": "..." }
```

### `GET /v1/secrets` — list metadata *(admin)*

Returns metadata only (no plaintext) for every secret. Each entry includes
`kind`, `format`, `version`, rotation settings, and timestamps.

### `PUT /v1/secrets/{name}` — update *(admin)*

Any field optional. Changing the secret material creates a new version; the
previous version is kept valid for `grace_period`.

Opaque — supply `value`:

```json
{ "value": "n3w-s3cr3t", "description": "rotated manually" }
```

Userpass — supply `username` and/or `password`; any field you omit is carried
over from the current version (e.g. change only the password):

```json
{ "password": "n3w-pass" }
```

Returns the updated metadata (includes `format`).

### `DELETE /v1/secrets/{name}` — delete *(admin)*

`204 No Content`. Cascades to all versions and pending jobs.

### `POST /v1/secrets/{name}/rotate` — rotate now *(admin)*

Valid for **automatic** secrets only (manual secrets are changed via `PUT`).
Generates a new version, supersedes the old one with a grace window, and resets
`next_rotation_at`. Returns the new `SecretValue`. For a `userpass` secret only
the **password** is regenerated; the **username carries over**.

### `POST /v1/secrets/{name}/verify` — validate a presented value *(reader, IP-allowlisted)*

```json
{ "value": "f3q..." }
```

→

```json
{ "valid": true, "version": 2 }
```

Checks the presented value (constant-time) against every **currently-valid**
version — the current one plus any superseded version still inside its grace
window. This is how a dependent service confirms an old automatic secret is
still accepted during rotation. For a `userpass` secret, `value` is matched
against the **password**. An empty `value` always returns `valid: false` and
counts as a failed attempt for the lockout.

### Role & token administration *(admin role only)*

All require a token whose role is `is_admin`; otherwise `403`.

#### `POST /v1/roles` — create a role

```json
{
  "name": "payment",
  "description": "manage Stripe secrets",
  "is_admin": false,
  "permissions": [ { "action": "*", "path": "stripe/*" } ]
}
```

`201 Created` → the `RoleInfo` (`name`, `description`, `is_admin`, `permissions`, `created_at`).

#### `GET /v1/roles` — list · `GET /v1/roles/{name}` — one role

Returns `RoleInfo` objects, permissions included.

#### `PUT /v1/roles/{name}/permissions` — replace a role's rules

```json
{ "permissions": [ { "action": "create", "path": "stripe/*" }, { "action": "rotate", "path": "stripe/*" } ] }
```

#### `DELETE /v1/roles/{name}` — delete a role

`204 No Content`. The built-in `admin` role cannot be deleted (`400`); a role
that still has tokens cannot be deleted (`409`) — revoke them first.

#### `POST /v1/tokens` — issue a token for a role

```json
{ "name": "payments-svc", "role": "payment" }
```

`201 Created` → **the raw token, shown once** (only its SHA-256 is stored):

```json
{ "name": "payments-svc", "role": "payment", "token": "f3q..." }
```

#### `GET /v1/tokens` — list · `DELETE /v1/tokens/{name}` — revoke

List returns metadata only (name, role, timestamps — never the token). Delete
sets `revoked_at` (`204`).

### Bootstrap the first token

Issuing tokens needs an admin token. Seed the first one by starting the node(s)
with `VAULT_BOOTSTRAP_TOKEN=<token>` set (the same value on every node): on
startup it creates a `bootstrap-admin` token mapped to the built-in `admin` role.
Use it to create real per-service tokens via `POST /v1/tokens`, then rotate it.

### `POST /v1/batch/secrets` — read many secrets at once *(reader, IP-allowlisted)*

Body — a list of names:

```json
{ "names": ["db/password", "svc/api-key"] }
```

Returns an array of `SecretValue` (same shape as `GET /v1/secrets/{name}`) for the
names that exist; missing names are omitted. IP-allowlisted like single reads (not
RBAC-gated). Capped at 256 names per request.

### Backup & restore *(admin role only)*

Both require a token whose role is `is_admin`; otherwise `403`. No cron or
background worker is involved — backup and restore are plain API calls.

#### `GET /v1/backup` — export a full snapshot

Returns a JSON snapshot of every data table — secrets, secret versions, roles,
tokens, the name index, and the local `audit_log` — as stored on the node that
serves the request. Taken under a single read transaction, so it is a
**consistent, point-in-time** view and does not block writes.

**Secret values stay encrypted.** The snapshot contains only the sealed records
(`{wrapped_dek, nonce, ciphertext, aad, kms_key_id}`), never plaintext —
decrypting a restored secret still requires the KMS key. Secret **names**, role
definitions, token **fingerprints** (SHA-256, not the tokens themselves), and
audit entries are in cleartext, so treat the artifact as sensitive and encrypt
it (e.g. `age`/`restic`) before it leaves the host.

Call the **leader** for the most up-to-date committed state. Response body:

```json
{ "version": 1, "secrets": [], "versions": [], "roles": [], "tokens": [], "tokens_by_name": [], "audit": [] }
```

(Each list holds `[key, bytes]` pairs of the raw stored rows; `version` is the
snapshot schema version.)

#### `POST /v1/restore` — import a snapshot

Body is a snapshot produced by `GET /v1/backup`. **Replaces** (not merges) every
data table on the node with the snapshot's contents. `204 No Content` on success;
`400` if `version` is not supported.

On a cluster the restore is **replicated**: it travels as one Raft log entry, so
every node replaces its tables at the same point in the log and no node
diverges. Call it on any node; a follower forwards it to the leader like any
other write. A single-node deployment writes it directly.

Because it is one log entry, a replicated restore is limited to 8 MiB of encoded
snapshot, half the node-to-node body limit. A larger snapshot returns `400` with
the measured size. Restoring one that big means taking the cluster down: stop
every node, delete each node's redb file, restore the snapshot into each node
started alone with `VAULT_PEERS` unset, then start the cluster.

The restore rejects a snapshot containing a secret name outside
`[A-Za-z0-9-_/.]`, a version row whose key does not belong to a secret in it, or
an audit key above the plausible range. A rejected restore changes nothing.

Because restore is a full replace, an older snapshot that predates your current
admin token will remove it: the token used for the restore call is already
authenticated so the call itself succeeds, but subsequent calls need a token that
exists in the restored set.

### `GET /healthz` / `GET /readyz`

Liveness (`ok`) and readiness (`ready`, checks the local store).
