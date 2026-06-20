# REST API

Base URL: `http://<node>:8200`. All bodies are JSON.

- **Reads** (`GET /v1/secrets/{name}`, `POST /v1/secrets/{name}/verify`) require
  the client IP to be in `VAULT_ALLOWED_IPS`. Reads are **not** RBAC-gated.
- **Management** (`POST/PUT/DELETE /v1/secrets`, `/rotate`) and **role/token
  administration** require `Authorization: Bearer <token>`. Each token maps to a
  **role** whose permissions decide which actions it may take on which secret
  paths — see [Roles & access control](#roles--access-control).
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

Auth/authz failures (missing/invalid token, IP-denied read, permission denied)
are counted **per client IP, per node**. After
`VAULT_AUTH_MAX_FAILURES` within `VAULT_AUTH_WINDOW_SECS`, the IP is locked and
every request from it returns `429` until `VAULT_AUTH_LOCKOUT_SECS` elapse. Set
`VAULT_AUTH_MAX_FAILURES=0` to disable.

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

`201 Created` returns the value (opaque) or the pair (userpass):

```json
{ "name": "svc/api-key", "kind": "automatic", "format": "opaque", "version": 1, "value": "f3q...", "created_at": "2026-06-13T12:00:00+00:00" }
```

```json
{ "name": "db/app", "kind": "manual", "format": "userpass", "version": 1, "username": "app", "password": "s3cr3t", "created_at": "..." }
```

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
against the **password**.

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

### `GET /healthz` / `GET /readyz`

Liveness (`ok`) and readiness (`ready`, checks the local store).
