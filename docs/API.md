# REST API

Base URL: `http://<node>:8200`. All bodies are JSON.

- **Reads** (`GET /v1/secrets/{name}`, `POST /v1/secrets/{name}/verify`) require
  the client IP to be in `VAULT_ALLOWED_IPS`.
- **Management** (`POST/PUT/DELETE /v1/secrets`, `/rotate`) requires
  `Authorization: Bearer <admin-token>`.

## Errors

`{ "error": "<message>" }` with status `400` (bad request), `401`
(unauthorized), `403` (IP not allowed), `404` (not found), `409` (name
conflict), `500` (internal — detail is logged, not returned).

## Endpoints

### `POST /v1/secrets` — create *(admin)*

```json
{
  "name": "db/password",
  "kind": "manual",
  "value": "s3cr3t",
  "description": "primary db password"
}
```

Automatic secret (value optional; generated if omitted):

```json
{
  "name": "svc/api-key",
  "kind": "automatic",
  "rotation_interval_secs": 86400,
  "grace_period_secs": 3600
}
```

`201 Created` →

```json
{ "name": "svc/api-key", "kind": "automatic", "version": 1, "value": "f3q...", "created_at": "2026-06-13T12:00:00+00:00" }
```

### `GET /v1/secrets/{name}` — read current value *(reader, IP-allowlisted)*

```json
{ "name": "db/password", "kind": "manual", "version": 1, "value": "s3cr3t", "created_at": "..." }
```

### `GET /v1/secrets` — list metadata *(admin)*

Returns metadata only (no plaintext) for every secret.

### `PUT /v1/secrets/{name}` — update *(admin)*

Any field optional. Supplying `value` creates a new version; the previous
version is kept valid for `grace_period`.

```json
{ "value": "n3w-s3cr3t", "description": "rotated manually" }
```

Returns the updated metadata.

### `DELETE /v1/secrets/{name}` — delete *(admin)*

`204 No Content`. Cascades to all versions and pending jobs.

### `POST /v1/secrets/{name}/rotate` — rotate now *(admin)*

Valid for **automatic** secrets only (manual secrets are changed via `PUT`).
Generates a new version, supersedes the old one with a grace window, and resets
`next_rotation_at`. Returns the new `SecretValue`.

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
still accepted during rotation.

### `GET /healthz` / `GET /readyz`

Liveness (`ok`) and readiness (`ready`, checks a DB connection).
