# Security

## Controls overview

| Control | Where | Notes |
|---------|-------|-------|
| Encryption at rest | API + KMS | XChaCha20-Poly1305 over a KMS-wrapped DEK; only ciphertext on disk. |
| Key management | AWS KMS | Master key never leaves KMS; DEKs are per-version and zeroized after use. |
| Read authorization | API | IPv4/CIDR allowlist, fail-closed. |
| Management authorization | API | Admin bearer tokens (SHA-256 fingerprints, constant-time check) + RBAC. |
| Lockout separation | API | A wrong value presented to `/verify` counts against that sending address and secret only, so it cannot revoke the caller's secret reads or management access. |
| Unforgeable lockout key | API | Both lockout counters are keyed on the TCP peer address, never on `X-Forwarded-For`. |
| Rotation ordering | API | A rotated password is committed to the vault before it is sent to the external system, so a failure never leaves a credential only the external system knows. |
| Tamper resistance | core | AEAD authentication tag; AAD binds ciphertext to `name:version`. |
| Peer authentication | raft | Optional shared credential on every node-to-node request, plus an optional source-address check. Both off by default; see Transport security. |
| Replication integrity | raft | Writes are committed via Raft consensus to a quorum before they are acknowledged. `POST /v1/restore` is replicated the same way, as a single log entry. |
| Storage key integrity | store | Secret names and version numbers are validated on every write path — create, restore and snapshot install — so one secret's version rows can never fall inside another's scan range. |
| Auditing | API | Per-node `audit_log` records actor, client IP, action, outcome. Each append takes the next key above the highest plausible one, so a tampered row cannot stop the log from growing. |
| Memory hygiene | core | `Zeroizing` for DEKs and master keys. |
| Rotation targets | API | A `pg_replica` target may only reach hosts listed in `VAULT_PG_TARGET_HOSTS`, and its `login_secret` must be covered by the creating token's role. |
| KMS-outage resilience | API | In-memory unwrapped-DEK cache (`VAULT_DEK_CACHE_TTL_SECS`); plaintext is never cached. |

## Key management

- Production uses `VAULT_KMS_MODE=aws` with `VAULT_KMS_KEY_ID`. Grant the API's
  IAM principal only `kms:GenerateDataKey` and `kms:Decrypt` on that key (add
  `kms:ListKeyRotations` and `kms:ReEncryptFrom`/`kms:ReEncryptTo` if the re-wrap
  worker below is enabled). AWS credentials and region come from the standard AWS
  SDK environment, not from `VAULT_*` variables.
- `local` mode (`VAULT_LOCAL_MASTER_KEY`, base64 32 bytes) is for development
  and tests **only**. Without the env var a random ephemeral master key is used
  and all secrets become undecryptable on restart — by design, to make misuse
  obvious. In a cluster, every node must share the same master key.
- DEKs are generated per secret version, used once to seal, and zeroized.

## KMS key rotation & re-wrapping

- **Automatic CMK rotation is transparent.** Each version stores the `kms_key_id`
  that wrapped its DEK; decrypt uses that stored id, not the configured one. AWS
  retains old key material under the same ARN, so existing versions keep
  decrypting after a rotation with no action required.
- **Re-wrap worker (optional).** When `VAULT_KMS_REWRAP_ENABLED=true`, a
  leader-gated worker polls `kms:ListKeyRotations` (every `VAULT_KMS_REWRAP_POLL_SECS`,
  default daily). When it sees a newer rotation than the persisted watermark it
  `ReEncrypt`s every live version's wrapped DEK onto the current CMK material —
  the plaintext DEK never leaves KMS and the ciphertext/nonce/AAD are untouched.
  Progress is tracked per version (`wrapped_rotation_at`) so a pass is resumable
  and idempotent; pacing is bounded by `VAULT_KMS_REWRAP_MAX_PER_SEC`.
- `POST /v1/admin/kms/rewrap` forces a pass; `GET /v1/admin/kms/rewrap/status`
  reports pending versions. Both require an admin token.
- **Rollout:** the worker introduces new Raft commands. Deploy the release with
  `VAULT_KMS_REWRAP_ENABLED=false`, roll every node, then enable it — so a new
  command is never replicated to a node that cannot decode it. Enabling adopts
  the current rotation as the baseline without an initial sweep; the first
  re-wrap happens on the next rotation (or a manual force).

## Bootstrap & access control

- The built-in `admin` role is seeded on first start. To mint the first admin
  token, start the node(s) with `VAULT_BOOTSTRAP_TOKEN=<token>` (the same value
  on every node); it creates a `bootstrap-admin` token mapped to `admin`. Use it
  to create real per-service tokens via `POST /v1/tokens`, then rotate it.
- Management (`create/update/delete/rotate`, role/token admin) requires a bearer
  token whose role grants the action on the secret path. Reads are governed by
  the IP allowlist, not RBAC. Access invariants are enforced in the API process;
  the storage layer holds only ciphertext and is reachable only through it.

## Transport security

- **Raft RPC** between nodes is plain HTTP on the internal Raft port. Run the
  cluster on a private network; the WireGuard overlay
  ([`WIREGUARD.md`](WIREGUARD.md)) is the supported way to keep both the Raft and
  admin surfaces off the public internet. Three settings harden that port, and
  all three are off by default so that upgrading a running cluster changes
  nothing until you act:

  1. `VAULT_RAFT_BIND` — bind the port to one address instead of every
     interface.
  2. `VAULT_CLUSTER_TOKEN` and `VAULT_CLUSTER_AUTH_REQUIRED` — a shared
     credential on every `/raft/*` request. Roll the token out to every node
     first, restarting them one at a time; then set the second variable on every
     node and restart again. Doing it in the other order refuses requests from
     nodes that have not been rolled yet.
  3. `VAULT_RAFT_PEER_CHECK` — accept connections only from the addresses in
     `VAULT_PEERS`.

  Without the credential, anyone who can open a connection to that port can
  submit any state-machine command, including one that adds a working admin
  token. Requests are also refused when the vote inside them names a node id
  that is not a configured peer, or when an append or snapshot carries an
  uncommitted vote.
- **Postgres rotation targets**: a `userpass` secret may carry a `pg_replica`
  `target`; on rotation the vault sends the `login_secret` username and password
  to that host to run `replica.rotate_credential`. The host must be listed in
  `VAULT_PG_TARGET_HOSTS`; when that variable is unset the node seeds the list
  from the targets already stored in its database, so a target can never name a
  host an operator has not already used. The token creating the secret must hold
  a permission rule covering the `login_secret` path, and a non-admin token may
  only name its own secret's `username` as the Postgres `role`. Without those
  limits a token with only `create` on one path could make the vault decrypt any
  other secret and send it to a host of its choosing. Set
  `VAULT_PG_TARGET_TLS=verify-full` to also require a verified TLS connection;
  the default `prefer` uses TLS only when the Postgres server offers it.
- **API**: terminate TLS at the API or a trusted local proxy. If a proxy sets
  the client IP, enable `VAULT_TRUST_PROXY=true` **only** when the proxy is
  trusted and strips inbound `X-Forwarded-For`; otherwise the read allowlist can
  be spoofed. The lockout counters are not affected by that header: they are
  keyed on the address of the TCP connection, so a forged header cannot lock out
  another client and cannot clear the sender's own failures.

## Admin token lifecycle

Tokens are 256-bit random strings; only `sha256(token)` is stored, compared in
constant time. Issue them via `POST /v1/tokens` (the raw token is returned once),
distribute over a secure channel, and revoke via `DELETE /v1/tokens/{name}`
(sets `revoked_at`). The plaintext token is never persisted.
