# Security

## Controls overview

| Control | Where | Notes |
|---------|-------|-------|
| Encryption at rest | API + KMS | XChaCha20-Poly1305 over a KMS-wrapped DEK; only ciphertext on disk. |
| Key management | AWS KMS | Master key never leaves KMS; DEKs are per-version and zeroized after use. |
| Read authorization | API | IPv4/CIDR allowlist, fail-closed. |
| Management authorization | API | Admin bearer tokens (SHA-256 fingerprints, constant-time check) + RBAC. |
| Tamper resistance | core | AEAD authentication tag; AAD binds ciphertext to `name:version`. |
| Replication integrity | raft | Writes are committed via Raft consensus to a quorum before they are acknowledged. |
| Auditing | API | Per-node `audit_log` records actor, client IP, action, outcome. |
| Memory hygiene | core | `Zeroizing` for DEKs and master keys. |
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
  admin surfaces off the public internet.
- **API**: terminate TLS at the API or a trusted local proxy. If a proxy sets
  the client IP, enable `VAULT_TRUST_PROXY=true` **only** when the proxy is
  trusted and strips inbound `X-Forwarded-For`; otherwise the allowlist can be
  spoofed.

## Admin token lifecycle

Tokens are 256-bit random strings; only `sha256(token)` is stored, compared in
constant time. Issue them via `POST /v1/tokens` (the raw token is returned once),
distribute over a secure channel, and revoke via `DELETE /v1/tokens/{name}`
(sets `revoked_at`). The plaintext token is never persisted.
