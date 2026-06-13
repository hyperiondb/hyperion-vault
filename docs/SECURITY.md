# Security

## Controls overview

| Control | Where | Notes |
|---------|-------|-------|
| Encryption at rest | API + KMS | XChaCha20-Poly1305 over a KMS-wrapped DEK; only ciphertext in Postgres/WAL. |
| Key management | AWS KMS | Master key never leaves KMS; DEKs are per-version and zeroized after use. |
| Read authorization | API | IPv4/CIDR allowlist, fail-closed. |
| Management authorization | API | Admin bearer tokens (SHA-256 fingerprints, constant-time check). |
| Tamper resistance | core | AEAD authentication tag; AAD binds ciphertext to `name:version`. |
| Least privilege in DB | extension | `REVOKE ALL FROM PUBLIC`, RLS `FORCE`d on all tables, scoped service-role policies. |
| Auditing | API + DB | `vault.audit_log` records actor, client IP, action, outcome. |
| Memory hygiene | core | `Zeroizing` for DEKs and master keys. |

## Key management

- Production uses `VAULT_KMS_MODE=aws` with `VAULT_KMS_KEY_ID`. Grant the API's
  IAM principal only `kms:GenerateDataKey` and `kms:Decrypt` on that key.
- `local` mode (`VAULT_LOCAL_MASTER_KEY`, base64 32 bytes) is for development
  and tests **only**. Without the env var a random ephemeral master key is used
  and all secrets become undecryptable on restart — by design, to make misuse
  obvious.
- DEKs are generated per secret version, used once to seal, and zeroized.

## Database role setup

The extension creates the schema and `REVOKE`s all access from `PUBLIC`. Create
a dedicated login role and grant it via the helper (run once on the primary;
roles and grants replicate to standbys):

```sql
CREATE EXTENSION IF NOT EXISTS hyperion_vault;
CREATE ROLE vault_service LOGIN PASSWORD '...';
SELECT vault.grant_service_role('vault_service');
```

`grant_service_role` grants table/sequence/function access and installs RLS
policies scoped to that role. RLS is `FORCE`d, so even a future table grant to
another role does not expose rows.

## Transport security

- **Postgres**: this scaffold connects with `NoTls`. For production, enable TLS
  (`sslmode=verify-full`) between the API and Postgres and configure
  certificates; do not run cross-host without it.
- **API**: terminate TLS at the API or a trusted local proxy. If a proxy sets
  the client IP, enable `VAULT_TRUST_PROXY=true` **only** when the proxy is
  trusted and strips inbound `X-Forwarded-For`; otherwise the allowlist can be
  spoofed.

## Admin token lifecycle

Tokens are created out-of-band (e.g. an admin bootstrap step inserts a
fingerprint). Generate with `hyperion_vault_core::auth::generate_token()`, store
`sha256(token)` in `vault.admin_tokens`, distribute the token over a secure
channel, and `UPDATE ... SET revoked_at = now()` to revoke. The plaintext token
is never persisted.

## Reporting

This is a scaffold; before production use, complete the items in
[`THREAT_MODEL.md`](THREAT_MODEL.md) marked as open, run the security test
suite (`scripts/test-security.sh`), and have the crypto and access paths
reviewed.
