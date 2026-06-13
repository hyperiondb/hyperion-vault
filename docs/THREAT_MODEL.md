# Threat model

## Assets

- Secret plaintext values (highest value).
- The KMS master key and derived DEKs.
- Admin tokens.
- The audit trail (integrity).

## Trust boundaries

- Network client ↔ API (HTTP).
- API ↔ PostgreSQL (libpq).
- API ↔ AWS KMS.
- Primary ↔ standbys (WAL stream, managed by `pg_replica`).

## Actors

- **Anonymous network client** — may reach the API port.
- **Read client** — an allowlisted service that fetches/verifies secrets.
- **Admin** — holds an admin token; manages secrets.
- **DB-only adversary** — can read Postgres files / WAL / a standby, but not the
  KMS key or the API process memory.
- **Insider with table write** — can modify rows in `vault.*`.

## Threats and mitigations (STRIDE-style)

| Threat | Mitigation |
|--------|-----------|
| **Spoofing** a read client by IP | IPv4/CIDR allowlist, fail-closed. Proxy IP trusted only when `VAULT_TRUST_PROXY` is set behind a trusted proxy. |
| **Spoofing** an admin | High-entropy bearer tokens; only SHA-256 fingerprints stored; constant-time check; revocation. |
| **Tampering** with stored ciphertext | AEAD tag fails `open`; AAD binds ciphertext to `name:version` so rows can't be swapped between secrets/versions. |
| **Tampering** to escalate read access | RLS `FORCE`d + `REVOKE FROM PUBLIC`; only the scoped service role can touch rows. |
| **Repudiation** | Append-only `vault.audit_log` with actor/IP/action/outcome. |
| **Information disclosure** from DB/WAL/standby theft | Only ciphertext + wrapped DEK at rest; decryption requires the KMS key (separate trust domain). |
| **Information disclosure** via error messages | Internal errors return a generic 500; crypto/DB detail is logged server-side only. |
| **Information disclosure** via timing on `/verify` | Constant-time comparison of presented value vs decrypted versions. |
| **DoS** via large bodies | 1 MiB request body limit; secret value size cap. |
| **Elevation** via rotation worker races | `rotation_jobs` claimed with `FOR UPDATE SKIP LOCKED`; stale claims reclaimed; rotation is a primary-only write. |
| **Nonce reuse** weakening AEAD | 192-bit random XChaCha20 nonces, fresh per version; uniqueness covered by tests. |
| **Key material in memory** after use | `Zeroizing` DEKs/master keys. The DEK cache holds unwrapped keys for up to `VAULT_DEK_CACHE_TTL_SECS` (never plaintext); lower or disable the TTL to shrink the window. |

## Residual risks / open items (must close before production)

- **TLS to Postgres** is not enabled in the scaffold (`NoTls`).
- **API TLS** termination must be added (proxy or in-process).
- **Admin-token bootstrap** flow (initial token provisioning) is operator-defined.
- A **KMS outage** makes reads/writes fail closed (availability vs
  confidentiality trade-off) — consider caching policy explicitly.
- The IP allowlist is **IPv4-only** by spec; IPv6 clients are denied.
- Rate limiting / lockout on repeated failed auth is **not** implemented.
