# Design decisions

Short ADRs for the choices that shape this project.

## 1. XChaCha20-Poly1305 for the data-encryption layer

**Decision.** Seal secret bytes with XChaCha20-Poly1305 (AEAD).

**Why.** Modern and fast in software (no AES-NI dependency, unlike AES-GCM),
constant-time by construction, and the 192-bit *extended* nonce makes random
nonces safe without a counter — important because each version is encrypted
independently and we never want nonce reuse. Poly1305 gives authenticated
encryption so tampering is detected on `open`.

## 2. Envelope encryption with AWS KMS (not raw KMS encrypt)

**Decision.** Use KMS `GenerateDataKey`/`Decrypt` to wrap a per-version 256-bit
DEK; encrypt the secret locally with the DEK.

**Why.** This is the OpenBao / industry pattern. KMS never sees the plaintext
secret, payload size is unbounded by KMS limits, and the master key never
leaves KMS. A `KeyWrapper` trait abstracts this so a local dev provider can
stand in without AWS.

## 3. Application-layer encryption, not in-database (TDE-style)

**Decision.** Encryption/decryption happen in the API process; Postgres stores
only ciphertext. The extension owns schema/RLS/rotation, **not** crypto.

**Why.** KMS calls are network I/O and must be async and non-blocking — that
does not belong inside a Postgres backend. Keeping crypto in the API keeps the
`.so` small (mirrors how `pg_replica` shells out rather than blocking
backends), and makes the security-critical code unit-testable in
`hyperion-vault-core` without a database.

**Trade-off.** Unlike Supabase Vault there is no in-SQL `decrypted_secrets`
view; decryption is only available through the API (gated by IP allowlist +
token). This is intentional — it is the single, audited access path.

## 4. Primary-routed writes, local reads (the `pg_replica` contract)

**Decision.** Two connection pools: a **writer** pool with
`target_session_attrs=read-write` and a **reader** pool with `=any`.

**Why.** `pg_replica` uses physical replication — standbys are read-only and
only the primary accepts writes. A multi-host writer pool always lands on the
current primary and follows failover, so `create/update/delete/rotate` work
from *any* node. Reads (and decryption) are served locally for latency and to
spread load. This is exactly the libpq pattern `pg_replica` documents for
clients.

## 5. Rotation: supervisor in the DB, worker in the API

**Decision.** The extension's background worker only **enqueues** due rotations
(primary-only) and notifies; the API worker **performs** them.

**Why.** Detecting "what is due" is cheap SQL that belongs next to the data and
should run autonomously even if the API restarts. Performing rotation needs KMS
(async) and the secret-generation logic, which live in the API. The
`rotation_jobs` queue with `FOR UPDATE SKIP LOCKED` makes rotation safe when
every node runs a worker.

## 6. Grace windows via per-version `expires_at`

**Decision.** Superseded versions keep `expires_at = now() + grace_period` and
remain decryptable/verifiable until then.

**Why.** Automatic secrets are consumed by external services that cannot all
cut over instantly. During the grace window both the new and previous secret
validate (`/verify`), enabling zero-downtime rotation. Manual secrets default
to zero grace (immediate supersede).

## 7. IP allowlist is fail-closed

**Decision.** Reads are allowed only from `VAULT_ALLOWED_IPS`; an empty or
unparseable-to-empty list denies everything.

**Why.** A misconfiguration must never silently expose secrets to the world.
The default posture is deny.

## 8. Admin tokens stored as SHA-256 fingerprints, compared in constant time

**Decision.** Generate 256-bit random tokens; store only `sha256(token)`;
verify with a constant-time comparison.

**Why.** Tokens are high-entropy (brute force infeasible), so a fast hash is
sufficient and avoids per-request KDF cost; storing only the fingerprint means
a database leak does not reveal usable tokens. Constant-time comparison closes
the timing side channel.

## 9. Extension lib `hyperion_vault`, SQL schema `vault`

**Decision.** The shared library / control file is `hyperion_vault`; the SQL
objects live in schema `vault`.

**Why.** Mirrors `pg_replica` (lib `pg_replica`, schema `replica`). The lib
name avoids crates.io / extension-name collisions; the short `vault` schema
keeps the SQL API ergonomic. Rename the schema if it would clash with another
installed `vault` extension in the same database.

## 10. Exact-pinned latest dependency versions

**Decision.** Every dependency is pinned to an exact `=x.y.z` of the latest
published version (e.g. `axum = "=0.8.9"`, `sha2 = "=0.11.0"`).

**Why.** Reproducible builds and no silent drift across the monorepo. `pgrx`
and `libc` match `pg_replica` exactly so both extensions are built against the
same toolchain.
