# Architecture

HyperionDB Vault has three deployable parts plus a reusable core library, all
co-located on each node of a `pg_replica` cluster.

```
                      ┌─────────────────────────── node (every pg_replica member) ───────────────────────────┐
   clients  ─────────▶│  hyperion-vault-api (axum)                                                            │
   (readers,          │    ├─ IP allowlist guard (reads)        ├─ writer pool ──(target_session_attrs=rw)──┐ │
    admins)           │    ├─ admin-token guard (writes)        └─ reader pool ──(target_session_attrs=any) │ │
                      │    ├─ service: envelope seal/open ──────▶ AWS KMS (GenerateDataKey / Decrypt)        │ │
                      │    └─ rotation worker (claims jobs)                                                  │ │
                      │                                                                                      ▼ │
                      │  PostgreSQL 18 + extension hyperion_vault                                  primary ◀─┘ │
                      │    ├─ schema `vault` (secrets, secret_versions, admin_tokens, rotation_jobs, audit)    │
                      │    ├─ RLS + service-role policies                                                      │
                      │    └─ rotation supervisor bgworker (primary-only: enqueue + NOTIFY)                    │
                      └──────────────────────────────────────────────────────────────────────────────────────┘
                                              │ physical WAL streaming (pg_replica)
                                              ▼  byte-for-byte to all standbys (read-only)
```

## Components

- **`hyperion-vault-core`** — pure Rust, no I/O. Owns the cryptographic
  envelope format (`seal`/`open` over XChaCha20-Poly1305), the `KeyWrapper`
  abstraction, the IPv4 allowlist, admin-token generation/fingerprinting, and
  the rotation policy math. This is where correctness is proven by tests.
- **`hyperion_vault` extension** — schema, constraints, RLS, SQL helper
  functions (`vault.status`, `vault.enqueue_due_rotations`,
  `vault.expire_grace_versions`, `vault.grant_service_role`), and the rotation
  **supervisor** background worker.
- **`hyperion-vault-api`** — the data/management plane: HTTP handlers, the two
  guards, the dual connection pools, the async KMS providers, and the rotation
  **worker** that performs re-encryption.

## Data model (schema `vault`)

| Table | Holds |
|-------|-------|
| `admin_tokens` | `name`, `token_sha256` (32-byte fingerprint), `revoked_at`, `last_used_at`. |
| `secrets` | `name`, `kind` (`manual`/`automatic`), `rotation_interval`, `grace_period`, `current_version`, `next_rotation_at`. |
| `secret_versions` | `(secret_id, version)`, `kms_key_id`, `wrapped_dek`, `nonce`, `ciphertext`, `aad`, `expires_at`. Plaintext never stored. |
| `rotation_jobs` | work queue for due automatic rotations (claim with `FOR UPDATE SKIP LOCKED`). |
| `audit_log` | append-only operation record. |

A **version** is the unit of encryption. The current version has
`expires_at = NULL`. When a secret rotates, the previous version's `expires_at`
is set to `now() + grace_period`; it remains decryptable and `verify`-able
until then, after which `vault.expire_grace_versions()` removes it.

## Cryptographic envelope

```
encrypt(plaintext, name, version):
    aad      = name || ":" || version
    dek      = KMS.GenerateDataKey(AES_256)          # plaintext + wrapped form
    nonce    = 24 random bytes
    ct       = XChaCha20Poly1305(dek).seal(nonce, aad, plaintext)
    store { kms_key_id, wrapped_dek, nonce, ct, aad }
    zeroize(dek)

decrypt(row, name, version):
    assert row.aad == name || ":" || version          # version/name binding
    dek = KMS.Decrypt(row.wrapped_dek)
    plaintext = XChaCha20Poly1305(dek).open(row.nonce, row.aad, row.ct)
    zeroize(dek)
```

The AAD binds each ciphertext to its `name` and `version`, so a stored row
cannot be replayed under a different secret or version even by someone with
table write access.

## Request flows

**Read** (`GET /v1/secrets/{name}`): IP allowlist guard → reader pool (local
node) → fetch current version → KMS `Decrypt` → AEAD open → return value.

**Write** (`POST/PUT/DELETE`, `/rotate`): admin-token guard → writer pool
(`read-write` → current primary) → transaction { seal new version via KMS,
insert, supersede old version, update secret } → commit → replicate.

**Verify** (`POST /v1/secrets/{name}/verify`): IP allowlist guard → reader pool
→ for each currently-valid version (current + within-grace) → decrypt →
constant-time compare → return `{valid, version}`.

## Rotation

1. The extension's **supervisor** bgworker runs on the **primary only**
   (`pg_is_in_recovery() = false`). Every `scan_interval_secs` it calls
   `vault.enqueue_due_rotations()` (inserts jobs for automatic secrets whose
   `next_rotation_at <= now()` with no open job) and `NOTIFY vault_rotation`.
2. The API **rotation worker** on each node polls/claims jobs from the queue
   (`FOR UPDATE SKIP LOCKED`, with stale-claim reclaim). Because the claim is a
   write, it executes on the primary; `SKIP LOCKED` makes concurrent workers
   across nodes safe.
3. For each job it generates new material, seals a new version, sets the old
   version's `expires_at = now() + grace_period`, advances `current_version`
   and `next_rotation_at`, then completes the job.

See [`DECISIONS.md`](DECISIONS.md) for the rationale behind these choices.
