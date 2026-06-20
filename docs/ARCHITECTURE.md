# Architecture

HyperionDB Vault is a single Rust binary (`hyperion-vault-api`) plus a reusable
core library, deployed as a Raft cluster. Each node owns an embedded redb store.

```
        ┌──────────── vault node (×N, odd count) ────────────┐
clients │  hyperion-vault-api (axum)                          │
 ──────▶│   ├─ IP allowlist guard (reads)                     │
        │   ├─ admin-token guard + RBAC (writes)              │
        │   ├─ service: envelope seal/open ─▶ AWS KMS         │
        │   ├─ store ports (VaultReader / VaultWriter)        │
        │   │     ├─ RedbStore  (single node)                 │
        │   │     └─ RaftStore  (cluster) ─┐                  │
        │   └─ rotation worker (leader only)│                 │
        │  redb file: secrets, versions, roles, tokens,       │
        │             audit, lockouts, raft log, snapshots    │
        └───────────────────────────────────┼────────────────┘
                                             │ openraft (HTTP RPC)
                              writes ▶ leader │ replicate to quorum
                              reads  ◀ local  ▼ apply to each redb
```

## Components

- **`hyperion-vault-core`** — pure Rust, no I/O. The cryptographic envelope
  (`seal`/`open` over XChaCha20-Poly1305), the `KeyWrapper` abstraction, the
  IPv4 allowlist, admin-token generation/fingerprinting, RBAC matching, and the
  rotation policy math. Correctness is proven by tests here.
- **`hyperion-vault-api`** — the data/management plane:
  - `store/` — the storage ports (`VaultReader` / `VaultWriter`), the `Command`
    enum, the deterministic `apply_command`, and the `RedbStore` engine.
  - `raft/` — the openraft `TypeConfig`, the redb-backed log store + state
    machine, the HTTP network, and `RaftStore` (the replicated adapter).
  - HTTP handlers, the IP/token guards, the async KMS providers, and the
    leader-gated rotation worker.

## Storage model (redb)

| Table | Holds | Scope |
|-------|-------|-------|
| `secrets` | `name`, `kind`, `format`, rotation settings, `current_version`, `next_rotation_at` | replicated |
| `secret_versions` | `(name, version)` → `kms_key_id`, `wrapped_dek`, `nonce`, `ciphertext`, `aad`, `expires_at` | replicated |
| `roles` | `name`, `is_admin`, permission rules | replicated |
| `admin_tokens` / `admin_tokens_by_name` | token fingerprint → role, timestamps | replicated |
| `audit_log` | append-only operation record | local per node |
| `auth_lockouts` | per-IP failure counters | local per node |
| `raft_log` / `raft_meta` | Raft entries, vote, applied index, membership, snapshot | per node |

Replicated tables form the Raft state machine. Local tables (audit, lockout) are
written directly, off the consensus path, so reads and failed-auth attempts
never incur a consensus round-trip.

A **version** is the unit of encryption; the current version has
`expires_at = None`. On rotation the previous version's `expires_at` is set to
`now + grace_period`; it stays decryptable/verifiable until the leader's rotation
worker expires it.

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
    dek = KMS.Decrypt(row.wrapped_dek)                 # or DEK cache
    plaintext = XChaCha20Poly1305(dek).open(row.nonce, row.aad, row.ct)
    zeroize(dek)
```

The AAD binds each ciphertext to its `name` and `version`, so a stored row
cannot be replayed under a different secret or version even by someone with
write access to the file.

## Request flows

**Read** (`GET /v1/secrets/{name}`): IP allowlist guard → local redb read →
KMS `Decrypt` (or DEK cache) → AEAD open → return value.

**Write** (`POST/PUT/DELETE`, `/rotate`): admin-token guard + RBAC → build a
`Command` → `VaultWriter::apply`. In a cluster the `RaftStore` submits the
command to the Raft leader (a follower forwards to the current leader), which
replicates to a quorum; each node's state machine runs `apply_command` against
its redb. Single-node applies directly.

**Verify** (`POST /v1/secrets/{name}/verify`): IP allowlist guard → local read of
currently-valid versions (current + within-grace) → constant-time compare →
`{valid, version}`.

## Replication & rotation

- **openraft** orders all writes through the leader and replicates the log to a
  quorum before acknowledging. Leader election provides failover. The same
  `apply_command` runs on every node, so all redb stores converge.
- The **rotation worker** runs on every node but acts only on the leader: it
  scans `next_rotation_at` and issues `RotateSecret` / `ExpireGraceVersions`
  commands through Raft, so rotations replicate like any other write.

See [`DECISIONS.md`](DECISIONS.md) for the rationale behind these choices.
