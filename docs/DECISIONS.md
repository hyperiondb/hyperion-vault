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

## 3. Application-layer encryption

**Decision.** Encryption/decryption happen in the API process; the store holds
only ciphertext.

**Why.** KMS calls are network I/O and must be async and non-blocking. Keeping
crypto in the API makes the security-critical code unit-testable in
`hyperion-vault-core` with no storage or network, and keeps the storage layer a
dumb byte store.

**Trade-off.** Decryption is only available through the API (gated by IP
allowlist + token). This is intentional — it is the single, audited access path.

## 4. Embedded storage with redb

**Decision.** Persist all state to a local embedded **redb** key-value store
(one file per node), instead of an external database.

**Why.** The previous design required operating a full PostgreSQL cluster plus
extensions just to hold a handful of secret rows. redb is a pure-Rust,
zero-dependency, ACID embedded store — no server to run, no connection pools, no
SQL. Secrets, versions, roles, tokens, the audit log, the lockout table, and the
Raft log/snapshots all live in that one file.

**Trade-off.** redb is single-process: it cannot be shared across hosts. Cross-
node durability and HA are provided by Raft (ADR 5), not by the storage engine.

## 5. Replication & failover via Raft (openraft)

**Decision.** Run the vault as a Raft cluster using **openraft**. The Raft state
machine is the redb store; writes are committed through consensus to the leader
and replicated to a quorum; reads are served locally from any node.

**Why.** This replaces PostgreSQL physical replication + `pg_replica` Raft
failover with a self-contained equivalent: the **leader** is the primary, leader
election is automatic failover, and a follower transparently forwards writes to
the current leader. Linearizable reads are available on request
(`VAULT_READ_CONSISTENCY=linearizable`); the default serves reads locally for
latency and load spreading.

**Trade-off.** A write needs a quorum, so it costs one consensus round-trip; and
the cluster needs an odd node count (3 or 5) to tolerate failures cleanly.

## 6. Ports & adapters around storage

**Decision.** The service layer depends only on the `VaultReader` /
`VaultWriter` traits. The single-node `RedbStore` and the Raft-backed
`RaftStore` are interchangeable adapters; every mutation is a `Command` applied
by one deterministic `apply_command`.

**Why.** It keeps the consensus/storage choice out of the business logic (a
future engine is one `impl`, not a rewrite), makes the write path testable
without a cluster, and guarantees the single-node and replicated paths apply
mutations identically — `apply_command` is the single source of truth, used both
directly by `RedbStore` and by the Raft state machine.

## 7. Rotation runs on the leader

**Decision.** The rotation worker runs on every node but only acts when it is
the Raft leader; it scans for due secrets and issues `RotateSecret` /
`ExpireGraceVersions` commands through Raft.

**Why.** Detecting "what is due" is a cheap local scan; performing rotation needs
KMS (async) and replicated state changes. Gating on leadership avoids the
multi-worker dedupe that a queue (`FOR UPDATE SKIP LOCKED`) previously required —
there is exactly one leader, so there is exactly one rotation driver, and the
mutations replicate like any other write.

## 8. Grace windows via per-version `expires_at`

**Decision.** Superseded versions keep `expires_at = now + grace_period` and
remain decryptable/verifiable until then.

**Why.** Automatic secrets are consumed by external services that cannot all cut
over instantly. During the grace window both the new and previous secret
validate (`/verify`), enabling zero-downtime rotation. Manual secrets default to
zero grace (immediate supersede).

## 9. IP allowlist is fail-closed

**Decision.** Reads are allowed only from `VAULT_ALLOWED_IPS`; an empty or
unparseable-to-empty list denies everything.

**Why.** A misconfiguration must never silently expose secrets to the world. The
default posture is deny.

## 10. Admin tokens stored as SHA-256 fingerprints, compared in constant time

**Decision.** Generate 256-bit random tokens; store only `sha256(token)`; verify
with a constant-time comparison.

**Why.** Tokens are high-entropy (brute force infeasible), so a fast hash is
sufficient and avoids per-request KDF cost; storing only the fingerprint means a
store leak does not reveal usable tokens. Constant-time comparison closes the
timing side channel.

## 11. Node identity from `NODE_ID` + `VAULT_PEERS`, derived not duplicated

**Decision.** A node's identity is `NODE_ID`; the cluster map `VAULT_PEERS`
(`id=host:port`, identical on every node) gives every node's reachable Raft
address. A node binds the port from its own `VAULT_PEERS` entry. The public API
binds `0.0.0.0:VAULT_API_PORT`.

**Why.** A bind address tells a peer nothing about how to reach a node (and the
external port can differ from the bind), so a single advertised cluster map is
the source of truth. This removes the redundant `VAULT_NODE_NAME` and
`VAULT_API_LISTEN` of the previous design.

## 12. Cache unwrapped data keys (not plaintext) for KMS-outage resilience

**Decision.** The API keeps an in-memory cache of **unwrapped DEKs**, keyed by
the wrapped-DEK bytes, with a TTL from `VAULT_DEK_CACHE_TTL_SECS` (default 300s;
`0` disables).

**Why.** AWS KMS can rate-limit or briefly fail. Caching the *unwrapped DEK*
(rather than the plaintext secret) lets reads of any previously-read version
continue through an outage while still requiring the AEAD `open` step and never
storing the secret value itself.

**Trade-off.** Cached DEKs live in process memory for up to the TTL. Set `0` for
maximum confidentiality (every read hits KMS). Writes always call KMS and fail
closed during an outage.

## 13. Retry KMS calls with exponential backoff

**Decision.** A `RetryingKms` decorator retries both KMS operations up to
`VAULT_KMS_MAX_RETRIES` (default 5; `0` disables) with exponential backoff
(100ms doubling, capped).

**Why.** Writes always call `GenerateDataKey`, so a KMS rate-limit or transient
error would otherwise fail every create/update/rotate. Reads retry too, but only
on a cache miss.
