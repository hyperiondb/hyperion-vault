# hyperion-vault fuzzing

Coverage-guided fuzz targets for the security-critical, untrusted-input surfaces
of hyperion-vault, built with [`cargo-fuzz`](https://rust-fuzz.github.io/book/)
(libFuzzer).

This crate is **detached from the workspace** (it has its own `[workspace]`
table) so the stable-pinned `cargo build/test --workspace` and CI never try to
compile these nightly-only targets.

## Requirements

- A **nightly** toolchain (the repo pins stable in `rust-toolchain.toml`, so
  invoke everything through `cargo +nightly`).
- `cargo install cargo-fuzz`.
- libFuzzer + AddressSanitizer. **Linux and macOS are the canonical, friction-free
  platforms.** Windows works too, with one runtime caveat — see [Windows](#windows).

```sh
cargo +nightly fuzz list
cargo +nightly fuzz run ip_allowlist_parse
```

## Running: continuous vs bounded

`cargo fuzz run` **never exits on its own** — libFuzzer keeps generating inputs
until it finds a crash or you press Ctrl-C. A run that prints `exec/s: …` with a
climbing iteration counter and no `SUMMARY:`/`ERROR` line is healthy and finding
nothing, not stuck. Once the `cov:` number stops climbing, coverage has saturated
and extra time adds nothing (these targets saturate within a minute or two).

For day-to-day use and CI, bound every run:

```sh
cargo +nightly fuzz run crypto_roundtrip -- -max_total_time=60   # stop after 60s
cargo +nightly fuzz run crypto_roundtrip -- -runs=2000000        # stop after N execs
```

To sweep every target for a fixed budget, use the helper:

```sh
./run-all.sh 60        # 60s per target (default 60)
```

## Targets

Core targets (`hyperion-vault-core`, lightweight — the default build):

| Target | Surface | What it checks |
| --- | --- | --- |
| `ip_allowlist_parse` | `IpAllowlist::parse` | Parsing an untrusted CIDR/IP spec never panics; `contains` is total. |
| `local_key_from_base64` | `LocalKeyWrapper::from_base64` | Base64 master-key decoding never panics; any accepted key seals/opens. |
| `envelope_unwrap` | `KeyWrapper::unwrap_data_key`, `crypto::open` | Decrypting attacker-controlled wrapped DEKs / ciphertext is total (Ok/Err only). |
| `crypto_roundtrip` | `seal_envelope` / `open_envelope` | AEAD invariants: authentic round-trips exactly; wrong AAD or a flipped ciphertext byte fails. |
| `rbac` | `authorize`, `visible`, `path_matches`, ... | Predicates never panic; admin is total; `authorize ⇒ visible`. |
| `auth_fingerprint` | `auth::fingerprint` / `verify` | Deterministic, self-verifying, length-sensitive constant-time compare. |
| `types_aad` | `aad_for`, `SecretKind/Format::parse` | AAD construction is total and name-prefixed; enum parsers round-trip. |
| `rotation` | `RotationPolicy`, `is_due`, `version_active` | Saturating timing arithmetic never overflow-panics at i64/u64 extremes. |

API targets (`hyperion-vault-api`, behind the `api` feature — pulls the full
server dependency tree). These exercise the deserialization of bytes that arrive
over the wire (raft RPCs, HTTP bodies) or from disk (backups, the raft log):

| Target | Surface | What it checks |
| --- | --- | --- |
| `store_decode` | `store::codec::decode::<Command/...>` | Decoding arbitrary bytes into any persisted/replicated record never panics; commands round-trip. |
| `backup_decode` | `BackupData` JSON | Restoring an untrusted backup never panics; parsed backups round-trip. |
| `raft_rpc_decode` | `AppendEntries/InstallSnapshot/VoteRequest`, `Entry<TypeConfig>` | Peer-supplied raft RPC JSON and on-disk log entries deserialize totally — a parse panic here is a remotely-triggerable node crash. |
| `dto_decode` | public request DTOs in `dto` | Decoding malformed HTTP-body JSON into any request DTO never panics. |

Behaviour targets — these run the decoded value through the code that acts on
it, against an in-memory redb where storage is involved:

| Target | Surface | What it checks |
| --- | --- | --- |
| `apply_command_sequence` | `store::apply::apply_command` over `redb::backends::InMemoryBackend` | Two replicas applying the same command sequence reach byte-identical state and identical per-command outcomes; a rejected write leaves no trace; `DeleteSecret` only removes its own version rows; `RewrapVersion` never touches ciphertext/nonce/aad; the audit log stays a gap-free sequence; every row is keyed by its own identity. |
| `backup_restore_roundtrip` | `store::backup::restore_database` / `dump_database` | Restore is total, rejects a foreign backup version without touching the store, is idempotent, and `dump(restore(x))` reproduces `x` exactly (after redb's per-key collapse). |
| `raft_log_normalize` | `raft::store::normalize_raft_log`, `LogStore::get_log_state` | After normalisation the log is contiguous from the first index above `last_applied`, holds nothing at or below `last_purged`, is idempotent, and `get_log_state` reports the highest surviving entry. |
| `snapshot_install` | `raft::store::StateMachine::install_snapshot` | A peer-supplied snapshot blob installs totally; a well-formed one replaces every table with exactly its own rows, records the supplied `last_log_id` and membership as applied, and removes every log entry the snapshot covers. |
| `store_key_encoding` | `version_key` / `version_lower` / `version_upper` | Version-key ranges are disjoint across secret names and byte order matches version numeric order. **Known-failing — see below.** |
| `name_validation` | `service::validate_name` / `validate_value` / `validate_field` / `normalize_grace`, `manage::validate_role_name` | Pins the charset, length and sign contract the version-key encoding depends on. |
| `bearer_token_parse` | `guards::bearer_token` | Parsing the Authorization header is total; anything returned is a non-empty, trimmed, verbatim substring of a `Bearer `/`bearer ` header. |
| `forwarded_for_parse` | `guards::client_ip` | With `VAULT_TRUST_PROXY` off the header can never move the result away from the transport peer; with it on the result is the peer or the first `X-Forwarded-For` field. |
| `pg_hostport` | `pg_apply::split_hostport` | Total; the host is a prefix of the input; a well-formed `host:port` round-trips. |
| `config_parse_peers` | `config::parse_peers` | Total; every accepted id and address appears verbatim in the input. |

Without `--features api` the API targets compile as no-ops (so the core
targets stay cheap to build):

```sh
cargo +nightly fuzz run --features api store_decode
cargo +nightly fuzz run --features api raft_rpc_decode
```

## Known-failing targets

`store_key_encoding` fails within seconds, on purpose. It reproduces the
secret-version key collision recorded as **VULN-2** in
[`../VULN.md`](../VULN.md): a secret name containing a NUL byte places its
version rows inside a *different* secret's scan range, and negative version
numbers sort backwards. `run-all.sh` keeps a `KNOWN_FAILING` map so a sweep
still reports every other target and does not fail the job on this one. Remove
the entry from that map when the defect is fixed.

Two defects are deliberately **not** reproduced by a target, because a target
that aborts on its first input never reaches the properties it was written for.
Both have a deterministic reproducer in `VULN.md` instead:

- `apply_command_sequence` bounds the `RecordAuthFailure` fields (VULN-5).
- `raft_log_normalize` skips a `last_applied`/`last_purged` index of
  `u64::MAX` (VULN-6).

## Seeds and dictionaries

Hand-written seed inputs live in `seeds/<target>/`. Pass the directory as an
extra corpus to bootstrap a run:

```sh
cargo +nightly fuzz run ip_allowlist_parse seeds/ip_allowlist_parse
```

The JSON-decoding targets (`store_decode`, `backup_decode`, `raft_rpc_decode`,
`dto_decode`) are byte mutators over structured text; give them the dictionary
of JSON punctuation and every field name:

```sh
cargo +nightly fuzz run --features api dto_decode seeds/dto_decode -- -dict=fuzz/dicts/json.dict
```

`run-all.sh` passes the dictionary to those four targets automatically.

Seeds exist for ten targets: `auth_fingerprint`, `backup_decode`,
`bearer_token_parse`, `config_parse_peers`, `dto_decode`, `ip_allowlist_parse`,
`local_key_from_base64`, `pg_hostport`, `raft_rpc_decode` and `store_decode`.
The `raft_rpc_decode` seeds are real `AppendEntriesRequest`,
`InstallSnapshotRequest`, `VoteRequest` and `Entry<TypeConfig>` payloads
serialised by openraft itself — a byte mutator will effectively never build one
from scratch. With those seeds and the dictionary that target reaches 2,200
edges in 25 seconds.

The remaining targets take a structured input (`Arbitrary`), not raw bytes, so a
text seed file would not help them.

(The live, fuzzer-managed corpus under `corpus/` and crash `artifacts/` are
git-ignored.)

## Reproducing a crash

```sh
cargo +nightly fuzz run <target> artifacts/<target>/crash-<hash>
cargo +nightly fuzz fmt  <target> artifacts/<target>/crash-<hash>   # decoded input
```

## Windows

The targets build and run on `x86_64-pc-windows-msvc`, but the default libFuzzer
build links against the dynamic AddressSanitizer runtime, so the resulting
`.exe` needs `clang_rt.asan_dynamic-x86_64.dll` on `PATH` at run time — otherwise
it exits with `STATUS_DLL_NOT_FOUND (0xc0000135)`. The DLL ships with MSVC under
`VC\Tools\MSVC\<ver>\bin\Hostx64\x64\`:

```powershell
$asan = (Get-ChildItem "${env:ProgramFiles}\Microsoft Visual Studio" -Recurse `
  -Filter clang_rt.asan_dynamic-x86_64.dll | Select-Object -First 1).Directory.FullName
$env:PATH = "$asan;$env:PATH"
cargo +nightly fuzz run rbac -- -max_total_time=30
```

Note: `--sanitizer none` does **not** link on MSVC — libFuzzer's
SanitizerCoverage needs the `__start___sancov_*` section-boundary symbols that
`link.exe` (unlike ELF linkers) does not synthesize. Keep the default
(address) sanitizer on Windows, or run under WSL/Linux.

Second Windows caveat: when a target panics, the process exits with
`STATUS_STACK_BUFFER_OVERRUN (0xc0000409)` before libFuzzer writes the crashing
input, so `artifacts/<target>/` stays empty. The panic message and location are
still printed. To capture a reproducible artifact, run that target under
WSL/Linux.

## Observed run rates

Measured on `x86_64-pc-windows-msvc`, address sanitizer, one 20-30 second run
per target. The targets that build an in-memory database per iteration are two
to four orders of magnitude slower than the pure-function ones, so give them a
much larger time budget in a real sweep.

| Target | exec/s | Edges covered |
| --- | --- | --- |
| `pg_hostport` | ~138,000 | 93 |
| `bearer_token_parse` | ~14,900 | 318 |
| `name_validation` | ~12,000 | 239 |
| `config_parse_peers` | ~9,200 | 482 |
| `forwarded_for_parse` | ~8,800 | 351 |
| `snapshot_install` | ~51 | 7,475 |
| `backup_restore_roundtrip` | ~43 | 4,307 |
| `raft_log_normalize` | ~25 | 5,799 |
| `apply_command_sequence` | ~10 | 5,046 |

`store_key_encoding` found the defect it was written for after 436 executions.

## Last full sweep

2026-09-02, `x86_64-pc-windows-msvc`, address sanitizer.

`./run-all.sh 90` ran all 22 targets for 90 seconds each. The only failure was
`store_key_encoding`, which is on the `KNOWN_FAILING` list and reproduced the
defect it exists to reproduce. No crashing input was saved (see the Windows
caveat above), and `artifacts/` is empty for every other target.

The four targets that build a database per iteration were then run again for
eight minutes each, with `-len_control=0 -max_len=1024` so that libFuzzer
generates long command sequences immediately instead of ramping the input length
up from a few bytes. All four passed:

| Target | Executions | Edges covered | exec/s |
| --- | --- | --- | --- |
| `raft_log_normalize` | 6,941 | 6,067 | 16 |
| `backup_restore_roundtrip` | 5,930 | 5,785 | 12 |
| `snapshot_install` | 5,141 | 7,873 | 10 |
| `apply_command_sequence` | 2,966 | 7,812 | 6 |

Forcing long inputs raises coverage substantially over the short runs in the
table above — `apply_command_sequence` goes from 5,046 edges to 7,812 — and
costs throughput, because each iteration now applies a longer command sequence.

The pure-parsing targets saturate much sooner: `types_aad`, for example, added
no new corpus entries across 1,519,946 executions in the same sweep.

## In CI

- `.github/workflows/ci.yml` builds every target and sweeps for 30 seconds each
  on every pull request, so a target that stops compiling is caught immediately.
- `.github/workflows/security.yml` runs a 10-minute-per-target sweep on the
  existing weekly cron and uploads `fuzz/artifacts/` and `fuzz/corpus/`.

## Ideas for more coverage

- **The rotation and lockout arithmetic** (`service.rs`, `apply.rs`): both are
  inline in `async` functions today. Extracting them as pure functions —
  `next_rotation(now, interval) -> Option<i64>` and
  `next_lockout_state(prev, now, max, window, lockout) -> LockoutRecord` — makes
  them a three-line fuzz target each, and routing them through
  `hyperion_vault_core::rotation` (which already saturates) fixes VULN-5 at the
  same time.
- **A libpq connection-string builder**: write the escaping helper first
  (VULN-4), then fuzz that quoting every field round-trips through
  `tokio_postgres::Config::from_str` for any input, including spaces, single
  quotes, backslashes and empty strings.
- **Coverage measurement**: `cargo +nightly fuzz coverage <target>` has not been
  run for any target, so there is no evidence of which lines each one reaches.
