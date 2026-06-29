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

Without `--features api` the four API targets compile as no-ops (so the core
targets stay cheap to build):

```sh
cargo +nightly fuzz run --features api store_decode
cargo +nightly fuzz run --features api raft_rpc_decode
```

## Seeds

Hand-written seed inputs live in `seeds/<target>/`. Pass the directory as an
extra corpus to bootstrap a run:

```sh
cargo +nightly fuzz run ip_allowlist_parse seeds/ip_allowlist_parse
```

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

## Ideas for more coverage

- **State-machine fuzzing of `store::apply::apply_command`**: drive a `Vec<Command>`
  against an in-memory redb (`redb::backends::InMemoryBackend`) and assert it
  never panics. Note: the lockout arithmetic in `RecordAuthFailure`
  (`now - window_start`, `now + lockout_secs`, `failures += 1`) is unchecked and
  can overflow-panic under debug overflow checks; that path is fed by the local
  node clock rather than replicated peer input, so harden or bound it before
  wiring this target up to avoid non-attacker-reachable false positives.
