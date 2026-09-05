#!/usr/bin/env bash
# Fuzz every target for a bounded time, then exit. Without a time limit
# `cargo fuzz run` never stops on its own.
#
#   ./run-all.sh [seconds_per_target]   (default 60)
set -u

budget="${1:-60}"
cd "$(dirname "$0")/.." || exit 1   # repo root; cargo-fuzz expects ./fuzz here

# Git Bash / MSYS on Windows: libFuzzer links the dynamic AddressSanitizer
# runtime, whose DLL must be on PATH or the target exits STATUS_DLL_NOT_FOUND.
case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN*)
    dll="$(find '/c/Program Files/Microsoft Visual Studio' \
      -path '*Hostx64/x64/clang_rt.asan_dynamic-x86_64.dll' 2>/dev/null | sort | tail -1)"
    [ -n "$dll" ] && export PATH="$(dirname "$dll"):$PATH"
    ;;
esac

# Targets that reproduce a defect that is reported but not yet fixed. They are
# still run — the output tells you the finding is still there — but they do not
# fail the sweep. Each name is followed by the VULN.md id it reproduces.
declare -A KNOWN_FAILING=()

# The serde targets are byte mutators over JSON; a dictionary of the punctuation
# and every field name is a large, cheap coverage win.
uses_dict() {
  case "$1" in
    store_decode | backup_decode | raft_rpc_decode | dto_decode) return 0 ;;
    *) return 1 ;;
  esac
}

# Targets whose input is a sequence of operations rather than a flat value.
needs_long_inputs() {
  case "$1" in
    apply_command_sequence | snapshot_install | backup_restore_roundtrip | \
      raft_log_normalize) return 0 ;;
    *) return 1 ;;
  esac
}

# --features api so the api-backed targets are real (core targets ignore it);
# one build, no feature-flip rebuilds between targets.
fail=0
expected=()
for target in $(cargo +nightly fuzz list); do
  echo "=== $target (${budget}s) ==="
  args=(-max_total_time="$budget" -print_final_stats=1)
  uses_dict "$target" && args+=(-dict=fuzz/dicts/json.dict)
  # The database-backed targets take a Vec of commands. Without this libFuzzer
  # spends most of a short run on inputs a few bytes long, i.e. sequences of one
  # or two commands; forcing the full length immediately roughly halves the
  # execution rate and raises covered edges by about half again.
  needs_long_inputs "$target" && args+=(-len_control=0 -max_len=1024)

  if cargo +nightly fuzz run --features api "$target" -- "${args[@]}"; then
    if [ -n "${KNOWN_FAILING[$target]:-}" ]; then
      echo "??? $target is listed as known-failing (${KNOWN_FAILING[$target]}) but passed."
      echo "    If the defect is fixed, drop it from KNOWN_FAILING in this script."
    fi
    continue
  fi

  if [ -n "${KNOWN_FAILING[$target]:-}" ]; then
    echo "--- $target failed as expected: reproduces ${KNOWN_FAILING[$target]} (see VULN.md)"
    expected+=("$target")
  else
    echo "!!! $target exited non-zero (crash artifact written, or build error)"
    fail=1
  fi
done

if [ "${#expected[@]}" -gt 0 ]; then
  echo
  echo "known-failing targets that reproduced their defect: ${expected[*]}"
fi
exit "$fail"
