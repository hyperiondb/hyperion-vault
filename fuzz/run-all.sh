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

# --features api so the api-backed targets are real (core targets ignore it);
# one build, no feature-flip rebuilds between targets.
fail=0
for target in $(cargo +nightly fuzz list); do
  echo "=== $target (${budget}s) ==="
  if ! cargo +nightly fuzz run --features api "$target" -- \
      -max_total_time="$budget" -print_final_stats=1; then
    echo "!!! $target exited non-zero (crash artifact written, or build error)"
    fail=1
  fi
done
exit "$fail"
