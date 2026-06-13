#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== fmt =="
cargo fmt --all -- --check

echo "== clippy (non-pgrx crates) =="
cargo clippy -p hyperion-vault-core -p hyperion-vault-api -p hyperion-vault --all-targets -- -D warnings

echo "== core tests =="
cargo test -p hyperion-vault-core

echo "== api build =="
cargo build -p hyperion-vault-api

echo "all checks passed"
