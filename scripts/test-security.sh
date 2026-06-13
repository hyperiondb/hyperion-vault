#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== security test suite (hyperion-vault-core) =="
cargo test -p hyperion-vault-core \
  --test crypto_security \
  --test auth_security \
  --test ip_allowlist_security \
  --test rotation_policy \
  --test rbac_security

if command -v cargo-audit >/dev/null 2>&1; then
  echo "== cargo audit =="
  cargo audit
else
  echo "cargo-audit not installed; skipping (install: cargo install --locked cargo-audit)"
fi

echo "security checks passed"
