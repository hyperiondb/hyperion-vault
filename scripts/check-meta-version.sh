#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cargo_ver="$(sed -nE '/^\[workspace\.package\]/,/^\[/ s/^version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "$ROOT/Cargo.toml" | head -n1)"
meta_ver="$(jq -r '.version' "$ROOT/META.json")"
prov_ver="$(jq -r '.provides.hyperion_vault.version' "$ROOT/META.json")"

if [ -z "$cargo_ver" ]; then
  echo "could not read [workspace.package] version from Cargo.toml" >&2
  exit 1
fi

status=0
if [ "$meta_ver" != "$cargo_ver" ]; then
  echo "META.json .version ($meta_ver) != workspace version ($cargo_ver)" >&2
  status=1
fi
if [ "$prov_ver" != "$cargo_ver" ]; then
  echo "META.json .provides.hyperion_vault.version ($prov_ver) != workspace version ($cargo_ver)" >&2
  status=1
fi

if [ "$status" -ne 0 ]; then
  echo "fix: set those META.json versions to $cargo_ver" >&2
  exit 1
fi

echo "META.json version matches workspace: $cargo_ver"
