#!/usr/bin/env bash
set -euo pipefail

PG_MAJOR="${1:?usage: packaging/build-deb.sh <pg-major>}"
EXT="hyperion_vault"
PKG="postgresql-${PG_MAJOR}-hyperion-vault"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRATE_DIR="${ROOT}/extension"
PG_CONFIG="${PG_CONFIG:-/usr/lib/postgresql/${PG_MAJOR}/bin/pg_config}"
ARCH="$(dpkg --print-architecture)"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "${ROOT}/Cargo.toml" | head -1)"
OUT_DIR="${ROOT}/dist"

if [ ! -x "$PG_CONFIG" ]; then
  echo "missing $PG_CONFIG — install postgresql-server-dev-${PG_MAJOR}" >&2
  exit 1
fi

cd "$CRATE_DIR"
export PGRX_PG_CONFIG_PATH="$PG_CONFIG"
cargo pgrx package --no-default-features --features "pg${PG_MAJOR}" --pg-config "$PG_CONFIG"

cd "$ROOT"
cargo build --release -p hyperion-vault-api

TARGET_DIR="$(cargo metadata --no-deps --format-version 1 \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["target_directory"])')"
STAGE="$(find "${TARGET_DIR}/release" -maxdepth 1 -type d -name "${EXT}-pg${PG_MAJOR}*" | head -1)"
if [ -z "${STAGE}" ] || [ ! -d "${STAGE}" ]; then
  echo "package stage not found under ${TARGET_DIR}/release" >&2
  exit 1
fi

PKGROOT="$(mktemp -d)"
cp -a "${STAGE}/." "${PKGROOT}/"
mkdir -p "${PKGROOT}/DEBIAN" "${PKGROOT}/usr/bin"
install -m 0755 "${TARGET_DIR}/release/hyperion-vault-api" "${PKGROOT}/usr/bin/hyperion-vault-api"

cat > "${PKGROOT}/DEBIAN/control" <<EOF
Package: ${PKG}
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: Tadas Talaikis <info@nordlet.com>
Section: database
Priority: optional
Depends: postgresql-${PG_MAJOR}
Recommends: postgresql-${PG_MAJOR}-pg-replica
Homepage: https://github.com/hyperiondb/hyperion-vault
Description: Encrypted secrets vault for PostgreSQL (KMS envelope encryption, REST API)
 hyperion-vault stores secrets encrypted at rest with AWS KMS envelope
 encryption and XChaCha20-Poly1305, and ships a REST API to create, read,
 update, delete, verify, and automatically rotate them. Built with pgrx and
 designed to run on every node of a pg_replica cluster.
EOF

cat > "${PKGROOT}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
cat <<'MSG'
hyperion-vault installed.

Extension:
  1) add it to shared_preload_libraries in postgresql.conf:
       shared_preload_libraries = 'pg_replica,hyperion_vault'
  2) restart PostgreSQL
  3) in your database:  CREATE EXTENSION hyperion_vault;
                        SELECT vault.grant_service_role('<service_role>');

REST API:
  /usr/bin/hyperion-vault-api  (configure via VAULT_* environment variables;
  run it under systemd next to PostgreSQL on each node).

See https://github.com/hyperiondb/hyperion-vault for configuration.
MSG
EOF
chmod 0755 "${PKGROOT}/DEBIAN/postinst"

mkdir -p "${OUT_DIR}"
DEB="${OUT_DIR}/${PKG}_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "${PKGROOT}" "${DEB}"
rm -rf "${PKGROOT}"
echo "built ${DEB}"
