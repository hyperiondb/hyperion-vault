#!/usr/bin/env bash
set -e

BASE_URL="${HYPERION_VAULT_REPO_URL:-https://hyperiondb.github.io/hyperion-vault}"
DIST="${HYPERION_VAULT_DIST:-stable}"
KEYRING="/usr/share/keyrings/hyperion_vault.gpg"
LIST="/etc/apt/sources.list.d/hyperion_vault.list"

if [ "$(id -u)" -ne 0 ]; then
  echo "this installer must run as root — pipe it to: sudo bash" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  apt-get update
  apt-get install -y curl ca-certificates
fi

curl -fsSL "${BASE_URL}/hyperion_vault.gpg" -o "${KEYRING}"
ARCH="$(dpkg --print-architecture)"
echo "deb [arch=${ARCH} signed-by=${KEYRING}] ${BASE_URL} ${DIST} main" > "${LIST}"
apt-get update

echo
echo "hyperion-vault apt repository added."
echo "Install for your PostgreSQL major version, e.g.:"
echo "  apt-get install -y postgresql-18-hyperion-vault"
