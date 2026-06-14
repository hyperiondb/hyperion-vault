#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
wg_dir="${repo_root}/docker/wireguard"
clients_dir="${wg_dir}/clients"
endpoint="${WG_ENDPOINT:-SERVER_PUBLIC_HOST:51820}"
docker_subnet="${WG_DOCKER_SUBNET:-172.30.0.0/24}"
wg_subnet="${WG_TUNNEL_SUBNET:-10.7.0.0/24}"
hub_addr="${WG_HUB_ADDR:-10.7.0.1}"

command -v wg >/dev/null 2>&1 || {
    echo "wireguard-tools not found: install 'wireguard-tools' to get the 'wg' command" >&2
    exit 1
}

names=("$@")
if [ "${#names[@]}" -eq 0 ]; then
    names=("admin1")
fi

umask 077
mkdir -p "${clients_dir}"

hub_priv="$(wg genkey)"
hub_pub="$(printf '%s' "${hub_priv}" | wg pubkey)"

conf="${wg_dir}/wg0.conf"
{
    echo "[Interface]"
    echo "Address = ${hub_addr}/24"
    echo "ListenPort = 51820"
    echo "PrivateKey = ${hub_priv}"
    echo "PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -s ${wg_subnet} -o eth0 -j MASQUERADE"
    echo "PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -s ${wg_subnet} -o eth0 -j MASQUERADE"
} >"${conf}"

octet=2
for name in "${names[@]}"; do
    client_priv="$(wg genkey)"
    client_pub="$(printf '%s' "${client_priv}" | wg pubkey)"
    client_addr="10.7.0.${octet}"

    {
        echo ""
        echo "[Peer]"
        echo "PublicKey = ${client_pub}"
        echo "AllowedIPs = ${client_addr}/32"
    } >>"${conf}"

    {
        echo "[Interface]"
        echo "PrivateKey = ${client_priv}"
        echo "Address = ${client_addr}/32"
        echo ""
        echo "[Peer]"
        echo "PublicKey = ${hub_pub}"
        echo "Endpoint = ${endpoint}"
        echo "AllowedIPs = ${docker_subnet}, ${wg_subnet}"
        echo "PersistentKeepalive = 25"
    } >"${clients_dir}/${name}.conf"
    chmod 600 "${clients_dir}/${name}.conf"

    octet=$((octet + 1))
done

chmod 600 "${conf}"

echo "hub public key: ${hub_pub}"
echo "wrote ${conf}"
for name in "${names[@]}"; do
    echo "wrote ${clients_dir}/${name}.conf"
done
echo "set WG_ENDPOINT to the gateway's public host:port before distributing client configs"
