# Admin access over WireGuard

WireGuard is an **optional** front door for operators. It puts the API behind a
mutually-authenticated, encrypted tunnel so that management/write endpoints —
and, when configured, reads — are reachable only by enrolled admin devices.

Why it fits an admin-only surface:

- **MITM-resistant by construction.** Each peer is pinned to the other's
  public key (Curve25519, Noise handshake). A handshake only completes with the
  holder of the matching private key, so an on-path attacker can't impersonate
  either end, decrypt, or inject. There is **no CA** to mis-issue and no
  trust-on-first-use window — stronger than public-CA TLS for this case.
- **Hides the API.** With only the tunnel's UDP port exposed, the API has no
  public attack surface (no login page to scan or brute-force).
- **Kernel data plane.** Uses in-kernel WireGuard via `wg-quick` — audited,
  fast, and standard. No application code is involved; this is deployment
  config only.

This complements, and does not replace, the API's bearer tokens + RBAC (user
identity and authorization) and Postgres auth.

## Topology

```
admin device (10.7.0.2)  ──wg──►  gateway (wg0 10.7.0.1)
                                   eth0 172.30.0.2  ──►  api1 172.30.0.11:8200
                                                         api2 172.30.0.12:8200
                                                         api3 172.30.0.13:8200
```

- Admin devices are WireGuard peers on `10.7.0.0/24` (hub `10.7.0.1`).
- The gateway joins the cluster network `172.30.0.0/24` and forwards tunnel
  traffic to the APIs, masquerading the source. The APIs therefore see the
  gateway (`172.30.0.2`) as the client IP, and `VAULT_ALLOWED_IPS` is set to
  `172.30.0.2/32` — so a read is accepted only when it arrives through the
  tunnel.

## 1. Generate keys

Requires `wireguard-tools` (the `wg` command) on the machine you run this from
(any Linux box, or inside the gateway container).

```bash
WG_ENDPOINT=vault.example.com:51820 bash scripts/wireguard/gen-keys.sh admin1 admin2
```

This writes (all **gitignored**, never commit them):

- `docker/wireguard/wg0.conf` — the hub config, with one `[Peer]` per admin.
- `docker/wireguard/clients/<name>.conf` — one client config per admin.

Set `WG_ENDPOINT` to the gateway's public `host:port` so the client configs
dial the right address.

## 2. Bring up the cluster with the gateway

```bash
docker compose \
  -f docker/docker-compose.yml \
  -f docker/docker-compose.wireguard.yml \
  up --build
```

Only UDP `51820` is published for the tunnel.

## 3. Connect an admin device

Import `docker/wireguard/clients/admin1.conf` into the WireGuard app, or on
Linux:

```bash
wg-quick up ./docker/wireguard/clients/admin1.conf
curl http://172.30.0.11:8200/v1/secrets/db/password \
  -H "Authorization: Bearer $VAULT_ADMIN_TOKEN"
```

## Add / remove admins

- Re-run `gen-keys.sh` with the full list of names, or append a `[Peer]` block
  to `wg0.conf` and apply it live with `wg syncconf wg0 <(wg-quick strip wg0)`.
- Removing a peer revokes that device immediately.

## Trade-offs

- **Source IP is the gateway.** Because traffic is masqueraded, every tunnel
  client appears to the API as `172.30.0.2`. Per-admin identity is still
  enforced by **RBAC tokens** and recorded as the actor in `vault.audit_log`,
  but the audit `client_ip` and the brute-force **lockout** are keyed to the
  gateway — so a lockout affects all tunnel users together. If you need
  per-admin source IPs (and per-admin lockout), run the gateway in routed
  (no-NAT) mode and give each API a return route to `10.7.0.0/24`, then set
  `VAULT_ALLOWED_IPS=10.7.0.0/24`.
- **Kernel module required.** The host must provide the `wireguard` module
  (present on Linux ≥ 5.6 and recent Docker Desktop / WSL2 kernels).
- **UDP only.** Clients on networks that block UDP can't connect; listen on
  `443/udp` if that is a concern.

## Production hardening

- **Don't publish the API ports.** Run the API services without the host
  `ports:` mappings so `:8200`–`:8202` are unreachable except over the tunnel;
  expose only the gateway's UDP `51820`.
- **Keep TLS on the API** for browser secure-context (cookies, HSTS, WebAuthn)
  and defense in depth, even inside the tunnel.
- **Protect client keys.** The `.conf` files contain private keys; store them
  in the OS keychain and rotate by regenerating keys and dropping old peers.
- **Endpoint compromise still wins.** A stolen device with an unlocked key is a
  valid peer; rely on disk encryption and device locking, and revoke promptly.
