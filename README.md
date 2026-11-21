# Topaz

P2P mesh network & session fabric workspace (virtual intranet `100.64.0.0/10` + `*.topaz` DNS + extensible `Service` plugin bus).

## Crates

- `topaz-proto`: Identity/account/device-cert/mux/STUN wire types (`DeviceCert`, `AccountRoot`, `SignalEnvelope`, `Frame`, `Mux`, `StunPacket`).
- `topaz-core`: Device identity (`device.json`), account metadata (`account.json`), and `Store` / `Config` (`config.json`).
- `topaz-net`: QUIC + mTLS endpoint (streams & unreliable datagrams), TCP/WSS relay fallback, UDP STUN & hole-punching, SPAKE2 enrollment, coord HTTP client, stream multiplexer (`Multiplexer`, `Channel`).
- `topaz-fabric`: Session engine (`EngineHandle`, `Service` trait, `PingService`, mDNS LAN discovery, RTT probe, datagram forwarding, `DISCOVERY` service advertisement).
- `topaz-vpn`: L3 TUN virtual network data plane (`100.64.0.0/10` on Linux/macOS), source-IP anti-spoofing, and `*.topaz` local DNS.
- `topaz-coord`: Coordination, STUN, IPAM (`100.64.0.0/10` + unique DNS names), and WebSocket/TCP relay server (accounts, devices, signaling, invites).
- `topaz-cli` (`topaz`): Network daemon, CLI & Jade-aligned TUI (`init`, `account`, `device`, `join`, `setup`, `run [--no-tun] [--detach]`, `stop`, `status`, `kick`, `doctor`, `service`, `tui`).

---

## Deploying `topaz-coord` on a Linux VPS (Instructions for Server-Side Agents)

> **For AI agents running on the target Linux VPS**: Prefer the **zero-build** path below — it downloads a prebuilt static `musl` binary from GitHub Releases (no Rust toolchain, no `git clone`, runs comfortably on 256 MB / 512 MB RAM VPSes). Do **not** put `topaz-coord` behind a standard TLS-terminating reverse proxy — clients pin the server's self-signed Ed25519 TLS key directly.

### Prerequisites
- Linux (`x86_64` or `aarch64`) with `systemd`, `curl`, and `root` / `sudo` access
- Public IPv4 address (auto-detected if not passed)

### Step 1: One-command zero-build install (or upgrade)
Detect the VPS public IPv4 (or substitute the desired public IP / domain) and run the idempotent installer:
```bash
PUBLIC_IP="$(curl -4 -fsS https://ifconfig.me)"
curl -fsSL https://raw.githubusercontent.com/Elysia5250/Topaz/master/scripts/deploy-coord.sh \
  | sudo bash -s -- --public-url "https://${PUBLIC_IP}:7722"
```
- The script automatically detects `x86_64` / `aarch64`, downloads `topaz-coord-linux-<arch>` + `SHA256SUMS.txt` from the latest GitHub Release, verifies SHA256, and configures `topaz-coord.service`.
- Optional: append `--ws-443` if port `443/tcp` is free and you want extra WSS relay fallback on `443`; append `--version v0.1.0` to pin a specific release tag.
- Re-running the same command safely upgrades `/usr/local/bin/topaz-coord` without overwriting `/etc/topaz-coord/coord.env` or `/var/lib/topaz-coord/coord.db`.
- *(Fallback — build from source only if no release asset exists for the host architecture)*:
  ```bash
  git clone https://github.com/Elysia5250/Topaz.git /opt/topaz-src && cd /opt/topaz-src
  cargo build --release -p topaz-coord
  sudo ./scripts/deploy-coord.sh --binary ./target/release/topaz-coord --public-url "https://${PUBLIC_IP}:7722"
  ```

### Step 2: Open required firewall ports
Ensure both the OS firewall (`ufw` / `firewalld` / `iptables`) and cloud provider security group allow:
- `7722/tcp` — HTTPS control plane + WSS signaling & WSS relay
- `7723/tcp` — TCP relay
- `3478/udp` — UDP STUN (NAT hole punching)
- `443/tcp` — *(only if `--ws-443` was enabled)*

Example for `ufw`:
```bash
sudo ufw allow 7722/tcp
sudo ufw allow 7723/tcp
sudo ufw allow 3478/udp
```

### Step 3: Verify the service is healthy
```bash
sudo systemctl is-active topaz-coord.service
curl -kfsS https://127.0.0.1:7722/healthz && echo " OK"
```
Both commands must succeed (`active` and `ok OK`). If not, inspect logs with `sudo journalctl -u topaz-coord -n 50 --no-pager`.

### Step 4: Generate the first invite code & report back to the user
```bash
sudo -u topaz bash -c 'set -a; source /etc/topaz-coord/coord.env; topaz-coord invite create'
```
**Report the following items clearly back to the user**:
1. Service status (`active`) and open ports confirmation (`7722/tcp`, `7723/tcp`, `3478/udp`).
2. The `COORD_PUBLIC_URL` and TLS `pin` (`topaz-coord fingerprint`).
3. The complete one-line `topaz account create --coord-url ... --pin ... --invite ...` command printed in Step 4 so the user can paste it directly on their first client machine.

For ongoing operations (usage stats, backup, manual config), see [docs/coord-deploy.md](./docs/coord-deploy.md).

---

## Client Quick Start (Linux / macOS)

```bash
# Build client binary
cargo build --release -p topaz-cli

# 1. First device (paste the one-line command generated on the VPS):
topaz account create --coord-url https://<VPS_IP>:7722 --pin <PIN> --invite <CODE> --name linux-box

# 2. Start daemon (with L3 TUN, or add --no-tun for user-level control.sock mode):
sudo topaz run --detach   # or: topaz run --no-tun --detach

# 3. Open live TUI (auto-opens when daemon is running):
topaz                     # press `a` to pair a new device, `c` to copy setup command

# 4. Join a second device (e.g. MacBook) in one command:
topaz setup 'topaz-setup:v1:...' --name macbook --start

# 5. Stop daemon cleanly:
topaz stop
```

## Boundary

Upper-layer applications (e.g. `jade`, `opal`) plug into `topaz_fabric::Service` or bridge at runtime over `control.sock` using allocated service IDs (`1` for sync, `16..` for registered services) without adding business state into `topaz`. See [ARCHITECTURE.md](./ARCHITECTURE.md) and [docs/jade-integration.md](./docs/jade-integration.md) for the integration contract.

## Test

```bash
cargo test --workspace
```
