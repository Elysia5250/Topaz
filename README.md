# Topaz (`topaz/`)

P2P mesh network & session fabric workspace (virtual intranet + extensible `Service` plugin bus).

## Crates

- `topaz-proto`: Identity/account/device-cert/mux/STUN wire types (`DeviceCert`, `AccountRoot`, `SignalEnvelope`, `Frame`, `Mux`, `StunPacket`).
- `topaz-core`: Device identity (`device.json`), account metadata (`account.json`), and `Store` / `Config` (`config.json`).
- `topaz-net`: QUIC + mTLS endpoint (streams & unreliable datagrams), TCP/WSS relay fallback, UDP STUN & hole-punching, SPAKE2 enrollment, coord HTTP client, stream multiplexer (`Multiplexer`, `Channel`).
- `topaz-fabric`: Session engine (`EngineHandle`, `Service` trait, `PingService`, mDNS LAN discovery, RTT probe, datagram forwarding).
- `topaz-vpn`: L3 TUN virtual network data plane (`100.64.0.0/10` on Linux/macOS), source-IP anti-spoofing, and `*.topaz` local DNS.
- `topaz-coord`: Coordination, STUN, IPAM (`100.64.0.0/10` + unique DNS names), and WebSocket/TCP relay server (accounts, devices, signaling, invites).
- `topaz-cli` (`topaz`): Network daemon & CLI (`init`, `account`, `device`, `join`, `setup`, `run [--no-tun]`, `status`, `kick`, `doctor`, `service`).

## Boundary

Upper-layer applications (e.g. `jade`, `opal`) plug into `topaz_fabric::Service` or bridge at runtime over `control.sock` / L3 virtual IP using allocated service IDs (`1` for sync, `16..` for registered services) without adding business state into `topaz`. See [ARCHITECTURE.md](./ARCHITECTURE.md) and [docs/jade-integration.md](./docs/jade-integration.md) for the integration contract.

## Test

```bash
cargo test --workspace
```
