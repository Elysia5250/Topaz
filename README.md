# Conduit (`conduit/`)

P2P mesh network & session fabric workspace (virtual intranet + extensible `Service` plugin bus).

## Crates

- `conduit-proto`: Identity/account/device-cert/mux/STUN wire types (`DeviceCert`, `AccountRoot`, `SignalEnvelope`, `Frame`, `Mux`, `StunPacket`).
- `conduit-core`: Device identity (`device.json`), account metadata (`account.json`), and `Store` / `Config` (`config.json`).
- `conduit-net`: QUIC + mTLS endpoint (streams & unreliable datagrams), TCP/WSS relay fallback, UDP STUN & hole-punching, SPAKE2 enrollment, coord HTTP client, stream multiplexer (`Multiplexer`, `Channel`).
- `conduit-fabric`: Session engine (`EngineHandle`, `Service` trait, `PingService`, mDNS LAN discovery, RTT probe, datagram forwarding).
- `conduit-vpn`: L3 TUN virtual network data plane (`100.64.0.0/10` on Linux/macOS), source-IP anti-spoofing, and `*.conduit` local DNS.
- `conduit-coord`: Coordination, STUN, IPAM (`100.64.0.0/10` + unique DNS names), and WebSocket/TCP relay server (accounts, devices, signaling, invites).
- `conduit-cli` (`conduit`): Network daemon & CLI (`init`, `account`, `device`, `join`, `setup`, `run [--no-tun]`, `status`, `kick`, `doctor`, `service`).

## Boundary

Upper-layer applications (e.g. `envoy`, `grain`) plug into `conduit_fabric::Service` or bridge at runtime over `control.sock` / L3 virtual IP using allocated service IDs (`1` for sync, `16..` for registered services) without adding business state into `conduit`. See [ARCHITECTURE.md](./ARCHITECTURE.md) and [docs/envoy-integration.md](./docs/envoy-integration.md) for the integration contract.

## Test

```bash
cargo test --workspace
```
