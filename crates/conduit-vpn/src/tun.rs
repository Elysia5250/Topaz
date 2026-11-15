//! Platform TUN creation (Linux `/dev/net/tun`, macOS `utun`) and
//! bidirectional packet pump between the TUN interface and `EngineHandle`.

use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use bytes::Bytes;
use conduit_fabric::{EngineHandle, SharedStatus};
use conduit_proto::auth::CONDUIT_VPN_CIDR;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use tun_rs::{AsyncDevice, DeviceBuilder};

use crate::dns::{bind_dns_socket, configure_system_dns, serve_dns};
use crate::route::{OutboundAction, RouteTable};
use crate::{SharedVpnStatus, VpnConfig, VpnStatus};

const INBOUND_DATAGRAM_QUEUE: usize = 1024;

pub(crate) async fn run_vpn_loop(
    engine: EngineHandle,
    status: Arc<SharedStatus>,
    vpn_status: SharedVpnStatus,
    cfg: VpnConfig,
) {
    let routes = Arc::new(RwLock::new(RouteTable::from_status(&status.engine())));

    // Wait until coord IPAM populates our own 100.64.x.y address.
    let self_ip = loop {
        let eng = status.engine();
        *routes.write().unwrap() = RouteTable::from_status(&eng);
        if let Some(ip) = routes.read().unwrap().self_ip() {
            break ip;
        }
        status.changed().await;
    };

    let dev = match open_tun(self_ip, &cfg) {
        Ok(d) => d,
        Err(e) => {
            warn!(
                error = %e,
                "could not open TUN device (run with sudo / CAP_NET_ADMIN, or pass --no-tun); \
                 continuing in session/control.sock-only mode"
            );
            vpn_status.set(VpnStatus {
                enabled: false,
                interface: None,
                cidr: CONDUIT_VPN_CIDR.to_string(),
                mtu: cfg.mtu,
                dns_listen: None,
                error: Some(e.to_string()),
            });
            status.signal();
            return;
        }
    };

    let iface = dev.name().unwrap_or_else(|_| "tun".to_string());
    let mut dns_guard = None;
    let mut dns_listen_str = None;
    let mut dns_task = None;

    match bind_dns_socket(cfg.dns_listen, self_ip).await {
        Ok(sock) => match sock.local_addr() {
            Ok(addr) => {
                dns_listen_str = Some(addr.to_string());
                dns_guard = Some(configure_system_dns(&iface, addr).await);
                dns_task = Some(tokio::spawn(serve_dns(sock, routes.clone())));
                info!(iface = %iface, dns = %addr, "local *.conduit DNS responder started");
            }
            Err(e) => warn!(error = %e, "reading bound DNS socket address failed"),
        },
        Err(e) => warn!(error = %e, "could not bind local *.conduit DNS responder"),
    }

    vpn_status.set(VpnStatus {
        enabled: true,
        interface: Some(iface.clone()),
        cidr: CONDUIT_VPN_CIDR.to_string(),
        mtu: cfg.mtu,
        dns_listen: dns_listen_str,
        error: None,
    });
    status.signal();

    info!(
        iface = %iface,
        ip = %self_ip,
        cidr = CONDUIT_VPN_CIDR,
        mtu = cfg.mtu,
        "VPN TUN data plane active"
    );

    let (in_tx, mut in_rx) = mpsc::channel::<(String, Bytes)>(INBOUND_DATAGRAM_QUEUE);
    engine.set_datagram_sink(in_tx);

    // Extra headroom above MTU so partial/oversized reads never truncate silently.
    let mut buf = vec![0u8; (cfg.mtu as usize).max(2048) + 64];

    loop {
        tokio::select! {
            biased;
            res = dev.recv(&mut buf) => {
                match res {
                    Ok(n) => {
                        let pkt = &buf[..n];
                        let action = {
                            let guard = routes.read().unwrap();
                            guard.route_outbound(pkt)
                        };
                        if let OutboundAction::Forward { peer_id } = action {
                            if let Err(e) = engine.send_datagram(&peer_id, Bytes::copy_from_slice(pkt)) {
                                debug!(peer = %peer_id, len = n, error = %e, "outbound packet not sent");
                            }
                        }
                    }
                    Err(e) => {
                        warn!(iface = %iface, error = %e, "TUN read failed; stopping VPN loop");
                        break;
                    }
                }
            }
            Some((peer_id, pkt)) = in_rx.recv() => {
                let allowed = {
                    let guard = routes.read().unwrap();
                    guard.validate_inbound(&peer_id, &pkt)
                };
                if allowed {
                    if let Err(e) = dev.send(&pkt).await {
                        debug!(iface = %iface, peer = %peer_id, error = %e, "TUN write failed");
                    }
                } else {
                    debug!(peer = %peer_id, len = pkt.len(), "dropped inbound packet failing source-IP check");
                }
            }
            _ = status.changed() => {
                let eng = status.engine();
                *routes.write().unwrap() = RouteTable::from_status(&eng);
            }
        }
    }

    if let Some(t) = dns_task {
        t.abort();
    }
    drop(dns_guard);
    vpn_status.set(VpnStatus {
        enabled: false,
        interface: None,
        cidr: CONDUIT_VPN_CIDR.to_string(),
        mtu: cfg.mtu,
        dns_listen: None,
        error: Some("TUN loop exited".to_string()),
    });
    status.signal();
}

fn open_tun(self_ip: Ipv4Addr, cfg: &VpnConfig) -> Result<AsyncDevice> {
    let mut builder = DeviceBuilder::new().ipv4(self_ip, 10, None).mtu(cfg.mtu);

    #[cfg(target_os = "linux")]
    {
        let name = cfg.tun_name.as_deref().unwrap_or("conduit0");
        builder = builder.name(name);
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(name) = cfg.tun_name.as_deref() {
            builder = builder.name(name);
        }
        builder = builder.with(|b| {
            b.associate_route(true).packet_information(false);
        });
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        if let Some(name) = cfg.tun_name.as_deref() {
            builder = builder.name(name);
        }
    }

    builder
        .build_async()
        .context("create and configure TUN interface")
}
