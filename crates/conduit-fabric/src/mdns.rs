//! LAN peer discovery over mDNS. The engine advertises its QUIC port as
//! `_conduit._udp.local.` and browses for the same; a resolved neighbor
//! lands in the shared candidate table the dialer merges with the coord's
//! endpoint list. Discovery never grants trust — the address is just a
//! dial candidate, and every connection still faces full mTLS against the
//! account's device list.

use crate::EngineHandle;
use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

const SERVICE_TYPE: &str = "_conduit._udp.local.";
/// How long a discovery entry stays dialable without a refresh.
const ENTRY_TTL: Duration = Duration::from_secs(150);

/// Device id → most recent LAN candidate. Shared with the engine loop.
#[derive(Clone, Default)]
pub struct MdnsPeers {
    inner: Arc<Mutex<HashMap<String, (SocketAddr, Instant)>>>,
}

impl MdnsPeers {
    /// The peer's freshest LAN address, if one is known and not stale.
    pub fn addr_of(&self, device_id: &str) -> Option<SocketAddr> {
        let map = self.inner.lock().unwrap();
        let (addr, seen) = map.get(device_id)?;
        (seen.elapsed() < ENTRY_TTL).then_some(*addr)
    }

    fn put(&self, device_id: String, addr: SocketAddr) {
        self.inner.lock().unwrap().insert(device_id, (addr, Instant::now()));
    }

    fn remove(&self, device_id: &str) {
        self.inner.lock().unwrap().remove(device_id);
    }
}

/// Advertise ourselves and browse for siblings until the process ends.
/// Any failure here only costs LAN discovery: the engine runs fine without.
pub fn spawn(quic_port: u16, my_id: &str, kick: EngineHandle) -> MdnsPeers {
    let my_id = my_id.to_string();
    let peers = MdnsPeers::default();
    let daemon = match ServiceDaemon::new() {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "mDNS daemon unavailable; LAN discovery disabled");
            return peers;
        }
    };
    let instance = sanitize_instance(&my_id);
    let host = format!("{instance}.local.");
    let props: HashMap<String, String> = [("device_id".into(), my_id.to_string())].into();
    let myself = match ServiceInfo::new(
        SERVICE_TYPE,
        &instance,
        &host,
        "",
        quic_port,
        Some(props),
    ) {
        Ok(s) => s.enable_addr_auto(),
        Err(e) => {
            warn!(error = %e, "mDNS service info invalid; LAN discovery disabled");
            return peers;
        }
    };
    if let Err(e) = daemon.register(myself) {
        warn!(error = %e, "mDNS register failed; LAN discovery disabled");
        return peers;
    }

    let receiver = match daemon.browse(SERVICE_TYPE) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "mDNS browse failed; LAN discovery disabled");
            return peers;
        }
    };
    info!(service = SERVICE_TYPE, %quic_port, "mDNS discovery on");

    let peers_out = peers.clone();
    tokio::spawn(async move {
        let _daemon = daemon; // keep alive for as long as we browse
        // Instance labels are truncated device ids; identity comes from the
        // TXT record. This maps an instance back to its device id so that
        // removals drop the right table entry.
        let mut by_instance: HashMap<String, String> = HashMap::new();
        while let Ok(event) = receiver.recv_async().await {
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    let (Some(raw), Some(addr)) = (
                        info.get_property_val_str("device_id"),
                        pick_addr(&info),
                    ) else {
                        continue;
                    };
                    if raw == my_id {
                        continue;
                    }
                    if let Some(label) = info.get_fullname().split('.').next() {
                        by_instance.insert(label.to_string(), raw.to_string());
                    }
                    info!(peer = %raw, %addr, "mdns peer resolved");
                    peers_out.put(raw.to_string(), addr);
                    kick.kick(false);
                }
                ServiceEvent::ServiceRemoved(_service, full_name) => {
                    let instance = full_name.split('.').next().unwrap_or("");
                    if let Some(id) = by_instance.remove(instance) {
                        debug!(peer = %id, "mdns peer removed");
                        peers_out.remove(&id);
                    }
                }
                _ => {}
            }
        }
    });
    peers
}

/// The most dialable address a resolved service offered. Prefer a v4
/// candidate: a link-local v6 loses its scope id when flattened to IpAddr
/// and would be undialable.
fn pick_addr(info: &ResolvedService) -> Option<SocketAddr> {
    let ip = info
        .get_addresses()
        .iter()
        .find(|a| matches!(a, mdns_sd::ScopedIp::V4(_)))
        .or_else(|| info.get_addresses().iter().next())?;
    Some(SocketAddr::new(ip.to_ip_addr(), info.get_port()))
}

/// One-shot LAN sweep for `doctor`: browse for `wait` and collect every
/// sibling instance (device id → address). Best effort; empty on any failure.
pub fn discover_once(wait: Duration) -> HashMap<String, SocketAddr> {
    let mut out = HashMap::new();
    let daemon = match ServiceDaemon::new() {
        Ok(d) => d,
        Err(_) => return out,
    };
    let receiver = match daemon.browse(SERVICE_TYPE) {
        Ok(r) => r,
        Err(_) => return out,
    };
    let deadline = Instant::now() + wait;
    while let Ok(event) = receiver.recv_timeout(deadline.saturating_duration_since(Instant::now()))
    {
        if let ServiceEvent::ServiceResolved(info) = event {
            if let (Some(id), Some(addr)) = (
                info.get_property_val_str("device_id"),
                pick_addr(&info),
            ) {
                out.insert(id.to_string(), addr);
            }
        }
    }
    let _ = daemon.shutdown();
    out
}

/// mDNS instance label for a device id. mdns-sd silently ignores services
/// whose instance name exceeds 15 bytes (`SERVICE_NAME_LEN_MAX_DEFAULT`),
/// so a full 43-char id never announces at all — truncate, and keep real
/// identity in the TXT `device_id` record. 12 hex chars = 48 bits; the odds
/// of two devices colliding on a LAN are negligible.
fn sanitize_instance(id: &str) -> String {
    let clean: String = id.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    clean.chars().take(12).collect()
}
