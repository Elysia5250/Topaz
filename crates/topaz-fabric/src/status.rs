//! Engine-side status shared with the host process.

use std::sync::Mutex;
use std::time::Duration;
use topaz_proto::mux::AdvertisedService;
use topaz_proto::DeviceCert;
use tokio::sync::{watch, Notify};

/// Virtual network address assigned by coordination IPAM.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VirtualAddr {
    pub virtual_ip: Option<String>,
    pub dns_name: Option<String>,
}

/// Snapshot of engine state for status rendering.
#[derive(Debug, Clone, Default)]
pub struct EngineStatus {
    /// Virtual address assigned to this device.
    pub self_addr: VirtualAddr,
    /// The account's other devices, as of the last refresh.
    pub peers: Vec<DeviceCert>,
    /// Virtual addresses per peer: device id -> assigned IP/DNS label.
    pub peer_addrs: Vec<(String, VirtualAddr)>,
    /// Live sessions: device id -> connection kind.
    pub sessions: Vec<(String, topaz_net::ConnectionKind)>,
    /// Round-trip probes per peer: device id -> last RTT.
    pub rtts: Vec<(String, Duration)>,
    /// Application services advertised by each connected peer.
    pub peer_services: Vec<(String, Vec<AdvertisedService>)>,
    /// Peers that have sent at least one DISCOVERY frame in this session.
    ///
    /// Distinguishes "supports discovery, advertises nothing" from "older peer
    /// that never advertised", which matters before trusting `peer_services`.
    pub discovery_seen: Vec<String>,
}

impl EngineStatus {
    pub fn peer_addr(&self, device_id: &str) -> Option<&VirtualAddr> {
        self.peer_addrs
            .iter()
            .find(|(id, _)| id == device_id)
            .map(|(_, addr)| addr)
    }

    pub fn peer_services(&self, device_id: &str) -> &[AdvertisedService] {
        self.peer_services
            .iter()
            .find(|(id, _)| id == device_id)
            .map(|(_, svcs)| svcs.as_slice())
            .unwrap_or(&[])
    }

    /// Whether this peer has advertised its service list at least once.
    pub fn has_discovery(&self, device_id: &str) -> bool {
        self.discovery_seen.iter().any(|id| id == device_id)
    }
}

/// Shared between the engine, its services (ping writes RTTs) and the host's
/// status writer. All fields are best-effort snapshots; nobody blocks.
pub struct SharedStatus {
    inner: Mutex<EngineStatus>,
    changed: Notify,
    seq: watch::Sender<u64>,
}

impl Default for SharedStatus {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedStatus {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(EngineStatus::default()),
            changed: Notify::new(),
            seq: watch::channel(0).0,
        }
    }

    pub fn engine(&self) -> EngineStatus {
        self.inner.lock().unwrap().clone()
    }

    pub fn signal(&self) {
        self.seq.send_modify(|n| *n = n.wrapping_add(1));
        self.changed.notify_waiters();
    }

    /// Wait until someone signals a change (or the wait is cancelled).
    pub async fn changed(&self) {
        self.changed.notified().await;
    }

    /// Race-free change receiver for streaming status observers.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.seq.subscribe()
    }

    pub(crate) fn set_peers(&self, peers: &[DeviceCert]) {
        self.inner.lock().unwrap().peers = peers.to_vec();
    }

    pub(crate) fn set_addrs(
        &self,
        self_addr: VirtualAddr,
        peer_addrs: Vec<(String, VirtualAddr)>,
    ) {
        let mut st = self.inner.lock().unwrap();
        st.self_addr = self_addr;
        st.peer_addrs = peer_addrs;
    }

    pub(crate) fn set_sessions(&self, sessions: Vec<(String, topaz_net::ConnectionKind)>) {
        self.inner.lock().unwrap().sessions = sessions;
    }

    pub(crate) fn set_peer_services(&self, peer: &str, services: Vec<AdvertisedService>) {
        let mut st = self.inner.lock().unwrap();
        match st.peer_services.iter_mut().find(|(id, _)| id == peer) {
            Some(slot) => slot.1 = services,
            None => st.peer_services.push((peer.to_string(), services)),
        }
    }

    pub(crate) fn retain_peer_services(&self, sessions: &[(String, topaz_net::ConnectionKind)]) {
        let mut st = self.inner.lock().unwrap();
        st.peer_services
            .retain(|(id, _)| sessions.iter().any(|(sid, _)| sid == id));
    }

    pub(crate) fn mark_discovery(&self, peer: &str) {
        let mut st = self.inner.lock().unwrap();
        if !st.discovery_seen.iter().any(|id| id == peer) {
            st.discovery_seen.push(peer.to_string());
        }
    }

    pub(crate) fn clear_discovery(&self, peer: &str) {
        let mut st = self.inner.lock().unwrap();
        st.discovery_seen.retain(|id| id != peer);
    }

    pub(crate) fn retain_discovery(&self, alive: &[String]) {
        let mut st = self.inner.lock().unwrap();
        st.discovery_seen
            .retain(|id| alive.iter().any(|sid| sid == id));
    }

    /// Record a round-trip measurement (used by the ping service).
    pub fn set_rtt(&self, peer: &str, rtt: Duration) {
        let mut st = self.inner.lock().unwrap();
        match st.rtts.iter_mut().find(|(id, _)| id == peer) {
            Some(slot) => slot.1 = rtt,
            None => st.rtts.push((peer.to_string(), rtt)),
        }
    }
}
