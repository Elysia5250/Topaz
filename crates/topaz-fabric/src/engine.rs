//! Engine event loop, peer discovery refresh, eager mesh reconciliation,
//! and parallel idle keepalive probes.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use bytes::Bytes;
use topaz_core::DeviceIdentity;
use topaz_net::{
    collect_local_endpoints, spawn_punch_window, Channel, ConnectionKind, CoordClient, CoordError,
    DatagramSender, DynamicServices, Multiplexer, PeerLink, QuicEndpoint, RelayAddrs, TrustStore,
};
use topaz_proto::auth::{evaluate, parse_pubkey, DeviceSet};
use topaz_proto::{DeviceCert, DeviceEntry, RegisterResponse, SignalEnvelope};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::dial::{DialResult, HostMsg, PendingOpen, SessionEntry};
use crate::{
    AdvertisedService, DynamicStreamHandler, MdnsPeers, PeerInfo, Service, SharedStatus,
    VirtualAddr,
};

/// A quiet session gets a keepalive ping at this interval.
const IDLE_PROBE_EVERY: Duration = Duration::from_secs(20);
/// Unanswered probe timeout: tears down half-open links.
const IDLE_PROBE_TIMEOUT: Duration = Duration::from_secs(30);
/// Maintenance interval (refresh devices, re-register, reconcile mesh, idle probes).
const MAINT_EVERY: Duration = Duration::from_secs(5);
/// Re-collect local NICs and asynchronously re-probe STUN to survive Wi-Fi / NAT changes.
const ENDPOINT_REFRESH_EVERY: Duration = Duration::from_secs(45);
/// Periodically attempt direct hole-punching to upgrade live Relay sessions back to Direct.
const RELAY_UPGRADE_EVERY: Duration = Duration::from_secs(60);

pub(crate) enum KickMsg {
    Local,
    Remote,
}

pub(crate) enum StreamMsg {
    Stream(PeerInfo, u16, Channel),
    PeerServices(String, u64, Vec<AdvertisedService>),
    SessionDead,
}

pub(crate) struct ProbeResult {
    peer_id: String,
    mux: Multiplexer,
    outcome: std::result::Result<Duration, String>,
}

pub(crate) enum RefreshOutcome {
    Ok(Vec<DeviceEntry>),
    Revoked(String),
    ClockSkew(String),
    Transient(String),
}

pub(crate) struct RefreshResult {
    outcome: RefreshOutcome,
}

pub(crate) struct RegisterResult {
    outcome: std::result::Result<RegisterResponse, String>,
}

pub(crate) struct SessionReadyResult {
    peer: PeerInfo,
    mux: Multiplexer,
    ok: bool,
}

pub(crate) type DatagramSink = Arc<Mutex<Option<mpsc::Sender<(String, Bytes)>>>>;

pub(crate) struct EngineChannels {
    pub(crate) kick_rx: mpsc::UnboundedReceiver<KickMsg>,
    pub(crate) host_rx: mpsc::UnboundedReceiver<HostMsg>,
    pub(crate) signal_rx: mpsc::Receiver<SignalEnvelope>,
    pub(crate) stream_rx: mpsc::UnboundedReceiver<StreamMsg>,
    pub(crate) punched_rx: mpsc::UnboundedReceiver<PeerLink>,
    pub(crate) dial_done_rx: mpsc::UnboundedReceiver<DialResult>,
    pub(crate) probe_done_rx: mpsc::UnboundedReceiver<ProbeResult>,
    pub(crate) refresh_done_rx: mpsc::UnboundedReceiver<RefreshResult>,
    pub(crate) register_done_rx: mpsc::UnboundedReceiver<RegisterResult>,
    pub(crate) session_ready_rx: mpsc::UnboundedReceiver<SessionReadyResult>,
    pub(crate) endpoints_done_rx: mpsc::UnboundedReceiver<Vec<String>>,
}

pub(crate) struct Engine {
    pub(crate) my_id: String,
    pub(crate) identity: DeviceIdentity,
    pub(crate) account_user_pubkey: String,
    pub(crate) coord: CoordClient,
    pub(crate) trust: TrustStore,
    pub(crate) quic: QuicEndpoint,
    pub(crate) endpoints: Vec<String>,
    pub(crate) relay: RelayAddrs,
    pub(crate) signal_tx: mpsc::Sender<SignalEnvelope>,
    pub(crate) force_relay: bool,
    pub(crate) services: Arc<Vec<Arc<dyn Service>>>,
    pub(crate) service_ids: Vec<u16>,
    pub(crate) dynamic_ids: DynamicServices,
    pub(crate) dynamic_handlers: Arc<RwLock<HashMap<u16, DynamicStreamHandler>>>,
    pub(crate) local_services: Vec<AdvertisedService>,
    pub(crate) local_services_seq: u64,
    pub(crate) peer_discovery_seq: HashMap<String, u64>,
    pub(crate) status: Arc<SharedStatus>,
    pub(crate) device_set: Arc<Mutex<DeviceSet>>,
    pub(crate) datagrams: Arc<RwLock<HashMap<String, DatagramSender>>>,
    pub(crate) datagram_sink: DatagramSink,
    pub(crate) stream_tx: mpsc::UnboundedSender<StreamMsg>,
    pub(crate) punched_tx: mpsc::UnboundedSender<PeerLink>,
    pub(crate) dial_done_tx: mpsc::UnboundedSender<DialResult>,
    pub(crate) probe_done_tx: mpsc::UnboundedSender<ProbeResult>,
    pub(crate) refresh_done_tx: mpsc::UnboundedSender<RefreshResult>,
    pub(crate) register_done_tx: mpsc::UnboundedSender<RegisterResult>,
    pub(crate) session_ready_tx: mpsc::UnboundedSender<SessionReadyResult>,
    pub(crate) endpoints_done_tx: mpsc::UnboundedSender<Vec<String>>,
    pub(crate) on_devices_cached: Option<Arc<dyn Fn(&[DeviceEntry]) + Send + Sync>>,
    pub(crate) refresh_in_flight: bool,
    pub(crate) register_in_flight: bool,
    pub(crate) endpoint_refresh_in_flight: bool,
    pub(crate) stun_advertised: Option<String>,
    pub(crate) last_observed_ip: Option<String>,
    pub(crate) last_endpoint_refresh: Instant,
    pub(crate) last_relay_upgrade: HashMap<String, Instant>,
    pub(crate) mdns_peers: MdnsPeers,
    pub(crate) self_addr: VirtualAddr,
    pub(crate) peers: Vec<DeviceCert>,
    pub(crate) peer_addrs: Vec<(String, VirtualAddr)>,
    pub(crate) sessions: Vec<SessionEntry>,
    pub(crate) pending_opens: HashMap<String, Vec<PendingOpen>>,
    pub(crate) dial_in_flight: HashSet<String>,
    pub(crate) relay_in_flight: HashSet<String>,
    pub(crate) dial_backoff: HashMap<String, Instant>,
    pub(crate) probing: HashSet<String>,
    pub(crate) punching: Arc<Mutex<HashSet<String>>>,
    pub(crate) kick: bool,
    pub(crate) announce: bool,
    pub(crate) pending_kick: bool,
    pub(crate) pending_announce: bool,
    pub(crate) ignore_until: Instant,
    pub(crate) last_dial_ok: Instant,
}

impl Engine {
    pub(crate) async fn run(
        mut self,
        channels: EngineChannels,
        enable_mdns: bool,
        initial_devices: Vec<DeviceEntry>,
        handle: crate::EngineHandle,
    ) -> Result<()> {
        let EngineChannels {
            mut kick_rx,
            mut host_rx,
            mut signal_rx,
            mut stream_rx,
            mut punched_rx,
            mut dial_done_rx,
            mut probe_done_rx,
            mut refresh_done_rx,
            mut register_done_rx,
            mut session_ready_rx,
            mut endpoints_done_rx,
        } = channels;
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<PeerLink>(16);
        {
            let quic_accept = self.quic.clone();
            tokio::spawn(async move {
                loop {
                    match quic_accept.accept().await {
                        Ok((link, peer_id)) => {
                            if inbound_tx
                                .send(PeerLink::direct_accepted(link, peer_id))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "quic accept error");
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
            });
        }

        // Hydrate from cached verified device entries first so LAN/mDNS and
        // TUN routing work even if coord is temporarily unreachable at boot.
        if !initial_devices.is_empty() {
            let _ = self.apply_entries(initial_devices, false).await;
        }
        // Best-effort live refresh at boot (short timeout so offline coord does not hang startup).
        self.refresh().await?;
        self.publish_status();
        for s in self.services.iter() {
            s.on_peers_refreshed().await;
        }
        info!(peers = self.peers.len(), "engine started");
        if enable_mdns {
            self.mdns_peers =
                crate::mdns::spawn(self.quic.local_addr.port(), &self.my_id, handle);
        }

        // Persistent maintenance interval outside `select!` so continuous
        // stream traffic can never starve periodic refresh/register/probes.
        let mut maint_interval = tokio::time::interval(MAINT_EVERY);
        maint_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        maint_interval.tick().await;

        loop {
            while let Ok(k) = kick_rx.try_recv() {
                self.record_kick(k);
            }
            if self.pending_kick && Instant::now() >= self.ignore_until {
                self.kick = true;
                self.announce |= self.pending_announce;
                self.pending_kick = false;
                self.pending_announce = false;
            }
            self.sweep_pending_opens();
            self.serve_ready_pending_opens().await;

            let kick_delay = if self.kick {
                Some(Duration::from_millis(50))
            } else if self.pending_kick {
                Some(
                    self.ignore_until
                        .saturating_duration_since(Instant::now())
                        .max(Duration::from_millis(10)),
                )
            } else {
                None
            };

            tokio::select! {
                biased;
                Some(msg) = stream_rx.recv() => {
                    match msg {
                        StreamMsg::Stream(peer, service_id, channel) => {
                            self.dispatch_stream(&peer, service_id, channel).await;
                            self.note_round_end();
                        }
                        StreamMsg::PeerServices(peer_id, seq, svcs) => {
                            if self.live_mux(&peer_id).is_some() {
                                let accept = self
                                    .peer_discovery_seq
                                    .get(&peer_id)
                                    .is_none_or(|prev| seq >= *prev);
                                if accept {
                                    self.peer_discovery_seq.insert(peer_id.clone(), seq);
                                    self.status.set_peer_services(&peer_id, svcs);
                                    self.status.mark_discovery(&peer_id);
                                    self.status.signal();
                                }
                            }
                            self.touch(&peer_id);
                        }
                        StreamMsg::SessionDead => {
                            self.sessions.retain(|s| s.mux.is_alive());
                            let sessions = &self.sessions;
                            self.peer_discovery_seq
                                .retain(|id, _| sessions.iter().any(|s| s.peer.device_id == *id));
                            let alive: Vec<String> =
                                sessions.iter().map(|s| s.peer.device_id.clone()).collect();
                            self.status.retain_discovery(&alive);
                            self.sync_datagram_map();
                            self.publish_status();
                        }
                    }
                }
                Some(res) = dial_done_rx.recv() => {
                    if res.is_relay_accept {
                        self.relay_in_flight.remove(&res.peer_id);
                    } else {
                        self.dial_in_flight.remove(&res.peer_id);
                    }
                    match res.link {
                        Ok(link) => {
                            let peer = PeerInfo {
                                device_id: link.peer_id.clone(),
                                kind: link.kind,
                            };
                            info!(peer = %peer.device_id, kind = ?peer.kind, "connected");
                            if let Some((peer, mux)) = self.register_session(peer, link) {
                                self.publish_status();
                                self.serve_ready_pending_opens().await;
                                if self.my_id < peer.device_id {
                                    self.spawn_after_session_ready(peer, mux);
                                }
                                self.note_dial_ok();
                            }
                        }
                        Err(e) => {
                            if e != "no endpoints" {
                                warn!(peer = %res.peer_id, error = %e, "background dial failed");
                            }
                            self.note_dial_failed(&res.peer_id);
                        }
                    }
                }
                Some(ready) = session_ready_rx.recv() => {
                    self.touch(&ready.peer.device_id);
                    if !ready.ok {
                        warn!(peer = %ready.peer.device_id, "session failed");
                        ready.mux.close();
                        self.sessions.retain(|s| s.mux.is_alive());
                        self.sync_datagram_map();
                        self.publish_status();
                        if ready.peer.kind == ConnectionKind::Direct && !self.force_relay {
                            warn!(peer = %ready.peer.device_id, "direct session died; trying relay");
                            self.spawn_dial(&ready.peer.device_id, true);
                        } else {
                            self.note_dial_failed(&ready.peer.device_id);
                        }
                    }
                }
                Some(probe) = probe_done_rx.recv() => {
                    self.probing.remove(&probe.peer_id);
                    match probe.outcome {
                        Ok(rtt) => {
                            debug!(peer = %probe.peer_id, ?rtt, "idle probe ok");
                            self.status.set_rtt(&probe.peer_id, rtt);
                            self.status.signal();
                            self.touch(&probe.peer_id);
                        }
                        Err(e) => {
                            warn!(peer = %probe.peer_id, error = %e, "idle probe failed; closing session");
                            probe.mux.close();
                            self.sessions.retain(|s| s.mux.is_alive());
                            self.sync_datagram_map();
                            self.publish_status();
                        }
                    }
                }
                Some(refreshed) = refresh_done_rx.recv() => {
                    self.refresh_in_flight = false;
                    match refreshed.outcome {
                        RefreshOutcome::Ok(entries) => {
                            self.apply_entries(entries, true).await?;
                            self.publish_status();
                            for s in self.services.iter() {
                                s.on_peers_refreshed().await;
                            }
                        }
                        RefreshOutcome::Revoked(msg) => {
                            bail!("this device has been revoked from the account ({msg})");
                        }
                        RefreshOutcome::ClockSkew(msg) => {
                            warn!(detail = %msg, "coord rejected request due to clock skew or nonce replay; check system clock (will retry)");
                        }
                        RefreshOutcome::Transient(e) => {
                            warn!(error = %e, "refreshing device list failed");
                        }
                    }
                }
                Some(reg) = register_done_rx.recv() => {
                    self.register_in_flight = false;
                    match reg.outcome {
                        Ok(resp) => {
                            self.relay.tcp = self.coord.relay_addr(&resp);
                            self.relay.ws = self.coord.relay_ws_url(&resp);
                            self.relay.quic = self.coord.relay_quic_addr(&resp);
                            if !resp.stun.trim().is_empty() {
                                self.stun_advertised = Some(resp.stun.trim().to_string());
                            }
                            if !resp.observed_ip.is_empty() {
                                self.last_observed_ip = Some(resp.observed_ip.clone());
                                if let Ok(ip) = resp.observed_ip.trim().parse::<std::net::IpAddr>() {
                                    if !ip.is_loopback() && !ip.is_unspecified() {
                                        let candidate =
                                            std::net::SocketAddr::new(ip, self.quic.local_addr.port())
                                                .to_string();
                                        if !self.endpoints.contains(&candidate) {
                                            self.endpoints.push(candidate);
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "re-register failed");
                        }
                    }
                }
                Some(new_eps) = endpoints_done_rx.recv() => {
                    self.endpoint_refresh_in_flight = false;
                    if !new_eps.is_empty() && new_eps != self.endpoints {
                        info!(old = self.endpoints.len(), new = new_eps.len(), "local/STUN endpoints changed; re-registering");
                        self.endpoints = new_eps;
                        self.spawn_register();
                    }
                }
                Some(link) = punched_rx.recv() => {
                    let peer = PeerInfo {
                        device_id: link.peer_id.clone(),
                        kind: link.kind,
                    };
                    info!(peer = %link.peer_id, kind = ?link.kind, "background connection established");
                    if let Some((peer, mux)) = self.register_session(peer, link) {
                        self.publish_status();
                        self.serve_ready_pending_opens().await;
                        if self.my_id < peer.device_id {
                            self.spawn_after_session_ready(peer, mux);
                        }
                        self.note_round_end();
                    }
                }
                Some(link) = inbound_rx.recv() => {
                    let peer = PeerInfo {
                        device_id: link.peer_id.clone(),
                        kind: link.kind,
                    };
                    info!(peer = %peer.device_id, "inbound direct connection");
                    if let Some((peer, mux)) = self.register_session(peer, link) {
                        self.publish_status();
                        self.serve_ready_pending_opens().await;
                        if self.my_id < peer.device_id {
                            self.spawn_after_session_ready(peer, mux);
                        }
                        self.ignore_until = Instant::now() + Duration::from_millis(400);
                    }
                }
                Some(env) = signal_rx.recv() => {
                    self.handle_signal(env);
                }
                Some(req) = host_rx.recv() => {
                    self.handle_host(req).await;
                }
                Some(k) = kick_rx.recv() => {
                    self.record_kick(k);
                }
                _ = maint_interval.tick() => {
                    self.run_maintenance();
                }
                _ = async {
                    if let Some(d) = kick_delay {
                        tokio::time::sleep(d).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    self.run_kick_round().await;
                }
            }
        }
    }

    fn record_kick(&mut self, k: KickMsg) {
        let local = matches!(k, KickMsg::Local);
        if Instant::now() >= self.ignore_until {
            self.kick = true;
            self.announce |= local;
        } else {
            self.pending_kick = true;
            self.pending_announce |= local;
        }
    }

    fn handle_signal(&mut self, env: SignalEnvelope) {
        if !self.peers.iter().any(|p| p.device_id == env.from) {
            return;
        }
        // Peer just signalled us — clear any stale dial backoff for them.
        self.dial_backoff.remove(&env.from);

        if env.kind == "relay" {
            if self
                .sessions
                .iter()
                .any(|s| s.peer.device_id == env.from && s.mux.is_alive())
            {
                return;
            }
            self.spawn_relay_accept(&env.from);
        } else if env.kind == "punch" {
            let already_punching = self.punching.lock().unwrap().contains(&env.from);
            // Only skip punching if we ALREADY have a live Direct session.
            // Accepting punches while on a Relay session enables Relay -> Direct upgrades!
            let already_direct = self.sessions.iter().any(|s| {
                s.peer.device_id == env.from
                    && s.peer.kind == ConnectionKind::Direct
                    && s.mux.is_alive()
            });
            if already_punching || already_direct {
                return;
            }
            info!(peer = %env.from, candidates = env.endpoints.len(), "peer invited us to punch");
            self.punching.lock().unwrap().insert(env.from.clone());
            let punching = self.punching.clone();
            let who = env.from.clone();
            spawn_punch_window(
                &self.quic,
                &env.from,
                &env.endpoints,
                &self.identity,
                &self.punched_tx,
                Arc::new(move || {
                    punching.lock().unwrap().remove(&who);
                }),
            );
        } else {
            self.kick = true;
        }
    }

    fn classify_refresh_err(e: anyhow::Error) -> RefreshOutcome {
        if let Some(ce) = e.downcast_ref::<CoordError>() {
            match ce {
                CoordError::DeviceRevoked(msg) => return RefreshOutcome::Revoked(msg.clone()),
                CoordError::ClockSkewOrReplay(msg) => {
                    return RefreshOutcome::ClockSkew(msg.clone())
                }
                CoordError::Unauthorized(msg) => {
                    return RefreshOutcome::Transient(format!("unauthorized: {msg}"))
                }
                CoordError::Http { .. } => return RefreshOutcome::Transient(ce.to_string()),
            }
        }
        RefreshOutcome::Transient(e.to_string())
    }

    /// Synchronous refresh used once at startup and for on-demand host open misses.
    pub(crate) async fn refresh(&mut self) -> Result<()> {
        match tokio::time::timeout(Duration::from_secs(5), self.coord.list_devices()).await {
            Ok(Ok(entries)) => self.apply_entries(entries, true).await,
            Ok(Err(e)) => match Self::classify_refresh_err(e) {
                RefreshOutcome::Revoked(msg) => {
                    bail!("this device has been revoked from the account ({msg})")
                }
                RefreshOutcome::ClockSkew(msg) => {
                    warn!(detail = %msg, "coord rejected request due to clock skew; check system clock");
                    Ok(())
                }
                RefreshOutcome::Transient(err) => {
                    warn!(error = %err, "refreshing device list failed");
                    Ok(())
                }
                RefreshOutcome::Ok(_) => Ok(()),
            },
            Err(_) => {
                warn!("refreshing device list timed out; continuing with cached state");
                Ok(())
            }
        }
    }

    fn spawn_refresh(&mut self) {
        if self.refresh_in_flight {
            return;
        }
        self.refresh_in_flight = true;
        let coord = self.coord.clone();
        let tx = self.refresh_done_tx.clone();
        tokio::spawn(async move {
            let outcome = match coord.list_devices().await {
                Ok(entries) => RefreshOutcome::Ok(entries),
                Err(e) => Self::classify_refresh_err(e),
            };
            let _ = tx.send(RefreshResult { outcome });
        });
    }

    fn spawn_register(&mut self) {
        if self.register_in_flight {
            return;
        }
        self.register_in_flight = true;
        let coord = self.coord.clone();
        let endpoints = self.endpoints.clone();
        let tx = self.register_done_tx.clone();
        tokio::spawn(async move {
            let outcome = coord.register(endpoints).await.map_err(|e| e.to_string());
            let _ = tx.send(RegisterResult { outcome });
        });
    }

    async fn apply_entries(&mut self, entries: Vec<DeviceEntry>, from_coord: bool) -> Result<()> {
        let set = evaluate(&self.account_user_pubkey, &entries);
        if !set.is_active(&self.my_id) {
            if from_coord {
                bail!("this device has been revoked from the account");
            }
            return Ok(());
        }
        if from_coord {
            if let Some(cb) = &self.on_devices_cached {
                cb(&entries);
            }
        }
        let mut addr_by_id: HashMap<&str, VirtualAddr> = HashMap::with_capacity(entries.len());
        for e in &entries {
            addr_by_id.insert(
                e.cert.device_id.as_str(),
                VirtualAddr {
                    virtual_ip: e.virtual_ip.clone(),
                    dns_name: e.dns_name.clone(),
                },
            );
        }
        self.self_addr = addr_by_id
            .get(self.my_id.as_str())
            .cloned()
            .unwrap_or_default();
        self.peers = set
            .active
            .iter()
            .filter(|c| c.device_id != self.my_id)
            .cloned()
            .collect();
        self.peer_addrs = self
            .peers
            .iter()
            .map(|c| {
                (
                    c.device_id.clone(),
                    addr_by_id
                        .get(c.device_id.as_str())
                        .cloned()
                        .unwrap_or_default(),
                )
            })
            .collect();
        let mut t = self.trust.write().unwrap();
        t.clear();
        for c in &self.peers {
            if let Some(pk) = parse_pubkey(&c.device_pubkey) {
                t.insert(pk, c.device_id.clone());
            }
        }
        drop(t);
        *self.device_set.lock().unwrap() = set;

        // Immediately terminate any live sessions (direct QUIC or relay) to
        // peers that are no longer active (e.g. just revoked).
        let active_ids: HashSet<&str> = self.peers.iter().map(|c| c.device_id.as_str()).collect();
        let mut revoked_sessions = 0usize;
        self.sessions.retain(|s| {
            if active_ids.contains(s.peer.device_id.as_str()) {
                true
            } else {
                info!(
                    peer = %s.peer.device_id,
                    kind = ?s.peer.kind,
                    "closing live session for revoked peer"
                );
                s.mux.close();
                revoked_sessions += 1;
                false
            }
        });
        let revoked_pending: Vec<String> = self
            .pending_opens
            .keys()
            .filter(|id| !active_ids.contains(id.as_str()))
            .cloned()
            .collect();
        for peer in revoked_pending {
            if let Some(waiters) = self.pending_opens.remove(&peer) {
                for p in waiters {
                    let _ = p
                        .reply
                        .send(Err("peer was revoked from the account".to_string()));
                }
            }
        }
        self.peer_discovery_seq
            .retain(|id, _| active_ids.contains(id.as_str()));
        self.dial_backoff
            .retain(|id, _| active_ids.contains(id.as_str()));
        if revoked_sessions > 0 {
            let alive: Vec<String> = self
                .sessions
                .iter()
                .map(|s| s.peer.device_id.clone())
                .collect();
            self.status.retain_discovery(&alive);
            self.sync_datagram_map();
            self.publish_status();
        }
        Ok(())
    }

    fn spawn_idle_probes(&mut self) {
        for s in &self.sessions {
            if s.last_active.elapsed() < IDLE_PROBE_EVERY || !s.mux.is_alive() {
                continue;
            }
            if !self.probing.insert(s.peer.device_id.clone()) {
                continue;
            }
            let peer_id = s.peer.device_id.clone();
            let mux = s.mux.clone();
            let tx = self.probe_done_tx.clone();
            tokio::spawn(async move {
                debug!(peer = %peer_id, "idle probe start");
                let outcome =
                    match tokio::time::timeout(IDLE_PROBE_TIMEOUT, crate::ping::probe(&mux)).await {
                        Ok(Ok(rtt)) => Ok(rtt),
                        Ok(Err(e)) => Err(e.to_string()),
                        Err(_) => Err("probe timed out".into()),
                    };
                let _ = tx.send(ProbeResult {
                    peer_id,
                    mux,
                    outcome,
                });
            });
        }
    }

    async fn dispatch_stream(&mut self, peer: &PeerInfo, service_id: u16, channel: Channel) {
        for s in self.services.iter() {
            if s.id() == service_id {
                s.on_stream(peer, channel).await;
                self.touch(&peer.device_id);
                return;
            }
        }
        let handler = self.dynamic_handlers.read().unwrap().get(&service_id).cloned();
        if let Some(handler) = handler {
            handler(peer.clone(), channel);
            self.touch(&peer.device_id);
            return;
        }
        warn!(service = service_id, peer = %peer.device_id, "no service for inbound stream");
    }

    fn touch(&mut self, peer_id: &str) {
        let now = Instant::now();
        for s in self.sessions.iter_mut() {
            if s.peer.device_id == peer_id {
                s.last_active = now;
            }
        }
    }

    fn note_round_end(&mut self) {
        self.ignore_until = Instant::now() + Duration::from_millis(400);
    }

    fn note_dial_ok(&mut self) {
        self.note_round_end();
        self.last_dial_ok = Instant::now();
    }

    pub(crate) fn publish_status(&self) {
        self.status.set_peers(&self.peers);
        self.status
            .set_addrs(self.self_addr.clone(), self.peer_addrs.clone());
        let sessions: Vec<_> = self
            .sessions
            .iter()
            .map(|s| (s.peer.device_id.clone(), s.peer.kind))
            .collect();
        self.status.retain_peer_services(&sessions);
        self.status.set_sessions(sessions);
        self.status.signal();
    }

    /// Periodic non-blocking maintenance (never starved by traffic).
    fn run_maintenance(&mut self) {
        self.sessions.retain(|s| s.mux.is_alive());
        self.sync_datagram_map();
        self.publish_status();
        self.spawn_refresh();
        self.spawn_register();
        self.maybe_spawn_endpoint_refresh();
        self.reconcile_eager_mesh();
        self.maybe_upgrade_relay_sessions();
        self.spawn_idle_probes();
    }

    /// Re-collect local NICs and asynchronously re-probe STUN on the live QUIC
    /// socket so network changes and NAT mapping expiry self-heal automatically.
    fn maybe_spawn_endpoint_refresh(&mut self) {
        if self.endpoint_refresh_in_flight
            || self.last_endpoint_refresh.elapsed() < ENDPOINT_REFRESH_EVERY
        {
            return;
        }
        self.endpoint_refresh_in_flight = true;
        self.last_endpoint_refresh = Instant::now();
        let port = self.quic.local_addr.port();
        let observed = self.last_observed_ip.clone();
        let stun_adv = self.stun_advertised.clone();
        let quic = self.quic.clone();
        let tx = self.endpoints_done_tx.clone();
        tokio::spawn(async move {
            let mut eps = collect_local_endpoints(port, observed.as_deref());
            if let Some(adv) = stun_adv {
                if let Some(stun_sock) = resolve_stun_socket_addr(&adv).await {
                    if let Ok(mapped) = quic.probe_stun(stun_sock).await {
                        let s = mapped.to_string();
                        if !eps.contains(&s) {
                            eps.push(s);
                        }
                    }
                }
            }
            let _ = tx.send(eps);
        });
    }

    /// Periodically invite peers currently on a Relay session to attempt a
    /// background direct hole-punch upgrade.
    fn maybe_upgrade_relay_sessions(&mut self) {
        if self.force_relay {
            return;
        }
        let now = Instant::now();
        let candidates: Vec<String> = self
            .sessions
            .iter()
            .filter(|s| {
                s.peer.kind == ConnectionKind::Relay
                    && s.mux.is_alive()
                    && self.my_id < s.peer.device_id
            })
            .map(|s| s.peer.device_id.clone())
            .collect();

        for peer_id in candidates {
            if self
                .last_relay_upgrade
                .get(&peer_id)
                .is_some_and(|t| now.saturating_duration_since(*t) < RELAY_UPGRADE_EVERY)
            {
                continue;
            }
            if !self.punching.lock().unwrap().insert(peer_id.clone()) {
                continue;
            }
            self.last_relay_upgrade.insert(peer_id.clone(), now);

            let coord = self.coord.clone();
            let mdns_addr = self.mdns_peers.addr_of(&peer_id).map(|a| a.to_string());
            let quic = self.quic.clone();
            let identity = self.identity.clone();
            let my_endpoints = self.endpoints.clone();
            let signal_tx = self.signal_tx.clone();
            let punched_tx = self.punched_tx.clone();
            let punching = self.punching.clone();
            let who = peer_id.clone();
            tokio::spawn(async move {
                let mut peer_eps: Vec<String> = match coord.peer_endpoints(&who).await {
                    Ok(Some(eps)) => eps.endpoints,
                    _ => Vec::new(),
                };
                if let Some(addr) = mdns_addr {
                    if !peer_eps.contains(&addr) {
                        peer_eps.push(addr);
                    }
                }
                if peer_eps.is_empty() {
                    punching.lock().unwrap().remove(&who);
                    return;
                }
                debug!(peer = %who, candidates = peer_eps.len(), "attempting Relay -> Direct upgrade punch");
                let _ = signal_tx
                    .send(SignalEnvelope {
                        kind: "punch".into(),
                        from: identity.device_id.clone(),
                        to: who.clone(),
                        endpoints: my_endpoints,
                        text: String::new(),
                    })
                    .await;
                let punching_done = punching.clone();
                let who_done = who.clone();
                spawn_punch_window(
                    &quic,
                    &who,
                    &peer_eps,
                    &identity,
                    &punched_tx,
                    Arc::new(move || {
                        punching_done.lock().unwrap().remove(&who_done);
                    }),
                );
            });
        }
    }

    /// Fast kick round (debounced ~50ms).
    async fn run_kick_round(&mut self) {
        if self.pending_kick && Instant::now() >= self.ignore_until {
            self.kick = true;
            self.announce |= self.pending_announce;
            self.pending_kick = false;
            self.pending_announce = false;
        }
        if !self.kick {
            return;
        }
        self.kick = false;
        self.spawn_refresh();
        self.sessions.retain(|s| s.mux.is_alive());
        self.sync_datagram_map();
        self.publish_status();

        let announcing = std::mem::take(&mut self.announce);
        if !announcing && self.last_dial_ok.elapsed() < Duration::from_secs(2) {
            debug!(
                since_dial = ?self.last_dial_ok.elapsed(),
                "kicked with nothing to announce; backing off"
            );
            return;
        }

        for peer_cert in self.peers.clone() {
            let peer_id = peer_cert.device_id.clone();
            if announcing {
                self.dial_backoff.remove(&peer_id);
                let _ = self
                    .signal_tx
                    .try_send(SignalEnvelope {
                        kind: "sync".into(),
                        from: self.my_id.clone(),
                        to: peer_id.clone(),
                        endpoints: self.endpoints.clone(),
                        text: String::new(),
                    });
            }
            if self.my_id >= peer_id {
                continue;
            }
            let existing = self
                .sessions
                .iter()
                .find(|s| s.peer.device_id == peer_id && s.mux.is_alive())
                .map(|s| {
                    (
                        PeerInfo {
                            device_id: peer_id.clone(),
                            kind: s.peer.kind,
                        },
                        s.mux.clone(),
                    )
                });
            match existing {
                Some((peer, mux)) => {
                    debug!(peer = %peer_id, "reusing live session");
                    self.spawn_after_session_ready(peer, mux);
                    self.note_dial_ok();
                }
                None => {
                    let in_backoff = !announcing
                        && self
                            .dial_backoff
                            .get(&peer_id)
                            .is_some_and(|until| Instant::now() < *until);
                    if !in_backoff {
                        self.spawn_dial(&peer_id, self.force_relay);
                    }
                }
            }
        }
        self.publish_status();
    }

    /// Background eager-mesh reconciliation: ensure every active peer with
    /// `my_id < peer_id` has an active session or an in-flight dial (respecting
    /// backoff when a peer is offline).
    fn reconcile_eager_mesh(&mut self) {
        let now = Instant::now();
        for peer_cert in self.peers.clone() {
            let peer_id = peer_cert.device_id;
            if self.my_id >= peer_id {
                continue;
            }
            if self.live_mux(&peer_id).is_some() {
                continue;
            }
            if self
                .dial_backoff
                .get(&peer_id)
                .is_some_and(|until| now < *until)
            {
                continue;
            }
            self.spawn_dial(&peer_id, self.force_relay);
        }
    }

    /// Run `Service::on_session` off the main event loop so a slow/dead peer
    /// probe never stalls other peers or host requests.
    fn spawn_after_session_ready(&self, peer: PeerInfo, mux: Multiplexer) {
        let services = self.services.clone();
        let tx = self.session_ready_tx.clone();
        tokio::spawn(async move {
            let mut ok = true;
            for s in services.iter() {
                ok &= s.on_session(&peer, &mux).await;
            }
            let _ = tx.send(SessionReadyResult { peer, mux, ok });
        });
    }
}

async fn resolve_stun_socket_addr(advertised: &str) -> Option<std::net::SocketAddr> {
    let adv = advertised.trim().to_string();
    if adv.is_empty() {
        return None;
    }
    tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        let mut iter = adv.to_socket_addrs().ok()?;
        let mut first = None;
        for a in iter.by_ref() {
            if a.is_ipv4() {
                return Some(a);
            }
            if first.is_none() {
                first = Some(a);
            }
        }
        first
    })
    .await
    .ok()
    .flatten()
}
