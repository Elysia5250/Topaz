//! Engine event loop, peer discovery refresh, eager mesh reconciliation,
//! and parallel idle keepalive probes.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use bytes::Bytes;
use conduit_core::DeviceIdentity;
use conduit_net::{
    spawn_punch_window, Channel, ConnectionKind, CoordClient, DatagramSender, DynamicServices,
    Multiplexer, PeerLink, QuicEndpoint, RelayAddrs, TrustStore,
};
use conduit_proto::auth::{evaluate, parse_pubkey, DeviceSet};
use conduit_proto::{DeviceCert, SignalEnvelope};
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

pub(crate) type DatagramSink = Arc<Mutex<Option<mpsc::Sender<(String, Bytes)>>>>;

pub(crate) struct EngineChannels {
    pub(crate) kick_rx: mpsc::UnboundedReceiver<KickMsg>,
    pub(crate) host_rx: mpsc::UnboundedReceiver<HostMsg>,
    pub(crate) signal_rx: mpsc::Receiver<SignalEnvelope>,
    pub(crate) stream_rx: mpsc::UnboundedReceiver<StreamMsg>,
    pub(crate) punched_rx: mpsc::UnboundedReceiver<PeerLink>,
    pub(crate) dial_done_rx: mpsc::UnboundedReceiver<DialResult>,
    pub(crate) probe_done_rx: mpsc::UnboundedReceiver<ProbeResult>,
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
    pub(crate) mdns_peers: MdnsPeers,
    pub(crate) self_addr: VirtualAddr,
    pub(crate) peers: Vec<DeviceCert>,
    pub(crate) peer_addrs: Vec<(String, VirtualAddr)>,
    pub(crate) sessions: Vec<SessionEntry>,
    pub(crate) pending_opens: HashMap<String, Vec<PendingOpen>>,
    pub(crate) dial_in_flight: HashSet<String>,
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

        loop {
            while let Ok(k) = kick_rx.try_recv() {
                let local = matches!(k, KickMsg::Local);
                if Instant::now() >= self.ignore_until {
                    self.kick = true;
                    self.announce |= local;
                } else {
                    self.pending_kick = true;
                    self.pending_announce |= local;
                }
            }
            if self.pending_kick && Instant::now() >= self.ignore_until {
                self.kick = true;
                self.announce |= self.pending_announce;
                self.pending_kick = false;
                self.pending_announce = false;
            }
            self.sweep_pending_opens();
            self.serve_ready_pending_opens().await;

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
                    self.dial_in_flight.remove(&res.peer_id);
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
                                    self.after_session_ready(&peer, &mux).await;
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
                            self.after_session_ready(&peer, &mux).await;
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
                            self.after_session_ready(&peer, &mux).await;
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
                _ = tokio::time::sleep(Duration::from_millis(if self.kick { 50 } else { 5000 })) => {
                    self.tick().await?;
                }
            }
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
            if already_punching
                || self
                    .sessions
                    .iter()
                    .any(|s| s.peer.device_id == env.from && s.mux.is_alive())
            {
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

    pub(crate) async fn refresh(&mut self) -> Result<()> {
        let entries = match self.coord.list_devices().await {
            Ok(e) => e,
            Err(e)
                if e.to_string().contains("401")
                    || e.to_string().contains("revoked")
                    || e.to_string().contains("unauthorized") =>
            {
                bail!("this device has been revoked from the account")
            }
            Err(e) => {
                warn!(error = %e, "refreshing device list failed");
                return Ok(());
            }
        };
        let set = evaluate(&self.account_user_pubkey, &entries);
        if !set.is_active(&self.my_id) {
            bail!("this device has been revoked from the account");
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
        self.self_addr = addr_by_id.get(self.my_id.as_str()).cloned().unwrap_or_default();
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
        *self.device_set.lock().unwrap() = set;
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
                let outcome = match tokio::time::timeout(IDLE_PROBE_TIMEOUT, crate::ping::probe(&mux)).await {
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

    async fn tick(&mut self) -> Result<()> {
        self.refresh().await?;
        for s in self.services.iter() {
            s.on_peers_refreshed().await;
        }
        self.sessions.retain(|s| s.mux.is_alive());
        self.sync_datagram_map();
        self.publish_status();

        if !self.kick {
            if let Err(e) = self.coord.register(self.endpoints.clone()).await {
                warn!(error = %e, "re-register failed");
            }
            self.reconcile_eager_mesh();
            self.spawn_idle_probes();
            return Ok(());
        }

        self.kick = false;
        let announcing = std::mem::take(&mut self.announce);
        if !announcing && self.last_dial_ok.elapsed() < Duration::from_secs(2) {
            debug!(
                since_dial = ?self.last_dial_ok.elapsed(),
                "kicked with nothing to announce; backing off"
            );
            self.publish_status();
            return Ok(());
        }

        for peer_cert in self.peers.clone() {
            let peer_id = peer_cert.device_id.clone();
            if announcing {
                self.dial_backoff.remove(&peer_id);
                let _ = self
                    .signal_tx
                    .send(SignalEnvelope {
                        kind: "sync".into(),
                        from: self.my_id.clone(),
                        to: peer_id.clone(),
                        endpoints: self.endpoints.clone(),
                        text: String::new(),
                    })
                    .await;
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
                    self.after_session_ready(&peer, &mux).await;
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
        Ok(())
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

    async fn after_session_ready(&mut self, peer: &PeerInfo, mux: &Multiplexer) {
        let ok = self.run_services(peer, mux).await;
        self.touch(&peer.device_id);
        if !ok {
            warn!(peer = %peer.device_id, "session failed");
            mux.close();
            self.sessions.retain(|s| s.mux.is_alive());
            self.sync_datagram_map();
            self.publish_status();
            if peer.kind == ConnectionKind::Direct && !self.force_relay {
                warn!(peer = %peer.device_id, "direct session died; trying relay");
                self.spawn_dial(&peer.device_id, true);
            } else {
                self.note_dial_failed(&peer.device_id);
            }
        }
    }

    async fn run_services(&self, peer: &PeerInfo, mux: &Multiplexer) -> bool {
        let mut ok = true;
        for s in self.services.iter() {
            ok &= s.on_session(peer, mux).await;
        }
        ok
    }
}
