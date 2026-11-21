//! The Topaz session engine.
//!
//! The engine owns the lifecycle of device sessions: it registers endpoints
//! with the coordination server, keeps the trusted device list fresh, dials
//! peers concurrently (direct QUIC, relay fallback) for an eager mesh, turns
//! every authenticated link into a multiplexed session with datagram support,
//! and dispatches streams to the registered [`Service`]s.

mod dial;
mod engine;
pub mod mdns;
mod ping;
mod status;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;
use topaz_core::DeviceIdentity;
use topaz_net::{
    Channel, ConnectionKind, CoordClient, DatagramSender, DynamicServices, Multiplexer, PeerLink,
    QuicEndpoint, RelayAddrs, TrustStore,
};
use topaz_proto::auth::DeviceSet;
use topaz_proto::SignalEnvelope;
use futures::future::BoxFuture;
use tokio::sync::{mpsc, oneshot};

use dial::{DialResult, HostMsg};
use engine::{DatagramSink, Engine, EngineChannels, KickMsg, ProbeResult, StreamMsg};

pub use topaz_proto::mux::AdvertisedService;
pub use mdns::MdnsPeers;
pub use ping::PingService;
pub use status::{EngineStatus, SharedStatus, VirtualAddr};

/// Handler invoked for inbound streams of a dynamically registered service.
/// Must not block (e.g. hand off to a task/waiter or drop the channel).
pub type DynamicStreamHandler = Arc<dyn Fn(PeerInfo, Channel) + Send + Sync>;

/// A service riding on the session fabric. The full contract — id allocation,
/// lifecycle, backpressure duties, concurrency rules — is documented in
/// `ARCHITECTURE.md` at the repo root; this trait is its code surface.
pub trait Service: Send + Sync + 'static {
    /// Well-known service id from `topaz_proto::mux::service`. Ids 1–15
    /// are core-reserved, 16–1023 registered, 1024+ experimental; 0 is
    /// invalid and rejected at startup.
    fn id(&self) -> u16;

    /// An inbound stream the peer opened to this service. Runs inline on the
    /// engine loop, serializing rounds: a request/response protocol runs to
    /// completion here, a long-lived handler must spawn itself and return
    /// promptly. Keep draining the channel or drop it — a stalled stream tears
    /// the whole session down.
    fn on_stream<'a>(&'a self, peer: &'a PeerInfo, channel: Channel) -> BoxFuture<'a, ()>;

    /// A session to `peer` is ready (freshly dialed or reused). Called only on
    /// the round-driving side (smaller device id). Return value is SESSION
    /// health: `false` means the link itself is bad and the engine closes it,
    /// falls back to relay and re-kicks.
    fn on_session<'a>(
        &'a self,
        peer: &'a PeerInfo,
        mux: &'a Multiplexer,
    ) -> BoxFuture<'a, bool> {
        let _ = (peer, mux);
        Box::pin(async { true })
    }

    /// The trusted device list was refreshed (also on start). Runs inline on
    /// the engine loop.
    fn on_peers_refreshed<'a>(&'a self) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}

/// Everything the engine needs to reach the world.
pub struct EngineDeps {
    pub identity: DeviceIdentity,
    /// Root public key of the account; device certs are evaluated against it.
    pub account_user_pubkey: String,
    pub coord: CoordClient,
    pub trust: TrustStore,
    pub quic: QuicEndpoint,
    pub endpoints: Vec<String>,
    pub relay: RelayAddrs,
    pub signal_tx: mpsc::Sender<SignalEnvelope>,
    pub signal_rx: mpsc::Receiver<SignalEnvelope>,
    pub force_relay: bool,
    /// Advertise and browse `_topaz._udp.local.` for LAN candidates.
    pub enable_mdns: bool,
}

/// A peer session as services see it.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub device_id: String,
    pub kind: ConnectionKind,
}

/// External handle into a running engine: kick it, read its status, ask it to
/// open a stream or send datagrams to a peer.
#[derive(Clone)]
pub struct EngineHandle {
    kick_tx: mpsc::UnboundedSender<KickMsg>,
    host_tx: mpsc::UnboundedSender<HostMsg>,
    status: Arc<SharedStatus>,
    device_set: Arc<Mutex<DeviceSet>>,
    datagrams: Arc<RwLock<HashMap<String, DatagramSender>>>,
    datagram_sink: DatagramSink,
    static_service_ids: Arc<std::sync::OnceLock<Vec<u16>>>,
    dynamic_ids: DynamicServices,
    dynamic_handlers: Arc<RwLock<HashMap<u16, DynamicStreamHandler>>>,
}

impl EngineHandle {
    /// Wake the engine for a round. `announce` says we have local changes
    /// peers should hear about; a plain "go look" does not announce.
    pub fn kick(&self, announce: bool) {
        let _ = self.kick_tx.send(if announce {
            KickMsg::Local
        } else {
            KickMsg::Remote
        });
    }

    /// Open a stream on `service` to `peer`, dialing if no session exists.
    pub async fn open(&self, peer: &str, service: u16) -> Result<Channel> {
        let (reply, answer) = oneshot::channel();
        self.host_tx
            .send(HostMsg::Open {
                peer: peer.to_string(),
                service,
                reply,
            })
            .map_err(|_| anyhow::anyhow!("engine is not running"))?;
        match tokio::time::timeout(Duration::from_secs(15), answer).await {
            Ok(Ok(Ok(ch))) => Ok(ch),
            Ok(Ok(Err(e))) => Err(anyhow::anyhow!(e)),
            Ok(Err(_)) => Err(anyhow::anyhow!("engine dropped the open request")),
            Err(_) => Err(anyhow::anyhow!(
                "timed out opening a stream to {peer} (peer offline?)"
            )),
        }
    }

    /// Send an unreliable datagram (e.g., an L3 IP packet) to `peer` on the
    /// active session. Fast-path: does not hop through the engine event loop.
    /// If no session is currently open, triggers an asynchronous on-demand dial
    /// and returns an error for this packet.
    pub fn send_datagram(&self, peer: &str, packet: Bytes) -> Result<()> {
        let sender = self.datagrams.read().unwrap().get(peer).cloned();
        match sender {
            Some(tx) => tx.send(packet),
            None => {
                let _ = self.host_tx.send(HostMsg::EnsurePeer {
                    peer: peer.to_string(),
                });
                anyhow::bail!("no live session to {peer}; dial triggered")
            }
        }
    }

    /// Register the sink that receives `(peer_device_id, packet)` for inbound
    /// datagrams across all active peer sessions.
    pub fn set_datagram_sink(&self, sink: mpsc::Sender<(String, Bytes)>) {
        *self.datagram_sink.lock().unwrap() = Some(sink);
    }

    /// Register a runtime handler for a non-core service id (`>= 16`).
    /// Active and future peer sessions will accept inbound streams for
    /// `service_id` and pass them to `handler`.
    pub fn register_service_handler(
        &self,
        service_id: u16,
        handler: DynamicStreamHandler,
    ) -> Result<()> {
        if service_id < topaz_proto::mux::service::REGISTERED_MIN {
            anyhow::bail!(
                "service_id {service_id} is reserved; must be >= {}",
                topaz_proto::mux::service::REGISTERED_MIN
            );
        }
        if self
            .static_service_ids
            .get()
            .is_some_and(|ids| ids.contains(&service_id))
        {
            anyhow::bail!("service_id {service_id} is already statically mounted");
        }
        self.dynamic_handlers
            .write()
            .unwrap()
            .insert(service_id, handler);
        self.dynamic_ids.write().unwrap().insert(service_id);
        Ok(())
    }

    /// Remove a previously registered runtime handler for `service_id`.
    pub fn unregister_service_handler(&self, service_id: u16) {
        self.dynamic_ids.write().unwrap().remove(&service_id);
        self.dynamic_handlers.write().unwrap().remove(&service_id);
    }

    /// Advertise the currently online local services (`16+`) to all live
    /// and future peer sessions.
    pub fn set_advertised_services(&self, services: Vec<AdvertisedService>) {
        let _ = self.host_tx.send(HostMsg::SetAdvertisedServices(services));
    }

    /// Maximum datagram payload size currently accepted for `peer`, if a
    /// session is active.
    pub fn peer_max_datagram(&self, peer: &str) -> Option<usize> {
        self.datagrams
            .read()
            .unwrap()
            .get(peer)
            .and_then(|s| s.max_size())
    }

    pub fn status(&self) -> EngineStatus {
        self.status.engine()
    }

    /// The latest evaluated device set (revocations applied).
    pub fn device_set(&self) -> DeviceSet {
        self.device_set.lock().unwrap().clone()
    }
}

/// Build the engine. `make_services` receives the engine handle and returns
/// the services to mount. The returned future runs the loop until it fails
/// (revocation, fatal error) or is dropped; the handle is live immediately.
pub fn build<F>(
    deps: EngineDeps,
    make_services: F,
    status: Arc<SharedStatus>,
) -> (EngineHandle, BoxFuture<'static, Result<()>>)
where
    F: FnOnce(EngineHandle) -> Vec<Arc<dyn Service>>,
{
    let EngineDeps {
        identity,
        account_user_pubkey,
        coord,
        trust,
        quic,
        endpoints,
        relay,
        signal_tx,
        signal_rx,
        force_relay,
        enable_mdns,
    } = deps;

    let (kick_tx, kick_rx) = mpsc::unbounded_channel::<KickMsg>();
    let (host_tx, host_rx) = mpsc::unbounded_channel::<HostMsg>();
    let device_set = Arc::new(Mutex::new(DeviceSet::default()));
    let datagrams = Arc::new(RwLock::new(HashMap::new()));
    let datagram_sink = Arc::new(Mutex::new(None));
    let static_service_ids = Arc::new(std::sync::OnceLock::new());
    let dynamic_ids: DynamicServices = Arc::new(RwLock::new(HashSet::new()));
    let dynamic_handlers = Arc::new(RwLock::new(HashMap::new()));
    let (stream_tx, stream_rx) = mpsc::unbounded_channel::<StreamMsg>();
    let (punched_tx, punched_rx) = mpsc::unbounded_channel::<PeerLink>();
    let (dial_done_tx, dial_done_rx) = mpsc::unbounded_channel::<DialResult>();
    let (probe_done_tx, probe_done_rx) = mpsc::unbounded_channel::<ProbeResult>();

    let handle = EngineHandle {
        kick_tx,
        host_tx,
        status: status.clone(),
        device_set: device_set.clone(),
        datagrams: datagrams.clone(),
        datagram_sink: datagram_sink.clone(),
        static_service_ids: static_service_ids.clone(),
        dynamic_ids: dynamic_ids.clone(),
        dynamic_handlers: dynamic_handlers.clone(),
    };

    let services = make_services(handle.clone());
    let mut service_ids: Vec<u16> = services.iter().map(|s| s.id()).collect();
    // Service id 0 is invalid, and two services on one id would steal each other's streams.
    let mut seen = HashSet::new();
    for id in &service_ids {
        assert_ne!(*id, 0, "service id 0 is reserved and invalid");
        assert!(seen.insert(*id), "duplicate service id {id}");
    }
    let _ = static_service_ids.set(service_ids.clone());
    if !service_ids.contains(&topaz_proto::mux::service::DISCOVERY) {
        service_ids.push(topaz_proto::mux::service::DISCOVERY);
    }

    let engine = Engine {
        my_id: identity.device_id.clone(),
        identity,
        account_user_pubkey,
        coord,
        trust,
        quic,
        endpoints,
        relay,
        signal_tx,
        force_relay,
        services: Arc::new(services),
        service_ids,
        dynamic_ids,
        dynamic_handlers,
        local_services: Vec::new(),
        local_services_seq: 0,
        peer_discovery_seq: HashMap::new(),
        status,
        device_set,
        datagrams,
        datagram_sink,
        stream_tx,
        punched_tx,
        dial_done_tx,
        probe_done_tx,
        mdns_peers: MdnsPeers::default(),
        self_addr: VirtualAddr::default(),
        peers: Vec::new(),
        peer_addrs: Vec::new(),
        sessions: Vec::new(),
        pending_opens: HashMap::new(),
        dial_in_flight: HashSet::new(),
        dial_backoff: HashMap::new(),
        probing: HashSet::new(),
        punching: Arc::new(Mutex::new(HashSet::new())),
        kick: true,
        announce: true,
        pending_kick: false,
        pending_announce: false,
        ignore_until: Instant::now(),
        last_dial_ok: Instant::now() - Duration::from_secs(60),
    };

    let fut = {
        let handle = handle.clone();
        Box::pin(async move {
            engine
                .run(
                    EngineChannels {
                        kick_rx,
                        host_rx,
                        signal_rx,
                        stream_rx,
                        punched_rx,
                        dial_done_rx,
                        probe_done_rx,
                    },
                    enable_mdns,
                    handle,
                )
                .await
        })
    };

    (handle, fut)
}
