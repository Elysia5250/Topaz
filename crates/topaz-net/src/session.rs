use crate::mux::{Channel, DynamicServices, Multiplexer, MuxRole, OnStream};
use crate::quic::{QuicEndpoint, QuicLink};
use crate::relay::{
    connect_quic_datagram_relay, connect_relay, connect_relay_once, RelayAddrs, RelayStream,
    RelayTunnel,
};
use crate::tls::TrustStore;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use futures::future::select_ok;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_rustls::TlsStream;
use topaz_core::DeviceIdentity;
use topaz_proto::mux::service;
use topaz_proto::SignalEnvelope;
use tracing::{debug, info, warn};

/// Receives inbound datagrams (raw packets) from a peer session.
pub type OnDatagram = Arc<dyn Fn(Bytes) + Send + Sync>;

const RELAY_DATAGRAM_QUEUE: usize = 256;
/// Wire overhead for E2E-encrypted UDP/QUIC relay datagrams: 8-byte counter + 16-byte Poly1305 tag.
const E2E_DGRAM_OVERHEAD: usize = 8 + 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionKind {
    Direct,
    Relay,
}

struct QuicDgramRelayTx {
    conn: quinn::Connection,
    cipher: ChaCha20Poly1305,
    seq: AtomicU64,
}

impl QuicDgramRelayTx {
    fn send(&self, pkt: &[u8]) -> Result<()> {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let nonce = counter_nonce(seq);
        let ct = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), pkt)
            .map_err(|_| anyhow!("encrypt relay datagram failed"))?;
        let mut frame = Vec::with_capacity(8 + ct.len());
        frame.extend_from_slice(&seq.to_be_bytes());
        frame.extend_from_slice(&ct);
        self.conn
            .send_datagram(Bytes::from(frame))
            .map_err(|e| anyhow!("quic relay send datagram: {e}"))
    }

    fn max_payload(&self) -> Option<usize> {
        self.conn
            .max_datagram_size()
            .map(|m| m.saturating_sub(E2E_DGRAM_OVERHEAD))
    }
}

fn counter_nonce(seq: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..12].copy_from_slice(&seq.to_be_bytes());
    n
}

/// 64-packet sliding anti-replay window for unreliable E2E-encrypted datagrams.
struct ReplayWindow {
    max_seq: u64,
    seen_mask: u64,
    initialized: bool,
}

impl ReplayWindow {
    fn new() -> Self {
        Self {
            max_seq: 0,
            seen_mask: 0,
            initialized: false,
        }
    }

    /// Returns `true` if `seq` is fresh and records it; `false` if duplicate or too old.
    fn accept(&mut self, seq: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.max_seq = seq;
            self.seen_mask = 1;
            return true;
        }
        if seq > self.max_seq {
            let shift = seq - self.max_seq;
            if shift >= 64 {
                self.seen_mask = 1;
            } else {
                self.seen_mask = (self.seen_mask << shift) | 1;
            }
            self.max_seq = seq;
            true
        } else {
            let diff = self.max_seq - seq;
            if diff >= 64 {
                return false;
            }
            let bit = 1u64 << diff;
            if (self.seen_mask & bit) != 0 {
                return false;
            }
            self.seen_mask |= bit;
            true
        }
    }
}

fn decrypt_e2e_datagram(
    cipher: &ChaCha20Poly1305,
    window: &mut ReplayWindow,
    frame: &[u8],
) -> Option<Bytes> {
    if frame.len() < E2E_DGRAM_OVERHEAD {
        return None;
    }
    let seq = u64::from_be_bytes(frame[0..8].try_into().ok()?);
    let nonce = counter_nonce(seq);
    // Authenticate ciphertext BEFORE advancing the replay window so forged
    // packets with large sequence numbers cannot shift the window.
    let plain = cipher.decrypt(Nonce::from_slice(&nonce), &frame[8..]).ok()?;
    if !window.accept(seq) {
        return None;
    }
    Some(Bytes::from(plain))
}

#[derive(Clone)]
struct RelayDatagramSender {
    quic_fast: Arc<RwLock<Option<Arc<QuicDgramRelayTx>>>>,
    fallback: mpsc::Sender<Bytes>,
}

/// Handle to send unreliable datagrams over an active peer session.
///
/// - On direct QUIC links, packets go through native QUIC datagrams (RFC 9221).
/// - On relay links, packets prefer coord's UDP/QUIC unreliable datagram relay
///   with E2E ChaCha20-Poly1305 encryption (no TCP-over-TCP congestion
///   collapse), falling back transparently to a Yamux `DATAGRAM` stream if
///   UDP 7724 is blocked or still connecting.
#[derive(Clone)]
pub struct DatagramSender {
    inner: DatagramKind,
}

#[derive(Clone)]
enum DatagramKind {
    Quic(quinn::Connection),
    Relay(RelayDatagramSender),
}

impl DatagramSender {
    pub fn send(&self, pkt: Bytes) -> Result<()> {
        match &self.inner {
            DatagramKind::Quic(conn) => conn
                .send_datagram(pkt)
                .map_err(|e| anyhow!("quic send datagram: {e}")),
            DatagramKind::Relay(r) => {
                if let Some(fast) = r.quic_fast.read().unwrap().as_ref().cloned() {
                    if fast.send(&pkt).is_ok() {
                        return Ok(());
                    }
                }
                r.fallback
                    .try_send(pkt)
                    .map_err(|e| anyhow!("relay send datagram: {e}"))
            }
        }
    }

    pub fn max_size(&self) -> Option<usize> {
        match &self.inner {
            DatagramKind::Quic(conn) => conn.max_datagram_size(),
            DatagramKind::Relay(r) => {
                if let Some(fast) = r.quic_fast.read().unwrap().as_ref() {
                    if let Some(sz) = fast.max_payload() {
                        return Some(sz);
                    }
                }
                Some(topaz_proto::mux::MAX_DATA_CHUNK.saturating_sub(2))
            }
        }
    }
}

/// A live multiplexed session paired with a datagram sender.
pub struct PeerSession {
    pub mux: Multiplexer,
    pub datagram: DatagramSender,
}

struct QuicRelayHint {
    addr: String,
    quic_tls: Arc<rustls::ClientConfig>,
    identity: DeviceIdentity,
}

enum Inner {
    Quic(QuicLink),
    Relay {
        stream: Box<TlsStream<RelayTunnel>>,
        dgram_keys: [u8; 64],
        quic_relay: Option<QuicRelayHint>,
    },
}

/// An authenticated, encrypted link to another device of the same account.
pub struct PeerLink {
    /// Device id proven by the peer's TLS certificate.
    pub peer_id: String,
    pub kind: ConnectionKind,
    /// On direct links: the device id of the QUIC client side (our own id
    /// when we dialed, the peer's when we accepted).
    pub quic_client: Option<String>,
    inner: Inner,
}

impl PeerLink {
    pub fn direct_dialed(link: QuicLink, peer_id: String, my_id: &str) -> Self {
        Self::direct(link, peer_id, Some(my_id.to_string()))
    }

    pub fn direct_accepted(link: QuicLink, peer_id: String) -> Self {
        let client = peer_id.clone();
        Self::direct(link, peer_id, Some(client))
    }

    fn direct(link: QuicLink, peer_id: String, quic_client: Option<String>) -> Self {
        Self {
            peer_id,
            kind: ConnectionKind::Direct,
            quic_client,
            inner: Inner::Quic(link),
        }
    }

    pub fn relay(stream: TlsStream<RelayTunnel>, peer_id: String) -> Self {
        Self {
            peer_id,
            kind: ConnectionKind::Relay,
            quic_client: None,
            inner: Inner::Relay {
                stream: Box::new(stream),
                dgram_keys: [0u8; 64],
                quic_relay: None,
            },
        }
    }

    fn relay_with_quic(
        relay_stream: RelayStream,
        peer_id: String,
        addrs: &RelayAddrs,
        identity: &DeviceIdentity,
    ) -> Self {
        let quic_relay = if !addrs.quic.is_empty() {
            addrs.coord_quic_tls.as_ref().map(|tls| QuicRelayHint {
                addr: addrs.quic.clone(),
                quic_tls: tls.clone(),
                identity: identity.clone(),
            })
        } else {
            None
        };
        Self {
            peer_id,
            kind: ConnectionKind::Relay,
            quic_client: None,
            inner: Inner::Relay {
                stream: Box::new(relay_stream.tls),
                dgram_keys: relay_stream.dgram_keys,
                quic_relay,
            },
        }
    }

    /// Turn this link into a multiplexed session (streams only).
    pub fn into_mux(
        self,
        my_device_id: &str,
        services: &[u16],
        on_stream: OnStream,
    ) -> Multiplexer {
        self.into_session(my_device_id, services, on_stream, Arc::new(|_| {}))
            .mux
    }

    /// Turn this link into a full [`PeerSession`] supporting both multiplexed
    /// streams and low-latency datagrams.
    pub fn into_session(
        self,
        my_device_id: &str,
        services: &[u16],
        on_stream: OnStream,
        on_datagram: OnDatagram,
    ) -> PeerSession {
        self.into_session_with_dynamic(my_device_id, services, None, on_stream, on_datagram)
    }

    /// Turn this link into a full [`PeerSession`] with a shared
    /// [`DynamicServices`] set for runtime-registered service bridges.
    pub fn into_session_with_dynamic(
        self,
        my_device_id: &str,
        services: &[u16],
        dynamic_services: Option<DynamicServices>,
        on_stream: OnStream,
        on_datagram: OnDatagram,
    ) -> PeerSession {
        let role = if my_device_id < self.peer_id.as_str() {
            MuxRole::Initiator
        } else {
            MuxRole::Acceptor
        };
        let peer_id = self.peer_id;
        let mut mux_services = services.to_vec();
        if !mux_services.contains(&service::DATAGRAM) {
            mux_services.push(service::DATAGRAM);
        }
        let dgram_cb = on_datagram.clone();
        let wrapped_on_stream: OnStream = Arc::new(move |svc, ch| {
            if svc == service::DATAGRAM {
                let cb = dgram_cb.clone();
                tokio::spawn(async move {
                    read_dgram_channel(ch, cb).await;
                });
                return;
            }
            on_stream(svc, ch);
        });

        match self.inner {
            Inner::Quic(QuicLink { conn }) => {
                let mux = Multiplexer::start_on_quic(
                    conn.clone(),
                    &mux_services,
                    dynamic_services,
                    wrapped_on_stream,
                );
                let conn_r = conn.clone();
                let mux_r = mux.clone();
                tokio::spawn(async move {
                    loop {
                        match conn_r.read_datagram().await {
                            Ok(pkt) => on_datagram(pkt),
                            Err(e) => {
                                debug!(error = %e, "quic datagram reader ended");
                                mux_r.close();
                                break;
                            }
                        }
                    }
                });
                PeerSession {
                    mux,
                    datagram: DatagramSender {
                        inner: DatagramKind::Quic(conn),
                    },
                }
            }
            Inner::Relay {
                stream,
                dgram_keys,
                quic_relay,
            } => {
                let mux = Multiplexer::start_on_with_dynamic(
                    stream,
                    role,
                    &mux_services,
                    dynamic_services,
                    wrapped_on_stream,
                );
                let (tx, mut rx) = mpsc::channel::<Bytes>(RELAY_DATAGRAM_QUEUE);
                let mux_w = mux.clone();
                tokio::spawn(async move {
                    let first = tokio::select! {
                        pkt = rx.recv() => match pkt {
                            Some(p) => p,
                            None => return,
                        },
                        _ = mux_w.closed() => return,
                    };
                    let mut ch = match mux_w.open_channel(service::DATAGRAM).await {
                        Ok(ch) => ch,
                        Err(e) => {
                            debug!(error = %e, "open relay datagram channel failed");
                            return;
                        }
                    };
                    if write_dgram_packet(&mut ch, &first).await.is_err() {
                        return;
                    }
                    loop {
                        tokio::select! {
                            pkt = rx.recv() => match pkt {
                                Some(p) => {
                                    if write_dgram_packet(&mut ch, &p).await.is_err() {
                                        break;
                                    }
                                }
                                None => break,
                            },
                            _ = mux_w.closed() => break,
                        }
                    }
                });

                let quic_fast: Arc<RwLock<Option<Arc<QuicDgramRelayTx>>>> =
                    Arc::new(RwLock::new(None));
                if let Some(hint) = quic_relay {
                    let (tx_key, rx_key) = match role {
                        MuxRole::Initiator => (&dgram_keys[0..32], &dgram_keys[32..64]),
                        MuxRole::Acceptor => (&dgram_keys[32..64], &dgram_keys[0..32]),
                    };
                    let tx_cipher = ChaCha20Poly1305::new(Key::from_slice(tx_key));
                    let rx_cipher = ChaCha20Poly1305::new(Key::from_slice(rx_key));
                    let fast_slot = quic_fast.clone();
                    let mux_q = mux.clone();
                    let on_dgram_q = on_datagram.clone();
                    tokio::spawn(async move {
                        let conn = tokio::select! {
                            res = connect_quic_datagram_relay(
                                &hint.addr,
                                &hint.quic_tls,
                                &hint.identity,
                                &peer_id,
                            ) => match res {
                                Ok(c) => c,
                                Err(e) => {
                                    debug!(peer = %peer_id, error = %e, "quic datagram relay unavailable; using yamux fallback");
                                    return;
                                }
                            },
                            _ = mux_q.closed() => return,
                        };
                        info!(peer = %peer_id, relay_quic = %hint.addr, "upgraded relay datagrams to UDP/QUIC");
                        let sender = Arc::new(QuicDgramRelayTx {
                            conn: conn.clone(),
                            cipher: tx_cipher,
                            seq: AtomicU64::new(0),
                        });
                        *fast_slot.write().unwrap() = Some(sender);

                        let mut window = ReplayWindow::new();
                        loop {
                            tokio::select! {
                                res = conn.read_datagram() => match res {
                                    Ok(frame) => {
                                        if let Some(plain) = decrypt_e2e_datagram(&rx_cipher, &mut window, &frame) {
                                            on_dgram_q(plain);
                                        }
                                    }
                                    Err(e) => {
                                        debug!(peer = %peer_id, error = %e, "quic datagram relay ended; falling back to yamux");
                                        break;
                                    }
                                },
                                _ = mux_q.closed() => {
                                    conn.close(0u32.into(), b"session closed");
                                    break;
                                }
                            }
                        }
                        *fast_slot.write().unwrap() = None;
                    });
                }

                PeerSession {
                    mux,
                    datagram: DatagramSender {
                        inner: DatagramKind::Relay(RelayDatagramSender {
                            quic_fast,
                            fallback: tx,
                        }),
                    },
                }
            }
        }
    }
}

async fn write_dgram_packet(ch: &mut Channel, pkt: &[u8]) -> std::io::Result<()> {
    let Ok(len) = u16::try_from(pkt.len()) else {
        return Ok(());
    };
    let mut frame = Vec::with_capacity(2 + pkt.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(pkt);
    ch.write_all(&frame).await
}

async fn read_dgram_channel(mut ch: Channel, on_datagram: OnDatagram) {
    loop {
        let mut len_buf = [0u8; 2];
        if ch.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 {
            continue;
        }
        let mut buf = vec![0u8; len];
        if ch.read_exact(&mut buf).await.is_err() {
            break;
        }
        on_datagram(Bytes::from(buf));
    }
}

/// Join a relay session that `peer_id` asked for.
pub async fn accept_relay(
    identity: &DeviceIdentity,
    trust: &TrustStore,
    relay: &RelayAddrs,
    peer_id: &str,
) -> Result<PeerLink> {
    let stream = connect_relay_once(relay, identity, trust, peer_id).await?;
    Ok(PeerLink::relay_with_quic(
        stream,
        peer_id.to_string(),
        relay,
        identity,
    ))
}

const PUNCH_WINDOW: Duration = Duration::from_secs(8);
const PUNCH_RETRY: Duration = Duration::from_millis(500);

/// Try direct QUIC to the peer's endpoints in parallel, then fall back to the
/// TCP/WSS (+ optional UDP/QUIC datagram) relay.
#[allow(clippy::too_many_arguments)]
pub async fn connect_peer(
    identity: &DeviceIdentity,
    trust: &TrustStore,
    peer_id: &str,
    quic: &QuicEndpoint,
    relay: &RelayAddrs,
    force_relay: bool,
    peer_endpoints: &[String],
    my_endpoints: &[String],
    punched: &tokio::sync::mpsc::UnboundedSender<PeerLink>,
    signal_tx: &tokio::sync::mpsc::Sender<SignalEnvelope>,
) -> Result<PeerLink> {
    if force_relay {
        info!("force_relay enabled; skipping direct connect");
    } else if let Some(link) = dial_direct(quic, peer_id, peer_endpoints, &identity.device_id).await
    {
        return Ok(link);
    }

    if !force_relay {
        info!(peer = %peer_id, "direct failed; inviting peer to punch");
        signal_tx
            .send(SignalEnvelope {
                kind: "punch".into(),
                from: identity.device_id.clone(),
                to: peer_id.to_string(),
                endpoints: my_endpoints.to_vec(),
                text: String::new(),
            })
            .await
            .map_err(|_| anyhow!("signaling channel closed"))?;
        spawn_punch_window(
            quic,
            peer_id,
            peer_endpoints,
            identity,
            punched,
            std::sync::Arc::new(|| {}),
        );
    }

    info!(peer = %peer_id, relay = %relay.tcp, relay_ws = %relay.ws, relay_quic = %relay.quic, "falling back to relay");
    signal_tx
        .send(SignalEnvelope {
            kind: "relay".into(),
            from: identity.device_id.clone(),
            to: peer_id.to_string(),
            endpoints: Vec::new(),
            text: String::new(),
        })
        .await
        .map_err(|_| anyhow!("signaling channel closed"))?;
    let stream = connect_relay(relay, identity, trust, peer_id)
        .await
        .map_err(|e| anyhow!("relay connect failed: {e}"))?;
    Ok(PeerLink::relay_with_quic(
        stream,
        peer_id.to_string(),
        relay,
        identity,
    ))
}

/// Dial the peer's candidates for `PUNCH_WINDOW`, reporting the first direct
/// link through `out`.
pub fn spawn_punch_window(
    quic: &QuicEndpoint,
    peer_id: &str,
    endpoints: &[String],
    identity: &DeviceIdentity,
    out: &tokio::sync::mpsc::UnboundedSender<PeerLink>,
    done: std::sync::Arc<dyn Fn() + Send + Sync>,
) {
    let quic = quic.clone();
    let peer_id = peer_id.to_string();
    let my_id = identity.device_id.clone();
    let endpoints = endpoints.to_vec();
    let out = out.clone();
    tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + PUNCH_WINDOW;
        while tokio::time::Instant::now() < deadline {
            if let Some(link) = dial_direct(&quic, &peer_id, &endpoints, &my_id).await {
                let _ = out.send(link);
                done();
                return;
            }
            tokio::time::sleep(PUNCH_RETRY).await;
        }
        warn!(peer = %peer_id, "punch window closed without a direct link");
        done();
    });
}

async fn dial_direct(
    quic: &QuicEndpoint,
    peer_id: &str,
    peer_endpoints: &[String],
    my_id: &str,
) -> Option<PeerLink> {
    let mut addrs = Vec::new();
    for ep in peer_endpoints {
        match ep.parse::<SocketAddr>() {
            Ok(addr) => addrs.push(addr),
            Err(e) => warn!(endpoint = %ep, error = %e, "skipping unparseable endpoint"),
        }
    }
    addrs.sort();
    addrs.dedup();
    if addrs.is_empty() {
        return None;
    }

    let futs = addrs.into_iter().map(|addr| {
        let quic = quic.clone();
        let expected = peer_id.to_string();
        let my_id = my_id.to_string();
        Box::pin(async move {
            match tokio::time::timeout(Duration::from_secs(3), quic.connect(addr)).await {
                Ok(Ok((link, authenticated))) => {
                    if authenticated != expected {
                        warn!(
                            %addr,
                            %authenticated,
                            expected = %expected,
                            "endpoint belongs to another device"
                        );
                        Err(anyhow!("endpoint belongs to another device"))
                    } else {
                        info!(%addr, "direct QUIC connected");
                        Ok(PeerLink::direct_dialed(link, authenticated, &my_id))
                    }
                }
                Ok(Err(e)) => {
                    warn!(%addr, error = %e, "direct QUIC failed");
                    Err(e)
                }
                Err(_) => {
                    warn!(%addr, "direct QUIC timed out");
                    Err(anyhow!("direct QUIC timed out"))
                }
            }
        })
    });
    match select_ok(futs).await {
        Ok((link, _rest)) => Some(link),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::{client_config, new_trust_store, server_config};
    use tokio::io::duplex;
    use tokio_rustls::{TlsAcceptor, TlsConnector};
    use topaz_proto::auth::parse_pubkey;

    fn make_trusted_pair() -> (DeviceIdentity, DeviceIdentity, TrustStore, TrustStore) {
        let a = DeviceIdentity::generate().unwrap();
        let b = DeviceIdentity::generate().unwrap();
        let ta = new_trust_store();
        let tb = new_trust_store();
        ta.write()
            .unwrap()
            .insert(parse_pubkey(&b.pubkey_hex).unwrap(), b.device_id.clone());
        tb.write()
            .unwrap()
            .insert(parse_pubkey(&a.pubkey_hex).unwrap(), a.device_id.clone());
        (a, b, ta, tb)
    }

    #[test]
    fn e2e_datagram_encryption_and_replay_window() {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&[7u8; 32]));
        let mut win = ReplayWindow::new();

        let seal_one = |seq: u64, msg: &[u8]| -> Vec<u8> {
            let ct = cipher
                .encrypt(Nonce::from_slice(&counter_nonce(seq)), msg)
                .unwrap();
            let mut out = Vec::with_capacity(8 + ct.len());
            out.extend_from_slice(&seq.to_be_bytes());
            out.extend_from_slice(&ct);
            out
        };

        let f5 = seal_one(5, b"pkt5");
        let f3 = seal_one(3, b"pkt3");
        let f70 = seal_one(70, b"pkt70");
        assert_eq!(
            decrypt_e2e_datagram(&cipher, &mut win, &f5).unwrap(),
            Bytes::from_static(b"pkt5")
        );
        // Replay rejected.
        assert!(decrypt_e2e_datagram(&cipher, &mut win, &f5).is_none());
        // Out-of-order within 64-packet window accepted.
        assert_eq!(
            decrypt_e2e_datagram(&cipher, &mut win, &f3).unwrap(),
            Bytes::from_static(b"pkt3")
        );
        // Forged packet with huge seq must NOT poison the window.
        let mut forged = seal_one(10_000, b"evil");
        forged[12] ^= 0xff;
        assert!(decrypt_e2e_datagram(&cipher, &mut win, &forged).is_none());
        // Advance window past 64 packets -> seq 4 now too old.
        assert_eq!(
            decrypt_e2e_datagram(&cipher, &mut win, &f70).unwrap(),
            Bytes::from_static(b"pkt70")
        );
        let f4 = seal_one(4, b"old");
        assert!(decrypt_e2e_datagram(&cipher, &mut win, &f4).is_none());
    }

    #[tokio::test]
    async fn quic_session_streams_half_close_and_datagrams() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (a_id, b_id, ta, tb) = make_trusted_pair();
        let (ep_a, _) = QuicEndpoint::bind(&a_id, &ta, None).unwrap();
        let (ep_b, _) = QuicEndpoint::bind(&b_id, &tb, None).unwrap();
        let addr_b = SocketAddr::from(([127, 0, 0, 1], ep_b.local_addr.port()));

        let accept_task = tokio::spawn(async move { ep_b.accept().await.unwrap() });
        let (link_a, peer_a) = ep_a.connect(addr_b).await.unwrap();
        let (link_b, peer_b) = accept_task.await.unwrap();
        assert_eq!(peer_a, b_id.device_id);
        assert_eq!(peer_b, a_id.device_id);

        let (sa_tx, mut sa_rx) = mpsc::unbounded_channel();
        let (da_tx, mut da_rx) = mpsc::unbounded_channel();
        let (sb_tx, mut sb_rx) = mpsc::unbounded_channel();
        let (db_tx, mut db_rx) = mpsc::unbounded_channel();

        let sess_a = PeerLink::direct_dialed(link_a, b_id.device_id.clone(), &a_id.device_id)
            .into_session(
                &a_id.device_id,
                &[service::PING],
                Arc::new(move |svc, ch| {
                    let _ = sa_tx.send((svc, ch));
                }),
                Arc::new(move |pkt| {
                    let _ = da_tx.send(pkt);
                }),
            );
        let sess_b = PeerLink::direct_accepted(link_b, a_id.device_id.clone()).into_session(
            &b_id.device_id,
            &[service::PING],
            Arc::new(move |svc, ch| {
                let _ = sb_tx.send((svc, ch));
            }),
            Arc::new(move |pkt| {
                let _ = db_tx.send(pkt);
            }),
        );

        // Stream roundtrip with true half-close.
        let mut ch_a = sess_a.mux.open_channel(service::PING).await.unwrap();
        ch_a.write_all(b"ping").await.unwrap();
        ch_a.shutdown().await.unwrap();
        let (svc, mut ch_b) = sb_rx.recv().await.unwrap();
        assert_eq!(svc, service::PING);
        let mut req = Vec::new();
        ch_b.read_to_end(&mut req).await.unwrap();
        assert_eq!(&req, b"ping");
        ch_b.write_all(b"pong").await.unwrap();
        ch_b.shutdown().await.unwrap();
        let mut resp = Vec::new();
        ch_a.read_to_end(&mut resp).await.unwrap();
        assert_eq!(&resp, b"pong");

        // Datagram roundtrip in both directions.
        sess_a
            .datagram
            .send(Bytes::from_static(b"pkt-a-to-b"))
            .unwrap();
        assert_eq!(
            db_rx.recv().await.unwrap(),
            Bytes::from_static(b"pkt-a-to-b")
        );

        sess_b
            .datagram
            .send(Bytes::from_static(b"pkt-b-to-a"))
            .unwrap();
        assert_eq!(
            da_rx.recv().await.unwrap(),
            Bytes::from_static(b"pkt-b-to-a")
        );
        assert!(sess_a.datagram.max_size().unwrap_or(0) >= 1200);
        drop(sa_rx.try_recv());

        // Closing mux tears down the underlying QUIC connection on both ends.
        sess_a.mux.close();
        tokio::time::timeout(Duration::from_secs(2), sess_b.mux.closed())
            .await
            .expect("peer session closed cleanly");
    }

    #[tokio::test]
    async fn relay_session_streams_and_datagrams() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (a_id, b_id, ta, tb) = make_trusted_pair();
        let (io_a, io_b) = duplex(1 << 20);
        let tun_a = RelayTunnel::Ws(io_a);
        let tun_b = RelayTunnel::Ws(io_b);

        let connector = TlsConnector::from(Arc::new(client_config(&a_id, &ta).unwrap()));
        let acceptor = TlsAcceptor::from(Arc::new(server_config(&b_id, &tb).unwrap()));
        let srv_name = rustls::pki_types::ServerName::try_from("topaz").unwrap();
        let (tls_a, tls_b) = tokio::try_join!(
            async {
                Ok::<_, anyhow::Error>(TlsStream::Client(connector.connect(srv_name, tun_a).await?))
            },
            async { Ok::<_, anyhow::Error>(TlsStream::Server(acceptor.accept(tun_b).await?)) },
        )
        .unwrap();

        let (da_tx, mut da_rx) = mpsc::unbounded_channel();
        let (sb_tx, mut sb_rx) = mpsc::unbounded_channel();
        let (db_tx, mut db_rx) = mpsc::unbounded_channel();

        let sess_a = PeerLink::relay(tls_a, b_id.device_id.clone()).into_session(
            &a_id.device_id,
            &[service::PING],
            Arc::new(|_, _| {}),
            Arc::new(move |pkt| {
                let _ = da_tx.send(pkt);
            }),
        );
        let sess_b = PeerLink::relay(tls_b, a_id.device_id.clone()).into_session(
            &b_id.device_id,
            &[service::PING],
            Arc::new(move |svc, ch| {
                let _ = sb_tx.send((svc, ch));
            }),
            Arc::new(move |pkt| {
                let _ = db_tx.send(pkt);
            }),
        );

        let mut ch_a = sess_a.mux.open_channel(service::PING).await.unwrap();
        ch_a.write_all(b"hey").await.unwrap();
        let (svc, mut ch_b) = sb_rx.recv().await.unwrap();
        assert_eq!(svc, service::PING);
        let mut sbuf = [0u8; 3];
        ch_b.read_exact(&mut sbuf).await.unwrap();
        assert_eq!(&sbuf, b"hey");

        sess_a
            .datagram
            .send(Bytes::from_static(b"relay-pkt-1"))
            .unwrap();
        assert_eq!(
            db_rx.recv().await.unwrap(),
            Bytes::from_static(b"relay-pkt-1")
        );
        sess_b
            .datagram
            .send(Bytes::from_static(b"relay-pkt-2"))
            .unwrap();
        assert_eq!(
            da_rx.recv().await.unwrap(),
            Bytes::from_static(b"relay-pkt-2")
        );
    }
}
