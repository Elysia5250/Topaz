//! Concurrent dialing, host open requests, and session deduplication.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use conduit_net::{
    accept_relay, connect_peer, Channel, ConnectionKind, DatagramSender, Multiplexer, OnDatagram,
    OnStream, PeerLink,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

use crate::engine::{Engine, StreamMsg};
use crate::{AdvertisedService, PeerInfo};

const MAX_DISCOVERY_BYTES: usize = 64 * 1024;

#[derive(Serialize, Deserialize)]
struct DiscoveryPayload {
    seq: u64,
    services: Vec<AdvertisedService>,
}

/// Requests from the host process (a daemon handler, VPN router, or plugin
/// acting on the user's behalf) that need the engine's sessions.
pub(crate) enum HostMsg {
    /// Open one stream to `peer` on `service`, dialing first if there is no
    /// live session.
    Open {
        peer: String,
        service: u16,
        reply: oneshot::Sender<std::result::Result<conduit_net::Channel, String>>,
    },
    /// Ensure a session to `peer` is dialed (triggered by on-demand datagrams).
    EnsurePeer { peer: String },
    /// Broadcast an updated list of locally online services (`16+`).
    SetAdvertisedServices(Vec<AdvertisedService>),
}

/// A host-requested stream open parked until a session to its peer exists.
pub(crate) struct PendingOpen {
    pub(crate) service: u16,
    pub(crate) reply: oneshot::Sender<std::result::Result<conduit_net::Channel, String>>,
    pub(crate) deadline: Instant,
}

/// Outcome reported back to the engine loop from a background dial task.
pub(crate) struct DialResult {
    pub(crate) peer_id: String,
    pub(crate) link: std::result::Result<PeerLink, String>,
}

pub(crate) struct SessionEntry {
    pub(crate) peer: PeerInfo,
    pub(crate) mux: Multiplexer,
    pub(crate) datagram: DatagramSender,
    /// Which side dialed this direct link (see `PeerLink::quic_client`).
    pub(crate) client_id: Option<String>,
    /// Last round, inbound stream, or successful probe on this session.
    pub(crate) last_active: Instant,
}

const DIAL_BACKOFF: Duration = Duration::from_secs(15);

impl Engine {
    pub(crate) fn live_mux(&self, peer: &str) -> Option<Multiplexer> {
        self.sessions
            .iter()
            .find(|s| s.peer.device_id == peer && s.mux.is_alive())
            .map(|s| s.mux.clone())
    }

    /// Sync the fast-path `EngineHandle::send_datagram` map with active sessions.
    pub(crate) fn sync_datagram_map(&self) {
        let mut map = self.datagrams.write().unwrap();
        map.clear();
        for s in &self.sessions {
            if s.mux.is_alive() {
                map.insert(s.peer.device_id.clone(), s.datagram.clone());
            }
        }
    }

    pub(crate) fn stream_dispatch(&self, peer: &PeerInfo) -> OnStream {
        let tx = self.stream_tx.clone();
        let peer = peer.clone();
        let services = self.services.clone();
        Arc::new(move |service_id, channel| {
            if service_id == conduit_proto::mux::service::PING {
                if let Some(svc) = services.iter().find(|s| s.id() == service_id).cloned() {
                    let peer = peer.clone();
                    tokio::spawn(async move {
                        svc.on_stream(&peer, channel).await;
                    });
                }
                return;
            }
            if service_id == conduit_proto::mux::service::DISCOVERY {
                let tx = tx.clone();
                let peer_id = peer.device_id.clone();
                tokio::spawn(async move {
                    match read_discovery_stream(channel).await {
                        Ok(payload) => {
                            let _ = tx.send(StreamMsg::PeerServices(
                                peer_id,
                                payload.seq,
                                payload.services,
                            ));
                        }
                        Err(e) => {
                            debug!(peer = %peer_id, error = %e, "discovery stream ended");
                        }
                    }
                });
                return;
            }
            let _ = tx.send(StreamMsg::Stream(peer.clone(), service_id, channel));
        })
    }

    pub(crate) fn datagram_dispatch(&self, peer_id: &str) -> OnDatagram {
        let sink = self.datagram_sink.clone();
        let peer_id = peer_id.to_string();
        Arc::new(move |pkt: Bytes| {
            let tx = sink.lock().unwrap().clone();
            if let Some(tx) = tx {
                let _ = tx.try_send((peer_id.clone(), pkt));
            }
        })
    }

    /// Register `link` if it beats any existing session for `peer`.
    /// Returns `Some((peer, mux))` when a new session was installed.
    pub(crate) fn register_session(
        &mut self,
        peer: PeerInfo,
        link: PeerLink,
    ) -> Option<(PeerInfo, Multiplexer)> {
        if !self.should_keep(&link) {
            drop(link);
            return None;
        }
        let new_direct = link.kind == ConnectionKind::Direct;
        let new_client = link.quic_client.clone();
        let dispatch = self.stream_dispatch(&peer);
        let dgram_cb = self.datagram_dispatch(&peer.device_id);
        let session = link.into_session_with_dynamic(
            &self.my_id,
            &self.service_ids,
            Some(self.dynamic_ids.clone()),
            dispatch,
            dgram_cb,
        );
        let mux = session.mux.clone();
        let datagram = session.datagram;

        self.sessions.retain(|s| {
            if s.peer.device_id != peer.device_id {
                return s.mux.is_alive();
            }
            let superseded = new_direct
                && (s.peer.kind != ConnectionKind::Direct
                    || match (&new_client, &s.client_id) {
                        (Some(nc), Some(sc)) => nc <= sc,
                        _ => false,
                    });
            if superseded {
                s.mux.close();
                false
            } else {
                s.mux.is_alive()
            }
        });
        self.push_session(peer.clone(), mux.clone(), datagram, new_client);
        self.peer_discovery_seq.remove(&peer.device_id);
        self.status.clear_discovery(&peer.device_id);
        self.dial_backoff.remove(&peer.device_id);
        self.sync_datagram_map();
        // Always advertise, even with an empty list: that is what lets peers
        // tell "new client, no plugins" apart from "old client, no discovery".
        spawn_send_discovery(mux.clone(), self.local_services_seq, self.local_services.clone());
        Some((peer, mux))
    }

    /// True when `link` deserves the (at most one) session slot for its peer.
    fn should_keep(&self, link: &PeerLink) -> bool {
        let Some(existing) = self
            .sessions
            .iter()
            .find(|s| s.peer.device_id == link.peer_id && s.mux.is_alive())
        else {
            return true;
        };
        if existing.peer.kind != ConnectionKind::Direct {
            return true; // any new link may replace a relay one
        }
        if link.kind != ConnectionKind::Direct {
            return false; // never downgrade an existing direct session
        }
        match (&link.quic_client, &existing.client_id) {
            (Some(nc), Some(sc)) => nc <= sc,
            _ => false,
        }
    }

    fn push_session(
        &mut self,
        peer: PeerInfo,
        mux: Multiplexer,
        datagram: DatagramSender,
        client_id: Option<String>,
    ) {
        let tx = self.stream_tx.clone();
        let watch = mux.clone();
        tokio::spawn(async move {
            watch.closed().await;
            let _ = tx.send(StreamMsg::SessionDead);
        });
        self.sessions.push(SessionEntry {
            peer,
            mux,
            datagram,
            client_id,
            last_active: Instant::now(),
        });
    }

    pub(crate) async fn handle_host(&mut self, req: HostMsg) {
        match req {
            HostMsg::Open {
                peer,
                service,
                reply,
            } => {
                if let Some(mux) = self.live_mux(&peer) {
                    match mux.open_channel(service).await {
                        Ok(ch) => {
                            let _ = reply.send(Ok(ch));
                        }
                        Err(e) => {
                            let _ = reply.send(Err(format!("opening stream: {e}")));
                        }
                    }
                    return;
                }
                if !self.peers.iter().any(|p| p.device_id == peer) {
                    if let Err(e) = self.refresh().await {
                        warn!(error = %e, "refreshing devices for a host request failed");
                    }
                    if !self.peers.iter().any(|p| p.device_id == peer) {
                        let _ = reply.send(Err(format!(
                            "{peer} is not an active device of this account"
                        )));
                        return;
                    }
                }
                self.pending_opens
                    .entry(peer.clone())
                    .or_default()
                    .push(PendingOpen {
                        service,
                        reply,
                        deadline: Instant::now() + Duration::from_secs(12),
                    });
                self.dial_backoff.remove(&peer);
                self.spawn_dial(&peer, self.force_relay);
            }
            HostMsg::EnsurePeer { peer } => {
                if self.live_mux(&peer).is_some() {
                    return;
                }
                if !self.peers.iter().any(|p| p.device_id == peer) {
                    return;
                }
                if let Some(until) = self.dial_backoff.get(&peer) {
                    if Instant::now() < *until {
                        return;
                    }
                }
                self.spawn_dial(&peer, self.force_relay);
            }
            HostMsg::SetAdvertisedServices(services) => {
                if self.local_services == services {
                    return;
                }
                self.local_services = services;
                self.local_services_seq = self.local_services_seq.wrapping_add(1);
                let seq = self.local_services_seq;
                let svcs = self.local_services.clone();
                for s in &self.sessions {
                    if s.mux.is_alive() {
                        spawn_send_discovery(s.mux.clone(), seq, svcs.clone());
                    }
                }
            }
        }
    }

    /// Spawn a background dial to `peer` if one is not already in flight.
    pub(crate) fn spawn_dial(&mut self, peer: &str, force_relay: bool) {
        if !self.dial_in_flight.insert(peer.to_string()) {
            return;
        }
        let coord = self.coord.clone();
        let mdns_addr = self.mdns_peers.addr_of(peer).map(|a| a.to_string());
        let identity = self.identity.clone();
        let trust = self.trust.clone();
        let quic = self.quic.clone();
        let relay = self.relay.clone();
        let endpoints = self.endpoints.clone();
        let punched_tx = self.punched_tx.clone();
        let signal_tx = self.signal_tx.clone();
        let dial_done_tx = self.dial_done_tx.clone();
        let peer_id = peer.to_string();

        tokio::spawn(async move {
            let mut peer_eps: Vec<String> = match coord.peer_endpoints(&peer_id).await {
                Ok(Some(eps)) => eps.endpoints,
                _ => Vec::new(),
            };
            if let Some(addr) = mdns_addr {
                if !peer_eps.contains(&addr) {
                    peer_eps.push(addr);
                }
            }
            if peer_eps.is_empty() {
                debug!(peer = %peer_id, "dial skipped: peer has no candidates");
                let _ = dial_done_tx.send(DialResult {
                    peer_id,
                    link: Err("no endpoints".into()),
                });
                return;
            }
            let res = connect_peer(
                &identity,
                &trust,
                &peer_id,
                &quic,
                &relay,
                force_relay,
                &peer_eps,
                &endpoints,
                &punched_tx,
                &signal_tx,
            )
            .await
            .map_err(|e| e.to_string());
            let _ = dial_done_tx.send(DialResult {
                peer_id,
                link: res,
            });
        });
    }

    /// Spawn a background relay accept when a peer asks us to meet at the relay.
    pub(crate) fn spawn_relay_accept(&mut self, peer: &str) {
        if !self.dial_in_flight.insert(peer.to_string()) {
            return;
        }
        let identity = self.identity.clone();
        let trust = self.trust.clone();
        let relay = self.relay.clone();
        let dial_done_tx = self.dial_done_tx.clone();
        let peer_id = peer.to_string();

        tokio::spawn(async move {
            info!(peer = %peer_id, "peer asked to meet at the relay");
            let res = accept_relay(&identity, &trust, &relay, &peer_id)
                .await
                .map_err(|e| e.to_string());
            let _ = dial_done_tx.send(DialResult {
                peer_id,
                link: res,
            });
        });
    }

    pub(crate) fn note_dial_failed(&mut self, peer_id: &str) {
        self.dial_backoff
            .insert(peer_id.to_string(), Instant::now() + DIAL_BACKOFF);
    }

    pub(crate) async fn serve_ready_pending_opens(&mut self) {
        if self.pending_opens.is_empty() {
            return;
        }
        let ready: Vec<String> = self
            .pending_opens
            .keys()
            .filter(|p| self.live_mux(p).is_some())
            .cloned()
            .collect();
        for peer in ready {
            let Some(mux) = self.live_mux(&peer) else {
                continue;
            };
            let Some(pending) = self.pending_opens.remove(&peer) else {
                continue;
            };
            for p in pending {
                match mux.open_channel(p.service).await {
                    Ok(ch) => {
                        let _ = p.reply.send(Ok(ch));
                    }
                    Err(e) => {
                        let _ = p.reply.send(Err(format!("opening stream: {e}")));
                    }
                }
            }
        }
    }

    pub(crate) fn sweep_pending_opens(&mut self) {
        if self.pending_opens.is_empty() {
            return;
        }
        let now = Instant::now();
        let mut expired: Vec<PendingOpen> = Vec::new();
        let mut drained: Vec<String> = Vec::new();
        for (peer, list) in self.pending_opens.iter_mut() {
            let (keep, gone): (Vec<PendingOpen>, Vec<PendingOpen>) =
                list.drain(..).partition(|p| p.deadline > now);
            *list = keep;
            expired.extend(gone);
            if list.is_empty() {
                drained.push(peer.clone());
            }
        }
        for p in expired {
            let _ = p
                .reply
                .send(Err("no session: peer offline or unreachable".to_string()));
        }
        for peer in drained {
            self.pending_opens.remove(&peer);
        }
    }
}

fn spawn_send_discovery(mux: Multiplexer, seq: u64, services: Vec<AdvertisedService>) {
    tokio::spawn(async move {
        let Ok(body) = serde_json::to_vec(&DiscoveryPayload { seq, services }) else {
            return;
        };
        if body.len() > MAX_DISCOVERY_BYTES {
            return;
        }
        let Ok(mut ch) = mux.open_channel(conduit_proto::mux::service::DISCOVERY).await else {
            return;
        };
        let len = (body.len() as u32).to_be_bytes();
        if ch.write_all(&len).await.is_err() {
            return;
        }
        if ch.write_all(&body).await.is_err() {
            return;
        }
        let _ = ch.flush().await;
        let _ = ch.shutdown().await;
    });
}

async fn read_discovery_stream(mut ch: Channel) -> anyhow::Result<DiscoveryPayload> {
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), ch.read_exact(&mut len_buf)).await??;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_DISCOVERY_BYTES {
        anyhow::bail!("discovery payload too large: {len} bytes");
    }
    let mut body = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(5), ch.read_exact(&mut body)).await??;
    Ok(serde_json::from_slice(&body)?)
}
