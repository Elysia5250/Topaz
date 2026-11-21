//! Local WebSocket service bridge (`control.sock`) and live status events.
//!
//! Exposes:
//! - `GET /v1/events` — live status snapshots pushed over WebSocket
//! - `GET /v1/services/{id}/open/{target}` — outbound binary stream bridge
//! - `GET /v1/services/{id}/accept?name=...` — inbound accept pool with mTLS peer handoff

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use topaz_fabric::{AdvertisedService, EngineHandle, EngineStatus, PeerInfo, SharedStatus};
use topaz_net::Channel;
use topaz_proto::mux::service;
use topaz_proto::DeviceCert;
use futures::{SinkExt, StreamExt};
use serde::Serialize;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tracing::{debug, warn};

use crate::control::{render_status, ControlState};

/// Summary of a locally registered service exposed in `/v1/status` and `/v1/events`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ServiceSummary {
    pub service_id: u16,
    pub name: String,
    pub online: bool,
    pub listeners: usize,
}

/// How long a service stays registered after its last idle listener was used
/// for a handoff. Covers the round trip while the client refills its pool.
const DRAIN_GRACE: Duration = Duration::from_secs(20);
/// How long an inbound stream waits for an idle listener before it is closed.
const PENDING_WAIT: Duration = Duration::from_secs(2);
/// Inbound streams parked per service while the pool refills.
const MAX_PENDING: usize = 32;

struct AcceptWaiter {
    id: u64,
    tx: oneshot::Sender<(PeerInfo, Channel)>,
}

struct PendingInbound {
    id: u64,
    peer: PeerInfo,
    /// Taken when the stream is handed to a listener; dropping closes it.
    channel: Option<Channel>,
}

struct RegisteredService {
    name: String,
    waiters: VecDeque<AcceptWaiter>,
    /// When a handoff consumed the final idle listener. Registration and
    /// advertisement survive the grace period so peers do not see the service
    /// flap while the pool refills.
    drained_at: Option<Instant>,
    /// Inbound streams parked during that window.
    pending: VecDeque<PendingInbound>,
}

impl RegisteredService {
    fn registered(&self, now: Instant) -> bool {
        !self.waiters.is_empty()
            || self
                .drained_at
                .is_some_and(|at| now.saturating_duration_since(at) < DRAIN_GRACE)
    }

    /// Hand parked inbound streams to idle listeners.
    fn drain_pending(&mut self) {
        while let Some(waiter) = self.waiters.pop_front() {
            let Some(mut item) = self.pending.pop_front() else {
                self.waiters.push_front(waiter);
                break;
            };
            let Some(channel) = item.channel.take() else {
                continue;
            };
            if let Err((peer, channel)) = waiter.tx.send((item.peer, channel)) {
                if self.pending.len() < MAX_PENDING {
                    self.pending.push_front(PendingInbound {
                        id: item.id,
                        peer,
                        channel: Some(channel),
                    });
                }
            }
        }
    }
}

/// Thread-safe registry of `/v1/services/{id}/accept` listener pools.
#[derive(Default)]
pub struct ServiceRegistry {
    services: Mutex<BTreeMap<u16, RegisteredService>>,
    next_id: AtomicU64,
}

impl ServiceRegistry {
    pub fn summaries(&self) -> Vec<ServiceSummary> {
        let now = Instant::now();
        let guard = self.services.lock().unwrap();
        guard
            .iter()
            .map(|(service_id, svc)| ServiceSummary {
                service_id: *service_id,
                name: svc.name.clone(),
                // Registered, not "idle right now": capacity is reported
                // separately and must not make availability flap.
                online: svc.registered(now),
                listeners: svc.waiters.len(),
            })
            .collect()
    }

    pub fn advertised(&self) -> Vec<AdvertisedService> {
        let now = Instant::now();
        let guard = self.services.lock().unwrap();
        guard
            .iter()
            .filter(|(_, svc)| svc.registered(now))
            .map(|(service_id, svc)| AdvertisedService {
                service_id: *service_id,
                name: svc.name.clone(),
            })
            .collect()
    }

    fn add_waiter(
        self: &Arc<Self>,
        service_id: u16,
        name: Option<&str>,
        engine: &EngineHandle,
        status: &Arc<SharedStatus>,
    ) -> anyhow::Result<(u64, oneshot::Receiver<(PeerInfo, Channel)>)> {
        let waiter_id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let (tx, rx) = oneshot::channel();
        let need_handler = {
            let mut guard = self.services.lock().unwrap();
            let now = Instant::now();
            let entry = guard.entry(service_id).or_insert_with(|| RegisteredService {
                name: default_service_name(service_id),
                waiters: VecDeque::new(),
                drained_at: None,
                pending: VecDeque::new(),
            });
            if let Some(n) = name.map(str::trim).filter(|s| !s.is_empty()) {
                entry.name = n.to_string();
            }
            let need_handler = !entry.registered(now);
            entry.waiters.push_back(AcceptWaiter { id: waiter_id, tx });
            entry.drained_at = None;
            entry.drain_pending();
            need_handler
        };

        if need_handler {
            let registry = Arc::clone(self);
            let eng = engine.clone();
            let st = Arc::clone(status);
            if let Err(e) = engine.register_service_handler(
                service_id,
                Arc::new(move |peer, channel| {
                    registry.dispatch_inbound(service_id, peer, channel, &eng, &st);
                }),
            ) {
                self.remove_waiter(service_id, waiter_id, engine, status);
                return Err(e);
            }
        }
        engine.set_advertised_services(self.advertised());
        status.signal();
        Ok((waiter_id, rx))
    }

    /// A parked listener went away. That is a client disconnect, not a
    /// handoff, so the service goes offline immediately.
    fn remove_waiter(
        &self,
        service_id: u16,
        waiter_id: u64,
        engine: &EngineHandle,
        status: &SharedStatus,
    ) {
        let mut dropped: Vec<PendingInbound> = Vec::new();
        let mut offline = false;
        {
            let mut guard = self.services.lock().unwrap();
            let Some(entry) = guard.get_mut(&service_id) else {
                return;
            };
            let before = entry.waiters.len();
            entry.waiters.retain(|w| w.id != waiter_id);
            if entry.waiters.len() == before {
                return;
            }
            if entry.waiters.is_empty() {
                // Keep the registration entry so status can say "offline"
                // instead of making the service vanish and reappear.
                entry.drained_at = None;
                dropped = entry.pending.drain(..).collect();
                offline = true;
            }
        }
        if offline {
            engine.unregister_service_handler(service_id);
            engine.set_advertised_services(self.advertised());
        }
        status.signal();
        drop(dropped);
    }

    /// Deliver an inbound stream, or park it briefly while the pool refills.
    fn dispatch_inbound(
        self: &Arc<Self>,
        service_id: u16,
        peer: PeerInfo,
        channel: Channel,
        engine: &EngineHandle,
        status: &Arc<SharedStatus>,
    ) {
        enum Outcome {
            Sent { drained: bool },
            Queued(u64),
            Dropped,
        }

        let now = Instant::now();
        let outcome = {
            let mut guard = self.services.lock().unwrap();
            let Some(entry) = guard.get_mut(&service_id) else {
                return;
            };
            let mut payload = Some((peer, channel));
            let mut sent = false;
            while let Some(waiter) = entry.waiters.pop_front() {
                let item = payload.take().expect("payload taken once");
                match waiter.tx.send(item) {
                    Ok(()) => {
                        sent = true;
                        break;
                    }
                    Err(returned) => payload = Some(returned),
                }
            }
            if sent {
                let drained = entry.waiters.is_empty();
                if drained {
                    entry.drained_at = Some(now);
                }
                Outcome::Sent { drained }
            } else if entry.registered(now) {
                let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
                let (peer, channel) = payload.take().expect("payload taken once");
                entry.pending.push_back(PendingInbound {
                    id,
                    peer,
                    channel: Some(channel),
                });
                while entry.pending.len() > MAX_PENDING {
                    entry.pending.pop_front();
                }
                Outcome::Queued(id)
            } else {
                Outcome::Dropped
            }
        };

        match outcome {
            Outcome::Sent { drained: true } => {
                let registry = Arc::clone(self);
                let eng = engine.clone();
                let st = Arc::clone(status);
                let at = now;
                tokio::spawn(async move {
                    tokio::time::sleep(DRAIN_GRACE).await;
                    registry.expire_registration(service_id, at, &eng, &st);
                });
            }
            Outcome::Sent { drained: false } => {}
            Outcome::Queued(id) => {
                let registry = Arc::clone(self);
                let st = Arc::clone(status);
                tokio::spawn(async move {
                    tokio::time::sleep(PENDING_WAIT).await;
                    registry.expire_pending(service_id, id);
                    st.signal();
                });
            }
            Outcome::Dropped => {
                debug!(
                    service_id,
                    "no listener and the service is unregistered; closing inbound stream"
                );
            }
        }
        status.signal();
    }

    /// The grace after a handoff ran out with no listener back: stop
    /// advertising and close anything still parked.
    fn expire_registration(
        &self,
        service_id: u16,
        drained_at: Instant,
        engine: &EngineHandle,
        status: &SharedStatus,
    ) {
        let mut dropped: Vec<PendingInbound> = Vec::new();
        let expired = {
            let mut guard = self.services.lock().unwrap();
            let expired = guard.get(&service_id).is_some_and(|entry| {
                entry.waiters.is_empty()
                    && entry.drained_at == Some(drained_at)
                    && drained_at.elapsed() >= DRAIN_GRACE
            });
            if expired {
                if let Some(entry) = guard.get_mut(&service_id) {
                    entry.drained_at = None;
                    dropped = entry.pending.drain(..).collect();
                }
            }
            expired
        };
        if expired {
            engine.unregister_service_handler(service_id);
            engine.set_advertised_services(self.advertised());
            status.signal();
            debug!(service_id, "service registration expired after handoff drain");
        }
        drop(dropped);
    }

    fn expire_pending(&self, service_id: u16, pending_id: u64) {
        let dropped = {
            let mut guard = self.services.lock().unwrap();
            guard.get_mut(&service_id).and_then(|entry| {
                let pos = entry.pending.iter().position(|p| p.id == pending_id)?;
                entry.pending.remove(pos)
            })
        };
        if let Some(item) = dropped {
            debug!(
                service_id,
                peer = %item.peer.device_id,
                "inbound stream waited too long for a listener; closing"
            );
        }
    }
}

fn default_service_name(service_id: u16) -> String {
    format!("service-{service_id}")
}

struct WaiterGuard {
    service_id: u16,
    waiter_id: u64,
    services: Arc<ServiceRegistry>,
    engine: EngineHandle,
    status: Arc<SharedStatus>,
    armed: bool,
}

impl Drop for WaiterGuard {
    fn drop(&mut self) {
        if self.armed {
            self.services
                .remove_waiter(self.service_id, self.waiter_id, &self.engine, &self.status);
        }
    }
}

/// Build an HTTP JSON error response with an explicit `Content-Length` header
/// so WebSocket clients (`tungstenite`, etc.) always receive the JSON error body.
pub fn json_error(
    status: StatusCode,
    code: &'static str,
    msg: impl Into<String>,
) -> Response {
    let body = serde_json::to_vec(&json!({ "error": msg.into(), "code": code }))
        .unwrap_or_else(|_| b"{\"error\":\"internal error\",\"code\":\"internal\"}".to_vec());
    let len = body.len().to_string();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_LENGTH, len)
        .body(axum::body::Body::from(body))
        .expect("valid json error response")
}

#[derive(Debug, Clone)]
pub struct ResolvedPeer {
    pub device_id: String,
    pub name: String,
    pub virtual_ip: Option<String>,
}

fn strip_topaz_suffix(s: &str) -> &str {
    let suffix = ".topaz";
    if s.len() >= suffix.len() && s.is_char_boundary(s.len() - suffix.len()) {
        let (head, tail) = s.split_at(s.len() - suffix.len());
        if tail.eq_ignore_ascii_case(suffix) && !head.is_empty() {
            return head;
        }
    }
    s
}

fn resolved_from(cert: &DeviceCert, engine: &EngineStatus) -> ResolvedPeer {
    let addr = engine.peer_addr(&cert.device_id);
    ResolvedPeer {
        device_id: cert.device_id.clone(),
        name: cert.name.clone(),
        virtual_ip: addr.and_then(|a| a.virtual_ip.clone()),
    }
}

/// Resolve an outbound `{target}` against active peers (excluding self):
/// 1. exact `device_id`
/// 2. exact `dns_name` (case-insensitive, optional `.topaz` suffix)
/// 3. exact `virtual_ip`
/// 4. unique `DeviceCert.name` (case-insensitive)
pub fn resolve_target(
    engine: &EngineStatus,
    target: &str,
) -> std::result::Result<ResolvedPeer, (StatusCode, &'static str, String)> {
    let target = target.trim();
    if target.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "empty_target",
            "empty target peer".to_string(),
        ));
    }

    if let Some(p) = engine.peers.iter().find(|p| p.device_id == target) {
        return Ok(resolved_from(p, engine));
    }

    let dns_target = strip_topaz_suffix(target);
    if let Some(p) = engine.peers.iter().find(|p| {
        engine
            .peer_addr(&p.device_id)
            .and_then(|a| a.dns_name.as_deref())
            .is_some_and(|d| d.eq_ignore_ascii_case(dns_target))
    }) {
        return Ok(resolved_from(p, engine));
    }

    if let Some(p) = engine.peers.iter().find(|p| {
        engine
            .peer_addr(&p.device_id)
            .and_then(|a| a.virtual_ip.as_deref())
            == Some(target)
    }) {
        return Ok(resolved_from(p, engine));
    }

    let name_matches: Vec<&DeviceCert> = engine
        .peers
        .iter()
        .filter(|p| p.name.eq_ignore_ascii_case(target))
        .collect();
    match name_matches.len() {
        0 => Err((
            StatusCode::NOT_FOUND,
            "device_not_found",
            format!("device not found: {target}"),
        )),
        1 => Ok(resolved_from(name_matches[0], engine)),
        _ => Err((
            StatusCode::CONFLICT,
            "ambiguous_target",
            format!("ambiguous device name '{target}'; use device_id or dns_name"),
        )),
    }
}

fn validate_service_id(
    service_id: u16,
) -> std::result::Result<(), (StatusCode, &'static str, String)> {
    if service_id < service::REGISTERED_MIN {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid_service",
            format!(
                "invalid service_id {service_id}; must be >= {}",
                service::REGISTERED_MIN
            ),
        ));
    }
    Ok(())
}

pub async fn ws_events(State(st): State<Arc<ControlState>>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |mut socket| async move {
        let mut rx = st.status.subscribe();
        let mut last = status_snapshot(&st);
        let initial = json!({ "type": "status", "status": last }).to_string();
        if socket.send(Message::Text(initial.into())).await.is_err() {
            return;
        }

        loop {
            tokio::select! {
                res = rx.changed() => {
                    if res.is_err() {
                        break;
                    }
                    let next = status_snapshot(&st);
                    if next != last {
                        let msg = json!({ "type": "status", "status": next }).to_string();
                        if socket.send(Message::Text(msg.into())).await.is_err() {
                            break;
                        }
                        last = next;
                    }
                }
                msg = socket.next() => {
                    match msg {
                        None | Some(Ok(Message::Close(_))) | Some(Err(_)) => break,
                        Some(Ok(_)) => {}
                    }
                }
            }
        }
    })
}

fn status_snapshot(st: &ControlState) -> serde_json::Value {
    let engine = st.status.engine();
    let vpn = st.vpn.get();
    let services = st.services.summaries();
    let store = st.store.lock().unwrap();
    render_status(&store, &engine, &vpn, &st.account_user_id, &services)
}

pub async fn ws_service_open(
    State(st): State<Arc<ControlState>>,
    Path((service_id, target)): Path<(u16, String)>,
    ws: WebSocketUpgrade,
) -> Response {
    if let Err((code, tag, msg)) = validate_service_id(service_id) {
        return json_error(code, tag, msg);
    }

    let engine = st.status.engine();
    let resolved = match resolve_target(&engine, &target) {
        Ok(p) => p,
        Err((code, tag, msg)) => return json_error(code, tag, msg),
    };

    // Only trust the discovery cache when the peer is connected *and* has
    // actually sent a DISCOVERY frame: an older peer advertises nothing and
    // must not be rejected for it.
    let online = engine
        .sessions
        .iter()
        .any(|(id, _)| id == &resolved.device_id);
    if online
        && engine.has_discovery(&resolved.device_id)
        && !engine
            .peer_services(&resolved.device_id)
            .iter()
            .any(|s| s.service_id == service_id)
    {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "service_not_registered",
            format!(
                "{} does not advertise service {service_id}",
                resolved.name
            ),
        );
    }

    let channel = match st.engine.open(&resolved.device_id, service_id).await {
        Ok(ch) => ch,
        Err(e) => {
            return json_error(StatusCode::SERVICE_UNAVAILABLE, "peer_offline", e.to_string())
        }
    };

    let mut resp = ws.on_upgrade(move |socket| splice_ws_channel(socket, channel));
    let headers = resp.headers_mut();
    if let Ok(val) = HeaderValue::from_str(&resolved.device_id) {
        headers.insert("X-Topaz-Peer-Id", val);
    }
    if let Ok(val) = HeaderValue::from_str(&resolved.name) {
        headers.insert("X-Topaz-Peer-Name", val);
    }
    if let Some(ip) = resolved.virtual_ip.as_deref() {
        if let Ok(val) = HeaderValue::from_str(ip) {
            headers.insert("X-Topaz-Peer-Ip", val);
        }
    }
    resp
}

#[derive(serde::Deserialize)]
pub struct AcceptQuery {
    name: Option<String>,
}

pub async fn ws_service_accept(
    State(st): State<Arc<ControlState>>,
    Path(service_id): Path<u16>,
    Query(q): Query<AcceptQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    if let Err((code, tag, msg)) = validate_service_id(service_id) {
        return json_error(code, tag, msg);
    }

    let (waiter_id, mut rx) =
        match st
            .services
            .add_waiter(service_id, q.name.as_deref(), &st.engine, &st.status)
        {
            Ok(pair) => pair,
            Err(e) => return json_error(StatusCode::BAD_REQUEST, "invalid_service", e.to_string()),
        };

    // Construct the guard *before* `ws.on_upgrade` so if the HTTP upgrade is
    // abandoned before the callback runs, dropping the closure still removes
    // the waiter from `ServiceRegistry`.
    let mut guard = WaiterGuard {
        service_id,
        waiter_id,
        services: Arc::clone(&st.services),
        engine: st.engine.clone(),
        status: Arc::clone(&st.status),
        armed: true,
    };

    ws.on_upgrade(move |mut socket| async move {
        let accepted = loop {
            tokio::select! {
                res = &mut rx => {
                    guard.armed = false;
                    match res {
                        Ok(item) => break Some(item),
                        Err(_) => break None,
                    }
                }
                msg = socket.next() => {
                    match msg {
                        None | Some(Ok(Message::Close(_))) | Some(Err(_)) => {
                            break None;
                        }
                        Some(Ok(_)) => {}
                    }
                }
            }
        };
        drop(guard);

        let Some((peer, channel)) = accepted else {
            return;
        };

        let handoff = build_accepted_handoff(&st.status.engine(), service_id, &peer);
        if socket
            .send(Message::Text(handoff.to_string().into()))
            .await
            .is_err()
        {
            warn!(service_id, peer = %peer.device_id, "failed to send accepted handoff over WS");
            drop(channel);
            return;
        }
        splice_ws_channel(socket, channel).await;
    })
}

fn build_accepted_handoff(
    engine: &EngineStatus,
    service_id: u16,
    peer: &PeerInfo,
) -> serde_json::Value {
    let peer_name = engine
        .peers
        .iter()
        .find(|p| p.device_id == peer.device_id)
        .map(|p| p.name.as_str())
        .unwrap_or(peer.device_id.as_str());
    let addr = engine.peer_addr(&peer.device_id);
    let connection = format!("{:?}", peer.kind).to_lowercase();
    json!({
        "event": "accepted",
        "service_id": service_id,
        "peer_device_id": peer.device_id,
        "peer_name": peer_name,
        "peer_dns_name": addr.and_then(|a| a.dns_name.as_deref()),
        "peer_virtual_ip": addr.and_then(|a| a.virtual_ip.as_deref()),
        "connection": connection,
    })
}

async fn splice_ws_channel(socket: WebSocket, channel: Channel) {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (mut ch_r, mut ch_w) = tokio::io::split(channel);

    let to_ws = async {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match ch_r.read(&mut buf).await {
                Ok(0) => {
                    let _ = ws_tx.send(Message::Close(None)).await;
                    let _ = ws_tx.close().await;
                    break;
                }
                Ok(n) => {
                    let payload = bytes::Bytes::copy_from_slice(&buf[..n]);
                    if ws_tx.send(Message::Binary(payload)).await.is_err() {
                        break;
                    }
                }
                Err(_) => {
                    let _ = ws_tx.send(Message::Close(None)).await;
                    break;
                }
            }
        }
    };

    let to_ch = async {
        while let Some(msg) = ws_rx.next().await {
            match msg {
                Ok(Message::Binary(data)) => {
                    if ch_w.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Close(_)) | Err(_) => {
                    break;
                }
                Ok(Message::Ping(_) | Message::Pong(_) | Message::Text(_)) => {}
            }
        }
        let _ = ch_w.shutdown().await;
    };

    tokio::select! {
        _ = to_ws => {}
        _ = to_ch => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use topaz_core::{generate_recovery_code, issue_cert, AccountKey, DeviceIdentity};
    use topaz_fabric::VirtualAddr;

    fn sample_engine_status() -> EngineStatus {
        let rec = generate_recovery_code();
        let root = AccountKey::from_recovery(&rec).unwrap();
        let a = DeviceIdentity::generate().unwrap();
        let b = DeviceIdentity::generate().unwrap();
        let c = DeviceIdentity::generate().unwrap();
        let cert_a = issue_cert(
            &root.signing,
            &root.user_id,
            &root.user_pubkey,
            &a.pubkey_hex,
            "laptop",
        )
        .unwrap();
        let cert_b = issue_cert(
            &root.signing,
            &root.user_id,
            &root.user_pubkey,
            &b.pubkey_hex,
            "worker",
        )
        .unwrap();
        let cert_c = issue_cert(
            &root.signing,
            &root.user_id,
            &root.user_pubkey,
            &c.pubkey_hex,
            "worker",
        )
        .unwrap();
        EngineStatus {
            self_addr: VirtualAddr {
                virtual_ip: Some("100.64.0.1".into()),
                dns_name: Some("self-node".into()),
            },
            peers: vec![cert_a.clone(), cert_b.clone(), cert_c.clone()],
            peer_addrs: vec![
                (
                    cert_a.device_id,
                    VirtualAddr {
                        virtual_ip: Some("100.64.0.2".into()),
                        dns_name: Some("laptop".into()),
                    },
                ),
                (
                    cert_b.device_id,
                    VirtualAddr {
                        virtual_ip: Some("100.64.0.3".into()),
                        dns_name: Some("worker".into()),
                    },
                ),
                (
                    cert_c.device_id,
                    VirtualAddr {
                        virtual_ip: Some("100.64.0.4".into()),
                        dns_name: Some("worker-2".into()),
                    },
                ),
            ],
            ..Default::default()
        }
    }

    #[test]
    fn registration_outlives_a_handoff_drain_for_the_grace_window() {
        let now = Instant::now();
        let drained = RegisteredService {
            name: "jade".into(),
            waiters: VecDeque::new(),
            drained_at: Some(now),
            pending: VecDeque::new(),
        };
        assert!(drained.registered(now));
        assert!(drained.registered(now + DRAIN_GRACE - Duration::from_millis(1)));
        assert!(!drained.registered(now + DRAIN_GRACE + Duration::from_millis(1)));

        let offline = RegisteredService {
            drained_at: None,
            ..drained
        };
        assert!(!offline.registered(now));
    }

    #[test]
    fn service_names_come_from_the_registration_not_a_hardcoded_table() {
        assert_eq!(default_service_name(16), "service-16");
        assert_eq!(default_service_name(1024), "service-1024");
    }

    #[test]
    fn resolve_target_priority_and_conflicts() {
        let st = sample_engine_status();
        let laptop_id = st.peers[0].device_id.clone();
        let worker2_id = st.peers[2].device_id.clone();

        // 1. Exact device_id
        assert_eq!(resolve_target(&st, &laptop_id).unwrap().device_id, laptop_id);
        // 2. dns_name with/without .topaz (case-insensitive)
        assert_eq!(resolve_target(&st, "LAPTOP").unwrap().device_id, laptop_id);
        assert_eq!(
            resolve_target(&st, "Laptop.Topaz").unwrap().device_id,
            laptop_id
        );
        assert_eq!(
            resolve_target(&st, "worker-2.topaz").unwrap().device_id,
            worker2_id
        );
        // 3. virtual_ip
        assert_eq!(resolve_target(&st, "100.64.0.4").unwrap().device_id, worker2_id);
        // 4. unique cert name vs ambiguous cert name
        // Note: "worker" matches dns_name of peer[1] at priority 2 before falling back to cert.name!
        // Test ambiguous cert.name with differing dns_name using a distinct cert.name collision:
        let mut st_ambig = st.clone();
        st_ambig.peer_addrs[1].1.dns_name = Some("worker-1".into());
        let err = resolve_target(&st_ambig, "WORKER").unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);
        // Not found / empty
        assert_eq!(resolve_target(&st, "   ").unwrap_err().0, StatusCode::BAD_REQUEST);
        assert_eq!(
            resolve_target(&st, "missing").unwrap_err().0,
            StatusCode::NOT_FOUND
        );
    }
}
