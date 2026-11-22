use crate::db::{normalize_invite, CreateAccountError};
use crate::state::{now_unix, ActiveDevice, AppState, Mailbox, Online, ONLINE_TTL_SECS};
use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rand::Rng;
use serde::de::DeserializeOwned;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use topaz_proto::auth::{
    request_signing_bytes, verify, HDR_DEVICE, HDR_NONCE, HDR_SIG, HDR_TIME,
    MAX_CERT_CLOCK_SKEW_SECS,
};
use topaz_proto::{
    CreateAccountRequest, DeviceCert, DeviceEntry, EnrollFinish, EnrollReply, EnrollStart,
    EnrollStarted, PeerEndpoints, RegisterRequest, RegisterResponse, Revocation, ServerInfo,
    ServerVersion, SignalEnvelope, HDR_ENROLL_TOKEN, HDR_VERSION, VERSION_LONG,
};
use tracing::{info, warn};

type ApiResult<T> = Result<T, (StatusCode, String)>;
type Shared = State<Arc<AppState>>;

const NAMEPLATE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const MAX_ENDPOINTS_PER_REGISTER: usize = 32;
const MAX_ENDPOINT_LEN: usize = 128;

fn err(status: StatusCode, msg: impl Into<String>) -> (StatusCode, String) {
    (status, msg.into())
}

fn internal(e: impl std::fmt::Display) -> (StatusCode, String) {
    warn!(error = %e, "internal error");
    err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
}

fn parse<T: DeserializeOwned>(body: &[u8]) -> ApiResult<T> {
    serde_json::from_slice(body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("bad request: {e}")))
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> ApiResult<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, format!("missing {name}")))
}

async fn run_blocking<F, T>(f: F) -> ApiResult<T>
where
    F: FnOnce() -> ApiResult<T> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| internal(format!("blocking task failed: {e}")))?
}

/// Verify a request signed by an active device without blocking Tokio workers.
async fn authenticate(
    state: &Arc<AppState>,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> ApiResult<ActiveDevice> {
    let device_id = header(headers, HDR_DEVICE)?.to_string();
    let time: u64 = header(headers, HDR_TIME)?
        .parse()
        .map_err(|_| err(StatusCode::UNAUTHORIZED, "bad timestamp"))?;
    let nonce = header(headers, HDR_NONCE)?.to_string();
    let sig = header(headers, HDR_SIG)?.to_string();
    let msg = request_signing_bytes(method.as_str(), uri.path(), time, &nonce, body);
    let st = state.clone();
    run_blocking(move || {
        let device = st
            .active_device(&device_id)
            .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "unknown or revoked device"))?;
        if !verify(&device.pubkey, &msg, &sig) {
            return Err(err(StatusCode::UNAUTHORIZED, "bad signature"));
        }
        if !st.fresh(&device.device_id, time, &nonce) {
            return Err(err(StatusCode::UNAUTHORIZED, "stale or replayed request"));
        }
        st.cache_device_user(&device.device_id, &device.user_id);
        Ok(device)
    })
    .await
}

async fn healthz() -> Response {
    let mut resp = "ok".into_response();
    if let Ok(val) = HeaderValue::from_str(VERSION_LONG) {
        resp.headers_mut().insert(HDR_VERSION, val);
    }
    resp
}

async fn version_info() -> Json<ServerVersion> {
    Json(ServerVersion::current())
}

async fn server_info(State(state): Shared, headers: HeaderMap) -> Json<ServerInfo> {
    let host = headers.get("host").and_then(|v| v.to_str().ok());
    Json(ServerInfo {
        version: ServerVersion::current(),
        server_time_unix: now_unix(),
        relay: state.advertise_relay(host),
        relay_ws: state.advertise_relay_ws(host),
        relay_quic: state.advertise_relay_quic(host),
        stun: state.advertise_stun(host),
    })
}

fn routes(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/version", get(version_info))
        .route("/v1/info", get(server_info))
        .route("/v1/accounts", post(create_account))
        .route("/v1/devices", post(add_device).get(list_devices))
        .route("/v1/revocations", post(revoke))
        .route("/v1/register", post(register))
        .route("/v1/endpoints/{device_id}", get(peer_endpoints))
        .route("/v1/enroll", post(enroll_start))
        .route("/v1/enroll/{nameplate}", get(enroll_offer))
        .route(
            "/v1/enroll/{nameplate}/reply",
            post(enroll_reply).get(enroll_get_reply),
        )
        .route(
            "/v1/enroll/{nameplate}/finish",
            post(enroll_finish).get(enroll_get_finish),
        )
        .route("/v1/signal", get(signal_ws))
        .route("/v1/relay", get(crate::relay::ws_upgrade))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

pub fn router(state: Arc<AppState>, relay: crate::relay::RelayHandle) -> Router {
    routes(state).layer(axum::Extension(relay))
}

async fn create_account(
    State(state): Shared,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    body: Bytes,
) -> ApiResult<StatusCode> {
    if !state.account_limiter.allow(addr.ip()) {
        return Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            "too many account requests; try again later",
        ));
    }
    let req: CreateAccountRequest = parse(&body)?;
    let cert = req.cert;
    if !cert.self_consistent() || cert.issuer_pubkey != cert.user_pubkey {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "first device must be issued by the account root key",
        ));
    }
    let now = now_unix();
    if cert.issued_at.abs_diff(now) > MAX_CERT_CLOCK_SKEW_SECS {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "certificate timestamp is outside the allowed clock skew window",
        ));
    }
    let invite = normalize_invite(&req.invite);
    let st = state.clone();
    let user_id = cert.user_id.clone();
    let device_id = cert.device_id.clone();
    run_blocking(move || {
        match st.db.create_account(&invite, &cert, now) {
            Ok(()) => {
                st.cache_device_user(&cert.device_id, &cert.user_id);
                Ok(())
            }
            Err(CreateAccountError::InviteInvalid) => Err(err(
                StatusCode::FORBIDDEN,
                "invite code is invalid or already used",
            )),
            Err(CreateAccountError::AccountExists) => {
                Err(err(StatusCode::CONFLICT, "account already exists"))
            }
            Err(CreateAccountError::Other(e)) => Err(internal(e)),
        }
    })
    .await?;
    info!(user = %user_id, device = %device_id, "account created");
    Ok(StatusCode::NO_CONTENT)
}

async fn add_device(State(state): Shared, body: Bytes) -> ApiResult<StatusCode> {
    let cert: DeviceCert = parse(&body)?;
    if !cert.self_consistent() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "certificate signature is not valid",
        ));
    }
    let now = now_unix();
    let st = state.clone();
    let user_id = cert.user_id.clone();
    let device_id = cert.device_id.clone();
    let name = cert.name.clone();
    let inserted = run_blocking(move || {
        let (user_pubkey, entries, set) = st
            .account(&cert.user_id)
            .ok_or_else(|| err(StatusCode::FORBIDDEN, "unknown account"))?;
        if cert.user_pubkey != user_pubkey {
            return Err(err(
                StatusCode::FORBIDDEN,
                "certificate is for a different account key",
            ));
        }
        if let Some(existing) = entries.iter().find(|e| e.cert.device_id == cert.device_id) {
            return if existing.cert == cert {
                Ok(false)
            } else {
                Err(err(StatusCode::CONFLICT, "device already exists"))
            };
        }
        if cert.issued_at.abs_diff(now) > MAX_CERT_CLOCK_SKEW_SECS {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "certificate timestamp is outside the allowed clock skew window",
            ));
        }
        if st
            .db
            .device_user(&cert.device_id)
            .map_err(internal)?
            .is_some()
        {
            return Err(err(
                StatusCode::CONFLICT,
                "device belongs to another account",
            ));
        }
        if !set
            .authority_keys(&user_pubkey)
            .contains(&cert.issuer_pubkey)
        {
            return Err(err(
                StatusCode::FORBIDDEN,
                "issuer is not the root key or an active device of this account",
            ));
        }
        if let Some(issuer_cert) = set
            .active
            .iter()
            .find(|c| c.device_pubkey == cert.issuer_pubkey)
        {
            if cert.issued_at < issuer_cert.issued_at {
                return Err(err(
                    StatusCode::BAD_REQUEST,
                    "certificate timestamp precedes its issuer certificate",
                ));
            }
        }
        st.db.insert_device(&cert).map_err(internal)?;
        st.cache_device_user(&cert.device_id, &cert.user_id);
        Ok(true)
    })
    .await?;
    if inserted {
        info!(user = %user_id, device = %device_id, name = %name, "device added");
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke(
    State(state): Shared,
    axum::Extension(relay): axum::Extension<crate::relay::RelayHandle>,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let rev: Revocation = parse(&body)?;
    let now = now_unix();
    if rev.issued_at.abs_diff(now) > MAX_CERT_CLOCK_SKEW_SECS {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "revocation timestamp is outside the allowed clock skew window",
        ));
    }
    let user_id = rev.user_id.clone();
    let device_id = rev.device_id.clone();
    let st = state.clone();
    run_blocking(move || {
        let (user_pubkey, entries, set) = st
            .account(&rev.user_id)
            .ok_or_else(|| err(StatusCode::FORBIDDEN, "unknown account"))?;
        if !entries.iter().any(|e| e.cert.device_id == rev.device_id) {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "device is not in this account",
            ));
        }
        if !set.can_revoke(&user_pubkey, &rev.issuer_pubkey, &rev.device_id)
            || !verify(&rev.issuer_pubkey, &rev.signing_bytes(), &rev.sig)
        {
            return Err(err(
                StatusCode::FORBIDDEN,
                "revocation must be signed by the account root key, an active ancestor, or the device itself",
            ));
        }
        st.db.set_revocation(&rev).map_err(internal)?;
        // Re-evaluate after writing: if revoking an ancestor invalidated any
        // prior revocation it had signed, heal DB revocation/dns_name state.
        if let Some((_, _, updated_set)) = st.account(&rev.user_id) {
            let active_ids: HashSet<String> = updated_set
                .active
                .iter()
                .map(|c| c.device_id.clone())
                .collect();
            st.db
                .ensure_active_dns_names(&rev.user_id, &active_ids)
                .map_err(internal)?;
        }
        Ok(())
    })
    .await?;
    state.drop_device(&device_id);
    relay.kick_device(&device_id).await;
    info!(user = %user_id, device = %device_id, "device revoked");
    Ok(StatusCode::NO_CONTENT)
}

async fn list_devices(
    State(state): Shared,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Vec<DeviceEntry>>> {
    let me = authenticate(&state, &method, &uri, &headers, &body).await?;
    let st = state.clone();
    let entries = run_blocking(move || st.db.entries(&me.user_id).map_err(internal)).await?;
    Ok(Json(entries))
}

async fn register(
    State(state): Shared,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<RegisterResponse>> {
    let me = authenticate(&state, &method, &uri, &headers, &body).await?;
    let req: RegisterRequest = parse(&body)?;
    if req.endpoints.len() > MAX_ENDPOINTS_PER_REGISTER
        || req.endpoints.iter().any(|e| e.len() > MAX_ENDPOINT_LEN)
    {
        return Err(err(StatusCode::BAD_REQUEST, "too many or oversized endpoints"));
    }
    state.online.lock().unwrap().insert(
        me.device_id.clone(),
        Online {
            user_id: me.user_id,
            endpoints: req.endpoints,
            last_seen: now_unix(),
        },
    );
    let host = headers.get("host").and_then(|v| v.to_str().ok());
    Ok(Json(RegisterResponse {
        observed_ip: addr.ip().to_string(),
        relay: state.advertise_relay(host),
        relay_ws: state.advertise_relay_ws(host),
        relay_quic: state.advertise_relay_quic(host),
        stun: state.advertise_stun(host),
    }))
}

async fn peer_endpoints(
    State(state): Shared,
    Path(device_id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<PeerEndpoints>> {
    let me = authenticate(&state, &method, &uri, &headers, &body).await?;
    let online = state.online.lock().unwrap();
    let peer = online
        .get(&device_id)
        .filter(|o| o.user_id == me.user_id)
        .filter(|o| now_unix().saturating_sub(o.last_seen) <= ONLINE_TTL_SECS)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "peer offline"))?;
    Ok(Json(PeerEndpoints {
        device_id,
        endpoints: peer.endpoints.clone(),
        last_seen_unix: peer.last_seen,
    }))
}

async fn enroll_start(
    State(state): Shared,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<EnrollStarted>> {
    let me = authenticate(&state, &method, &uri, &headers, &body).await?;
    let start: EnrollStart = parse(&body)?;
    state.purge_mailboxes();
    let mut boxes = state.mailboxes.lock().unwrap();
    if boxes.len() >= 1024 {
        return Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            "too many active pairing sessions on server; try again later",
        ));
    }
    let owner_count = boxes.values().filter(|m| m.owner == me.device_id).count();
    if owner_count >= 3 {
        return Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            "too many pending pairing codes for this device",
        ));
    }
    let nameplate = if let Some(room) = start.room {
        let room = room.trim().to_string();
        if room.len() < 6
            || room.len() > 64
            || !room
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(err(StatusCode::BAD_REQUEST, "invalid pairing room key"));
        }
        if boxes.contains_key(&room) {
            return Err(err(
                StatusCode::CONFLICT,
                "pairing code is already in use; choose another phrase",
            ));
        }
        room
    } else {
        let mut rng = rand::rngs::OsRng;
        let mut np_opt = None;
        for _ in 0..64 {
            let np: String = (0..3)
                .map(|_| NAMEPLATE_ALPHABET[rng.gen_range(0..NAMEPLATE_ALPHABET.len())] as char)
                .collect();
            if !boxes.contains_key(&np) {
                np_opt = Some(np);
                break;
            }
        }
        let Some(np) = np_opt else {
            return Err(err(
                StatusCode::SERVICE_UNAVAILABLE,
                "pairing code space exhausted; try again later",
            ));
        };
        np
    };
    boxes.insert(
        nameplate.clone(),
        Mailbox {
            user_id: me.user_id,
            owner: me.device_id,
            created: Instant::now(),
            msg_a: start.msg_a,
            reply: None,
            finish_token: None,
            finish: None,
        },
    );
    Ok(Json(EnrollStarted { nameplate }))
}

fn not_found() -> (StatusCode, String) {
    err(StatusCode::NOT_FOUND, "code not found or expired")
}

async fn enroll_offer(
    State(state): Shared,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(nameplate): Path<String>,
) -> ApiResult<Json<EnrollStart>> {
    if !state.enroll_limiter.allow(addr.ip()) {
        return Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            "too many pairing requests; try again shortly",
        ));
    }
    state.purge_mailboxes();
    let boxes = state.mailboxes.lock().unwrap();
    let mb = boxes.get(&nameplate).ok_or_else(not_found)?;
    Ok(Json(EnrollStart {
        msg_a: mb.msg_a.clone(),
        room: None,
    }))
}

async fn enroll_reply(
    State(state): Shared,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(nameplate): Path<String>,
    body: Bytes,
) -> ApiResult<StatusCode> {
    if !state.enroll_limiter.allow(addr.ip()) {
        return Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            "too many pairing requests; try again shortly",
        ));
    }
    let reply: EnrollReply = parse(&body)?;
    if reply.finish_token.len() < 16 || reply.finish_token.len() > 128 {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "missing or malformed finish_token",
        ));
    }
    state.purge_mailboxes();
    let mut boxes = state.mailboxes.lock().unwrap();
    let mb = boxes.get_mut(&nameplate).ok_or_else(not_found)?;
    if mb.reply.is_some() {
        return Err(err(StatusCode::CONFLICT, "code was already used"));
    }
    mb.finish_token = Some(reply.finish_token.clone());
    mb.reply = Some(reply);
    Ok(StatusCode::NO_CONTENT)
}

async fn enroll_get_reply(
    State(state): Shared,
    Path(nameplate): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<EnrollReply>> {
    let me = authenticate(&state, &method, &uri, &headers, &body).await?;
    let boxes = state.mailboxes.lock().unwrap();
    let mb = boxes
        .get(&nameplate)
        .filter(|m| m.owner == me.device_id)
        .ok_or_else(not_found)?;
    mb.reply
        .clone()
        .map(Json)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "no reply yet"))
}

async fn enroll_finish(
    State(state): Shared,
    Path(nameplate): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let me = authenticate(&state, &method, &uri, &headers, &body).await?;
    let finish: EnrollFinish = parse(&body)?;
    let mut boxes = state.mailboxes.lock().unwrap();
    let mb = boxes
        .get_mut(&nameplate)
        .filter(|m| m.owner == me.device_id && m.user_id == me.user_id)
        .ok_or_else(not_found)?;
    mb.finish = Some(finish.payload);
    Ok(StatusCode::NO_CONTENT)
}

async fn enroll_get_finish(
    State(state): Shared,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(nameplate): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<EnrollFinish>> {
    if !state.enroll_limiter.allow(addr.ip()) {
        return Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            "too many pairing requests; try again shortly",
        ));
    }
    let token = headers
        .get(HDR_ENROLL_TOKEN)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| err(StatusCode::FORBIDDEN, "missing enroll finish token"))?;
    let mut boxes = state.mailboxes.lock().unwrap();
    let mb = boxes
        .get(&nameplate)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "not finished yet"))?;
    if mb.finish_token.as_deref() != Some(token) {
        return Err(err(StatusCode::FORBIDDEN, "invalid enroll finish token"));
    }
    let payload = mb
        .finish
        .clone()
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "not finished yet"))?;
    boxes.remove(&nameplate);
    Ok(Json(EnrollFinish { payload }))
}

async fn signal_ws(
    State(state): Shared,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let Ok(permit) = state.ws_semaphore.clone().try_acquire_owned() else {
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "too many websocket connections",
        )
        .into_response();
    };
    match authenticate(&state, &method, &uri, &headers, &[]).await {
        Ok(me) => ws.on_upgrade(move |socket| async move {
            let _permit = permit;
            handle_signal(socket, state, me).await;
        }),
        Err(e) => e.into_response(),
    }
}

async fn device_belongs_to_user(state: &Arc<AppState>, device_id: &str, user_id: &str) -> bool {
    if let Some(cached) = state.cached_device_user(device_id) {
        return cached == user_id;
    }
    let st = state.clone();
    let dev = device_id.to_string();
    let fetched = tokio::task::spawn_blocking(move || st.db.device_user(&dev).ok().flatten())
        .await
        .ok()
        .flatten();
    if let Some(uid) = fetched {
        state.cache_device_user(device_id, &uid);
        uid == user_id
    } else {
        false
    }
}

const SIGNAL_PING_EVERY: std::time::Duration = std::time::Duration::from_secs(30);
const SIGNAL_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);

async fn handle_signal(mut socket: WebSocket, state: Arc<AppState>, me: ActiveDevice) {
    let mut rx = state.subscribe_signals(&me.device_id);
    let mut ping = tokio::time::interval(SIGNAL_PING_EVERY);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping.tick().await;
    let mut last_seen = Instant::now();

    loop {
        let idle_deadline = tokio::time::Instant::from_std(last_seen + SIGNAL_IDLE_TIMEOUT);
        tokio::select! {
            msg = socket.recv() => match msg {
                Some(Ok(Message::Text(text))) => {
                    last_seen = Instant::now();
                    let Ok(mut env) = serde_json::from_str::<SignalEnvelope>(&text) else { continue };
                    env.from = me.device_id.clone();
                    if device_belongs_to_user(&state, &env.to, &me.user_id).await {
                        state.route_signal(env);
                    }
                }
                Some(Ok(Message::Pong(_))) => {
                    last_seen = Instant::now();
                }
                Some(Ok(Message::Ping(payload))) => {
                    last_seen = Instant::now();
                    if socket.send(Message::Pong(payload)).await.is_err() {
                        break;
                    }
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => {
                    last_seen = Instant::now();
                }
            },
            env = rx.recv() => match env {
                Ok(env) => {
                    let Ok(text) = serde_json::to_string(&env) else { continue };
                    if socket.send(Message::Text(text.into())).await.is_err() {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            },
            _ = ping.tick() => {
                if socket.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break;
                }
            }
            _ = tokio::time::sleep_until(idle_deadline) => {
                break;
            }
        }
    }
    drop(rx);
    state.unsubscribe_signal_if_idle(&me.device_id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::{Limits, RelayHandle};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use ed25519_dalek::{Signer, SigningKey};
    use topaz_proto::auth::derive_id;
    use tower::ServiceExt;

    fn test_app(tag: &str) -> (Router, Arc<AppState>, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "topaz-api-{tag}-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let db = crate::db::Db::open(&path).unwrap();
        let state = Arc::new(AppState::new(db, None, 7723, None, 7722));
        let relay = RelayHandle::new(
            state.clone(),
            Limits {
                bytes_per_sec: 1_000_000,
                sessions: 8,
            },
        );
        (router(state.clone(), relay), state, path)
    }

    fn mk_cert(root: &SigningKey, dev: &SigningKey, issuer: &SigningKey, name: &str) -> DeviceCert {
        let mut c = DeviceCert {
            user_id: derive_id(root.verifying_key().as_bytes()),
            user_pubkey: hex::encode(root.verifying_key().as_bytes()),
            device_id: derive_id(dev.verifying_key().as_bytes()),
            device_pubkey: hex::encode(dev.verifying_key().as_bytes()),
            name: name.into(),
            issued_at: now_unix(),
            issuer_pubkey: hex::encode(issuer.verifying_key().as_bytes()),
            sig: String::new(),
        };
        c.sig = hex::encode(issuer.sign(&c.signing_bytes()).to_bytes());
        c
    }

    #[tokio::test]
    async fn relay_ws_route_exists() {
        let (app, _state, path) = test_app("relay");
        let mut req = Request::builder()
            .uri("/v1/relay")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo("127.0.0.1:1".parse::<SocketAddr>().unwrap()));
        let res = app.oneshot(req).await.unwrap();
        assert_ne!(
            res.status(),
            StatusCode::NOT_FOUND,
            "GET /v1/relay should be registered"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn version_endpoint_and_healthz_header() {
        let (app, state, path) = test_app("ver");
        state.set_relay_quic(None, 7724);
        state.set_stun(None, 3478);
        let res = app
            .clone()
            .oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers().get(HDR_VERSION).and_then(|v| v.to_str().ok()),
            Some(VERSION_LONG)
        );

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/version")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(res.into_body(), 4096).await.unwrap();
        let ver: ServerVersion = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(ver, ServerVersion::current());

        let res = app
            .oneshot(
                Request::builder()
                    .uri("/v1/info")
                    .header("host", "coord.example.com:7722")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(res.into_body(), 4096).await.unwrap();
        let info: ServerInfo = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(info.version, ServerVersion::current());
        assert!(info.server_time_unix.abs_diff(now_unix()) <= 5);
        assert_eq!(info.relay, "tcp://coord.example.com:7723");
        assert_eq!(info.relay_ws, "wss://coord.example.com:7722/v1/relay");
        assert_eq!(info.relay_quic, "coord.example.com:7724");
        assert_eq!(info.stun, "coord.example.com:3478");
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn revoke_enforces_1a_ancestor_policy_and_per_device_nonces() {
        let (app, state, path) = test_app("1a");
        let root = SigningKey::from_bytes(&[1u8; 32]);
        let a = SigningKey::from_bytes(&[2u8; 32]);
        let b = SigningKey::from_bytes(&[3u8; 32]);
        let ca = mk_cert(&root, &a, &root, "a");
        let cb = mk_cert(&root, &b, &root, "b");
        let invite = state.db.create_invites(1, now_unix()).unwrap().pop().unwrap();
        state.db.create_account(&invite, &ca, now_unix()).unwrap();
        state.db.insert_device(&cb).unwrap();

        // Sibling A trying to revoke B must be rejected (403).
        let mut bad_rev = Revocation {
            user_id: ca.user_id.clone(),
            device_id: cb.device_id.clone(),
            issued_at: now_unix(),
            issuer_pubkey: ca.device_pubkey.clone(),
            sig: String::new(),
        };
        bad_rev.sig = hex::encode(a.sign(&bad_rev.signing_bytes()).to_bytes());
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/revocations")
                    .body(Body::from(serde_json::to_vec(&bad_rev).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // Root revoking B succeeds (204).
        let mut root_rev = Revocation {
            user_id: ca.user_id.clone(),
            device_id: cb.device_id.clone(),
            issued_at: now_unix(),
            issuer_pubkey: hex::encode(root.verifying_key().as_bytes()),
            sig: String::new(),
        };
        root_rev.sig = hex::encode(root.sign(&root_rev.signing_bytes()).to_bytes());
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/revocations")
                    .body(Body::from(serde_json::to_vec(&root_rev).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        // Per-device nonce isolation: exhausting dev-1 does not block dev-2.
        let now = now_unix();
        for i in 0..1024u32 {
            assert!(state.fresh("dev-1", now, &format!("nonce-dev1-{i:08}")));
        }
        assert!(!state.fresh("dev-1", now, "nonce-dev1-overflow-0001"));
        assert!(state.fresh("dev-2", now, "nonce-dev2-healthy-00001"));

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn enroll_finish_requires_matching_token() {
        let (app, state, path) = test_app("enroll-tok");
        state.mailboxes.lock().unwrap().insert(
            "ABC".into(),
            Mailbox {
                user_id: "u1".into(),
                owner: "d1".into(),
                created: Instant::now(),
                msg_a: "aa".into(),
                reply: None,
                finish_token: Some("0123456789abcdef0123456789abcdef".into()),
                finish: Some("deadbeef".into()),
            },
        );

        // Wrong token returns 403 and MUST NOT delete the mailbox.
        let mut bad = Request::builder()
            .uri("/v1/enroll/ABC/finish")
            .header(HDR_ENROLL_TOKEN, "wrong-token-12345678")
            .body(Body::empty())
            .unwrap();
        bad.extensions_mut()
            .insert(ConnectInfo("127.0.0.1:1".parse::<SocketAddr>().unwrap()));
        let res = app.clone().oneshot(bad).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        assert!(state.mailboxes.lock().unwrap().contains_key("ABC"));

        // Correct token returns 200 and consumes the mailbox.
        let mut ok = Request::builder()
            .uri("/v1/enroll/ABC/finish")
            .header(HDR_ENROLL_TOKEN, "0123456789abcdef0123456789abcdef")
            .body(Body::empty())
            .unwrap();
        ok.extensions_mut()
            .insert(ConnectInfo("127.0.0.1:1".parse::<SocketAddr>().unwrap()));
        let res = app.oneshot(ok).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(!state.mailboxes.lock().unwrap().contains_key("ABC"));

        let _ = std::fs::remove_file(&path);
    }
}
