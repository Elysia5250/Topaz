use crate::db::{normalize_invite, CreateAccountError};
use crate::state::{now_unix, ActiveDevice, AppState, Mailbox, Online, ONLINE_TTL_SECS};
use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rand::Rng;
use serde::de::DeserializeOwned;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use topaz_proto::auth::{
    request_signing_bytes, verify, HDR_DEVICE, HDR_NONCE, HDR_SIG, HDR_TIME,
};
use topaz_proto::{
    CreateAccountRequest, DeviceCert, DeviceEntry, EnrollFinish, EnrollReply, EnrollStart,
    EnrollStarted, PeerEndpoints, RegisterRequest, RegisterResponse, Revocation, SignalEnvelope,
};
use tracing::{info, warn};

type ApiResult<T> = Result<T, (StatusCode, String)>;
type Shared = State<Arc<AppState>>;

const NAMEPLATE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";

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

/// Verify a request signed by an active device.
fn authenticate(
    state: &AppState,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> ApiResult<ActiveDevice> {
    let device_id = header(headers, HDR_DEVICE)?;
    let time: u64 = header(headers, HDR_TIME)?
        .parse()
        .map_err(|_| err(StatusCode::UNAUTHORIZED, "bad timestamp"))?;
    let nonce = header(headers, HDR_NONCE)?;
    let sig = header(headers, HDR_SIG)?;
    let device = state
        .active_device(device_id)
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "unknown or revoked device"))?;
    let msg = request_signing_bytes(method.as_str(), uri.path(), time, nonce, body);
    if !verify(&device.pubkey, &msg, sig) {
        return Err(err(StatusCode::UNAUTHORIZED, "bad signature"));
    }
    if !state.fresh(time, nonce) {
        return Err(err(StatusCode::UNAUTHORIZED, "stale or replayed request"));
    }
    Ok(device)
}

fn routes(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
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

async fn create_account(State(state): Shared, body: Bytes) -> ApiResult<StatusCode> {
    let req: CreateAccountRequest = parse(&body)?;
    let cert = &req.cert;
    if !cert.self_consistent() || cert.issuer_pubkey != cert.user_pubkey {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "first device must be issued by the account root key",
        ));
    }
    match state
        .db
        .create_account(&normalize_invite(&req.invite), cert, now_unix())
    {
        Ok(()) => {
            info!(user = %cert.user_id, device = %cert.device_id, "account created");
            Ok(StatusCode::NO_CONTENT)
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
}

async fn add_device(State(state): Shared, body: Bytes) -> ApiResult<StatusCode> {
    let cert: DeviceCert = parse(&body)?;
    if !cert.self_consistent() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "certificate signature is not valid",
        ));
    }
    let (user_pubkey, entries, set) = state
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
            Ok(StatusCode::NO_CONTENT)
        } else {
            Err(err(StatusCode::CONFLICT, "device already exists"))
        };
    }
    if state
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
    state.db.insert_device(&cert).map_err(internal)?;
    info!(user = %cert.user_id, device = %cert.device_id, name = %cert.name, "device added");
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke(State(state): Shared, body: Bytes) -> ApiResult<StatusCode> {
    let rev: Revocation = parse(&body)?;
    let (user_pubkey, entries, set) = state
        .account(&rev.user_id)
        .ok_or_else(|| err(StatusCode::FORBIDDEN, "unknown account"))?;
    if !entries.iter().any(|e| e.cert.device_id == rev.device_id) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "device is not in this account",
        ));
    }
    if !set
        .authority_keys(&user_pubkey)
        .contains(&rev.issuer_pubkey)
        || !verify(&rev.issuer_pubkey, &rev.signing_bytes(), &rev.sig)
    {
        return Err(err(
            StatusCode::FORBIDDEN,
            "revocation is not signed by this account",
        ));
    }
    state.db.set_revocation(&rev).map_err(internal)?;
    state.drop_device(&rev.device_id);
    info!(user = %rev.user_id, device = %rev.device_id, "device revoked");
    Ok(StatusCode::NO_CONTENT)
}

async fn list_devices(
    State(state): Shared,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Vec<DeviceEntry>>> {
    let me = authenticate(&state, &method, &uri, &headers, &body)?;
    Ok(Json(state.db.entries(&me.user_id).map_err(internal)?))
}

async fn register(
    State(state): Shared,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<RegisterResponse>> {
    let me = authenticate(&state, &method, &uri, &headers, &body)?;
    let req: RegisterRequest = parse(&body)?;
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
    let me = authenticate(&state, &method, &uri, &headers, &body)?;
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
    let me = authenticate(&state, &method, &uri, &headers, &body)?;
    let start: EnrollStart = parse(&body)?;
    state.purge_mailboxes();
    let mut boxes = state.mailboxes.lock().unwrap();
    let mut rng = rand::rngs::OsRng;
    let nameplate = loop {
        let np: String = (0..3)
            .map(|_| NAMEPLATE_ALPHABET[rng.gen_range(0..NAMEPLATE_ALPHABET.len())] as char)
            .collect();
        if !boxes.contains_key(&np) {
            break np;
        }
    };
    boxes.insert(
        nameplate.clone(),
        Mailbox {
            user_id: me.user_id,
            owner: me.device_id,
            created: Instant::now(),
            msg_a: start.msg_a,
            reply: None,
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
    Path(nameplate): Path<String>,
) -> ApiResult<Json<EnrollStart>> {
    state.purge_mailboxes();
    let boxes = state.mailboxes.lock().unwrap();
    let mb = boxes.get(&nameplate).ok_or_else(not_found)?;
    Ok(Json(EnrollStart {
        msg_a: mb.msg_a.clone(),
    }))
}

async fn enroll_reply(
    State(state): Shared,
    Path(nameplate): Path<String>,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let reply: EnrollReply = parse(&body)?;
    state.purge_mailboxes();
    let mut boxes = state.mailboxes.lock().unwrap();
    let mb = boxes.get_mut(&nameplate).ok_or_else(not_found)?;
    if mb.reply.is_some() {
        return Err(err(StatusCode::CONFLICT, "code was already used"));
    }
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
    let me = authenticate(&state, &method, &uri, &headers, &body)?;
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
    let me = authenticate(&state, &method, &uri, &headers, &body)?;
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
    Path(nameplate): Path<String>,
) -> ApiResult<Json<EnrollFinish>> {
    let mut boxes = state.mailboxes.lock().unwrap();
    let payload = boxes
        .get(&nameplate)
        .and_then(|m| m.finish.clone())
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
    match authenticate(&state, &method, &uri, &headers, &[]) {
        Ok(me) => ws.on_upgrade(move |socket| handle_signal(socket, state, me)),
        Err(e) => e.into_response(),
    }
}

async fn handle_signal(mut socket: WebSocket, state: Arc<AppState>, me: ActiveDevice) {
    let mut rx = state.subscribe_signals(&me.device_id);
    loop {
        tokio::select! {
            msg = socket.recv() => match msg {
                Some(Ok(Message::Text(text))) => {
                    let Ok(mut env) = serde_json::from_str::<SignalEnvelope>(&text) else { continue };
                    env.from = me.device_id.clone();
                    let same_account = state
                        .db
                        .device_user(&env.to)
                        .ok()
                        .flatten()
                        .is_some_and(|u| u == me.user_id);
                    if same_account {
                        state.route_signal(env);
                    }
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => {}
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::{Limits, RelayHandle};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn relay_ws_route_exists() {
        let path = std::env::temp_dir().join(format!(
            "ss-api-{}-{}.db",
            std::process::id(),
            now_unix()
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
        let app = router(state, relay);
        let mut req = Request::builder()
            .uri("/v1/relay")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo("127.0.0.1:1".parse::<std::net::SocketAddr>().unwrap()));
        let res = app.oneshot(req).await.unwrap();
        assert_ne!(
            res.status(),
            StatusCode::NOT_FOUND,
            "GET /v1/relay should be registered"
        );
    }
}
