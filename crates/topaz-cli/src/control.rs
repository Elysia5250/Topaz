//! Local control plane for the pure network engine: HTTP/JSON over a Unix
//! domain socket in the data-dir (`control.sock`).

use anyhow::{bail, Context, Result};
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use topaz_core::Store;
use topaz_fabric::{EngineHandle, EngineStatus, SharedStatus};
use topaz_net::CoordClient;
use topaz_vpn::{SharedVpnStatus, VpnStatus};
use serde_json::json;
use std::collections::HashMap;
use std::path::Path as FilePath;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::bridge::{
    json_error, ws_events, ws_service_accept, ws_service_open, ServiceRegistry, ServiceSummary,
};
use crate::ops;

type PendingAdds = Mutex<HashMap<String, tokio::sync::oneshot::Receiver<Result<(String, String)>>>>;

pub struct ControlState {
    pub store: Arc<Mutex<Store>>,
    pub engine: EngineHandle,
    pub status: Arc<SharedStatus>,
    pub vpn: SharedVpnStatus,
    pub services: Arc<ServiceRegistry>,
    pub coord: CoordClient,
    pub account_user_id: String,
    pub control_lock: tokio::sync::Mutex<()>,
    pub pending_adds: PendingAdds,
    pub started: Instant,
}

impl ControlState {
    fn ctx(&self) -> Result<ops::OpCtx> {
        let s = self.store.lock().unwrap();
        Ok(ops::OpCtx {
            coord: self.coord.clone(),
            account: s.require_account()?.clone(),
            me: s.identity.device_id.clone(),
        })
    }
}

pub async fn bind_socket(path: &FilePath) -> Result<tokio::net::UnixListener> {
    if tokio::net::UnixStream::connect(path).await.is_ok() {
        bail!("another topaz run owns this data-dir (its control socket answered)");
    }
    let _ = std::fs::remove_file(path);
    let listener = tokio::net::UnixListener::bind(path)
        .with_context(|| format!("bind control socket {}", path.display()))?;
    configure_socket_permissions(path);
    Ok(listener)
}

#[cfg(unix)]
fn configure_socket_permissions(path: &FilePath) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660));
    if let (Ok(uid_s), Ok(gid_s)) = (std::env::var("SUDO_UID"), std::env::var("SUDO_GID")) {
        if let (Ok(uid), Ok(gid)) = (uid_s.parse::<libc::uid_t>(), gid_s.parse::<libc::gid_t>()) {
            if let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) {
                unsafe {
                    libc::chown(c_path.as_ptr(), uid, gid);
                }
            }
        }
    }
}

#[cfg(not(unix))]
fn configure_socket_permissions(_path: &FilePath) {}

pub fn remove_socket(path: &FilePath) {
    let _ = std::fs::remove_file(path);
}

pub async fn serve(listener: tokio::net::UnixListener, state: Arc<ControlState>) -> Result<()> {
    axum::serve(listener, router(state)).await?;
    Ok(())
}

fn router(state: Arc<ControlState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/status", get(get_status))
        .route("/v1/events", get(ws_events))
        .route("/v1/services/{id}/open/{target}", get(ws_service_open))
        .route("/v1/services/{id}/accept", get(ws_service_accept))
        .route("/v1/kick", post(post_kick))
        .route("/v1/devices", get(list_devices))
        .route("/v1/devices/add", post(start_device_add))
        .route("/v1/devices/add/{code}", get(poll_device_add))
        .route("/v1/devices/{id}/revoke", post(revoke_device))
        .with_state(state)
}

struct ApiError(axum::http::StatusCode, String);

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        json_error(self.0, "bad_request", self.1)
    }
}

fn api_err(e: anyhow::Error) -> ApiError {
    ApiError(axum::http::StatusCode::BAD_REQUEST, e.to_string())
}

async fn healthz(State(st): State<Arc<ControlState>>) -> Json<serde_json::Value> {
    Json(json!({
        "ok": true,
        "uptime_s": st.started.elapsed().as_secs(),
    }))
}

async fn get_status(State(st): State<Arc<ControlState>>) -> Json<serde_json::Value> {
    let engine = st.status.engine();
    let vpn = st.vpn.get();
    let services = st.services.summaries();
    let value = {
        let store = st.store.lock().unwrap();
        render_status(&store, &engine, &vpn, &st.account_user_id, &services)
    };
    Json(value)
}

#[derive(serde::Deserialize)]
struct KickQuery {
    announce: Option<bool>,
}

async fn post_kick(
    State(st): State<Arc<ControlState>>,
    Query(q): Query<KickQuery>,
) -> Json<serde_json::Value> {
    let announce = q.announce.unwrap_or(true);
    st.engine.kick(announce);
    Json(json!({ "kicked": true, "announce": announce }))
}

async fn list_devices(
    State(st): State<Arc<ControlState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let ctx = st.ctx().map_err(api_err)?;
    let devices = ctx.coord.list_devices().await.map_err(api_err)?;
    let rows = ops::device_rows(&ctx, &devices);
    Ok(Json(json!({ "account": ctx.account.user_id, "devices": rows })))
}

async fn start_device_add(
    State(st): State<Arc<ControlState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (coord, identity, account) = {
        let s = st.store.lock().unwrap();
        (
            st.coord.clone(),
            s.identity.clone(),
            s.require_account().map_err(api_err)?.clone(),
        )
    };
    let (code_tx, code_rx) = tokio::sync::oneshot::channel::<String>();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<Result<(String, String)>>();
    tokio::spawn(async move {
        let res = topaz_net::approve_new_device(&coord, &identity, &account, |code| {
            let _ = code_tx.send(code.to_string());
        })
        .await;
        let _ = done_tx.send(res.map(|c| (c.name.clone(), c.device_id.clone())));
    });
    let code = tokio::time::timeout(Duration::from_secs(15), code_rx)
        .await
        .map_err(|_| api_err(anyhow::anyhow!("device add timed out before a code arrived")))?
        .map_err(|_| api_err(anyhow::anyhow!("device add task died")))?;
    st.pending_adds
        .lock()
        .unwrap()
        .insert(code.clone(), done_rx);
    let setup = {
        let s = st.store.lock().unwrap();
        crate::setup_bundle(&s, &code)
    };
    Ok(Json(json!({ "code": code, "setup": setup })))
}

async fn poll_device_add(
    State(st): State<Arc<ControlState>>,
    Path(code): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let rx = st.pending_adds.lock().unwrap().remove(&code);
    match rx {
        None => Err(api_err(anyhow::anyhow!(
            "no pending device add for {code} (already fetched, or never started here)"
        ))),
        Some(rx) => match rx.await {
            Ok(Ok((name, device_id))) => Ok(Json(json!({
                "added": true, "name": name, "device_id": device_id,
            }))),
            Ok(Err(e)) => Err(api_err(e)),
            Err(_) => Err(api_err(anyhow::anyhow!(
                "device add task died before completion"
            ))),
        },
    }
}

async fn revoke_device(
    State(st): State<Arc<ControlState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _guard = st.control_lock.lock().await;
    let ctx = st.ctx().map_err(api_err)?;
    let rev = {
        let s = st.store.lock().unwrap();
        ops::device_revoke_local(&s, &id)
    }
    .map_err(api_err)?;
    ops::publish_revocation(&ctx, &rev).await.map_err(api_err)?;
    Ok(Json(json!({ "revoked": id })))
}

pub fn render_status(
    store: &Store,
    engine: &EngineStatus,
    vpn: &VpnStatus,
    account_user_id: &str,
    services: &[ServiceSummary],
) -> serde_json::Value {
    let me = store.identity.device_id.clone();
    let connection = engine
        .sessions
        .first()
        .map(|(_, k)| format!("{k:?}").to_lowercase());
    json!({
        "account": account_user_id,
        "device_id": me,
        "device_name": store.device_name(),
        "dns_name": engine.self_addr.dns_name,
        "virtual_ip": engine.self_addr.virtual_ip,
        "tun": vpn,
        "connection": connection,
        "peers": engine.peers.iter().map(|p| {
            let addr = engine.peer_addr(&p.device_id);
            let path = engine.sessions.iter()
                .find(|(id, _)| *id == p.device_id)
                .map(|(_, k)| format!("{k:?}").to_lowercase());
            let rtt_ms = engine.rtts.iter()
                .find(|(id, _)| *id == p.device_id)
                .map(|(_, rtt)| rtt.as_millis() as u64);
            let peer_services = engine.peer_services(&p.device_id);
            json!({
                "device_id": p.device_id,
                "name": p.name,
                "dns_name": addr.and_then(|a| a.dns_name.as_deref()),
                "virtual_ip": addr.and_then(|a| a.virtual_ip.as_deref()),
                "path": path,
                "rtt_ms": rtt_ms,
                "services": peer_services,
            })
        }).collect::<Vec<_>>(),
        "services": services,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use topaz_core::{generate_recovery_code, issue_cert, AccountInfo, AccountKey, Store};
    use topaz_fabric::{EngineDeps, PingService, Service};
    use topaz_net::{new_trust_store, CoordClient, QuicEndpoint, RelayAddrs};
    use topaz_proto::auth::{format_pin, pin_bytes, HDR_DEVICE};
    use topaz_proto::{
        DeviceEntry, PeerEndpoints, RegisterRequest, RegisterResponse, SignalEnvelope,
    };
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use ed25519_dalek::SigningKey;
    use futures::{SinkExt, StreamExt};
    use http_body_util::{BodyExt, Full};
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper::{Method, Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use rcgen::{CertificateParams, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::path::Path;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use tokio_tungstenite::tungstenite::{self, Message as WsMessage};

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let p = Path::new("/tmp").join(format!(
            "eng-ctrl-{tag}-{}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[tokio::test]
    async fn socket_is_a_single_instance_lock() {
        let root = tmp_root("lock");
        let path = root.join("control.sock");

        let first = bind_socket(&path).await.unwrap();
        assert!(bind_socket(&path)
            .await
            .unwrap_err()
            .to_string()
            .contains("another topaz run"));
        drop(first);

        let second = bind_socket(&path).await.unwrap();
        drop(second);
        remove_socket(&path);
        let _ = std::fs::remove_dir_all(&root);
    }

    fn test_state(data: &FilePath) -> Arc<ControlState> {
        let store = Arc::new(Mutex::new(Store::open(data.to_path_buf()).unwrap()));
        let identity = store.lock().unwrap().identity.clone();
        let recovery = generate_recovery_code();
        let root_key = AccountKey::from_recovery(&recovery).unwrap();
        let cert = issue_cert(
            &root_key.signing,
            &root_key.user_id,
            &root_key.user_pubkey,
            &identity.pubkey_hex,
            "test",
        )
        .unwrap();
        let account = AccountInfo::from_cert(&identity, cert).unwrap();
        let pin = format_pin(&[7u8; 20]);
        {
            let mut s = store.lock().unwrap();
            s.save_account(account.clone()).unwrap();
            s.config.coord_url = "https://127.0.0.1:1".into();
            s.config.coord_pin = pin.clone();
        }
        let coord = CoordClient::new("https://127.0.0.1:1", &pin).unwrap();
        let trust = new_trust_store();
        let (quic, _mapped) = QuicEndpoint::bind(&identity, &trust, None).unwrap();
        let (signal_tx, signal_rx) = tokio::sync::mpsc::channel::<SignalEnvelope>(64);
        let status = Arc::new(SharedStatus::new());
        let (engine, _fut) = topaz_fabric::build(
            EngineDeps {
                identity,
                account_user_pubkey: account.user_pubkey.clone(),
                coord: coord.clone(),
                trust,
                quic,
                endpoints: Vec::new(),
                relay: RelayAddrs {
                    tcp: "127.0.0.1:1".into(),
                    ws: "wss://127.0.0.1:1".into(),
                    coord_tls: coord.tls_config(),
                },
                signal_tx,
                signal_rx,
                force_relay: true,
                enable_mdns: false,
            },
            |_handle| {
                let ping = Arc::new(PingService::new(status.clone()));
                vec![ping as Arc<dyn Service>]
            },
            status.clone(),
        );
        Arc::new(ControlState {
            store,
            engine,
            status,
            vpn: SharedVpnStatus::default(),
            services: Arc::new(ServiceRegistry::default()),
            coord,
            account_user_id: account.user_id,
            control_lock: tokio::sync::Mutex::new(()),
            pending_adds: Mutex::new(HashMap::new()),
            started: Instant::now(),
        })
    }

    #[tokio::test]
    async fn serves_healthz_status_kick_over_unix_socket() {
        let root = tmp_root("serve");
        let st = test_state(&root.join("data"));
        let path = root.join("control.sock");
        let listener = bind_socket(&path).await.unwrap();
        tokio::spawn(serve(listener, st.clone()));

        let mut conn = tokio::net::UnixStream::connect(&path).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        conn.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = String::new();
        conn.read_to_string(&mut buf).await.unwrap();
        assert!(buf.starts_with("HTTP/1.1 200"), "healthz: {buf}");
        assert!(buf.contains("\"ok\":true"), "healthz: {buf}");

        let mut conn = tokio::net::UnixStream::connect(&path).await.unwrap();
        conn.write_all(b"GET /v1/status HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = String::new();
        conn.read_to_string(&mut buf).await.unwrap();
        assert!(buf.starts_with("HTTP/1.1 200"), "status: {buf}");
        assert!(buf.contains("\"device_id\""), "status: {buf}");
        assert!(buf.contains("\"tun\""), "status: {buf}");
        assert!(buf.contains("\"services\":[]"), "status: {buf}");
        assert!(buf.contains("\"connection\":null"), "status: {buf}");

        let mut conn = tokio::net::UnixStream::connect(&path).await.unwrap();
        conn.write_all(
            b"POST /v1/kick?announce=false HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        )
        .await
        .unwrap();
        let mut buf = String::new();
        conn.read_to_string(&mut buf).await.unwrap();
        assert!(buf.starts_with("HTTP/1.1 200"), "kick: {buf}");
        assert!(buf.contains("\"announce\":false"), "kick: {buf}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn render_status_shapes_the_document() {
        let root = tmp_root("render");
        let store = Store::open(root.join("data")).unwrap();
        let engine = EngineStatus {
            self_addr: topaz_fabric::VirtualAddr {
                virtual_ip: Some("100.64.0.1".into()),
                dns_name: Some("workstation".into()),
            },
            ..Default::default()
        };
        let vpn = VpnStatus {
            enabled: true,
            interface: Some("topaz0".into()),
            cidr: "100.64.0.0/10".into(),
            mtu: 1280,
            dns_listen: Some("100.64.0.1:53".into()),
            error: None,
        };
        let services = vec![ServiceSummary {
            service_id: 16,
            name: "jade".into(),
            online: true,
            listeners: 2,
        }];
        let doc = render_status(&store, &engine, &vpn, "user-1", &services);
        assert_eq!(doc["device_id"], store.identity.device_id);
        assert_eq!(doc["account"], "user-1");
        assert_eq!(doc["virtual_ip"], "100.64.0.1");
        assert_eq!(doc["dns_name"], "workstation");
        assert_eq!(doc["tun"]["enabled"], true);
        assert_eq!(doc["tun"]["interface"], "topaz0");
        assert_eq!(doc["connection"], serde_json::Value::Null);
        assert_eq!(doc["services"][0]["service_id"], 16);
        assert_eq!(doc["services"][0]["listeners"], 2);
        assert!(doc.get("folders").is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    async fn ws_connect_unix(
        path: &FilePath,
        uri: &str,
    ) -> std::result::Result<
        (
            tokio_tungstenite::WebSocketStream<tokio::net::UnixStream>,
            tungstenite::handshake::client::Response,
        ),
        Box<tungstenite::Error>,
    > {
        let stream = tokio::net::UnixStream::connect(path).await.unwrap();
        tokio_tungstenite::client_async(uri, stream)
            .await
            .map_err(Box::new)
    }

    fn assert_tungstenite_json_error(
        err: tungstenite::Error,
        expected_status: u16,
    ) -> serde_json::Value {
        match err {
            tungstenite::Error::Http(resp) => {
                assert_eq!(resp.status().as_u16(), expected_status);
                assert!(
                    resp.headers().get("content-length").is_some(),
                    "error response must include explicit Content-Length header"
                );
                assert_eq!(
                    resp.headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok()),
                    Some("application/json")
                );
                let body = resp.body().as_ref().expect("tungstenite must receive JSON error body");
                serde_json::from_slice(body).unwrap()
            }
            other => panic!("expected Http error {expected_status}, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn events_push_and_ws_errors_include_content_length() {
        let root = tmp_root("events-err");
        let st = test_state(&root.join("data"));
        let path = root.join("control.sock");
        let listener = bind_socket(&path).await.unwrap();
        tokio::spawn(serve(listener, st.clone()));

        // 1. Subscribe to /v1/events and verify initial snapshot.
        let (mut events_ws, _) = ws_connect_unix(&path, "ws://localhost/v1/events")
            .await
            .unwrap();
        let first = match events_ws.next().await.unwrap().unwrap() {
            WsMessage::Text(t) => serde_json::from_str::<serde_json::Value>(&t).unwrap(),
            other => panic!("expected text frame, got {other:?}"),
        };
        assert_eq!(first["type"], "status");
        assert_eq!(first["status"]["services"], json!([]));

        // 2. Register an accept listener on service 16 -> /v1/events pushes listeners=1.
        let (accept_ws1, _) =
            ws_connect_unix(&path, "ws://localhost/v1/services/16/accept?name=jade")
                .await
                .unwrap();
        let ev1 = tokio::time::timeout(Duration::from_secs(2), events_ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let ev1_json: serde_json::Value =
            serde_json::from_str(ev1.to_text().unwrap()).unwrap();
        assert_eq!(ev1_json["status"]["services"][0]["service_id"], 16);
        assert_eq!(ev1_json["status"]["services"][0]["name"], "jade");
        assert_eq!(ev1_json["status"]["services"][0]["online"], true);
        assert_eq!(ev1_json["status"]["services"][0]["listeners"], 1);

        // 3. Second listener -> listeners=2; close both -> listeners=0, online=false.
        let (accept_ws2, _) =
            ws_connect_unix(&path, "ws://localhost/v1/services/16/accept?name=jade")
                .await
                .unwrap();
        let ev2 = tokio::time::timeout(Duration::from_secs(2), events_ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let ev2_json: serde_json::Value =
            serde_json::from_str(ev2.to_text().unwrap()).unwrap();
        assert_eq!(ev2_json["status"]["services"][0]["listeners"], 2);

        drop(accept_ws1);
        drop(accept_ws2);
        let offline = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let msg = events_ws.next().await.unwrap().unwrap();
                let v: serde_json::Value =
                    serde_json::from_str(msg.to_text().unwrap()).unwrap();
                if v["status"]["services"][0]["listeners"] == 0 {
                    return v;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(offline["status"]["services"][0]["online"], false);

        // 4. Verify non-101 WS error responses carry Content-Length + JSON {"error": ...}.
        let err_400 = ws_connect_unix(&path, "ws://localhost/v1/services/0/open/laptop")
            .await
            .unwrap_err();
        let body = assert_tungstenite_json_error(*err_400, 400);
        assert!(
            body["error"].as_str().unwrap().contains("invalid service_id"),
            "{body}"
        );
        assert_eq!(body["code"], "invalid_service");

        let err_404 = ws_connect_unix(&path, "ws://localhost/v1/services/16/open/nonexistent")
            .await
            .unwrap_err();
        let body = assert_tungstenite_json_error(*err_404, 404);
        assert!(
            body["error"].as_str().unwrap().contains("device not found"),
            "{body}"
        );
        assert_eq!(body["code"], "device_not_found");

        let _ = std::fs::remove_dir_all(&root);
    }

    struct MockCoord {
        url: String,
        pin: String,
        endpoints: Arc<Mutex<HashMap<String, Vec<String>>>>,
    }

    impl MockCoord {
        async fn start(entries: Vec<DeviceEntry>) -> Self {
            let signing = SigningKey::from_bytes(&[9u8; 32]);
            let pin = format_pin(&pin_bytes(signing.verifying_key().as_bytes()));
            let key_der = signing.to_pkcs8_der().unwrap().as_bytes().to_vec();
            let kp = KeyPair::try_from(key_der.as_slice()).unwrap();
            let cert = CertificateParams::new(vec!["topaz-coord".into()])
                .unwrap()
                .self_signed(&kp)
                .unwrap();
            let mut tls_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
            )
            .unwrap();
            tls_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
            let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let entries = Arc::new(Mutex::new(entries));
            let endpoints: Arc<Mutex<HashMap<String, Vec<String>>>> =
                Arc::new(Mutex::new(HashMap::new()));

            let entries_s = entries.clone();
            let endpoints_s = endpoints.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((tcp, _)) = listener.accept().await else {
                        break;
                    };
                    let acceptor = acceptor.clone();
                    let entries = entries_s.clone();
                    let endpoints = endpoints_s.clone();
                    tokio::spawn(async move {
                        let Ok(tls) = acceptor.accept(tcp).await else {
                            return;
                        };
                        let svc = service_fn(move |req: Request<Incoming>| {
                            let entries = entries.clone();
                            let endpoints = endpoints.clone();
                            async move {
                                let method = req.method().clone();
                                let path = req.uri().path().to_string();
                                let caller = req
                                    .headers()
                                    .get(HDR_DEVICE)
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or_default()
                                    .to_string();
                                let body = req
                                    .into_body()
                                    .collect()
                                    .await
                                    .map(|c| c.to_bytes())
                                    .unwrap_or_default();

                                if method == Method::GET && path == "/v1/devices" {
                                    let json =
                                        serde_json::to_vec(&*entries.lock().unwrap()).unwrap();
                                    return Ok::<_, hyper::Error>(Response::new(Full::new(
                                        Bytes::from(json),
                                    )));
                                }
                                if method == Method::POST && path == "/v1/register" {
                                    if let Ok(reg) = serde_json::from_slice::<RegisterRequest>(&body)
                                    {
                                        endpoints.lock().unwrap().insert(caller, reg.endpoints);
                                    }
                                    let resp = RegisterResponse {
                                        observed_ip: "127.0.0.1".into(),
                                        relay: "tcp://127.0.0.1:1".into(),
                                        relay_ws: "wss://127.0.0.1:1/v1/relay".into(),
                                        stun: String::new(),
                                    };
                                    let json = serde_json::to_vec(&resp).unwrap();
                                    return Ok(Response::new(Full::new(Bytes::from(json))));
                                }
                                if method == Method::GET && path.starts_with("/v1/endpoints/") {
                                    let target = path.trim_start_matches("/v1/endpoints/");
                                    let eps = endpoints.lock().unwrap().get(target).cloned();
                                    if let Some(eps) = eps {
                                        let resp = PeerEndpoints {
                                            device_id: target.to_string(),
                                            endpoints: eps,
                                            last_seen_unix: 0,
                                        };
                                        let json = serde_json::to_vec(&resp).unwrap();
                                        return Ok(Response::new(Full::new(Bytes::from(json))));
                                    }
                                    let mut r = Response::new(Full::new(Bytes::new()));
                                    *r.status_mut() = StatusCode::NOT_FOUND;
                                    return Ok(r);
                                }
                                let mut r = Response::new(Full::new(Bytes::new()));
                                *r.status_mut() = StatusCode::NOT_FOUND;
                                Ok(r)
                            }
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(tls), svc)
                            .await;
                    });
                }
            });

            Self {
                url: format!("https://127.0.0.1:{}", addr.port()),
                pin,
                endpoints,
            }
        }
    }

    #[tokio::test]
    async fn end_to_end_service_bridge_over_real_p2p_mesh() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let root = tmp_root("e2e-bridge");
        let rec = generate_recovery_code();
        let root_key = AccountKey::from_recovery(&rec).unwrap();

        let store_a = Arc::new(Mutex::new(Store::open(root.join("node-a")).unwrap()));
        let store_b = Arc::new(Mutex::new(Store::open(root.join("node-b")).unwrap()));
        let id_a = store_a.lock().unwrap().identity.clone();
        let id_b = store_b.lock().unwrap().identity.clone();

        let cert_a = issue_cert(
            &root_key.signing,
            &root_key.user_id,
            &root_key.user_pubkey,
            &id_a.pubkey_hex,
            "workstation",
        )
        .unwrap();
        let cert_b = issue_cert(
            &root_key.signing,
            &root_key.user_id,
            &root_key.user_pubkey,
            &id_b.pubkey_hex,
            "laptop",
        )
        .unwrap();

        let acct_a = AccountInfo::from_cert(&id_a, cert_a.clone()).unwrap();
        let acct_b = AccountInfo::from_cert(&id_b, cert_b.clone()).unwrap();

        let mut e_a = DeviceEntry::new(cert_a, None);
        e_a.virtual_ip = Some("100.64.0.1".into());
        e_a.dns_name = Some("workstation".into());
        let mut e_b = DeviceEntry::new(cert_b, None);
        e_b.virtual_ip = Some("100.64.0.2".into());
        e_b.dns_name = Some("laptop".into());
        let coord = MockCoord::start(vec![e_a, e_b]).await;

        let (a_in_tx, a_in_rx) = tokio::sync::mpsc::channel(32);
        let (b_in_tx, b_in_rx) = tokio::sync::mpsc::channel(32);
        let (hub_tx, mut hub_rx) = tokio::sync::mpsc::channel::<SignalEnvelope>(64);
        let a_id_str = id_a.device_id.clone();
        let b_id_str = id_b.device_id.clone();
        tokio::spawn(async move {
            while let Some(env) = hub_rx.recv().await {
                if env.to == a_id_str {
                    let _ = a_in_tx.send(env).await;
                } else if env.to == b_id_str {
                    let _ = b_in_tx.send(env).await;
                }
            }
        });

        let spawn_ctrl = |store: Arc<Mutex<Store>>,
                          account: AccountInfo,
                          sig_out: tokio::sync::mpsc::Sender<SignalEnvelope>,
                          sig_in: tokio::sync::mpsc::Receiver<SignalEnvelope>,
                          sock_path: std::path::PathBuf| {
            let identity = store.lock().unwrap().identity.clone();
            {
                let mut s = store.lock().unwrap();
                s.save_account(account.clone()).unwrap();
                s.config.coord_url = coord.url.clone();
                s.config.coord_pin = coord.pin.clone();
            }
            let client = CoordClient::new(&coord.url, &coord.pin)
                .unwrap()
                .with_identity(identity.clone());
            let trust = new_trust_store();
            let (quic, _) = QuicEndpoint::bind(&identity, &trust, None).unwrap();
            let ep = format!("127.0.0.1:{}", quic.local_addr.port());
            coord
                .endpoints
                .lock()
                .unwrap()
                .insert(identity.device_id.clone(), vec![ep.clone()]);
            let relay = RelayAddrs {
                tcp: "127.0.0.1:1".into(),
                ws: "wss://127.0.0.1:1/v1/relay".into(),
                coord_tls: client.tls_config(),
            };
            let status = Arc::new(SharedStatus::new());
            let st_for_svc = status.clone();
            let (engine, fut) = topaz_fabric::build(
                EngineDeps {
                    identity,
                    account_user_pubkey: account.user_pubkey.clone(),
                    coord: client.clone(),
                    trust,
                    quic,
                    endpoints: vec![ep],
                    relay,
                    signal_tx: sig_out,
                    signal_rx: sig_in,
                    force_relay: false,
                    enable_mdns: false,
                },
                move |_| vec![Arc::new(PingService::new(st_for_svc)) as Arc<dyn Service>],
                status.clone(),
            );
            tokio::spawn(async move {
                let _ = fut.await;
            });
            let ctrl = Arc::new(ControlState {
                store,
                engine,
                status,
                vpn: SharedVpnStatus::default(),
                services: Arc::new(ServiceRegistry::default()),
                coord: client,
                account_user_id: account.user_id,
                control_lock: tokio::sync::Mutex::new(()),
                pending_adds: Mutex::new(HashMap::new()),
                started: Instant::now(),
            });
            let ctrl_srv = ctrl.clone();
            tokio::spawn(async move {
                let listener = bind_socket(&sock_path).await.unwrap();
                let _ = serve(listener, ctrl_srv).await;
            });
            ctrl
        };

        let sock_a = root.join("a.sock");
        let sock_b = root.join("b.sock");
        let ctrl_a = spawn_ctrl(store_a, acct_a, hub_tx.clone(), a_in_rx, sock_a.clone());
        let ctrl_b = spawn_ctrl(store_b, acct_b, hub_tx, b_in_rx, sock_b.clone());

        // Wait for direct session between A and B.
        tokio::time::timeout(Duration::from_secs(6), async {
            loop {
                if !ctrl_a.status.engine().sessions.is_empty()
                    && !ctrl_b.status.engine().sessions.is_empty()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("mesh session ready");

        // Attach jade-serve accept listener on node B.
        let (mut accept_ws, _) =
            ws_connect_unix(&sock_b, "ws://localhost/v1/services/16/accept?name=jade")
                .await
                .unwrap();

        // Node A discovers that node B has mounted service 16 ("jade").
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let eng = ctrl_a.status.engine();
                if eng.peer_services(&id_b.device_id)
                    == [topaz_fabric::AdvertisedService {
                        service_id: 16,
                        name: "jade".into(),
                    }]
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("node A should discover node B's service 16");

        // Client on node A opens service 16 to "laptop.topaz".
        let (mut open_ws, open_resp) =
            ws_connect_unix(&sock_a, "ws://localhost/v1/services/16/open/laptop.topaz")
                .await
                .unwrap();
        assert_eq!(
            open_resp.headers().get("x-topaz-peer-id").unwrap(),
            id_b.device_id.as_str()
        );
        assert_eq!(
            open_resp.headers().get("x-topaz-peer-name").unwrap(),
            "laptop"
        );
        assert_eq!(
            open_resp.headers().get("x-topaz-peer-ip").unwrap(),
            "100.64.0.2"
        );

        // Node B receives the mTLS-verified accepted metadata frame first.
        let handoff_msg = tokio::time::timeout(Duration::from_secs(2), accept_ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let handoff: serde_json::Value =
            serde_json::from_str(handoff_msg.to_text().unwrap()).unwrap();
        assert_eq!(handoff["event"], "accepted");
        assert_eq!(handoff["service_id"], 16);
        assert_eq!(handoff["peer_device_id"], id_a.device_id);
        assert_eq!(handoff["peer_name"], "workstation");
        assert_eq!(handoff["peer_dns_name"], "workstation");
        assert_eq!(handoff["peer_virtual_ip"], "100.64.0.1");
        assert_eq!(handoff["connection"], "direct");

        // Full-duplex binary frame exchange over the bridged Channel.
        open_ws
            .send(WsMessage::Binary(Bytes::from_static(b"rpc-req")))
            .await
            .unwrap();
        let got_on_b = tokio::time::timeout(Duration::from_secs(2), accept_ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(got_on_b.into_data().as_ref(), b"rpc-req");

        accept_ws
            .send(WsMessage::Binary(Bytes::from_static(b"rpc-resp")))
            .await
            .unwrap();
        let got_on_a = tokio::time::timeout(Duration::from_secs(2), open_ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(got_on_a.into_data().as_ref(), b"rpc-resp");

        // Closing client WS propagates cleanly to accept WS.
        open_ws.close(None).await.unwrap();
        let closed_b = tokio::time::timeout(Duration::from_secs(2), async {
            while let Some(Ok(msg)) = accept_ws.next().await {
                if matches!(msg, WsMessage::Close(_)) {
                    return true;
                }
            }
            true
        })
        .await
        .expect("accept WS must close when opener disconnects");
        assert!(closed_b);

        let _ = std::fs::remove_dir_all(&root);
    }
}
