use crate::tls::{pinned_client_config, pinned_quic_client_config};
use anyhow::{anyhow, bail, Context, Result};
use futures::{SinkExt, StreamExt};
use rand::RngCore;
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use topaz_core::{now_unix, DeviceIdentity};
use topaz_proto::auth::{
    parse_pin, request_signing_bytes, DeviceEntry, Revocation, HDR_DEVICE, HDR_NONCE, HDR_SIG,
    HDR_TIME,
};
use topaz_proto::{
    CreateAccountRequest, DeviceCert, EnrollFinish, EnrollReply, EnrollStart, EnrollStarted,
    PeerEndpoints, RegisterRequest, RegisterResponse, ServerInfo, ServerVersion, SignalEnvelope,
    HDR_ENROLL_TOKEN,
};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::{connect_async_tls_with_config, tungstenite::Message, Connector};
use tracing::{info, warn};

const SIGNAL_PING_EVERY: Duration = Duration::from_secs(30);
const SIGNAL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// Structured error returned by [`CoordClient`] HTTP calls so callers can
/// distinguish permanent device revocation from transient clock skew or
/// transport outages without string-matching `"401"`.
#[derive(Debug, thiserror::Error)]
pub enum CoordError {
    #[error("device revoked or unknown on coord: {0}")]
    DeviceRevoked(String),
    #[error("request rejected due to clock skew or nonce replay: {0}")]
    ClockSkewOrReplay(String),
    #[error("unauthorized coord request: {0}")]
    Unauthorized(String),
    #[error("{method} {path} failed: {status} {body}")]
    Http {
        method: String,
        path: String,
        status: u16,
        body: String,
    },
}

fn classify_http_error(method: &Method, path: &str, status: StatusCode, body: String) -> CoordError {
    if status == StatusCode::UNAUTHORIZED {
        let lower = body.to_ascii_lowercase();
        if lower.contains("unknown or revoked device") {
            return CoordError::DeviceRevoked(body);
        }
        if lower.contains("stale or replayed") || lower.contains("bad timestamp") {
            return CoordError::ClockSkewOrReplay(body);
        }
        return CoordError::Unauthorized(body);
    }
    CoordError::Http {
        method: method.to_string(),
        path: path.to_string(),
        status: status.as_u16(),
        body,
    }
}

/// Client for the coordination server. Requests that act on an account are
/// signed with the device key; account creation, device certificates and
/// revocations carry their own signatures and are sent unsigned.
#[derive(Clone)]
pub struct CoordClient {
    base: String,
    http: reqwest::Client,
    tls: Arc<rustls::ClientConfig>,
    quic_tls: Arc<rustls::ClientConfig>,
    identity: Option<DeviceIdentity>,
}

fn signed_headers(
    identity: &DeviceIdentity,
    method: &str,
    path: &str,
    body: &[u8],
) -> Vec<(&'static str, String)> {
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let nonce = hex::encode(nonce);
    let time = now_unix();
    let sig = identity.sign_hex(&request_signing_bytes(method, path, time, &nonce, body));
    vec![
        (HDR_DEVICE, identity.device_id.clone()),
        (HDR_TIME, time.to_string()),
        (HDR_NONCE, nonce),
        (HDR_SIG, sig),
    ]
}

impl CoordClient {
    /// `base` must be `https://`; the server's TLS key must match `pin`.
    pub fn new(base: &str, pin: &str) -> Result<Self> {
        let base = base.trim_end_matches('/').to_string();
        if !base.starts_with("https://") {
            bail!("coord URL must start with https:// (got {base})");
        }
        let pin = parse_pin(pin).ok_or_else(|| anyhow!("coord pin is missing or malformed"))?;
        let tls = Arc::new(pinned_client_config(pin)?);
        let quic_tls = Arc::new(pinned_quic_client_config(pin)?);
        let http = reqwest::Client::builder()
            .use_preconfigured_tls((*tls).clone())
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(Self {
            base,
            http,
            tls,
            quic_tls,
            identity: None,
        })
    }

    pub fn with_identity(mut self, identity: DeviceIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    pub async fn healthz(&self) -> Result<()> {
        self.call(Method::GET, "/healthz", None, false)
            .await?
            .ok_or_else(|| anyhow!("GET /healthz failed: 404 not found"))?;
        Ok(())
    }

    pub async fn server_version(&self) -> Result<ServerVersion> {
        self.json(Method::GET, "/v1/version", None::<&()>, false)
            .await?
            .ok_or_else(|| anyhow!("GET /v1/version failed: 404 not found"))
    }

    pub async fn server_info(&self) -> Result<ServerInfo> {
        self.json(Method::GET, "/v1/info", None::<&()>, false)
            .await?
            .ok_or_else(|| anyhow!("GET /v1/info failed: 404 not found"))
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
        signed: bool,
    ) -> Result<Option<reqwest::Response>> {
        let body = body.unwrap_or_default();
        let mut req = self
            .http
            .request(method.clone(), format!("{}{path}", self.base));
        if signed {
            let identity = self
                .identity
                .as_ref()
                .ok_or_else(|| anyhow!("request needs a device identity"))?;
            for (k, v) in signed_headers(identity, method.as_str(), path, &body) {
                req = req.header(k, v);
            }
        }
        if !body.is_empty() {
            req = req.header("content-type", "application/json").body(body);
        }
        let res = req
            .send()
            .await
            .with_context(|| format!("{method} {path}"))?;
        if res.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !res.status().is_success() {
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            return Err(classify_http_error(&method, path, status, text).into());
        }
        Ok(Some(res))
    }

    async fn json<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&impl Serialize>,
        signed: bool,
    ) -> Result<Option<T>> {
        let body = body.map(serde_json::to_vec).transpose()?;
        match self.call(method, path, body, signed).await? {
            Some(res) => Ok(Some(res.json().await?)),
            None => Ok(None),
        }
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        body: &impl Serialize,
        signed: bool,
    ) -> Result<()> {
        let body = serde_json::to_vec(body)?;
        self.call(method.clone(), path, Some(body), signed)
            .await?
            .ok_or_else(|| anyhow!("{method} {path} failed: 404 not found"))?;
        Ok(())
    }

    pub async fn create_account(&self, req: &CreateAccountRequest) -> Result<()> {
        self.send(Method::POST, "/v1/accounts", req, false).await
    }

    pub async fn add_device(&self, cert: &DeviceCert) -> Result<()> {
        self.send(Method::POST, "/v1/devices", cert, false).await
    }

    pub async fn revoke(&self, rev: &Revocation) -> Result<()> {
        self.send(Method::POST, "/v1/revocations", rev, false).await
    }

    pub async fn list_devices(&self) -> Result<Vec<DeviceEntry>> {
        self.json::<Vec<DeviceEntry>>(Method::GET, "/v1/devices", None::<&()>, true)
            .await?
            .ok_or_else(|| anyhow!("this device is not registered with the coord"))
    }

    pub async fn register(&self, endpoints: Vec<String>) -> Result<RegisterResponse> {
        self.json(
            Method::POST,
            "/v1/register",
            Some(&RegisterRequest { endpoints }),
            true,
        )
        .await?
        .ok_or_else(|| anyhow!("this device is not registered with the coord"))
    }

    pub async fn peer_endpoints(&self, device_id: &str) -> Result<Option<PeerEndpoints>> {
        self.json(
            Method::GET,
            &format!("/v1/endpoints/{device_id}"),
            None::<&()>,
            true,
        )
        .await
    }

    pub async fn enroll_start(&self, msg_a: String) -> Result<String> {
        self.enroll_start_room(msg_a, None).await
    }

    pub async fn enroll_start_room(&self, msg_a: String, room: Option<String>) -> Result<String> {
        let started: EnrollStarted = self
            .json(
                Method::POST,
                "/v1/enroll",
                Some(&EnrollStart { msg_a, room }),
                true,
            )
            .await?
            .ok_or_else(|| anyhow!("coord refused to open an enrollment"))?;
        Ok(started.nameplate)
    }

    pub async fn enroll_offer_opt(&self, nameplate: &str) -> Result<Option<String>> {
        let start: Option<EnrollStart> = self
            .json(
                Method::GET,
                &format!("/v1/enroll/{nameplate}"),
                None::<&()>,
                false,
            )
            .await?;
        Ok(start.map(|s| s.msg_a))
    }

    pub async fn enroll_offer(&self, nameplate: &str) -> Result<String> {
        self.enroll_offer_opt(nameplate)
            .await?
            .ok_or_else(|| anyhow!("code not found or expired"))
    }

    pub async fn enroll_reply(&self, nameplate: &str, reply: &EnrollReply) -> Result<()> {
        self.send(
            Method::POST,
            &format!("/v1/enroll/{nameplate}/reply"),
            reply,
            false,
        )
        .await
    }

    pub async fn enroll_get_reply(&self, nameplate: &str) -> Result<Option<EnrollReply>> {
        self.json(
            Method::GET,
            &format!("/v1/enroll/{nameplate}/reply"),
            None::<&()>,
            true,
        )
        .await
    }

    pub async fn enroll_finish(&self, nameplate: &str, payload: String) -> Result<()> {
        self.send(
            Method::POST,
            &format!("/v1/enroll/{nameplate}/finish"),
            &EnrollFinish { payload },
            true,
        )
        .await
    }

    pub async fn enroll_get_finish(
        &self,
        nameplate: &str,
        finish_token: &str,
    ) -> Result<Option<String>> {
        let path = format!("/v1/enroll/{nameplate}/finish");
        let res = self
            .http
            .request(Method::GET, format!("{}{path}", self.base))
            .header(HDR_ENROLL_TOKEN, finish_token)
            .send()
            .await
            .with_context(|| format!("GET {path}"))?;
        if res.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !res.status().is_success() {
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            return Err(anyhow!("GET {path} failed: {status} {text}"));
        }
        let finish: EnrollFinish = res.json().await?;
        Ok(Some(finish.payload))
    }

    pub fn tls_config(&self) -> Arc<rustls::ClientConfig> {
        self.tls.clone()
    }

    pub fn quic_tls_config(&self) -> Arc<rustls::ClientConfig> {
        self.quic_tls.clone()
    }

    pub fn relay_quic_addr(&self, register: &RegisterResponse) -> String {
        register
            .relay_quic
            .strip_prefix("quic://")
            .unwrap_or(&register.relay_quic)
            .to_string()
    }

    pub fn relay_addr(&self, register: &RegisterResponse) -> String {
        register
            .relay
            .strip_prefix("tcp://")
            .unwrap_or(&register.relay)
            .to_string()
    }

    pub fn relay_ws_url(&self, register: &RegisterResponse) -> String {
        if !register.relay_ws.is_empty() {
            return register.relay_ws.clone();
        }
        self.websocket_relay_url()
    }

    pub fn websocket_relay_url(&self) -> String {
        format!("{}/v1/relay", self.base.replacen("https://", "wss://", 1))
    }

    /// Upgrade-only probe of the WebSocket relay path (no relay hello).
    pub async fn probe_relay_ws(&self) -> Result<()> {
        let url = self.websocket_relay_url();
        self.probe_relay_ws_url(&url).await
    }

    /// Upgrade-only probe of a specific WebSocket relay URL (no relay hello).
    pub async fn probe_relay_ws_url(&self, url: &str) -> Result<()> {
        let request = url.into_client_request()?;
        let (mut ws, _) = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            connect_async_tls_with_config(
                request,
                None,
                false,
                Some(Connector::Rustls(self.tls.clone())),
            ),
        )
        .await
        .map_err(|_| anyhow!("websocket relay timed out"))?
        .with_context(|| format!("websocket relay {url}"))?;
        let _ = ws.close(None).await;
        Ok(())
    }

    /// Handshake-only probe of the coord's UDP/QUIC datagram relay (`addr` as `host:port`).
    pub async fn probe_relay_quic(&self, addr: &str) -> Result<()> {
        let target = addr.trim().strip_prefix("quic://").unwrap_or(addr.trim()).to_string();
        if target.is_empty() {
            bail!("quic datagram relay is disabled");
        }
        let remote = tokio::task::spawn_blocking(move || -> Result<std::net::SocketAddr> {
            use std::net::ToSocketAddrs;
            let mut addrs = target
                .to_socket_addrs()
                .with_context(|| format!("resolve {target}"))?;
            addrs
                .next()
                .ok_or_else(|| anyhow!("{target} resolved to no addresses"))
        })
        .await??;

        let quic_crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from((*self.quic_tls).clone())?;
        let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.initial_mtu(1350);
        transport.max_idle_timeout(Some(Duration::from_secs(5).try_into()?));
        client_cfg.transport_config(Arc::new(transport));

        let bind_addr: std::net::SocketAddr = if remote.is_ipv6() {
            "[::]:0".parse()?
        } else {
            "0.0.0.0:0".parse()?
        };
        let mut endpoint = quinn::Endpoint::client(bind_addr)?;
        endpoint.set_default_client_config(client_cfg);

        let conn = tokio::time::timeout(
            Duration::from_secs(3),
            endpoint.connect(remote, "topaz-coord")?,
        )
        .await
        .map_err(|_| anyhow!("quic datagram relay timed out"))??;
        conn.close(0u32.into(), b"doctor");
        endpoint.close(0u32.into(), b"doctor");
        Ok(())
    }

    /// Open a single signaling websocket connection with ping/pong keepalive.
    async fn connect_signal_ws(
        &self,
    ) -> Result<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    > {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| anyhow!("signaling needs a device identity"))?;
        let url = format!("{}/v1/signal", self.base.replacen("https://", "wss://", 1));
        let mut request = url.as_str().into_client_request()?;
        for (k, v) in signed_headers(identity, "GET", "/v1/signal", &[]) {
            request.headers_mut().insert(k, HeaderValue::from_str(&v)?);
        }

        let (ws, _) = tokio::time::timeout(
            Duration::from_secs(10),
            connect_async_tls_with_config(
                request,
                None,
                false,
                Some(Connector::Rustls(self.tls.clone())),
            ),
        )
        .await
        .map_err(|_| anyhow!("signal websocket connect timed out"))?
        .context("signal websocket")?;
        Ok(ws)
    }

    /// Open a single signaling websocket (non-reconnecting).
    pub async fn signal(
        &self,
    ) -> Result<(mpsc::Sender<SignalEnvelope>, mpsc::Receiver<SignalEnvelope>)> {
        let ws = self.connect_signal_ws().await?;
        let (tx_out, mut rx_out) = mpsc::channel::<SignalEnvelope>(32);
        let (tx_in, rx_in) = mpsc::channel::<SignalEnvelope>(32);
        tokio::spawn(async move {
            let _ = drive_signal_ws(ws, &mut rx_out, &tx_in).await;
        });
        Ok((tx_out, rx_in))
    }

    /// Spawn a persistent, self-healing signaling websocket supervisor.
    ///
    /// The returned `(tx, rx)` channels stay open across coord restarts, NAT
    /// idle drops, and temporary network outages. `on_connected` is invoked
    /// whenever a signaling session connects (including reconnects).
    pub fn spawn_signal_supervisor(
        &self,
        on_connected: Arc<dyn Fn() + Send + Sync>,
    ) -> (mpsc::Sender<SignalEnvelope>, mpsc::Receiver<SignalEnvelope>) {
        let (tx_out, mut rx_out) = mpsc::channel::<SignalEnvelope>(64);
        let (tx_in, rx_in) = mpsc::channel::<SignalEnvelope>(64);
        let client = self.clone();
        tokio::spawn(async move {
            let mut backoff = Duration::from_secs(1);
            let mut first = true;
            loop {
                if tx_in.is_closed() {
                    break;
                }
                match client.connect_signal_ws().await {
                    Ok(ws) => {
                        let connected_at = Instant::now();
                        if first {
                            info!("signaling websocket connected");
                            first = false;
                        } else {
                            info!("signaling websocket reconnected");
                        }
                        on_connected();
                        let should_stop = drive_signal_ws(ws, &mut rx_out, &tx_in).await;
                        if should_stop || tx_in.is_closed() {
                            break;
                        }
                        if connected_at.elapsed() >= Duration::from_secs(10) {
                            backoff = Duration::from_secs(1);
                        }
                        warn!(retry_in = ?backoff, "signaling websocket disconnected; reconnecting");
                    }
                    Err(e) => {
                        warn!(error = %e, retry_in = ?backoff, "signaling websocket connect failed; retrying");
                    }
                }
                // Drain stale queued outbound signals while offline so we don't
                // burst outdated punch/relay envelopes on reconnect.
                while rx_out.try_recv().is_ok() {}
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = tx_in.closed() => break,
                }
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        });
        (tx_out, rx_in)
    }
}

/// Drive one live signaling WebSocket with bidirectional Ping/Pong keepalive
/// and idle timeout. Returns `true` if local callers closed the channels.
async fn drive_signal_ws<S>(
    ws: tokio_tungstenite::WebSocketStream<S>,
    rx_out: &mut mpsc::Receiver<SignalEnvelope>,
    tx_in: &mpsc::Sender<SignalEnvelope>,
) -> bool
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sink, mut stream) = ws.split();
    let mut ping = tokio::time::interval(SIGNAL_PING_EVERY);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping.tick().await;
    let mut last_seen = Instant::now();

    loop {
        let idle_deadline = tokio::time::Instant::from_std(last_seen + SIGNAL_IDLE_TIMEOUT);
        tokio::select! {
            out = rx_out.recv() => match out {
                Some(env) => {
                    let Ok(text) = serde_json::to_string(&env) else {
                        continue;
                    };
                    if sink.send(Message::Text(text.into())).await.is_err() {
                        return false;
                    }
                }
                None => {
                    let _ = sink.send(Message::Close(None)).await;
                    return true;
                }
            },
            incoming = stream.next() => match incoming {
                Some(Ok(Message::Text(t))) => {
                    last_seen = Instant::now();
                    if let Ok(env) = serde_json::from_str::<SignalEnvelope>(&t) {
                        if tx_in.send(env).await.is_err() {
                            return true;
                        }
                    }
                }
                Some(Ok(Message::Binary(b))) => {
                    last_seen = Instant::now();
                    let text = String::from_utf8_lossy(&b);
                    if let Ok(env) = serde_json::from_str::<SignalEnvelope>(&text) {
                        if tx_in.send(env).await.is_err() {
                            return true;
                        }
                    }
                }
                Some(Ok(Message::Ping(p))) => {
                    last_seen = Instant::now();
                    if sink.send(Message::Pong(p)).await.is_err() {
                        return false;
                    }
                }
                Some(Ok(Message::Pong(_))) => {
                    last_seen = Instant::now();
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return false,
                Some(Ok(Message::Frame(_))) => {
                    last_seen = Instant::now();
                }
            },
            _ = ping.tick() => {
                if sink.send(Message::Ping(Vec::new().into())).await.is_err() {
                    return false;
                }
            },
            _ = tokio::time::sleep_until(idle_deadline) => {
                warn!("signaling websocket idle timeout; dropping connection");
                let _ = sink.send(Message::Close(None)).await;
                return false;
            }
        }
    }
}
