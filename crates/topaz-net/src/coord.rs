use crate::tls::pinned_client_config;
use anyhow::{anyhow, bail, Context, Result};
use futures::{SinkExt, StreamExt};
use rand::RngCore;
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::sync::Arc;
use topaz_core::{now_unix, DeviceIdentity};
use topaz_proto::auth::{
    parse_pin, request_signing_bytes, DeviceEntry, Revocation, HDR_DEVICE, HDR_NONCE, HDR_SIG,
    HDR_TIME,
};
use topaz_proto::{
    CreateAccountRequest, DeviceCert, EnrollFinish, EnrollReply, EnrollStart, EnrollStarted,
    PeerEndpoints, RegisterRequest, RegisterResponse, SignalEnvelope,
};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::{connect_async_tls_with_config, tungstenite::Message, Connector};

/// Client for the coordination server. Requests that act on an account are
/// signed with the device key; account creation, device certificates and
/// revocations carry their own signatures and are sent unsigned.
#[derive(Clone)]
pub struct CoordClient {
    base: String,
    http: reqwest::Client,
    tls: Arc<rustls::ClientConfig>,
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
        let http = reqwest::Client::builder()
            .use_preconfigured_tls((*tls).clone())
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()?;
        Ok(Self {
            base,
            http,
            tls,
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
            return Err(anyhow!("{method} {path} failed: {status} {text}"));
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
        let started: EnrollStarted = self
            .json(
                Method::POST,
                "/v1/enroll",
                Some(&EnrollStart { msg_a }),
                true,
            )
            .await?
            .ok_or_else(|| anyhow!("coord refused to open an enrollment"))?;
        Ok(started.nameplate)
    }

    pub async fn enroll_offer(&self, nameplate: &str) -> Result<String> {
        let start: EnrollStart = self
            .json(
                Method::GET,
                &format!("/v1/enroll/{nameplate}"),
                None::<&()>,
                false,
            )
            .await?
            .ok_or_else(|| anyhow!("code not found or expired"))?;
        Ok(start.msg_a)
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

    pub async fn enroll_get_finish(&self, nameplate: &str) -> Result<Option<String>> {
        let finish: Option<EnrollFinish> = self
            .json(
                Method::GET,
                &format!("/v1/enroll/{nameplate}/finish"),
                None::<&()>,
                false,
            )
            .await?;
        Ok(finish.map(|f| f.payload))
    }

    pub fn tls_config(&self) -> Arc<rustls::ClientConfig> {
        self.tls.clone()
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
        let request = url.as_str().into_client_request()?;
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

    /// Open the signaling websocket. Returns a sender for outgoing envelopes
    /// and a receiver for incoming ones.
    pub async fn signal(
        &self,
    ) -> Result<(mpsc::Sender<SignalEnvelope>, mpsc::Receiver<SignalEnvelope>)> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| anyhow!("signaling needs a device identity"))?;
        let url = format!("{}/v1/signal", self.base.replacen("https://", "wss://", 1));
        let mut request = url.as_str().into_client_request()?;
        for (k, v) in signed_headers(identity, "GET", "/v1/signal", &[]) {
            request.headers_mut().insert(k, HeaderValue::from_str(&v)?);
        }

        let (ws, _) = connect_async_tls_with_config(
            request,
            None,
            false,
            Some(Connector::Rustls(self.tls.clone())),
        )
        .await
        .context("signal websocket")?;
        let (mut sink, mut stream) = ws.split();
        let (tx_out, mut rx_out) = mpsc::channel::<SignalEnvelope>(32);
        let (tx_in, rx_in) = mpsc::channel::<SignalEnvelope>(32);

        tokio::spawn(async move {
            while let Some(env) = rx_out.recv().await {
                let Ok(text) = serde_json::to_string(&env) else {
                    continue;
                };
                if sink.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
        });

        tokio::spawn(async move {
            while let Some(Ok(msg)) = stream.next().await {
                let text = match msg {
                    Message::Text(t) => t.to_string(),
                    Message::Binary(b) => String::from_utf8_lossy(&b).into_owned(),
                    Message::Close(_) => break,
                    _ => continue,
                };
                if let Ok(env) = serde_json::from_str::<SignalEnvelope>(&text) {
                    if tx_in.send(env).await.is_err() {
                        break;
                    }
                }
            }
        });

        Ok((tx_out, rx_in))
    }
}
