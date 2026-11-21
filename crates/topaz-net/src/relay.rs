use crate::tls::{client_config, peer_device_id, server_config, TrustStore};
use anyhow::{anyhow, bail, Context, Result};
use futures::{SinkExt, StreamExt};
use rand::RngCore;
use rustls::pki_types::ServerName;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use topaz_core::{now_unix, DeviceIdentity};
use topaz_proto::auth::relay_signing_bytes;
use topaz_proto::RelayHello;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async_tls_with_config, Connector};
use tracing::{info, warn};

/// Must stay <= the coordinator's pending TTL so a waiting peer is still
/// matchable when this wait expires.
const PEER_WAIT: Duration = Duration::from_secs(45);
const JOIN_ATTEMPTS: usize = 3;
const JOIN_RETRY_PAUSE: Duration = Duration::from_secs(1);
const TCP_DIAL: Duration = Duration::from_secs(3);
const WS_FRAME: usize = 16 * 1024;

/// How to reach the coord relay: TCP first, WebSocket if that path is blocked.
#[derive(Clone)]
pub struct RelayAddrs {
    pub tcp: String,
    pub ws: String,
    pub coord_tls: Arc<rustls::ClientConfig>,
}

/// Byte pipe used as the outer hop (TCP or WSS). Inner mTLS still runs on top.
pub enum RelayTunnel {
    Tcp(TcpStream),
    Ws(DuplexStream),
}

impl AsyncRead for RelayTunnel {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Self::Ws(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for RelayTunnel {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Self::Ws(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            Self::Ws(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Self::Ws(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Join a relay session with `peer_id` and run mutual TLS over it, so the
/// relay only forwards ciphertext. The device with the smaller id is the TLS
/// client.
///
/// TCP 7723 is tried first (short connect timeout). On connect timeout or
/// refusal, the same hello/READY exchange runs over WSS `/v1/relay`.
/// Auth rejection and the account session limit are not retried. A drop
/// after READY is a mid-session failure and is not retried here.
pub async fn connect_relay(
    addrs: &RelayAddrs,
    identity: &DeviceIdentity,
    trust: &TrustStore,
    peer_id: &str,
) -> Result<TlsStream<RelayTunnel>> {
    connect_relay_attempts(addrs, identity, trust, peer_id, JOIN_ATTEMPTS).await
}

/// Acceptor side: the dialer is already waiting. One shot, no long retry loop
/// that would block the node's event loop (and delay noticing a revocation).
pub async fn connect_relay_once(
    addrs: &RelayAddrs,
    identity: &DeviceIdentity,
    trust: &TrustStore,
    peer_id: &str,
) -> Result<TlsStream<RelayTunnel>> {
    connect_relay_attempts(addrs, identity, trust, peer_id, 1).await
}

async fn connect_relay_attempts(
    addrs: &RelayAddrs,
    identity: &DeviceIdentity,
    trust: &TrustStore,
    peer_id: &str,
    attempts: usize,
) -> Result<TlsStream<RelayTunnel>> {
    let mut last_err: Option<JoinError> = None;
    let mut prefer_ws = false;
    for attempt in 1..=attempts {
        if attempt > 1 {
            tokio::time::sleep(JOIN_RETRY_PAUSE).await;
        }
        let mut used_ws = false;
        match join_relay(addrs, identity, peer_id, prefer_ws, &mut used_ws).await {
            Ok(stream) => return upgrade_relay_tls(stream, identity, trust, peer_id).await,
            Err(e) if e.retryable() && attempt < attempts => {
                if used_ws {
                    prefer_ws = true;
                }
                warn!(attempt, error = %e, "relay join failed; retrying");
                last_err = Some(e);
            }
            Err(e) => return Err(e.into_anyhow()),
        }
    }
    Err(last_err.unwrap_or(JoinError::Timeout).into_anyhow())
}

enum JoinError {
    Timeout,
    Io(io::Error),
    OverLimit,
    Rejected,
    Other(anyhow::Error),
}

impl JoinError {
    fn retryable(&self) -> bool {
        matches!(self, Self::Timeout | Self::Io(_))
    }

    fn into_anyhow(self) -> anyhow::Error {
        match self {
            Self::Timeout => anyhow!("peer did not join the relay within {PEER_WAIT:?}"),
            Self::Io(e) => anyhow::Error::new(e).context("relay join failed"),
            Self::OverLimit => anyhow!("relay session limit reached for this account"),
            Self::Rejected => anyhow!("relay rejected the session"),
            Self::Other(e) => e,
        }
    }
}

impl std::fmt::Display for JoinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => write!(f, "peer did not join the relay within {PEER_WAIT:?}"),
            Self::Io(e) => write!(f, "{e}"),
            Self::OverLimit => write!(f, "relay session limit reached for this account"),
            Self::Rejected => write!(f, "relay rejected the session"),
            Self::Other(e) => write!(f, "{e}"),
        }
    }
}

async fn join_relay(
    addrs: &RelayAddrs,
    identity: &DeviceIdentity,
    peer_id: &str,
    prefer_ws: bool,
    used_ws: &mut bool,
) -> Result<RelayTunnel, JoinError> {
    if !prefer_ws {
        match tokio::time::timeout(TCP_DIAL, TcpStream::connect(&addrs.tcp)).await {
            Ok(Ok(tcp)) => {
                let _ = tcp.set_nodelay(true);
                let mut stream = RelayTunnel::Tcp(tcp);
                wait_hello_ready(&mut stream, identity, peer_id).await?;
                return Ok(stream);
            }
            Ok(Err(e)) => {
                if addrs.ws.is_empty() {
                    return Err(JoinError::Io(e));
                }
                info!(error = %e, ws = %addrs.ws, "falling back to websocket relay");
            }
            Err(_) => {
                if addrs.ws.is_empty() {
                    return Err(JoinError::Io(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "tcp relay connect timed out",
                    )));
                }
                info!(ws = %addrs.ws, "falling back to websocket relay");
            }
        }
    } else if !addrs.ws.is_empty() {
        info!(ws = %addrs.ws, "falling back to websocket relay");
    }

    if addrs.ws.is_empty() {
        return Err(JoinError::Other(anyhow!("no websocket relay url")));
    }
    *used_ws = true;
    join_relay_ws(&addrs.ws, &addrs.coord_tls, identity, peer_id).await
}

async fn join_relay_ws(
    url: &str,
    tls: &Arc<rustls::ClientConfig>,
    identity: &DeviceIdentity,
    peer_id: &str,
) -> Result<RelayTunnel, JoinError> {
    let request = url
        .into_client_request()
        .map_err(|e| JoinError::Other(anyhow!("websocket relay url: {e}")))?;
    let (ws, _) = tokio::time::timeout(
        Duration::from_secs(10),
        connect_async_tls_with_config(
            request,
            None,
            false,
            Some(Connector::Rustls(tls.clone())),
        ),
    )
    .await
    .map_err(|_| {
        JoinError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "websocket relay connect timed out",
        ))
    })?
    .map_err(|e| JoinError::Io(io::Error::other(e.to_string())))?;
    let mut stream = bridge_tungstenite(ws);
    wait_hello_ready(&mut stream, identity, peer_id).await?;
    Ok(stream)
}

fn bridge_tungstenite<S>(ws: tokio_tungstenite::WebSocketStream<S>) -> RelayTunnel
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sink, mut stream) = ws.split();
    let (local, mut remote) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let mut buf = vec![0u8; WS_FRAME];
        loop {
            tokio::select! {
                incoming = stream.next() => {
                    match incoming {
                        Some(Ok(Message::Binary(b))) => {
                            if remote.write_all(&b).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(Message::Ping(p))) => {
                            if sink.send(Message::Pong(p)).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(Message::Pong(_))) | Some(Ok(Message::Text(_))) | Some(Ok(Message::Frame(_))) => {}
                        Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    }
                }
                outgoing = remote.read(&mut buf) => {
                    match outgoing {
                        Ok(0) | Err(_) => {
                            let _ = sink.send(Message::Close(None)).await;
                            break;
                        }
                        Ok(n) => {
                            if sink.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        }
        let _ = remote.shutdown().await;
    });
    RelayTunnel::Ws(local)
}

/// One connect + hello + wait for READY. Uses a fresh nonce each call so
/// a retry is not treated as a replay.
async fn wait_hello_ready(
    stream: &mut RelayTunnel,
    identity: &DeviceIdentity,
    peer_id: &str,
) -> Result<(), JoinError> {
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let nonce = hex::encode(nonce);
    let time = now_unix();
    let hello = RelayHello {
        device_id: identity.device_id.clone(),
        peer_id: peer_id.to_string(),
        time,
        sig: identity.sign_hex(&relay_signing_bytes(
            &identity.device_id,
            peer_id,
            time,
            &nonce,
        )),
        nonce,
    };
    let bytes = postcard::to_stdvec(&hello).map_err(|e| JoinError::Other(e.into()))?;
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await
        .map_err(JoinError::Io)?;
    stream.write_all(&bytes).await.map_err(JoinError::Io)?;
    stream.flush().await.map_err(JoinError::Io)?;

    let mut ready = [0u8; 1];
    match tokio::time::timeout(PEER_WAIT, stream.read_exact(&mut ready)).await {
        Err(_) => return Err(JoinError::Timeout),
        Ok(Err(e)) => return Err(JoinError::Io(e)),
        Ok(Ok(_)) => {}
    }
    match ready[0] {
        1 => Ok(()),
        2 => Err(JoinError::OverLimit),
        _ => Err(JoinError::Rejected),
    }
}

async fn upgrade_relay_tls(
    stream: RelayTunnel,
    identity: &DeviceIdentity,
    trust: &TrustStore,
    peer_id: &str,
) -> Result<TlsStream<RelayTunnel>> {
    let tls: TlsStream<RelayTunnel> = if identity.device_id.as_str() < peer_id {
        let connector = TlsConnector::from(Arc::new(client_config(identity, trust)?));
        let s = connector
            .connect(ServerName::try_from("topaz")?, stream)
            .await
            .context("relay TLS handshake")?;
        TlsStream::Client(s)
    } else {
        let acceptor = TlsAcceptor::from(Arc::new(server_config(identity, trust)?));
        let s = acceptor
            .accept(stream)
            .await
            .context("relay TLS handshake")?;
        TlsStream::Server(s)
    };

    let authenticated = peer_device_id(tls.get_ref().1.peer_certificates())
        .ok_or_else(|| anyhow!("relay peer presented no device certificate"))?;
    if authenticated != peer_id {
        bail!("relay peer authenticated as {authenticated}, expected {peer_id}");
    }
    Ok(tls)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn relay_tunnel_duplex_roundtrip() {
        let (a, b) = tokio::io::duplex(1024);
        let mut a = RelayTunnel::Ws(a);
        let mut b = RelayTunnel::Ws(b);
        a.write_all(b"hello").await.unwrap();
        a.flush().await.unwrap();
        let mut buf = [0u8; 5];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }
}
