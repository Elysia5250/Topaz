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

/// How to reach the coord relay: TCP first, WebSocket if that path is blocked,
/// plus optional UDP/QUIC unreliable datagram relay for L3 VPN packets.
#[derive(Clone)]
pub struct RelayAddrs {
    pub tcp: String,
    pub ws: String,
    pub quic: String,
    pub coord_tls: Arc<rustls::ClientConfig>,
    pub coord_quic_tls: Option<Arc<rustls::ClientConfig>>,
}

/// Authenticated inner-mTLS relay stream paired with forward-secret E2E
/// datagram keys exported via RFC 5705 TLS 1.3 key exporter.
pub struct RelayStream {
    pub tls: TlsStream<RelayTunnel>,
    pub dgram_keys: [u8; 64],
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
) -> Result<RelayStream> {
    connect_relay_attempts(addrs, identity, trust, peer_id, JOIN_ATTEMPTS).await
}

/// Acceptor side: the dialer is already waiting. One shot, no long retry loop
/// that would block the node's event loop (and delay noticing a revocation).
pub async fn connect_relay_once(
    addrs: &RelayAddrs,
    identity: &DeviceIdentity,
    trust: &TrustStore,
    peer_id: &str,
) -> Result<RelayStream> {
    connect_relay_attempts(addrs, identity, trust, peer_id, 1).await
}

async fn connect_relay_attempts(
    addrs: &RelayAddrs,
    identity: &DeviceIdentity,
    trust: &TrustStore,
    peer_id: &str,
    attempts: usize,
) -> Result<RelayStream> {
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
    let (local, remote) = tokio::io::duplex(64 * 1024);
    let (mut remote_r, mut remote_w) = tokio::io::split(remote);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Message>(32);

    // Writer task: exclusively owns the WS sink so reads and writes can never deadlock.
    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sink.send(msg).await.is_err() {
                break;
            }
        }
        let _ = sink.send(Message::Close(None)).await;
    });

    // Outbound pump: duplex -> WS channel.
    let tx_out = tx.clone();
    let outbound = tokio::spawn(async move {
        let mut buf = vec![0u8; WS_FRAME];
        loop {
            match remote_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx_out
                        .send(Message::Binary(buf[..n].to_vec().into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });

    // Inbound pump: WS stream -> duplex.
    let tx_in = tx.clone();
    let inbound = tokio::spawn(async move {
        while let Some(incoming) = stream.next().await {
            match incoming {
                Ok(Message::Binary(b)) => {
                    if remote_w.write_all(&b).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Ping(p)) => {
                    let _ = tx_in.try_send(Message::Pong(p));
                }
                Ok(Message::Pong(_)) | Ok(Message::Text(_)) | Ok(Message::Frame(_)) => {}
                Ok(Message::Close(_)) | Err(_) => break,
            }
        }
        let _ = remote_w.shutdown().await;
    });

    // Coordinate shutdown: when either direction finishes, tear down the other.
    drop(tx);
    tokio::spawn(async move {
        let mut outbound = outbound;
        let mut inbound = inbound;
        tokio::select! {
            _ = &mut outbound => { inbound.abort(); }
            _ = &mut inbound => { outbound.abort(); }
        }
        let _ = writer.await;
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
) -> Result<RelayStream> {
    let mut tls: TlsStream<RelayTunnel> = if identity.device_id.as_str() < peer_id {
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

    // Export 64 bytes of forward-secret E2E keying material (32B per direction)
    // for the coord UDP/QUIC unreliable datagram relay so coord only ever sees
    // opaque ChaCha20-Poly1305 ciphertext.
    let mut dgram_keys = [0u8; 64];
    match &tls {
        TlsStream::Client(s) => s.get_ref().1.export_keying_material(
            &mut dgram_keys,
            b"topaz-relay-dgram-v1",
            None,
        ),
        TlsStream::Server(s) => s.get_ref().1.export_keying_material(
            &mut dgram_keys,
            b"topaz-relay-dgram-v1",
            None,
        ),
    }
    .map_err(|e| anyhow!("export relay datagram keys: {e}"))?;

    // Exchange 1-byte protocol version so v1/v2 mismatches fail fast cleanly.
    tokio::time::timeout(Duration::from_secs(5), async {
        tls.write_all(&[topaz_proto::mux::MUX_VERSION]).await?;
        tls.flush().await?;
        let mut peer_ver = [0u8; 1];
        tls.read_exact(&mut peer_ver).await?;
        if peer_ver[0] != topaz_proto::mux::MUX_VERSION {
            bail!(
                "unsupported relay mux version {} (expected {})",
                peer_ver[0],
                topaz_proto::mux::MUX_VERSION
            );
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow!("timed out negotiating relay mux version"))??;

    Ok(RelayStream { tls, dgram_keys })
}

/// Connect to coord's UDP/QUIC unreliable datagram relay (port 7724 by default),
/// authenticate via signed `RelayHello`, and wait for `READY`.
pub async fn connect_quic_datagram_relay(
    addr_str: &str,
    quic_tls: &Arc<rustls::ClientConfig>,
    identity: &DeviceIdentity,
    peer_id: &str,
) -> Result<quinn::Connection> {
    let target_str = addr_str.trim().to_string();
    if target_str.is_empty() {
        bail!("no quic datagram relay address");
    }
    let remote = tokio::task::spawn_blocking(move || -> Result<std::net::SocketAddr> {
        use std::net::ToSocketAddrs;
        let mut addrs = target_str
            .to_socket_addrs()
            .with_context(|| format!("resolve quic relay {target_str}"))?;
        addrs
            .next()
            .ok_or_else(|| anyhow!("quic relay {target_str} resolved to no addresses"))
    })
    .await??;

    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from((**quic_tls).clone())?;
    let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.initial_mtu(1350);
    transport.max_idle_timeout(Some(Duration::from_secs(30).try_into()?));
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    transport.datagram_receive_buffer_size(Some(256 * 1024));
    transport.datagram_send_buffer_size(1024 * 1024);
    client_cfg.transport_config(Arc::new(transport));

    let bind_addr: std::net::SocketAddr = if remote.is_ipv6() {
        "[::]:0".parse()?
    } else {
        "0.0.0.0:0".parse()?
    };
    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_cfg);

    let conn = tokio::time::timeout(
        Duration::from_secs(5),
        endpoint.connect(remote, "topaz-coord")?,
    )
    .await
    .map_err(|_| anyhow!("quic datagram relay connect timed out"))??;

    let (mut send, mut recv) = conn.open_bi().await?;
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
    let bytes = postcard::to_stdvec(&hello)?;
    send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    let _ = send.finish();

    let mut ready = [0u8; 1];
    tokio::time::timeout(PEER_WAIT, recv.read_exact(&mut ready))
        .await
        .map_err(|_| anyhow!("peer did not join quic datagram relay"))??;
    match ready[0] {
        1 => Ok(conn),
        2 => bail!("relay session limit reached for this account"),
        _ => bail!("quic datagram relay rejected the session"),
    }
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
