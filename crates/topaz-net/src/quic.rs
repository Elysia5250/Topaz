use crate::tls::{client_config, peer_device_id, server_config, TrustStore};
use anyhow::{anyhow, bail, Context, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig, UdpPoller};
use rand::RngCore;
use rustls::pki_types::CertificateDer;
use std::collections::HashMap;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;
use topaz_core::DeviceIdentity;
use topaz_proto::stun::{binding_request, parse_binding_response, BINDING_RESPONSE, MAGIC};
use tracing::{debug, info, warn};

/// Custom `quinn::AsyncUdpSocket` wrapper that demultiplexes RFC 5389 STUN
/// Binding Responses on the same UDP port used by QUIC.
///
/// Zero-overhead hot path: an atomic waiter counter avoids even locking the
/// waiter table whenever no STUN probe is in flight.
#[derive(Debug)]
struct DemuxUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    waiter_count: AtomicUsize,
    stun_waiters: Mutex<HashMap<[u8; 12], oneshot::Sender<SocketAddr>>>,
}

impl DemuxUdpSocket {
    fn new(inner: Arc<dyn AsyncUdpSocket>) -> Self {
        Self {
            inner,
            waiter_count: AtomicUsize::new(0),
            stun_waiters: Mutex::new(HashMap::new()),
        }
    }

    fn register_stun(&self, txn: [u8; 12]) -> oneshot::Receiver<SocketAddr> {
        let (tx, rx) = oneshot::channel();
        self.stun_waiters.lock().unwrap().insert(txn, tx);
        self.waiter_count.fetch_add(1, Ordering::Release);
        rx
    }

    fn unregister_stun(&self, txn: &[u8; 12]) {
        if self.stun_waiters.lock().unwrap().remove(txn).is_some() {
            self.waiter_count.fetch_sub(1, Ordering::Release);
        }
    }
}

fn is_stun_binding_response(pkt: &[u8]) -> bool {
    pkt.len() >= 20
        && (pkt[0] & 0xc0) == 0
        && u16::from_be_bytes([pkt[0], pkt[1]]) == BINDING_RESPONSE
        && u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]) == MAGIC
}

impl AsyncUdpSocket for DemuxUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut TaskContext<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            let n = match self.inner.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(n)) => n,
                other => return other,
            };
            if self.waiter_count.load(Ordering::Acquire) == 0 {
                return Poll::Ready(Ok(n));
            }
            let mut write_idx = 0usize;
            for i in 0..n {
                let len = meta[i].len;
                let pkt = &bufs[i][..len];
                if is_stun_binding_response(pkt) {
                    let mut txn = [0u8; 12];
                    txn.copy_from_slice(&pkt[8..20]);
                    if let Some(mapped) = parse_binding_response(pkt, &txn) {
                        if let Some(tx) = self.stun_waiters.lock().unwrap().remove(&txn) {
                            self.waiter_count.fetch_sub(1, Ordering::Release);
                            let _ = tx.send(mapped);
                            continue;
                        }
                    }
                }
                if write_idx != i {
                    let tmp = bufs[i][..len].to_vec();
                    bufs[write_idx][..len].copy_from_slice(&tmp);
                    meta[write_idx] = meta[i];
                }
                write_idx += 1;
            }
            if write_idx > 0 {
                return Poll::Ready(Ok(write_idx));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[derive(Clone)]
pub struct QuicEndpoint {
    pub endpoint: Endpoint,
    pub local_addr: SocketAddr,
    demux: Arc<DemuxUdpSocket>,
}

/// One native bidirectional QUIC stream implementing `AsyncRead + AsyncWrite`
/// with true half-close semantics (`poll_shutdown` closes only `send`).
pub struct QuicStream {
    pub send: SendStream,
    pub recv: RecvStream,
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        std::pin::Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(std::io::Error::other)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.send)
            .poll_flush(cx)
            .map_err(std::io::Error::other)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(std::io::Error::other)
    }
}

/// Authenticated direct QUIC connection carrying native multiplexed streams
/// and unreliable RFC 9221 datagrams.
pub struct QuicLink {
    pub conn: Connection,
}

fn authenticated_peer(conn: &Connection) -> Result<String> {
    let identity = conn
        .peer_identity()
        .ok_or_else(|| anyhow!("peer presented no certificate"))?;
    let certs = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| anyhow!("unexpected peer identity type"))?;
    peer_device_id(Some(&certs)).ok_or_else(|| anyhow!("peer certificate has no Ed25519 key"))
}

fn transport_config() -> Result<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.initial_mtu(1350);
    transport.max_idle_timeout(Some(Duration::from_secs(30).try_into()?));
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    transport.datagram_receive_buffer_size(Some(256 * 1024));
    transport.datagram_send_buffer_size(1024 * 1024);
    Ok(transport)
}

fn server_cfg(identity: &DeviceIdentity, trust: &TrustStore) -> Result<ServerConfig> {
    let mut tls = server_config(identity, trust)?;
    tls.alpn_protocols = vec![topaz_proto::mux::ALPN_DIRECT.to_vec()];
    let server_crypto = QuicServerConfig::try_from(tls)?;
    let mut server = ServerConfig::with_crypto(Arc::new(server_crypto));
    server.transport = Arc::new(transport_config()?);
    Ok(server)
}

/// Bind UDP `[::]:0` with `IPV6_V6ONLY=false` so IPv4-mapped and IPv6 share one socket.
fn dual_stack_udp() -> io::Result<std::net::UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_only_v6(false)?;
    socket.set_nonblocking(true)?;
    socket.bind(&socket2::SockAddr::from(SocketAddr::from((
        Ipv6Addr::UNSPECIFIED,
        0u16,
    ))))?;
    Ok(socket.into())
}

fn bind_with_demux(
    server: ServerConfig,
    sock: std::net::UdpSocket,
) -> Result<(Endpoint, Arc<DemuxUdpSocket>)> {
    let runtime = quinn::default_runtime().ok_or_else(|| anyhow!("no async runtime"))?;
    let wrapped = runtime.wrap_udp_socket(sock)?;
    let demux = Arc::new(DemuxUdpSocket::new(wrapped));
    let ep = Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server),
        demux.clone(),
        runtime,
    )
    .context("demux QUIC endpoint")?;
    Ok((ep, demux))
}

/// Quinn rejects a remote whose family does not match the bound socket.
/// Dual-stack `[::]` needs IPv4 remotes rewritten as v4-mapped IPv6.
pub(crate) fn remote_for_endpoint(local: SocketAddr, remote: SocketAddr) -> SocketAddr {
    match (local, remote) {
        (SocketAddr::V6(_), SocketAddr::V4(v4)) => {
            SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())
        }
        (SocketAddr::V4(_), SocketAddr::V6(v6)) => v6
            .ip()
            .to_ipv4_mapped()
            .map(|v4| SocketAddr::new(IpAddr::V4(v4), v6.port()))
            .unwrap_or(remote),
        _ => remote,
    }
}

impl QuicEndpoint {
    /// Bind the QUIC socket with live STUN/QUIC demultiplexing.
    ///
    /// Pass `stun: None` to bind instantaneously without blocking; use the
    /// async [`Self::probe_stun`] method at startup and periodically on the
    /// live socket to learn/refresh the NAT mapping.
    pub fn bind(
        identity: &DeviceIdentity,
        trust: &TrustStore,
        stun: Option<SocketAddr>,
    ) -> Result<(Self, Option<SocketAddr>)> {
        let mut tls_client = client_config(identity, trust)?;
        tls_client.alpn_protocols = vec![topaz_proto::mux::ALPN_DIRECT.to_vec()];
        let client_crypto = QuicClientConfig::try_from(tls_client)?;
        let mut client_cfg = ClientConfig::new(Arc::new(client_crypto));
        client_cfg.transport_config(Arc::new(transport_config()?));

        let sock = match dual_stack_udp() {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "dual-stack UDP bind failed; falling back to 0.0.0.0:0");
                let s = std::net::UdpSocket::bind("0.0.0.0:0")?;
                s.set_nonblocking(true)?;
                s
            }
        };

        let mapped = stun.and_then(|server| match sock.try_clone() {
            Ok(clone) => {
                let _ = clone.set_nonblocking(false);
                let res =
                    crate::stun::probe_with_timeout(&clone, server, Duration::from_secs(2));
                let _ = clone.set_nonblocking(true);
                match res {
                    Ok(mapped) => {
                        info!(%server, %mapped, "stun mapped");
                        Some(mapped)
                    }
                    Err(e) => {
                        warn!(error = %e, %server, "stun probe failed; hole punching unavailable");
                        None
                    }
                }
            }
            Err(_) => None,
        });

        let (mut endpoint, demux, mapped) = match bind_with_demux(server_cfg(identity, trust)?, sock)
        {
            Ok((ep, demux)) => (ep, demux, mapped),
            Err(e) => {
                warn!(error = %e, "dual-stack QUIC bind failed; falling back to 0.0.0.0:0");
                let v4_sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
                v4_sock.set_nonblocking(true)?;
                let (ep, demux) = bind_with_demux(server_cfg(identity, trust)?, v4_sock)?;
                (ep, demux, None)
            }
        };
        endpoint.set_default_client_config(client_cfg);
        let local_addr = endpoint.local_addr()?;
        if local_addr.is_ipv6() {
            info!(addr = %local_addr, "QUIC bound dual-stack [::] (IPv4-mapped + IPv6)");
        } else {
            info!(addr = %local_addr, "QUIC bound IPv4-only");
        }
        Ok((
            Self {
                endpoint,
                local_addr,
                demux,
            },
            mapped,
        ))
    }

    /// Asynchronously probe a STUN server over this **live** QUIC UDP socket
    /// without interrupting active QUIC sessions or blocking Tokio threads.
    pub async fn probe_stun(&self, server: SocketAddr) -> Result<SocketAddr> {
        let dest = remote_for_endpoint(self.local_addr, server);
        for attempt in 1..=3u8 {
            let mut txn = [0u8; 12];
            rand::rngs::OsRng.fill_bytes(&mut txn);
            let req = binding_request(&txn);
            let rx = self.demux.register_stun(txn);
            let transmit = Transmit {
                destination: dest,
                ecn: None,
                contents: &req,
                segment_size: None,
                src_ip: None,
            };
            if let Err(e) = self.demux.try_send(&transmit) {
                self.demux.unregister_stun(&txn);
                debug!(attempt, %server, error = %e, "live stun send failed");
                tokio::time::sleep(Duration::from_millis(150)).await;
                continue;
            }
            match tokio::time::timeout(Duration::from_millis(1500), rx).await {
                Ok(Ok(mapped)) => {
                    // Normalize v4-mapped IPv6 addresses returned by dual-stack sockets.
                    let clean = match mapped {
                        SocketAddr::V6(v6) => v6
                            .ip()
                            .to_ipv4_mapped()
                            .map(|v4| SocketAddr::new(IpAddr::V4(v4), v6.port()))
                            .unwrap_or(mapped),
                        other => other,
                    };
                    return Ok(clean);
                }
                _ => {
                    self.demux.unregister_stun(&txn);
                    debug!(attempt, %server, "live stun probe retry");
                }
            }
        }
        bail!("no stun reply from {server}")
    }

    /// Connect to `addr` using native QUIC v2 (ALPN `topaz-v2`) and return the
    /// link and authenticated peer device id.
    pub async fn connect(&self, addr: SocketAddr) -> Result<(QuicLink, String)> {
        let dest = remote_for_endpoint(self.local_addr, addr);
        let conn = self
            .endpoint
            .connect(dest, "topaz")?
            .await
            .with_context(|| format!("quic connect {addr}"))?;
        let peer = authenticated_peer(&conn)?;
        Ok((QuicLink { conn }, peer))
    }

    pub async fn accept(&self) -> Result<(QuicLink, String)> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| anyhow!("endpoint closed"))?;
        let conn = incoming.await?;
        let peer = authenticated_peer(&conn)?;
        Ok((QuicLink { conn }, peer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4, SocketAddrV6};
    use topaz_proto::stun::{binding_response, parse_binding_request};

    #[test]
    fn maps_v4_remote_onto_v6_endpoint() {
        let local = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 9, 0, 0));
        let remote = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 4242));
        let mapped = remote_for_endpoint(local, remote);
        assert_eq!(
            mapped,
            SocketAddr::new(
                IpAddr::V6(Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped()),
                4242
            )
        );
    }

    #[test]
    fn maps_v4_mapped_remote_onto_v4_endpoint() {
        let local = SocketAddr::from(([0, 0, 0, 0], 9));
        let remote = SocketAddr::new(
            IpAddr::V6(Ipv4Addr::new(192, 168, 1, 8).to_ipv6_mapped()),
            80,
        );
        assert_eq!(
            remote_for_endpoint(local, remote),
            SocketAddr::from(([192, 168, 1, 8], 80))
        );
    }

    #[tokio::test]
    async fn live_quic_endpoint_probes_stun_while_running() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let stun_srv = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stun_addr = stun_srv.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            loop {
                let Ok((n, peer)) = stun_srv.recv_from(&mut buf).await else {
                    break;
                };
                if let Some(txn) = parse_binding_request(&buf[..n]) {
                    let _ = stun_srv
                        .send_to(&binding_response(&txn, peer), peer)
                        .await;
                }
            }
        });

        let id = DeviceIdentity::generate().unwrap();
        let trust = crate::tls::new_trust_store();
        let (ep, _) = QuicEndpoint::bind(&id, &trust, None).unwrap();
        let mapped = ep.probe_stun(stun_addr).await.unwrap();
        assert_eq!(mapped.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(mapped.port(), ep.local_addr.port());
    }
}
