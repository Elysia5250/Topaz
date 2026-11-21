use crate::tls::{client_config, peer_device_id, server_config, TrustStore};
use anyhow::{anyhow, Context, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig};
use rustls::pki_types::CertificateDer;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use topaz_core::DeviceIdentity;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{info, warn};

#[derive(Clone)]
pub struct QuicEndpoint {
    pub endpoint: Endpoint,
    pub local_addr: SocketAddr,
}

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

pub struct QuicLink {
    pub conn: Connection,
    pub stream: QuicStream,
}

impl AsyncRead for QuicLink {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicLink {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
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
    transport.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into()?));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    transport.datagram_receive_buffer_size(Some(256 * 1024));
    transport.datagram_send_buffer_size(1024 * 1024);
    Ok(transport)
}

fn server_cfg(identity: &DeviceIdentity, trust: &TrustStore) -> Result<ServerConfig> {
    let server_crypto = QuicServerConfig::try_from(server_config(identity, trust)?)?;
    let mut server = ServerConfig::with_crypto(Arc::new(server_crypto));
    server.transport = Arc::new(transport_config()?);
    Ok(server)
}

/// Bind UDP `[::]:0` with `IPV6_V6ONLY=false` so IPv4-mapped and IPv6 share one socket.
fn dual_stack_udp() -> std::io::Result<std::net::UdpSocket> {
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

fn bind_dual_stack(server: ServerConfig, sock: std::net::UdpSocket) -> Result<Endpoint> {
    let runtime = quinn::default_runtime().ok_or_else(|| anyhow!("no async runtime"))?;
    Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server),
        sock,
        runtime,
    )
    .context("dual-stack QUIC endpoint")
}

/// Quinn rejects a remote whose family does not match the bound socket.
/// Dual-stack `[::]` needs IPv4 remotes rewritten as v4-mapped IPv6.
fn remote_for_endpoint(local: SocketAddr, remote: SocketAddr) -> SocketAddr {
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
    /// Bind the QUIC socket and, when `stun` is given, learn its UDP mapping
    /// from that server **before** quinn takes the socket over: restricted
    /// and full-cone NATs map by local endpoint, so the learned address is
    /// the one later handshakes share. Returns the mapped address, None when
    /// no STUN was requested or the probe failed (direct/relay keep working).
    pub fn bind(
        identity: &DeviceIdentity,
        trust: &TrustStore,
        stun: Option<SocketAddr>,
    ) -> Result<(Self, Option<SocketAddr>)> {
        let client_crypto = QuicClientConfig::try_from(client_config(identity, trust)?)?;
        let mut client_cfg = ClientConfig::new(Arc::new(client_crypto));
        client_cfg.transport_config(Arc::new(transport_config()?));

        let sock = match dual_stack_udp() {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "dual-stack UDP bind failed; falling back to 0.0.0.0:0");
                std::net::UdpSocket::bind("0.0.0.0:0")?
            }
        };
        // Probe while the socket is still ours: the receive queue has no
        // quinn task racing for packets yet. The probe clone shares the same
        // kernel socket, hence the same NAT mapping.
        let mapped = stun.and_then(|server| match sock.try_clone() {
            Ok(clone) => {
                // dual_stack_udp leaves the socket nonblocking for quinn; a
                // nonblocking clone would report WouldBlock before any reply
                // could arrive, so flip to blocking for the probe and always
                // restore nonblocking afterwards (Unix clones share O_NONBLOCK).
                let _ = clone.set_nonblocking(false);
                let res = crate::stun::probe_with_timeout(
                    &clone,
                    server,
                    std::time::Duration::from_secs(2),
                );
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
            Err(e) => {
                warn!(error = %e, "socket clone failed; stun probe skipped");
                None
            }
        });

        let mut endpoint = match bind_dual_stack(server_cfg(identity, trust)?, sock) {
            Ok(ep) => ep,
            Err(e) => {
                warn!(error = %e, "dual-stack QUIC bind failed; falling back to 0.0.0.0:0");
                Endpoint::server(server_cfg(identity, trust)?, "0.0.0.0:0".parse()?)?
            }
        };
        endpoint.set_default_client_config(client_cfg);
        let local_addr = endpoint.local_addr()?;
        if local_addr.is_ipv6() {
            info!(addr = %local_addr, "QUIC bound dual-stack [::] (IPv4-mapped + IPv6)");
        } else {
            info!(addr = %local_addr, "QUIC bound IPv4-only");
        }
        Ok((Self { endpoint, local_addr }, mapped))
    }

    /// Returns the link and the authenticated peer device id.
    pub async fn connect(&self, addr: SocketAddr) -> Result<(QuicLink, String)> {
        let dest = remote_for_endpoint(self.local_addr, addr);
        let conn = self
            .endpoint
            .connect(dest, "topaz")?
            .await
            .with_context(|| format!("quic connect {addr}"))?;
        let peer = authenticated_peer(&conn)?;
        let (mut send, recv) = conn.open_bi().await?;
        // Materialize the QUIC stream immediately so the acceptor's
        // `accept_bi()` returns even before any mux `Frame::Open` is sent.
        send.write_all(&[topaz_proto::mux::MUX_VERSION]).await?;
        Ok((
            QuicLink {
                conn,
                stream: QuicStream { send, recv },
            },
            peer,
        ))
    }

    pub async fn accept(&self) -> Result<(QuicLink, String)> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| anyhow!("endpoint closed"))?;
        let conn = incoming.await?;
        let peer = authenticated_peer(&conn)?;
        let (send, recv) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let (send, mut recv) = conn.accept_bi().await?;
            let mut ver = [0u8; 1];
            tokio::io::AsyncReadExt::read_exact(&mut recv, &mut ver).await?;
            if ver[0] != topaz_proto::mux::MUX_VERSION {
                anyhow::bail!("unsupported mux version {}", ver[0]);
            }
            Ok::<_, anyhow::Error>((send, recv))
        })
        .await
        .map_err(|_| anyhow!("timed out waiting for peer control stream"))??;
        Ok((
            QuicLink {
                conn,
                stream: QuicStream { send, recv },
            },
            peer,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4, SocketAddrV6};

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
}
