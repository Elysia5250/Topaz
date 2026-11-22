//! HTTPS/WSS for the control plane with a self-signed certificate. Clients
//! pin the Ed25519 key, so no domain or CA is needed.

use anyhow::{anyhow, Result};
use axum::extract::ConnectInfo;
use axum::Router;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use std::time::Duration;
use topaz_proto::auth::{format_pin, pin_bytes};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tower_service::Service;
use tracing::{debug, warn};

const MAX_CONCURRENT_CONNS: usize = 4096;

fn enable_tcp_keepalive(stream: &tokio::net::TcpStream) {
    let sock = socket2::SockRef::from(stream);
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(15))
        .with_interval(Duration::from_secs(5));
    let _ = sock.set_tcp_keepalive(&ka);
}

#[derive(Clone)]
pub struct ServerTls {
    pub pin: String,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    config: Arc<rustls::ServerConfig>,
}

impl ServerTls {
    pub fn from_seed(seed: [u8; 32]) -> Result<Self> {
        let signing = SigningKey::from_bytes(&seed);
        let pin = format_pin(&pin_bytes(signing.verifying_key().as_bytes()));
        let key_der = signing
            .to_pkcs8_der()
            .map_err(|e| anyhow!("encode server key: {e}"))?
            .as_bytes()
            .to_vec();
        let key_pair = KeyPair::try_from(key_der.as_slice())?;
        let cert = CertificateParams::new(vec!["topaz-coord".into()])?.self_signed(&key_pair)?;
        let cert_der = cert.der().to_vec();

        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.clone())),
        )?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            pin,
            cert_der,
            key_der,
            config: Arc::new(config),
        })
    }

    /// Build a Quinn `ServerConfig` reusing the same pinned Ed25519 key for
    /// the coord's UDP/QUIC unreliable datagram relay.
    pub fn quic_relay_server_config(&self) -> Result<quinn::ServerConfig> {
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(self.cert_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der.clone())),
        )?;
        tls.alpn_protocols = vec![topaz_proto::mux::ALPN_DGRAM_RELAY.to_vec()];
        let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.initial_mtu(1350);
        transport.max_idle_timeout(Some(Duration::from_secs(30).try_into()?));
        transport.keep_alive_interval(Some(Duration::from_secs(10)));
        transport.datagram_receive_buffer_size(Some(256 * 1024));
        transport.datagram_send_buffer_size(1024 * 1024);
        server.transport = Arc::new(transport);
        Ok(server)
    }

    /// Serve `app` over TLS, inserting each connection's peer address as
    /// `ConnectInfo<SocketAddr>` and allowing WebSocket upgrades.
    pub async fn serve(&self, listener: TcpListener, app: Router) -> Result<()> {
        let acceptor = TlsAcceptor::from(self.config.clone());
        let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNS));
        loop {
            let permit = match sem.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => return Ok(()),
            };
            let (tcp, addr) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    drop(permit);
                    warn!(error = %e, "https accept failed; backing off");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let acceptor = acceptor.clone();
            let app = app.clone();
            enable_tcp_keepalive(&tcp);
            let _ = tcp.set_nodelay(true);
            tokio::spawn(async move {
                let _permit = permit;
                let tls = match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
                    Ok(Ok(tls)) => tls,
                    Ok(Err(e)) => {
                        debug!(%addr, error = %e, "TLS handshake failed");
                        return;
                    }
                    Err(_) => return,
                };
                let service = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
                    req.extensions_mut().insert(ConnectInfo(addr));
                    let mut app = app.clone();
                    app.call(req)
                });
                let mut builder = Builder::new(TokioExecutor::new());
                builder
                    .http1()
                    .timer(TokioTimer::new())
                    .header_read_timeout(Duration::from_secs(15));
                if let Err(e) = builder
                    .serve_connection_with_upgrades(TokioIo::new(tls), service)
                    .await
                {
                    debug!(%addr, error = %e, "connection ended with error");
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn serves_http1_over_tls_with_header_read_timeout() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls = ServerTls::from_seed([42u8; 32]).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route("/healthz", get(|| async { "ok" }));
        let server_tls = tls.clone();
        tokio::spawn(async move {
            let _ = server_tls.serve(listener, app).await;
        });

        // Connect with a permissive test TLS verifier and send a raw HTTP/1.1 request.
        #[derive(Debug)]
        struct NoVerify;
        impl rustls::client::danger::ServerCertVerifier for NoVerify {
            fn verify_server_cert(
                &self,
                _: &CertificateDer<'_>,
                _: &[CertificateDer<'_>],
                _: &rustls::pki_types::ServerName<'_>,
                _: &[u8],
                _: rustls::pki_types::UnixTime,
            ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _: &[u8],
                _: &CertificateDer<'_>,
                _: &rustls::DigitallySignedStruct,
            ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _: &[u8],
                _: &CertificateDer<'_>,
                _: &rustls::DigitallySignedStruct,
            ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                vec![rustls::SignatureScheme::ED25519]
            }
        }

        let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
        let mut stream = connector
            .connect(
                rustls::pki_types::ServerName::try_from("topaz-coord").unwrap(),
                tcp,
            )
            .await
            .unwrap();
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).await.unwrap();
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "unexpected response: {resp}");
        assert!(resp.ends_with("\r\n\r\nok"), "unexpected body: {resp}");
    }
}
