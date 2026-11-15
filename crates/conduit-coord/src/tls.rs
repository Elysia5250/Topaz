//! HTTPS/WSS for the control plane with a self-signed certificate. Clients
//! pin the Ed25519 key, so no domain or CA is needed.

use anyhow::{anyhow, Result};
use axum::extract::ConnectInfo;
use axum::Router;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use std::time::Duration;
use conduit_proto::auth::{format_pin, pin_bytes};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower_service::Service;
use tracing::debug;

#[derive(Clone)]
pub struct ServerTls {
    pub pin: String,
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
        let cert = CertificateParams::new(vec!["conduit-coord".into()])?.self_signed(&key_pair)?;

        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
        )?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            pin,
            config: Arc::new(config),
        })
    }

    /// Serve `app` over TLS, inserting each connection's peer address as
    /// `ConnectInfo<SocketAddr>` and allowing WebSocket upgrades.
    pub async fn serve(&self, listener: TcpListener, app: Router) -> Result<()> {
        let acceptor = TlsAcceptor::from(self.config.clone());
        loop {
            let (tcp, addr) = listener.accept().await?;
            let acceptor = acceptor.clone();
            let app = app.clone();
            tokio::spawn(async move {
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
                if let Err(e) = Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(TokioIo::new(tls), service)
                    .await
                {
                    debug!(%addr, error = %e, "connection ended with error");
                }
            });
        }
    }
}
