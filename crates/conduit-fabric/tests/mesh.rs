use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use conduit_core::{generate_recovery_code, issue_cert, AccountKey, DeviceIdentity};
use conduit_fabric::{
    build, EngineDeps, EngineHandle, PeerInfo, PingService, Service, SharedStatus,
};
use conduit_net::{new_trust_store, Channel, ConnectionKind, CoordClient, QuicEndpoint, RelayAddrs};
use conduit_proto::auth::{format_pin, pin_bytes, HDR_DEVICE};
use conduit_proto::{
    DeviceEntry, PeerEndpoints, RegisterRequest, RegisterResponse, SignalEnvelope,
};
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use futures::future::BoxFuture;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;

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
        let cert = CertificateParams::new(vec!["conduit-coord".into()])
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
                                return Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from(
                                    json,
                                ))));
                            }
                            if method == Method::POST && path == "/v1/register" {
                                if let Ok(reg) = serde_json::from_slice::<RegisterRequest>(&body) {
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

struct EchoService;

impl Service for EchoService {
    fn id(&self) -> u16 {
        16
    }

    fn on_stream<'a>(&'a self, _peer: &'a PeerInfo, mut channel: Channel) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                while let Ok(n) = channel.read(&mut buf).await {
                    if n == 0 || channel.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    let _ = channel.flush().await;
                }
            });
        })
    }
}

struct NodeHarness {
    id: DeviceIdentity,
    handle: EngineHandle,
    status: Arc<SharedStatus>,
    _task: tokio::task::JoinHandle<()>,
}

fn spawn_node(
    id: DeviceIdentity,
    user_pubkey: String,
    coord: &MockCoord,
    sig_out: mpsc::Sender<SignalEnvelope>,
    sig_in: mpsc::Receiver<SignalEnvelope>,
) -> NodeHarness {
    let trust = new_trust_store();
    let (quic, _) = QuicEndpoint::bind(&id, &trust, None).unwrap();
    let ep = SocketAddr::from(([127, 0, 0, 1], quic.local_addr.port())).to_string();
    coord
        .endpoints
        .lock()
        .unwrap()
        .insert(id.device_id.clone(), vec![ep.clone()]);

    let client = CoordClient::new(&coord.url, &coord.pin)
        .unwrap()
        .with_identity(id.clone());
    let relay = RelayAddrs {
        tcp: "127.0.0.1:1".into(),
        ws: "wss://127.0.0.1:1/v1/relay".into(),
        coord_tls: client.tls_config(),
    };
    let status = Arc::new(SharedStatus::new());
    let st_for_svc = status.clone();
    let (handle, fut) = build(
        EngineDeps {
            identity: id.clone(),
            account_user_pubkey: user_pubkey,
            coord: client,
            trust,
            quic,
            endpoints: vec![ep.clone()],
            relay,
            signal_tx: sig_out,
            signal_rx: sig_in,
            force_relay: false,
            enable_mdns: false,
        },
        move |_| {
            vec![
                Arc::new(PingService::new(st_for_svc)) as Arc<dyn Service>,
                Arc::new(EchoService) as Arc<dyn Service>,
            ]
        },
        status.clone(),
    );
    let task = tokio::spawn(async move {
        let _ = fut.await;
    });
    NodeHarness {
        id,
        handle,
        status,
        _task: task,
    }
}

fn make_account_pair() -> (String, DeviceIdentity, DeviceIdentity, Vec<DeviceEntry>) {
    let rec = generate_recovery_code();
    let root = AccountKey::from_recovery(&rec).unwrap();
    let mut a = DeviceIdentity::generate().unwrap();
    let mut b = DeviceIdentity::generate().unwrap();
    if a.device_id > b.device_id {
        std::mem::swap(&mut a, &mut b);
    }
    let cert_a = issue_cert(
        &root.signing,
        &root.user_id,
        &root.user_pubkey,
        &a.pubkey_hex,
        "node-a",
    )
    .unwrap();
    let cert_b = issue_cert(
        &root.signing,
        &root.user_id,
        &root.user_pubkey,
        &b.pubkey_hex,
        "node-b",
    )
    .unwrap();
    let mut e_a = DeviceEntry::new(cert_a, None);
    e_a.virtual_ip = Some("100.64.0.1".into());
    e_a.dns_name = Some("node-a".into());
    let mut e_b = DeviceEntry::new(cert_b, None);
    e_b.virtual_ip = Some("100.64.0.2".into());
    e_b.dns_name = Some("node-b".into());
    let entries = vec![e_a, e_b];
    (root.user_pubkey, a, b, entries)
}

async fn wait_for_session(handle: &EngineHandle, peer_id: &str) {
    tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            let st = handle.status();
            if st
                .sessions
                .iter()
                .any(|(id, kind)| id == peer_id && *kind == ConnectionKind::Direct)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .expect("session did not come up in time");
}

#[tokio::test]
async fn eager_mesh_connects_measures_rtt_and_exchanges_datagrams_and_streams() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (user_pubkey, a, b, entries) = make_account_pair();
    let coord = MockCoord::start(entries).await;

    let (a_in_tx, a_in_rx) = mpsc::channel(32);
    let (b_in_tx, b_in_rx) = mpsc::channel(32);
    let (hub_tx, mut hub_rx) = mpsc::channel::<SignalEnvelope>(64);
    let a_id_str = a.device_id.clone();
    let b_id_str = b.device_id.clone();
    tokio::spawn(async move {
        while let Some(env) = hub_rx.recv().await {
            if env.to == a_id_str {
                let _ = a_in_tx.send(env).await;
            } else if env.to == b_id_str {
                let _ = b_in_tx.send(env).await;
            }
        }
    });

    let node_a = spawn_node(a, user_pubkey.clone(), &coord, hub_tx.clone(), a_in_rx);
    let node_b = spawn_node(b, user_pubkey, &coord, hub_tx, b_in_rx);

    wait_for_session(&node_a.handle, &node_b.id.device_id).await;
    wait_for_session(&node_b.handle, &node_a.id.device_id).await;

    let st_a = node_a.handle.status();
    assert_eq!(st_a.self_addr.virtual_ip.as_deref(), Some("100.64.0.1"));
    assert_eq!(st_a.self_addr.dns_name.as_deref(), Some("node-a"));
    assert_eq!(
        st_a.peer_addr(&node_b.id.device_id)
            .and_then(|v| v.virtual_ip.as_deref()),
        Some("100.64.0.2")
    );

    // Wait for PingService RTT probe on smaller-ID side.
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if node_a
                .status
                .engine()
                .rtts
                .iter()
                .any(|(id, _)| id == &node_b.id.device_id)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("ping RTT should be recorded");

    // Bidirectional datagrams via EngineHandle fast path.
    let (da_tx, mut da_rx) = mpsc::channel(16);
    let (db_tx, mut db_rx) = mpsc::channel(16);
    node_a.handle.set_datagram_sink(da_tx);
    node_b.handle.set_datagram_sink(db_tx);

    node_a
        .handle
        .send_datagram(&node_b.id.device_id, Bytes::from_static(b"ip-packet-1"))
        .unwrap();
    let (from_a, pkt_a) = tokio::time::timeout(Duration::from_secs(2), db_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from_a, node_a.id.device_id);
    assert_eq!(pkt_a, Bytes::from_static(b"ip-packet-1"));

    node_b
        .handle
        .send_datagram(&node_a.id.device_id, Bytes::from_static(b"ip-packet-2"))
        .unwrap();
    let (from_b, pkt_b) = tokio::time::timeout(Duration::from_secs(2), da_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from_b, node_b.id.device_id);
    assert_eq!(pkt_b, Bytes::from_static(b"ip-packet-2"));

    // Larger-ID node opens a service_id = 16 stream to smaller-ID node.
    let mut ch = node_b
        .handle
        .open(&node_a.id.device_id, 16)
        .await
        .unwrap();
    ch.write_all(b"agent-rpc").await.unwrap();
    ch.flush().await.unwrap();
    let mut resp = [0u8; 9];
    ch.read_exact(&mut resp).await.unwrap();
    assert_eq!(&resp, b"agent-rpc");
}

#[tokio::test]
async fn late_joiner_clears_backoff_and_connects() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (user_pubkey, a, b, entries) = make_account_pair();
    let coord = MockCoord::start(entries).await;

    let (a_in_tx, a_in_rx) = mpsc::channel(32);
    let (b_in_tx, b_in_rx) = mpsc::channel(32);
    let (hub_tx, mut hub_rx) = mpsc::channel::<SignalEnvelope>(64);
    let a_id_str = a.device_id.clone();
    let b_id_str = b.device_id.clone();
    tokio::spawn(async move {
        while let Some(env) = hub_rx.recv().await {
            if env.to == a_id_str {
                let _ = a_in_tx.send(env).await;
            } else if env.to == b_id_str {
                let _ = b_in_tx.send(env).await;
            }
        }
    });

    // Start A first while B has no endpoints yet (enters 15s backoff).
    let node_a = spawn_node(a, user_pubkey.clone(), &coord, hub_tx.clone(), a_in_rx);
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(node_a.handle.status().sessions.is_empty());

    // Start B later; its startup sync clears A's backoff immediately (< 5s).
    let node_b = spawn_node(b, user_pubkey, &coord, hub_tx, b_in_rx);
    wait_for_session(&node_a.handle, &node_b.id.device_id).await;
    wait_for_session(&node_b.handle, &node_a.id.device_id).await;
}
