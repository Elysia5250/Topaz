use crate::state::{now_unix, utc_day, AppState};
use anyhow::{bail, Result};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Extension};
use axum::response::Response;
use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use topaz_proto::auth::{relay_signing_bytes, verify};
use topaz_proto::{RelayHello, MAX_FRAME_BYTES};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{info, warn};

/// Waiting halves older than this are dropped. Must stay >= the client's
/// PEER_WAIT (45s) so a still-waiting peer can be matched.
const PENDING_TTL: Duration = Duration::from_secs(45);
const USAGE_FLUSH: Duration = Duration::from_secs(60);
const WS_FRAME: usize = 16 * 1024;

/// Byte sent to both halves when the session starts.
const READY: u8 = 1;
const REJECTED: u8 = 0;
const OVER_LIMIT: u8 = 2;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub bytes_per_sec: u64,
    pub sessions: usize,
}

/// Token bucket that lets callers go into debt and sleep it off, so the
/// average rate holds regardless of chunk size.
#[derive(Debug)]
struct Bucket {
    rate: f64,
    capacity: f64,
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn new(bytes_per_sec: u64, now: Instant) -> Self {
        let rate = bytes_per_sec.max(1) as f64;
        // One second of burst, but never less than a typical read.
        let capacity = rate.max(64.0 * 1024.0);
        Self {
            rate,
            capacity,
            tokens: capacity,
            last: now,
        }
    }

    /// Spend `n` bytes; returns how long to wait before sending them.
    fn take(&mut self, n: usize, now: Instant) -> Duration {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.tokens -= n as f64;
        if self.tokens >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-self.tokens / self.rate)
        }
    }
}

struct AccountRelay {
    bucket: std::sync::Mutex<Bucket>,
    sessions: AtomicUsize,
    unflushed: AtomicU64,
}

struct WsConn {
    stream: DuplexStream,
    dead: Arc<AtomicBool>,
}

enum RelayConn {
    Tcp(TcpStream),
    Ws(WsConn),
}

impl RelayConn {
    #[cfg(test)]
    fn from_duplex(stream: DuplexStream) -> Self {
        Self::Ws(WsConn {
            stream,
            dead: Arc::new(AtomicBool::new(false)),
        })
    }

    fn alive(&self) -> bool {
        match self {
            Self::Tcp(s) => socket_alive(s),
            Self::Ws(ws) => !ws.dead.load(Ordering::Relaxed),
        }
    }
}

impl AsyncRead for RelayConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Self::Ws(ws) => Pin::new(&mut ws.stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for RelayConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Self::Ws(ws) => Pin::new(&mut ws.stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            Self::Ws(ws) => Pin::new(&mut ws.stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Self::Ws(ws) => Pin::new(&mut ws.stream).poll_shutdown(cx),
        }
    }
}

struct Pending {
    device_id: String,
    user_id: String,
    since: Instant,
    stream: RelayConn,
}

struct ActiveSession {
    dev_a: String,
    dev_b: String,
    cancel: tokio::sync::oneshot::Sender<()>,
}

struct Relay {
    state: Arc<AppState>,
    limits: Limits,
    pending: Mutex<HashMap<String, Pending>>,
    accounts: std::sync::Mutex<HashMap<String, Arc<AccountRelay>>>,
    active: std::sync::Mutex<HashMap<u64, ActiveSession>>,
    next_session_id: AtomicU64,
}

impl Relay {
    fn account(&self, user_id: &str) -> Arc<AccountRelay> {
        self.accounts
            .lock()
            .unwrap()
            .entry(user_id.to_string())
            .or_insert_with(|| {
                Arc::new(AccountRelay {
                    bucket: std::sync::Mutex::new(Bucket::new(
                        self.limits.bytes_per_sec,
                        Instant::now(),
                    )),
                    sessions: AtomicUsize::new(0),
                    unflushed: AtomicU64::new(0),
                })
            })
            .clone()
    }

    fn flush_usage(&self) {
        let day = utc_day(now_unix());
        let accounts: Vec<(String, Arc<AccountRelay>)> = self
            .accounts
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (user_id, acct) in accounts {
            let bytes = acct.unflushed.swap(0, Ordering::Relaxed);
            if bytes > 0 {
                if let Err(e) = self.state.db.add_usage(&user_id, &day, bytes) {
                    warn!(error = %e, "recording relay usage failed");
                    acct.unflushed.fetch_add(bytes, Ordering::Relaxed);
                }
            }
        }
    }
}

/// Handle for flushing usage on shutdown.
#[derive(Clone)]
pub struct RelayHandle(Arc<Relay>);

impl RelayHandle {
    pub fn new(state: Arc<AppState>, limits: Limits) -> Self {
        let relay = Arc::new(Relay {
            state,
            limits,
            pending: Mutex::new(HashMap::new()),
            accounts: std::sync::Mutex::new(HashMap::new()),
            active: std::sync::Mutex::new(HashMap::new()),
            next_session_id: AtomicU64::new(1),
        });
        {
            let relay = relay.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(USAGE_FLUSH).await;
                    relay.flush_usage();
                }
            });
        }
        Self(relay)
    }

    pub fn flush_usage(&self) {
        self.0.flush_usage();
    }

    /// Drop any pending or active relay sessions involving a revoked device.
    pub async fn kick_device(&self, device_id: &str) {
        {
            let mut pending = self.0.pending.lock().await;
            pending.retain(|_, p| p.device_id != device_id);
        }
        let cancels: Vec<tokio::sync::oneshot::Sender<()>> = {
            let mut active = self.0.active.lock().unwrap();
            let ids: Vec<u64> = active
                .iter()
                .filter(|(_, s)| s.dev_a == device_id || s.dev_b == device_id)
                .map(|(&id, _)| id)
                .collect();
            ids.into_iter()
                .filter_map(|id| active.remove(&id).map(|s| s.cancel))
                .collect()
        };
        for tx in cancels {
            let _ = tx.send(());
        }
    }

    pub async fn listen_tcp(&self, addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        info!(
            %addr,
            mbps = self.0.limits.bytes_per_sec * 8 / 1_000_000,
            sessions = self.0.limits.sessions,
            "relay listening"
        );
        let relay = self.0.clone();
        tokio::spawn(async move {
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(c) => c,
                    Err(e) => {
                        warn!(error = %e, "relay accept failed");
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                };
                let relay = relay.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_tcp(stream, peer, relay).await {
                        warn!(error = %e, %peer, "relay connection rejected");
                    }
                });
            }
        });
        Ok(())
    }
}

pub async fn start(addr: SocketAddr, state: Arc<AppState>, limits: Limits) -> Result<RelayHandle> {
    let relay = RelayHandle::new(state, limits);
    relay.listen_tcp(addr).await?;
    Ok(relay)
}

/// HTTP upgrade for `/v1/relay`. Hello/auth is in-band, same as TCP.
pub async fn ws_upgrade(
    Extension(relay): Extension<RelayHandle>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| async move {
        if let Err(e) = handle_ws(socket, addr, relay).await {
            warn!(error = %e, %addr, "relay websocket rejected");
        }
    })
}

fn session_key(a: &str, b: &str) -> String {
    if a <= b {
        format!("{a}|{b}")
    } else {
        format!("{b}|{a}")
    }
}

async fn read_hello(stream: &mut RelayConn) -> Result<RelayHello> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_FRAME_BYTES.min(4096) {
            bail!("relay hello too large");
        }
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;
        Ok(postcard::from_bytes(&buf)?)
    })
    .await?
}

/// Both ends must be active devices of the same account. Returns the account.
fn authorize(state: &AppState, hello: &RelayHello) -> Result<String> {
    let Some(me) = state.active_device(&hello.device_id) else {
        bail!("unknown or revoked device {}", hello.device_id);
    };
    let msg = relay_signing_bytes(&hello.device_id, &hello.peer_id, hello.time, &hello.nonce);
    if !verify(&me.pubkey, &msg, &hello.sig) {
        bail!("bad relay signature from {}", hello.device_id);
    }
    if !state.fresh(hello.time, &hello.nonce) {
        bail!("stale or replayed relay hello");
    }
    match state.active_device(&hello.peer_id) {
        Some(peer) if peer.user_id == me.user_id => Ok(me.user_id),
        _ => bail!(
            "peer {} is not an active device of the same account",
            hello.peer_id
        ),
    }
}

fn enable_tcp_keepalive(stream: &TcpStream) {
    let sock = socket2::SockRef::from(stream);
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(10))
        .with_interval(Duration::from_secs(5));
    if let Err(e) = sock.set_tcp_keepalive(&ka) {
        warn!(error = %e, "failed to enable relay TCP keepalive");
    }
}

/// True unless the peer has closed or the socket is already in error.
/// A waiting client that timed out sends FIN; `try_read` then returns 0.
fn socket_alive(stream: &TcpStream) -> bool {
    let mut buf = [0u8; 1];
    match stream.try_read(&mut buf) {
        Ok(0) => false,
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => true,
        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => true,
        Err(_) => false,
    }
}

fn take_partner(
    map: &mut HashMap<String, Pending>,
    key: &str,
    device_id: &str,
    user_id: &str,
) -> Option<Pending> {
    map.retain(|_, p| p.since.elapsed() < PENDING_TTL);
    match map.remove(key) {
        Some(p) if p.device_id != device_id && p.user_id == user_id => {
            if p.stream.alive() {
                Some(p)
            } else {
                info!(session = %key, from = %p.device_id, "dropped dead pending relay socket");
                None
            }
        }
        Some(_) => None,
        None => None,
    }
}

async fn signal_ready(stream: &mut RelayConn) -> std::io::Result<()> {
    stream.write_all(&[READY]).await?;
    stream.flush().await?;
    Ok(())
}

fn park_pending(map: &mut HashMap<String, Pending>, key: String, pending: Pending) {
    map.retain(|_, p| p.since.elapsed() < PENDING_TTL);
    map.insert(key, pending);
}

const WS_PING_EVERY: Duration = Duration::from_secs(30);
const WS_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

fn bridge_axum_ws(ws: WebSocket) -> RelayConn {
    let (mut sink, mut stream) = ws.split();
    let (local, remote) = tokio::io::duplex(64 * 1024);
    let (mut remote_r, mut remote_w) = tokio::io::split(remote);
    let dead = Arc::new(AtomicBool::new(false));
    let flag = dead.clone();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Message>(32);

    // Writer task exclusively owns the WS sink, preventing duplex deadlocks.
    let writer = tokio::spawn(async move {
        let mut ping = tokio::time::interval(WS_PING_EVERY);
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ping.tick().await;
        loop {
            tokio::select! {
                msg = rx.recv() => {
                    let Some(msg) = msg else { break; };
                    if sink.send(msg).await.is_err() {
                        break;
                    }
                }
                _ = ping.tick() => {
                    if sink.send(Message::Ping(Vec::new().into())).await.is_err() {
                        break;
                    }
                }
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

    // Inbound pump: WS stream -> duplex (with idle timeout).
    let tx_in = tx.clone();
    let inbound = tokio::spawn(async move {
        loop {
            let next = match tokio::time::timeout(WS_IDLE_TIMEOUT, stream.next()).await {
                Ok(item) => item,
                Err(_) => break,
            };
            match next {
                Some(Ok(Message::Binary(b))) => {
                    if remote_w.write_all(&b).await.is_err() {
                        break;
                    }
                }
                Some(Ok(Message::Ping(p))) => {
                    let _ = tx_in.try_send(Message::Pong(p));
                }
                Some(Ok(Message::Pong(_))) | Some(Ok(Message::Text(_))) => {}
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
            }
        }
        let _ = remote_w.shutdown().await;
    });

    drop(tx);
    tokio::spawn(async move {
        let mut outbound = outbound;
        let mut inbound = inbound;
        tokio::select! {
            _ = &mut outbound => { inbound.abort(); }
            _ = &mut inbound => { outbound.abort(); }
        }
        flag.store(true, Ordering::Relaxed);
        let _ = writer.await;
    });

    RelayConn::Ws(WsConn {
        stream: local,
        dead,
    })
}

async fn handle_tcp(stream: TcpStream, peer: SocketAddr, relay: Arc<Relay>) -> Result<()> {
    let _ = stream.set_nodelay(true);
    enable_tcp_keepalive(&stream);
    handle_conn(RelayConn::Tcp(stream), peer, relay).await
}

async fn handle_ws(socket: WebSocket, peer: SocketAddr, relay: RelayHandle) -> Result<()> {
    handle_conn(bridge_axum_ws(socket), peer, relay.0).await
}

async fn handle_conn(mut stream: RelayConn, peer_addr: SocketAddr, relay: Arc<Relay>) -> Result<()> {
    let hello = read_hello(&mut stream).await?;
    let user_id = match authorize(&relay.state, &hello) {
        Ok(u) => u,
        Err(e) => {
            let _ = stream.write_all(&[REJECTED]).await;
            return Err(e);
        }
    };

    let key = session_key(&hello.device_id, &hello.peer_id);
    let mut mine = Pending {
        device_id: hello.device_id,
        user_id: user_id.clone(),
        since: Instant::now(),
        stream,
    };

    let mut map = relay.pending.lock().await;
    let partner = take_partner(&mut map, &key, &mine.device_id, &mine.user_id);
    let Some(mut other) = partner else {
        info!(session = %key, from = %mine.device_id, %peer_addr, "relay waiting for peer");
        park_pending(&mut map, key, mine);
        return Ok(());
    };
    drop(map);

    let acct = relay.account(&user_id);
    if acct.sessions.fetch_add(1, Ordering::AcqRel) >= relay.limits.sessions {
        acct.sessions.fetch_sub(1, Ordering::AcqRel);
        let _ = mine.stream.write_all(&[OVER_LIMIT]).await;
        let _ = other.stream.write_all(&[OVER_LIMIT]).await;
        bail!("account {user_id} is at its relay session limit");
    }

    // Signal the waiting half first: it is the one that may have gone away.
    // If that write fails, the new arriver never saw READY and can wait again.
    if let Err(e) = signal_ready(&mut other.stream).await {
        acct.sessions.fetch_sub(1, Ordering::AcqRel);
        warn!(error = %e, session = %key, "waiting relay socket died; parking new arriver");
        if mine.stream.alive() {
            let mut map = relay.pending.lock().await;
            park_pending(&mut map, key, mine);
        }
        return Ok(());
    }
    if let Err(e) = signal_ready(&mut mine.stream).await {
        acct.sessions.fetch_sub(1, Ordering::AcqRel);
        warn!(
            error = %e,
            session = %key,
            "new relay socket died after partner was signaled; dropping both"
        );
        return Ok(());
    }

    info!(session = %key, account = %user_id, "relay session established");
    let sid = relay.next_session_id.fetch_add(1, Ordering::Relaxed);
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
    relay.active.lock().unwrap().insert(
        sid,
        ActiveSession {
            dev_a: mine.device_id.clone(),
            dev_b: other.device_id.clone(),
            cancel: cancel_tx,
        },
    );
    let relay_for_task = relay.clone();
    tokio::spawn(async move {
        let pump = async {
            match (mine.stream, other.stream) {
                (RelayConn::Tcp(a), RelayConn::Tcp(b)) => {
                    let (ar, aw) = a.into_split();
                    let (br, bw) = b.into_split();
                    tokio::select! {
                        _ = pump_tcp(ar, bw, acct.clone()) => {}
                        _ = pump_tcp(br, aw, acct.clone()) => {}
                    }
                }
                (a, b) => {
                    let (ar, aw) = tokio::io::split(a);
                    let (br, bw) = tokio::io::split(b);
                    tokio::select! {
                        _ = pump_any(ar, bw, acct.clone()) => {}
                        _ = pump_any(br, aw, acct.clone()) => {}
                    }
                }
            }
        };
        tokio::select! {
            _ = pump => {}
            _ = cancel_rx => {
                info!(session = %key, "relay session terminated due to device revocation");
            }
        }
        relay_for_task.active.lock().unwrap().remove(&sid);
        acct.sessions.fetch_sub(1, Ordering::AcqRel);
    });
    Ok(())
}

/// Copy one direction, charging the account's bucket before each write.
async fn pump_tcp(
    mut r: OwnedReadHalf,
    mut w: OwnedWriteHalf,
    acct: Arc<AccountRelay>,
) -> std::io::Result<()> {
    pump_loop(&mut r, &mut w, acct).await
}

async fn pump_any<R, W>(mut r: R, mut w: W, acct: Arc<AccountRelay>) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pump_loop(&mut r, &mut w, acct).await
}

async fn pump_loop<R, W>(r: &mut R, w: &mut W, acct: Arc<AccountRelay>) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; WS_FRAME];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            let _ = w.shutdown().await;
            return Ok(());
        }
        let wait = acct.bucket.lock().unwrap().take(n, Instant::now());
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
        w.write_all(&buf[..n]).await?;
        acct.unflushed.fetch_add(n as u64, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use topaz_proto::auth::{derive_id, DeviceCert};
    use topaz_proto::RelayHello;

    #[test]
    fn bucket_enforces_average_rate() {
        let start = Instant::now();
        let mut b = Bucket::new(100_000, start);
        // The initial burst is free.
        assert_eq!(b.take(100_000, start), Duration::ZERO);
        // The next 50 KB at the same instant must wait half a second.
        let wait = b.take(50_000, start);
        assert!((wait.as_secs_f64() - 0.5).abs() < 1e-6, "{wait:?}");
        // After that wait has passed (plus the debt), the bucket is back at zero.
        let later = start + Duration::from_millis(500);
        assert_eq!(b.take(0, later), Duration::ZERO);
        // Refill never exceeds capacity.
        let much_later = start + Duration::from_secs(100);
        assert_eq!(b.take(100_000, much_later), Duration::ZERO);
        assert!(b.take(1, much_later) > Duration::ZERO);
    }

    #[test]
    fn session_key_is_order_independent() {
        assert_eq!(session_key("aaa", "bbb"), session_key("bbb", "aaa"));
        assert_eq!(session_key("aaa", "bbb"), "aaa|bbb");
        assert_eq!(session_key("dev-z", "dev-a"), "dev-a|dev-z");
        assert_eq!(session_key("same", "same"), "same|same");
    }

    #[tokio::test]
    async fn socket_alive_detects_peer_close() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        assert!(socket_alive(&server));
        drop(client);
        let mut dead = false;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if !socket_alive(&server) {
                dead = true;
                break;
            }
        }
        assert!(dead, "closed peer should look dead to the waiting half");
    }

    fn pk_hex(k: &SigningKey) -> String {
        hex::encode(k.verifying_key().as_bytes())
    }

    fn cert(root: &SigningKey, device: &SigningKey, name: &str) -> DeviceCert {
        let mut c = DeviceCert {
            user_id: derive_id(root.verifying_key().as_bytes()),
            user_pubkey: pk_hex(root),
            device_id: derive_id(device.verifying_key().as_bytes()),
            device_pubkey: pk_hex(device),
            name: name.into(),
            issued_at: 1,
            issuer_pubkey: pk_hex(root),
            sig: String::new(),
        };
        c.sig = hex::encode(root.sign(&c.signing_bytes()).to_bytes());
        c
    }

    fn hello(device: &SigningKey, peer_id: &str, nonce_byte: u8) -> (RelayHello, Vec<u8>) {
        let device_id = derive_id(device.verifying_key().as_bytes());
        let nonce = hex::encode([nonce_byte; 16]);
        let time = now_unix();
        let msg = relay_signing_bytes(&device_id, peer_id, time, &nonce);
        let hello = RelayHello {
            device_id,
            peer_id: peer_id.to_string(),
            time,
            nonce,
            sig: hex::encode(device.sign(&msg).to_bytes()),
        };
        let body = postcard::to_stdvec(&hello).unwrap();
        let mut framed = Vec::new();
        framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
        framed.extend_from_slice(&body);
        (hello, framed)
    }

    async fn test_relay() -> (RelayHandle, SigningKey, SigningKey) {
        let mut n = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut n);
        let path = std::env::temp_dir().join(format!(
            "ss-relay-{}-{}.db",
            std::process::id(),
            u64::from_le_bytes(n)
        ));
        let db = crate::db::Db::open(&path).unwrap();
        let root = SigningKey::from_bytes(&[11u8; 32]);
        let a = SigningKey::from_bytes(&[12u8; 32]);
        let b = SigningKey::from_bytes(&[13u8; 32]);
        let ca = cert(&root, &a, "a");
        let cb = cert(&root, &b, "b");
        let invite = db.create_invites(1, now_unix()).unwrap().pop().unwrap();
        db.create_account(&invite, &ca, now_unix()).unwrap();
        db.insert_device(&cb).unwrap();
        let state = Arc::new(AppState::new(db, None, 7723, None, 7722));
        let relay = RelayHandle::new(
            state,
            Limits {
                bytes_per_sec: 1_000_000,
                sessions: 8,
            },
        );
        (relay, a, b)
    }

    async fn write_hello_wait_ready(stream: &mut DuplexStream, framed: &[u8]) -> u8 {
        stream.write_all(framed).await.unwrap();
        stream.flush().await.unwrap();
        let mut ready = [0u8; 1];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut ready))
            .await
            .unwrap()
            .unwrap();
        ready[0]
    }

    #[tokio::test]
    async fn websocket_halves_pair_and_forward() {
        let (relay, ka, kb) = test_relay().await;
        let a_id = derive_id(ka.verifying_key().as_bytes());
        let b_id = derive_id(kb.verifying_key().as_bytes());
        let (_, hello_a) = hello(&ka, &b_id, 1);
        let (_, hello_b) = hello(&kb, &a_id, 2);

        let (mut client_a, server_a) = tokio::io::duplex(64 * 1024);
        let (mut client_b, server_b) = tokio::io::duplex(64 * 1024);
        let r1 = relay.0.clone();
        let r2 = relay.0.clone();
        tokio::spawn(async move {
            handle_conn(
                RelayConn::from_duplex(server_a),
                "127.0.0.1:1".parse().unwrap(),
                r1,
            )
            .await
            .unwrap();
        });
        tokio::spawn(async move {
            handle_conn(
                RelayConn::from_duplex(server_b),
                "127.0.0.1:2".parse().unwrap(),
                r2,
            )
            .await
            .unwrap();
        });

        let (ra, rb) = tokio::join!(
            write_hello_wait_ready(&mut client_a, &hello_a),
            write_hello_wait_ready(&mut client_b, &hello_b),
        );
        assert_eq!(ra, READY);
        assert_eq!(rb, READY);

        client_a.write_all(b"ping-ws").await.unwrap();
        client_a.flush().await.unwrap();
        let mut buf = [0u8; 7];
        tokio::time::timeout(Duration::from_secs(2), client_b.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"ping-ws");
    }

    #[tokio::test]
    async fn tcp_and_websocket_halves_pair() {
        let (relay, ka, kb) = test_relay().await;
        let a_id = derive_id(ka.verifying_key().as_bytes());
        let b_id = derive_id(kb.verifying_key().as_bytes());
        let (_, hello_a) = hello(&ka, &b_id, 3);
        let (_, hello_b) = hello(&kb, &a_id, 4);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let r_tcp = relay.0.clone();
        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            handle_tcp(stream, peer, r_tcp).await.unwrap();
        });
        let mut tcp = TcpStream::connect(addr).await.unwrap();

        let (mut client_ws, server_ws) = tokio::io::duplex(64 * 1024);
        let r_ws = relay.0.clone();
        tokio::spawn(async move {
            handle_conn(
                RelayConn::from_duplex(server_ws),
                "127.0.0.1:9".parse().unwrap(),
                r_ws,
            )
            .await
            .unwrap();
        });

        let write_tcp = async {
            tcp.write_all(&hello_a).await.unwrap();
            tcp.flush().await.unwrap();
            let mut ready = [0u8; 1];
            tokio::time::timeout(Duration::from_secs(5), tcp.read_exact(&mut ready))
                .await
                .unwrap()
                .unwrap();
            ready[0]
        };
        let (ra, rb) = tokio::join!(
            write_tcp,
            write_hello_wait_ready(&mut client_ws, &hello_b),
        );
        assert_eq!(ra, READY);
        assert_eq!(rb, READY);

        tcp.write_all(b"mixed").await.unwrap();
        let mut buf = [0u8; 5];
        tokio::time::timeout(Duration::from_secs(2), client_ws.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"mixed");
    }
}
