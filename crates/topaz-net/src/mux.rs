//! Stream multiplexer for authenticated device sessions (v2).
//!
//! - **Direct QUIC links** use QUIC's native bidirectional streams directly
//!   (`quinn::Connection::open_bi` / `accept_bi`), eliminating head-of-line
//!   blocking and inheriting QUIC's per-stream flow control.
//! - **Relay links** (TCP/WSS) use `yamux` with per-stream receive-window flow
//!   control, so one slow reader can never stall other streams or tear down the
//!   entire session.
//!
//! Every logical stream starts with a 2-byte big-endian `service_id` prefix
//! written by the opener. `Channel` implements `AsyncRead + AsyncWrite` with
//! true half-close semantics (`poll_shutdown` closes only the write half).

use crate::quic::QuicStream;
use anyhow::{anyhow, Result};
use futures::future::poll_fn;
use std::collections::{HashSet, VecDeque};
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use topaz_proto::mux::MUX_VERSION;
use tracing::{debug, warn};

/// Which side of a session we are. The smaller device id is the initiator on
/// both direct and relay paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxRole {
    Initiator,
    Acceptor,
}

/// Receives inbound streams for served service ids. The closure must spawn its
/// own task for the channel; when it returns, the channel is dropped.
pub type OnStream = Arc<dyn Fn(u16, Channel) + Send + Sync>;

/// Dynamically updated set of extra served service ids shared with live multiplexers.
pub type DynamicServices = Arc<RwLock<HashSet<u16>>>;

enum YamuxCmd {
    Open(oneshot::Sender<Result<yamux::Stream>>),
    Close,
}

#[derive(Clone)]
enum MuxBackend {
    Quic(quinn::Connection),
    Yamux { cmd_tx: mpsc::Sender<YamuxCmd> },
}

/// A multiplexed session. Cheap to clone; backed by either native QUIC streams
/// (direct links) or Yamux (relay links).
#[derive(Clone)]
pub struct Multiplexer {
    backend: MuxBackend,
    alive_tx: Arc<watch::Sender<bool>>,
}

enum ChannelInner {
    Quic(QuicStream),
    Yamux(Compat<yamux::Stream>),
}

/// One logical bidirectional stream inside a [`Multiplexer`].
///
/// Implements `AsyncRead + AsyncWrite + Unpin + Send` with true half-close
/// semantics: calling `shutdown()` closes only the outbound write direction
/// without discarding unread inbound data.
pub struct Channel {
    inner: ChannelInner,
}

impl Channel {
    fn quic(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self {
            inner: ChannelInner::Quic(QuicStream { send, recv }),
        }
    }

    fn yamux(stream: yamux::Stream) -> Self {
        Self {
            inner: ChannelInner::Yamux(stream.compat()),
        }
    }
}

impl AsyncRead for Channel {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut self.get_mut().inner {
            ChannelInner::Quic(q) => Pin::new(q).poll_read(cx, buf),
            ChannelInner::Yamux(y) => Pin::new(y).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Channel {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match &mut self.get_mut().inner {
            ChannelInner::Quic(q) => Pin::new(q).poll_write(cx, buf),
            ChannelInner::Yamux(y) => Pin::new(y).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        match &mut self.get_mut().inner {
            ChannelInner::Quic(q) => Pin::new(q).poll_flush(cx),
            ChannelInner::Yamux(y) => Pin::new(y).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match &mut self.get_mut().inner {
            ChannelInner::Quic(q) => Pin::new(q).poll_shutdown(cx),
            ChannelInner::Yamux(y) => Pin::new(y).poll_shutdown(cx),
        }
    }
}

fn is_service_accepted(
    service: u16,
    static_services: &[u16],
    dynamic_services: Option<&DynamicServices>,
) -> bool {
    static_services.contains(&service)
        || dynamic_services.is_some_and(|d| d.read().unwrap().contains(&service))
}

impl Multiplexer {
    /// Start a native QUIC multistream multiplexer directly over `conn`.
    pub fn start_on_quic(
        conn: quinn::Connection,
        services: &[u16],
        dynamic_services: Option<DynamicServices>,
        on_stream: OnStream,
    ) -> Self {
        let alive_tx = Arc::new(watch::channel(true).0);
        let static_services = Arc::new(services.to_vec());

        // Accept inbound QUIC bidirectional streams and route by 2-byte service header.
        {
            let conn_r = conn.clone();
            let alive_r = alive_tx.clone();
            let static_svcs = static_services.clone();
            let dyn_svcs = dynamic_services.clone();
            tokio::spawn(async move {
                debug!(version = MUX_VERSION, "native QUIC mux session started");
                loop {
                    let (mut send, mut recv) = match conn_r.accept_bi().await {
                        Ok(pair) => pair,
                        Err(e) => {
                            debug!(error = %e, "QUIC accept_bi ended");
                            break;
                        }
                    };
                    let static_svcs = static_svcs.clone();
                    let dyn_svcs = dyn_svcs.clone();
                    let on_stream = on_stream.clone();
                    tokio::spawn(async move {
                        let mut hdr = [0u8; 2];
                        let ok = tokio::time::timeout(
                            Duration::from_secs(5),
                            recv.read_exact(&mut hdr),
                        )
                        .await;
                        let service = match ok {
                            Ok(Ok(_)) => u16::from_be_bytes(hdr),
                            _ => {
                                let _ = send.reset(1u32.into());
                                let _ = recv.stop(1u32.into());
                                return;
                            }
                        };
                        if is_service_accepted(service, &static_svcs, dyn_svcs.as_ref()) {
                            on_stream(service, Channel::quic(send, recv));
                        } else {
                            warn!(service, "QUIC stream for unserved service; resetting");
                            let _ = send.reset(1u32.into());
                            let _ = recv.stop(1u32.into());
                        }
                    });
                }
                let _ = alive_r.send_replace(false);
            });
        }

        // Watch connection closure even if no streams are opened.
        {
            let conn_w = conn.clone();
            let alive_w = alive_tx.clone();
            tokio::spawn(async move {
                conn_w.closed().await;
                let _ = alive_w.send_replace(false);
            });
        }

        Self {
            backend: MuxBackend::Quic(conn),
            alive_tx,
        }
    }

    /// Start a Yamux multiplexer on any ordered `AsyncRead + AsyncWrite` byte
    /// stream (used for TCP/WSS relay links and in-memory tests).
    pub fn start_on<S>(io: S, role: MuxRole, services: &[u16], on_stream: OnStream) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::start_on_with_dynamic(io, role, services, None, on_stream)
    }

    /// Start a Yamux multiplexer with an optional [`DynamicServices`] set
    /// consulted on every inbound stream.
    pub fn start_on_with_dynamic<S>(
        io: S,
        role: MuxRole,
        services: &[u16],
        dynamic_services: Option<DynamicServices>,
        on_stream: OnStream,
    ) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let alive_tx = Arc::new(watch::channel(true).0);
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<YamuxCmd>(64);
        let static_services = Arc::new(services.to_vec());

        let mut cfg = yamux::Config::default();
        cfg.set_max_num_streams(512);
        let mode = match role {
            MuxRole::Initiator => yamux::Mode::Client,
            MuxRole::Acceptor => yamux::Mode::Server,
        };
        let mut conn = yamux::Connection::new(io.compat(), cfg, mode);
        let alive_driver = alive_tx.clone();

        tokio::spawn(async move {
            debug!(version = MUX_VERSION, ?role, "yamux relay session started");
            let mut pending_opens: VecDeque<oneshot::Sender<Result<yamux::Stream>>> =
                VecDeque::new();
            let mut closing = false;

            let _ = poll_fn(|cx| -> Poll<()> {
                if !closing {
                    loop {
                        match cmd_rx.poll_recv(cx) {
                            Poll::Ready(Some(YamuxCmd::Open(reply))) => {
                                pending_opens.push_back(reply);
                            }
                            Poll::Ready(Some(YamuxCmd::Close)) => {
                                closing = true;
                                break;
                            }
                            Poll::Ready(None) | Poll::Pending => break,
                        }
                    }
                }

                if closing {
                    for tx in pending_opens.drain(..) {
                        let _ = tx.send(Err(anyhow!("session closed")));
                    }
                    return match conn.poll_close(cx) {
                        Poll::Ready(_) => Poll::Ready(()),
                        Poll::Pending => Poll::Pending,
                    };
                }

                // Fulfill pending outbound opens while Yamux accepts them.
                while let Some(reply) = pending_opens.pop_front() {
                    match conn.poll_new_outbound(cx) {
                        Poll::Ready(Ok(stream)) => {
                            let _ = reply.send(Ok(stream));
                        }
                        Poll::Ready(Err(e)) => {
                            let msg = format!("yamux open failed: {e}");
                            let _ = reply.send(Err(anyhow!("{msg}")));
                            for rest in pending_opens.drain(..) {
                                let _ = rest.send(Err(anyhow!("{msg}")));
                            }
                            return Poll::Ready(());
                        }
                        Poll::Pending => {
                            pending_opens.push_front(reply);
                            break;
                        }
                    }
                }

                // Always drive inbound frames (handles window updates, ACKs, and inbound opens).
                loop {
                    match conn.poll_next_inbound(cx) {
                        Poll::Ready(Some(Ok(stream))) => {
                            let static_svcs = static_services.clone();
                            let dyn_svcs = dynamic_services.clone();
                            let on_stream = on_stream.clone();
                            tokio::spawn(async move {
                                let mut ch = Channel::yamux(stream);
                                let mut hdr = [0u8; 2];
                                let ok = tokio::time::timeout(
                                    Duration::from_secs(5),
                                    ch.read_exact(&mut hdr),
                                )
                                .await;
                                let service = match ok {
                                    Ok(Ok(_)) => u16::from_be_bytes(hdr),
                                    _ => return,
                                };
                                if is_service_accepted(service, &static_svcs, dyn_svcs.as_ref()) {
                                    on_stream(service, ch);
                                } else {
                                    warn!(service, "yamux stream for unserved service; dropping");
                                }
                            });
                        }
                        Poll::Ready(Some(Err(e))) => {
                            debug!(error = %e, "yamux connection ended with error");
                            for rest in pending_opens.drain(..) {
                                let _ = rest.send(Err(anyhow!("session closed")));
                            }
                            return Poll::Ready(());
                        }
                        Poll::Ready(None) => {
                            debug!("yamux connection closed cleanly");
                            for rest in pending_opens.drain(..) {
                                let _ = rest.send(Err(anyhow!("session closed")));
                            }
                            return Poll::Ready(());
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
            })
            .await;

            let _ = alive_driver.send_replace(false);
        });

        Self {
            backend: MuxBackend::Yamux { cmd_tx },
            alive_tx,
        }
    }

    /// Open a new logical bidirectional stream to `service`.
    pub async fn open_channel(&self, service: u16) -> Result<Channel> {
        if !self.is_alive() {
            return Err(anyhow!("session is closed"));
        }
        match &self.backend {
            MuxBackend::Quic(conn) => {
                let (mut send, recv) = conn.open_bi().await?;
                send.write_all(&service.to_be_bytes()).await?;
                Ok(Channel::quic(send, recv))
            }
            MuxBackend::Yamux { cmd_tx } => {
                let (tx, rx) = oneshot::channel();
                cmd_tx
                    .send(YamuxCmd::Open(tx))
                    .await
                    .map_err(|_| anyhow!("session is closed"))?;
                let stream = rx
                    .await
                    .map_err(|_| anyhow!("session is closed"))??;
                let mut ch = Channel::yamux(stream);
                ch.write_all(&service.to_be_bytes()).await?;
                Ok(ch)
            }
        }
    }

    /// Resolves when the underlying link dies or the session is torn down.
    pub async fn closed(&self) {
        let mut alive = self.alive_tx.subscribe();
        while *alive.borrow() {
            if alive.changed().await.is_err() {
                return;
            }
        }
    }

    pub fn is_alive(&self) -> bool {
        *self.alive_tx.borrow()
    }

    /// Tear down the session immediately.
    pub fn close(&self) {
        let _ = self.alive_tx.send_replace(false);
        match &self.backend {
            MuxBackend::Quic(conn) => {
                conn.close(0u32.into(), b"session closed");
            }
            MuxBackend::Yamux { cmd_tx } => {
                let _ = cmd_tx.try_send(YamuxCmd::Close);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use topaz_proto::mux::service;

    /// Two Yamux sessions facing each other over an in-memory duplex pipe.
    struct Pair {
        a: Multiplexer,
        b: Multiplexer,
        b_streams: mpsc::UnboundedReceiver<Channel>,
    }

    impl Pair {
        fn new(services: &[u16]) -> Pair {
            let (a_io, b_io) = duplex(1 << 20);
            let (tx, b_streams) = mpsc::unbounded_channel::<Channel>();
            let on_b: OnStream = Arc::new(move |_service, ch| {
                let _ = tx.send(ch);
            });
            let a = Multiplexer::start_on(
                a_io,
                MuxRole::Initiator,
                services,
                Arc::new(|_service, _ch| {}),
            );
            let b = Multiplexer::start_on(b_io, MuxRole::Acceptor, services, on_b);
            Self { a, b, b_streams }
        }
    }

    #[tokio::test]
    async fn open_echo_over_channel() {
        let mut pair = Pair::new(&[service::REGISTERED_MIN]);
        let mut ch = pair.a.open_channel(service::REGISTERED_MIN).await.unwrap();
        ch.write_all(b"hello").await.unwrap();
        ch.flush().await.unwrap();
        let mut b_ch = pair.b_streams.recv().await.unwrap();
        let mut buf = [0u8; 5];
        b_ch.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        b_ch.write_all(b"world").await.unwrap();
        b_ch.flush().await.unwrap();
        let mut buf = [0u8; 5];
        ch.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");
    }

    #[tokio::test]
    async fn half_close_preserves_read_direction() {
        let mut pair = Pair::new(&[service::REGISTERED_MIN]);
        let mut ch = pair.a.open_channel(service::REGISTERED_MIN).await.unwrap();
        ch.write_all(b"req").await.unwrap();
        ch.shutdown().await.unwrap(); // half-close write end only

        let mut b_ch = pair.b_streams.recv().await.unwrap();
        let mut req = Vec::new();
        b_ch.read_to_end(&mut req).await.unwrap();
        assert_eq!(req, b"req");

        // B responds after reading A's EOF; A must still receive the full response.
        b_ch.write_all(b"response-after-half-close").await.unwrap();
        b_ch.shutdown().await.unwrap();

        let mut resp = Vec::new();
        ch.read_to_end(&mut resp).await.unwrap();
        assert_eq!(resp, b"response-after-half-close");
    }

    #[tokio::test]
    async fn slow_reader_does_not_kill_session_or_block_other_streams() {
        let (tx, mut rx) = mpsc::unbounded_channel::<(u16, Channel)>();
        let on_b: OnStream = Arc::new(move |svc, ch| {
            let _ = tx.send((svc, ch));
        });
        let (a_io, b_io) = duplex(1 << 20);
        let a = Multiplexer::start_on(
            a_io,
            MuxRole::Initiator,
            &[service::PING, service::REGISTERED_MIN],
            Arc::new(|_, _| {}),
        );
        let b = Multiplexer::start_on(
            b_io,
            MuxRole::Acceptor,
            &[service::PING, service::REGISTERED_MIN],
            on_b,
        );

        // Open a bulk stream on REGISTERED_MIN where B NEVER reads.
        let mut bulk = a.open_channel(service::REGISTERED_MIN).await.unwrap();
        let (svc_bulk, _stalled_b) = rx.recv().await.unwrap();
        assert_eq!(svc_bulk, service::REGISTERED_MIN);

        // Flood bulk in the background; Yamux per-stream flow control pauses
        // ONLY the bulk stream once its receive window fills.
        let flood = tokio::spawn(async move {
            let chunk = vec![9u8; 64 * 1024];
            for _ in 0..16 {
                if bulk.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        });
        tokio::time::sleep(Duration::from_millis(80)).await;

        // Session MUST still be alive and PING must complete cleanly!
        assert!(a.is_alive());
        assert!(b.is_alive());
        let mut ping_a = a.open_channel(service::PING).await.unwrap();
        ping_a.write_all(b"ok").await.unwrap();
        ping_a.flush().await.unwrap();
        let (svc_ping, mut ping_b) =
            tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .expect("ping stream must not be blocked by stalled bulk stream")
                .unwrap();
        assert_eq!(svc_ping, service::PING);
        let mut buf = [0u8; 2];
        ping_b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ok");

        flood.abort();
    }

    #[tokio::test]
    async fn parallel_streams_do_not_interleave_payloads() {
        let mut pair = Pair::new(&[service::PING]);
        let mut s1 = pair.a.open_channel(service::PING).await.unwrap();
        let mut s2 = pair.a.open_channel(service::PING).await.unwrap();
        let p1 = vec![1u8; 100_000];
        let p2 = vec![2u8; 50_000];
        let (mut c1, mut c2) = tokio::join!(
            async {
                s1.write_all(&p1).await.unwrap();
                s1.flush().await.unwrap();
            },
            async {
                s2.write_all(&p2).await.unwrap();
                s2.flush().await.unwrap();
            },
            async {
                (
                    pair.b_streams.recv().await.unwrap(),
                    pair.b_streams.recv().await.unwrap(),
                )
            }
        )
        .2;
        let mut first = [0u8; 1];
        c1.read_exact(&mut first).await.unwrap();
        let (mut ch_one, mut ch_two) = if first[0] == 1 {
            (c1, c2)
        } else {
            let mut other = [0u8; 1];
            c2.read_exact(&mut other).await.unwrap();
            assert_eq!(other[0], 1);
            (c2, c1)
        };
        let mut got1 = vec![0u8; 99_999];
        ch_one.read_exact(&mut got1).await.unwrap();
        assert!(got1.iter().all(|&b| b == 1));
        let mut got2 = vec![0u8; if first[0] == 1 { 50_000 } else { 49_999 }];
        ch_two.read_exact(&mut got2).await.unwrap();
        assert!(got2.iter().all(|&b| b == 2));
    }

    #[tokio::test]
    async fn unknown_service_is_rejected_and_survives() {
        let mut pair = Pair::new(&[service::REGISTERED_MIN]);
        let mut bad = pair.a.open_channel(service::PING).await.unwrap();
        let mut buf = [0u8; 4];
        let n = tokio::time::timeout(Duration::from_secs(2), bad.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0);

        let mut good = pair.a.open_channel(service::REGISTERED_MIN).await.unwrap();
        good.write_all(b"data").await.unwrap();
        good.flush().await.unwrap();
        let mut b_ch = pair.b_streams.recv().await.unwrap();
        b_ch.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"data");
        assert!(pair.b.is_alive());
        assert!(pair.a.is_alive());
    }

    #[tokio::test]
    async fn link_death_marks_session_dead() {
        let pair = Pair::new(&[service::REGISTERED_MIN]);
        drop(pair.b_streams);
        pair.b.close();
        let a = pair.a.clone();
        let ended = tokio::time::timeout(Duration::from_secs(5), a.closed()).await;
        assert!(ended.is_ok());
        assert!(!pair.a.is_alive());
    }

    #[tokio::test]
    async fn dynamic_service_and_unserved_eof_on_live_session() {
        let dyn_svcs: DynamicServices = Arc::new(RwLock::new(HashSet::new()));
        let (a_io, b_io) = duplex(1 << 20);
        let (tx, mut rx) = mpsc::unbounded_channel::<(u16, Channel)>();
        let on_b: OnStream = Arc::new(move |svc, ch| {
            let _ = tx.send((svc, ch));
        });
        let a = Multiplexer::start_on(
            a_io,
            MuxRole::Initiator,
            &[service::PING],
            Arc::new(|_, _| {}),
        );
        let _b = Multiplexer::start_on_with_dynamic(
            b_io,
            MuxRole::Acceptor,
            &[service::PING],
            Some(dyn_svcs.clone()),
            on_b,
        );

        // Before dynamic registration, opening service 16 returns clean EOF.
        let mut unserved = a.open_channel(16).await.unwrap();
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(2), unserved.read(&mut buf))
            .await
            .expect("unserved read must not hang")
            .unwrap();
        assert_eq!(n, 0);

        // Register service 16 dynamically on the live session and open again.
        dyn_svcs.write().unwrap().insert(16);
        let mut ch = a.open_channel(16).await.unwrap();
        ch.write_all(b"dyn").await.unwrap();
        ch.flush().await.unwrap();
        let (svc, mut b_ch) = rx.recv().await.unwrap();
        assert_eq!(svc, 16);
        let mut got = [0u8; 3];
        b_ch.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"dyn");
    }
}
