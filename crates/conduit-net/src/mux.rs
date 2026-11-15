//! Stream multiplexer for authenticated device sessions.
//!
//! `Multiplexer` turns one ordered byte stream (a `PeerLink`, or any duplex
//! stream in tests) into any number of logical `Channel`s tagged with a
//! service id. A `Channel` implements `AsyncRead + AsyncWrite`, so an existing
//! length-prefixed protocol (the sync `Msg` lockstep) runs over it unchanged.
//!
//! Backpressure and prioritization contract:
//! - Each stream owns a FIFO queue capped at [`WRITE_BACKLOG`] bytes; a writer
//!   hitting the cap blocks in `poll_write` until the session writer drains,
//!   so a bulk sender never queues an unbounded file in memory.
//! - Frames within a stream keep their order. Between streams the writer picks
//!   small frames first (see [`SMALL_FRAME`]), so an interactive probe rides
//!   between bulk chunks instead of behind the whole backlog. The bytes of one
//!   frame already handed to the transport always complete first.
//! - `flush` is queued per stream and completes once that stream's earlier
//!   frames are written and flushed.
//!
//! Stream ids: the session initiator uses odd ids, the acceptor even, so both
//! sides open streams without coordination.

use anyhow::{anyhow, Result};
use futures::future::poll_fn;
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use conduit_proto::mux::{Frame, MAX_DATA_CHUNK, MUX_VERSION};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot, watch, Notify};
use tracing::{debug, warn};

/// Frames at or below this size count as interactive and are sent ahead of
/// bulk streams. Payload estimate per frame, not bytes on the wire.
const SMALL_FRAME: usize = 4 * 1024;
/// Per-stream queued-byte cap before `Channel::poll_write` blocks. Roughly a
/// few bulk chunks: enough to keep the transport fed, bounded memory.
const WRITE_BACKLOG: usize = 2 * 1024 * 1024;
/// How long the transport may refuse bytes before the session is declared
/// wedged. A healthy throttle never stalls a 60 KiB chunk anywhere near
/// this; a half-open peer (kernel buffers full, userspace gone) stalls
/// forever, and without this watchdog every queued write — including the
/// engine's own round hello — would park on it indefinitely.
fn write_stall() -> std::time::Duration {
    // Tests shrink the watchdog so stall paths complete in milliseconds.
    if cfg!(test) {
        std::time::Duration::from_millis(200)
    } else {
        std::time::Duration::from_secs(30)
    }
}

/// Which side of a session we are. The smaller device id is the initiator on
/// both the direct and the relay path, matching the TLS client role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxRole {
    Initiator,
    Acceptor,
}

impl MuxRole {
    fn first_stream(&self) -> u32 {
        match self {
            MuxRole::Initiator => 1,
            MuxRole::Acceptor => 2,
        }
    }
}

/// Receives inbound `Open`s for served service ids. The closure must spawn its
/// own task for the channel; when it returns, the channel is dropped.
pub type OnStream = Arc<dyn Fn(u16, Channel) + Send + Sync>;

enum Queued {
    Frame(Frame),
    Flush(oneshot::Sender<()>),
}

/// One stream's outbound queue, in FIFO order.
struct StreamQ {
    dq: VecDeque<Queued>,
    /// Rough byte estimate of queued frames, for the backlog cap.
    bytes: usize,
    /// Waker of a task blocked in `poll_write` on the cap.
    writer_waker: Option<Waker>,
    /// Monotonic stamp of the current head frame, for cross-stream ordering.
    head_seq: u64,
}

#[derive(Default)]
struct WriterQ {
    /// Session-level control frames (`Unknown` today) go ahead of everything.
    control: VecDeque<Queued>,
    streams: HashMap<u32, StreamQ>,
    seq: u64,
    shutdown: bool,
}

struct Inbound {
    /// Reader task feeds these; each open stream's `Channel` consumes.
    streams: HashMap<u32, mpsc::Sender<Vec<u8>>>,
    /// Streams whose service we do not serve: drain until Close.
    rejected: HashSet<u32>,
    closed: bool,
}

/// Dynamically updated set of extra served service ids shared with live multiplexers.
pub type DynamicServices = Arc<std::sync::RwLock<HashSet<u16>>>;

struct Shared {
    writer: Mutex<WriterQ>,
    writer_notify: Notify,
    inbound: Mutex<Inbound>,
    next_stream: AtomicU32,
    services: Vec<u16>,
    dynamic_services: Option<DynamicServices>,
    alive_tx: watch::Sender<bool>,
}

/// A multiplexed session. Cheap to clone; the session ends when the last
/// clone and every channel are dropped, or when the underlying link dies.
#[derive(Clone)]
pub struct Multiplexer {
    shared: Arc<Shared>,
}

/// One logical stream inside a `Multiplexer`.
pub struct Channel {
    shared: Arc<Shared>,
    stream: u32,
    rx: Option<mpsc::Receiver<Vec<u8>>>,
    read_buf: Vec<u8>,
    read_pos: usize,
    flush_wait: Option<oneshot::Receiver<()>>,
}

fn frame_weight(q: &Queued) -> usize {
    match q {
        Queued::Frame(Frame::Data { payload, .. }) => payload.len() + 64,
        Queued::Frame(_) => 64,
        Queued::Flush(_) => 0,
    }
}

fn is_small(q: &Queued) -> bool {
    match q {
        Queued::Frame(Frame::Data { payload, .. }) => payload.len() <= SMALL_FRAME,
        _ => true,
    }
}

impl Shared {
    fn enqueue(&self, stream: Option<u32>, item: Queued) -> std::io::Result<()> {
        let mut q = self.writer.lock().unwrap();
        if q.shutdown {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "session closed",
            ));
        }
        match stream {
            None => q.control.push_back(item),
            Some(id) => {
                // Field-level split borrow: `streams` and `seq` are disjoint.
                let w = &mut *q;
                let sq = w.streams.entry(id).or_insert_with(|| StreamQ {
                    dq: VecDeque::new(),
                    bytes: 0,
                    writer_waker: None,
                    head_seq: 0,
                });
                if sq.dq.is_empty() {
                    w.seq += 1;
                    sq.head_seq = w.seq;
                }
                sq.bytes += frame_weight(&item);
                sq.dq.push_back(item);
            }
        }
        drop(q);
        self.writer_notify.notify_one();
        Ok(())
    }

    fn queued_bytes(&self, stream: u32) -> usize {
        self.writer
            .lock()
            .unwrap()
            .streams
            .get(&stream)
            .map_or(0, |s| s.bytes)
    }

    /// Pop the next frame to send: control first, then interactive streams
    /// (small head) oldest-first, then bulk streams oldest-first. Per-stream
    /// FIFO is never violated.
    fn pop_item(&self) -> Option<Queued> {
        let mut q = self.writer.lock().unwrap();
        if let Some(item) = q.control.pop_front() {
            return Some(item);
        }
        let mut best: Option<u32> = None;
        for (id, sq) in q.streams.iter() {
            if sq.dq.is_empty() {
                continue;
            }
            let better = match best {
                None => true,
                Some(b) => {
                    let bsq = &q.streams[&b];
                    (is_small(sq.dq.front().unwrap()) && !is_small(bsq.dq.front().unwrap()))
                        || (is_small(sq.dq.front().unwrap()) == is_small(bsq.dq.front().unwrap())
                            && sq.head_seq < bsq.head_seq)
                }
            };
            if better {
                best = Some(*id);
            }
        }
        let id = best?;
        let (item, waker) = {
            let sq = q.streams.get_mut(&id)?;
            let item = sq.dq.pop_front()?;
            sq.bytes = sq.bytes.saturating_sub(frame_weight(&item));
            let waker = if sq.bytes < WRITE_BACKLOG {
                sq.writer_waker.take()
            } else {
                None
            };
            if sq.dq.is_empty() {
                q.streams.remove(&id);
            }
            (item, waker)
        };
        drop(q);
        if let Some(w) = waker {
            w.wake();
        }
        Some(item)
    }

    fn has_pending(&self) -> bool {
        let q = self.writer.lock().unwrap();
        !q.control.is_empty() || q.streams.values().any(|s| !s.dq.is_empty())
    }

    fn is_shutdown(&self) -> bool {
        self.writer.lock().unwrap().shutdown
    }
}

impl Multiplexer {
    /// Spawn the reader and writer tasks on `io`. `on_stream` receives
    /// inbound streams for the service ids in `services`; everything else is
    /// answered with `Frame::Unknown` and drained.
    pub fn start_on<S>(io: S, role: MuxRole, services: &[u16], on_stream: OnStream) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::start_on_with_dynamic(io, role, services, None, on_stream)
    }

    /// Spawn the reader and writer tasks on `io` with an optional shared
    /// [`DynamicServices`] set consulted on every inbound `Open`.
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
        let shared = Arc::new(Shared {
            writer: Mutex::new(WriterQ::default()),
            writer_notify: Notify::new(),
            inbound: Mutex::new(Inbound {
                streams: HashMap::new(),
                rejected: HashSet::new(),
                closed: false,
            }),
            next_stream: AtomicU32::new(role.first_stream()),
            services: services.to_vec(),
            dynamic_services,
            alive_tx: watch::channel(true).0,
        });

        let (read_half, write_half) = tokio::io::split(io);
        debug!(version = MUX_VERSION, role = ?role, "mux session started");
        tokio::spawn(writer_task(write_half, shared.clone()));
        tokio::spawn(reader_task(read_half, shared.clone(), on_stream));
        Self { shared }
    }

    /// Open a new logical stream to `service`. Ids come from this side's
    /// parity, so both sides can open concurrently without collision. The
    /// stream is bidirectional: peer frames for this id land in the returned
    /// channel, so the opener registers a receive end here too.
    pub async fn open_channel(&self, service: u16) -> Result<Channel> {
        let stream = self.shared.next_stream.fetch_add(2, AtomicOrdering::Relaxed);
        if stream > u32::MAX - 2 {
            return Err(anyhow!("stream id space exhausted"));
        }
        let rx = {
            let (tx, rx) = mpsc::channel::<Vec<u8>>(16);
            let mut inbound = self.shared.inbound.lock().unwrap();
            if inbound.closed {
                return Err(anyhow!("session is closed"));
            }
            inbound.streams.insert(stream, tx);
            rx
        };
        self.shared
            .enqueue(Some(stream), Queued::Frame(Frame::Open { service, stream }))?;
        Ok(Channel {
            shared: Arc::clone(&self.shared),
            stream,
            rx: Some(rx),
            read_buf: Vec::new(),
            read_pos: 0,
            flush_wait: None,
        })
    }

    /// Resolves when the underlying link dies or the session is torn down.
    pub async fn closed(&self) {
        let mut alive = self.shared.alive_tx.subscribe();
        while *alive.borrow() {
            if alive.changed().await.is_err() {
                return;
            }
        }
    }

    pub fn is_alive(&self) -> bool {
        *self.shared.alive_tx.borrow()
    }

    /// Tear the session down now: every channel sees EOF, pending writes are
    /// dropped and the writer shuts the link down. Idle sessions must be
    /// closed explicitly; dropping the handles alone does not unwind the tasks.
    pub fn close(&self) {
        teardown(&self.shared);
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        let _ = self.send_close();
    }
}

impl Channel {
    fn send_close(&mut self) -> std::io::Result<()> {
        self.rx = None;
        self.shared.inbound.lock().unwrap().streams.remove(&self.stream);
        self.send_frame(Frame::Close { stream: self.stream })
    }

    fn send_frame(&self, frame: Frame) -> std::io::Result<()> {
        self.shared.enqueue(Some(self.stream), Queued::Frame(frame))
    }
}

impl AsyncRead for Channel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        let Some(rx) = this.rx.as_mut() else {
            return Poll::Ready(Ok(())); // writer side of an inbound stream: EOF
        };
        if this.read_pos < this.read_buf.len() {
            let n = (this.read_buf.len() - this.read_pos).min(buf.remaining());
            buf.put_slice(&this.read_buf[this.read_pos..this.read_pos + n]);
            this.read_pos += n;
            if this.read_pos == this.read_buf.len() {
                this.read_buf.clear();
                this.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        match rx.poll_recv(cx) {
            Poll::Ready(Some(chunk)) => {
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    this.read_buf = chunk;
                    this.read_pos = n;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                this.rx = None;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for Channel {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let this = self.get_mut();
        let mut offset = 0;
        while offset < buf.len() {
            // Backpressure: once this stream has a full backlog queued, stop
            // accepting — bulk senders must not buffer an unbounded file in
            // memory. Bytes already accepted in this call are reported as a
            // short write; only a zero-progress call parks.
            if this.queued_bytes() >= WRITE_BACKLOG {
                let mut q = this.shared.writer.lock().unwrap();
                if q.shutdown {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "session closed",
                    )));
                }
                if let Some(sq) = q.streams.get_mut(&this.stream) {
                    if sq.bytes >= WRITE_BACKLOG {
                        return if offset > 0 {
                            Poll::Ready(Ok(offset))
                        } else {
                            sq.writer_waker = Some(cx.waker().clone());
                            Poll::Pending
                        };
                    }
                }
            }
            let end = (offset + MAX_DATA_CHUNK).min(buf.len());
            this.send_frame(Frame::Data {
                stream: this.stream,
                payload: buf[offset..end].to_vec(),
            })?;
            offset = end;
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let this = &mut *self;
        if this.flush_wait.is_none() {
            let (done, rx) = oneshot::channel();
            if this
                .shared
                .enqueue(Some(this.stream), Queued::Flush(done))
                .is_err()
            {
                return Poll::Ready(Ok(())); // writer gone; nothing to flush
            }
            this.flush_wait = Some(rx);
        }
        let rx = this.flush_wait.as_mut().unwrap();
        match Pin::new(rx).poll(cx) {
            Poll::Ready(_) => {
                this.flush_wait = None;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.send_close()?;
        Poll::Ready(Ok(()))
    }
}

impl Channel {
    fn queued_bytes(&self) -> usize {
        self.shared.queued_bytes(self.stream)
    }
}

/// One non-blocking write attempt: returns how many bytes the transport took.
async fn one_write<W: AsyncWrite + Unpin>(w: &mut W, buf: &[u8]) -> std::io::Result<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    let n = poll_fn(|cx| Pin::new(&mut *w).poll_write(cx, buf)).await?;
    Ok(n)
}

/// `one_write` under the stall watchdog: a transport that refuses bytes for
/// [`write_stall()`] means the link is wedged; the session is torn down so
/// every queued writer sees EOF instead of parking forever.
async fn one_write_watched<W: AsyncWrite + Unpin>(
    w: &mut W,
    shared: &Arc<Shared>,
    buf: &[u8],
) -> std::io::Result<usize> {
    match tokio::time::timeout(write_stall(), one_write(w, buf)).await {
        Ok(r) => r,
        Err(_) => {
            warn!("mux write stalled; tearing session down");
            teardown(shared);
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "write stalled",
            ))
        }
    }
}

async fn writer_task<W>(mut w: W, shared: Arc<Shared>)
where
    W: AsyncWrite + Unpin,
{
    // Bytes of a frame the transport only partially accepted. They must
    // complete before anything else; after they drain, the next frame is
    // picked by priority, which is where small frames jump the bulk backlog.
    let mut rest: Vec<u8> = Vec::new();
    loop {
        if !rest.is_empty() {
            let n = match one_write_watched(&mut w, &shared, &rest).await {
                Ok(0) => {
                    warn!("mux writer: transport accepted zero bytes");
                    break;
                }
                Ok(n) => n,
                Err(e) => {
                    debug!(error = %e, "mux writer failed");
                    break;
                }
            };
            rest.drain(..n);
            continue;
        }
        let item = shared.pop_item();
        let Some(item) = item else {
            if shared.is_shutdown() {
                break;
            }
            let notified = shared.writer_notify.notified();
            if shared.has_pending() {
                continue; // raced with an enqueue; pop it now
            }
            notified.await;
            continue;
        };
        match item {
            Queued::Frame(f) => {
                let mut bytes = match postcard::to_stdvec(&f) {
                    Ok(b) => b,
                    Err(e) => {
                        debug!(error = %e, "mux frame encode failed");
                        break;
                    }
                };
                if 4 + bytes.len() > conduit_proto::MAX_FRAME_BYTES {
                    warn!(len = bytes.len(), "mux frame too large; dropping");
                    continue;
                }
                let len_prefix = (bytes.len() as u32).to_be_bytes();
                let mut framed = len_prefix.to_vec();
                framed.append(&mut bytes);
                match one_write_watched(&mut w, &shared, &framed).await {
                    Ok(0) => {
                        warn!("mux writer: transport accepted zero bytes");
                        break;
                    }
                    Ok(n) if n < framed.len() => rest = framed[n..].to_vec(),
                    Ok(_) => {}
                    Err(e) => {
                        debug!(error = %e, "mux writer failed");
                        break;
                    }
                }
            }
            Queued::Flush(done) => {
                match tokio::time::timeout(write_stall(), w.flush()).await {
                    Ok(r) => {
                        let _ = r;
                        let _ = done.send(());
                    }
                    Err(_) => {
                        warn!("mux flush stalled; tearing session down");
                        teardown(&shared);
                        let _ = done.send(());
                    }
                }
            }
        }
    }
    // The link may be wedged; never hang the task on shutdown either.
    let _ = tokio::time::timeout(write_stall(), w.shutdown()).await;
}

async fn reader_task<R>(mut r: R, shared: Arc<Shared>, on_stream: OnStream)
where
    R: AsyncRead + Unpin,
{
    let reason = loop {
        let frame = match read_frame(&mut r).await {
            Ok(f) => f,
            Err(e) => break format!("{e}"),
        };
        match frame {
            Frame::Open { service, stream } => {
                let mut inbound = shared.inbound.lock().unwrap();
                if inbound.closed || inbound.streams.contains_key(&stream) {
                    warn!(%stream, "mux open for taken stream id; ignoring");
                    continue;
                }
                let accepted = shared.services.contains(&service)
                    || shared
                        .dynamic_services
                        .as_ref()
                        .is_some_and(|d| d.read().unwrap().contains(&service));
                if accepted {
                    let (tx, rx) = mpsc::channel::<Vec<u8>>(16);
                    inbound.streams.insert(stream, tx);
                    drop(inbound);
                    debug!(%stream, service, "open accepted");
                    on_stream(
                        service,
                        Channel {
                            shared: Arc::clone(&shared),
                            stream,
                            rx: Some(rx),
                            read_buf: Vec::new(),
                            read_pos: 0,
                            flush_wait: None,
                        },
                    );
                } else {
                    warn!(service, %stream, "mux open for unserved service");
                    inbound.rejected.insert(stream);
                    drop(inbound);
                    let _ = shared.enqueue(None, Queued::Frame(Frame::Unknown { service }));
                    let _ = shared.enqueue(None, Queued::Frame(Frame::Close { stream }));
                }
            }
            Frame::Data { stream, payload } => {
                let inbound = shared.inbound.lock().unwrap();
                if !inbound.rejected.contains(&stream) {
                    if let Some(tx) = inbound.streams.get(&stream) {
                        // A full queue means the service stopped reading while
                        // the peer kept sending. Dropping the chunk would
                        // silently corrupt that stream's byte sequence, so the
                        // whole session is torn down instead: both sides see
                        // EOF and the engine re-dials.
                        if let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) =
                            tx.try_send(payload)
                        {
                            drop(inbound);
                            warn!(%stream, "service stalled; tearing session down");
                            break "inbound queue full".to_string();
                        }
                    }
                }
            }
            Frame::Close { stream } => {
                let mut inbound = shared.inbound.lock().unwrap();
                inbound.rejected.remove(&stream);
                inbound.streams.remove(&stream);
            }
            Frame::Unknown { service } => {
                warn!(service, "peer does not serve this service");
            }
        }
    };
    debug!(%reason, "reader ended; tearing session down");
    teardown(&shared);
}

/// Mark the session dead, unblock every channel with EOF and stop the writer.
fn teardown(shared: &Shared) {
    {
        let mut inbound = shared.inbound.lock().unwrap();
        inbound.closed = true;
        inbound.rejected.clear();
        inbound.streams.clear();
    }
    {
        let mut q = shared.writer.lock().unwrap();
        q.shutdown = true;
        let wakers: Vec<Waker> = q
            .streams
            .values_mut()
            .filter_map(|sq| sq.writer_waker.take())
            .collect();
        drop(q);
        for w in wakers {
            w.wake();
        }
    }
    // send_replace: the flag must land even when nobody is subscribed yet.
    let _ = shared.alive_tx.send_replace(false);
    shared.writer_notify.notify_one();
}

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Frame> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > conduit_proto::MAX_FRAME_BYTES {
        anyhow::bail!("frame length {len} exceeds max");
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(postcard::from_bytes(&buf)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use conduit_proto::mux::service;
    use std::time::Duration;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    /// Two muxes facing each other over an in-memory duplex pipe.
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
                Arc::new(|_service, _ch| {}), // A accepts nothing in tests
            );
            let b = Multiplexer::start_on(b_io, MuxRole::Acceptor, services, on_b);
            Self {
                a,
                b,
                b_streams,
            }
        }
    }

    #[tokio::test]
    async fn stalled_writer_tears_session_down() {
        // A transport nobody reads: it swallows the first bufferful then
        // wedges. The watchdog must tear the session down instead of parking
        // the writer (and with it every queued frame) forever.
        let (a_io, _b_raw) = tokio::io::duplex(64);
        let a = Multiplexer::start_on(
            a_io,
            MuxRole::Initiator,
            &[service::REGISTERED_MIN],
            Arc::new(|_service, _ch| {}),
        );
        let mut ch = a.open_channel(service::REGISTERED_MIN).await.unwrap();
        let chunk = vec![0u8; 4096];
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if ch.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        })
        .await
        .expect("write must fail via the watchdog, not hang");
        assert!(!a.is_alive());
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
    async fn parallel_streams_do_not_interleave_payloads() {
        let mut pair = Pair::new(&[service::PING]);
        let s1 = pair.a.open_channel(service::PING).await.unwrap();
        let s2 = pair.a.open_channel(service::PING).await.unwrap();
        assert_ne!(s1.stream, s2.stream);
        let p1 = vec![1u8; 100_000];
        let p2 = vec![2u8; 50_000];
        let (mut c1, mut c2) = {
            let (mut s1, mut s2) = (s1, s2);
            tokio::join!(
                async {
                    s1.write_all(&p1).await.unwrap();
                    s1.flush().await.unwrap();
                },
                async {
                    s2.write_all(&p2).await.unwrap();
                    s2.flush().await.unwrap();
                }
            );
            (
                pair.b_streams.recv().await.unwrap(),
                pair.b_streams.recv().await.unwrap(),
            )
        };
        let mut got1 = vec![0u8; 100_000];
        let mut got2 = vec![0u8; 50_000];
        c1.read_exact(&mut got1).await.unwrap();
        c2.read_exact(&mut got2).await.unwrap();
        assert_eq!(got1, vec![1u8; 100_000]);
        assert_eq!(got2, vec![2u8; 50_000]);
    }

    #[tokio::test]
    async fn close_ends_stream_with_eof() {
        let mut pair = Pair::new(&[service::PING]);
        let mut ch = pair.a.open_channel(service::PING).await.unwrap();
        ch.write_all(b"x").await.unwrap();
        let mut b_ch = pair.b_streams.recv().await.unwrap();
        let mut buf = [0u8; 1];
        b_ch.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[0], b'x');
        ch.shutdown().await.unwrap();
        drop(ch);
        let n = b_ch.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn unknown_service_is_rejected_and_survives() {
        let mut pair = Pair::new(&[service::REGISTERED_MIN]);
        let bad = pair.a.open_channel(service::PING).await.unwrap();
        let mut good = pair.a.open_channel(service::REGISTERED_MIN).await.unwrap();
        good.write_all(b"data").await.unwrap();
        good.flush().await.unwrap();
        let mut b_ch = pair.b_streams.recv().await.unwrap();
        let mut buf = [0u8; 4];
        b_ch.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"data");
        assert!(pair.b.is_alive());
        drop(bad);
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

    /// Writer selection: interactive frames jump bulk queues; a stream's own
    /// order is never broken.
    #[test]
    fn writer_picks_small_frames_first() {
        let shared = Shared {
            writer: Mutex::new(WriterQ::default()),
            writer_notify: Notify::new(),
            inbound: Mutex::new(Inbound {
                streams: HashMap::new(),
                rejected: HashSet::new(),
                closed: false,
            }),
            next_stream: AtomicU32::new(1),
            services: vec![1],
            dynamic_services: None,
            alive_tx: watch::channel(true).0,
        };
        let bulk = |s: u32| Frame::Data {
            stream: s,
            payload: vec![0u8; MAX_DATA_CHUNK],
        };
        let small = |s: u32| Frame::Data {
            stream: s,
            payload: vec![0u8; 16],
        };
        // Stream 1: two bulk chunks queued first…
        shared.enqueue(Some(1), Queued::Frame(bulk(1))).unwrap();
        shared.enqueue(Some(1), Queued::Frame(bulk(1))).unwrap();
        // …stream 3 small afterwards: must be served before stream 1.
        shared.enqueue(Some(3), Queued::Frame(small(3))).unwrap();
        let pop = || match shared.pop_item().unwrap() {
            Queued::Frame(f) => f,
            _ => panic!("expected frame"),
        };
        assert!(matches!(pop(), Frame::Data { stream: 3, .. }));
        // Stream 1 keeps FIFO between its own chunks.
        assert!(matches!(pop(), Frame::Data { stream: 1, .. }));
        assert!(matches!(pop(), Frame::Data { stream: 1, .. }));
        // Two small streams are served oldest-head-first.
        shared.enqueue(Some(5), Queued::Frame(small(5))).unwrap();
        shared.enqueue(Some(7), Queued::Frame(small(7))).unwrap();
        assert!(matches!(pop(), Frame::Data { stream: 5, .. }));
        assert!(matches!(pop(), Frame::Data { stream: 7, .. }));
        assert!(shared.pop_item().is_none());
    }

    /// Backpressure: a stream with a full backlog blocks its writer until the
    /// session writer drains it, instead of buffering the file without bound.
    /// Driven by manual polls (single-thread runtime: the session tasks do not
    /// advance between awaits), so the cap is observed deterministically.
    #[tokio::test]
    async fn bulk_backlog_blocks_poll_write() {
        use futures::task::noop_waker;
        let pair = Pair::new(&[service::REGISTERED_MIN]);
        let mut ch = pair.a.open_channel(service::REGISTERED_MIN).await.unwrap();
        let big = vec![7u8; 3 * 1024 * 1024]; // 3 MiB against a 2 MiB cap
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut written = 0usize;
        let mut pending = false;
        while written < big.len() {
            match Pin::new(&mut ch).poll_write(&mut cx, &big[written..]) {
                Poll::Ready(Ok(n)) => written += n,
                Poll::Pending => {
                    pending = true;
                    break;
                }
                Poll::Ready(Err(e)) => panic!("poll_write failed: {e}"),
            }
        }
        assert!(pending, "write should have parked on the backlog cap");
        assert!(
            written >= WRITE_BACKLOG - MAX_DATA_CHUNK && written < big.len(),
            "parked after ~2 MiB, wrote {written}"
        );
        // Drain the writer queue: the parked writer must make progress again.
        while pair.a.shared.pop_item().is_some() {}
        match Pin::new(&mut ch).poll_write(&mut cx, &big[written..]) {
            Poll::Ready(Ok(n)) => assert!(n > 0),
            other => panic!("expected progress after drain, got {other:?}"),
        }
    }

    /// A service that stops reading while the peer floods tears the session
    /// down (no silent chunk loss), per the backpressure contract.
    #[tokio::test]
    async fn unread_stream_flood_tears_session_down() {
        let (tx, _hold) = mpsc::unbounded_channel::<Channel>();
        let on_b: OnStream = Arc::new(move |_s, ch| {
            let _ = tx.send(ch);
        });
        let (a_io, b_io) = duplex(1 << 20);
        let a = Multiplexer::start_on(a_io, MuxRole::Initiator, &[service::REGISTERED_MIN], Arc::new(
            |_s, _ch| {},
        ));
        let b = Multiplexer::start_on(b_io, MuxRole::Acceptor, &[service::REGISTERED_MIN], on_b);
        let mut ch = a.open_channel(service::REGISTERED_MIN).await.unwrap();
        // 20 chunks > B's 16-chunk inbound queue; B never reads, so its
        // reader tears the session down instead of dropping a chunk.
        let payload = vec![9u8; 20 * MAX_DATA_CHUNK];
        ch.write_all(&payload).await.unwrap();
        let dead = tokio::time::timeout(Duration::from_secs(10), a.closed()).await;
        assert!(dead.is_ok(), "session should have been torn down");
        assert!(!a.is_alive());
        assert!(!b.is_alive());
    }

    /// A frame length prefix beyond MAX_FRAME_BYTES kills the session reader.
    #[tokio::test]
    async fn oversize_frame_kills_session() {
        let (a_io, raw) = duplex(1 << 16);
        let a = Multiplexer::start_on(a_io, MuxRole::Initiator, &[service::REGISTERED_MIN], Arc::new(
            |_s, _ch| {},
        ));
        let mut raw = raw;
        let len = (conduit_proto::MAX_FRAME_BYTES + 1) as u32;
        raw.write_all(&len.to_be_bytes()).await.unwrap();
        let dead = tokio::time::timeout(Duration::from_secs(5), a.closed()).await;
        assert!(dead.is_ok());
        assert!(!a.is_alive());
    }

    #[tokio::test]
    async fn dynamic_service_and_unserved_eof_on_live_session() {
        let dyn_svcs: DynamicServices = Arc::new(std::sync::RwLock::new(HashSet::new()));
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
