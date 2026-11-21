//! Round-trip probe service.
//!
//! Every fresh or reused session gets one ping: a random 16-byte echo over a
//! `PING` stream. The measured RTT lands in the shared engine status so
//! `status` can show it. The service also proves that a second service can
//! ride the same session next to sync.
//!
//! The responder side spawns itself and the engine dispatches PING streams
//! off its loop (plugin spec §5): a busy sync round on either side must not
//! delay echo answers into probe timeouts.

use std::sync::Arc;
use std::time::{Duration, Instant};
use topaz_proto::mux::service;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::{PeerInfo, Service, SharedStatus};

const NONCE: usize = 16;
/// Budget for the per-round probe in `on_session`. Generous on purpose: the
/// peer's engine loop may be mid-round when a fresh session is dialed.
const PING_TIMEOUT: Duration = Duration::from_secs(10);

pub struct PingService {
    status: Arc<SharedStatus>,
}

impl PingService {
    pub fn new(status: Arc<SharedStatus>) -> Self {
        Self { status }
    }
}

/// One nonce echo over a fresh PING stream. Shared by `on_session` and the
/// engine's idle keepalive; returns the round-trip time.
pub(crate) async fn probe(mux: &topaz_net::Multiplexer) -> anyhow::Result<Duration> {
    let mut channel = mux.open_channel(service::PING).await?;
    let nonce: [u8; NONCE] = rand::random();
    let started = Instant::now();
    channel.write_all(&nonce).await?;
    channel.flush().await?;
    tracing::trace!("probe nonce sent");
    let mut echo = [0u8; NONCE];
    channel.read_exact(&mut echo).await?;
    if echo != nonce {
        anyhow::bail!("ping echo mismatch");
    }
    Ok(started.elapsed())
}

impl Service for PingService {
    fn id(&self) -> u16 {
        service::PING
    }

    fn on_stream<'a>(
        &'a self,
        peer: &'a PeerInfo,
        channel: topaz_net::Channel,
    ) -> futures::future::BoxFuture<'a, ()> {
        Box::pin(async move {
            let peer_id = peer.device_id.clone();
            debug!(peer = %peer_id, "ping echo task spawned");
            tokio::spawn(async move {
                let mut channel = channel;
                let mut buf = [0u8; NONCE];
                match channel.read_exact(&mut buf).await {
                    Ok(_) => {
                        debug!(peer = %peer_id, "ping echo replying");
                        let _ = channel.write_all(&buf).await;
                        let _ = channel.flush().await;
                    }
                    Err(e) => debug!(peer = %peer_id, error = %e, "ping stream ended"),
                }
            });
        })
    }

    fn on_session<'a>(
        &'a self,
        peer: &'a PeerInfo,
        mux: &'a topaz_net::Multiplexer,
    ) -> futures::future::BoxFuture<'a, bool> {
        Box::pin(async move {
            match timeout(PING_TIMEOUT, probe(mux)).await {
                Ok(Ok(rtt)) => {
                    debug!(peer = %peer.device_id, ?rtt, "ping");
                    self.status.set_rtt(&peer.device_id, rtt);
                    self.status.signal();
                    true
                }
                Ok(Err(e)) => {
                    // The channel broke mid-probe: the session itself is bad,
                    // not just slow. Say so and let the engine redial.
                    warn!(peer = %peer.device_id, error = %e, "ping failed");
                    false
                }
                Err(_) => {
                    // No echo within the budget means the link is silently
                    // wedged (a healthy peer echoes in milliseconds). Report
                    // the session unhealthy so it gets torn down and re-dialed
                    // instead of hanging every later round on it.
                    warn!(peer = %peer.device_id, "ping timed out");
                    false
                }
            }
        })
    }
}
