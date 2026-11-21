//! CLI-side client for the daemon's local control API: HTTP/1.1 over the
//! data-dir's Unix socket. Connect failures surface as `DaemonDown` so
//! callers can fall back to direct file access — the daemon is simply not
//! running, which is the supported bootstrap mode.

use anyhow::{bail, Result};
use http_body_util::{BodyExt, Full};
use hyper::{Request, StatusCode};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// The daemon is not reachable — its control socket does not answer.
#[derive(Debug)]
pub struct DaemonDown(pub PathBuf);

impl std::fmt::Display for DaemonDown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "daemon not running (control socket {:?} does not answer)", self.0)
    }
}

impl std::error::Error for DaemonDown {}

pub struct ControlClient {
    path: PathBuf,
}

impl ControlClient {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            path: topaz_core::control_socket_path(data_dir),
        }
    }

    /// The client when a daemon answers, None otherwise (direct-mode signal).
    pub async fn try_daemon(data_dir: &Path) -> Option<Self> {
        let client = Self::new(data_dir);
        match client
            .get_with_timeout("/healthz", Duration::from_secs(2))
            .await
        {
            Ok(_) => Some(client),
            Err(_) => None,
        }
    }

    pub async fn get(&self, path_and_query: &str) -> Result<Value> {
        self.get_with_timeout(path_and_query, DEFAULT_TIMEOUT).await
    }

    pub async fn get_with_timeout(&self, path_and_query: &str, timeout: Duration) -> Result<Value> {
        let (status, value) = self.request("GET", path_and_query, None, timeout).await?;
        ensure_ok(status, value)
    }

    pub async fn post(&self, path_and_query: &str, body: Option<&Value>) -> Result<Value> {
        let bytes = body
            .map(serde_json::to_vec)
            .transpose()?
            .map(hyper::body::Bytes::from);
        let (status, value) = self
            .request("POST", path_and_query, bytes, DEFAULT_TIMEOUT)
            .await?;
        ensure_ok(status, value)
    }

    async fn request(
        &self,
        method: &str,
        path_and_query: &str,
        body: Option<hyper::body::Bytes>,
        timeout: Duration,
    ) -> Result<(u16, Value)> {
        let path = self.path.clone();
        let fut = async {
            let stream = tokio::net::UnixStream::connect(&self.path)
                .await
                .map_err(|_| DaemonDown(self.path.clone()))?;
            let io = hyper_util::rt::TokioIo::new(stream);
            let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let mut builder = Request::builder()
                .method(method)
                .uri(format!("http://localhost{path_and_query}"))
                .header("connection", "close");
            if body.is_some() {
                builder = builder.header("content-type", "application/json");
            }
            let req = builder.body(Full::new(body.unwrap_or_default()))?;
            let res = sender.send_request(req).await?;
            let status = res.status();
            let bytes = res.into_body().collect().await?.to_bytes();
            let value = if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap_or(Value::Null)
            };
            Ok((status.as_u16(), value))
        };
        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| DaemonDown(path))?
    }
}

fn ensure_ok(status: u16, value: Value) -> Result<Value> {
    if StatusCode::from_u16(status)
        .map(|s| s.is_success())
        .unwrap_or(false)
    {
        Ok(value)
    } else {
        bail!("control API returned {status}: {value}")
    }
}
