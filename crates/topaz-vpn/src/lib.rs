//! Topaz L3 virtual network data plane (`100.64.0.0/10` TUN + `*.topaz` DNS).
//!
//! Targets Linux (`/dev/net/tun`) and macOS (`utun`). When `--no-tun` is set
//! or TUN creation lacks privileges, the rest of the Topaz engine and
//! `control.sock` bridge continue operating normally.

pub mod dns;
pub mod route;
mod tun;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use topaz_fabric::{EngineHandle, SharedStatus};
use topaz_proto::auth::TOPAZ_VPN_CIDR;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

/// Default TUN MTU chosen to fit comfortably inside initial QUIC datagrams.
pub const DEFAULT_MTU: u16 = 1280;

/// Configuration for the L3 VPN data plane.
#[derive(Debug, Clone)]
pub struct VpnConfig {
    /// Disable TUN creation entirely (`--no-tun`).
    pub disabled: bool,
    /// Optional TUN interface name (`topaz0` on Linux, `utunN` on macOS).
    pub tun_name: Option<String>,
    /// Interface MTU (default `1280`).
    pub mtu: u16,
    /// Optional explicit UDP bind address for the `*.topaz` local DNS server.
    pub dns_listen: Option<SocketAddr>,
}

impl Default for VpnConfig {
    fn default() -> Self {
        Self {
            disabled: false,
            tun_name: None,
            mtu: DEFAULT_MTU,
            dns_listen: None,
        }
    }
}

/// Live VPN interface & DNS state exposed via `control.sock` and `status.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VpnStatus {
    pub enabled: bool,
    pub interface: Option<String>,
    pub cidr: String,
    pub mtu: u16,
    pub dns_listen: Option<String>,
    pub error: Option<String>,
}

impl Default for VpnStatus {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: None,
            cidr: TOPAZ_VPN_CIDR.to_string(),
            mtu: DEFAULT_MTU,
            dns_listen: None,
            error: None,
        }
    }
}

/// Thread-safe handle to the current [`VpnStatus`].
#[derive(Clone, Default)]
pub struct SharedVpnStatus {
    inner: Arc<Mutex<VpnStatus>>,
}

impl SharedVpnStatus {
    pub fn new(mtu: u16) -> Self {
        Self {
            inner: Arc::new(Mutex::new(VpnStatus {
                mtu,
                ..Default::default()
            })),
        }
    }

    pub fn get(&self) -> VpnStatus {
        self.inner.lock().unwrap().clone()
    }

    pub fn set(&self, next: VpnStatus) {
        *self.inner.lock().unwrap() = next;
    }
}

/// Spawn the VPN TUN + DNS task. Returns `None` when `cfg.disabled` (`--no-tun`).
pub fn spawn(
    engine: EngineHandle,
    status: Arc<SharedStatus>,
    vpn_status: SharedVpnStatus,
    cfg: VpnConfig,
) -> Option<JoinHandle<()>> {
    if cfg.disabled {
        vpn_status.set(VpnStatus {
            enabled: false,
            interface: None,
            cidr: TOPAZ_VPN_CIDR.to_string(),
            mtu: cfg.mtu,
            dns_listen: None,
            error: None,
        });
        return None;
    }
    Some(tokio::spawn(tun::run_vpn_loop(
        engine,
        status,
        vpn_status,
        cfg,
    )))
}
