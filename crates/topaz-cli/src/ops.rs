//! Pure-network device operations shared by the CLI's direct mode and the
//! daemon's local control API.

use anyhow::Result;
use topaz_core::{issue_revocation, AccountInfo, Store};
use topaz_net::CoordClient;
use topaz_proto::auth::{evaluate, Revocation};
use topaz_proto::DeviceEntry;
use serde::{Deserialize, Serialize};

pub struct OpCtx {
    pub coord: CoordClient,
    pub account: AccountInfo,
    pub me: String,
}

pub fn coord_client(store: &Store) -> Result<CoordClient> {
    let (url, pin) = store.require_coord()?;
    Ok(CoordClient::new(url, pin)?.with_identity(store.identity.clone()))
}

impl OpCtx {
    pub fn for_store(store: &Store) -> Result<Self> {
        let account = store.require_account()?.clone();
        let (url, pin) = store.require_coord()?;
        let coord = CoordClient::new(url, pin)?.with_identity(store.identity.clone());
        Ok(Self {
            coord,
            account,
            me: store.identity.device_id.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRow {
    pub device_id: String,
    pub name: String,
    #[serde(default)]
    pub dns_name: Option<String>,
    #[serde(default)]
    pub virtual_ip: Option<String>,
    pub status: String,
    pub issuer: String,
    pub me: bool,
}

pub fn device_rows(ctx: &OpCtx, devices: &[DeviceEntry]) -> Vec<DeviceRow> {
    let set = evaluate(&ctx.account.user_pubkey, devices);
    devices
        .iter()
        .map(|e| {
            let c = &e.cert;
            let status = if set.is_active(&c.device_id) {
                "active"
            } else if set.valid.iter().any(|v| v.device_id == c.device_id) {
                "revoked"
            } else {
                "invalid"
            };
            let issuer = if c.issuer_pubkey == ctx.account.user_pubkey {
                "recovery code".to_string()
            } else {
                topaz_proto::auth::derive_id_hex(&c.issuer_pubkey).unwrap_or_default()
            };
            DeviceRow {
                device_id: c.device_id.clone(),
                name: c.name.clone(),
                dns_name: e.dns_name.clone(),
                virtual_ip: e.virtual_ip.clone(),
                status: status.to_string(),
                issuer,
                me: c.device_id == ctx.me,
            }
        })
        .collect()
}

pub fn device_revoke_local(store: &Store, device_id: &str) -> Result<Revocation> {
    let account = store.require_account()?;
    Ok(issue_revocation(
        &store.identity.signing,
        &account.user_id,
        device_id,
    ))
}

pub async fn publish_revocation(ctx: &OpCtx, rev: &Revocation) -> Result<()> {
    ctx.coord.revoke(rev).await
}
