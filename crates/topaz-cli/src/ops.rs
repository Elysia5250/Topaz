//! Pure-network device & account operations shared by the CLI's direct mode,
//! the daemon's local control API, and the full-lifecycle TUI.

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::Path;
use topaz_core::{
    generate_recovery_code, issue_cert, issue_revocation, AccountInfo, AccountKey, Store,
};
use topaz_net::{join_with_code, join_with_secret, CoordClient};
use topaz_proto::auth::{evaluate, format_pin, parse_pin, Revocation};
use topaz_proto::{CreateAccountRequest, DeviceEntry};

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

pub fn normalize_coord_arg(raw: &str) -> String {
    let s = raw.trim().trim_end_matches('/');
    if s.starts_with("https://") || s.starts_with("http://") {
        return s.to_string();
    }
    if s.starts_with('[') {
        if s.contains("]:") {
            format!("https://{s}")
        } else {
            format!("https://{s}:7722")
        }
    } else if s.contains(':') {
        format!("https://{s}")
    } else {
        format!("https://{s}:7722")
    }
}

pub fn coord_short_host(coord_url: &str) -> String {
    let trimmed = coord_url.trim().trim_end_matches('/');
    let no_scheme = trimmed.strip_prefix("https://").unwrap_or(trimmed);
    no_scheme
        .strip_suffix(":7722")
        .unwrap_or(no_scheme)
        .to_string()
}

pub fn setup_bundle(store: &Store, code: &str) -> String {
    let payload = json!({
        "url": store.config.coord_url,
        "pin": store.config.coord_pin,
        "code": code,
        "by": store.identity.device_id,
        "by_name": store.config.device_name,
    });
    format!(
        "topaz-setup:v1:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string())
    )
}

#[derive(Debug, Clone, Deserialize)]
pub struct SetupBundle {
    pub url: String,
    pub pin: String,
    pub code: String,
    #[allow(dead_code)]
    pub by: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub by_name: String,
}

pub fn parse_setup_bundle(raw: &str) -> Result<SetupBundle> {
    let s = raw.trim().trim_matches(|c| c == '\'' || c == '"');
    let body = s
        .strip_prefix("topaz-setup:v1:")
        .with_context(|| "not a topaz-setup:v1 bundle (generate one with Pair / `topaz device add`)")?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body)
        .context("bundle is not valid base64")?;
    serde_json::from_slice(&bytes).context("bundle payload is malformed")
}

pub fn ensure_no_account(store: &Store) -> Result<()> {
    if let Some(a) = &store.account {
        bail!(
            "this device already belongs to account {}; use a fresh --data-dir to join another",
            a.user_id
        );
    }
    Ok(())
}

/// Update local node configuration (`config.json`).
pub fn save_config_values(
    data_dir: &Path,
    coord_url: Option<&str>,
    pin: Option<&str>,
    device_name: Option<&str>,
    force_relay: Option<bool>,
) -> Result<()> {
    let mut store = Store::open(data_dir.to_path_buf())?;
    if let Some(u) = coord_url {
        let u = u.trim();
        if !u.is_empty() {
            let norm = normalize_coord_arg(u);
            if !norm.starts_with("https://") {
                bail!("coord URL must start with https://");
            }
            store.config.coord_url = norm;
        }
    }
    if let Some(p) = pin {
        let p = p.trim();
        if !p.is_empty() {
            let bytes = parse_pin(p).ok_or_else(|| {
                anyhow::anyhow!("invalid pin (expected 32 base32 chars from `topaz-coord fingerprint`)")
            })?;
            store.config.coord_pin = format_pin(&bytes);
        }
    }
    if let Some(n) = device_name {
        store.config.device_name = n.trim().to_string();
    }
    if let Some(fr) = force_relay {
        store.config.force_relay = fr;
    }
    store.save_config()
}

/// Create a brand-new account using an invite code and return `(AccountInfo, recovery_code)`.
pub async fn create_account_direct(
    data_dir: &Path,
    invite: &str,
    coord_url: Option<&str>,
    pin: Option<&str>,
    name: Option<&str>,
) -> Result<(AccountInfo, String)> {
    let mut store = Store::open(data_dir.to_path_buf())?;
    ensure_no_account(&store)?;
    let mut changed = false;
    if let Some(u) = coord_url.map(str::trim).filter(|s| !s.is_empty()) {
        let norm = normalize_coord_arg(u);
        if !norm.starts_with("https://") {
            bail!("coord URL must start with https://");
        }
        store.config.coord_url = norm;
        changed = true;
    }
    if let Some(p) = pin.map(str::trim).filter(|s| !s.is_empty()) {
        let bytes = parse_pin(p).ok_or_else(|| {
            anyhow::anyhow!("invalid pin (expected 32 base32 chars from `topaz-coord fingerprint`)")
        })?;
        store.config.coord_pin = format_pin(&bytes);
        changed = true;
    }
    if let Some(n) = name.map(str::trim).filter(|s| !s.is_empty()) {
        store.config.device_name = n.to_string();
        changed = true;
    }
    if changed {
        store.save_config()?;
    }
    let coord = coord_client(&store)?;
    let recovery = generate_recovery_code();
    let root = AccountKey::from_recovery(&recovery)?;
    let cert = issue_cert(
        &root.signing,
        &root.user_id,
        &root.user_pubkey,
        &store.identity.pubkey_hex,
        &store.device_name(),
    )?;
    coord
        .create_account(&CreateAccountRequest {
            invite: invite.trim().to_string(),
            cert: cert.clone(),
        })
        .await
        .context("create account")?;
    let info = AccountInfo::from_cert(&store.identity, cert)?;
    store.save_account(info.clone())?;
    Ok((info, recovery))
}

/// Join an existing account using a `topaz-setup:v1:...` bundle.
pub async fn join_with_setup_bundle(
    data_dir: &Path,
    bundle: &str,
    name: Option<&str>,
) -> Result<AccountInfo> {
    let b = parse_setup_bundle(bundle)?;
    if !b.url.starts_with("https://") {
        bail!("bundle coord URL is not https://: {}", b.url);
    }
    let pin = parse_pin(&b.pin).ok_or_else(|| anyhow::anyhow!("bundle pin is malformed"))?;

    let mut store = Store::open(data_dir.to_path_buf())?;
    ensure_no_account(&store)?;
    store.config.coord_url = b.url;
    store.config.coord_pin = format_pin(&pin);
    if let Some(n) = name.map(str::trim).filter(|s| !s.is_empty()) {
        store.config.device_name = n.to_string();
    }
    store.save_config()?;

    let coord = coord_client(&store)?;
    let my_name = store.device_name();
    let cert = join_with_code(&coord, &store.identity, &my_name, &b.code).await?;
    let info = AccountInfo::from_cert(&store.identity, cert)?;
    store.save_account(info.clone())?;
    Ok(info)
}

/// Join using a short one-time code (`ABC-DEFGH`) against an already-configured coord.
pub async fn join_with_short_code(
    data_dir: &Path,
    coord_url: Option<&str>,
    pin: Option<&str>,
    code: &str,
    name: Option<&str>,
) -> Result<AccountInfo> {
    let mut store = Store::open(data_dir.to_path_buf())?;
    ensure_no_account(&store)?;
    let mut changed = false;
    if let Some(u) = coord_url.map(str::trim).filter(|s| !s.is_empty()) {
        let norm = normalize_coord_arg(u);
        if !norm.starts_with("https://") {
            bail!("coord URL must start with https://");
        }
        store.config.coord_url = norm;
        changed = true;
    }
    if let Some(p) = pin.map(str::trim).filter(|s| !s.is_empty()) {
        let bytes = parse_pin(p).ok_or_else(|| anyhow::anyhow!("invalid pin"))?;
        store.config.coord_pin = format_pin(&bytes);
        changed = true;
    }
    if let Some(n) = name.map(str::trim).filter(|s| !s.is_empty()) {
        store.config.device_name = n.to_string();
        changed = true;
    }
    if changed {
        store.save_config()?;
    }

    let coord = coord_client(&store)?;
    let my_name = store.device_name();
    let cert = join_with_code(&coord, &store.identity, &my_name, code.trim()).await?;
    let info = AccountInfo::from_cert(&store.identity, cert)?;
    store.save_account(info.clone())?;
    Ok(info)
}

/// Join using a custom pairing phrase (after coord URL and pin have been trusted/configured).
pub async fn join_with_phrase_direct(
    data_dir: &Path,
    coord_url: Option<&str>,
    pin: Option<&str>,
    phrase: &str,
    name: Option<&str>,
) -> Result<AccountInfo> {
    let mut store = Store::open(data_dir.to_path_buf())?;
    ensure_no_account(&store)?;
    let mut changed = false;
    if let Some(u) = coord_url.map(str::trim).filter(|s| !s.is_empty()) {
        let norm = normalize_coord_arg(u);
        if !norm.starts_with("https://") {
            bail!("coord URL must start with https://");
        }
        store.config.coord_url = norm;
        changed = true;
    }
    if let Some(p) = pin.map(str::trim).filter(|s| !s.is_empty()) {
        let bytes = parse_pin(p).ok_or_else(|| anyhow::anyhow!("invalid pin"))?;
        store.config.coord_pin = format_pin(&bytes);
        changed = true;
    }
    if let Some(n) = name.map(str::trim).filter(|s| !s.is_empty()) {
        store.config.device_name = n.to_string();
        changed = true;
    }
    if changed {
        store.save_config()?;
    }

    let coord = coord_client(&store)?;
    let my_name = store.device_name();
    let cert = join_with_secret(&coord, &store.identity, &my_name, phrase).await?;
    let info = AccountInfo::from_cert(&store.identity, cert)?;
    store.save_account(info.clone())?;
    Ok(info)
}

/// Join using the offline account recovery code.
pub async fn join_with_recovery_direct(
    data_dir: &Path,
    coord_url: Option<&str>,
    pin: Option<&str>,
    recovery: &str,
    name: Option<&str>,
) -> Result<AccountInfo> {
    let mut store = Store::open(data_dir.to_path_buf())?;
    ensure_no_account(&store)?;
    let mut changed = false;
    if let Some(u) = coord_url.map(str::trim).filter(|s| !s.is_empty()) {
        let norm = normalize_coord_arg(u);
        if !norm.starts_with("https://") {
            bail!("coord URL must start with https://");
        }
        store.config.coord_url = norm;
        changed = true;
    }
    if let Some(p) = pin.map(str::trim).filter(|s| !s.is_empty()) {
        let bytes = parse_pin(p).ok_or_else(|| anyhow::anyhow!("invalid pin"))?;
        store.config.coord_pin = format_pin(&bytes);
        changed = true;
    }
    if let Some(n) = name.map(str::trim).filter(|s| !s.is_empty()) {
        store.config.device_name = n.to_string();
        changed = true;
    }
    if changed {
        store.save_config()?;
    }

    let root = AccountKey::from_recovery(recovery.trim())?;
    let coord = coord_client(&store)?;
    let my_name = store.device_name();
    let cert = issue_cert(
        &root.signing,
        &root.user_id,
        &root.user_pubkey,
        &store.identity.pubkey_hex,
        &my_name,
    )?;
    coord
        .add_device(&cert)
        .await
        .context("join with recovery code")?;
    let info = AccountInfo::from_cert(&store.identity, cert)?;
    store.save_account(info.clone())?;
    Ok(info)
}

/// Revoke a device directly against coord (optionally signed with the recovery code).
pub async fn revoke_device_direct(
    data_dir: &Path,
    device_id: &str,
    recovery_code: Option<&str>,
) -> Result<()> {
    let store = Store::open(data_dir.to_path_buf())?;
    let account = store.require_account()?.clone();
    let rev = if let Some(code) = recovery_code {
        let root = AccountKey::from_recovery(code.trim())?;
        if root.user_id != account.user_id {
            bail!("that recovery code belongs to a different account");
        }
        issue_revocation(&root.signing, &account.user_id, device_id)
    } else {
        issue_revocation(&store.identity.signing, &account.user_id, device_id)
    };
    OpCtx::for_store(&store)?.coord.revoke(&rev).await?;
    Ok(())
}

/// List all devices directly from coord (works even when the local daemon is stopped).
pub async fn list_devices_direct(data_dir: &Path) -> Result<(String, Vec<DeviceRow>)> {
    let store = Store::open(data_dir.to_path_buf())?;
    let ctx = OpCtx::for_store(&store)?;
    let devices = ctx.coord.list_devices().await?;
    Ok((ctx.account.user_id.clone(), device_rows(&ctx, &devices)))
}
