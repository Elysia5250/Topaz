use crate::account::AccountInfo;
use crate::identity::DeviceIdentity;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TMP_SEQ: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    pub coord_url: String,
    /// Fingerprint of the coord's TLS key, from `topaz-coord fingerprint`.
    #[serde(default)]
    pub coord_pin: String,
    #[serde(default)]
    pub device_name: String,
    /// Force relay even when direct might work (for testing).
    #[serde(default)]
    pub force_relay: bool,
}

pub struct Store {
    pub root: PathBuf,
    pub identity: DeviceIdentity,
    pub config: Config,
    pub account: Option<AccountInfo>,
}

impl Store {
    pub fn open(root: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&root)?;
        let tmp_dir = root.join("tmp");
        std::fs::create_dir_all(&tmp_dir)?;
        chown_to_sudo_user(&root);
        chown_to_sudo_user(&tmp_dir);
        let identity = DeviceIdentity::load_or_create(&root.join("device.json"))?;
        let config_path = root.join("config.json");
        let config = if config_path.exists() {
            let raw = std::fs::read_to_string(&config_path)?;
            serde_json::from_str(&raw)?
        } else {
            Config::default()
        };
        let account = AccountInfo::load(&root.join("account.json"))?;
        Ok(Self {
            root,
            identity,
            config,
            account,
        })
    }

    pub fn save_config(&self) -> Result<()> {
        self.atomic_write("config.json", serde_json::to_string_pretty(&self.config)?)
    }

    fn atomic_write(&self, name: &str, data: String) -> Result<()> {
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = self
            .root
            .join("tmp")
            .join(format!("{name}.{}.{seq}.tmp", std::process::id()));
        std::fs::write(&tmp, data)?;
        chown_to_sudo_user(&tmp);
        let dst = self.root.join(name);
        std::fs::rename(&tmp, &dst).with_context(|| format!("write {name}"))?;
        chown_to_sudo_user(&dst);
        Ok(())
    }

    pub fn save_account(&mut self, account: AccountInfo) -> Result<()> {
        account.save(&self.root.join("account.json"))?;
        self.account = Some(account);
        Ok(())
    }

    pub fn require_account(&self) -> Result<&AccountInfo> {
        match &self.account {
            Some(a) => Ok(a),
            None => bail!(
                "this device is not in an account yet: run `topaz account create --invite CODE` or `topaz join CODE`"
            ),
        }
    }

    /// Coord URL and pin, both required.
    pub fn require_coord(&self) -> Result<(&str, &str)> {
        if self.config.coord_url.is_empty() || self.config.coord_pin.is_empty() {
            bail!(
                "coord not set: run `topaz init --coord-url https://HOST:7722 --pin PIN`"
            );
        }
        Ok((&self.config.coord_url, &self.config.coord_pin))
    }

    pub fn device_name(&self) -> String {
        if !self.config.device_name.is_empty() {
            return self.config.device_name.clone();
        }
        std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| format!("device-{}", &self.identity.device_id[..6]))
    }

    pub fn default_data_dir() -> PathBuf {
        dirs_next_home()
            .map(|h| h.join(".topaz"))
            .unwrap_or_else(|| PathBuf::from(".topaz"))
    }

    pub fn status_path(&self) -> PathBuf {
        self.root.join("status.json")
    }

    pub fn control_path(&self) -> PathBuf {
        control_socket_path(&self.root)
    }

    pub fn write_status(&self, value: &serde_json::Value) -> Result<()> {
        self.atomic_write("status.json", serde_json::to_string_pretty(value)?)
    }
}

fn dirs_next_home() -> Option<PathBuf> {
    #[cfg(unix)]
    if let Some(sudo_home) = sudo_user_home() {
        return Some(sudo_home);
    }
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

#[cfg(unix)]
fn sudo_user_home() -> Option<PathBuf> {
    let user = std::env::var("SUDO_USER").ok()?;
    let user = user.trim();
    if user.is_empty() || user == "root" {
        return None;
    }
    let c_user = std::ffi::CString::new(user).ok()?;
    unsafe {
        let pw = libc::getpwnam(c_user.as_ptr());
        if pw.is_null() || (*pw).pw_dir.is_null() {
            return None;
        }
        let dir = std::ffi::CStr::from_ptr((*pw).pw_dir);
        use std::os::unix::ffi::OsStrExt;
        Some(PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes())))
    }
}

/// If running under `sudo`, transfer ownership of `path` back to the invoking
/// user (`SUDO_UID`/`SUDO_GID`) so non-root CLI/TUI commands stay usable.
#[cfg(unix)]
pub fn chown_to_sudo_user(path: &Path) {
    if let (Ok(uid_s), Ok(gid_s)) = (std::env::var("SUDO_UID"), std::env::var("SUDO_GID")) {
        if let (Ok(uid), Ok(gid)) = (uid_s.parse::<libc::uid_t>(), gid_s.parse::<libc::gid_t>()) {
            if let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) {
                unsafe {
                    libc::chown(c_path.as_ptr(), uid, gid);
                }
            }
        }
    }
}

#[cfg(not(unix))]
pub fn chown_to_sudo_user(_path: &Path) {}

pub fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

/// Local control API socket path for a data-dir.
pub fn control_socket_path(root: &Path) -> PathBuf {
    root.join("control.sock")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "engine-store-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn opens_and_persists_network_config() {
        let root = tmp();
        let mut store = Store::open(root.join("data")).unwrap();
        store.config.coord_url = "https://127.0.0.1:7722".into();
        store.config.coord_pin = "pin".into();
        store.config.device_name = "node-a".into();
        store.save_config().unwrap();

        let reopened = Store::open(root.join("data")).unwrap();
        assert_eq!(reopened.config.coord_url, "https://127.0.0.1:7722");
        assert_eq!(reopened.device_name(), "node-a");
        assert_eq!(reopened.identity.device_id, store.identity.device_id);
        let _ = std::fs::remove_dir_all(&root);
    }
}
