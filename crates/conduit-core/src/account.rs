use crate::identity::{write_private, DeviceIdentity};
use anyhow::{anyhow, bail, Context, Result};
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;
use conduit_proto::auth::{derive_id, DeviceCert, Revocation};

const RECOVERY_BYTES: usize = 20;

/// Root key of an account. Derived from the recovery code and never stored.
pub struct AccountKey {
    pub signing: SigningKey,
    pub user_id: String,
    pub user_pubkey: String,
}

impl AccountKey {
    pub fn from_recovery(code: &str) -> Result<Self> {
        let normalized: String = code
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_uppercase();
        let bytes = BASE32_NOPAD
            .decode(normalized.as_bytes())
            .map_err(|_| anyhow!("recovery code is not valid"))?;
        if bytes.len() != RECOVERY_BYTES {
            bail!("recovery code is not valid");
        }
        let seed = blake3::derive_key("conduit account root key v1", &bytes);
        let signing = SigningKey::from_bytes(&seed);
        let pubkey = signing.verifying_key().to_bytes();
        Ok(Self {
            user_id: derive_id(&pubkey),
            user_pubkey: hex::encode(pubkey),
            signing,
        })
    }
}

/// 160 random bits, shown as eight groups of four base32 characters.
pub fn generate_recovery_code() -> String {
    let mut bytes = [0u8; RECOVERY_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let encoded = BASE32_NOPAD.encode(&bytes);
    encoded
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("-")
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn issue_cert(
    issuer: &SigningKey,
    user_id: &str,
    user_pubkey: &str,
    device_pubkey: &str,
    name: &str,
) -> Result<DeviceCert> {
    let device_id = conduit_proto::auth::derive_id_hex(device_pubkey)
        .ok_or_else(|| anyhow!("invalid device public key"))?;
    let mut cert = DeviceCert {
        user_id: user_id.to_string(),
        user_pubkey: user_pubkey.to_string(),
        device_id,
        device_pubkey: device_pubkey.to_string(),
        name: name.to_string(),
        issued_at: now_unix(),
        issuer_pubkey: hex::encode(issuer.verifying_key().as_bytes()),
        sig: String::new(),
    };
    cert.sig = hex::encode(issuer.sign(&cert.signing_bytes()).to_bytes());
    Ok(cert)
}

pub fn issue_revocation(issuer: &SigningKey, user_id: &str, device_id: &str) -> Revocation {
    let mut rev = Revocation {
        user_id: user_id.to_string(),
        device_id: device_id.to_string(),
        issued_at: now_unix(),
        issuer_pubkey: hex::encode(issuer.verifying_key().as_bytes()),
        sig: String::new(),
    };
    rev.sig = hex::encode(issuer.sign(&rev.signing_bytes()).to_bytes());
    rev
}

/// This device's membership in an account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub user_id: String,
    pub user_pubkey: String,
    pub cert: DeviceCert,
}

impl AccountInfo {
    pub fn from_cert(identity: &DeviceIdentity, cert: DeviceCert) -> Result<Self> {
        if cert.device_pubkey != identity.pubkey_hex {
            bail!("certificate was issued for a different device");
        }
        if !cert.self_consistent() {
            bail!("certificate signature is not valid");
        }
        Ok(Self {
            user_id: cert.user_id.clone(),
            user_pubkey: cert.user_pubkey.clone(),
            cert,
        })
    }

    pub fn load(path: &Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        Ok(Some(serde_json::from_str(&raw)?))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        write_private(path, serde_json::to_string_pretty(self)?.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_code_roundtrip_is_stable() {
        let code = generate_recovery_code();
        assert_eq!(code.len(), 8 * 4 + 7);
        let a = AccountKey::from_recovery(&code).unwrap();
        let b = AccountKey::from_recovery(&code.to_lowercase().replace('-', " ")).unwrap();
        assert_eq!(a.user_pubkey, b.user_pubkey);
        assert!(AccountKey::from_recovery("ABCD-EFGH").is_err());
    }

    #[test]
    fn issued_cert_verifies() {
        let root = AccountKey::from_recovery(&generate_recovery_code()).unwrap();
        let device = DeviceIdentity::generate().unwrap();
        let cert = issue_cert(
            &root.signing,
            &root.user_id,
            &root.user_pubkey,
            &device.pubkey_hex,
            "mac",
        )
        .unwrap();
        let info = AccountInfo::from_cert(&device, cert).unwrap();
        assert_eq!(info.user_id, root.user_id);
    }
}
