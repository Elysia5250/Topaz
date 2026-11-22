use anyhow::{anyhow, Context, Result};
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use rcgen::{CertificateParams, KeyPair};
use serde::{Deserialize, Serialize};
use std::path::Path;
use topaz_proto::auth::derive_id;

/// Per-device key. The same key signs coord requests and backs the device's
/// TLS certificate, so peers authenticate the device by this public key.
#[derive(Clone)]
pub struct DeviceIdentity {
    pub signing: SigningKey,
    pub device_id: String,
    pub pubkey_hex: String,
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct DeviceKeyFile {
    secret_key: String,
}

impl DeviceIdentity {
    pub fn generate() -> Result<Self> {
        Self::from_signing(SigningKey::generate(&mut OsRng))
    }

    fn from_signing(signing: SigningKey) -> Result<Self> {
        let pubkey = signing.verifying_key().to_bytes();
        let key_der = signing
            .to_pkcs8_der()
            .map_err(|e| anyhow!("encode device key: {e}"))?
            .as_bytes()
            .to_vec();
        let key_pair = KeyPair::try_from(key_der.as_slice())?;
        let params = CertificateParams::new(vec!["topaz".into()])?;
        let cert_der = params.self_signed(&key_pair)?.der().to_vec();
        Ok(Self {
            device_id: derive_id(&pubkey),
            pubkey_hex: hex::encode(pubkey),
            signing,
            cert_der,
            key_der,
        })
    }

    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            Self::load(path)
        } else {
            let id = Self::generate()?;
            id.save(path)?;
            Ok(id)
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let file: DeviceKeyFile = serde_json::from_str(&raw)?;
        let bytes: [u8; 32] = hex::decode(&file.secret_key)?
            .try_into()
            .map_err(|_| anyhow!("invalid device key length"))?;
        Self::from_signing(SigningKey::from_bytes(&bytes))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let file = DeviceKeyFile {
            secret_key: hex::encode(self.signing.to_bytes()),
        };
        write_private(path, serde_json::to_string_pretty(&file)?.as_bytes())
    }

    pub fn sign_hex(&self, msg: &[u8]) -> String {
        hex::encode(self.signing.sign(msg).to_bytes())
    }
}

/// Atomically write a private file (`0o600`, no symlink following) readable
/// only by the current/sudo user where the OS supports it.
pub fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(1);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("private");
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_file_name(format!(".{file_name}.{}.{seq}.tmp", std::process::id()));
    crate::store::write_new_file(&tmp, contents, 0o600)?;
    std::fs::rename(&tmp, path).with_context(|| format!("rename to {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_matches_key() {
        let id = DeviceIdentity::generate().unwrap();
        let pk: [u8; 32] = hex::decode(&id.pubkey_hex).unwrap().try_into().unwrap();
        assert_eq!(id.device_id, derive_id(&pk));
        assert!(!id.cert_der.is_empty());
    }
}
