//! Account and device signatures shared by nodes and the coordination server.
//!
//! An account is identified by a root Ed25519 key derived from the recovery
//! code. Each device has its own key and a certificate issued either by the
//! root key or by another valid device of the same account.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Maximum clock skew accepted for signed requests and relay hellos.
pub const MAX_SKEW_SECS: u64 = 120;

pub const HDR_DEVICE: &str = "x-ss-device";
pub const HDR_TIME: &str = "x-ss-time";
pub const HDR_NONCE: &str = "x-ss-nonce";
pub const HDR_SIG: &str = "x-ss-sig";

/// Short id derived from a public key: first 8 bytes of blake3, hex.
pub fn derive_id(pubkey: &[u8; 32]) -> String {
    hex::encode(&blake3::hash(pubkey).as_bytes()[..8])
}

/// Fingerprint of the coord's TLS key that clients pin: first 20 bytes of
/// blake3 over the Ed25519 public key.
pub fn pin_bytes(pubkey: &[u8; 32]) -> [u8; 20] {
    blake3::hash(pubkey).as_bytes()[..20].try_into().unwrap()
}

/// Human form of a pin: base32 in groups of four.
pub fn format_pin(pin: &[u8; 20]) -> String {
    let encoded = data_encoding::BASE32_NOPAD.encode(pin);
    encoded
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("-")
}

pub fn parse_pin(s: &str) -> Option<[u8; 20]> {
    let cleaned: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_uppercase();
    data_encoding::BASE32_NOPAD
        .decode(cleaned.as_bytes())
        .ok()?
        .try_into()
        .ok()
}

pub fn parse_pubkey(pubkey_hex: &str) -> Option<[u8; 32]> {
    hex::decode(pubkey_hex).ok()?.try_into().ok()
}

pub fn derive_id_hex(pubkey_hex: &str) -> Option<String> {
    parse_pubkey(pubkey_hex).map(|pk| derive_id(&pk))
}

pub fn verify(pubkey_hex: &str, msg: &[u8], sig_hex: &str) -> bool {
    let Some(pk) = parse_pubkey(pubkey_hex) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    let Some(sig) = hex::decode(sig_hex)
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b).ok())
    else {
        return false;
    };
    vk.verify(msg, &Signature::from_bytes(&sig)).is_ok()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceCert {
    pub user_id: String,
    pub user_pubkey: String,
    pub device_id: String,
    pub device_pubkey: String,
    pub name: String,
    pub issued_at: u64,
    /// Root key or the key of the device that approved this one.
    pub issuer_pubkey: String,
    pub sig: String,
}

impl DeviceCert {
    pub fn signing_bytes(&self) -> Vec<u8> {
        format!(
            "topaz-devcert-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            self.user_id,
            self.user_pubkey,
            self.device_id,
            self.device_pubkey,
            self.name,
            self.issued_at,
            self.issuer_pubkey
        )
        .into_bytes()
    }

    /// Ids match their keys, name is well-formed, and the issuer signature is valid.
    /// Does not check whether the issuer itself belongs to the account.
    pub fn self_consistent(&self) -> bool {
        self.name.len() <= 128
            && !self.name.chars().any(|c| c.is_control())
            && derive_id_hex(&self.user_pubkey).as_deref() == Some(self.user_id.as_str())
            && derive_id_hex(&self.device_pubkey).as_deref() == Some(self.device_id.as_str())
            && verify(&self.issuer_pubkey, &self.signing_bytes(), &self.sig)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Revocation {
    pub user_id: String,
    pub device_id: String,
    pub issued_at: u64,
    pub issuer_pubkey: String,
    pub sig: String,
}

impl Revocation {
    pub fn signing_bytes(&self) -> Vec<u8> {
        format!(
            "topaz-revoke-v1\n{}\n{}\n{}\n{}",
            self.user_id, self.device_id, self.issued_at, self.issuer_pubkey
        )
        .into_bytes()
    }
}

/// Virtual subnet shared by all active devices in an account (CGNAT RFC 6598).
pub const TOPAZ_VPN_CIDR: &str = "100.64.0.0/10";

/// Sanitize a human device name into a valid RFC 1123 DNS label (max 63 chars).
/// Falls back to `node-<short_id>` when the device name has no ASCII
/// alphanumeric characters.
pub fn sanitize_dns_label(name: &str, device_id: &str) -> String {
    let mut out = String::with_capacity(name.len().min(63));
    let mut prev_dash = true; // suppresses leading '-'
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            if out.len() >= 63 {
                break;
            }
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            if out.len() >= 63 {
                break;
            }
            out.push('-');
            prev_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        let short: String = device_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(6)
            .collect::<String>()
            .to_ascii_lowercase();
        if short.is_empty() {
            "node".to_string()
        } else {
            format!("node-{short}")
        }
    } else {
        out
    }
}

/// Append a numeric deduplication suffix (`-2`, `-3`, ...) while preserving
/// the 63-byte DNS label limit.
pub fn dns_label_with_suffix(base: &str, index: u32) -> String {
    if index <= 1 {
        return base.to_string();
    }
    let suffix = format!("-{index}");
    let max_base = 63usize.saturating_sub(suffix.len());
    let mut prefix: String = base.chars().take(max_base).collect();
    while prefix.ends_with('-') {
        prefix.pop();
    }
    if prefix.is_empty() {
        format!("node{suffix}")
    } else {
        format!("{prefix}{suffix}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceEntry {
    pub cert: DeviceCert,
    pub revocation: Option<Revocation>,
    /// Assigned virtual IPv4 inside `100.64.0.0/10` (e.g. `"100.64.0.1"`).
    #[serde(default)]
    pub virtual_ip: Option<String>,
    /// Account-unique DNS label (e.g. `"laptop"` for `laptop.topaz`).
    #[serde(default)]
    pub dns_name: Option<String>,
}

impl DeviceEntry {
    pub fn new(cert: DeviceCert, revocation: Option<Revocation>) -> Self {
        Self {
            cert,
            revocation,
            virtual_ip: None,
            dns_name: None,
        }
    }
}

/// Result of checking an account's device list against its root key.
#[derive(Debug, Default, Clone)]
pub struct DeviceSet {
    /// Certs that chain to the root key, revoked or not.
    pub valid: Vec<DeviceCert>,
    /// Valid certs without a valid revocation.
    pub active: Vec<DeviceCert>,
}

impl DeviceSet {
    pub fn is_active(&self, device_id: &str) -> bool {
        self.active.iter().any(|c| c.device_id == device_id)
    }

    pub fn active_by_id(&self, device_id: &str) -> Option<&DeviceCert> {
        self.active.iter().find(|c| c.device_id == device_id)
    }

    /// Keys allowed to sign new certs or revocations: root plus active devices.
    pub fn authority_keys(&self, user_pubkey: &str) -> HashSet<String> {
        let mut keys: HashSet<String> = self
            .active
            .iter()
            .map(|c| c.device_pubkey.clone())
            .collect();
        keys.insert(user_pubkey.to_string());
        keys
    }
}

pub fn evaluate(user_pubkey: &str, entries: &[DeviceEntry]) -> DeviceSet {
    let candidates: Vec<&DeviceEntry> = entries
        .iter()
        .filter(|e| e.cert.user_pubkey == user_pubkey && e.cert.self_consistent())
        .collect();

    // First collect every cert that chains to the root key.
    let mut trusted_keys: HashSet<String> = HashSet::from([user_pubkey.to_string()]);
    let mut all_chained: Vec<&DeviceEntry> = Vec::new();
    loop {
        let mut progressed = false;
        for e in &candidates {
            if all_chained
                .iter()
                .any(|v| v.cert.device_id == e.cert.device_id)
            {
                continue;
            }
            if trusted_keys.contains(&e.cert.issuer_pubkey) {
                trusted_keys.insert(e.cert.device_pubkey.clone());
                all_chained.push(e);
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }

    let valid_rev = |e: &DeviceEntry, authorities: &HashSet<String>| -> Option<u64> {
        let r = e.revocation.as_ref()?;
        if r.device_id == e.cert.device_id
            && r.user_id == e.cert.user_id
            && authorities.contains(&r.issuer_pubkey)
            && verify(&r.issuer_pubkey, &r.signing_bytes(), &r.sig)
        {
            Some(r.issued_at)
        } else {
            None
        }
    };

    // Determine effective revocations starting from the root key so a device
    // revoked by root cannot counter-revoke other active devices.
    let mut revoked_at: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let root_only: HashSet<String> = HashSet::from([user_pubkey.to_string()]);
    for e in &all_chained {
        if let Some(ts) = valid_rev(e, &root_only) {
            revoked_at.insert(e.cert.device_pubkey.clone(), ts);
        }
    }
    loop {
        let mut authorities: HashSet<String> = HashSet::from([user_pubkey.to_string()]);
        for e in &all_chained {
            if !revoked_at.contains_key(&e.cert.device_pubkey) {
                authorities.insert(e.cert.device_pubkey.clone());
            }
        }
        let mut progressed = false;
        for e in &all_chained {
            if revoked_at.contains_key(&e.cert.device_pubkey) {
                continue;
            }
            if let Some(ts) = valid_rev(e, &authorities) {
                revoked_at.insert(e.cert.device_pubkey.clone(), ts);
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }

    // Re-evaluate the certificate chain while rejecting any cert issued by a
    // device at or after its revocation timestamp.
    let mut valid_keys: HashSet<String> = HashSet::from([user_pubkey.to_string()]);
    let mut valid: Vec<&DeviceEntry> = Vec::new();
    loop {
        let mut progressed = false;
        for e in &all_chained {
            if valid.iter().any(|v| v.cert.device_id == e.cert.device_id) {
                continue;
            }
            if !valid_keys.contains(&e.cert.issuer_pubkey) {
                continue;
            }
            if let Some(&rev_ts) = revoked_at.get(&e.cert.issuer_pubkey) {
                if e.cert.issued_at >= rev_ts {
                    continue;
                }
            }
            valid_keys.insert(e.cert.device_pubkey.clone());
            valid.push(e);
            progressed = true;
        }
        if !progressed {
            break;
        }
    }

    let active = valid
        .iter()
        .filter(|e| !revoked_at.contains_key(&e.cert.device_pubkey))
        .map(|e| e.cert.clone())
        .collect();

    DeviceSet {
        valid: valid.iter().map(|e| e.cert.clone()).collect(),
        active,
    }
}

pub fn request_signing_bytes(
    method: &str,
    path: &str,
    time: u64,
    nonce: &str,
    body: &[u8],
) -> Vec<u8> {
    format!(
        "topaz-req-v1\n{method}\n{path}\n{time}\n{nonce}\n{}",
        blake3::hash(body).to_hex()
    )
    .into_bytes()
}

pub fn relay_signing_bytes(device_id: &str, peer_id: &str, time: u64, nonce: &str) -> Vec<u8> {
    format!("topaz-relay-v1\n{device_id}\n{peer_id}\n{time}\n{nonce}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn pk_hex(k: &SigningKey) -> String {
        hex::encode(k.verifying_key().as_bytes())
    }

    fn cert(root: &SigningKey, device: &SigningKey, issuer: &SigningKey) -> DeviceCert {
        let mut c = DeviceCert {
            user_id: derive_id(root.verifying_key().as_bytes()),
            user_pubkey: pk_hex(root),
            device_id: derive_id(device.verifying_key().as_bytes()),
            device_pubkey: pk_hex(device),
            name: "dev".into(),
            issued_at: 1,
            issuer_pubkey: pk_hex(issuer),
            sig: String::new(),
        };
        c.sig = hex::encode(issuer.sign(&c.signing_bytes()).to_bytes());
        c
    }

    fn revoke(root: &SigningKey, target: &DeviceCert, issuer: &SigningKey) -> Revocation {
        let mut r = Revocation {
            user_id: derive_id(root.verifying_key().as_bytes()),
            device_id: target.device_id.clone(),
            issued_at: 2,
            issuer_pubkey: pk_hex(issuer),
            sig: String::new(),
        };
        r.sig = hex::encode(issuer.sign(&r.signing_bytes()).to_bytes());
        r
    }

    #[test]
    fn chain_through_device_and_revoke() {
        let root = key(1);
        let a = key(2);
        let b = key(3);
        let ca = cert(&root, &a, &root);
        let cb = cert(&root, &b, &a);
        let mut entries = vec![
            DeviceEntry::new(cb.clone(), None),
            DeviceEntry::new(ca.clone(), None),
        ];
        let set = evaluate(&pk_hex(&root), &entries);
        assert!(set.is_active(&ca.device_id));
        assert!(set.is_active(&cb.device_id));

        entries[0].revocation = Some(revoke(&root, &cb, &a));
        let set = evaluate(&pk_hex(&root), &entries);
        assert!(set.is_active(&ca.device_id));
        assert!(!set.is_active(&cb.device_id));
    }

    #[test]
    fn pin_roundtrip() {
        let pin = pin_bytes(key(5).verifying_key().as_bytes());
        let text = format_pin(&pin);
        assert_eq!(text.len(), 8 * 4 + 7);
        assert_eq!(parse_pin(&text.to_lowercase().replace('-', "")), Some(pin));
        assert_eq!(parse_pin("ABCD"), None);
    }

    #[test]
    fn rejects_foreign_issuer_and_tampering() {
        let root = key(1);
        let stranger = key(9);
        let a = key(2);
        let forged = cert(&root, &a, &stranger);
        let mut tampered = cert(&root, &key(4), &root);
        tampered.name = "renamed".into();
        let set = evaluate(
            &pk_hex(&root),
            &[
                DeviceEntry::new(forged, None),
                DeviceEntry::new(tampered, None),
            ],
        );
        assert!(set.active.is_empty());
    }

    #[test]
    fn dns_label_sanitization_and_suffixing() {
        assert_eq!(sanitize_dns_label("MacBook Pro", "abc123"), "macbook-pro");
        assert_eq!(sanitize_dns_label("  __Dev_Box__!! ", "abc123"), "dev-box");
        assert_eq!(sanitize_dns_label("我的笔记本", "3fa9c1d2e4"), "node-3fa9c1");
        let long = "a".repeat(80);
        assert_eq!(sanitize_dns_label(&long, "123456").len(), 63);
        let suffixed = dns_label_with_suffix(&"a".repeat(63), 12);
        assert_eq!(suffixed.len(), 63);
        assert!(suffixed.ends_with("-12"));
    }

    #[test]
    fn device_entry_deserializes_without_ipam_fields() {
        let root = key(1);
        let dev = key(2);
        let c = cert(&root, &dev, &root);
        let legacy_json = serde_json::json!({
            "cert": c,
            "revocation": null
        });
        let entry: DeviceEntry = serde_json::from_value(legacy_json).unwrap();
        assert_eq!(entry.virtual_ip, None);
        assert_eq!(entry.dns_name, None);
    }

    #[test]
    fn revoked_device_cannot_revoke_peers_or_issue_new_certs() {
        let root = key(1);
        let a = key(2);
        let b = key(3);
        let c = key(4);
        let ca = cert(&root, &a, &root); // issued_at = 1
        let cb = cert(&root, &b, &root); // issued_at = 1
        // A is revoked by root at issued_at = 2.
        let rev_a = revoke(&root, &ca, &root);
        // A tries to counter-revoke B and issue a post-revocation cert for C (issued_at = 3).
        let fake_rev_b = revoke(&root, &cb, &a);
        let mut cc = cert(&root, &c, &a);
        cc.issued_at = 3;
        cc.sig = hex::encode(a.sign(&cc.signing_bytes()).to_bytes());

        let entries = vec![
            DeviceEntry::new(ca.clone(), Some(rev_a)),
            DeviceEntry::new(cb.clone(), Some(fake_rev_b)),
            DeviceEntry::new(cc.clone(), None),
        ];
        let set = evaluate(&pk_hex(&root), &entries);
        assert!(!set.is_active(&ca.device_id));
        assert!(set.is_active(&cb.device_id), "revoked A must not revoke active B");
        assert!(!set.is_active(&cc.device_id), "post-revocation cert by A must be rejected");
    }
}
