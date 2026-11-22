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
/// Maximum clock skew accepted for certificate/revocation `issued_at` at coord submission time.
pub const MAX_CERT_CLOCK_SKEW_SECS: u64 = 300;

pub const HDR_DEVICE: &str = "x-topaz-device";
pub const HDR_TIME: &str = "x-topaz-time";
pub const HDR_NONCE: &str = "x-topaz-nonce";
pub const HDR_SIG: &str = "x-topaz-sig";

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

    /// Keys allowed to sign new certs: root plus active devices.
    pub fn authority_keys(&self, user_pubkey: &str) -> HashSet<String> {
        let mut keys: HashSet<String> = self
            .active
            .iter()
            .map(|c| c.device_pubkey.clone())
            .collect();
        keys.insert(user_pubkey.to_string());
        keys
    }

    /// Whether `issuer_pubkey` is authorized to revoke `target_device_id`.
    ///
    /// Policy (1A): only the account root key, an active ancestor on the
    /// target's certificate issuance chain, or the target device itself may
    /// revoke the target. Siblings and descendants can never revoke peers or
    /// parents.
    pub fn can_revoke(
        &self,
        user_pubkey: &str,
        issuer_pubkey: &str,
        target_device_id: &str,
    ) -> bool {
        let Some(target) = self.active_by_id(target_device_id) else {
            return false;
        };
        if issuer_pubkey == user_pubkey || issuer_pubkey == target.device_pubkey {
            return true;
        }
        // Issuer must itself be an active device on the target's ancestor chain.
        if !self.active.iter().any(|c| c.device_pubkey == issuer_pubkey) {
            return false;
        }
        let by_pubkey: std::collections::HashMap<&str, &DeviceCert> = self
            .valid
            .iter()
            .map(|c| (c.device_pubkey.as_str(), c))
            .collect();
        let mut cursor = target.issuer_pubkey.as_str();
        for _ in 0..=self.valid.len() {
            if cursor == issuer_pubkey {
                return true;
            }
            if cursor == user_pubkey {
                return false;
            }
            match by_pubkey.get(cursor) {
                Some(parent) => cursor = parent.issuer_pubkey.as_str(),
                None => return false,
            }
        }
        false
    }
}

pub fn evaluate(user_pubkey: &str, entries: &[DeviceEntry]) -> DeviceSet {
    use std::collections::HashMap;

    let candidates: Vec<&DeviceEntry> = entries
        .iter()
        .filter(|e| {
            e.cert.user_pubkey == user_pubkey
                && e.cert.device_pubkey != user_pubkey
                && e.cert.device_pubkey != e.cert.issuer_pubkey
                && e.cert.self_consistent()
        })
        .collect();

    // Build an acyclic issuance tree rooted at `user_pubkey` in BFS layers.
    // Because each layer only expands from the previous layer, the parent
    // relationship is strictly acyclic and every device has a unique ancestor
    // chain to the root key.
    let mut visited_ids: HashSet<&str> = HashSet::new();
    let mut visited_keys: HashSet<&str> = HashSet::from([user_pubkey]);
    let mut current_layer: HashSet<&str> = HashSet::from([user_pubkey]);
    let mut layers: Vec<Vec<&DeviceEntry>> = Vec::new();
    let mut parent_of: HashMap<&str, &str> = HashMap::new();

    loop {
        let mut next_entries: Vec<&DeviceEntry> = Vec::new();
        let mut next_keys: HashSet<&str> = HashSet::new();
        for e in &candidates {
            let dev_id = e.cert.device_id.as_str();
            let dev_pk = e.cert.device_pubkey.as_str();
            let iss_pk = e.cert.issuer_pubkey.as_str();
            if visited_ids.contains(dev_id) || visited_keys.contains(dev_pk) {
                continue;
            }
            if current_layer.contains(iss_pk) {
                visited_ids.insert(dev_id);
                visited_keys.insert(dev_pk);
                next_keys.insert(dev_pk);
                parent_of.insert(dev_pk, iss_pk);
                next_entries.push(e);
            }
        }
        if next_entries.is_empty() {
            break;
        }
        layers.push(next_entries);
        current_layer = next_keys;
    }

    // Evaluate validity and revocations strictly top-down by tree depth.
    // When processing a device at depth k, the status of every strict ancestor
    // (depths 0..k) is already finalized, so resolution is order-independent
    // and immune to mutual-revocation cycles.
    let mut valid_keys: HashSet<&str> = HashSet::from([user_pubkey]);
    let mut revoked_at: HashMap<&str, u64> = HashMap::new();
    let mut valid: Vec<DeviceCert> = Vec::new();
    let mut active: Vec<DeviceCert> = Vec::new();

    for layer in &layers {
        for e in layer {
            let dev_pk = e.cert.device_pubkey.as_str();
            let iss_pk = e.cert.issuer_pubkey.as_str();
            if !valid_keys.contains(iss_pk) {
                continue;
            }
            if let Some(&parent_rev_ts) = revoked_at.get(iss_pk) {
                if e.cert.issued_at >= parent_rev_ts {
                    continue;
                }
            }
            valid_keys.insert(dev_pk);
            valid.push(e.cert.clone());

            let is_revoked = e.revocation.as_ref().and_then(|r| {
                if r.device_id != e.cert.device_id || r.user_id != e.cert.user_id {
                    return None;
                }
                let rev_issuer = r.issuer_pubkey.as_str();
                let authorized = if rev_issuer == user_pubkey || rev_issuer == dev_pk {
                    true
                } else {
                    // Must be a currently-active (unrevoked) strict ancestor.
                    let mut found = false;
                    let mut cursor = iss_pk;
                    while cursor != user_pubkey {
                        if cursor == rev_issuer {
                            found = !revoked_at.contains_key(rev_issuer);
                            break;
                        }
                        match parent_of.get(cursor) {
                            Some(&p) => cursor = p,
                            None => break,
                        }
                    }
                    found
                };
                if authorized && verify(&r.issuer_pubkey, &r.signing_bytes(), &r.sig) {
                    Some(r.issued_at)
                } else {
                    None
                }
            });

            if let Some(ts) = is_revoked {
                revoked_at.insert(dev_pk, ts);
            } else {
                active.push(e.cert.clone());
            }
        }
    }

    DeviceSet { valid, active }
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

    #[test]
    fn sibling_and_child_cannot_revoke_peer_or_parent() {
        let root = key(1);
        let a = key(2);
        let b = key(3);
        let c = key(4);
        let ca = cert(&root, &a, &root);
        let cb = cert(&root, &b, &root);
        let cc = cert(&root, &c, &a);

        // Sibling A tries to revoke sibling B, and child C tries to revoke parent A.
        let rev_b_by_a = revoke(&root, &cb, &a);
        let rev_a_by_c = revoke(&root, &ca, &c);
        let entries = vec![
            DeviceEntry::new(ca.clone(), Some(rev_a_by_c)),
            DeviceEntry::new(cb.clone(), Some(rev_b_by_a)),
            DeviceEntry::new(cc.clone(), None),
        ];
        let set = evaluate(&pk_hex(&root), &entries);
        assert!(set.is_active(&ca.device_id), "child must not revoke parent");
        assert!(set.is_active(&cb.device_id), "sibling must not revoke sibling");
        assert!(set.is_active(&cc.device_id));
        assert!(!set.can_revoke(&pk_hex(&root), &pk_hex(&a), &cb.device_id));
        assert!(!set.can_revoke(&pk_hex(&root), &pk_hex(&c), &ca.device_id));
        assert!(set.can_revoke(&pk_hex(&root), &pk_hex(&a), &cc.device_id));
        assert!(set.can_revoke(&pk_hex(&root), &pk_hex(&root), &ca.device_id));
        assert!(set.can_revoke(&pk_hex(&root), &pk_hex(&c), &cc.device_id));
    }

    #[test]
    fn grandparent_and_self_can_revoke() {
        let root = key(1);
        let a = key(2);
        let b = key(3);
        let c = key(4);
        let ca = cert(&root, &a, &root);
        let cb = cert(&root, &b, &a);
        let cc = cert(&root, &c, &b);

        // Grandparent A revokes C; B self-revokes.
        let entries = vec![
            DeviceEntry::new(ca.clone(), None),
            DeviceEntry::new(cb.clone(), Some(revoke(&root, &cb, &b))),
            DeviceEntry::new(cc.clone(), Some(revoke(&root, &cc, &a))),
        ];
        let set = evaluate(&pk_hex(&root), &entries);
        assert!(set.is_active(&ca.device_id));
        assert!(!set.is_active(&cb.device_id), "self-revocation should take effect");
        assert!(!set.is_active(&cc.device_id), "active grandparent should revoke descendant");
    }

    #[test]
    fn revoked_ancestor_loses_revocation_authority_over_descendant() {
        let root = key(1);
        let a = key(2);
        let b = key(3);
        let ca = cert(&root, &a, &root);
        let cb = cert(&root, &b, &a);
        // Root revokes A; A had also tried to revoke B.
        let entries = vec![
            DeviceEntry::new(ca.clone(), Some(revoke(&root, &ca, &root))),
            DeviceEntry::new(cb.clone(), Some(revoke(&root, &cb, &a))),
        ];
        let set = evaluate(&pk_hex(&root), &entries);
        assert!(!set.is_active(&ca.device_id));
        assert!(
            set.is_active(&cb.device_id),
            "revocation by a root-revoked ancestor must not hold B revoked"
        );
    }
}
