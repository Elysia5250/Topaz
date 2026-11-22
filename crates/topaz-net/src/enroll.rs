//! Adding a device to an account with a short one-time code.
//!
//! The code is `NAMEPLATE-PASSWORD`. The nameplate finds the mailbox on the
//! coord; the password feeds SPAKE2, so the coord (or anyone watching the
//! plaintext HTTP) cannot swap keys without guessing the password, and a wrong
//! guess burns the mailbox.

use crate::coord::CoordClient;
use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::time::{Duration, Instant};
use topaz_core::{issue_cert, AccountInfo, DeviceIdentity};
use topaz_proto::{DeviceCert, EnrollReply};

/// Both sides poll for up to the coord's mailbox TTL: the code may travel to
/// the other machine as a `setup` bundle, by hand.
const TIMEOUT: Duration = Duration::from_secs(300);
const POLL: Duration = Duration::from_millis(500);
const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const ID_A: &[u8] = b"topaz-enroll-existing";
const ID_B: &[u8] = b"topaz-enroll-new";
const NONCE_NEW: [u8; 12] = [0; 12];
const NONCE_EXISTING: [u8; 12] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

#[derive(Serialize, Deserialize)]
struct JoinRequest {
    device_pubkey: String,
    name: String,
}

fn cipher(shared: &[u8]) -> ChaCha20Poly1305 {
    let key = blake3::derive_key("topaz enroll v1", shared);
    ChaCha20Poly1305::new(Key::from_slice(&key))
}

fn seal(shared: &[u8], nonce: [u8; 12], plain: &[u8]) -> Result<String> {
    let ct = cipher(shared)
        .encrypt(Nonce::from_slice(&nonce), plain)
        .map_err(|_| anyhow!("encrypt failed"))?;
    Ok(hex::encode(ct))
}

fn open(shared: &[u8], nonce: [u8; 12], hex_ct: &str) -> Result<Vec<u8>> {
    let ct = hex::decode(hex_ct)?;
    cipher(shared)
        .decrypt(Nonce::from_slice(&nonce), ct.as_slice())
        .map_err(|_| anyhow!("code did not match; start again with a new code"))
}

fn password() -> String {
    let mut rng = rand::rngs::OsRng;
    (0..5)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

fn normalize(code: &str) -> Result<(String, String)> {
    let cleaned: String = code
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    let (nameplate, pw) = cleaned
        .split_once('-')
        .ok_or_else(|| anyhow!("code should look like ABC-DEFGH"))?;
    if nameplate.is_empty() || pw.is_empty() {
        bail!("code should look like ABC-DEFGH");
    }
    Ok((nameplate.to_string(), pw.to_string()))
}

async fn poll<T, F, Fut>(mut f: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Option<T>>>,
{
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if let Some(v) = f().await? {
            return Ok(v);
        }
        if Instant::now() > deadline {
            bail!("timed out waiting for the other device");
        }
        tokio::time::sleep(POLL).await;
    }
}

/// Run on a device that is already in the account. `show_code` is called once
/// with the code to type on the new device. Returns the issued certificate.
pub async fn approve_new_device(
    coord: &CoordClient,
    identity: &DeviceIdentity,
    account: &AccountInfo,
    show_code: impl FnOnce(&str),
) -> Result<DeviceCert> {
    let pw = password();
    let (state, msg_a) =
        Spake2::<Ed25519Group>::start_a(&Password::new(pw.as_bytes()), &Identity::new(ID_A), &Identity::new(ID_B));
    let nameplate = coord.enroll_start(hex::encode(msg_a)).await?;
    show_code(&format!("{nameplate}-{pw}"));

    let reply = poll(|| coord.enroll_get_reply(&nameplate)).await?;
    let shared = state
        .finish(&hex::decode(&reply.msg_b)?)
        .map_err(|_| anyhow!("key exchange failed"))?;
    let req: JoinRequest = serde_json::from_slice(&open(&shared, NONCE_NEW, &reply.payload)?)
        .context("malformed join request")?;

    let cert = issue_cert(
        &identity.signing,
        &account.user_id,
        &account.user_pubkey,
        &req.device_pubkey,
        &req.name,
    )?;
    coord.add_device(&cert).await?;
    coord
        .enroll_finish(
            &nameplate,
            seal(&shared, NONCE_EXISTING, &serde_json::to_vec(&cert)?)?,
        )
        .await?;
    Ok(cert)
}

fn generate_finish_token() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Derive a 6-digit Short Authentication String (`NNN-NNN`) from the SPAKE2
/// shared key so both users can visually confirm there is no MitM.
pub fn derive_sas(shared: &[u8]) -> String {
    let digest = blake3::derive_key("topaz pair sas v1", shared);
    let num = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    format!("{:03}-{:03}", num / 1000, num % 1000)
}

/// Run on the new device with the code shown by an existing device.
pub async fn join_with_code(
    coord: &CoordClient,
    identity: &DeviceIdentity,
    name: &str,
    code: &str,
) -> Result<DeviceCert> {
    let (nameplate, pw) = normalize(code)?;
    let msg_a = coord.enroll_offer(&nameplate).await?;
    let (state, msg_b) =
        Spake2::<Ed25519Group>::start_b(&Password::new(pw.as_bytes()), &Identity::new(ID_A), &Identity::new(ID_B));
    let shared = state
        .finish(&hex::decode(&msg_a)?)
        .map_err(|_| anyhow!("key exchange failed"))?;
    let request = JoinRequest {
        device_pubkey: identity.pubkey_hex.clone(),
        name: name.to_string(),
    };
    let finish_token = generate_finish_token();
    coord
        .enroll_reply(
            &nameplate,
            &EnrollReply {
                msg_b: hex::encode(msg_b),
                payload: seal(&shared, NONCE_NEW, &serde_json::to_vec(&request)?)?,
                finish_token: finish_token.clone(),
            },
        )
        .await?;

    let payload = poll(|| coord.enroll_get_finish(&nameplate, &finish_token)).await?;
    let cert: DeviceCert = serde_json::from_slice(&open(&shared, NONCE_EXISTING, &payload)?)
        .context("malformed certificate")?;
    Ok(cert)
}

/// Normalize a user-chosen pairing phrase (case-insensitive, trimmed).
pub fn normalize_secret(secret: &str) -> Result<String> {
    let cleaned = secret.trim().to_ascii_lowercase();
    if cleaned.len() < 6 {
        bail!("pairing phrase must be at least 6 characters");
    }
    Ok(cleaned)
}

/// Derive an opaque 24-hex-char room key from a user-chosen pairing phrase
/// using Argon2id (19 MiB, t=2, p=1) so the coord never sees the plaintext
/// secret and offline dictionary attacks against the room key are expensive.
pub fn pair_room_key(normalized_secret: &str) -> String {
    const SALT: &[u8] = b"topaz-pair-room-argon2id-v2";
    let params = Params::new(19 * 1024, 2, 1, Some(32)).expect("valid argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(normalized_secret.as_bytes(), SALT, &mut out)
        .expect("argon2 hash failed");
    hex::encode(&out[..12])
}

async fn pair_room_key_async(normalized_secret: String) -> Result<String> {
    tokio::task::spawn_blocking(move || pair_room_key(&normalized_secret))
        .await
        .map_err(|e| anyhow!("kdf task failed: {e}"))
}

/// Decrypted incoming phrase-pairing request waiting for explicit user approval.
pub struct PendingSecretApproval {
    coord: CoordClient,
    identity: DeviceIdentity,
    account: AccountInfo,
    nameplate: String,
    shared: Vec<u8>,
    pub device_pubkey: String,
    pub device_name: String,
    pub device_id: String,
    /// 6-digit Short Authentication String derived from the SPAKE2 key.
    pub sas: String,
}

impl PendingSecretApproval {
    /// Sign and publish the new device certificate and finish the SPAKE2 exchange.
    pub async fn approve(self) -> Result<DeviceCert> {
        let cert = issue_cert(
            &self.identity.signing,
            &self.account.user_id,
            &self.account.user_pubkey,
            &self.device_pubkey,
            &self.device_name,
        )?;
        self.coord.add_device(&cert).await?;
        self.coord
            .enroll_finish(
                &self.nameplate,
                seal(&self.shared, NONCE_EXISTING, &serde_json::to_vec(&cert)?)?,
            )
            .await?;
        Ok(cert)
    }
}

/// Stage 1 of phrase pairing: publish a derived room on coord and wait for the
/// joining device to complete SPAKE2 key exchange and send its name & pubkey.
pub async fn wait_secret_pair_request(
    coord: &CoordClient,
    identity: &DeviceIdentity,
    account: &AccountInfo,
    secret: &str,
) -> Result<PendingSecretApproval> {
    let pw = normalize_secret(secret)?;
    let room = pair_room_key_async(pw.clone()).await?;
    let (state, msg_a) = Spake2::<Ed25519Group>::start_a(
        &Password::new(pw.as_bytes()),
        &Identity::new(ID_A),
        &Identity::new(ID_B),
    );
    let nameplate = coord.enroll_start_room(hex::encode(msg_a), Some(room)).await?;

    let reply = poll(|| coord.enroll_get_reply(&nameplate)).await?;
    let shared = state
        .finish(&hex::decode(&reply.msg_b)?)
        .map_err(|_| anyhow!("key exchange failed"))?;
    let req: JoinRequest = serde_json::from_slice(&open(&shared, NONCE_NEW, &reply.payload)?)
        .context("malformed join request")?;

    let device_id = topaz_proto::auth::derive_id_hex(&req.device_pubkey)
        .ok_or_else(|| anyhow!("new device sent malformed public key"))?;
    let sas = derive_sas(&shared);
    Ok(PendingSecretApproval {
        coord: coord.clone(),
        identity: identity.clone(),
        account: account.clone(),
        nameplate,
        shared,
        device_pubkey: req.device_pubkey,
        device_name: req.name,
        device_id,
        sas,
    })
}

/// Approve a new device using a user-chosen pairing phrase (both sides enter
/// the same phrase; the coord only sees an Argon2id-derived room key and SPAKE2
/// traffic). `confirm` is called with `(device_name, device_id, sas)` before
/// signing the cert.
pub async fn approve_with_secret(
    coord: &CoordClient,
    identity: &DeviceIdentity,
    account: &AccountInfo,
    secret: &str,
    confirm: impl FnOnce(&str, &str, &str) -> Result<bool>,
) -> Result<DeviceCert> {
    let pending = wait_secret_pair_request(coord, identity, account, secret).await?;
    if !confirm(&pending.device_name, &pending.device_id, &pending.sas)? {
        bail!("pairing rejected by user");
    }
    pending.approve().await
}

/// Join an existing account using a user-chosen pairing phrase, invoking
/// `on_sas` once the SPAKE2 shared key and 6-digit verification code are ready.
pub async fn join_with_secret_with_sas(
    coord: &CoordClient,
    identity: &DeviceIdentity,
    name: &str,
    secret: &str,
    on_sas: impl FnOnce(&str),
) -> Result<DeviceCert> {
    let pw = normalize_secret(secret)?;
    let room = pair_room_key_async(pw.clone()).await?;
    let msg_a = poll(|| coord.enroll_offer_opt(&room)).await?;
    let (state, msg_b) = Spake2::<Ed25519Group>::start_b(
        &Password::new(pw.as_bytes()),
        &Identity::new(ID_A),
        &Identity::new(ID_B),
    );
    let shared = state
        .finish(&hex::decode(&msg_a)?)
        .map_err(|_| anyhow!("key exchange failed"))?;
    on_sas(&derive_sas(&shared));
    let request = JoinRequest {
        device_pubkey: identity.pubkey_hex.clone(),
        name: name.to_string(),
    };
    let finish_token = generate_finish_token();
    coord
        .enroll_reply(
            &room,
            &EnrollReply {
                msg_b: hex::encode(msg_b),
                payload: seal(&shared, NONCE_NEW, &serde_json::to_vec(&request)?)?,
                finish_token: finish_token.clone(),
            },
        )
        .await?;

    let payload = poll(|| coord.enroll_get_finish(&room, &finish_token)).await?;
    let cert: DeviceCert = serde_json::from_slice(&open(&shared, NONCE_EXISTING, &payload)?)
        .context("malformed certificate")?;
    Ok(cert)
}

/// Join an existing account using a user-chosen pairing phrase. Polls until
/// the existing device publishes the matching room (order-independent).
pub async fn join_with_secret(
    coord: &CoordClient,
    identity: &DeviceIdentity,
    name: &str,
    secret: &str,
) -> Result<DeviceCert> {
    join_with_secret_with_sas(coord, identity, name, secret, |_| {}).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_normalization() {
        assert_eq!(
            normalize(" k7q-4mzp2 ").unwrap(),
            ("K7Q".to_string(), "4MZP2".to_string())
        );
        assert!(normalize("K7Q4MZP2").is_err());
    }

    #[test]
    fn spake_wrong_password_fails_to_open() {
        let (a, ma) = Spake2::<Ed25519Group>::start_a(
            &Password::new(b"RIGHT"),
            &Identity::new(ID_A),
            &Identity::new(ID_B),
        );
        let (b, mb) = Spake2::<Ed25519Group>::start_b(
            &Password::new(b"WRONG"),
            &Identity::new(ID_A),
            &Identity::new(ID_B),
        );
        let ka = a.finish(&mb).unwrap();
        let kb = b.finish(&ma).unwrap();
        let sealed = seal(&kb, NONCE_NEW, b"hello").unwrap();
        assert!(open(&ka, NONCE_NEW, &sealed).is_err());
    }
}
