//! Adding a device to an account with a short one-time code.
//!
//! The code is `NAMEPLATE-PASSWORD`. The nameplate finds the mailbox on the
//! coord; the password feeds SPAKE2, so the coord (or anyone watching the
//! plaintext HTTP) cannot swap keys without guessing the password, and a wrong
//! guess burns the mailbox.

use crate::coord::CoordClient;
use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::Rng;
use serde::{Deserialize, Serialize};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::time::{Duration, Instant};
use conduit_core::{issue_cert, AccountInfo, DeviceIdentity};
use conduit_proto::{DeviceCert, EnrollReply};

/// Both sides poll for up to the coord's mailbox TTL: the code may travel to
/// the other machine as a `setup` bundle, by hand.
const TIMEOUT: Duration = Duration::from_secs(300);
const POLL: Duration = Duration::from_millis(500);
const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const ID_A: &[u8] = b"conduit-enroll-existing";
const ID_B: &[u8] = b"conduit-enroll-new";
const NONCE_NEW: [u8; 12] = [0; 12];
const NONCE_EXISTING: [u8; 12] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

#[derive(Serialize, Deserialize)]
struct JoinRequest {
    device_pubkey: String,
    name: String,
}

fn cipher(shared: &[u8]) -> ChaCha20Poly1305 {
    let key = blake3::derive_key("conduit enroll v1", shared);
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
    coord
        .enroll_reply(
            &nameplate,
            &EnrollReply {
                msg_b: hex::encode(msg_b),
                payload: seal(&shared, NONCE_NEW, &serde_json::to_vec(&request)?)?,
            },
        )
        .await?;

    let payload = poll(|| coord.enroll_get_finish(&nameplate)).await?;
    let cert: DeviceCert = serde_json::from_slice(&open(&shared, NONCE_EXISTING, &payload)?)
        .context("malformed certificate")?;
    Ok(cert)
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
