//! Persistent account data: root public keys, device certificates,
//! revocations and invite codes. Nothing here lets the server act as a user.

use anyhow::{bail, Result};
use rand::Rng;
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Mutex;
use topaz_proto::auth::{dns_label_with_suffix, sanitize_dns_label};
use topaz_proto::{DeviceCert, DeviceEntry, Revocation};

const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";

/// Base IPv4 of `100.64.0.0/10` (`100.64.0.0`).
const CGNAT_BASE: u32 = u32::from_be_bytes([100, 64, 0, 0]);
/// Inclusive end of `100.64.0.0/10` (`100.127.255.255`).
const CGNAT_END: u32 = u32::from_be_bytes([100, 127, 255, 255]);

pub struct Db {
    conn: Mutex<Connection>,
}

#[derive(Debug)]
pub enum CreateAccountError {
    InviteInvalid,
    AccountExists,
    Other(anyhow::Error),
}

impl From<rusqlite::Error> for CreateAccountError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Other(e.into())
    }
}

impl From<anyhow::Error> for CreateAccountError {
    fn from(e: anyhow::Error) -> Self {
        Self::Other(e)
    }
}

pub fn normalize_invite(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_uppercase()
}

pub fn display_invite(code: &str) -> String {
    if code.len() == 10 {
        format!("{}-{}", &code[..5], &code[5..])
    } else {
        code.to_string()
    }
}

fn has_column(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn allocate_virtual_ip(tx: &Transaction<'_>, user_id: &str) -> Result<String> {
    let mut stmt = tx.prepare(
        "SELECT virtual_ip FROM devices WHERE user_id = ?1 AND virtual_ip IS NOT NULL",
    )?;
    let used: HashSet<String> = stmt
        .query_map(params![user_id], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<HashSet<_>>>()?;

    for raw in (CGNAT_BASE + 1)..=CGNAT_END {
        let last_octet = raw & 0xff;
        if last_octet == 0 || last_octet == 255 {
            continue;
        }
        let candidate = Ipv4Addr::from(raw).to_string();
        if !used.contains(&candidate) {
            return Ok(candidate);
        }
    }
    bail!("virtual IP pool exhausted for account {user_id}");
}

fn allocate_dns_name(
    tx: &Transaction<'_>,
    user_id: &str,
    device_id: &str,
    device_name: &str,
) -> Result<String> {
    let mut stmt = tx.prepare(
        "SELECT dns_name FROM devices \
         WHERE user_id = ?1 AND revocation IS NULL AND dns_name IS NOT NULL AND device_id != ?2",
    )?;
    let used: HashSet<String> = stmt
        .query_map(params![user_id, device_id], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<HashSet<_>>>()?;

    let base = sanitize_dns_label(device_name, device_id);
    for idx in 1u32.. {
        let candidate = dns_label_with_suffix(&base, idx);
        if !used.contains(&candidate) {
            return Ok(candidate);
        }
    }
    unreachable!("unbounded u32 loop")
}

fn backfill_ipam(conn: &mut Connection) -> Result<()> {
    struct BackfillRow {
        device_id: String,
        user_id: String,
        cert_json: String,
        revocation: Option<String>,
        virtual_ip: Option<String>,
        dns_name: Option<String>,
    }

    let tx = conn.transaction()?;
    let rows: Vec<BackfillRow> = {
        let mut stmt = tx.prepare(
            "SELECT device_id, user_id, cert, revocation, virtual_ip, dns_name \
             FROM devices \
             WHERE virtual_ip IS NULL OR (revocation IS NULL AND dns_name IS NULL) \
             ORDER BY rowid",
        )?;
        let items = stmt
            .query_map([], |r| {
                Ok(BackfillRow {
                    device_id: r.get(0)?,
                    user_id: r.get(1)?,
                    cert_json: r.get(2)?,
                    revocation: r.get(3)?,
                    virtual_ip: r.get(4)?,
                    dns_name: r.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        items
    };

    for row in rows {
        let cert: DeviceCert = serde_json::from_str(&row.cert_json)?;
        let new_vip = match row.virtual_ip {
            Some(v) => v,
            None => allocate_virtual_ip(&tx, &row.user_id)?,
        };
        let new_dns = if row.revocation.is_some() {
            None
        } else {
            match row.dns_name {
                Some(d) => Some(d),
                None => Some(allocate_dns_name(
                    &tx,
                    &row.user_id,
                    &row.device_id,
                    &cert.name,
                )?),
            }
        };
        tx.execute(
            "UPDATE devices SET virtual_ip = ?1, dns_name = ?2 WHERE device_id = ?3",
            params![new_vip, new_dns, row.device_id],
        )?;
    }
    tx.commit()?;
    Ok(())
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        let mut conn = Connection::open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        conn.execute_batch(
            "PRAGMA busy_timeout=5000;
             PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS users(
                 user_id TEXT PRIMARY KEY,
                 user_pubkey TEXT NOT NULL,
                 created_at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS devices(
                 device_id TEXT PRIMARY KEY,
                 user_id TEXT NOT NULL,
                 cert TEXT NOT NULL,
                 revocation TEXT,
                 virtual_ip TEXT,
                 dns_name TEXT);
             CREATE INDEX IF NOT EXISTS devices_user ON devices(user_id);
             CREATE TABLE IF NOT EXISTS invites(
                 code TEXT PRIMARY KEY,
                 created_at INTEGER NOT NULL,
                 used_by TEXT,
                 used_at INTEGER);
             CREATE TABLE IF NOT EXISTS server_meta(
                 key TEXT PRIMARY KEY,
                 value BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS usage(
                 user_id TEXT NOT NULL,
                 day TEXT NOT NULL,
                 bytes INTEGER NOT NULL,
                 PRIMARY KEY (user_id, day));",
        )?;
        if !has_column(&conn, "devices", "virtual_ip")? {
            conn.execute("ALTER TABLE devices ADD COLUMN virtual_ip TEXT", [])?;
        }
        if !has_column(&conn, "devices", "dns_name")? {
            conn.execute("ALTER TABLE devices ADD COLUMN dns_name TEXT", [])?;
        }
        backfill_ipam(&mut conn)?;
        conn.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS devices_user_vip
                 ON devices(user_id, virtual_ip) WHERE virtual_ip IS NOT NULL;
             CREATE UNIQUE INDEX IF NOT EXISTS devices_user_dns
                 ON devices(user_id, dns_name) WHERE dns_name IS NOT NULL AND revocation IS NULL;",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// The server's TLS key seed, created on first use.
    pub fn server_key_seed(&self) -> Result<[u8; 32]> {
        let conn = self.conn.lock().unwrap();
        let existing: Option<Vec<u8>> = conn
            .query_row(
                "SELECT value FROM server_meta WHERE key = 'tls_key'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(seed) = existing {
            return seed
                .try_into()
                .map_err(|_| anyhow::anyhow!("stored TLS key has the wrong length"));
        }
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        conn.execute(
            "INSERT INTO server_meta(key, value) VALUES ('tls_key', ?1)",
            params![seed.to_vec()],
        )?;
        Ok(seed)
    }

    pub fn add_usage(&self, user_id: &str, day: &str, bytes: u64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO usage(user_id, day, bytes) VALUES (?1, ?2, ?3)
             ON CONFLICT(user_id, day) DO UPDATE SET bytes = bytes + excluded.bytes",
            params![user_id, day, bytes as i64],
        )?;
        Ok(())
    }

    /// (day, user_id, bytes), newest day first.
    pub fn usage(&self) -> Result<Vec<(String, String, u64)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT day, user_id, bytes FROM usage ORDER BY day DESC, bytes DESC")?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)? as u64,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn create_invites(&self, count: u32, now: u64) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut rng = rand::rngs::OsRng;
        let mut out = Vec::new();
        while out.len() < count as usize {
            let code: String = (0..10)
                .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
                .collect();
            let inserted = conn.execute(
                "INSERT OR IGNORE INTO invites(code, created_at) VALUES (?1, ?2)",
                params![code, now as i64],
            )?;
            if inserted == 1 {
                out.push(code);
            }
        }
        Ok(out)
    }

    pub fn list_invites(&self) -> Result<Vec<(String, u64, Option<String>)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT code, created_at, used_by FROM invites ORDER BY created_at")?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)? as u64,
                    r.get::<_, Option<String>>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn create_account(
        &self,
        invite: &str,
        cert: &DeviceCert,
        now: u64,
    ) -> Result<(), CreateAccountError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let unused: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM invites WHERE code = ?1 AND used_by IS NULL",
                params![invite],
                |r| r.get(0),
            )
            .optional()?;
        if unused.is_none() {
            return Err(CreateAccountError::InviteInvalid);
        }
        let exists: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM users WHERE user_id = ?1",
                params![cert.user_id],
                |r| r.get(0),
            )
            .optional()?;
        if exists.is_some() {
            return Err(CreateAccountError::AccountExists);
        }
        let cert_json =
            serde_json::to_string(cert).map_err(|e| CreateAccountError::Other(e.into()))?;
        let vip = allocate_virtual_ip(&tx, &cert.user_id)?;
        let dns = allocate_dns_name(&tx, &cert.user_id, &cert.device_id, &cert.name)?;
        tx.execute(
            "INSERT INTO users(user_id, user_pubkey, created_at) VALUES (?1, ?2, ?3)",
            params![cert.user_id, cert.user_pubkey, now as i64],
        )?;
        tx.execute(
            "INSERT INTO devices(device_id, user_id, cert, virtual_ip, dns_name) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![cert.device_id, cert.user_id, cert_json, vip, dns],
        )?;
        tx.execute(
            "UPDATE invites SET used_by = ?1, used_at = ?2 WHERE code = ?3",
            params![cert.user_id, now as i64, invite],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn user_pubkey(&self, user_id: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT user_pubkey FROM users WHERE user_id = ?1",
                params![user_id],
                |r| r.get(0),
            )
            .optional()?)
    }

    pub fn device_user(&self, device_id: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT user_id FROM devices WHERE device_id = ?1",
                params![device_id],
                |r| r.get(0),
            )
            .optional()?)
    }

    pub fn entries(&self, user_id: &str) -> Result<Vec<DeviceEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT cert, revocation, virtual_ip, dns_name \
             FROM devices WHERE user_id = ?1 ORDER BY rowid",
        )?;
        let rows = stmt
            .query_map(params![user_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut out = Vec::with_capacity(rows.len());
        for (cert, rev, virtual_ip, dns_name) in rows {
            out.push(DeviceEntry {
                cert: serde_json::from_str(&cert)?,
                revocation: rev.map(|r| serde_json::from_str(&r)).transpose()?,
                virtual_ip,
                dns_name,
            });
        }
        Ok(out)
    }

    pub fn insert_device(&self, cert: &DeviceCert) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let vip = allocate_virtual_ip(&tx, &cert.user_id)?;
        let dns = allocate_dns_name(&tx, &cert.user_id, &cert.device_id, &cert.name)?;
        tx.execute(
            "INSERT INTO devices(device_id, user_id, cert, virtual_ip, dns_name) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                cert.device_id,
                cert.user_id,
                serde_json::to_string(cert)?,
                vip,
                dns
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn set_revocation(&self, rev: &Revocation) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE devices SET revocation = ?1, dns_name = NULL WHERE device_id = ?2",
            params![serde_json::to_string(rev)?, rev.device_id],
        )?;
        Ok(())
    }

    /// Re-assign `dns_name` for any device that is currently active according to
    /// `active_ids` (e.g. if a previously stored revocation became invalid after
    /// its issuer was revoked by the root key) but currently has `dns_name IS NULL`.
    pub fn ensure_active_dns_names(
        &self,
        user_id: &str,
        active_ids: &HashSet<String>,
    ) -> Result<()> {
        if active_ids.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let missing: Vec<(String, String)> = {
            let mut stmt = tx.prepare(
                "SELECT device_id, cert FROM devices \
                 WHERE user_id = ?1 AND (dns_name IS NULL OR revocation IS NOT NULL) \
                 ORDER BY rowid",
            )?;
            let rows = stmt
                .query_map(params![user_id], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        for (device_id, cert_json) in missing {
            if !active_ids.contains(&device_id) {
                continue;
            }
            let cert: DeviceCert = serde_json::from_str(&cert_json)?;
            let dns = allocate_dns_name(&tx, user_id, &device_id, &cert.name)?;
            tx.execute(
                "UPDATE devices SET revocation = NULL, dns_name = ?1 WHERE device_id = ?2",
                params![dns, device_id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use topaz_proto::auth::derive_id;
    use ed25519_dalek::{Signer, SigningKey};

    fn tmp_db(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "topaz-db-{tag}-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn mk_cert(root_seed: u8, dev_seed: u8, name: &str) -> DeviceCert {
        let root = SigningKey::from_bytes(&[root_seed; 32]);
        let dev = SigningKey::from_bytes(&[dev_seed; 32]);
        let user_pk = root.verifying_key().to_bytes();
        let dev_pk = dev.verifying_key().to_bytes();
        let mut cert = DeviceCert {
            user_id: derive_id(&user_pk),
            user_pubkey: hex::encode(user_pk),
            device_id: derive_id(&dev_pk),
            device_pubkey: hex::encode(dev_pk),
            name: name.to_string(),
            issued_at: 100,
            issuer_pubkey: hex::encode(user_pk),
            sig: String::new(),
        };
        cert.sig = hex::encode(root.sign(&cert.signing_bytes()).to_bytes());
        cert
    }

    #[test]
    fn ipam_assigns_sequential_cgnat_ips_and_unique_dns_names() {
        let path = tmp_db("ipam");
        let db = Db::open(&path).unwrap();
        let invites = db.create_invites(2, 100).unwrap();

        let c1 = mk_cert(1, 10, "MacBook Pro");
        let c2 = mk_cert(1, 11, "MacBook Pro");
        let c3 = mk_cert(1, 12, "工作站");
        db.create_account(&invites[0], &c1, 100).unwrap();
        db.insert_device(&c2).unwrap();
        db.insert_device(&c3).unwrap();

        let entries = db.entries(&c1.user_id).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].virtual_ip.as_deref(), Some("100.64.0.1"));
        assert_eq!(entries[0].dns_name.as_deref(), Some("macbook-pro"));
        assert_eq!(entries[1].virtual_ip.as_deref(), Some("100.64.0.2"));
        assert_eq!(entries[1].dns_name.as_deref(), Some("macbook-pro-2"));
        assert_eq!(entries[2].virtual_ip.as_deref(), Some("100.64.0.3"));
        assert_eq!(
            entries[2].dns_name.as_deref(),
            Some(format!("node-{}", &c3.device_id[..6]).as_str())
        );

        // Separate account gets its own 100.64.0.1 & dns namespace.
        let other = mk_cert(2, 20, "MacBook Pro");
        db.create_account(&invites[1], &other, 100).unwrap();
        let other_entries = db.entries(&other.user_id).unwrap();
        assert_eq!(other_entries[0].virtual_ip.as_deref(), Some("100.64.0.1"));
        assert_eq!(other_entries[0].dns_name.as_deref(), Some("macbook-pro"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn revocation_reclaims_dns_name_while_preserving_ip_history() {
        let path = tmp_db("revoke");
        let db = Db::open(&path).unwrap();
        let invite = db.create_invites(1, 100).unwrap().pop().unwrap();
        let c1 = mk_cert(1, 10, "laptop");
        db.create_account(&invite, &c1, 100).unwrap();

        db.set_revocation(&Revocation {
            user_id: c1.user_id.clone(),
            device_id: c1.device_id.clone(),
            issued_at: 200,
            issuer_pubkey: c1.user_pubkey.clone(),
            sig: "sig".into(),
        })
        .unwrap();

        let c2 = mk_cert(1, 11, "laptop");
        db.insert_device(&c2).unwrap();

        let entries = db.entries(&c1.user_id).unwrap();
        assert_eq!(entries[0].virtual_ip.as_deref(), Some("100.64.0.1"));
        assert_eq!(entries[0].dns_name, None);
        assert_eq!(entries[1].virtual_ip.as_deref(), Some("100.64.0.2"));
        assert_eq!(entries[1].dns_name.as_deref(), Some("laptop"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn opens_and_backfills_legacy_schema_without_ipam_columns() {
        let path = tmp_db("legacy");
        let c1 = mk_cert(3, 30, "dev-a");
        let c2 = mk_cert(3, 31, "dev-a");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE users(user_id TEXT PRIMARY KEY, user_pubkey TEXT NOT NULL, created_at INTEGER NOT NULL);
                 CREATE TABLE devices(device_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, cert TEXT NOT NULL, revocation TEXT);
                 CREATE TABLE invites(code TEXT PRIMARY KEY, created_at INTEGER NOT NULL, used_by TEXT, used_at INTEGER);
                 CREATE TABLE server_meta(key TEXT PRIMARY KEY, value BLOB NOT NULL);
                 CREATE TABLE usage(user_id TEXT NOT NULL, day TEXT NOT NULL, bytes INTEGER NOT NULL, PRIMARY KEY (user_id, day));",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO users(user_id, user_pubkey, created_at) VALUES (?1, ?2, 1)",
                params![c1.user_id, c1.user_pubkey],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO devices(device_id, user_id, cert) VALUES (?1, ?2, ?3)",
                params![c1.device_id, c1.user_id, serde_json::to_string(&c1).unwrap()],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO devices(device_id, user_id, cert) VALUES (?1, ?2, ?3)",
                params![c2.device_id, c2.user_id, serde_json::to_string(&c2).unwrap()],
            )
            .unwrap();
        }

        let db = Db::open(&path).unwrap();
        let entries = db.entries(&c1.user_id).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].virtual_ip.as_deref(), Some("100.64.0.1"));
        assert_eq!(entries[0].dns_name.as_deref(), Some("dev-a"));
        assert_eq!(entries[1].virtual_ip.as_deref(), Some("100.64.0.2"));
        assert_eq!(entries[1].dns_name.as_deref(), Some("dev-a-2"));

        let _ = std::fs::remove_file(&path);
    }
}
