use crate::db::Db;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use topaz_proto::auth::{evaluate, DeviceSet, MAX_SKEW_SECS};
use topaz_proto::{DeviceEntry, EnrollReply, SignalEnvelope};
use tokio::sync::broadcast;

/// Devices that stop re-registering are treated as offline after this.
pub const ONLINE_TTL_SECS: u64 = 60;
/// Enrollment mailboxes live 5 minutes: enough to carry a `setup` bundle to
/// the other machine by hand, still a narrow one-time window.
pub const MAILBOX_TTL: Duration = Duration::from_secs(300);

pub struct Online {
    pub user_id: String,
    pub endpoints: Vec<String>,
    pub last_seen: u64,
}

pub struct Mailbox {
    pub user_id: String,
    pub owner: String,
    pub created: Instant,
    pub msg_a: String,
    pub reply: Option<EnrollReply>,
    pub finish: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ActiveDevice {
    pub device_id: String,
    pub user_id: String,
    pub pubkey: String,
}

pub struct AppState {
    pub db: Db,
    relay_advertise: Option<String>,
    relay_port: u16,
    relay_ws_advertise: Option<String>,
    https_port: u16,
    relay_ws_port: Mutex<Option<u16>>,
    /// `(advertised host:port override, bound port)`; None while STUN is off.
    stun: Mutex<Option<(Option<String>, u16)>>,
    pub online: Mutex<HashMap<String, Online>>,
    nonces: Mutex<HashMap<String, u64>>,
    pub mailboxes: Mutex<HashMap<String, Mailbox>>,
    signals: Mutex<HashMap<String, broadcast::Sender<SignalEnvelope>>>,
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `YYYY-MM-DD` in UTC for a unix timestamp.
pub fn utc_day(secs: u64) -> String {
    // Howard Hinnant's civil_from_days.
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

impl AppState {
    pub fn new(
        db: Db,
        relay_advertise: Option<String>,
        relay_port: u16,
        relay_ws_advertise: Option<String>,
        https_port: u16,
    ) -> Self {
        Self {
            db,
            relay_advertise,
            relay_port,
            relay_ws_advertise,
            https_port,
            relay_ws_port: Mutex::new(None),
            stun: Mutex::new(None),
            online: Mutex::new(HashMap::new()),
            nonces: Mutex::new(HashMap::new()),
            mailboxes: Mutex::new(HashMap::new()),
            signals: Mutex::new(HashMap::new()),
        }
    }

    /// Record that an extra HTTPS+WSS port (typically 443) is actually listening.
    pub fn set_relay_ws_listen_port(&self, port: u16) {
        *self.relay_ws_port.lock().unwrap() = Some(port);
    }

    /// Record the STUN listener (`advertise` as `host:port`, or derived).
    /// Calling this is what enables STUN in the register response.
    pub fn set_stun(&self, advertise: Option<String>, port: u16) {
        *self.stun.lock().unwrap() = Some((advertise, port));
    }

    /// STUN endpoint for the register response; empty while STUN is off.
    pub fn advertise_stun(&self, host_header: Option<&str>) -> String {
        let Some((advertise, port)) = &*self.stun.lock().unwrap() else {
            return String::new();
        };
        if let Some(adv) = advertise {
            return adv.clone();
        }
        let host = host_without_port(host_header);
        format!("{host}:{port}")
    }

    /// Root key, raw entries and evaluated device set for an account.
    pub fn account(&self, user_id: &str) -> Option<(String, Vec<DeviceEntry>, DeviceSet)> {
        let user_pubkey = self.db.user_pubkey(user_id).ok()??;
        let entries = self.db.entries(user_id).ok()?;
        let set = evaluate(&user_pubkey, &entries);
        Some((user_pubkey, entries, set))
    }

    pub fn active_device(&self, device_id: &str) -> Option<ActiveDevice> {
        let user_id = self.db.device_user(device_id).ok()??;
        let (_, _, set) = self.account(&user_id)?;
        let cert = set.active_by_id(device_id)?;
        Some(ActiveDevice {
            device_id: device_id.to_string(),
            user_id,
            pubkey: cert.device_pubkey.clone(),
        })
    }

    /// Accept a signed message's time and nonce at most once.
    pub fn fresh(&self, time: u64, nonce: &str) -> bool {
        let now = now_unix();
        if time.abs_diff(now) > MAX_SKEW_SECS || nonce.len() < 16 || nonce.len() > 128 {
            return false;
        }
        let mut nonces = self.nonces.lock().unwrap();
        nonces.retain(|_, t| now.saturating_sub(*t) <= 2 * MAX_SKEW_SECS);
        if nonces.len() >= 65_536 {
            return false;
        }
        nonces.insert(nonce.to_string(), time).is_none()
    }

    pub fn advertise_relay(&self, host_header: Option<&str>) -> String {
        if let Some(adv) = &self.relay_advertise {
            return if adv.starts_with("tcp://") {
                adv.clone()
            } else {
                format!("tcp://{adv}")
            };
        }
        let host = host_without_port(host_header);
        format!("tcp://{host}:{}", self.relay_port)
    }

    pub fn advertise_relay_ws(&self, host_header: Option<&str>) -> String {
        if let Some(adv) = &self.relay_ws_advertise {
            if adv.starts_with("wss://") || adv.starts_with("ws://") {
                return adv.clone();
            }
            let path = if adv.contains("/v1/relay") {
                String::new()
            } else {
                "/v1/relay".to_string()
            };
            return format!("wss://{adv}{path}");
        }
        let host = host_without_port(host_header);
        let port = self
            .relay_ws_port
            .lock()
            .unwrap()
            .unwrap_or(self.https_port);
        format!("wss://{host}:{port}/v1/relay")
    }

    pub fn drop_device(&self, device_id: &str) {
        self.online.lock().unwrap().remove(device_id);
        self.signals.lock().unwrap().remove(device_id);
    }

    pub fn subscribe_signals(&self, device_id: &str) -> broadcast::Receiver<SignalEnvelope> {
        let mut map = self.signals.lock().unwrap();
        map.entry(device_id.to_string())
            .or_insert_with(|| broadcast::channel(64).0)
            .subscribe()
    }

    pub fn route_signal(&self, env: SignalEnvelope) {
        if let Some(tx) = self.signals.lock().unwrap().get(&env.to) {
            let _ = tx.send(env);
        }
    }

    pub fn purge_mailboxes(&self) {
        self.mailboxes
            .lock()
            .unwrap()
            .retain(|_, m| m.created.elapsed() < MAILBOX_TTL);
    }
}

/// Strip an optional `:port` suffix from an HTTP `Host` header while preserving
/// bracketed IPv6 literals such as `[2001:db8::1]` or `[2001:db8::1]:7722`.
fn host_without_port(host_header: Option<&str>) -> &str {
    let Some(h) = host_header.map(str::trim).filter(|s| !s.is_empty()) else {
        return "127.0.0.1";
    };
    if let Some(rest) = h.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return &h[..=end + 1];
        }
        return h;
    }
    match h.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !host.contains(':') && port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => h,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_day_known_dates() {
        assert_eq!(super::utc_day(0), "1970-01-01");
        assert_eq!(super::utc_day(1_709_164_800), "2024-02-29");
        assert_eq!(super::utc_day(1_792_281_600), "2026-10-18");
    }

    fn tmp_state(relay_ws_advertise: Option<String>, https_port: u16) -> AppState {
        let path = std::env::temp_dir().join(format!(
            "ss-state-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let db = crate::db::Db::open(&path).unwrap();
        AppState::new(db, None, 7723, relay_ws_advertise, https_port)
    }

    #[test]
    fn advertise_relay_ws_defaults_to_https_port() {
        let st = tmp_state(None, 7722);
        assert_eq!(
            st.advertise_relay_ws(Some("10.0.0.1:7722")),
            "wss://10.0.0.1:7722/v1/relay"
        );
    }

    #[test]
    fn advertise_relay_ws_prefers_bound_extra_port() {
        let st = tmp_state(None, 7722);
        st.set_relay_ws_listen_port(443);
        assert_eq!(
            st.advertise_relay_ws(Some("10.0.0.1:7722")),
            "wss://10.0.0.1:443/v1/relay"
        );
    }

    #[test]
    fn advertise_relay_ws_explicit_url() {
        let st = tmp_state(Some("wss://vps.example:443/v1/relay".into()), 7722);
        assert_eq!(
            st.advertise_relay_ws(Some("10.0.0.1:7722")),
            "wss://vps.example:443/v1/relay"
        );
    }

    #[test]
    fn host_without_port_preserves_ipv6_literals() {
        assert_eq!(host_without_port(Some("[2001:db8::1]")), "[2001:db8::1]");
        assert_eq!(host_without_port(Some("[2001:db8::1]:7722")), "[2001:db8::1]");
        assert_eq!(host_without_port(Some("vps.example:7722")), "vps.example");
        assert_eq!(host_without_port(Some("vps.example")), "vps.example");
        assert_eq!(host_without_port(None), "127.0.0.1");
    }
}

