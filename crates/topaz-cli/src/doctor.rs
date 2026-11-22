use anyhow::Result;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;
use topaz_core::Store;
use topaz_fabric::mdns;
use topaz_net::{collect_local_endpoints, stun, CoordClient};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    Running,
    Ok,
    Warn,
    Fail,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorCheck {
    pub id: &'static str,
    pub label: &'static str,
    pub status: CheckStatus,
    pub detail: String,
    pub latency_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorPeerReport {
    pub device_id: String,
    pub name: String,
    pub session_path: Option<String>,
    pub rtt_ms: Option<u64>,
    pub udp_endpoints: Option<Vec<String>>,
    pub udp_error: Option<String>,
    pub lan_addr: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DoctorReport {
    pub device_id: String,
    pub device_name: String,
    pub account: Option<String>,
    pub coord_url: String,
    pub coord_pin: String,
    pub coord_version: Option<String>,
    pub daemon_live: bool,
    pub daemon_uptime_s: Option<u64>,
    pub daemon_note: String,
    pub coord_ok: bool,
    pub checks: Vec<DoctorCheck>,
    pub local_addrs: Vec<String>,
    pub mdns: Vec<(String, String)>,
    pub peers: Vec<DoctorPeerReport>,
    pub peers_error: Option<String>,
    pub finished: bool,
}

impl DoctorReport {
    pub fn to_plain_summary(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("device_id {}\n", self.device_id));
        out.push_str(&format!("device_name {}\n", self.device_name));
        out.push_str(&format!(
            "account {}\n",
            self.account.as_deref().unwrap_or("(none)")
        ));
        out.push_str(&format!("client_version {}\n", topaz_proto::VERSION_LONG));
        out.push_str(&format!("coord_url {}\n", self.coord_url));
        out.push_str(&format!("coord_pin {}\n", self.coord_pin));
        if let Some(ref v) = self.coord_version {
            out.push_str(&format!("coord_version {v}\n"));
        }
        for c in &self.checks {
            let tag = match c.status {
                CheckStatus::Ok => "ok",
                CheckStatus::Warn => "warn",
                CheckStatus::Fail => "fail",
                CheckStatus::Running => "running",
                CheckStatus::Skipped => "skip",
            };
            if let Some(ms) = c.latency_ms {
                out.push_str(&format!("{} [{}] {} ({ms}ms)\n", c.label, tag, c.detail));
            } else {
                out.push_str(&format!("{} [{}] {}\n", c.label, tag, c.detail));
            }
        }
        if !self.local_addrs.is_empty() {
            out.push_str("local_addrs\n");
            for addr in &self.local_addrs {
                out.push_str(&format!("  {addr}\n"));
            }
        }
        if !self.peers.is_empty() {
            out.push_str("peers\n");
            for p in &self.peers {
                let path = p.session_path.as_deref().unwrap_or("offline");
                let rtt = p
                    .rtt_ms
                    .map(|m| format!("{m}ms"))
                    .unwrap_or_else(|| "-".into());
                out.push_str(&format!(
                    "  {} ({}) session={path} rtt={rtt}\n",
                    p.name, p.device_id
                ));
            }
        }
        out
    }
}

fn push_snapshot(tx: &Option<mpsc::UnboundedSender<DoctorReport>>, report: &DoctorReport) {
    if let Some(tx) = tx {
        let _ = tx.send(report.clone());
    }
}

fn upsert_check(
    report: &mut DoctorReport,
    id: &'static str,
    label: &'static str,
    status: CheckStatus,
    detail: impl Into<String>,
    latency_ms: Option<u64>,
) {
    let detail = detail.into();
    if let Some(c) = report.checks.iter_mut().find(|c| c.id == id) {
        c.status = status;
        c.detail = detail;
        c.latency_ms = latency_ms;
    } else {
        report.checks.push(DoctorCheck {
            id,
            label,
            status,
            detail,
            latency_ms,
        });
    }
}

/// Run full network & node diagnostics, optionally streaming intermediate snapshots.
pub async fn run_doctor(
    data_dir: &Path,
    progress: Option<mpsc::UnboundedSender<DoctorReport>>,
) -> Result<DoctorReport> {
    let store = Store::open(data_dir.to_path_buf())?;
    let mut report = DoctorReport {
        device_id: store.identity.device_id.clone(),
        device_name: store.device_name(),
        account: store.account.as_ref().map(|a| a.user_id.clone()),
        coord_url: store.config.coord_url.clone(),
        coord_pin: store.config.coord_pin.clone(),
        ..Default::default()
    };

    upsert_check(&mut report, "daemon", "Local daemon", CheckStatus::Running, "checking control.sock…", None);
    upsert_check(&mut report, "vpn", "VPN TUN / DNS", CheckStatus::Running, "waiting…", None);
    upsert_check(&mut report, "coord", "Coord HTTPS", CheckStatus::Running, "waiting…", None);
    upsert_check(&mut report, "clock", "Clock skew", CheckStatus::Running, "waiting…", None);
    upsert_check(&mut report, "relay_tcp", "TCP Relay", CheckStatus::Running, "waiting…", None);
    upsert_check(&mut report, "relay_ws", "WSS Relay", CheckStatus::Running, "waiting…", None);
    upsert_check(&mut report, "relay_quic", "QUIC Dgram Relay", CheckStatus::Running, "waiting…", None);
    upsert_check(&mut report, "stun", "UDP STUN", CheckStatus::Running, "waiting…", None);
    upsert_check(&mut report, "mdns", "LAN mDNS", CheckStatus::Running, "waiting…", None);
    push_snapshot(&progress, &report);

    // 1. Local daemon
    let mut live_status: Option<serde_json::Value> = None;
    let t0 = Instant::now();
    match crate::client::ControlClient::try_daemon(&store.root).await {
        Some(c) => {
            match c.get("/healthz").await {
                Ok(v) => {
                    let uptime = v["uptime_s"].as_u64().unwrap_or(0);
                    report.daemon_live = true;
                    report.daemon_uptime_s = Some(uptime);
                    report.daemon_note = format!("live  uptime={uptime}s");
                    upsert_check(
                        &mut report,
                        "daemon",
                        "Local daemon",
                        CheckStatus::Ok,
                        format!("running (uptime {}s)", uptime),
                        Some(t0.elapsed().as_millis() as u64),
                    );
                }
                Err(e) => {
                    report.daemon_note = format!("({e})");
                    upsert_check(
                        &mut report,
                        "daemon",
                        "Local daemon",
                        CheckStatus::Warn,
                        e.to_string(),
                        None,
                    );
                }
            }
            if let Ok(st) = c.get("/v1/status").await {
                live_status = Some(st);
            }
        }
        None => {
            report.daemon_note = "(not running)".into();
            upsert_check(
                &mut report,
                "daemon",
                "Local daemon",
                CheckStatus::Warn,
                "not running",
                None,
            );
        }
    }

    // 1b. VPN TUN / DNS status from live daemon
    if let Some(st) = &live_status {
        let tun = &st["tun"];
        let enabled = tun["enabled"].as_bool().unwrap_or(false);
        let iface = tun["interface"].as_str();
        let vip = st["virtual_ip"].as_str();
        let dns = tun["dns_listen"].as_str();
        let err = tun["error"].as_str();
        if enabled {
            let mut parts = Vec::new();
            if let Some(i) = iface {
                parts.push(i.to_string());
            }
            if let Some(ip) = vip {
                parts.push(ip.to_string());
            }
            if let Some(d) = dns {
                parts.push(format!("dns={d}"));
            }
            let detail = if parts.is_empty() {
                "enabled".into()
            } else {
                parts.join("  ")
            };
            upsert_check(&mut report, "vpn", "VPN TUN / DNS", CheckStatus::Ok, detail, None);
        } else if let Some(e) = err {
            upsert_check(&mut report, "vpn", "VPN TUN / DNS", CheckStatus::Warn, e, None);
        } else {
            upsert_check(
                &mut report,
                "vpn",
                "VPN TUN / DNS",
                CheckStatus::Skipped,
                "disabled (--no-tun)",
                None,
            );
        }
    } else {
        upsert_check(
            &mut report,
            "vpn",
            "VPN TUN / DNS",
            CheckStatus::Skipped,
            "daemon not running",
            None,
        );
    }
    push_snapshot(&progress, &report);

    // 2. Local addrs
    report.local_addrs = collect_local_endpoints(0, None)
        .into_iter()
        .map(|a| strip_zero_port(&a))
        .collect();

    // 3. Coord HTTPS + ServerInfo + Clock skew
    let coord = match store.require_coord() {
        Ok((url, pin)) => match CoordClient::new(url, pin) {
            Ok(c) => Some(c.with_identity(store.identity.clone())),
            Err(e) => {
                upsert_check(&mut report, "coord", "Coord HTTPS", CheckStatus::Fail, e.to_string(), None);
                None
            }
        },
        Err(e) => {
            upsert_check(&mut report, "coord", "Coord HTTPS", CheckStatus::Fail, e.to_string(), None);
            None
        }
    };

    let mut server_info: Option<topaz_proto::ServerInfo> = None;
    if let Some(coord) = &coord {
        let t = Instant::now();
        match coord.healthz().await {
            Ok(()) => {
                report.coord_ok = true;
                let elapsed = t.elapsed().as_millis() as u64;
                server_info = coord.server_info().await.ok();
                let ver_line = match &server_info {
                    Some(info) => Some(info.version.display_line()),
                    None => coord.server_version().await.ok().map(|v| v.display_line()),
                };
                let detail = match &ver_line {
                    Some(v) => format!("{}  [{}]", store.config.coord_url, v),
                    None => store.config.coord_url.clone(),
                };
                report.coord_version = ver_line;
                upsert_check(
                    &mut report,
                    "coord",
                    "Coord HTTPS",
                    CheckStatus::Ok,
                    detail,
                    Some(elapsed),
                );
            }
            Err(e) => {
                upsert_check(
                    &mut report,
                    "coord",
                    "Coord HTTPS",
                    CheckStatus::Fail,
                    e.to_string(),
                    Some(t.elapsed().as_millis() as u64),
                );
            }
        }
    }

    if let Some(info) = &server_info {
        let local = topaz_core::now_unix();
        let diff = local.abs_diff(info.server_time_unix);
        let sign = if local >= info.server_time_unix { "+" } else { "-" };
        let (status, detail) = if diff <= 30 {
            (CheckStatus::Ok, format!("{sign}{diff}s vs coord"))
        } else if diff < 120 {
            (
                CheckStatus::Warn,
                format!("{sign}{diff}s vs coord (auth limit 120s — sync NTP)"),
            )
        } else {
            (
                CheckStatus::Fail,
                format!("{sign}{diff}s vs coord (exceeds 120s auth window — sync NTP)"),
            )
        };
        upsert_check(&mut report, "clock", "Clock skew", status, detail, None);
    } else {
        upsert_check(
            &mut report,
            "clock",
            "Clock skew",
            CheckStatus::Skipped,
            "coord /v1/info unavailable",
            None,
        );
    }
    push_snapshot(&progress, &report);

    // 4. TCP Relay
    let tcp_relay_target = match &server_info {
        Some(info) if !info.relay.is_empty() => Some(
            info.relay
                .strip_prefix("tcp://")
                .unwrap_or(&info.relay)
                .to_string(),
        ),
        Some(_) => None,
        None => guessed_host_port(&store.config.coord_url, 7723),
    };
    if let Some(relay) = tcp_relay_target {
        let t = Instant::now();
        let probe = probe_tcp(&relay, Duration::from_secs(3)).await;
        let status = if probe == "ok" {
            CheckStatus::Ok
        } else {
            CheckStatus::Fail
        };
        let detail = if probe == "ok" {
            relay
        } else {
            format!("{relay} — {probe}")
        };
        upsert_check(
            &mut report,
            "relay_tcp",
            "TCP Relay",
            status,
            detail,
            Some(t.elapsed().as_millis() as u64),
        );
    } else {
        let msg = if server_info.is_some() {
            "disabled on coord"
        } else {
            "no coord URL"
        };
        upsert_check(&mut report, "relay_tcp", "TCP Relay", CheckStatus::Skipped, msg, None);
    }
    push_snapshot(&progress, &report);

    // 5. WSS Relay
    if let Some(coord) = &coord {
        let ws = server_info
            .as_ref()
            .filter(|i| !i.relay_ws.is_empty())
            .map(|i| i.relay_ws.clone())
            .unwrap_or_else(|| coord.websocket_relay_url());
        let t = Instant::now();
        match coord.probe_relay_ws_url(&ws).await {
            Ok(()) => upsert_check(
                &mut report,
                "relay_ws",
                "WSS Relay",
                CheckStatus::Ok,
                ws,
                Some(t.elapsed().as_millis() as u64),
            ),
            Err(e) => upsert_check(
                &mut report,
                "relay_ws",
                "WSS Relay",
                CheckStatus::Fail,
                format!("{ws} — {e}"),
                Some(t.elapsed().as_millis() as u64),
            ),
        }
    } else {
        upsert_check(&mut report, "relay_ws", "WSS Relay", CheckStatus::Skipped, "coord unavailable", None);
    }
    push_snapshot(&progress, &report);

    // 5b. QUIC Datagram Relay (UDP)
    let quic_relay_target = match &server_info {
        Some(info) if !info.relay_quic.is_empty() => Some(info.relay_quic.clone()),
        Some(_) => None,
        None => guessed_host_port(&store.config.coord_url, 7724),
    };
    if let (Some(coord), Some(quic_addr)) = (&coord, quic_relay_target) {
        let t = Instant::now();
        match coord.probe_relay_quic(&quic_addr).await {
            Ok(()) => upsert_check(
                &mut report,
                "relay_quic",
                "QUIC Dgram Relay",
                CheckStatus::Ok,
                quic_addr,
                Some(t.elapsed().as_millis() as u64),
            ),
            Err(e) => upsert_check(
                &mut report,
                "relay_quic",
                "QUIC Dgram Relay",
                CheckStatus::Warn,
                format!("{quic_addr} — {e} (will fall back to TCP/WSS)"),
                Some(t.elapsed().as_millis() as u64),
            ),
        }
    } else {
        let msg = if server_info.is_some() {
            "disabled on coord"
        } else {
            "coord unavailable"
        };
        upsert_check(
            &mut report,
            "relay_quic",
            "QUIC Dgram Relay",
            CheckStatus::Skipped,
            msg,
            None,
        );
    }
    push_snapshot(&progress, &report);

    // 6. UDP STUN
    let stun_target = match &server_info {
        Some(info) if !info.stun.is_empty() => Some(info.stun.clone()),
        Some(_) => None,
        None => guessed_host_port(&store.config.coord_url, 3478),
    };
    if let Some(stun_addr) = stun_target {
        let t = Instant::now();
        match probe_stun(&stun_addr).await {
            Ok(mapped) => upsert_check(
                &mut report,
                "stun",
                "UDP STUN",
                CheckStatus::Ok,
                format!("mapped {mapped} via {stun_addr}"),
                Some(t.elapsed().as_millis() as u64),
            ),
            Err(e) => upsert_check(
                &mut report,
                "stun",
                "UDP STUN",
                CheckStatus::Fail,
                format!("{stun_addr} — {e}"),
                Some(t.elapsed().as_millis() as u64),
            ),
        }
    } else {
        let msg = if server_info.is_some() {
            "disabled on coord"
        } else {
            "no coord URL"
        };
        upsert_check(&mut report, "stun", "UDP STUN", CheckStatus::Skipped, msg, None);
    }
    push_snapshot(&progress, &report);

    // 7. mDNS LAN discovery (run off the async runtime thread)
    let t = Instant::now();
    let lan = tokio::task::spawn_blocking(|| mdns::discover_once(Duration::from_secs(2)))
        .await
        .unwrap_or_default();
    let mut lan_list: Vec<(String, String)> = lan
        .iter()
        .map(|(k, v)| (k.clone(), v.to_string()))
        .collect();
    lan_list.sort_by(|a, b| a.0.cmp(&b.0));
    report.mdns = lan_list;
    let mdns_count = report.mdns.len();
    upsert_check(
        &mut report,
        "mdns",
        "LAN mDNS",
        if mdns_count == 0 {
            CheckStatus::Warn
        } else {
            CheckStatus::Ok
        },
        if mdns_count == 0 {
            "no LAN peers seen (2s window)".into()
        } else {
            format!("{mdns_count} peer(s) on LAN")
        },
        Some(t.elapsed().as_millis() as u64),
    );
    push_snapshot(&progress, &report);

    // 8. Peers & endpoints
    if store.account.is_some() {
        if let Some(coord) = &coord {
            match coord.list_devices().await {
                Ok(entries) => {
                    let others: Vec<_> = entries
                        .into_iter()
                        .filter(|e| e.cert.device_id != store.identity.device_id)
                        .collect();
                    for e in others {
                        let mut session_path = None;
                        let mut rtt_ms = None;
                        if let Some(st) = &live_status {
                            if let Some(p) = st["peers"].as_array().and_then(|arr| {
                                arr.iter().find(|p| {
                                    p["device_id"].as_str() == Some(e.cert.device_id.as_str())
                                })
                            }) {
                                session_path = p["path"].as_str().map(|s| s.to_string());
                                rtt_ms = p["rtt_ms"].as_u64();
                            }
                        }
                        let (udp_endpoints, udp_error) =
                            match coord.peer_endpoints(&e.cert.device_id).await {
                                Ok(Some(eps)) => (Some(eps.endpoints), None),
                                Ok(None) => (None, None),
                                Err(err) => (None, Some(err.to_string())),
                            };
                        let lan_addr = lan.get(&e.cert.device_id).map(|a| a.to_string());
                        report.peers.push(DoctorPeerReport {
                            device_id: e.cert.device_id,
                            name: e.cert.name,
                            session_path,
                            rtt_ms,
                            udp_endpoints,
                            udp_error,
                            lan_addr,
                        });
                    }
                }
                Err(e) => {
                    report.peers_error = Some(e.to_string());
                }
            }
        }
    }

    report.finished = true;
    push_snapshot(&progress, &report);
    Ok(report)
}

pub async fn cmd_doctor(data_dir: PathBuf) -> Result<()> {
    let report = run_doctor(&data_dir, None).await?;
    println!("device_id {}", report.device_id);
    println!("device_name {}", report.device_name);
    match &report.account {
        Some(a) => println!("account {a}"),
        None => println!("account (none)"),
    }
    println!("client_version {}", topaz_proto::VERSION_LONG);
    println!("coord_url {}", report.coord_url);
    println!("coord_pin {}", report.coord_pin);
    if let Some(ref v) = report.coord_version {
        println!("coord_version {v}");
    }
    println!("daemon {}", report.daemon_note);

    for check in &report.checks {
        match check.id {
            "vpn" if check.status != CheckStatus::Skipped => {
                println!("vpn {}", check.detail);
            }
            "coord" => {
                if check.status == CheckStatus::Ok {
                    println!("coord_healthz ok");
                } else {
                    println!("coord_healthz {}", check.detail);
                }
            }
            "clock" if check.status != CheckStatus::Skipped => {
                println!("clock_skew {}", check.detail);
            }
            "relay_tcp" if check.status != CheckStatus::Skipped => {
                if check.status == CheckStatus::Ok {
                    println!("relay {}  ok", check.detail);
                } else {
                    println!("relay {}", check.detail);
                }
            }
            "relay_ws" if check.status != CheckStatus::Skipped => {
                if check.status == CheckStatus::Ok {
                    println!("relay_ws {}  ok", check.detail);
                } else {
                    println!("relay_ws {}", check.detail);
                }
            }
            "relay_quic" if check.status != CheckStatus::Skipped => {
                if check.status == CheckStatus::Ok {
                    println!("relay_quic {}  ok", check.detail);
                } else {
                    println!("relay_quic {}", check.detail);
                }
            }
            "stun" if check.status != CheckStatus::Skipped => {
                if check.status == CheckStatus::Ok {
                    println!("stun {}  ok", check.detail);
                } else {
                    println!("stun {}", check.detail);
                }
            }
            _ => {}
        }
    }

    println!("local_addrs");
    for addr in &report.local_addrs {
        println!("  {addr}");
    }

    if report.mdns.is_empty() {
        println!("mdns (none)");
    } else {
        println!("mdns");
        for (id, addr) in &report.mdns {
            println!("  {id}  {addr}");
        }
    }

    if report.account.is_some() {
        if let Some(err) = &report.peers_error {
            println!("peers ({err})");
        } else if report.peers.is_empty() {
            println!("peers (none)");
        } else {
            println!("peers");
            for p in &report.peers {
                println!("  {}  {}", p.device_id, p.name);
                if report.daemon_live {
                    let path = p.session_path.as_deref().unwrap_or("offline");
                    let rtt = p
                        .rtt_ms
                        .map(|ms| format!("{ms}ms"))
                        .unwrap_or_else(|| "-".into());
                    println!("    session {path}  rtt={rtt}");
                }
                match (&p.udp_endpoints, &p.udp_error) {
                    (Some(eps), _) if eps.is_empty() => println!("    udp_endpoints (none)"),
                    (Some(eps), _) => println!("    udp_endpoints {}", eps.join(" ")),
                    (None, Some(err)) => println!("    udp_endpoints ({err})"),
                    (None, None) => println!("    udp_endpoints (offline)"),
                }
                match &p.lan_addr {
                    Some(addr) => println!("    lan {addr}"),
                    None => println!("    lan (none)"),
                }
            }
        }
    }

    if report.coord_ok {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

fn strip_zero_port(ep: &str) -> String {
    ep.strip_suffix(":0")
        .map(|s| s.to_string())
        .unwrap_or_else(|| ep.to_string())
}

fn guessed_host_port(coord_url: &str, port: u16) -> Option<String> {
    let rest = coord_url
        .trim()
        .strip_prefix("https://")
        .or_else(|| coord_url.trim().strip_prefix("http://"))?;
    let hostport = rest.split('/').next()?.trim();
    if hostport.is_empty() {
        return None;
    }
    let host = if let Some(inner) = hostport.strip_prefix('[') {
        inner
            .find(']')
            .map(|end| &hostport[..=end + 1])
            .unwrap_or(hostport)
    } else {
        hostport
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(hostport)
    };
    Some(format!("{host}:{port}"))
}

async fn probe_stun(advertised: &str) -> Result<SocketAddr> {
    let target = advertised.to_string();
    let addr = tokio::task::spawn_blocking(move || -> std::io::Result<SocketAddr> {
        use std::net::ToSocketAddrs;
        let addrs: Vec<SocketAddr> = target.to_socket_addrs()?.collect();
        addrs
            .iter()
            .copied()
            .find(|a| a.is_ipv4())
            .or_else(|| addrs.into_iter().next())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no address resolved"))
    })
    .await??;
    let bind_addr = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let sock = std::net::UdpSocket::bind(bind_addr)?;
    stun::probe_with_timeout(&sock, addr, Duration::from_secs(2))
}

async fn probe_tcp(addr: &str, wait: Duration) -> String {
    match timeout(wait, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => "ok".into(),
        Ok(Err(e)) => e.to_string(),
        Err(_) => "timeout".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guessed_host_port_handles_ipv4_domain_and_ipv6() {
        assert_eq!(
            guessed_host_port("https://coord.example.com:7722", 3478).as_deref(),
            Some("coord.example.com:3478")
        );
        assert_eq!(
            guessed_host_port("https://1.2.3.4:7722/extra", 7724).as_deref(),
            Some("1.2.3.4:7724")
        );
        assert_eq!(
            guessed_host_port("https://[2001:db8::1]:7722", 3478).as_deref(),
            Some("[2001:db8::1]:3478")
        );
        assert_eq!(
            guessed_host_port("https://[::1]", 7723).as_deref(),
            Some("[::1]:7723")
        );
    }
}
