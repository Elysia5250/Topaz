use anyhow::Result;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use topaz_core::Store;
use topaz_fabric::mdns;
use topaz_net::{collect_local_endpoints, stun, CoordClient};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub async fn cmd_doctor(data_dir: PathBuf) -> Result<()> {
    let store = Store::open(data_dir)?;
    println!("device_id {}", store.identity.device_id);
    println!("device_name {}", store.device_name());
    match &store.account {
        Some(a) => println!("account {}", a.user_id),
        None => println!("account (none)"),
    }
    println!("coord_url {}", store.config.coord_url);
    println!("coord_pin {}", store.config.coord_pin);

    // Daemon section: is this data-dir's node running, and how long?
    let mut live_status: Option<serde_json::Value> = None;
    match crate::client::ControlClient::try_daemon(&store.root).await {
        Some(c) => {
            match c.get("/healthz").await {
                Ok(v) => println!(
                    "daemon live  uptime={}s",
                    v["uptime_s"].as_u64().unwrap_or(0)
                ),
                Err(e) => println!("daemon ({e})"),
            }
            if let Ok(st) = c.get("/v1/status").await {
                live_status = Some(st);
            }
        }
        None => println!("daemon (not running)"),
    }

    let mut coord_ok = false;
    let coord = match store.require_coord() {
        Ok((url, pin)) => match CoordClient::new(url, pin) {
            Ok(c) => Some(c.with_identity(store.identity.clone())),
            Err(e) => {
                println!("coord_healthz {e}");
                None
            }
        },
        Err(e) => {
            println!("coord_healthz {e}");
            None
        }
    };

    if let Some(coord) = &coord {
        match coord.healthz().await {
            Ok(()) => {
                println!("coord_healthz ok");
                coord_ok = true;
            }
            Err(e) => println!("coord_healthz {e}"),
        }
    }

    println!("local_addrs");
    for addr in collect_local_endpoints(0, None) {
        println!("  {}", strip_zero_port(&addr));
    }

    // Do not register: that would overwrite a running node's advertised endpoints.
    if let Some(relay) = guessed_relay(&store.config.coord_url) {
        let probe = probe_tcp(&relay, Duration::from_secs(3)).await;
        println!("relay {relay}  {probe}");
    }
    if let Some(coord) = &coord {
        let ws = coord.websocket_relay_url();
        match coord.probe_relay_ws().await {
            Ok(()) => println!("relay_ws {ws}  ok"),
            Err(e) => println!("relay_ws {ws}  {e}"),
        }
    }

    // doctor never registers, so it cannot read the coord-advertised STUN
    // address; guess the default port on the coord host, like the relay.
    if let Some(stun_addr) = guessed_stun(&store.config.coord_url) {
        match probe_stun(&stun_addr).await {
            Ok(mapped) => println!("stun {stun_addr} mapped {mapped}  ok"),
            Err(e) => println!("stun {stun_addr}  {e}"),
        }
    }

    let lan = mdns::discover_once(Duration::from_secs(2));
    if lan.is_empty() {
        println!("mdns (none)");
    } else {
        println!("mdns");
        for (id, addr) in &lan {
            println!("  {id}  {addr}");
        }
    }

    if store.account.is_some() {
        if let Some(coord) = &coord {
            match coord.list_devices().await {
                Ok(entries) => {
                    let others: Vec<_> = entries
                        .into_iter()
                        .filter(|e| e.cert.device_id != store.identity.device_id)
                        .collect();
                    if others.is_empty() {
                        println!("peers (none)");
                    } else {
                        println!("peers");
                        for e in others {
                            println!("  {}  {}", e.cert.device_id, e.cert.name);
                            if let Some(st) = &live_status {
                                if let Some(p) = st["peers"]
                                    .as_array()
                                    .and_then(|arr| {
                                        arr.iter().find(|p| {
                                            p["device_id"].as_str() == Some(e.cert.device_id.as_str())
                                        })
                                    })
                                {
                                    let path = p["path"].as_str().unwrap_or("offline");
                                    let rtt = p["rtt_ms"]
                                        .as_u64()
                                        .map(|ms| format!("{ms}ms"))
                                        .unwrap_or_else(|| "-".into());
                                    println!("    session {path}  rtt={rtt}");
                                }
                            }
                            match coord.peer_endpoints(&e.cert.device_id).await {
                                Ok(Some(eps)) => {
                                    if eps.endpoints.is_empty() {
                                        println!("    udp_endpoints (none)");
                                    } else {
                                        println!("    udp_endpoints {}", eps.endpoints.join(" "));
                                    }
                                }
                                Ok(None) => println!("    udp_endpoints (offline)"),
                                Err(err) => println!("    udp_endpoints ({err})"),
                            }
                            match lan.get(&e.cert.device_id) {
                                Some(addr) => println!("    lan {addr}"),
                                None => println!("    lan (none)"),
                            }
                        }
                    }
                }
                Err(e) => println!("peers ({e})"),
            }
        }
    }

    if coord_ok {
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

fn guessed_relay(coord_url: &str) -> Option<String> {
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
    Some(format!("{host}:7723"))
}

fn guessed_stun(coord_url: &str) -> Option<String> {
    let rest = coord_url
        .trim()
        .strip_prefix("https://")
        .or_else(|| coord_url.trim().strip_prefix("http://"))?;
    let hostport = rest.split('/').next()?.trim();
    if hostport.is_empty() {
        return None;
    }
    let host = hostport
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(hostport);
    Some(format!("{host}:3478"))
}

async fn probe_stun(advertised: &str) -> Result<SocketAddr> {
    let target = advertised.to_string();
    let addr = tokio::task::spawn_blocking(move || -> std::io::Result<SocketAddr> {
        use std::net::ToSocketAddrs;
        target
            .to_socket_addrs()?
            .find(|a| a.is_ipv4())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no ipv4 address"))
    })
    .await??;
    let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    stun::probe_with_timeout(&sock, addr, Duration::from_secs(2))
}

async fn probe_tcp(addr: &str, wait: Duration) -> String {
    match timeout(wait, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => "ok".into(),
        Ok(Err(e)) => e.to_string(),
        Err(_) => "timeout".into(),
    }
}
