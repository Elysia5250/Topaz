//! Assembly for `topaz run`: bootstrap the store, coord session
//! and QUIC endpoint, then hand everything to the fabric engine with `PingService`
//! mounted, a task that renders `status.json`, and the local control API.

use anyhow::{bail, Context, Result};
use topaz_core::Store;
use topaz_fabric::{EngineDeps, PingService, Service, SharedStatus};
use topaz_net::{collect_local_endpoints, new_trust_store, CoordClient, QuicEndpoint, RelayAddrs};
use topaz_proto::auth::{evaluate, parse_pubkey};
use topaz_vpn::{SharedVpnStatus, VpnConfig};
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{info, warn};

pub fn build_run_args(
    data_dir: &Path,
    coord_url: Option<&str>,
    force_relay: bool,
    enable_mdns: bool,
    vpn_cfg: &VpnConfig,
) -> Vec<OsString> {
    let mut args = vec![
        OsString::from("--data-dir"),
        data_dir.as_os_str().to_os_string(),
        OsString::from("run"),
    ];
    if let Some(u) = coord_url {
        args.push(OsString::from("--coord-url"));
        args.push(OsString::from(u));
    }
    if force_relay {
        args.push(OsString::from("--force-relay"));
    }
    if !enable_mdns {
        args.push(OsString::from("--no-mdns"));
    }
    if vpn_cfg.disabled {
        args.push(OsString::from("--no-tun"));
    }
    if let Some(ref tun) = vpn_cfg.tun_name {
        args.push(OsString::from("--tun-name"));
        args.push(OsString::from(tun));
    }
    args.push(OsString::from("--mtu"));
    args.push(OsString::from(vpn_cfg.mtu.to_string()));
    if let Some(dns) = vpn_cfg.dns_listen {
        args.push(OsString::from("--dns-listen"));
        args.push(OsString::from(dns.to_string()));
    }
    args
}

pub async fn spawn_detached(
    data_dir: PathBuf,
    coord_url: Option<String>,
    force_relay: bool,
    enable_mdns: bool,
    vpn_cfg: VpnConfig,
) -> Result<()> {
    if crate::client::ControlClient::try_daemon(&data_dir)
        .await
        .is_some()
    {
        bail!(
            "another topaz run owns {} (control socket already active)",
            data_dir.display()
        );
    }

    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("create data dir {}", data_dir.display()))?;
    let log_path = data_dir.join("topaz.log");
    let log_out = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("open log file {}", log_path.display()))?;
    let log_err = log_out
        .try_clone()
        .context("clone log file handle for stderr")?;

    let exe = std::env::current_exe().context("locate current executable")?;
    let args = build_run_args(
        &data_dir,
        coord_url.as_deref(),
        force_relay,
        enable_mdns,
        &vpn_cfg,
    );
    let mut cmd = std::process::Command::new(exe);
    cmd.args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_out))
        .stderr(Stdio::from(log_err));

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    let mut child = cmd.spawn().context("spawn detached topaz daemon")?;
    let pid = child.id();

    for _ in 0..100 {
        if let Some(status) = child.try_wait()? {
            let tail = read_log_tail(&log_path, 20);
            if tail.is_empty() {
                bail!(
                    "topaz daemon exited immediately ({status}); check {}",
                    log_path.display()
                );
            }
            bail!(
                "topaz daemon exited immediately ({status}); tail of {}:\n{tail}",
                log_path.display()
            );
        }
        if crate::client::ControlClient::try_daemon(&data_dir)
            .await
            .is_some()
        {
            println!("topaz daemon started (pid {pid}, log {})", log_path.display());
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    println!(
        "topaz daemon spawned (pid {pid}, log {}); control socket still initializing",
        log_path.display()
    );
    Ok(())
}

fn read_log_tail(path: &Path, max_lines: usize) -> String {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return String::new();
    };
    let lines: Vec<&str> = raw.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    lines[start..].join("\n")
}

pub async fn cmd_run(
    data_dir: PathBuf,
    coord_url: Option<String>,
    force_relay: bool,
    enable_mdns: bool,
    vpn_cfg: VpnConfig,
) -> Result<()> {
    let mut store = Store::open(data_dir)?;
    let control_path = store.control_path();
    let control_listener = crate::control::bind_socket(&control_path).await?;
    if let Some(u) = coord_url {
        store.config.coord_url = u;
        store.save_config()?;
    }
    let force_relay = force_relay || store.config.force_relay;
    let account = store.require_account()?.clone();

    let (url, pin) = store.require_coord()?;
    let coord = CoordClient::new(url, pin)?.with_identity(store.identity.clone());
    let trust = new_trust_store();
    match coord.list_devices().await {
        Ok(entries) => {
            let set = evaluate(&account.user_pubkey, &entries);
            let mut t = trust.write().unwrap();
            for c in &set.active {
                if c.device_id != store.identity.device_id {
                    if let Some(pk) = parse_pubkey(&c.device_pubkey) {
                        t.insert(pk, c.device_id.clone());
                    }
                }
            }
        }
        Err(e) => warn!(error = %e, "trust store priming failed; first refresh retries"),
    }

    let (mut quic, mut mapped) = QuicEndpoint::bind(&store.identity, &trust, None)?;
    info!(addr = %quic.local_addr, "QUIC endpoint bound");
    let mut endpoints = collect_local_endpoints(quic.local_addr.port(), None);
    let reg = coord.register(endpoints.clone()).await?;
    let with_observed =
        collect_local_endpoints(quic.local_addr.port(), Some(reg.observed_ip.as_str()));
    let mut reg = if with_observed != endpoints {
        endpoints = with_observed;
        coord.register(endpoints.clone()).await?
    } else {
        reg
    };

    if mapped.is_none() {
        if let Ok(stun_addr) = resolve_stun(&reg.stun).await {
            drop(quic);
            let (q, m) = QuicEndpoint::bind(&store.identity, &trust, Some(stun_addr))?;
            quic = q;
            mapped = m;
            endpoints =
                collect_local_endpoints(quic.local_addr.port(), Some(reg.observed_ip.as_str()));
            if let Some(mapped) = mapped {
                let s = mapped.to_string();
                if !endpoints.contains(&s) {
                    endpoints.push(s);
                }
            }
            reg = coord.register(endpoints.clone()).await?;
        }
    }
    let relay = RelayAddrs {
        tcp: coord.relay_addr(&reg),
        ws: coord.relay_ws_url(&reg),
        coord_tls: coord.tls_config(),
    };
    info!(
        observed = %reg.observed_ip,
        relay = %relay.tcp,
        relay_ws = %relay.ws,
        "registered with coord"
    );

    let (signal_tx, signal_rx) = coord.signal().await?;

    let store = Arc::new(Mutex::new(store));
    let status = Arc::new(SharedStatus::new());
    let vpn_status = SharedVpnStatus::new(vpn_cfg.mtu);
    let services = Arc::new(crate::bridge::ServiceRegistry::default());

    let identity = store.lock().unwrap().identity.clone();
    let services_for_writer = services.clone();
    let (handle, engine_fut) = topaz_fabric::build(
        EngineDeps {
            identity,
            account_user_pubkey: account.user_pubkey.clone(),
            coord: coord.clone(),
            trust,
            quic,
            endpoints,
            relay,
            signal_tx,
            signal_rx,
            force_relay,
            enable_mdns,
        },
        |_handle| {
            let ping = Arc::new(PingService::new(status.clone()));
            spawn_status_writer(
                store.clone(),
                status.clone(),
                vpn_status.clone(),
                services_for_writer,
                account.clone(),
            );
            vec![ping as Arc<dyn Service>]
        },
        status.clone(),
    );

    let vpn_task = topaz_vpn::spawn(handle.clone(), status.clone(), vpn_status.clone(), vpn_cfg);

    let state = Arc::new(crate::control::ControlState {
        store: store.clone(),
        engine: handle,
        status: status.clone(),
        vpn: vpn_status,
        services,
        coord,
        account_user_id: account.user_id.clone(),
        control_lock: tokio::sync::Mutex::new(()),
        pending_adds: std::sync::Mutex::new(std::collections::HashMap::new()),
        started: std::time::Instant::now(),
    });
    tokio::spawn(async move {
        if let Err(e) = crate::control::serve(control_listener, state).await {
            tracing::error!(error = %e, "control API server stopped");
        }
    });

    let outcome = tokio::select! {
        res = engine_fut => res,
        _ = shutdown_signal() => {
            info!("shutdown signal; exiting");
            Ok(())
        }
    };
    if let Some(t) = vpn_task {
        t.abort();
    }
    crate::control::remove_socket(&control_path);
    outcome
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

async fn resolve_stun(advertised: &str) -> Result<std::net::SocketAddr> {
    use std::net::ToSocketAddrs as _;
    let advertised = advertised.trim().to_string();
    if advertised.is_empty() {
        anyhow::bail!("coord advertises no stun");
    }
    let for_error = advertised.clone();
    let mut addrs: Vec<std::net::SocketAddr> = tokio::task::spawn_blocking(move || {
        advertised
            .to_socket_addrs()
            .map(|it| it.filter(|a| a.is_ipv4()).collect())
            .unwrap_or_default()
    })
    .await?;
    addrs.truncate(1);
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("stun address {for_error} did not resolve"))
}

fn spawn_status_writer(
    store: Arc<Mutex<Store>>,
    status: Arc<SharedStatus>,
    vpn: SharedVpnStatus,
    services: Arc<crate::bridge::ServiceRegistry>,
    account: topaz_core::AccountInfo,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = status.changed() => {}
                _ = tokio::time::sleep(Duration::from_secs(2)) => {}
            }
            let engine = status.engine();
            let vpn_snap = vpn.get();
            let svc_snap = services.summaries();
            let store = store.lock().unwrap();
            let value = crate::control::render_status(
                &store,
                &engine,
                &vpn_snap,
                &account.user_id,
                &svc_snap,
            );
            let _ = store.write_status(&value);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detached_args_forward_options_without_detach_flag() {
        let cfg = VpnConfig {
            disabled: true,
            tun_name: Some("topaz9".into()),
            mtu: 1400,
            dns_listen: Some("127.0.0.1:5354".parse().unwrap()),
        };
        let args: Vec<String> = build_run_args(
            Path::new("/tmp/topaz-data"),
            Some("https://coord.example:7722"),
            true,
            false,
            &cfg,
        )
        .into_iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect();

        assert_eq!(
            args,
            vec![
                "--data-dir",
                "/tmp/topaz-data",
                "run",
                "--coord-url",
                "https://coord.example:7722",
                "--force-relay",
                "--no-mdns",
                "--no-tun",
                "--tun-name",
                "topaz9",
                "--mtu",
                "1400",
                "--dns-listen",
                "127.0.0.1:5354",
            ]
        );
    }
}
