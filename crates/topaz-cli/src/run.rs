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
    let msg = spawn_detached_quiet(data_dir, coord_url, force_relay, enable_mdns, vpn_cfg).await?;
    println!("{msg}");
    Ok(())
}

/// Spawn a detached background daemon without writing to stdout/stderr (safe for TUI callers).
pub async fn spawn_detached_quiet(
    data_dir: PathBuf,
    coord_url: Option<String>,
    force_relay: bool,
    enable_mdns: bool,
    vpn_cfg: VpnConfig,
) -> Result<String> {
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
    let log_out = open_log_file(&log_path)?;
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
            return Ok(format!(
                "topaz daemon started (pid {pid}, log {})",
                log_path.display()
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Ok(format!(
        "topaz daemon spawned (pid {pid}, log {}); control socket still initializing",
        log_path.display()
    ))
}

/// Cleanly request daemon shutdown over control.sock and wait up to 5 seconds.
/// Returns `Ok(true)` if a running daemon stopped, `Ok(false)` if none was running.
pub async fn stop_daemon_quiet(data_dir: &Path) -> Result<bool> {
    let Some(daemon) = crate::client::ControlClient::try_daemon(data_dir).await else {
        return Ok(false);
    };
    let _ = daemon.post("/v1/shutdown", None).await;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if crate::client::ControlClient::try_daemon(data_dir)
            .await
            .is_none()
        {
            return Ok(true);
        }
    }
    bail!("daemon did not exit within 5 seconds")
}

/// Whether the current process already runs with root privileges.
pub fn is_elevated() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Check if `sudo` can execute without prompting for a password (cached timestamp or NOPASSWD).
pub async fn sudo_cached() -> bool {
    if is_elevated() {
        return true;
    }
    let fut = tokio::process::Command::new("sudo")
        .args(["-n", "true"])
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    matches!(
        tokio::time::timeout(Duration::from_secs(2), fut).await,
        Ok(Ok(s)) if s.success()
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElevationError {
    PasswordRequired,
    IncorrectPassword,
    Failed(String),
}

impl std::fmt::Display for ElevationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PasswordRequired => write!(f, "administrator password required"),
            Self::IncorrectPassword => write!(f, "incorrect password, please try again"),
            Self::Failed(msg) => write!(f, "{msg}"),
        }
    }
}

/// Start a detached TUN daemon, using `sudo` when not already root.
/// If `password` is `Some`, it is piped to `sudo -S -p ""` and zeroed immediately afterward.
pub async fn spawn_detached_elevated(
    data_dir: PathBuf,
    force_relay: bool,
    enable_mdns: bool,
    vpn_cfg: VpnConfig,
    mut password: Option<String>,
) -> std::result::Result<String, ElevationError> {
    if is_elevated() || vpn_cfg.disabled {
        zeroize_opt_string(&mut password);
        return spawn_detached_quiet(data_dir, None, force_relay, enable_mdns, vpn_cfg)
            .await
            .map_err(|e| ElevationError::Failed(e.to_string()));
    }

    let exe = std::env::current_exe()
        .map_err(|e| ElevationError::Failed(format!("locate executable: {e}")))?;
    let mut run_args = build_run_args(&data_dir, None, force_relay, enable_mdns, &vpn_cfg);
    run_args.push(OsString::from("--detach"));

    let mut cmd = tokio::process::Command::new("sudo");
    cmd.env("LC_ALL", "C");
    if password.is_some() {
        cmd.args(["-S", "-p", "", "--"]);
    } else {
        cmd.args(["-n", "--"]);
    }
    cmd.arg(&exe)
        .args(&run_args)
        .stdin(if password.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            zeroize_opt_string(&mut password);
            return Err(ElevationError::Failed(format!(
                "failed to launch sudo ({e}); try No-TUN mode or run `sudo topaz run --detach`"
            )));
        }
    };

    if let Some(mut pw) = password.take() {
        use tokio::io::AsyncWriteExt;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(pw.as_bytes()).await;
            let _ = stdin.write_all(b"\n").await;
            let _ = stdin.flush().await;
            drop(stdin);
        }
        zeroize_string(&mut pw);
    }

    let output = match tokio::time::timeout(Duration::from_secs(20), child.wait_with_output()).await
    {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => {
            return Err(ElevationError::Failed(format!("sudo wait failed: {e}")));
        }
        Err(_) => {
            return Err(ElevationError::Failed(
                "timed out waiting for sudo to start the daemon".into(),
            ));
        }
    };

    if output.status.success() {
        let out = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if out.is_empty() {
            Ok("VPN TUN daemon started".into())
        } else {
            Ok(out)
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let lower = stderr.to_ascii_lowercase();
        if lower.contains("a password is required") {
            Err(ElevationError::PasswordRequired)
        } else if lower.contains("incorrect password")
            || lower.contains("sorry, try again")
            || lower.contains("authentication failure")
        {
            Err(ElevationError::IncorrectPassword)
        } else if !stderr.is_empty() {
            Err(ElevationError::Failed(stderr))
        } else {
            Err(ElevationError::Failed(format!(
                "sudo exited with status {}",
                output.status
            )))
        }
    }
}

fn open_log_file(log_path: &Path) -> Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(log_path)
            .with_context(|| format!("open log file {}", log_path.display()))?;
        topaz_core::chown_fd_to_sudo_user(f.as_raw_fd());
        Ok(f)
    }
    #[cfg(not(unix))]
    {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .with_context(|| format!("open log file {}", log_path.display()))
    }
}

fn zeroize_string(s: &mut String) {
    use zeroize::Zeroize;
    s.zeroize();
}

fn zeroize_opt_string(opt: &mut Option<String>) {
    if let Some(s) = opt.as_mut() {
        zeroize_string(s);
    }
    *opt = None;
}

pub fn read_log_tail(path: &Path, max_lines: usize) -> String {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return String::new();
    };
    let lines: Vec<&str> = raw.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    lines[start..].join("\n")
}

struct SocketGuard(PathBuf);

impl Drop for SocketGuard {
    fn drop(&mut self) {
        crate::control::remove_socket(&self.0);
    }
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
    let _socket_guard = SocketGuard(control_path.clone());
    if let Some(u) = coord_url {
        store.config.coord_url = u;
        store.save_config()?;
    }
    let force_relay = force_relay || store.config.force_relay;
    let account = store.require_account()?.clone();

    let (url, pin) = store.require_coord()?;
    let coord = CoordClient::new(url, pin)?.with_identity(store.identity.clone());
    let trust = new_trust_store();
    let initial_devices = match tokio::time::timeout(Duration::from_secs(5), coord.list_devices())
        .await
    {
        Ok(Ok(entries)) => {
            let _ = store.save_devices_cache(&entries);
            entries
        }
        Ok(Err(e)) => {
            warn!(error = %e, "trust store priming from coord failed; loading cached device list");
            store.load_devices_cache()
        }
        Err(_) => {
            warn!("trust store priming timed out; loading cached device list");
            store.load_devices_cache()
        }
    };
    if !initial_devices.is_empty() {
        let set = evaluate(&account.user_pubkey, &initial_devices);
        let mut t = trust.write().unwrap();
        for c in &set.active {
            if c.device_id != store.identity.device_id {
                if let Some(pk) = parse_pubkey(&c.device_pubkey) {
                    t.insert(pk, c.device_id.clone());
                }
            }
        }
    }

    let (quic, _) = QuicEndpoint::bind(&store.identity, &trust, None)?;
    info!(addr = %quic.local_addr, "QUIC endpoint bound");
    let mut endpoints = collect_local_endpoints(quic.local_addr.port(), None);
    let initial_reg = match tokio::time::timeout(
        Duration::from_secs(5),
        coord.register(endpoints.clone()),
    )
    .await
    {
        Ok(Ok(r)) => Some(r),
        Ok(Err(e)) => {
            warn!(error = %e, "initial coord register failed; continuing in offline/mDNS mode until coord returns");
            None
        }
        Err(_) => {
            warn!("initial coord register timed out; continuing in offline/mDNS mode until coord returns");
            None
        }
    };

    let relay = if let Some(mut reg) = initial_reg {
        let mut updated =
            collect_local_endpoints(quic.local_addr.port(), Some(reg.observed_ip.as_str()));
        // Live async STUN probe on the SAME QUIC socket (no socket recreation or thread blocking).
        if let Ok(stun_addr) = resolve_stun(&reg.stun).await {
            match quic.probe_stun(stun_addr).await {
                Ok(mapped) => {
                    info!(%stun_addr, %mapped, "stun mapped on live QUIC socket");
                    let s = mapped.to_string();
                    if !updated.contains(&s) {
                        updated.push(s);
                    }
                }
                Err(e) => {
                    warn!(error = %e, %stun_addr, "initial live stun probe failed");
                }
            }
        }
        if updated != endpoints {
            endpoints = updated;
            reg = coord.register(endpoints.clone()).await.unwrap_or(reg);
        }
        let relay = RelayAddrs {
            tcp: coord.relay_addr(&reg),
            ws: coord.relay_ws_url(&reg),
            quic: coord.relay_quic_addr(&reg),
            coord_tls: coord.tls_config(),
            coord_quic_tls: Some(coord.quic_tls_config()),
        };
        info!(
            observed = %reg.observed_ip,
            relay = %relay.tcp,
            relay_ws = %relay.ws,
            relay_quic = %relay.quic,
            "registered with coord"
        );
        relay
    } else {
        RelayAddrs {
            tcp: String::new(),
            ws: coord.websocket_relay_url(),
            quic: String::new(),
            coord_tls: coord.tls_config(),
            coord_quic_tls: Some(coord.quic_tls_config()),
        }
    };

    let kick_slot: Arc<Mutex<Option<topaz_fabric::EngineHandle>>> = Arc::new(Mutex::new(None));
    let kick_slot_cb = kick_slot.clone();
    let (signal_tx, signal_rx) = coord.spawn_signal_supervisor(Arc::new(move || {
        if let Some(h) = kick_slot_cb.lock().unwrap().as_ref() {
            h.kick(false);
        }
    }));

    let store = Arc::new(Mutex::new(store));
    let status = Arc::new(SharedStatus::new());
    let vpn_status = SharedVpnStatus::new(vpn_cfg.mtu);
    let services = Arc::new(crate::bridge::ServiceRegistry::default());

    let identity = store.lock().unwrap().identity.clone();
    let services_for_writer = services.clone();
    let store_for_cache = store.clone();
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
            initial_devices,
            on_devices_cached: Some(Arc::new(move |entries| {
                if let Ok(s) = store_for_cache.lock() {
                    let _ = s.save_devices_cache(entries);
                }
            })),
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
    *kick_slot.lock().unwrap() = Some(handle.clone());

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let vpn_task = topaz_vpn::spawn(
        handle.clone(),
        status.clone(),
        vpn_status.clone(),
        vpn_cfg,
        shutdown_tx.subscribe(),
    );
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
        shutdown: shutdown_tx.clone(),
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
        _ = async {
            while !*shutdown_rx.borrow() {
                if shutdown_rx.changed().await.is_err() {
                    std::future::pending::<()>().await;
                }
            }
        } => {
            info!("shutdown requested over control.sock; exiting");
            Ok(())
        }
    };
    let _ = shutdown_tx.send(true);
    if let Some(t) = vpn_task {
        // Wait briefly so SystemDnsGuard::drop cleanly removes OS split-DNS config.
        if tokio::time::timeout(Duration::from_secs(2), t).await.is_err() {
            warn!("VPN task did not finish cleanup within 2s");
        }
    }
    outcome
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
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
