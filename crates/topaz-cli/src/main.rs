mod bridge;
mod client;
mod control;
mod doctor;
mod ops;
mod run;
mod service;
mod tui;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use topaz_core::{issue_cert, issue_revocation, AccountInfo, AccountKey, Store};
use topaz_net::{
    approve_new_device, approve_with_secret, join_with_code, join_with_secret_with_sas,
    probe_coord_pin,
};
use topaz_proto::auth::{format_pin, parse_pin};
use zeroize::Zeroize;

#[derive(Parser, Debug)]
#[command(
    name = "topaz",
    version = topaz_proto::VERSION_LONG,
    about = "Topaz Session Engine — pure-network P2P device fabric (QUIC/mTLS/STUN/mDNS/relay)"
)]
struct Cli {
    /// Data directory (device key, account, config, status).
    #[arg(long, global = true, env = "TOPAZ_DATA_DIR")]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Create this device's key and set the coord URL and pin.
    Init {
        #[arg(long, env = "COORD_URL")]
        coord_url: Option<String>,
        #[arg(long, env = "COORD_PIN")]
        pin: Option<String>,
        #[arg(long)]
        name: Option<String>,
    },
    /// Account management.
    Account {
        #[command(subcommand)]
        cmd: AccountCmd,
    },
    /// Devices in this account.
    Device {
        #[command(subcommand)]
        cmd: DeviceCmd,
    },
    /// Join an account with a code from `device add`, or with the recovery code.
    Join {
        #[arg(required_unless_present = "recovery")]
        code: Option<String>,
        #[arg(long, conflicts_with = "code")]
        recovery: bool,
    },
    /// Pair devices using a short human-chosen phrase (zero copy-paste).
    ///
    /// Existing device: `topaz pair <phrase>`
    /// New device:      `topaz pair <coord-ip-or-url> <phrase> [--name macbook]`
    Pair {
        /// Either `<phrase>` (existing device or already-initialized new device),
        /// or `<coord-host-or-url>` when followed by `<phrase>`.
        first: String,
        /// Pairing phrase when `<first>` is the coord host/URL.
        second: Option<String>,
        /// Optional friendly device name (new device).
        #[arg(long)]
        name: Option<String>,
        /// Auto-confirm TOFU server pin / new device approval without prompting.
        #[arg(long, short = 'y')]
        yes: bool,
        /// Start the daemon in the background right after joining (new device).
        #[arg(long)]
        start: bool,
        /// Used with `--start`: run without TUN (control.sock + sessions only).
        #[arg(long)]
        no_tun: bool,
    },
    /// One-line onboarding on a new device from a `device add` bundle.
    Setup {
        bundle: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        install: bool,
        /// Start the daemon in the background right after joining.
        #[arg(long)]
        start: bool,
        /// Used with `--start`: run without TUN (control.sock + sessions only).
        #[arg(long)]
        no_tun: bool,
    },
    /// Print account, connection and peer session status.
    Status,
    /// Print the local control socket path clients should dial.
    SocketPath,
    /// Stop the running background daemon cleanly.
    Stop,
    /// Nudge the running daemon to probe/announce peers.
    Kick {
        #[arg(long)]
        local: bool,
    },
    /// Diagnose this device, coord reachability, STUN, mDNS, and peer endpoints.
    Doctor,
    /// Manage user-level or system-level autostart for the daemon.
    Service {
        #[command(subcommand)]
        cmd: ServiceCmd,
    },
    /// Full-lifecycle interactive terminal UI (onboarding, daemon, pairing, doctor, logs).
    Tui {
        /// Color theme override ("ink", "tokyonight", or "light").
        #[arg(long)]
        theme: Option<String>,
    },
    /// Run the network engine node (long-lived).
    Run {
        #[arg(long, env = "COORD_URL")]
        coord_url: Option<String>,
        #[arg(long)]
        force_relay: bool,
        #[arg(long)]
        no_mdns: bool,
        /// Disable the L3 TUN interface and run session/control.sock mode only.
        #[arg(long)]
        no_tun: bool,
        /// Custom TUN interface name (e.g. topaz0 on Linux, utunN on macOS).
        #[arg(long)]
        tun_name: Option<String>,
        /// Virtual interface MTU.
        #[arg(long, default_value_t = topaz_vpn::DEFAULT_MTU)]
        mtu: u16,
        /// Local UDP bind address for the `*.topaz` DNS responder.
        #[arg(long)]
        dns_listen: Option<std::net::SocketAddr>,
        /// Detach into a background daemon (setsid + `<data_dir>/topaz.log`).
        #[arg(long)]
        detach: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum ServiceCmd {
    Install {
        /// Do not start the TUN device (control.sock + sessions only).
        #[arg(long)]
        no_tun: bool,
        /// Install as a system service (systemd with CAP_NET_ADMIN / macOS LaunchDaemon; requires sudo).
        #[arg(long)]
        system: bool,
    },
    Uninstall {
        /// Uninstall the system-level service (requires sudo).
        #[arg(long)]
        system: bool,
    },
    Status,
}

#[derive(Subcommand, Debug)]
enum AccountCmd {
    Create {
        #[arg(long)]
        invite: String,
        /// Optional coord URL (merges `topaz init` into a single step).
        #[arg(long, env = "COORD_URL")]
        coord_url: Option<String>,
        /// Optional coord TLS pin (used with `--coord-url`).
        #[arg(long, env = "COORD_PIN")]
        pin: Option<String>,
        /// Optional friendly device name.
        #[arg(long)]
        name: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum DeviceCmd {
    Add,
    List,
    Revoke {
        device_id: String,
        #[arg(long)]
        recovery: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    let is_run = matches!(&cli.cmd, Some(Commands::Run { .. }));
    let is_tui = matches!(&cli.cmd, Some(Commands::Tui { .. }) | None);
    #[cfg(unix)]
    if !is_run {
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        }
    }
    if !is_tui {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            tracing_subscriber::EnvFilter::new(
                "topaz_cli=info,topaz_net=info,topaz_fabric=info,topaz_vpn=info",
            )
        });
        tracing_subscriber::fmt()
            .with_ansi(std::io::stderr().is_terminal())
            .with_env_filter(filter)
            .init();
    }

    let data_dir = cli.data_dir.unwrap_or_else(Store::default_data_dir);

    let Some(cmd) = cli.cmd else {
        if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
            return tui::cmd_tui(data_dir, None).await;
        }
        if client::ControlClient::try_daemon(&data_dir).await.is_some() {
            println!("topaz daemon is running for {}", data_dir.display());
        } else {
            println!("topaz daemon is not running for {}", data_dir.display());
            println!("  interactive TUI: topaz");
            println!("  start (no TUN):  topaz run --no-tun --detach");
            println!("  start (VPN TUN): sudo topaz run --detach");
        }
        return Ok(());
    };

    match cmd {
        Commands::Init {
            coord_url,
            pin,
            name,
        } => cmd_init(data_dir, coord_url, pin, name),
        Commands::Account {
            cmd:
                AccountCmd::Create {
                    invite,
                    coord_url,
                    pin,
                    name,
                },
        } => cmd_account_create(data_dir, invite, coord_url, pin, name).await,
        Commands::Device { cmd } => match cmd {
            DeviceCmd::Add => cmd_device_add(data_dir).await,
            DeviceCmd::List => cmd_device_list(data_dir).await,
            DeviceCmd::Revoke {
                device_id,
                recovery,
            } => cmd_device_revoke(data_dir, device_id, recovery).await,
        },
        Commands::Join { code, recovery } => cmd_join(data_dir, code, recovery).await,
        Commands::Pair {
            first,
            second,
            name,
            yes,
            start,
            no_tun,
        } => cmd_pair(data_dir, first, second, name, yes, start, no_tun).await,
        Commands::Setup {
            bundle,
            name,
            install,
            start,
            no_tun,
        } => cmd_setup(data_dir, bundle, name, install, start, no_tun).await,
        Commands::Status => cmd_status(data_dir).await,
        Commands::SocketPath => {
            println!(
                "{}",
                topaz_core::control_socket_path(&data_dir).display()
            );
            Ok(())
        }
        Commands::Stop => cmd_stop(data_dir).await,
        Commands::Kick { local } => cmd_kick(data_dir, !local).await,
        Commands::Doctor => doctor::cmd_doctor(data_dir).await,
        Commands::Service { cmd } => service::cmd_service(data_dir, cmd).await,
        Commands::Tui { theme } => tui::cmd_tui(data_dir, theme.as_deref()).await,
        Commands::Run {
            coord_url,
            force_relay,
            no_mdns,
            no_tun,
            tun_name,
            mtu,
            dns_listen,
            detach,
        } => {
            let vpn_cfg = topaz_vpn::VpnConfig {
                disabled: no_tun,
                tun_name,
                mtu,
                dns_listen,
            };
            if detach {
                run::spawn_detached(data_dir, coord_url, force_relay, !no_mdns, vpn_cfg).await
            } else {
                run::cmd_run(data_dir, coord_url, force_relay, !no_mdns, vpn_cfg).await
            }
        }
    }
}

fn read_recovery_code() -> Result<AccountKey> {
    eprint!("recovery code: ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let res = AccountKey::from_recovery(line.trim());
    line.zeroize();
    res
}

fn cmd_init(
    data_dir: PathBuf,
    coord_url: Option<String>,
    pin: Option<String>,
    name: Option<String>,
) -> Result<()> {
    let mut store = Store::open(data_dir.clone())?;
    if let Some(u) = coord_url {
        let norm = ops::normalize_coord_arg(&u);
        if !norm.starts_with("https://") {
            bail!("coord URL must start with https://");
        }
        store.config.coord_url = norm;
    }
    if let Some(p) = pin {
        let bytes = parse_pin(&p).ok_or_else(|| anyhow::anyhow!("pin is malformed"))?;
        store.config.coord_pin = format_pin(&bytes);
    }
    if let Some(n) = name {
        store.config.device_name = n;
    }
    store.save_config()?;
    println!("initialized {}", data_dir.display());
    println!("device_id {}", store.identity.device_id);
    Ok(())
}

async fn cmd_account_create(
    data_dir: PathBuf,
    invite: String,
    coord_url: Option<String>,
    pin: Option<String>,
    name: Option<String>,
) -> Result<()> {
    let (info, mut recovery) = ops::create_account_direct(
        &data_dir,
        &invite,
        coord_url.as_deref(),
        pin.as_deref(),
        name.as_deref(),
    )
    .await?;
    println!("account {} created", info.user_id);
    println!();
    println!("recovery code (write it down; it is not stored anywhere):");
    println!();
    println!("    {recovery}");
    println!();
    println!("Use it to add a device when no other device is online, or to revoke a lost one.");
    recovery.zeroize();
    Ok(())
}

async fn cmd_device_add(data_dir: PathBuf) -> Result<()> {
    if let Some(daemon) = client::ControlClient::try_daemon(&data_dir).await {
        let v = daemon.post("/v1/devices/add", None).await?;
        let code = v["code"].as_str().unwrap_or("?").to_string();
        println!("{code}");
        if let Some(setup) = v["setup"].as_str() {
            println!("on the new device run:");
            println!("  topaz setup '{setup}'");
        }
        println!("waiting up to 5 minutes...");
        let _ = std::io::stdout().flush();
        let v = daemon
            .get_with_timeout(
                &format!("/v1/devices/add/{code}"),
                std::time::Duration::from_secs(330),
            )
            .await?;
        println!(
            "added {} ({})",
            v["name"].as_str().unwrap_or("?"),
            v["device_id"].as_str().unwrap_or("?")
        );
        return Ok(());
    }
    let store = Store::open(data_dir)?;
    let account = store.require_account()?.clone();
    let coord = ops::coord_client(&store)?;
    let cert = approve_new_device(&coord, &store.identity, &account, |code| {
        println!("{code}");
        println!("on the new device run:");
        println!("  topaz setup '{}'", setup_bundle(&store, code));
        println!("waiting up to 5 minutes...");
        let _ = std::io::stdout().flush();
    })
    .await?;
    println!("added {} ({})", cert.name, cert.device_id);
    Ok(())
}

pub(crate) use ops::setup_bundle;

async fn cmd_setup(
    data_dir: PathBuf,
    bundle: String,
    name: Option<String>,
    install: bool,
    start: bool,
    no_tun: bool,
) -> Result<()> {
    let info = ops::join_with_setup_bundle(&data_dir, &bundle, name.as_deref()).await?;
    let store = Store::open(data_dir.clone())?;
    println!(
        "joined account {} as {} ({})",
        info.user_id,
        store.identity.device_id,
        store.device_name()
    );

    if install {
        service::cmd_service(
            data_dir,
            ServiceCmd::Install {
                no_tun: true,
                system: false,
            },
        )
        .await?;
    } else if start {
        let vpn_cfg = topaz_vpn::VpnConfig {
            disabled: no_tun,
            tun_name: None,
            mtu: topaz_vpn::DEFAULT_MTU,
            dns_listen: None,
        };
        run::spawn_detached(data_dir, None, false, true, vpn_cfg).await?;
    } else {
        println!(
            "start the node with `topaz` (TUI), `topaz run --detach`, or `topaz service install`"
        );
    }
    Ok(())
}

async fn cmd_stop(data_dir: PathBuf) -> Result<()> {
    if run::stop_daemon_quiet(&data_dir).await? {
        println!("topaz daemon stopped");
    } else {
        println!("topaz daemon is not running");
    }
    Ok(())
}

async fn cmd_join(data_dir: PathBuf, code: Option<String>, recovery: bool) -> Result<()> {
    let mut store = Store::open(data_dir)?;
    ops::ensure_no_account(&store)?;
    let coord = ops::coord_client(&store)?;
    let name = store.device_name();
    let cert = if recovery {
        let root = read_recovery_code()?;
        let cert = issue_cert(
            &root.signing,
            &root.user_id,
            &root.user_pubkey,
            &store.identity.pubkey_hex,
            &name,
        )?;
        coord
            .add_device(&cert)
            .await
            .context("join with recovery code")?;
        cert
    } else {
        let code = code.expect("clap requires code unless --recovery");
        join_with_code(&coord, &store.identity, &name, &code).await?
    };
    let info = AccountInfo::from_cert(&store.identity, cert)?;
    println!(
        "joined account {} as {}",
        info.user_id, store.identity.device_id
    );
    store.save_account(info)?;
    Ok(())
}

fn confirm_prompt(prompt: &str) -> Result<bool> {
    eprint!("{prompt} [Y/n] ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let ans = line.trim().to_ascii_lowercase();
    Ok(ans.is_empty() || ans == "y" || ans == "yes")
}

async fn cmd_pair(
    data_dir: PathBuf,
    first: String,
    second: Option<String>,
    name: Option<String>,
    yes: bool,
    start: bool,
    no_tun: bool,
) -> Result<()> {
    let mut store = Store::open(data_dir.clone())?;

    // Existing device with an account -> approve mode (`topaz pair <phrase>`).
    if let Some(account) = store.account.clone() {
        if second.is_some() {
            bail!(
                "this device already belongs to account {}; run `topaz pair <phrase>` to approve a new device",
                account.user_id
            );
        }
        let phrase = first;
        let coord = ops::coord_client(&store)?;
        let coord_display = store.config.coord_url.clone();
        println!("waiting for peer with phrase '{phrase}' on {coord_display} (up to 5 min)...");
        println!(
            "on the new device run:\n  topaz pair {} {phrase}",
            ops::coord_short_host(&coord_display)
        );
        let _ = std::io::stdout().flush();

        let cert = approve_with_secret(
            &coord,
            &store.identity,
            &account,
            &phrase,
            |dev_name, dev_id, sas| {
                if yes {
                    return Ok(true);
                }
                confirm_prompt(&format!(
                    "Approve '{dev_name}' ({dev_id}) [verify code: {sas}] to join this account?"
                ))
            },
        )
        .await?;
        println!("added {} ({})", cert.name, cert.device_id);
        return Ok(());
    }

    // New device without an account -> join mode.
    let (coord_arg, phrase) = match second {
        Some(p) => (Some(first), p),
        None => (None, first),
    };

    if let Some(raw_coord) = coord_arg {
        let url = ops::normalize_coord_arg(&raw_coord);
        if !url.starts_with("https://") {
            bail!("coord URL must start with https:// (got {url})");
        }
        let need_probe = store.config.coord_url != url || store.config.coord_pin.is_empty();
        if need_probe {
            println!("probing coord TLS fingerprint at {url}...");
            let pin = probe_coord_pin(&url).await?;
            let short = &pin[..9.min(pin.len())];
            if !yes
                && !confirm_prompt(&format!(
                    "Trust coord {url}\n  pin: {pin} (starts with {short})?"
                ))?
            {
                bail!("aborted by user");
            }
            store.config.coord_url = url;
            store.config.coord_pin = pin;
            store.save_config()?;
        }
    }

    if let Some(n) = &name {
        store.config.device_name = n.clone();
        store.save_config()?;
    }

    let coord = ops::coord_client(&store)?;
    let my_name = store.device_name();
    println!(
        "waiting to pair as '{my_name}' ({}) with phrase '{phrase}' on {} (up to 5 min)...",
        store.identity.device_id, store.config.coord_url
    );
    let _ = std::io::stdout().flush();

    let cert = join_with_secret_with_sas(&coord, &store.identity, &my_name, &phrase, |sas| {
        println!("verification code: {sas} (confirm this matches the approving device)");
        let _ = std::io::stdout().flush();
    })
    .await?;
    let info = AccountInfo::from_cert(&store.identity, cert)?;
    println!(
        "joined account {} as {} ({})",
        info.user_id, store.identity.device_id, my_name
    );
    store.save_account(info)?;

    if start {
        let vpn_cfg = topaz_vpn::VpnConfig {
            disabled: no_tun,
            tun_name: None,
            mtu: topaz_vpn::DEFAULT_MTU,
            dns_listen: None,
        };
        run::spawn_detached(data_dir, None, false, true, vpn_cfg).await?;
    } else {
        println!("start the node with `sudo topaz run --detach` (or `topaz run --no-tun --detach`)");
    }
    Ok(())
}

async fn cmd_device_list(data_dir: PathBuf) -> Result<()> {
    if let Some(daemon) = client::ControlClient::try_daemon(&data_dir).await {
        let v = daemon.get("/v1/devices").await?;
        let account = v["account"].as_str().unwrap_or("?").to_string();
        let rows: Vec<ops::DeviceRow> = serde_json::from_value(v["devices"].clone())?;
        print_device_rows(&account, &rows);
        return Ok(());
    }
    let store = Store::open(data_dir)?;
    let ctx = ops::OpCtx::for_store(&store)?;
    let devices = ctx.coord.list_devices().await?;
    print_device_rows(&ctx.account.user_id, &ops::device_rows(&ctx, &devices));
    Ok(())
}

fn print_device_rows(account: &str, rows: &[ops::DeviceRow]) {
    println!("account {account}");
    for r in rows {
        let me = if r.me { "  (this device)" } else { "" };
        let vip = r.virtual_ip.as_deref().unwrap_or("-");
        let fqdn = r
            .dns_name
            .as_deref()
            .map(|d| format!("{d}.topaz"))
            .unwrap_or_else(|| "-".to_string());
        println!(
            "  {}  {:<16} {:<15} {:<24} {:<8} added by {}{}",
            r.device_id, r.name, vip, fqdn, r.status, r.issuer, me
        );
    }
}

async fn cmd_device_revoke(data_dir: PathBuf, device_id: String, recovery: bool) -> Result<()> {
    if !recovery {
        if let Some(daemon) = client::ControlClient::try_daemon(&data_dir).await {
            daemon
                .post(&format!("/v1/devices/{device_id}/revoke"), None)
                .await?;
            println!("revoked {device_id}");
            return Ok(());
        }
    }
    let store = Store::open(data_dir)?;
    let account = store.require_account()?.clone();
    let rev = if recovery {
        let root = read_recovery_code()?;
        if root.user_id != account.user_id {
            bail!("that recovery code belongs to a different account");
        }
        issue_revocation(&root.signing, &account.user_id, &device_id)
    } else {
        issue_revocation(&store.identity.signing, &account.user_id, &device_id)
    };
    ops::OpCtx::for_store(&store)?.coord.revoke(&rev).await?;
    println!("revoked {device_id}");
    Ok(())
}

async fn cmd_kick(data_dir: PathBuf, announce: bool) -> Result<()> {
    let client = client::ControlClient::new(&data_dir);
    client
        .post(&format!("/v1/kick?announce={announce}"), None)
        .await
        .map_err(|e| anyhow::anyhow!("{e}; start the daemon with `topaz run`"))?;
    println!("kicked (announce={announce})");
    Ok(())
}

async fn cmd_status(data_dir: PathBuf) -> Result<()> {
    let store = Store::open(data_dir)?;
    println!("device_id {}", store.identity.device_id);
    println!("device_name {}", store.device_name());
    match &store.account {
        Some(a) => println!("account {}", a.user_id),
        None => println!("account (none)"),
    }
    println!("coord_url {}", store.config.coord_url);
    println!("coord_pin {}", store.config.coord_pin);

    let live = match client::ControlClient::try_daemon(&store.root).await {
        Some(c) => c.get("/v1/status").await.ok(),
        None => None,
    };
    match live {
        Some(v) => println!(
            "runtime_status (live)\n{}",
            serde_json::to_string_pretty(&v)?
        ),
        None if store.status_path().exists() => {
            let raw = std::fs::read_to_string(store.status_path())?;
            println!("runtime_status (last written; daemon not running)\n{raw}");
        }
        None => println!("runtime_status (none — start with `topaz run`)"),
    }
    Ok(())
}
