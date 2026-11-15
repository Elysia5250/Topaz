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
use conduit_core::{
    generate_recovery_code, issue_cert, issue_revocation, AccountInfo, AccountKey, Store,
};
use conduit_net::{approve_new_device, join_with_code};
use conduit_proto::auth::{format_pin, parse_pin};
use conduit_proto::CreateAccountRequest;
use serde_json::json;
use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "conduit",
    about = "Conduit Session Engine — pure-network P2P device fabric (QUIC/mTLS/STUN/mDNS/relay)"
)]
struct Cli {
    /// Data directory (device key, account, config, status).
    #[arg(long, global = true, env = "CONDUIT_DATA_DIR")]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Commands,
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
    /// One-line onboarding on a new device from a `device add` bundle.
    Setup {
        bundle: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        install: bool,
    },
    /// Print account, connection and peer session status.
    Status,
    /// Print the local control socket path clients should dial.
    SocketPath,
    /// Nudge the running daemon to probe/announce peers.
    Kick {
        #[arg(long)]
        local: bool,
    },
    /// Diagnose this device, coord reachability, STUN, mDNS, and peer endpoints.
    Doctor,
    /// Manage user-level autostart for the daemon.
    Service {
        #[command(subcommand)]
        cmd: ServiceCmd,
    },
    /// OpenCode-style live terminal UI connected to the running daemon over control.sock.
    Tui {
        /// Color theme ("opencode" or "light").
        #[arg(long, default_value = "opencode")]
        theme: String,
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
        /// Custom TUN interface name (e.g. conduit0 on Linux, utunN on macOS).
        #[arg(long)]
        tun_name: Option<String>,
        /// Virtual interface MTU.
        #[arg(long, default_value_t = conduit_vpn::DEFAULT_MTU)]
        mtu: u16,
        /// Local UDP bind address for the `*.conduit` DNS responder.
        #[arg(long)]
        dns_listen: Option<std::net::SocketAddr>,
        /// Detach into a background daemon (setsid + `<data_dir>/conduit.log`).
        #[arg(long)]
        detach: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum ServiceCmd {
    Install,
    Uninstall,
    Status,
}

#[derive(Subcommand, Debug)]
enum AccountCmd {
    Create {
        #[arg(long)]
        invite: String,
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
    #[cfg(unix)]
    if !matches!(&cli.cmd, Commands::Run { .. }) {
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        }
    }
    if !matches!(&cli.cmd, Commands::Tui { .. }) {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            tracing_subscriber::EnvFilter::new(
                "conduit_cli=info,conduit_net=info,conduit_fabric=info,conduit_vpn=info",
            )
        });
        tracing_subscriber::fmt()
            .with_ansi(std::io::stderr().is_terminal())
            .with_env_filter(filter)
            .init();
    }

    let data_dir = cli.data_dir.unwrap_or_else(Store::default_data_dir);

    match cli.cmd {
        Commands::Init {
            coord_url,
            pin,
            name,
        } => cmd_init(data_dir, coord_url, pin, name),
        Commands::Account {
            cmd: AccountCmd::Create { invite },
        } => cmd_account_create(data_dir, invite).await,
        Commands::Device { cmd } => match cmd {
            DeviceCmd::Add => cmd_device_add(data_dir).await,
            DeviceCmd::List => cmd_device_list(data_dir).await,
            DeviceCmd::Revoke {
                device_id,
                recovery,
            } => cmd_device_revoke(data_dir, device_id, recovery).await,
        },
        Commands::Join { code, recovery } => cmd_join(data_dir, code, recovery).await,
        Commands::Setup {
            bundle,
            name,
            install,
        } => cmd_setup(data_dir, bundle, name, install).await,
        Commands::Status => cmd_status(data_dir).await,
        Commands::SocketPath => {
            println!(
                "{}",
                conduit_core::control_socket_path(&data_dir).display()
            );
            Ok(())
        }
        Commands::Kick { local } => cmd_kick(data_dir, !local).await,
        Commands::Doctor => doctor::cmd_doctor(data_dir).await,
        Commands::Service { cmd } => service::cmd_service(data_dir, cmd).await,
        Commands::Tui { theme } => tui::cmd_tui(data_dir, &theme).await,
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
            let vpn_cfg = conduit_vpn::VpnConfig {
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
    AccountKey::from_recovery(line.trim())
}

fn ensure_no_account(store: &Store) -> Result<()> {
    if let Some(a) = &store.account {
        bail!(
            "this device already belongs to account {}; use a fresh --data-dir to join another",
            a.user_id
        );
    }
    Ok(())
}

fn cmd_init(
    data_dir: PathBuf,
    coord_url: Option<String>,
    pin: Option<String>,
    name: Option<String>,
) -> Result<()> {
    let mut store = Store::open(data_dir.clone())?;
    if let Some(u) = coord_url {
        if !u.starts_with("https://") {
            bail!("coord URL must start with https://");
        }
        store.config.coord_url = u;
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

async fn cmd_account_create(data_dir: PathBuf, invite: String) -> Result<()> {
    let mut store = Store::open(data_dir)?;
    ensure_no_account(&store)?;
    let coord = ops::coord_client(&store)?;
    let recovery = generate_recovery_code();
    let root = AccountKey::from_recovery(&recovery)?;
    let cert = issue_cert(
        &root.signing,
        &root.user_id,
        &root.user_pubkey,
        &store.identity.pubkey_hex,
        &store.device_name(),
    )?;
    coord
        .create_account(&CreateAccountRequest {
            invite,
            cert: cert.clone(),
        })
        .await
        .context("create account")?;
    let info = AccountInfo::from_cert(&store.identity, cert)?;
    println!("account {} created", info.user_id);
    store.save_account(info)?;
    println!();
    println!("recovery code (write it down; it is not stored anywhere):");
    println!();
    println!("    {recovery}");
    println!();
    println!("Use it to add a device when no other device is online, or to revoke a lost one.");
    Ok(())
}

async fn cmd_device_add(data_dir: PathBuf) -> Result<()> {
    if let Some(daemon) = client::ControlClient::try_daemon(&data_dir).await {
        let v = daemon.post("/v1/devices/add", None).await?;
        let code = v["code"].as_str().unwrap_or("?").to_string();
        println!("{code}");
        if let Some(setup) = v["setup"].as_str() {
            println!("on the new device run:");
            println!("  conduit setup '{setup}'");
        }
        println!("waiting up to 5 minutes...");
        let _ = std::io::stdout().flush();
        let v = daemon.get(&format!("/v1/devices/add/{code}")).await?;
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
        println!("  conduit setup '{}'", setup_bundle(&store, code));
        println!("waiting up to 5 minutes...");
        let _ = std::io::stdout().flush();
    })
    .await?;
    println!("added {} ({})", cert.name, cert.device_id);
    Ok(())
}

pub(crate) fn setup_bundle(store: &Store, code: &str) -> String {
    use base64::Engine as _;
    let payload = json!({
        "url": store.config.coord_url,
        "pin": store.config.coord_pin,
        "code": code,
        "by": store.identity.device_id,
        "by_name": store.config.device_name,
    });
    format!(
        "conduit-setup:v1:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string())
    )
}

#[derive(serde::Deserialize)]
struct SetupBundle {
    url: String,
    pin: String,
    code: String,
    #[allow(dead_code)]
    by: String,
    #[serde(default)]
    #[allow(dead_code)]
    by_name: String,
}

fn parse_setup_bundle(raw: &str) -> Result<SetupBundle> {
    use base64::Engine as _;
    let s = raw.trim().trim_matches(|c| c == '\'' || c == '"');
    let body = s.strip_prefix("conduit-setup:v1:").with_context(|| {
        "not an conduit-setup:v1 bundle (print one with `conduit device add`)"
    })?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body)
        .context("bundle is not valid base64")?;
    serde_json::from_slice(&bytes).context("bundle payload is malformed")
}

async fn cmd_setup(
    data_dir: PathBuf,
    bundle: String,
    name: Option<String>,
    install: bool,
) -> Result<()> {
    let b = parse_setup_bundle(&bundle)?;
    if !b.url.starts_with("https://") {
        bail!("bundle coord URL is not https://: {}", b.url);
    }
    let pin = parse_pin(&b.pin).ok_or_else(|| anyhow::anyhow!("bundle pin is malformed"))?;

    let mut store = Store::open(data_dir.clone())?;
    ensure_no_account(&store)?;
    store.config.coord_url = b.url.clone();
    store.config.coord_pin = format_pin(&pin);
    if let Some(n) = &name {
        store.config.device_name = n.clone();
    }
    store.save_config()?;

    let coord = ops::coord_client(&store)?;
    let name = store.device_name();
    let cert = join_with_code(&coord, &store.identity, &name, &b.code).await?;
    let info = AccountInfo::from_cert(&store.identity, cert)?;
    println!(
        "joined account {} as {} ({})",
        info.user_id, store.identity.device_id, name
    );
    store.save_account(info)?;

    if install {
        service::cmd_service(data_dir, ServiceCmd::Install).await?;
    } else {
        println!(
            "start the node with `conduit run`, or `conduit service install` for autostart"
        );
    }
    Ok(())
}

async fn cmd_join(data_dir: PathBuf, code: Option<String>, recovery: bool) -> Result<()> {
    let mut store = Store::open(data_dir)?;
    ensure_no_account(&store)?;
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
            .map(|d| format!("{d}.conduit"))
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
        .map_err(|e| anyhow::anyhow!("{e}; start the daemon with `conduit run`"))?;
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
        None => println!("runtime_status (none — start with `conduit run`)"),
    }
    Ok(())
}
