mod api;
mod db;
mod relay;
mod state;
mod stun;
mod tls;

use anyhow::Result;
use clap::{Parser, Subcommand};
use db::{display_invite, Db};
use state::{now_unix, AppState};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tls::ServerTls;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "conduit-coord", about = "Conduit coordination and relay server")]
struct Args {
    /// HTTPS + WSS listen address (control plane).
    #[arg(long, default_value = "0.0.0.0:7722", env = "COORD_LISTEN")]
    listen: SocketAddr,
    /// TCP relay listen address.
    #[arg(long, default_value = "0.0.0.0:7723", env = "COORD_RELAY_LISTEN")]
    relay_listen: SocketAddr,
    /// Relay host:port returned to clients. Defaults to the Host the client used
    /// plus the relay listen port.
    #[arg(long, env = "COORD_RELAY_ADVERTISE")]
    relay_advertise: Option<String>,
    /// Extra HTTPS+WSS listen (same API, including `/v1/relay`). Off by default.
    /// Binding 443 needs `CAP_NET_BIND_SERVICE` or root.
    #[arg(long, env = "COORD_RELAY_WS_LISTEN")]
    relay_ws_listen: Option<SocketAddr>,
    /// WebSocket relay URL returned to clients. Defaults to `wss://<Host>/v1/relay`
    /// on the control-plane port, or on `--relay-ws-listen` if that bind succeeded.
    #[arg(long, env = "COORD_RELAY_WS_ADVERTISE")]
    relay_ws_advertise: Option<String>,
    /// STUN (UDP, RFC 5389 BINDING) listen address for NAT traversal.
    #[arg(long, default_value = "0.0.0.0:3478", env = "COORD_STUN_LISTEN")]
    stun_listen: SocketAddr,
    /// Advertised STUN `host:port` returned to clients. Defaults to the
    /// request's Host header with the STUN port.
    #[arg(long, env = "COORD_STUN_ADVERTISE")]
    stun_advertise: Option<String>,
    /// Turn the STUN listener off (register responses advertise no STUN).
    #[arg(long)]
    stun_disable: bool,
    /// SQLite database with accounts, devices, invites and the TLS key.
    #[arg(long, default_value = "coord.db", env = "COORD_DB")]
    db: PathBuf,
    /// Public URL clients use, e.g. https://1.2.3.4:7722. Only used to print
    /// ready-to-copy commands with new invites.
    #[arg(long, env = "COORD_PUBLIC_URL")]
    public_url: Option<String>,
    /// Relay bandwidth shared by all sessions of one account, in Mbit/s.
    #[arg(long, default_value_t = 50, env = "COORD_RELAY_MBPS_PER_ACCOUNT")]
    relay_mbps_per_account: u64,
    /// Concurrent relay sessions allowed per account.
    #[arg(long, default_value_t = 8, env = "COORD_RELAY_SESSIONS_PER_ACCOUNT")]
    relay_sessions_per_account: usize,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Manage invite codes for account creation.
    Invite {
        #[command(subcommand)]
        action: InviteCmd,
    },
    /// Print the TLS key fingerprint clients pass to `conduit init --pin`.
    Fingerprint,
    /// Relay bytes per account per day.
    Usage,
}

#[derive(Subcommand, Debug)]
enum InviteCmd {
    /// Create new single-use invite codes.
    Create {
        #[arg(long, default_value_t = 1)]
        count: u32,
    },
    /// List invite codes and whether they were used.
    List,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "conduit_coord=info,tower_http=info".into()),
        )
        .init();

    let args = Args::parse();
    let db = Db::open(&args.db)?;
    let server_tls = ServerTls::from_seed(db.server_key_seed()?)?;

    match args.cmd {
        Some(Cmd::Invite {
            action: InviteCmd::Create { count },
        }) => {
            for code in db.create_invites(count, now_unix())? {
                let code = display_invite(&code);
                match &args.public_url {
                    Some(url) => println!(
                        "{code}\n  conduit init --coord-url {url} --pin {} && conduit account create --invite {code}",
                        server_tls.pin
                    ),
                    None => println!("{code}"),
                }
            }
            return Ok(());
        }
        Some(Cmd::Invite {
            action: InviteCmd::List,
        }) => {
            for (code, created, used_by) in db.list_invites()? {
                let status = used_by.map_or("unused".to_string(), |u| format!("used by {u}"));
                println!("{}  created {created}  {status}", display_invite(&code));
            }
            return Ok(());
        }
        Some(Cmd::Fingerprint) => {
            println!("{}", server_tls.pin);
            return Ok(());
        }
        Some(Cmd::Usage) => {
            for (day, user_id, bytes) in db.usage()? {
                println!("{day}  {user_id}  {:.1} MiB", bytes as f64 / (1024.0 * 1024.0));
            }
            return Ok(());
        }
        None => {}
    }

    let state = Arc::new(AppState::new(
        db,
        args.relay_advertise.clone(),
        args.relay_listen.port(),
        args.relay_ws_advertise.clone(),
        args.listen.port(),
    ));

    let limits = relay::Limits {
        bytes_per_sec: args.relay_mbps_per_account * 1_000_000 / 8,
        sessions: args.relay_sessions_per_account,
    };
    let relay = relay::start(args.relay_listen, state.clone(), limits).await?;

    if args.stun_disable {
        info!("stun disabled");
    } else {
        let stun_addr = args.stun_listen;
        tokio::spawn(async move {
            if let Err(e) = crate::stun::listen(stun_addr).await {
                warn!(error = %e, %stun_addr, "stun listen failed");
            }
        });
        state.set_stun(args.stun_advertise.clone(), args.stun_listen.port());
    }

    let extra_listener = match args.relay_ws_listen {
        Some(addr) => match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => {
                state.set_relay_ws_listen_port(addr.port());
                info!(%addr, "extra https+wss listen");
                Some(l)
            }
            Err(e) => {
                warn!(
                    error = %e,
                    %addr,
                    "extra relay-ws listen failed; websocket relay remains on the control-plane port"
                );
                None
            }
        },
        None => None,
    };

    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    let app = api::router(state, relay.clone());
    info!(
        addr = %args.listen,
        relay = %args.relay_listen,
        relay_ws = "/v1/relay",
        db = %args.db.display(),
        pin = %server_tls.pin,
        "coord listening (https)"
    );
    let extra = extra_serve(server_tls.clone(), extra_listener, app.clone());
    tokio::select! {
        r = server_tls.serve(listener, app) => r?,
        r = extra => r?,
        _ = shutdown_signal() => info!("shutting down"),
    }
    relay.flush_usage();
    Ok(())
}

async fn extra_serve(
    tls: ServerTls,
    listener: Option<tokio::net::TcpListener>,
    app: axum::Router,
) -> Result<()> {
    match listener {
        Some(l) => tls.serve(l, app).await,
        None => std::future::pending::<Result<()>>().await,
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "cannot listen for SIGTERM");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
