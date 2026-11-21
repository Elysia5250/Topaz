//! OpenCode-style Terminal UI (`topaz tui`) connected to the running
//! daemon over `control.sock`.
//!
//! Pure client: closing `topaz tui` or its terminal never stops `topaz run`.

use std::collections::HashSet;
use std::io::{self, Stdout};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::client::ControlClient;
use crate::ops::DeviceRow;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeKind {
    OpenCode,
    Light,
}

impl ThemeKind {
    pub fn from_name(name: &str) -> Self {
        if name.eq_ignore_ascii_case("light") {
            Self::Light
        } else {
            Self::OpenCode
        }
    }

    pub fn toggle(self) -> Self {
        match self {
            Self::OpenCode => Self::Light,
            Self::Light => Self::OpenCode,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::OpenCode => "opencode",
            Self::Light => "light",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub accent: Color,
    pub ok: Color,
    pub warn: Color,
    pub bad: Color,
    pub border: Color,
    pub muted: Color,
    pub selection: Color,
    pub fg: Color,
    pub modal_bg: Color,
}

impl Theme {
    pub fn for_kind(kind: ThemeKind) -> Self {
        match kind {
            ThemeKind::OpenCode => Self {
                accent: Color::Rgb(157, 124, 216),   // #9d7cd8
                ok: Color::Rgb(127, 216, 143),       // #7fd88f
                warn: Color::Rgb(242, 201, 76),      // #f2c94c
                bad: Color::Rgb(242, 107, 107),      // #f26b6b
                border: Color::Rgb(74, 74, 85),      // #4a4a55
                muted: Color::Rgb(138, 138, 153),    // #8a8a99
                selection: Color::Rgb(45, 42, 58),   // #2d2a3a
                fg: Color::Rgb(229, 229, 239),       // #e5e5ef
                modal_bg: Color::Rgb(26, 25, 34),    // #1a1922
            },
            ThemeKind::Light => Self {
                accent: Color::Rgb(59, 95, 196),     // #3b5fc4
                ok: Color::Rgb(47, 125, 50),         // #2f7d32
                warn: Color::Rgb(154, 107, 0),       // #9a6b00
                bad: Color::Rgb(179, 38, 30),        // #b3261e
                border: Color::Rgb(181, 181, 181),   // #b5b5b5
                muted: Color::Rgb(102, 102, 115),    // #666673
                selection: Color::Rgb(230, 230, 239), // #e6e6ef
                fg: Color::Rgb(27, 27, 34),          // #1b1b22
                modal_bg: Color::Rgb(245, 245, 250), // #f5f5fa
            },
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct TunSnapshot {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub cidr: String,
    #[serde(default)]
    pub mtu: u16,
    #[serde(default)]
    pub dns_listen: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct PeerServiceSnapshot {
    pub service_id: u16,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct PeerSnapshot {
    pub device_id: String,
    pub name: String,
    #[serde(default)]
    pub dns_name: Option<String>,
    #[serde(default)]
    pub virtual_ip: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub rtt_ms: Option<u64>,
    #[serde(default)]
    pub services: Vec<PeerServiceSnapshot>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct LocalServiceSnapshot {
    pub service_id: u16,
    pub name: String,
    #[serde(default)]
    pub online: bool,
    #[serde(default)]
    pub listeners: usize,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct StatusSnapshot {
    #[serde(default)]
    pub account: String,
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub device_name: String,
    #[serde(default)]
    pub dns_name: Option<String>,
    #[serde(default)]
    pub virtual_ip: Option<String>,
    #[serde(default)]
    pub tun: TunSnapshot,
    #[serde(default)]
    pub connection: Option<String>,
    #[serde(default)]
    pub peers: Vec<PeerSnapshot>,
    #[serde(default)]
    pub services: Vec<LocalServiceSnapshot>,
}

#[derive(Debug, Clone, Deserialize)]
struct EventEnvelope {
    #[serde(rename = "type")]
    kind: String,
    status: StatusSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergedPeer {
    pub device_id: String,
    pub name: String,
    pub dns_name: Option<String>,
    pub virtual_ip: Option<String>,
    pub path: Option<String>,
    pub rtt_ms: Option<u64>,
    pub account_status: String,
    pub issuer: Option<String>,
    pub services: Vec<PeerServiceSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusPane {
    Peers,
    Input,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modal {
    Palette {
        query: String,
        selected: usize,
    },
    Pairing {
        code: Option<String>,
        setup: Option<String>,
        state: PairingState,
    },
    RevokeConfirm {
        device_id: String,
        name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingState {
    Starting,
    Waiting,
    Added { name: String, device_id: String },
    Failed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PaletteAction {
    KickAnnounce,
    KickLocal,
    AddDevice,
    RevokeSelected,
    Refresh,
    ToggleSidebar,
    ToggleTheme,
    ClearFilter,
    Quit,
}

const PALETTE_ITEMS: &[(&str, &str, PaletteAction)] = &[
    ("Kick peers (announce)", "Probe peers and broadcast endpoints", PaletteAction::KickAnnounce),
    ("Kick peers (local only)", "Probe peers without announcing", PaletteAction::KickLocal),
    ("Add new device", "Generate one-time pairing code & setup bundle", PaletteAction::AddDevice),
    ("Revoke selected device", "Revoke cert for highlighted peer", PaletteAction::RevokeSelected),
    ("Refresh devices", "Fetch latest /v1/devices and /v1/status", PaletteAction::Refresh),
    ("Toggle sidebar", "Show or hide device list (b / ctrl+x b)", PaletteAction::ToggleSidebar),
    ("Switch color theme", "Toggle opencode / light theme", PaletteAction::ToggleTheme),
    ("Clear peer filter", "Reset bottom filter input", PaletteAction::ClearFilter),
    ("Quit TUI", "Exit UI (daemon keeps running)", PaletteAction::Quit),
];

#[derive(Debug)]
enum UiEvent {
    WsConnected,
    WsDisconnected(String),
    StatusUpdated(Box<StatusSnapshot>),
    DevicesUpdated(Vec<DeviceRow>),
    DevicesError(String),
    ActionResult { ok: bool, message: String },
    PairingCode { code: String, setup: String },
    PairingFinished(std::result::Result<(String, String), String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedCommand {
    Kick { announce: bool },
    AddDevice,
    Revoke { target: Option<String> },
    Refresh,
    ToggleTheme,
    ToggleSidebar,
    ClearFilter,
    Quit,
    Help,
    Unknown(String),
}

pub fn parse_command(raw: &str) -> Option<ParsedCommand> {
    let trimmed = raw.trim();
    let body = trimmed.strip_prefix(':')?;
    let mut parts = body.split_whitespace();
    let Some(cmd) = parts.next() else {
        return Some(ParsedCommand::Help);
    };
    let arg = parts.next();
    Some(match cmd.to_ascii_lowercase().as_str() {
        "k" | "kick" => ParsedCommand::Kick {
            announce: !matches!(arg, Some("local")),
        },
        "a" | "add" | "pair" => ParsedCommand::AddDevice,
        "rev" | "revoke" => ParsedCommand::Revoke {
            target: arg.map(ToString::to_string),
        },
        "r" | "refresh" => ParsedCommand::Refresh,
        "t" | "theme" => ParsedCommand::ToggleTheme,
        "b" | "sidebar" => ParsedCommand::ToggleSidebar,
        "c" | "clear" => ParsedCommand::ClearFilter,
        "q" | "quit" | "exit" => ParsedCommand::Quit,
        "h" | "help" | "?" => ParsedCommand::Help,
        other => ParsedCommand::Unknown(other.to_string()),
    })
}

pub fn merge_peers(status: &StatusSnapshot, devices: &[DeviceRow]) -> Vec<MergedPeer> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for p in &status.peers {
        seen.insert(p.device_id.clone());
        let row = devices.iter().find(|d| d.device_id == p.device_id);
        out.push(MergedPeer {
            device_id: p.device_id.clone(),
            name: p.name.clone(),
            dns_name: p
                .dns_name
                .clone()
                .or_else(|| row.and_then(|r| r.dns_name.clone())),
            virtual_ip: p
                .virtual_ip
                .clone()
                .or_else(|| row.and_then(|r| r.virtual_ip.clone())),
            path: p.path.clone(),
            rtt_ms: p.rtt_ms,
            account_status: row
                .map(|r| r.status.clone())
                .unwrap_or_else(|| "active".to_string()),
            issuer: row.map(|r| r.issuer.clone()),
            services: p.services.clone(),
        });
    }

    for d in devices {
        if d.me || d.device_id == status.device_id || seen.contains(&d.device_id) {
            continue;
        }
        seen.insert(d.device_id.clone());
        out.push(MergedPeer {
            device_id: d.device_id.clone(),
            name: d.name.clone(),
            dns_name: d.dns_name.clone(),
            virtual_ip: d.virtual_ip.clone(),
            path: None,
            rtt_ms: None,
            account_status: d.status.clone(),
            issuer: Some(d.issuer.clone()),
            services: Vec::new(),
        });
    }

    out.sort_by(|a, b| {
        let rank = |m: &MergedPeer| -> u8 {
            if m.path.is_some() {
                0
            } else if m.account_status == "active" {
                1
            } else {
                2
            }
        };
        rank(a)
            .cmp(&rank(b))
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            .then_with(|| a.device_id.cmp(&b.device_id))
    });
    out
}

pub struct AppState {
    pub theme_kind: ThemeKind,
    pub connected: bool,
    pub conn_detail: String,
    pub status: StatusSnapshot,
    pub devices: Vec<DeviceRow>,
    pub selected_idx: usize,
    pub selected_id: Option<String>,
    pub show_sidebar: bool,
    pub focus: FocusPane,
    pub input: String,
    pub modal: Option<Modal>,
    pub leader_until: Option<Instant>,
    pub toast: Option<(String, bool, Instant)>,
    pub activity: Vec<String>,
    pub should_quit: bool,
}

impl AppState {
    pub fn new(theme_kind: ThemeKind) -> Self {
        Self {
            theme_kind,
            connected: false,
            conn_detail: "connecting to control.sock...".to_string(),
            status: StatusSnapshot::default(),
            devices: Vec::new(),
            selected_idx: 0,
            selected_id: None,
            show_sidebar: true,
            focus: FocusPane::Peers,
            input: String::new(),
            modal: None,
            leader_until: None,
            toast: None,
            activity: vec!["TUI started; daemon stays running in background on quit.".into()],
            should_quit: false,
        }
    }

    pub fn active_filter(&self) -> Option<&str> {
        let trimmed = self.input.trim();
        if trimmed.is_empty() || trimmed.starts_with(':') {
            return None;
        }
        let q = trimmed.strip_prefix('/').unwrap_or(trimmed).trim();
        if q.is_empty() {
            None
        } else {
            Some(q)
        }
    }

    pub fn filtered_peers(&self) -> Vec<MergedPeer> {
        let merged = merge_peers(&self.status, &self.devices);
        let Some(q) = self.active_filter() else {
            return merged;
        };
        let q = q.to_lowercase();
        merged
            .into_iter()
            .filter(|p| {
                p.name.to_lowercase().contains(&q)
                    || p.device_id.to_lowercase().contains(&q)
                    || p.dns_name
                        .as_deref()
                        .is_some_and(|d| d.to_lowercase().contains(&q))
                    || p.virtual_ip.as_deref().is_some_and(|ip| ip.contains(&q))
                    || p.services
                        .iter()
                        .any(|s| s.name.to_lowercase().contains(&q))
            })
            .collect()
    }

    pub fn selected_peer(&self) -> Option<MergedPeer> {
        let peers = self.filtered_peers();
        if peers.is_empty() {
            return None;
        }
        if let Some(ref id) = self.selected_id {
            if let Some(found) = peers.iter().find(|p| &p.device_id == id) {
                return Some(found.clone());
            }
        }
        peers.get(self.selected_idx.min(peers.len() - 1)).cloned()
    }

    fn sync_selection(&mut self) {
        let peers = self.filtered_peers();
        if peers.is_empty() {
            self.selected_idx = 0;
            self.selected_id = None;
            return;
        }
        if let Some(ref id) = self.selected_id {
            if let Some(pos) = peers.iter().position(|p| &p.device_id == id) {
                self.selected_idx = pos;
                return;
            }
        }
        self.selected_idx = self.selected_idx.min(peers.len() - 1);
        self.selected_id = Some(peers[self.selected_idx].device_id.clone());
    }

    pub fn move_selection(&mut self, delta: isize) {
        let peers = self.filtered_peers();
        if peers.is_empty() {
            self.selected_idx = 0;
            self.selected_id = None;
            return;
        }
        let len = peers.len() as isize;
        let next = (self.selected_idx as isize + delta).clamp(0, len - 1) as usize;
        self.selected_idx = next;
        self.selected_id = Some(peers[next].device_id.clone());
    }

    fn push_activity(&mut self, line: impl Into<String>) {
        self.activity.push(line.into());
        if self.activity.len() > 60 {
            let drain = self.activity.len() - 60;
            self.activity.drain(..drain);
        }
    }

    fn set_toast(&mut self, ok: bool, msg: impl Into<String>) {
        let msg = msg.into();
        self.push_activity(msg.clone());
        self.toast = Some((msg, ok, Instant::now() + Duration::from_secs(4)));
    }
}

pub async fn cmd_tui(data_dir: PathBuf, theme_name: &str) -> Result<()> {
    let mut guard = TerminalGuard::enter()?;
    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel::<UiEvent>();

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(events_loop(data_dir.clone(), ev_tx.clone(), shutdown_rx.clone()));
    tokio::spawn(devices_poll_loop(data_dir.clone(), ev_tx.clone(), shutdown_rx));

    let mut app = AppState::new(ThemeKind::from_name(theme_name));
    let mut last_tick = Instant::now();

    loop {
        guard.terminal.draw(|f| draw_ui(f, &app))?;

        while let Ok(ev) = ev_rx.try_recv() {
            handle_ui_event(&mut app, ev);
        }

        if let Some((_, _, until)) = app.toast {
            if Instant::now() >= until {
                app.toast = None;
            }
        }
        if let Some(until) = app.leader_until {
            if Instant::now() >= until {
                app.leader_until = None;
            }
        }

        if app.should_quit {
            break;
        }

        let timeout = Duration::from_millis(80);
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                    handle_key(&mut app, key, &data_dir, &ev_tx);
                }
            }
        } else if last_tick.elapsed() >= Duration::from_secs(1) {
            last_tick = Instant::now();
        }
    }

    let _ = shutdown_tx.send(true);
    Ok(())
}

struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalGuard {
    fn enter() -> Result<Self> {
        enable_raw_mode().context("enable terminal raw mode")?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
            .context("enter alternate terminal screen")?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend).context("create ratatui terminal")?;
        Ok(Self { terminal })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        );
        let _ = self.terminal.show_cursor();
    }
}

async fn events_loop(
    data_dir: PathBuf,
    tx: mpsc::UnboundedSender<UiEvent>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let sock_path = topaz_core::control_socket_path(&data_dir);
    loop {
        if *shutdown.borrow() {
            break;
        }
        match tokio::net::UnixStream::connect(&sock_path).await {
            Ok(stream) => match tokio_tungstenite::client_async("ws://localhost/v1/events", stream).await
            {
                Ok((mut ws, _)) => {
                    let _ = tx.send(UiEvent::WsConnected);
                    spawn_refresh_devices(data_dir.clone(), tx.clone());
                    loop {
                        tokio::select! {
                            _ = shutdown.changed() => return,
                            frame = ws.next() => {
                                match frame {
                                    Some(Ok(WsMessage::Text(text))) => {
                                        if let Ok(env) = serde_json::from_str::<EventEnvelope>(&text) {
                                            if env.kind == "status" {
                                                let _ = tx.send(UiEvent::StatusUpdated(Box::new(env.status)));
                                            }
                                        }
                                    }
                                    Some(Ok(WsMessage::Close(_))) | None => {
                                        let _ = tx.send(UiEvent::WsDisconnected("control.sock stream closed".into()));
                                        break;
                                    }
                                    Some(Err(e)) => {
                                        let _ = tx.send(UiEvent::WsDisconnected(format!("ws error: {e}")));
                                        break;
                                    }
                                    Some(Ok(_)) => {}
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(UiEvent::WsDisconnected(format!("ws handshake failed: {e}")));
                }
            },
            Err(_) => {
                let _ = tx.send(UiEvent::WsDisconnected(format!(
                    "daemon offline ({})",
                    sock_path.display()
                )));
            }
        }

        tokio::select! {
            _ = shutdown.changed() => break,
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
}

async fn devices_poll_loop(
    data_dir: PathBuf,
    tx: mpsc::UnboundedSender<UiEvent>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = tokio::time::sleep(Duration::from_secs(10)) => {
                spawn_refresh_devices(data_dir.clone(), tx.clone());
            }
        }
    }
}

fn spawn_refresh_devices(data_dir: PathBuf, tx: mpsc::UnboundedSender<UiEvent>) {
    tokio::spawn(async move {
        let client = ControlClient::new(&data_dir);
        match client.get("/v1/devices").await {
            Ok(v) => match serde_json::from_value::<Vec<DeviceRow>>(v["devices"].clone()) {
                Ok(rows) => {
                    let _ = tx.send(UiEvent::DevicesUpdated(rows));
                }
                Err(e) => {
                    let _ = tx.send(UiEvent::DevicesError(format!("decode devices: {e}")));
                }
            },
            Err(e) => {
                let _ = tx.send(UiEvent::DevicesError(e.to_string()));
            }
        }
    });
}

fn spawn_kick(data_dir: PathBuf, announce: bool, tx: mpsc::UnboundedSender<UiEvent>) {
    tokio::spawn(async move {
        let client = ControlClient::new(&data_dir);
        let msg = match client
            .post(&format!("/v1/kick?announce={announce}"), None)
            .await
        {
            Ok(_) => UiEvent::ActionResult {
                ok: true,
                message: format!("kicked peers (announce={announce})"),
            },
            Err(e) => UiEvent::ActionResult {
                ok: false,
                message: format!("kick failed: {e}"),
            },
        };
        let _ = tx.send(msg);
    });
}

fn spawn_device_add(data_dir: PathBuf, tx: mpsc::UnboundedSender<UiEvent>) {
    tokio::spawn(async move {
        let client = ControlClient::new(&data_dir);
        match client.post("/v1/devices/add", None).await {
            Ok(v) => {
                let code = v["code"].as_str().unwrap_or("?").to_string();
                let setup = v["setup"].as_str().unwrap_or("").to_string();
                let _ = tx.send(UiEvent::PairingCode {
                    code: code.clone(),
                    setup,
                });
                match client.get(&format!("/v1/devices/add/{code}")).await {
                    Ok(done) => {
                        let name = done["name"].as_str().unwrap_or("?").to_string();
                        let id = done["device_id"].as_str().unwrap_or("?").to_string();
                        let _ = tx.send(UiEvent::PairingFinished(Ok((name, id))));
                        spawn_refresh_devices(data_dir, tx);
                    }
                    Err(e) => {
                        let _ = tx.send(UiEvent::PairingFinished(Err(e.to_string())));
                    }
                }
            }
            Err(e) => {
                let _ = tx.send(UiEvent::PairingFinished(Err(e.to_string())));
            }
        }
    });
}

fn spawn_revoke(data_dir: PathBuf, device_id: String, tx: mpsc::UnboundedSender<UiEvent>) {
    tokio::spawn(async move {
        let client = ControlClient::new(&data_dir);
        match client
            .post(&format!("/v1/devices/{device_id}/revoke"), None)
            .await
        {
            Ok(_) => {
                let _ = tx.send(UiEvent::ActionResult {
                    ok: true,
                    message: format!("revoked device {device_id}"),
                });
                spawn_refresh_devices(data_dir, tx);
            }
            Err(e) => {
                let _ = tx.send(UiEvent::ActionResult {
                    ok: false,
                    message: format!("revoke failed: {e}"),
                });
            }
        }
    });
}

fn handle_ui_event(app: &mut AppState, ev: UiEvent) {
    match ev {
        UiEvent::WsConnected => {
            if !app.connected {
                app.push_activity("connected to control.sock /v1/events");
            }
            app.connected = true;
            app.conn_detail = "live ws".to_string();
        }
        UiEvent::WsDisconnected(reason) => {
            if app.connected {
                app.push_activity(format!("disconnected: {reason}"));
            }
            app.connected = false;
            app.conn_detail = reason;
        }
        UiEvent::StatusUpdated(next) => {
            // Record peer plugin mount/unmount transitions into activity feed.
            for peer in &next.peers {
                let prev_svcs: Vec<&str> = app
                    .status
                    .peers
                    .iter()
                    .find(|p| p.device_id == peer.device_id)
                    .map(|p| p.services.iter().map(|s| s.name.as_str()).collect())
                    .unwrap_or_default();
                let next_svcs: Vec<&str> = peer.services.iter().map(|s| s.name.as_str()).collect();
                if prev_svcs != next_svcs && !next_svcs.is_empty() {
                    app.push_activity(format!(
                        "peer {} mounted plugin: {}",
                        peer.name,
                        next_svcs.join(", ")
                    ));
                }
            }
            app.status = *next;
            app.sync_selection();
        }
        UiEvent::DevicesUpdated(rows) => {
            app.devices = rows;
            app.sync_selection();
        }
        UiEvent::DevicesError(err) => {
            if app.connected {
                app.push_activity(format!("devices refresh warning: {err}"));
            }
        }
        UiEvent::ActionResult { ok, message } => {
            app.set_toast(ok, message);
        }
        UiEvent::PairingCode { code, setup } => {
            app.push_activity(format!("pairing code ready: {code}"));
            app.modal = Some(Modal::Pairing {
                code: Some(code),
                setup: Some(setup),
                state: PairingState::Waiting,
            });
        }
        UiEvent::PairingFinished(res) => match res {
            Ok((name, device_id)) => {
                app.set_toast(true, format!("added device {name} ({device_id})"));
                if let Some(Modal::Pairing { code, setup, .. }) = app.modal.take() {
                    app.modal = Some(Modal::Pairing {
                        code,
                        setup,
                        state: PairingState::Added { name, device_id },
                    });
                }
            }
            Err(err) => {
                app.set_toast(false, format!("device add failed: {err}"));
                if let Some(Modal::Pairing { code, setup, .. }) = app.modal.take() {
                    app.modal = Some(Modal::Pairing {
                        code,
                        setup,
                        state: PairingState::Failed(err),
                    });
                }
            }
        },
    }
}

fn handle_key(
    app: &mut AppState,
    key: KeyEvent,
    data_dir: &Path,
    tx: &mpsc::UnboundedSender<UiEvent>,
) {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        app.should_quit = true;
        return;
    }

    if app.leader_until.take().is_some() {
        match key.code {
            KeyCode::Char('q') => app.should_quit = true,
            KeyCode::Char('b') => app.show_sidebar = !app.show_sidebar,
            KeyCode::Char('t') => {
                app.theme_kind = app.theme_kind.toggle();
                app.set_toast(true, format!("theme: {}", app.theme_kind.label()));
            }
            KeyCode::Char('k') => spawn_kick(data_dir.to_path_buf(), true, tx.clone()),
            KeyCode::Char('a') => start_pairing(app, data_dir, tx),
            KeyCode::Char('r') => {
                spawn_refresh_devices(data_dir.to_path_buf(), tx.clone());
                app.set_toast(true, "refreshed devices");
            }
            KeyCode::Char('p') => {
                app.modal = Some(Modal::Palette {
                    query: String::new(),
                    selected: 0,
                });
            }
            _ => {}
        }
        return;
    }

    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('x') {
        app.leader_until = Some(Instant::now() + Duration::from_secs(2));
        return;
    }

    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('p') {
        if matches!(app.modal, Some(Modal::Palette { .. })) {
            app.modal = None;
        } else {
            app.modal = Some(Modal::Palette {
                query: String::new(),
                selected: 0,
            });
        }
        return;
    }

    if app.modal.is_some() {
        handle_modal_key(app, key, data_dir, tx);
        return;
    }

    if matches!(key.code, KeyCode::Tab | KeyCode::BackTab) {
        app.focus = match app.focus {
            FocusPane::Peers => FocusPane::Input,
            FocusPane::Input => FocusPane::Peers,
        };
        return;
    }

    match app.focus {
        FocusPane::Input => handle_input_key(app, key, data_dir, tx),
        FocusPane::Peers => handle_peers_key(app, key, data_dir, tx),
    }
}

fn handle_modal_key(
    app: &mut AppState,
    key: KeyEvent,
    data_dir: &Path,
    tx: &mpsc::UnboundedSender<UiEvent>,
) {
    let Some(modal) = app.modal.take() else {
        return;
    };
    match modal {
        Modal::Palette {
            mut query,
            mut selected,
        } => {
            let matches = filtered_palette(&query);
            match key.code {
                KeyCode::Esc => {}
                KeyCode::Up | KeyCode::Char('k')
                    if key.code == KeyCode::Up || key.modifiers.contains(KeyModifiers::CONTROL) =>
                {
                    selected = selected.saturating_sub(1);
                    app.modal = Some(Modal::Palette { query, selected });
                }
                KeyCode::Down | KeyCode::Char('j')
                    if key.code == KeyCode::Down || key.modifiers.contains(KeyModifiers::CONTROL) =>
                {
                    if !matches.is_empty() {
                        selected = (selected + 1).min(matches.len() - 1);
                    }
                    app.modal = Some(Modal::Palette { query, selected });
                }
                KeyCode::Enter => {
                    if let Some((_, _, action)) = matches.get(selected.min(matches.len().saturating_sub(1))) {
                        execute_palette_action(app, *action, data_dir, tx);
                    }
                }
                KeyCode::Backspace => {
                    query.pop();
                    selected = 0;
                    app.modal = Some(Modal::Palette { query, selected });
                }
                KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    query.push(c);
                    selected = 0;
                    app.modal = Some(Modal::Palette { query, selected });
                }
                _ => {
                    app.modal = Some(Modal::Palette { query, selected });
                }
            }
        }
        Modal::Pairing { code, setup, state } => match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {}
            _ => {
                app.modal = Some(Modal::Pairing { code, setup, state });
            }
        },
        Modal::RevokeConfirm { device_id, name } => match key.code {
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                app.set_toast(true, "revoke cancelled");
            }
            KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => {
                spawn_revoke(data_dir.to_path_buf(), device_id, tx.clone());
            }
            _ => {
                app.modal = Some(Modal::RevokeConfirm { device_id, name });
            }
        },
    }
}

fn handle_input_key(
    app: &mut AppState,
    key: KeyEvent,
    data_dir: &Path,
    tx: &mpsc::UnboundedSender<UiEvent>,
) {
    match key.code {
        KeyCode::Esc => {
            if !app.input.is_empty() {
                app.input.clear();
                app.sync_selection();
            } else {
                app.focus = FocusPane::Peers;
            }
        }
        KeyCode::Enter => {
            let line = app.input.trim().to_string();
            if let Some(cmd) = parse_command(&line) {
                app.input.clear();
                execute_parsed_command(app, cmd, data_dir, tx);
            } else {
                app.focus = FocusPane::Peers;
            }
        }
        KeyCode::Backspace => {
            app.input.pop();
            app.sync_selection();
        }
        KeyCode::Up => app.move_selection(-1),
        KeyCode::Down => app.move_selection(1),
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.input.push(c);
            app.sync_selection();
        }
        _ => {}
    }
}

fn handle_peers_key(
    app: &mut AppState,
    key: KeyEvent,
    data_dir: &Path,
    tx: &mpsc::UnboundedSender<UiEvent>,
) {
    match key.code {
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Char('b') => app.show_sidebar = !app.show_sidebar,
        KeyCode::Char('t') => {
            app.theme_kind = app.theme_kind.toggle();
            app.set_toast(true, format!("theme: {}", app.theme_kind.label()));
        }
        KeyCode::Char('j') | KeyCode::Down => app.move_selection(1),
        KeyCode::Char('k') | KeyCode::Up => {
            if key.code == KeyCode::Char('k') && key.modifiers.contains(KeyModifiers::SHIFT) {
                spawn_kick(data_dir.to_path_buf(), true, tx.clone());
            } else {
                app.move_selection(-1);
            }
        }
        KeyCode::Char('K') => spawn_kick(data_dir.to_path_buf(), true, tx.clone()),
        KeyCode::Char('g') => {
            app.selected_idx = 0;
            app.selected_id = None;
            app.sync_selection();
        }
        KeyCode::Char('G') => {
            let len = app.filtered_peers().len();
            if len > 0 {
                app.selected_idx = len - 1;
                app.selected_id = None;
                app.sync_selection();
            }
        }
        KeyCode::Char('/') => {
            app.focus = FocusPane::Input;
            if app.input.starts_with(':') {
                app.input.clear();
            }
        }
        KeyCode::Char(':') => {
            app.focus = FocusPane::Input;
            if !app.input.starts_with(':') {
                app.input = ":".to_string();
            }
        }
        KeyCode::Char('i') => app.focus = FocusPane::Input,
        KeyCode::Char('a') => start_pairing(app, data_dir, tx),
        KeyCode::Char('r') => {
            spawn_refresh_devices(data_dir.to_path_buf(), tx.clone());
            app.set_toast(true, "refreshing devices...");
        }
        KeyCode::Char('x') | KeyCode::Delete => prompt_revoke_selected(app, None),
        KeyCode::Esc if !app.input.is_empty() => {
            app.input.clear();
            app.sync_selection();
        }
        _ => {}
    }
}

fn start_pairing(app: &mut AppState, data_dir: &Path, tx: &mpsc::UnboundedSender<UiEvent>) {
    app.modal = Some(Modal::Pairing {
        code: None,
        setup: None,
        state: PairingState::Starting,
    });
    spawn_device_add(data_dir.to_path_buf(), tx.clone());
}

fn prompt_revoke_selected(app: &mut AppState, target: Option<&str>) {
    let peers = merge_peers(&app.status, &app.devices);
    let chosen = if let Some(t) = target {
        peers
            .into_iter()
            .find(|p| p.device_id == t || p.name.eq_ignore_ascii_case(t))
    } else {
        app.selected_peer()
    };
    let Some(peer) = chosen else {
        app.set_toast(false, "no peer selected to revoke");
        return;
    };
    if peer.account_status != "active" {
        app.set_toast(false, format!("{} is already {}", peer.name, peer.account_status));
        return;
    }
    app.modal = Some(Modal::RevokeConfirm {
        device_id: peer.device_id,
        name: peer.name,
    });
}

fn execute_parsed_command(
    app: &mut AppState,
    cmd: ParsedCommand,
    data_dir: &Path,
    tx: &mpsc::UnboundedSender<UiEvent>,
) {
    match cmd {
        ParsedCommand::Kick { announce } => {
            spawn_kick(data_dir.to_path_buf(), announce, tx.clone());
        }
        ParsedCommand::AddDevice => start_pairing(app, data_dir, tx),
        ParsedCommand::Revoke { target } => prompt_revoke_selected(app, target.as_deref()),
        ParsedCommand::Refresh => {
            spawn_refresh_devices(data_dir.to_path_buf(), tx.clone());
            app.set_toast(true, "refreshing devices...");
        }
        ParsedCommand::ToggleTheme => {
            app.theme_kind = app.theme_kind.toggle();
            app.set_toast(true, format!("theme: {}", app.theme_kind.label()));
        }
        ParsedCommand::ToggleSidebar => app.show_sidebar = !app.show_sidebar,
        ParsedCommand::ClearFilter => {
            app.input.clear();
            app.sync_selection();
        }
        ParsedCommand::Quit => app.should_quit = true,
        ParsedCommand::Help => {
            app.set_toast(
                true,
                "cmds: :kick [local], :add, :revoke [name|id], :refresh, :theme, :sidebar, :quit",
            );
        }
        ParsedCommand::Unknown(name) => {
            app.set_toast(false, format!("unknown command ':{name}' (try :help or ctrl+p)"));
        }
    }
}

fn execute_palette_action(
    app: &mut AppState,
    action: PaletteAction,
    data_dir: &Path,
    tx: &mpsc::UnboundedSender<UiEvent>,
) {
    match action {
        PaletteAction::KickAnnounce => spawn_kick(data_dir.to_path_buf(), true, tx.clone()),
        PaletteAction::KickLocal => spawn_kick(data_dir.to_path_buf(), false, tx.clone()),
        PaletteAction::AddDevice => start_pairing(app, data_dir, tx),
        PaletteAction::RevokeSelected => prompt_revoke_selected(app, None),
        PaletteAction::Refresh => {
            spawn_refresh_devices(data_dir.to_path_buf(), tx.clone());
            app.set_toast(true, "refreshing devices...");
        }
        PaletteAction::ToggleSidebar => app.show_sidebar = !app.show_sidebar,
        PaletteAction::ToggleTheme => {
            app.theme_kind = app.theme_kind.toggle();
            app.set_toast(true, format!("theme: {}", app.theme_kind.label()));
        }
        PaletteAction::ClearFilter => {
            app.input.clear();
            app.sync_selection();
        }
        PaletteAction::Quit => app.should_quit = true,
    }
}

fn filtered_palette(query: &str) -> Vec<&'static (&'static str, &'static str, PaletteAction)> {
    let q = query.trim().to_lowercase();
    PALETTE_ITEMS
        .iter()
        .filter(|(label, desc, _)| {
            q.is_empty() || label.to_lowercase().contains(&q) || desc.to_lowercase().contains(&q)
        })
        .collect()
}

pub fn draw_ui(f: &mut Frame, app: &AppState) {
    let theme = Theme::for_kind(app.theme_kind);
    let area = f.area();

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // header
            Constraint::Min(6),    // body
            Constraint::Length(3), // 3-line filter / command input box
            Constraint::Length(1), // footer
        ])
        .split(area);

    draw_header(f, rows[0], app, theme);
    draw_body(f, rows[1], app, theme);
    draw_input_box(f, rows[2], app, theme);
    draw_footer(f, rows[3], app, theme);

    if let Some(ref modal) = app.modal {
        draw_modal(f, area, modal, theme);
    }
}

fn draw_header(f: &mut Frame, area: Rect, app: &AppState, theme: Theme) {
    let st = &app.status;
    let fqdn = st
        .dns_name
        .as_deref()
        .map(|d| format!("{d}.topaz"))
        .unwrap_or_else(|| {
            if st.device_name.is_empty() {
                "-".into()
            } else {
                st.device_name.clone()
            }
        });
    let vip = st.virtual_ip.as_deref().unwrap_or("-");
    let tun = if st.tun.enabled {
        st.tun
            .interface
            .as_deref()
            .map(|i| format!("TUN:{i}"))
            .unwrap_or_else(|| "TUN:on".into())
    } else {
        "TUN:off".into()
    };
    let online_peers = st.peers.iter().filter(|p| p.path.is_some()).count();
    let total_peers = merge_peers(&app.status, &app.devices).len();
    let plugin_summary = if st.services.is_empty() {
        "plugins:none".to_string()
    } else {
        let items: Vec<String> = st
            .services
            .iter()
            .map(|s| format!("{}:{}", s.name, s.listeners))
            .collect();
        format!("plugins:{}", items.join(","))
    };

    let mut spans = vec![
        Span::styled(
            " TOPAZ ",
            Style::default()
                .fg(Color::Black)
                .bg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(fqdn, Style::default().fg(theme.fg).add_modifier(Modifier::BOLD)),
        Span::styled(format!(" ({vip}) "), Style::default().fg(theme.muted)),
        Span::styled(
            format!(" {tun} "),
            Style::default().fg(if st.tun.enabled { theme.ok } else { theme.warn }),
        ),
        Span::styled(" | ", Style::default().fg(theme.border)),
        Span::styled(
            format!("peers {online_peers}/{total_peers}"),
            Style::default().fg(theme.fg),
        ),
        Span::styled(" | ", Style::default().fg(theme.border)),
        Span::styled(plugin_summary, Style::default().fg(theme.accent)),
        Span::styled(" | ", Style::default().fg(theme.border)),
    ];

    if app.connected {
        spans.push(Span::styled(
            "● live",
            Style::default().fg(theme.ok).add_modifier(Modifier::BOLD),
        ));
    } else {
        spans.push(Span::styled(
            format!("○ {}", app.conn_detail),
            Style::default().fg(theme.bad),
        ));
    }

    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_body(f: &mut Frame, area: Rect, app: &AppState, theme: Theme) {
    if app.show_sidebar && area.width >= 68 {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(38), Constraint::Min(28)])
            .split(area);
        draw_sidebar(f, cols[0], app, theme);
        draw_main_pane(f, cols[1], app, theme);
    } else {
        draw_main_pane(f, area, app, theme);
    }
}

fn draw_sidebar(f: &mut Frame, area: Rect, app: &AppState, theme: Theme) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(6), Constraint::Min(4)])
        .split(area);

    // Local node & mounted plugins summary
    let st = &app.status;
    let id_short = if st.device_id.len() >= 8 {
        &st.device_id[..8]
    } else if st.device_id.is_empty() {
        "-"
    } else {
        &st.device_id
    };
    let vip = st.virtual_ip.as_deref().unwrap_or("-");
    let local_svcs = if st.services.is_empty() {
        Line::from(vec![
            Span::styled(" plugins: ", Style::default().fg(theme.muted)),
            Span::styled("none mounted", Style::default().fg(theme.muted)),
        ])
    } else {
        let list: Vec<String> = st
            .services
            .iter()
            .map(|s| format!("{}({})", s.name, s.listeners))
            .collect();
        Line::from(vec![
            Span::styled(" plugins: ", Style::default().fg(theme.muted)),
            Span::styled(list.join(", "), Style::default().fg(theme.ok)),
        ])
    };
    let local_lines = vec![
        Line::from(vec![
            Span::styled(" id: ", Style::default().fg(theme.muted)),
            Span::styled(id_short, Style::default().fg(theme.fg)),
            Span::styled(format!("  ip: {vip}"), Style::default().fg(theme.accent)),
        ]),
        Line::from(vec![
            Span::styled(" net: ", Style::default().fg(theme.muted)),
            Span::styled(
                if st.tun.enabled {
                    st.tun.cidr.clone()
                } else {
                    "bridge-only (--no-tun)".into()
                },
                Style::default().fg(theme.fg),
            ),
        ]),
        local_svcs,
    ];
    let local_block = Block::default()
        .title(" Local Node ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border));
    f.render_widget(Paragraph::new(local_lines).block(local_block), chunks[0]);

    // Peer / device list
    let peers = app.filtered_peers();
    let list_border = if app.focus == FocusPane::Peers {
        theme.accent
    } else {
        theme.border
    };
    let title = match app.active_filter() {
        Some(q) => format!(" Devices [/{q}] ({}) ", peers.len()),
        None => format!(" Devices ({}) ", peers.len()),
    };

    let items: Vec<ListItem> = if peers.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "  (no matching devices)",
            Style::default().fg(theme.muted),
        )))]
    } else {
        peers
            .iter()
            .map(|p| {
                let (dot, dot_color) = if p.account_status != "active" {
                    ("×", theme.bad)
                } else if p.path.as_deref() == Some("direct") {
                    ("●", theme.ok)
                } else if p.path.is_some() {
                    ("◐", theme.warn)
                } else {
                    ("○", theme.muted)
                };
                let vip = p.virtual_ip.as_deref().unwrap_or("-");
                let rtt = p
                    .rtt_ms
                    .map(|ms| format!("{ms}ms"))
                    .unwrap_or_else(|| "-".into());
                let plugin_tag = if p.services.is_empty() {
                    String::new()
                } else {
                    let names: Vec<&str> = p.services.iter().map(|s| s.name.as_str()).collect();
                    format!(" [{}]", names.join(","))
                };

                ListItem::new(vec![
                    Line::from(vec![
                        Span::styled(format!("{dot} "), Style::default().fg(dot_color)),
                        Span::styled(
                            p.name.clone(),
                            Style::default().fg(theme.fg).add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(plugin_tag, Style::default().fg(theme.accent)),
                    ]),
                    Line::from(vec![
                        Span::styled(format!("  {vip:<12} "), Style::default().fg(theme.muted)),
                        Span::styled(
                            format!(
                                "{} {rtt}",
                                p.path
                                    .as_deref()
                                    .unwrap_or(p.account_status.as_str())
                            ),
                            Style::default().fg(dot_color),
                        ),
                    ]),
                ])
            })
            .collect()
    };

    let mut list_state = ListState::default();
    if !peers.is_empty() {
        list_state.select(Some(app.selected_idx.min(peers.len() - 1)));
    }
    let list = List::new(items)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(list_border)),
        )
        .highlight_style(Style::default().bg(theme.selection));
    f.render_stateful_widget(list, chunks[1], &mut list_state);
}

fn draw_main_pane(f: &mut Frame, area: Rect, app: &AppState, theme: Theme) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(8)])
        .split(area);

    // Top: Selected Peer & Remote Services + Local Bridge Summary
    let detail_block = Block::default()
        .title(" Mesh & Service Inspection ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border));

    let mut lines: Vec<Line> = Vec::new();
    if let Some(peer) = app.selected_peer() {
        let fqdn = peer
            .dns_name
            .as_deref()
            .map(|d| format!("{d}.topaz"))
            .unwrap_or_else(|| "-".into());
        let vip = peer.virtual_ip.as_deref().unwrap_or("-").to_string();
        let path_str = peer
            .path
            .as_deref()
            .unwrap_or("offline (no active session)")
            .to_string();
        let rtt_str = peer
            .rtt_ms
            .map(|m| format!("{m} ms"))
            .unwrap_or_else(|| "-".into());
        let path_color = match peer.path.as_deref() {
            Some("direct") => theme.ok,
            Some(_) => theme.warn,
            None => theme.muted,
        };

        lines.push(Line::from(vec![
            Span::styled("Peer:        ", Style::default().fg(theme.muted)),
            Span::styled(
                peer.name.clone(),
                Style::default().fg(theme.fg).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  [{}]", peer.account_status),
                Style::default().fg(if peer.account_status == "active" {
                    theme.ok
                } else {
                    theme.bad
                }),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Device ID:   ", Style::default().fg(theme.muted)),
            Span::styled(peer.device_id.clone(), Style::default().fg(theme.fg)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Address:     ", Style::default().fg(theme.muted)),
            Span::styled(vip, Style::default().fg(theme.accent)),
            Span::styled("   DNS: ", Style::default().fg(theme.muted)),
            Span::styled(fqdn, Style::default().fg(theme.fg)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Session:     ", Style::default().fg(theme.muted)),
            Span::styled(path_str, Style::default().fg(path_color)),
            Span::styled(format!("   RTT: {rtt_str}"), Style::default().fg(theme.fg)),
        ]));
        if let Some(issuer) = peer.issuer {
            lines.push(Line::from(vec![
                Span::styled("Issued By:   ", Style::default().fg(theme.muted)),
                Span::styled(issuer, Style::default().fg(theme.muted)),
            ]));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Remote Mounted Plugins (discovered via service 4):",
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )));
        if peer.services.is_empty() {
            // Offline and "online but nothing mounted" are different states;
            // do not tell the user a live VPN-only node is "not running".
            let message = if peer.path.is_none() {
                "  (offline — no live session, services unknown)"
            } else {
                "  (online — no plugins advertised)"
            };
            lines.push(Line::from(Span::styled(
                message,
                Style::default().fg(theme.muted),
            )));
        } else {
            for svc in &peer.services {
                lines.push(Line::from(vec![
                    Span::styled("  ● ", Style::default().fg(theme.ok)),
                    Span::styled(
                        format!("service {} ({})", svc.service_id, svc.name),
                        Style::default().fg(theme.fg),
                    ),
                    Span::styled(
                        " — ready for /v1/services/.../open",
                        Style::default().fg(theme.muted),
                    ),
                ]));
            }
        }
    } else {
        lines.push(Line::from(Span::styled(
            "No remote peers in account yet. Press `a` or type `:add` to generate a pairing code.",
            Style::default().fg(theme.muted),
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Local Control Bridge & TUN:",
        Style::default()
            .fg(theme.accent)
            .add_modifier(Modifier::BOLD),
    )));
    let tun_line = if app.status.tun.enabled {
        format!(
            "  interface={}  cidr={}  mtu={}  dns={}",
            app.status.tun.interface.as_deref().unwrap_or("-"),
            app.status.tun.cidr,
            app.status.tun.mtu,
            app.status.tun.dns_listen.as_deref().unwrap_or("-")
        )
    } else {
        "  TUN disabled (--no-tun); control.sock service bridge active".to_string()
    };
    lines.push(Line::from(Span::styled(
        tun_line,
        Style::default().fg(theme.fg),
    )));
    if app.status.services.is_empty() {
        lines.push(Line::from(Span::styled(
            "  local services: none (start `jade serve` to attach service 16)",
            Style::default().fg(theme.muted),
        )));
    } else {
        for s in &app.status.services {
            lines.push(Line::from(vec![
                Span::styled(
                    if s.online { "  ● " } else { "  ○ " },
                    Style::default().fg(if s.online { theme.ok } else { theme.muted }),
                ),
                Span::styled(
                    format!(
                        "local service {} ({}) — {} idle accept listeners",
                        s.service_id, s.name, s.listeners
                    ),
                    Style::default().fg(theme.fg),
                ),
            ]));
        }
    }

    f.render_widget(
        Paragraph::new(lines)
            .block(detail_block)
            .wrap(Wrap { trim: false }),
        chunks[0],
    );

    // Bottom: Activity feed
    let max_lines = chunks[1].height.saturating_sub(2) as usize;
    let start = app.activity.len().saturating_sub(max_lines);
    let log_lines: Vec<Line> = app.activity[start..]
        .iter()
        .map(|s| Line::from(Span::styled(format!("  {s}"), Style::default().fg(theme.muted))))
        .collect();
    let log_block = Block::default()
        .title(" Events & Activity ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border));
    f.render_widget(Paragraph::new(log_lines).block(log_block), chunks[1]);
}

fn draw_input_box(f: &mut Frame, area: Rect, app: &AppState, theme: Theme) {
    let focused = app.focus == FocusPane::Input && app.modal.is_none();
    let border_color = if focused { theme.accent } else { theme.border };
    let title = if app.input.starts_with(':') {
        " Command (:kick [local], :add, :revoke [target], :theme, :quit) "
    } else {
        " Filter / Command (type to filter peers, or :command) "
    };
    let display = if app.input.is_empty() && !focused {
        Span::styled(
            "Press `/` to filter devices or `:` to run a command...",
            Style::default().fg(theme.muted),
        )
    } else {
        Span::styled(app.input.clone(), Style::default().fg(theme.fg))
    };
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));
    f.render_widget(Paragraph::new(Line::from(display)).block(block), area);

    if focused {
        let cursor_x = (area.x + 1 + app.input.chars().count() as u16)
            .min(area.x + area.width.saturating_sub(2));
        f.set_cursor_position((cursor_x, area.y + 1));
    }
}

fn draw_footer(f: &mut Frame, area: Rect, app: &AppState, theme: Theme) {
    let leader_hint = if app.leader_until.is_some() {
        Span::styled(
            " LEADER (q quit · b sidebar · t theme · k kick · a add · p palette) ",
            Style::default()
                .fg(Color::Black)
                .bg(theme.warn)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            " ctrl+p commands · ctrl+x leader · tab focus · j/k nav · a add · K kick · x revoke · q quit ",
            Style::default().fg(theme.muted),
        )
    };

    if let Some((ref msg, ok, _)) = app.toast {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(20), Constraint::Length((msg.len() + 4) as u16)])
            .split(area);
        f.render_widget(Paragraph::new(Line::from(leader_hint)), cols[0]);
        let toast_p = Paragraph::new(Line::from(Span::styled(
            format!(" {msg} "),
            Style::default()
                .fg(if ok { theme.ok } else { theme.bad })
                .add_modifier(Modifier::BOLD),
        )))
        .alignment(Alignment::Right);
        f.render_widget(toast_p, cols[1]);
    } else {
        f.render_widget(Paragraph::new(Line::from(leader_hint)), area);
    }
}

fn draw_modal(f: &mut Frame, area: Rect, modal: &Modal, theme: Theme) {
    match modal {
        Modal::Palette { query, selected } => {
            let popup = centered_rect(64, 15, area);
            f.render_widget(Clear, popup);
            let block = Block::default()
                .title(" Command Palette (Enter run · Esc close) ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.accent))
                .style(Style::default().bg(theme.modal_bg));
            let inner = block.inner(popup);
            f.render_widget(block, popup);

            let parts = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(2), Constraint::Min(3)])
                .split(inner);

            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled("> ", Style::default().fg(theme.accent)),
                    Span::styled(query.clone(), Style::default().fg(theme.fg)),
                ])),
                parts[0],
            );

            let matches = filtered_palette(query);
            let items: Vec<ListItem> = matches
                .iter()
                .map(|(label, desc, _)| {
                    ListItem::new(Line::from(vec![
                        Span::styled(
                            format!(" {label:<26} "),
                            Style::default().fg(theme.fg).add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(*desc, Style::default().fg(theme.muted)),
                    ]))
                })
                .collect();
            let mut state = ListState::default();
            if !matches.is_empty() {
                state.select(Some((*selected).min(matches.len() - 1)));
            }
            f.render_stateful_widget(
                List::new(items).highlight_style(Style::default().bg(theme.selection)),
                parts[1],
                &mut state,
            );
        }
        Modal::Pairing { code, setup, state } => {
            let popup = centered_rect(76, 13, area);
            f.render_widget(Clear, popup);
            let block = Block::default()
                .title(" Add Device / Pairing (Esc or Enter to close) ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.accent))
                .style(Style::default().bg(theme.modal_bg));

            let mut lines = Vec::new();
            match state {
                PairingState::Starting => {
                    lines.push(Line::from(Span::styled(
                        "Requesting one-time pairing code from coord...",
                        Style::default().fg(theme.warn),
                    )));
                }
                PairingState::Waiting => {
                    lines.push(Line::from(vec![
                        Span::styled("Pairing Code: ", Style::default().fg(theme.muted)),
                        Span::styled(
                            code.as_deref().unwrap_or("?"),
                            Style::default().fg(theme.ok).add_modifier(Modifier::BOLD),
                        ),
                    ]));
                    lines.push(Line::from(""));
                    lines.push(Line::from(Span::styled(
                        "On the new device, run:",
                        Style::default().fg(theme.muted),
                    )));
                    lines.push(Line::from(Span::styled(
                        format!("  topaz setup '{}'", setup.as_deref().unwrap_or("")),
                        Style::default().fg(theme.fg),
                    )));
                    lines.push(Line::from(""));
                    lines.push(Line::from(Span::styled(
                        "Waiting up to 5 minutes for the new device to join...",
                        Style::default().fg(theme.warn),
                    )));
                }
                PairingState::Added { name, device_id } => {
                    lines.push(Line::from(Span::styled(
                        format!("Device joined: {name} ({device_id})"),
                        Style::default().fg(theme.ok).add_modifier(Modifier::BOLD),
                    )));
                    lines.push(Line::from(""));
                    lines.push(Line::from(Span::styled(
                        "Press Esc or Enter to return.",
                        Style::default().fg(theme.muted),
                    )));
                }
                PairingState::Failed(err) => {
                    lines.push(Line::from(Span::styled(
                        format!("Pairing failed: {err}"),
                        Style::default().fg(theme.bad),
                    )));
                }
            }
            f.render_widget(
                Paragraph::new(lines).block(block).wrap(Wrap { trim: false }),
                popup,
            );
        }
        Modal::RevokeConfirm { device_id, name } => {
            let popup = centered_rect(58, 7, area);
            f.render_widget(Clear, popup);
            let block = Block::default()
                .title(" Confirm Device Revocation ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.bad))
                .style(Style::default().bg(theme.modal_bg));
            let lines = vec![
                Line::from(vec![
                    Span::styled("Revoke certificate for ", Style::default().fg(theme.fg)),
                    Span::styled(
                        format!("{name} ({device_id})"),
                        Style::default().fg(theme.bad).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("?", Style::default().fg(theme.fg)),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    "Press `y` / `Enter` to confirm, or `n` / `Esc` to cancel.",
                    Style::default().fg(theme.muted),
                )),
            ];
            f.render_widget(
                Paragraph::new(lines).block(block).wrap(Wrap { trim: false }),
                popup,
            );
        }
    }
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let w = width.min(area.width.saturating_sub(2)).max(20);
    let h = height.min(area.height.saturating_sub(2)).max(5);
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    Rect::new(x, y, w, h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    fn sample_status() -> StatusSnapshot {
        serde_json::from_value(serde_json::json!({
            "account": "acct_123",
            "device_id": "aaaa111122223333",
            "device_name": "workstation",
            "dns_name": "workstation",
            "virtual_ip": "100.64.0.1",
            "tun": {
                "enabled": true,
                "interface": "topaz0",
                "cidr": "100.64.0.0/10",
                "mtu": 1380,
                "dns_listen": "127.0.0.1:5353"
            },
            "connection": "direct",
            "peers": [
                {
                    "device_id": "bbbb444455556666",
                    "name": "laptop",
                    "dns_name": "laptop",
                    "virtual_ip": "100.64.0.2",
                    "path": "direct",
                    "rtt_ms": 14,
                    "services": [
                        { "service_id": 16, "name": "jade" }
                    ]
                }
            ],
            "services": [
                {
                    "service_id": 16,
                    "name": "jade",
                    "online": true,
                    "listeners": 2
                }
            ]
        }))
        .unwrap()
    }

    #[test]
    fn merges_live_peers_and_offline_devices_with_filter() {
        let status = sample_status();
        let devices = vec![
            DeviceRow {
                device_id: "aaaa111122223333".into(),
                name: "workstation".into(),
                dns_name: Some("workstation".into()),
                virtual_ip: Some("100.64.0.1".into()),
                status: "active".into(),
                issuer: "recovery code".into(),
                me: true,
            },
            DeviceRow {
                device_id: "bbbb444455556666".into(),
                name: "laptop".into(),
                dns_name: Some("laptop".into()),
                virtual_ip: Some("100.64.0.2".into()),
                status: "active".into(),
                issuer: "aaaa111122223333".into(),
                me: false,
            },
            DeviceRow {
                device_id: "cccc777788889999".into(),
                name: "nas".into(),
                dns_name: Some("nas".into()),
                virtual_ip: Some("100.64.0.3".into()),
                status: "active".into(),
                issuer: "aaaa111122223333".into(),
                me: false,
            },
        ];

        let mut app = AppState::new(ThemeKind::OpenCode);
        app.connected = true;
        app.status = status;
        app.devices = devices;
        app.sync_selection();

        let all = app.filtered_peers();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].name, "laptop");
        assert_eq!(all[0].services[0].name, "jade");
        assert_eq!(all[1].name, "nas");
        assert!(all[1].path.is_none());

        app.input = "/jade".into();
        let by_plugin = app.filtered_peers();
        assert_eq!(by_plugin.len(), 1);
        assert_eq!(by_plugin[0].name, "laptop");
    }

    #[test]
    fn parses_bottom_input_commands() {
        assert_eq!(parse_command(":kick"), Some(ParsedCommand::Kick { announce: true }));
        assert_eq!(
            parse_command(":kick local"),
            Some(ParsedCommand::Kick { announce: false })
        );
        assert_eq!(parse_command(":add"), Some(ParsedCommand::AddDevice));
        assert_eq!(
            parse_command(":revoke laptop"),
            Some(ParsedCommand::Revoke {
                target: Some("laptop".into())
            })
        );
        assert_eq!(parse_command(":theme"), Some(ParsedCommand::ToggleTheme));
        assert_eq!(parse_command(":q"), Some(ParsedCommand::Quit));
        assert_eq!(parse_command("/laptop"), None);
    }

    #[test]
    fn renders_opencode_layout_with_plugin_badges() {
        let mut app = AppState::new(ThemeKind::OpenCode);
        app.connected = true;
        app.conn_detail = "live ws".into();
        app.status = sample_status();
        app.sync_selection();

        let backend = TestBackend::new(110, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| draw_ui(f, &app)).unwrap();

        let buf = terminal.backend().buffer();
        let mut rendered = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                rendered.push_str(buf[(x, y)].symbol());
            }
            rendered.push('\n');
        }
        assert!(rendered.contains("TOPAZ"));
        assert!(rendered.contains("workstation.topaz"));
        assert!(rendered.contains("laptop"));
        assert!(rendered.contains("[jade]"));
        assert!(rendered.contains("service 16 (jade)"));
        assert!(rendered.contains("Filter / Command"));
    }
}
