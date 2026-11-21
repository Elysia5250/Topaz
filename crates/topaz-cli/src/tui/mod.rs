//! Jade-aligned Terminal UI (`topaz tui`) connected to the running daemon over
//! `control.sock`.
//!
//! Pure client: closing `topaz tui` or its terminal never stops `topaz run`.

mod clipboard;
mod prefs;
mod terminal;
pub mod theme;
mod view;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Result;
use futures::StreamExt;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::client::ControlClient;
use crate::ops::DeviceRow;
use prefs::ConsolePrefs;
use terminal::TerminalGuard;
pub use theme::ThemeKind;

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
pub(super) enum PaletteAction {
    KickAnnounce,
    KickLocal,
    AddDevice,
    CopyPeerAddr,
    RevokeSelected,
    Refresh,
    ToggleSidebar,
    CycleTheme,
    ClearFilter,
    StopDaemon,
    Quit,
}

const PALETTE_ITEMS: &[(&str, &str, PaletteAction)] = &[
    ("Kick peers (announce)", "Probe peers and broadcast endpoints", PaletteAction::KickAnnounce),
    ("Kick peers (local only)", "Probe peers without announcing", PaletteAction::KickLocal),
    ("Add new device", "Generate one-time pairing code & setup bundle", PaletteAction::AddDevice),
    ("Copy peer address", "Copy selected peer's .topaz DNS or virtual IP", PaletteAction::CopyPeerAddr),
    ("Revoke selected device", "Revoke cert for highlighted peer", PaletteAction::RevokeSelected),
    ("Refresh devices", "Fetch latest /v1/devices and /v1/status", PaletteAction::Refresh),
    ("Toggle sidebar", "Show or hide device list (Ctrl+B / Ctrl+X b)", PaletteAction::ToggleSidebar),
    ("Cycle color theme", "Switch ink / tokyonight / light (Ctrl+X t)", PaletteAction::CycleTheme),
    ("Clear peer filter", "Reset bottom filter input", PaletteAction::ClearFilter),
    ("Stop daemon", "Shut down background topaz run cleanly", PaletteAction::StopDaemon),
    ("Quit TUI", "Exit UI (daemon keeps running)", PaletteAction::Quit),
];

#[derive(Debug)]
enum UiEvent {
    Key(KeyEvent),
    Resize,
    WsConnected,
    WsDisconnected(String),
    StatusUpdated(Box<StatusSnapshot>),
    DevicesUpdated(Vec<DeviceRow>),
    ActionResult { ok: bool, message: String },
    PairingCode { code: String, setup: String },
    PairingFinished(std::result::Result<(String, String), String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputCommand {
    Kick { announce: bool },
    Add,
    Revoke { target: Option<String> },
    Copy,
    Refresh,
    ToggleSidebar,
    Theme { name: Option<String> },
    StopDaemon,
    Quit,
    Help,
}

pub fn parse_input_command(raw: &str) -> std::result::Result<InputCommand, String> {
    let trimmed = raw.trim().strip_prefix(':').unwrap_or(raw.trim()).trim();
    let mut parts = trimmed.split_whitespace();
    let Some(cmd) = parts.next() else {
        return Err("empty command".into());
    };
    match cmd.to_ascii_lowercase().as_str() {
        "k" | "kick" => {
            let local = parts.next().is_some_and(|a| a == "local" || a == "--local");
            Ok(InputCommand::Kick { announce: !local })
        }
        "a" | "add" | "pair" => Ok(InputCommand::Add),
        "r" | "revoke" => Ok(InputCommand::Revoke {
            target: parts.next().map(|s| s.to_string()),
        }),
        "c" | "y" | "copy" => Ok(InputCommand::Copy),
        "refresh" | "reload" => Ok(InputCommand::Refresh),
        "sidebar" | "b" | "panel" => Ok(InputCommand::ToggleSidebar),
        "theme" => Ok(InputCommand::Theme {
            name: parts.next().map(|s| s.to_string()),
        }),
        "stop" => Ok(InputCommand::StopDaemon),
        "q" | "quit" | "exit" => Ok(InputCommand::Quit),
        "h" | "help" | "?" => Ok(InputCommand::Help),
        other => Err(format!(
            "unknown command ':{other}' (try :kick, :add, :revoke, :copy, :theme, :stop, :quit)"
        )),
    }
}

/// Merge live `/v1/status` peers with `/v1/devices` (including offline/revoked)
/// and filter by `query` (case-insensitive match on name, dns_name, IP, ID, or plugin name).
pub fn merge_peers(
    status: &StatusSnapshot,
    devices: &[DeviceRow],
    filter: &str,
) -> Vec<MergedPeer> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for d in devices {
        if d.me {
            continue;
        }
        seen.insert(d.device_id.clone());
        let live = status.peers.iter().find(|p| p.device_id == d.device_id);
        out.push(MergedPeer {
            device_id: d.device_id.clone(),
            name: live.map(|p| p.name.clone()).unwrap_or_else(|| d.name.clone()),
            dns_name: live
                .and_then(|p| p.dns_name.clone())
                .or_else(|| d.dns_name.clone()),
            virtual_ip: live
                .and_then(|p| p.virtual_ip.clone())
                .or_else(|| d.virtual_ip.clone()),
            path: live.and_then(|p| p.path.clone()),
            rtt_ms: live.and_then(|p| p.rtt_ms),
            account_status: d.status.clone(),
            issuer: Some(d.issuer.clone()),
            services: live.map(|p| p.services.clone()).unwrap_or_default(),
        });
    }

    for p in &status.peers {
        if seen.insert(p.device_id.clone()) {
            out.push(MergedPeer {
                device_id: p.device_id.clone(),
                name: p.name.clone(),
                dns_name: p.dns_name.clone(),
                virtual_ip: p.virtual_ip.clone(),
                path: p.path.clone(),
                rtt_ms: p.rtt_ms,
                account_status: "active".into(),
                issuer: None,
                services: p.services.clone(),
            });
        }
    }

    out.sort_by(|a, b| {
        let a_rank = match (a.account_status == "active", a.path.is_some()) {
            (true, true) => 0u8,
            (true, false) => 1u8,
            (false, _) => 2u8,
        };
        let b_rank = match (b.account_status == "active", b.path.is_some()) {
            (true, true) => 0u8,
            (true, false) => 1u8,
            (false, _) => 2u8,
        };
        a_rank
            .cmp(&b_rank)
            .then_with(|| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()))
            .then_with(|| a.device_id.cmp(&b.device_id))
    });

    let q = filter.trim().to_ascii_lowercase();
    if q.is_empty() {
        return out;
    }
    out.into_iter()
        .filter(|p| {
            p.name.to_ascii_lowercase().contains(&q)
                || p.device_id.to_ascii_lowercase().contains(&q)
                || p.dns_name
                    .as_deref()
                    .is_some_and(|d| d.to_ascii_lowercase().contains(&q))
                || p.virtual_ip
                    .as_deref()
                    .is_some_and(|ip| ip.to_ascii_lowercase().contains(&q))
                || p.services
                    .iter()
                    .any(|s| s.name.to_ascii_lowercase().contains(&q))
        })
        .collect()
}

pub struct AppState {
    pub theme: ThemeKind,
    pub sidebar_visible: bool,
    pub focus: FocusPane,
    pub input: String,
    pub status: StatusSnapshot,
    pub devices: Vec<DeviceRow>,
    pub ws_connected: bool,
    pub selected_idx: usize,
    pub selected_id: Option<String>,
    pub modal: Option<Modal>,
    pub leader_until: Option<Instant>,
    pub toast: Option<(String, bool, Instant)>,
    pub activity: Vec<String>,
    pub should_quit: bool,
}

impl AppState {
    pub fn new(theme: ThemeKind, sidebar_visible: bool) -> Self {
        Self {
            theme,
            sidebar_visible,
            focus: FocusPane::Peers,
            input: String::new(),
            status: StatusSnapshot::default(),
            devices: Vec::new(),
            ws_connected: false,
            selected_idx: 0,
            selected_id: None,
            modal: None,
            leader_until: None,
            toast: None,
            activity: vec!["Connecting to local control.sock…".into()],
            should_quit: false,
        }
    }

    pub fn filter_query(&self) -> &str {
        if self.input.starts_with(':') {
            ""
        } else {
            self.input.trim()
        }
    }

    pub fn filtered_peers(&self) -> Vec<MergedPeer> {
        merge_peers(&self.status, &self.devices, self.filter_query())
    }

    pub fn selected_peer(&self) -> Option<MergedPeer> {
        let peers = self.filtered_peers();
        if peers.is_empty() {
            return None;
        }
        let idx = self.selected_idx.min(peers.len() - 1);
        peers.into_iter().nth(idx)
    }

    pub fn reconcile_selection(&mut self) {
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

    fn save_prefs(&self, data_dir: &Path) {
        prefs::save(
            data_dir,
            &ConsolePrefs {
                theme: self.theme.label().to_string(),
                show_sidebar: self.sidebar_visible,
            },
        );
    }
}

pub async fn cmd_tui(data_dir: PathBuf, theme_override: Option<&str>) -> Result<()> {
    let saved = prefs::load(&data_dir);
    let theme = match theme_override {
        Some(name) => ThemeKind::from_name(name),
        None => ThemeKind::from_name(&saved.theme),
    };
    let mut guard = TerminalGuard::enter()?;
    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel::<UiEvent>();

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(events_loop(data_dir.clone(), ev_tx.clone(), shutdown_rx.clone()));
    tokio::spawn(devices_poll_loop(data_dir.clone(), ev_tx.clone(), shutdown_rx.clone()));
    spawn_input_reader(ev_tx.clone(), shutdown_rx);

    let mut app = AppState::new(theme, saved.show_sidebar);
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        guard.terminal.draw(|f| view::draw_ui(f, &app))?;
        if app.should_quit {
            break;
        }

        tokio::select! {
            Some(ev) = ev_rx.recv() => {
                process_event(&mut app, ev, &data_dir, &ev_tx);
                while let Ok(more) = ev_rx.try_recv() {
                    process_event(&mut app, more, &data_dir, &ev_tx);
                    if app.should_quit {
                        break;
                    }
                }
            }
            _ = tick.tick() => {}
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
    }

    let _ = shutdown_tx.send(true);
    Ok(())
}

fn spawn_input_reader(
    tx: mpsc::UnboundedSender<UiEvent>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) {
    std::thread::spawn(move || loop {
        if *shutdown.borrow() {
            break;
        }
        match event::poll(Duration::from_millis(120)) {
            Ok(true) => match event::read() {
                Ok(Event::Key(key))
                    if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) =>
                {
                    if tx.send(UiEvent::Key(key)).is_err() {
                        break;
                    }
                }
                Ok(Event::Resize(_, _)) => {
                    if tx.send(UiEvent::Resize).is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            },
            Ok(false) => {}
            Err(_) => break,
        }
    });
}

fn process_event(
    app: &mut AppState,
    ev: UiEvent,
    data_dir: &Path,
    ev_tx: &mpsc::UnboundedSender<UiEvent>,
) {
    match ev {
        UiEvent::Key(key) => handle_key(app, key, data_dir, ev_tx),
        UiEvent::Resize => {}
        other => handle_ui_event(app, other),
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
                let _ = tx.send(UiEvent::WsDisconnected(
                    "waiting for daemon (`topaz run --detach`)".into(),
                ));
            }
        }
        tokio::select! {
            _ = shutdown.changed() => return,
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
        if *shutdown.borrow() {
            break;
        }
        spawn_refresh_devices(data_dir.clone(), tx.clone());
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = tokio::time::sleep(Duration::from_secs(10)) => {}
        }
    }
}

fn spawn_refresh_devices(data_dir: PathBuf, tx: mpsc::UnboundedSender<UiEvent>) {
    tokio::spawn(async move {
        let client = ControlClient::new(&data_dir);
        if let Ok(v) = client.get("/v1/devices").await {
            if let Some(arr) = v.get("devices").cloned() {
                if let Ok(rows) = serde_json::from_value::<Vec<DeviceRow>>(arr) {
                    let _ = tx.send(UiEvent::DevicesUpdated(rows));
                }
            }
        }
    });
}

fn spawn_kick(data_dir: PathBuf, announce: bool, tx: mpsc::UnboundedSender<UiEvent>) {
    tokio::spawn(async move {
        let client = ControlClient::new(&data_dir);
        let path = format!("/v1/kick?announce={announce}");
        let res = client.post(&path, None).await;
        let _ = tx.send(match res {
            Ok(_) => UiEvent::ActionResult {
                ok: true,
                message: if announce {
                    "Kicked peers (announce)".into()
                } else {
                    "Kicked peers (local)".into()
                },
            },
            Err(e) => UiEvent::ActionResult {
                ok: false,
                message: format!("Kick failed: {e}"),
            },
        });
    });
}

fn spawn_stop_daemon(data_dir: PathBuf, tx: mpsc::UnboundedSender<UiEvent>) {
    tokio::spawn(async move {
        let client = ControlClient::new(&data_dir);
        let res = client.post("/v1/shutdown", None).await;
        let _ = tx.send(match res {
            Ok(_) => UiEvent::ActionResult {
                ok: true,
                message: "Daemon shutdown requested".into(),
            },
            Err(e) => UiEvent::ActionResult {
                ok: false,
                message: format!("Stop failed: {e}"),
            },
        });
    });
}

fn spawn_add_device(data_dir: PathBuf, tx: mpsc::UnboundedSender<UiEvent>) {
    tokio::spawn(async move {
        let client = ControlClient::new(&data_dir);
        match client.post("/v1/devices/add", None).await {
            Ok(v) => {
                let code = v["code"].as_str().unwrap_or_default().to_string();
                let setup = v["setup"].as_str().unwrap_or_default().to_string();
                let _ = tx.send(UiEvent::PairingCode {
                    code: code.clone(),
                    setup,
                });
                let poll_res = client
                    .get_with_timeout(&format!("/v1/devices/add/{code}"), Duration::from_secs(330))
                    .await;
                match poll_res {
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

fn spawn_revoke(data_dir: PathBuf, device_id: String, name: String, tx: mpsc::UnboundedSender<UiEvent>) {
    tokio::spawn(async move {
        let client = ControlClient::new(&data_dir);
        let res = client
            .post(&format!("/v1/devices/{device_id}/revoke"), None)
            .await;
        match res {
            Ok(_) => {
                let _ = tx.send(UiEvent::ActionResult {
                    ok: true,
                    message: format!("Revoked {name} ({device_id})"),
                });
                spawn_refresh_devices(data_dir, tx);
            }
            Err(e) => {
                let _ = tx.send(UiEvent::ActionResult {
                    ok: false,
                    message: format!("Revoke failed: {e}"),
                });
            }
        }
    });
}

fn handle_ui_event(app: &mut AppState, ev: UiEvent) {
    match ev {
        UiEvent::WsConnected => {
            if !app.ws_connected {
                app.push_activity("Connected to control.sock /v1/events");
            }
            app.ws_connected = true;
        }
        UiEvent::WsDisconnected(reason) => {
            if app.ws_connected {
                app.push_activity(format!("Disconnected: {reason}"));
            }
            app.ws_connected = false;
        }
        UiEvent::StatusUpdated(next) => {
            app.status = *next;
            app.reconcile_selection();
        }
        UiEvent::DevicesUpdated(rows) => {
            app.devices = rows;
            app.reconcile_selection();
        }
        UiEvent::ActionResult { ok, message } => {
            app.set_toast(ok, message);
        }
        UiEvent::PairingCode { code, setup } => {
            app.push_activity(format!("Pairing code ready: {code}"));
            app.modal = Some(Modal::Pairing {
                code: Some(code),
                setup: Some(setup),
                state: PairingState::Waiting,
            });
        }
        UiEvent::PairingFinished(res) => match res {
            Ok((name, device_id)) => {
                app.set_toast(true, format!("Added device {name} ({device_id})"));
                if let Some(Modal::Pairing { state, .. }) = &mut app.modal {
                    *state = PairingState::Added { name, device_id };
                }
            }
            Err(err) => {
                app.set_toast(false, format!("Pairing failed: {err}"));
                if let Some(Modal::Pairing { state, .. }) = &mut app.modal {
                    *state = PairingState::Failed(err);
                }
            }
        },
        UiEvent::Key(_) | UiEvent::Resize => {}
    }
}

fn handle_key(
    app: &mut AppState,
    key: KeyEvent,
    data_dir: &Path,
    ev_tx: &mpsc::UnboundedSender<UiEvent>,
) {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        app.should_quit = true;
        return;
    }

    if app.modal.is_some() {
        handle_modal_key(app, key, data_dir, ev_tx);
        return;
    }

    if app.leader_until.is_some() {
        app.leader_until = None;
        match key.code {
            KeyCode::Char('q') => app.should_quit = true,
            KeyCode::Char('b') => {
                app.sidebar_visible = !app.sidebar_visible;
                app.save_prefs(data_dir);
            }
            KeyCode::Char('t') => {
                app.theme = app.theme.cycle();
                app.save_prefs(data_dir);
                app.set_toast(true, format!("Theme: {}", app.theme.label()));
            }
            KeyCode::Char('k') => spawn_kick(data_dir.to_path_buf(), true, ev_tx.clone()),
            KeyCode::Char('a') => start_pairing(app, data_dir, ev_tx),
            KeyCode::Char('p') => open_palette(app),
            _ => {}
        }
        return;
    }

    if key.modifiers.contains(KeyModifiers::CONTROL) {
        match key.code {
            KeyCode::Char('p') => {
                open_palette(app);
                return;
            }
            KeyCode::Char('b') => {
                app.sidebar_visible = !app.sidebar_visible;
                app.save_prefs(data_dir);
                return;
            }
            KeyCode::Char('x') => {
                app.leader_until = Some(Instant::now() + Duration::from_secs(2));
                return;
            }
            _ => {}
        }
    }

    if key.code == KeyCode::Tab {
        app.focus = match app.focus {
            FocusPane::Peers => FocusPane::Input,
            FocusPane::Input => FocusPane::Peers,
        };
        return;
    }

    match app.focus {
        FocusPane::Input => handle_input_key(app, key, data_dir, ev_tx),
        FocusPane::Peers => handle_peers_key(app, key, data_dir, ev_tx),
    }
}

fn handle_peers_key(
    app: &mut AppState,
    key: KeyEvent,
    data_dir: &Path,
    ev_tx: &mpsc::UnboundedSender<UiEvent>,
) {
    match key.code {
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Down | KeyCode::Char('j') => app.move_selection(1),
        KeyCode::Up | KeyCode::Char('k') => app.move_selection(-1),
        KeyCode::Char('g') => app.move_selection(-10_000),
        KeyCode::Char('G') => app.move_selection(10_000),
        KeyCode::Char('b') => {
            app.sidebar_visible = !app.sidebar_visible;
            app.save_prefs(data_dir);
        }
        KeyCode::Char('t') => {
            app.theme = app.theme.cycle();
            app.save_prefs(data_dir);
            app.set_toast(true, format!("Theme: {}", app.theme.label()));
        }
        KeyCode::Char('K') => spawn_kick(data_dir.to_path_buf(), true, ev_tx.clone()),
        KeyCode::Char('r') => {
            spawn_refresh_devices(data_dir.to_path_buf(), ev_tx.clone());
            app.set_toast(true, "Refreshing device list…");
        }
        KeyCode::Char('a') => start_pairing(app, data_dir, ev_tx),
        KeyCode::Char('y') => copy_selected_peer(app),
        KeyCode::Char('x') => prompt_revoke_selected(app),
        KeyCode::Char('/') => {
            app.focus = FocusPane::Input;
            if app.input.starts_with(':') {
                app.input.clear();
            }
        }
        KeyCode::Char(':') => {
            app.focus = FocusPane::Input;
            app.input = ":".into();
        }
        KeyCode::Esc if !app.input.is_empty() => {
            app.input.clear();
            app.reconcile_selection();
        }
        _ => {}
    }
}

fn handle_input_key(
    app: &mut AppState,
    key: KeyEvent,
    data_dir: &Path,
    ev_tx: &mpsc::UnboundedSender<UiEvent>,
) {
    match key.code {
        KeyCode::Esc => {
            app.focus = FocusPane::Peers;
            if app.input.starts_with(':') {
                app.input.clear();
            }
        }
        KeyCode::Enter => {
            if app.input.starts_with(':') {
                let raw = std::mem::take(&mut app.input);
                app.focus = FocusPane::Peers;
                match parse_input_command(&raw) {
                    Ok(cmd) => execute_input_command(app, cmd, data_dir, ev_tx),
                    Err(msg) => app.set_toast(false, msg),
                }
            } else {
                app.focus = FocusPane::Peers;
            }
        }
        KeyCode::Backspace => {
            app.input.pop();
            app.reconcile_selection();
        }
        KeyCode::Char(c)
            if !key.modifiers.contains(KeyModifiers::CONTROL)
                && !key.modifiers.contains(KeyModifiers::ALT) =>
        {
            app.input.push(c);
            app.reconcile_selection();
        }
        _ => {}
    }
}

fn handle_modal_key(
    app: &mut AppState,
    key: KeyEvent,
    data_dir: &Path,
    ev_tx: &mpsc::UnboundedSender<UiEvent>,
) {
    let Some(modal) = app.modal.clone() else {
        return;
    };
    match modal {
        Modal::Palette {
            mut query,
            mut selected,
        } => match key.code {
            KeyCode::Esc => app.modal = None,
            KeyCode::Down => {
                let len = filtered_palette(&query).len();
                if len > 0 {
                    selected = (selected + 1).min(len - 1);
                }
                app.modal = Some(Modal::Palette { query, selected });
            }
            KeyCode::Up => {
                selected = selected.saturating_sub(1);
                app.modal = Some(Modal::Palette { query, selected });
            }
            KeyCode::Backspace => {
                query.pop();
                selected = 0;
                app.modal = Some(Modal::Palette { query, selected });
            }
            KeyCode::Enter => {
                let matches = filtered_palette(&query);
                app.modal = None;
                if let Some(&(_, _, action)) = matches.get(selected) {
                    run_palette_action(app, *action, data_dir, ev_tx);
                }
            }
            KeyCode::Char(c)
                if !key.modifiers.contains(KeyModifiers::CONTROL)
                    && !key.modifiers.contains(KeyModifiers::ALT) =>
            {
                query.push(c);
                selected = 0;
                app.modal = Some(Modal::Palette { query, selected });
            }
            _ => {}
        },
        Modal::Pairing { setup, .. } => match key.code {
            KeyCode::Char('c') => {
                if let Some(bundle) = setup {
                    let cmd = format!("topaz setup '{bundle}' --start");
                    let dest = clipboard::copy_text(&cmd);
                    app.set_toast(true, format!("Copied setup command to {dest}"));
                }
            }
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                app.modal = None;
            }
            _ => {}
        },
        Modal::RevokeConfirm { device_id, name } => match key.code {
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                app.modal = None;
            }
            KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => {
                app.modal = None;
                spawn_revoke(data_dir.to_path_buf(), device_id, name, ev_tx.clone());
            }
            _ => {}
        },
    }
}

pub(super) fn filtered_palette(query: &str) -> Vec<&'static (&'static str, &'static str, PaletteAction)> {
    let q = query.trim().to_ascii_lowercase();
    PALETTE_ITEMS
        .iter()
        .filter(|(label, desc, _)| {
            q.is_empty()
                || label.to_ascii_lowercase().contains(&q)
                || desc.to_ascii_lowercase().contains(&q)
        })
        .collect()
}

fn open_palette(app: &mut AppState) {
    app.modal = Some(Modal::Palette {
        query: String::new(),
        selected: 0,
    });
}

fn start_pairing(app: &mut AppState, data_dir: &Path, ev_tx: &mpsc::UnboundedSender<UiEvent>) {
    app.modal = Some(Modal::Pairing {
        code: None,
        setup: None,
        state: PairingState::Starting,
    });
    spawn_add_device(data_dir.to_path_buf(), ev_tx.clone());
}

fn copy_selected_peer(app: &mut AppState) {
    let Some(peer) = app.selected_peer() else {
        app.set_toast(false, "No peer selected");
        return;
    };
    let text = peer
        .dns_name
        .as_deref()
        .map(|d| format!("{d}.topaz"))
        .or_else(|| peer.virtual_ip.clone())
        .unwrap_or_else(|| peer.device_id.clone());
    let dest = clipboard::copy_text(&text);
    app.set_toast(true, format!("Copied {text} to {dest}"));
}

fn prompt_revoke_selected(app: &mut AppState) {
    if let Some(peer) = app.selected_peer() {
        app.modal = Some(Modal::RevokeConfirm {
            device_id: peer.device_id,
            name: peer.name,
        });
    } else {
        app.set_toast(false, "No peer selected to revoke");
    }
}

fn run_palette_action(
    app: &mut AppState,
    action: PaletteAction,
    data_dir: &Path,
    ev_tx: &mpsc::UnboundedSender<UiEvent>,
) {
    match action {
        PaletteAction::KickAnnounce => spawn_kick(data_dir.to_path_buf(), true, ev_tx.clone()),
        PaletteAction::KickLocal => spawn_kick(data_dir.to_path_buf(), false, ev_tx.clone()),
        PaletteAction::AddDevice => start_pairing(app, data_dir, ev_tx),
        PaletteAction::CopyPeerAddr => copy_selected_peer(app),
        PaletteAction::RevokeSelected => prompt_revoke_selected(app),
        PaletteAction::Refresh => {
            spawn_refresh_devices(data_dir.to_path_buf(), ev_tx.clone());
            app.set_toast(true, "Refreshing device list…");
        }
        PaletteAction::ToggleSidebar => {
            app.sidebar_visible = !app.sidebar_visible;
            app.save_prefs(data_dir);
        }
        PaletteAction::CycleTheme => {
            app.theme = app.theme.cycle();
            app.save_prefs(data_dir);
            app.set_toast(true, format!("Theme: {}", app.theme.label()));
        }
        PaletteAction::ClearFilter => {
            app.input.clear();
            app.reconcile_selection();
        }
        PaletteAction::StopDaemon => spawn_stop_daemon(data_dir.to_path_buf(), ev_tx.clone()),
        PaletteAction::Quit => app.should_quit = true,
    }
}

fn execute_input_command(
    app: &mut AppState,
    cmd: InputCommand,
    data_dir: &Path,
    ev_tx: &mpsc::UnboundedSender<UiEvent>,
) {
    match cmd {
        InputCommand::Kick { announce } => {
            spawn_kick(data_dir.to_path_buf(), announce, ev_tx.clone())
        }
        InputCommand::Add => start_pairing(app, data_dir, ev_tx),
        InputCommand::Revoke { target } => {
            if let Some(t) = target {
                let peers = merge_peers(&app.status, &app.devices, "");
                let found = peers.into_iter().find(|p| {
                    p.device_id == t
                        || p.name.eq_ignore_ascii_case(&t)
                        || p.dns_name
                            .as_deref()
                            .is_some_and(|d| d.eq_ignore_ascii_case(&t))
                });
                if let Some(p) = found {
                    app.modal = Some(Modal::RevokeConfirm {
                        device_id: p.device_id,
                        name: p.name,
                    });
                } else {
                    app.set_toast(false, format!("Device not found: {t}"));
                }
            } else {
                prompt_revoke_selected(app);
            }
        }
        InputCommand::Copy => copy_selected_peer(app),
        InputCommand::Refresh => {
            spawn_refresh_devices(data_dir.to_path_buf(), ev_tx.clone());
            app.set_toast(true, "Refreshing device list…");
        }
        InputCommand::ToggleSidebar => {
            app.sidebar_visible = !app.sidebar_visible;
            app.save_prefs(data_dir);
        }
        InputCommand::Theme { name } => {
            app.theme = match name {
                Some(n) => ThemeKind::from_name(&n),
                None => app.theme.cycle(),
            };
            app.save_prefs(data_dir);
            app.set_toast(true, format!("Theme: {}", app.theme.label()));
        }
        InputCommand::StopDaemon => spawn_stop_daemon(data_dir.to_path_buf(), ev_tx.clone()),
        InputCommand::Quit => app.should_quit = true,
        InputCommand::Help => {
            app.set_toast(
                true,
                "Commands: :kick [local] · :add · :revoke [peer] · :copy · :theme · :stop · :quit",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn parses_bottom_input_commands() {
        assert_eq!(
            parse_input_command(":kick"),
            Ok(InputCommand::Kick { announce: true })
        );
        assert_eq!(
            parse_input_command(":kick local"),
            Ok(InputCommand::Kick { announce: false })
        );
        assert_eq!(parse_input_command(":add"), Ok(InputCommand::Add));
        assert_eq!(parse_input_command(":copy"), Ok(InputCommand::Copy));
        assert_eq!(parse_input_command(":stop"), Ok(InputCommand::StopDaemon));
        assert_eq!(
            parse_input_command(":revoke laptop"),
            Ok(InputCommand::Revoke {
                target: Some("laptop".into())
            })
        );
        assert_eq!(
            parse_input_command(":theme tokyonight"),
            Ok(InputCommand::Theme {
                name: Some("tokyonight".into())
            })
        );
        assert_eq!(parse_input_command(":q"), Ok(InputCommand::Quit));
        assert!(parse_input_command(":bogus").is_err());
    }

    #[test]
    fn merges_live_peers_and_offline_devices_with_filter() {
        let status = StatusSnapshot {
            account: "acct".into(),
            device_id: "me".into(),
            device_name: "workstation".into(),
            dns_name: Some("workstation".into()),
            virtual_ip: Some("100.64.0.1".into()),
            peers: vec![PeerSnapshot {
                device_id: "p1".into(),
                name: "laptop".into(),
                dns_name: Some("laptop".into()),
                virtual_ip: Some("100.64.0.2".into()),
                path: Some("direct".into()),
                rtt_ms: Some(12),
                services: vec![PeerServiceSnapshot {
                    service_id: 16,
                    name: "jade".into(),
                }],
            }],
            ..Default::default()
        };
        let devices = vec![
            DeviceRow {
                device_id: "me".into(),
                name: "workstation".into(),
                dns_name: Some("workstation".into()),
                virtual_ip: Some("100.64.0.1".into()),
                status: "active".into(),
                issuer: "recovery code".into(),
                me: true,
            },
            DeviceRow {
                device_id: "p1".into(),
                name: "laptop".into(),
                dns_name: Some("laptop".into()),
                virtual_ip: Some("100.64.0.2".into()),
                status: "active".into(),
                issuer: "me".into(),
                me: false,
            },
            DeviceRow {
                device_id: "p2".into(),
                name: "nas".into(),
                dns_name: Some("nas".into()),
                virtual_ip: Some("100.64.0.3".into()),
                status: "active".into(),
                issuer: "me".into(),
                me: false,
            },
        ];

        let all = merge_peers(&status, &devices, "");
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].device_id, "p1");
        assert_eq!(all[0].services.len(), 1);
        assert_eq!(all[1].device_id, "p2");
        assert_eq!(all[1].path, None);

        let by_plugin = merge_peers(&status, &devices, "jade");
        assert_eq!(by_plugin.len(), 1);
        assert_eq!(by_plugin[0].device_id, "p1");
    }

    #[test]
    fn renders_jade_aligned_layout_across_all_themes() {
        for kind in [ThemeKind::Ink, ThemeKind::TokyoNight, ThemeKind::Light] {
            let mut app = AppState::new(kind, true);
            app.ws_connected = true;
            app.status = StatusSnapshot {
                account: "acct".into(),
                device_id: "me".into(),
                device_name: "workstation".into(),
                dns_name: Some("workstation".into()),
                virtual_ip: Some("100.64.0.1".into()),
                tun: TunSnapshot {
                    enabled: true,
                    interface: Some("topaz0".into()),
                    cidr: "100.64.0.0/10".into(),
                    mtu: 1280,
                    dns_listen: Some("100.64.0.1:53".into()),
                },
                connection: Some("direct".into()),
                peers: vec![PeerSnapshot {
                    device_id: "p1".into(),
                    name: "macbook".into(),
                    dns_name: Some("macbook".into()),
                    virtual_ip: Some("100.64.0.2".into()),
                    path: Some("direct".into()),
                    rtt_ms: Some(9),
                    services: vec![PeerServiceSnapshot {
                        service_id: 16,
                        name: "jade".into(),
                    }],
                }],
                services: vec![LocalServiceSnapshot {
                    service_id: 16,
                    name: "jade".into(),
                    online: true,
                    listeners: 2,
                }],
            };
            app.reconcile_selection();

            let backend = TestBackend::new(110, 32);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal.draw(|f| view::draw_ui(f, &app)).unwrap();

            let buf = terminal.backend().buffer();
            let mut rendered = String::new();
            for y in 0..buf.area.height {
                for x in 0..buf.area.width {
                    rendered.push_str(buf[(x, y)].symbol());
                }
                rendered.push('\n');
            }
            assert!(rendered.contains("topaz"));
            assert!(rendered.contains("macbook"));
            assert!(rendered.contains("[jade]"));
            assert!(rendered.contains("100.64.0.2"));
            assert!(rendered.contains("tun:on"));
            assert!(rendered.contains(kind.label()));
        }
    }
}
