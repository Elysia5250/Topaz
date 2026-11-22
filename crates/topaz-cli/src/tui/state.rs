//! Core TUI state, reusable text field, hit-test regions, and modal models.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ratatui::layout::Rect;
use serde::Deserialize;
use tokio::sync::oneshot;
use tokio::task::AbortHandle;

use crate::doctor::DoctorReport;
use crate::ops::DeviceRow;
use crate::run::ElevationError;

use super::prefs::{self, ConsolePrefs};
use super::theme::ThemeKind;

pub const NARROW_WIDTH: u16 = 74;

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
    #[serde(default)]
    pub error: Option<String>,
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

/// Snapshot of local store & host state loaded from `<data_dir>` (works offline).
#[derive(Debug, Clone, Default)]
pub struct LocalSnapshot {
    pub device_id: String,
    pub device_name: String,
    pub account_user_id: Option<String>,
    pub coord_url: String,
    pub coord_pin: String,
    pub force_relay: bool,
    pub service_status: String,
    pub data_dir: PathBuf,
    pub socket_path: PathBuf,
    pub uptime_s: Option<u64>,
}

impl LocalSnapshot {
    pub fn load(data_dir: &Path) -> Self {
        let mut snap = Self {
            data_dir: data_dir.to_path_buf(),
            socket_path: topaz_core::control_socket_path(data_dir),
            service_status: crate::service::status_line(),
            ..Default::default()
        };
        if let Ok(store) = topaz_core::Store::open(data_dir.to_path_buf()) {
            snap.device_id = store.identity.device_id.clone();
            snap.device_name = store.device_name();
            snap.account_user_id = store.account.as_ref().map(|a| a.user_id.clone());
            snap.coord_url = store.config.coord_url.clone();
            snap.coord_pin = store.config.coord_pin.clone();
            snap.force_relay = store.config.force_relay;
        }
        snap
    }

    pub fn has_account(&self) -> bool {
        self.account_user_id.is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppMode {
    Onboarding,
    Standby,
    Live,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusArea {
    Sidebar,
    Filter,
    Detail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidebarEntry {
    SelfDevice,
    Peer(Box<MergedPeer>),
}

/// Reusable modern single-line text input with UTF-8 character cursor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TextField {
    pub value: String,
    /// Cursor position measured in Unicode scalar values (`chars().count()`).
    pub cursor: usize,
    pub masked: bool,
    pub reveal: bool,
    pub placeholder: String,
}

impl TextField {
    pub fn new(placeholder: impl Into<String>) -> Self {
        Self {
            value: String::new(),
            cursor: 0,
            masked: false,
            reveal: false,
            placeholder: placeholder.into(),
        }
    }

    pub fn with_value(mut self, val: impl Into<String>) -> Self {
        self.value = val.into();
        self.cursor = self.value.chars().count();
        self
    }

    pub fn masked(mut self) -> Self {
        self.masked = true;
        self
    }

    pub fn byte_index(&self) -> usize {
        self.value
            .char_indices()
            .nth(self.cursor)
            .map(|(i, _)| i)
            .unwrap_or(self.value.len())
    }

    pub fn insert_char(&mut self, c: char) {
        let idx = self.byte_index();
        self.value.insert(idx, c);
        self.cursor += 1;
    }

    pub fn insert_str(&mut self, s: &str) {
        let cleaned: String = s
            .chars()
            .filter(|c| !matches!(c, '\r' | '\n' | '\t'))
            .collect();
        if cleaned.is_empty() {
            return;
        }
        let idx = self.byte_index();
        self.value.insert_str(idx, &cleaned);
        self.cursor += cleaned.chars().count();
    }

    pub fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        self.cursor -= 1;
        let idx = self.byte_index();
        self.value.remove(idx);
    }

    pub fn delete(&mut self) {
        let len = self.value.chars().count();
        if self.cursor >= len {
            return;
        }
        let idx = self.byte_index();
        self.value.remove(idx);
    }

    pub fn delete_word(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let chars: Vec<char> = self.value.chars().collect();
        let mut pos = self.cursor;
        while pos > 0 && chars[pos - 1].is_whitespace() {
            pos -= 1;
        }
        while pos > 0 && !chars[pos - 1].is_whitespace() {
            pos -= 1;
        }
        let before: String = chars[..pos].iter().collect();
        let after: String = chars[self.cursor..].iter().collect();
        self.value = format!("{before}{after}");
        self.cursor = pos;
    }

    pub fn move_left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn move_right(&mut self) {
        let len = self.value.chars().count();
        self.cursor = (self.cursor + 1).min(len);
    }

    pub fn move_home(&mut self) {
        self.cursor = 0;
    }

    pub fn move_end(&mut self) {
        self.cursor = self.value.chars().count();
    }

    pub fn clear(&mut self) {
        self.value.clear();
        self.cursor = 0;
    }

    pub fn zeroize_clear(&mut self) {
        use zeroize::Zeroize;
        self.value.zeroize();
        self.cursor = 0;
    }

    pub fn display_text(&self) -> String {
        if self.masked && !self.reveal {
            "•".repeat(self.value.chars().count())
        } else {
            self.value.clone()
        }
    }

    pub fn cursor_display_width(&self) -> usize {
        if self.masked && !self.reveal {
            self.cursor
        } else {
            let prefix: String = self.value.chars().take(self.cursor).collect();
            ratatui::text::Span::raw(prefix).width()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnboardingChoice {
    JoinPhrase,
    JoinBundle,
    CreateAccount,
    JoinRecovery,
}

impl OnboardingChoice {
    pub const ALL: [Self; 4] = [
        Self::JoinPhrase,
        Self::JoinBundle,
        Self::CreateAccount,
        Self::JoinRecovery,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Self::JoinPhrase => "Pair with Phrase",
            Self::JoinBundle => "Join with Setup Bundle / Code",
            Self::CreateAccount => "Create New Account",
            Self::JoinRecovery => "Join with Recovery Code",
        }
    }

    pub fn badge(self) -> Option<&'static str> {
        match self {
            Self::JoinPhrase => Some("recommended"),
            _ => None,
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::JoinPhrase => "Zero copy-paste: enter server IP & a shared phrase to pair with an existing device",
            Self::JoinBundle => "Paste a topaz-setup:v1:… bundle or ABC-DEFGH one-time code",
            Self::CreateAccount => "First device on a coord server using a VPS invite code",
            Self::JoinRecovery => "Offline fallback using your account's secret recovery code",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnboardingStep {
    Form,
    ProbingPin,
    TofuConfirm {
        coord_url: String,
        pin: String,
    },
    Submitting(String),
    RecoveryBackup {
        account_id: String,
        recovery_code: String,
    },
}

#[derive(Debug, Clone)]
pub struct OnboardingModal {
    pub kind: OnboardingChoice,
    pub coord_url: TextField,
    pub coord_pin: TextField,
    pub secret: TextField, // phrase, bundle/code, invite, or recovery code
    pub device_name: TextField,
    pub focus_field: usize,
    pub step: OnboardingStep,
    pub error: Option<String>,
}

impl OnboardingModal {
    pub fn new(kind: OnboardingChoice, local: &LocalSnapshot) -> Self {
        let secret = match kind {
            OnboardingChoice::JoinPhrase => TextField::new("e.g. sunny-otter-42"),
            OnboardingChoice::JoinBundle => TextField::new("topaz-setup:v1:... or ABC-DEFGH"),
            OnboardingChoice::CreateAccount => TextField::new("invite code from VPS"),
            OnboardingChoice::JoinRecovery => TextField::new("account recovery code").masked(),
        };
        Self {
            kind,
            coord_url: TextField::new("1.2.3.4 or https://host:7722")
                .with_value(local.coord_url.clone()),
            coord_pin: TextField::new("leave blank to auto-probe & verify")
                .with_value(local.coord_pin.clone()),
            secret,
            device_name: TextField::new("e.g. macbook").with_value(local.device_name.clone()),
            focus_field: 0,
            step: OnboardingStep::Form,
            error: None,
        }
    }

    /// Logical field list for this onboarding form.
    pub fn field_count(&self) -> usize {
        match self.kind {
            OnboardingChoice::JoinPhrase => 3, // coord_url, phrase, device_name
            OnboardingChoice::JoinBundle => 2, // bundle/code, device_name
            OnboardingChoice::CreateAccount => 4, // coord_url, pin (opt), invite, device_name
            OnboardingChoice::JoinRecovery => 4, // coord_url, pin (opt), recovery, device_name
        }
    }

    pub fn active_field_mut(&mut self) -> Option<&mut TextField> {
        match (self.kind, self.focus_field) {
            (OnboardingChoice::JoinPhrase, 0) => Some(&mut self.coord_url),
            (OnboardingChoice::JoinPhrase, 1) => Some(&mut self.secret),
            (OnboardingChoice::JoinPhrase, 2) => Some(&mut self.device_name),
            (OnboardingChoice::JoinBundle, 0) => Some(&mut self.secret),
            (OnboardingChoice::JoinBundle, 1) => Some(&mut self.device_name),
            (OnboardingChoice::CreateAccount | OnboardingChoice::JoinRecovery, 0) => {
                Some(&mut self.coord_url)
            }
            (OnboardingChoice::CreateAccount | OnboardingChoice::JoinRecovery, 1) => {
                Some(&mut self.coord_pin)
            }
            (OnboardingChoice::CreateAccount | OnboardingChoice::JoinRecovery, 2) => {
                Some(&mut self.secret)
            }
            (OnboardingChoice::CreateAccount | OnboardingChoice::JoinRecovery, 3) => {
                Some(&mut self.device_name)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairTab {
    Phrase,
    Bundle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairStatus {
    Idle,
    Starting,
    WaitingPhrase {
        phrase: String,
        peer_cmd: String,
    },
    ConfirmPeer {
        device_name: String,
        device_id: String,
        sas: String,
    },
    WaitingBundle {
        code: String,
        setup: String,
    },
    Added {
        name: String,
        device_id: String,
    },
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct PairModal {
    pub tab: PairTab,
    pub phrase: TextField,
    pub status: PairStatus,
}

impl PairModal {
    pub fn new() -> Self {
        Self {
            tab: PairTab::Phrase,
            phrase: TextField::new("e.g. my-pair-01 (min 4 chars)"),
            status: PairStatus::Idle,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SudoModal {
    pub password: TextField,
    pub restart_first: bool,
    pub busy: bool,
    pub error: Option<String>,
    pub command_preview: String,
    /// Focus index: 0=password, 1=Start TUN, 2=Start No-TUN, 3=Cancel.
    pub focus: usize,
}

impl SudoModal {
    pub fn new(data_dir: &Path, restart_first: bool) -> Self {
        Self {
            password: TextField::new("Enter administrator password").masked(),
            restart_first,
            busy: false,
            error: None,
            command_preview: format!(
                "sudo topaz --data-dir {} run --detach",
                data_dir.display()
            ),
            focus: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DoctorModal {
    pub report: DoctorReport,
    pub scroll: u16,
    pub max_scroll: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFilter {
    All,
    Warn,
    Error,
}

impl LogFilter {
    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Warn => "Warn+",
            Self::Error => "Error",
        }
    }
}

#[derive(Debug, Clone)]
pub struct LogsModal {
    pub lines: Vec<String>,
    pub filter: LogFilter,
    pub follow: bool,
    pub scroll: u16,
    pub max_scroll: u16,
    pub log_path: PathBuf,
}

impl LogsModal {
    pub fn filtered_lines(&self) -> Vec<&str> {
        self.lines
            .iter()
            .map(String::as_str)
            .filter(|line| match self.filter {
                LogFilter::All => true,
                LogFilter::Warn => {
                    let u = line.to_ascii_uppercase();
                    u.contains("WARN") || u.contains("ERROR") || u.contains("ERR ")
                }
                LogFilter::Error => {
                    let u = line.to_ascii_uppercase();
                    u.contains("ERROR") || u.contains("ERR ") || u.contains("FAILED")
                }
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct SettingsModal {
    pub device_name: TextField,
    pub coord_url: TextField,
    pub coord_pin: TextField,
    pub force_relay: bool,
    /// Focus index: 0=device_name, 1=coord_url, 2=coord_pin, 3=force_relay, 4=theme, 5=mouse
    pub focus_idx: usize,
    pub probing_pin: bool,
    pub error: Option<String>,
}

impl SettingsModal {
    pub fn from_local(local: &LocalSnapshot) -> Self {
        Self {
            device_name: TextField::new("friendly hostname").with_value(local.device_name.clone()),
            coord_url: TextField::new("https://host:7722").with_value(local.coord_url.clone()),
            coord_pin: TextField::new("32-char base32 TLS pin").with_value(local.coord_pin.clone()),
            force_relay: local.force_relay,
            focus_idx: 0,
            probing_pin: false,
            error: None,
        }
    }

    pub fn active_field_mut(&mut self) -> Option<&mut TextField> {
        match self.focus_idx {
            0 => Some(&mut self.device_name),
            1 => Some(&mut self.coord_url),
            2 => Some(&mut self.coord_pin),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RevokeModal {
    pub device_id: String,
    pub name: String,
    pub use_recovery: bool,
    pub recovery: TextField,
    pub busy: bool,
    pub error: Option<String>,
}

impl RevokeModal {
    pub fn new(device_id: String, name: String) -> Self {
        Self {
            device_id,
            name,
            use_recovery: false,
            recovery: TextField::new("recovery code").masked(),
            busy: false,
            error: None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Modal {
    Palette {
        query: TextField,
        selected: usize,
    },
    SudoPrompt(SudoModal),
    Pair(PairModal),
    OnboardingForm(OnboardingModal),
    Doctor(DoctorModal),
    Logs(LogsModal),
    Settings(SettingsModal),
    RevokeConfirm(RevokeModal),
    StopConfirm,
    Help,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaletteAction {
    StartTun,
    StartNoTun,
    RestartTun,
    RestartNoTun,
    StopDaemon,
    PairDevice,
    KickAnnounce,
    KickLocal,
    RefreshDevices,
    CopyPeerDns,
    CopyPeerIp,
    RevokeSelected,
    OpenDoctor,
    OpenLogs,
    OpenSettings,
    InstallAutostartTun,
    InstallAutostartNoTun,
    UninstallAutostart,
    ToggleFilter,
    ToggleSidebar,
    CycleTheme,
    ToggleMouseCapture,
    OpenHelp,
    Quit,
}

pub const PALETTE_ITEMS: &[(&str, &str, &str, PaletteAction)] = &[
    ("Start VPN (TUN)", "Launch daemon with 100.64.0.0/10 TUN interface", "", PaletteAction::StartTun),
    ("Start Session Mode (--no-tun)", "Launch user-level daemon without sudo", "", PaletteAction::StartNoTun),
    ("Restart in VPN (TUN) Mode", "Stop and relaunch daemon with TUN", "", PaletteAction::RestartTun),
    ("Restart in Session Mode", "Stop and relaunch daemon without TUN", "", PaletteAction::RestartNoTun),
    ("Stop Daemon", "Shut down background topaz daemon", "", PaletteAction::StopDaemon),
    ("Pair / Add Device", "Phrase pairing or one-time setup bundle", "Ctrl+N", PaletteAction::PairDevice),
    ("Refresh & Probe Peers", "Sync device list and nudge peer links", "Ctrl+R", PaletteAction::RefreshDevices),
    ("Kick Peers (Announce)", "Broadcast local endpoints & probe mesh", "", PaletteAction::KickAnnounce),
    ("Kick Peers (Local Only)", "Probe peers without coord announce", "", PaletteAction::KickLocal),
    ("Network Doctor", "Test coord, relay, STUN, mDNS & peers", "Ctrl+D", PaletteAction::OpenDoctor),
    ("Daemon Logs", "Inspect live <data_dir>/topaz.log", "Ctrl+L", PaletteAction::OpenLogs),
    ("Settings & Autostart", "Edit coord/name, theme & autostart service", "Ctrl+O", PaletteAction::OpenSettings),
    ("Copy Peer Domain (.topaz)", "Copy selected peer's DNS name", "Ctrl+Y", PaletteAction::CopyPeerDns),
    ("Copy Peer Virtual IP", "Copy selected peer's 100.64.x.x IP", "", PaletteAction::CopyPeerIp),
    ("Revoke Selected Device", "Permanently revoke highlighted peer", "Del", PaletteAction::RevokeSelected),
    ("Install Autostart (TUN)", "Register systemd/launchd with TUN", "", PaletteAction::InstallAutostartTun),
    ("Install Autostart (No-TUN)", "Register user autostart without TUN", "", PaletteAction::InstallAutostartNoTun),
    ("Uninstall Autostart", "Remove systemd/launchd unit", "", PaletteAction::UninstallAutostart),
    ("Filter Devices", "Search devices by name, IP, or service", "Ctrl+F", PaletteAction::ToggleFilter),
    ("Toggle Sidebar", "Show or hide left device list", "Ctrl+B", PaletteAction::ToggleSidebar),
    ("Cycle Color Theme", "Switch ink / tokyonight / light", "Ctrl+T", PaletteAction::CycleTheme),
    ("Toggle Mouse Capture", "Switch mouse clicks vs native terminal select", "", PaletteAction::ToggleMouseCapture),
    ("Keyboard & Mouse Help", "View all shortcuts and mouse gestures", "F1", PaletteAction::OpenHelp),
    ("Quit TUI", "Close console (daemon keeps running)", "Ctrl+Q", PaletteAction::Quit),
];

pub fn filtered_palette(query: &str) -> Vec<&'static (&'static str, &'static str, &'static str, PaletteAction)> {
    let q = query.trim().to_ascii_lowercase();
    PALETTE_ITEMS
        .iter()
        .filter(|(label, desc, key, _)| {
            q.is_empty()
                || label.to_ascii_lowercase().contains(&q)
                || desc.to_ascii_lowercase().contains(&q)
                || key.to_ascii_lowercase().contains(&q)
        })
        .collect()
}

/// Interactive buttons inside the Detail pane (supports both mouse click and Tab+Enter).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailButton {
    StartTun,
    StartNoTun,
    RestartTun,
    RestartNoTun,
    StopDaemon,
    ProbePeers,
    OpenPair,
    OpenDoctor,
    OpenLogs,
    OpenSettings,
    CopyDns,
    CopyIp,
    RevokePeer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HitTarget {
    // Top bar
    SelectSelf,
    TopTunPill,
    OpenPair,
    OpenDoctor,
    OpenLogs,
    OpenSettings,
    OpenPalette,
    OpenHelp,
    ToggleSidebar,
    CycleTheme,
    Quit,
    // Sidebar
    FocusFilter,
    ClearFilter,
    SelectSidebarRow(usize),
    NarrowBackToList,
    // Detail actions
    DetailAction(DetailButton),
    CopyText { label: String, text: String },
    // Onboarding main view
    OnboardingPick(OnboardingChoice),
    // Modal generic
    ModalBackdrop,
    ModalClose,
    // Palette
    PaletteRow(usize),
    // Sudo modal
    SudoToggleReveal,
    SudoSubmit,
    SudoFallbackNoTun,
    // Pair modal
    PairSelectTab(PairTab),
    PairStartPhrase,
    PairApprovePeer(bool),
    PairCopyCmd(String),
    PairRestart,
    // Onboarding form modal
    OnboardingFocusField(usize),
    OnboardingToggleReveal,
    OnboardingSubmit,
    OnboardingTofuTrust,
    OnboardingCopyRecovery(String),
    OnboardingFinishRecovery,
    // Doctor modal
    DoctorRerun,
    DoctorCopy,
    // Logs modal
    LogsFilter(LogFilter),
    LogsToggleFollow,
    LogsCopy,
    // Settings modal
    SettingsFocus(usize),
    SettingsProbePin,
    SettingsSave,
    SettingsInstallAutostart(bool), // no_tun
    SettingsUninstallAutostart,
    SettingsCycleTheme,
    SettingsToggleMouse,
    // Revoke modal
    RevokeToggleRecovery,
    RevokeToggleReveal,
    RevokeSubmit,
    // Stop confirm
    StopConfirmSubmit,
}

#[derive(Debug, Clone)]
pub struct HitRegion {
    pub rect: Rect,
    pub target: HitTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GridPos {
    pub col: u16,
    pub row: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MouseSelection {
    pub start: GridPos,
    pub end: GridPos,
    pub active: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DividerState {
    pub x: Option<u16>,
    pub hover: bool,
    pub dragging: bool,
    pub width_override: Option<u16>,
}

#[derive(Debug)]
pub enum UiEvent {
    Key(ratatui::crossterm::event::KeyEvent),
    Mouse(ratatui::crossterm::event::MouseEvent),
    Paste(String),
    Resize,
    WsConnected,
    WsDisconnected,
    UptimeUpdated(Option<u64>),
    StatusUpdated(Box<StatusSnapshot>),
    DevicesUpdated(Vec<DeviceRow>),
    LocalRefreshed(LocalSnapshot),
    ActionResult { ok: bool, message: String },
    DaemonStarted { ok: bool, message: String },
    NeedSudoPrompt { restart_first: bool },
    SudoResult(std::result::Result<String, ElevationError>),
    PairCodeReady { code: String, setup: String },
    PairPeerIncoming {
        device_name: String,
        device_id: String,
        sas: String,
        decision_tx: oneshot::Sender<bool>,
    },
    PairFinished(std::result::Result<(String, String), String>),
    OnboardingPinProbed(std::result::Result<(String, String), String>),
    OnboardingDone {
        account_id: String,
        recovery_code: Option<String>,
    },
    OnboardingFailed(String),
    DoctorUpdate(DoctorReport),
    DoctorError(String),
    LogsLoaded(Vec<String>),
    SettingsPinProbed(std::result::Result<String, String>),
    RevokeFinished(std::result::Result<String, String>),
}

/// Merge live `/v1/status` peers with `/v1/devices` (including offline/revoked)
/// and filter by `query`.
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

pub fn format_uptime(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs < 86_400 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d {}h", secs / 86_400, (secs % 86_400) / 3600)
    }
}

pub struct AppState {
    pub theme: ThemeKind,
    pub sidebar_visible: bool,
    pub mouse_capture: bool,
    pub focus: FocusArea,
    pub filter_open: bool,
    pub filter: TextField,
    pub local: LocalSnapshot,
    pub status: StatusSnapshot,
    pub devices: Vec<DeviceRow>,
    pub ws_connected: bool,
    /// Selected index in the unified sidebar (`0` = This Device, `1..` = peers).
    pub selected_idx: usize,
    /// Stable selection key (`None` = This Device, `Some(device_id)` = peer).
    pub selected_peer_id: Option<String>,
    pub sidebar_scroll: usize,
    pub detail_scroll: u16,
    pub detail_max_scroll: u16,
    pub detail_btn_idx: usize,
    pub narrow_showing_detail: bool,
    pub onboarding_idx: usize,
    pub modal: Option<Modal>,
    pub toast: Option<(String, bool, Instant)>,
    pub busy_banner: Option<String>,
    pub tick_count: u64,
    pub should_quit: bool,
    /// Pending mouse capture toggle requested by UI action (applied by main loop).
    pub pending_mouse_toggle: Option<bool>,
    // Background task handles
    pub pair_abort: Option<AbortHandle>,
    pub pair_decision_tx: Option<oneshot::Sender<bool>>,
    // Render-pass geometry for mouse support
    pub last_area: Rect,
    pub sidebar_area: Rect,
    pub detail_area: Rect,
    pub modal_area: Option<Rect>,
    pub divider: DividerState,
    pub hit_regions: Vec<HitRegion>,
    pub screen_lines: Vec<Vec<String>>,
    pub drag_start: Option<GridPos>,
    pub selection: Option<MouseSelection>,
}

impl AppState {
    pub fn new(theme: ThemeKind, prefs: &ConsolePrefs, local: LocalSnapshot) -> Self {
        Self {
            theme,
            sidebar_visible: prefs.show_sidebar,
            mouse_capture: true,
            focus: FocusArea::Sidebar,
            filter_open: false,
            filter: TextField::new("Filter devices…"),
            local,
            status: StatusSnapshot::default(),
            devices: Vec::new(),
            ws_connected: false,
            selected_idx: 0,
            selected_peer_id: None,
            sidebar_scroll: 0,
            detail_scroll: 0,
            detail_max_scroll: 0,
            detail_btn_idx: 0,
            narrow_showing_detail: false,
            onboarding_idx: 0,
            modal: None,
            toast: None,
            busy_banner: None,
            tick_count: 0,
            should_quit: false,
            pending_mouse_toggle: None,
            pair_abort: None,
            pair_decision_tx: None,
            last_area: Rect::default(),
            sidebar_area: Rect::default(),
            detail_area: Rect::default(),
            modal_area: None,
            divider: DividerState {
                width_override: prefs.sidebar_width,
                ..Default::default()
            },
            hit_regions: Vec::new(),
            screen_lines: Vec::new(),
            drag_start: None,
            selection: None,
        }
    }

    pub fn mode(&self) -> AppMode {
        if !self.local.has_account() && self.status.account.is_empty() {
            AppMode::Onboarding
        } else if self.ws_connected {
            AppMode::Live
        } else {
            AppMode::Standby
        }
    }

    pub fn effective_device_name(&self) -> &str {
        if !self.status.device_name.is_empty() {
            &self.status.device_name
        } else if !self.local.device_name.is_empty() {
            &self.local.device_name
        } else {
            "topaz"
        }
    }

    pub fn effective_device_id(&self) -> &str {
        if !self.status.device_id.is_empty() {
            &self.status.device_id
        } else {
            &self.local.device_id
        }
    }

    pub fn effective_account(&self) -> Option<&str> {
        if !self.status.account.is_empty() {
            Some(&self.status.account)
        } else {
            self.local.account_user_id.as_deref()
        }
    }

    pub fn filtered_peers(&self) -> Vec<MergedPeer> {
        merge_peers(&self.status, &self.devices, &self.filter.value)
    }

    pub fn all_peers(&self) -> Vec<MergedPeer> {
        merge_peers(&self.status, &self.devices, "")
    }

    pub fn sidebar_entries(&self) -> Vec<SidebarEntry> {
        let mut out = vec![SidebarEntry::SelfDevice];
        for p in self.filtered_peers() {
            out.push(SidebarEntry::Peer(Box::new(p)));
        }
        out
    }

    pub fn selected_entry(&self) -> SidebarEntry {
        let entries = self.sidebar_entries();
        let idx = self.selected_idx.min(entries.len().saturating_sub(1));
        entries.into_iter().nth(idx).unwrap_or(SidebarEntry::SelfDevice)
    }

    pub fn selected_peer(&self) -> Option<MergedPeer> {
        match self.selected_entry() {
            SidebarEntry::SelfDevice => None,
            SidebarEntry::Peer(p) => Some(*p),
        }
    }

    pub fn select_sidebar_index(&mut self, idx: usize) {
        let entries = self.sidebar_entries();
        if entries.is_empty() {
            self.selected_idx = 0;
            self.selected_peer_id = None;
            return;
        }
        let clamped = idx.min(entries.len() - 1);
        self.selected_idx = clamped;
        self.selected_peer_id = match &entries[clamped] {
            SidebarEntry::SelfDevice => None,
            SidebarEntry::Peer(p) => Some(p.device_id.clone()),
        };
        self.detail_scroll = 0;
        self.detail_btn_idx = 0;
    }

    pub fn reconcile_selection(&mut self) {
        let entries = self.sidebar_entries();
        if let Some(ref id) = self.selected_peer_id {
            if let Some(pos) = entries.iter().position(|e| matches!(e, SidebarEntry::Peer(p) if &p.device_id == id)) {
                self.selected_idx = pos;
                return;
            }
        }
        if self.selected_peer_id.is_none() {
            self.selected_idx = 0;
            return;
        }
        self.selected_idx = self.selected_idx.min(entries.len().saturating_sub(1));
        self.selected_peer_id = match entries.get(self.selected_idx) {
            Some(SidebarEntry::Peer(p)) => Some(p.device_id.clone()),
            _ => None,
        };
    }

    pub fn move_selection(&mut self, delta: isize) {
        let len = self.sidebar_entries().len() as isize;
        if len <= 0 {
            return;
        }
        let next = (self.selected_idx as isize + delta).clamp(0, len - 1) as usize;
        self.select_sidebar_index(next);
    }

    pub fn detail_buttons(&self) -> Vec<DetailButton> {
        match self.selected_entry() {
            SidebarEntry::SelfDevice => match self.mode() {
                AppMode::Standby => vec![
                    DetailButton::StartTun,
                    DetailButton::StartNoTun,
                    DetailButton::OpenPair,
                    DetailButton::OpenDoctor,
                    DetailButton::OpenSettings,
                ],
                AppMode::Live => {
                    let mut btns = Vec::new();
                    if self.status.tun.enabled {
                        btns.push(DetailButton::RestartNoTun);
                    } else {
                        btns.push(DetailButton::RestartTun);
                    }
                    btns.push(DetailButton::StopDaemon);
                    btns.push(DetailButton::ProbePeers);
                    btns.push(DetailButton::OpenDoctor);
                    btns.push(DetailButton::OpenLogs);
                    btns.push(DetailButton::OpenSettings);
                    btns
                }
                AppMode::Onboarding => vec![],
            },
            SidebarEntry::Peer(p) => {
                let mut btns = Vec::new();
                if p.dns_name.is_some() {
                    btns.push(DetailButton::CopyDns);
                }
                if p.virtual_ip.is_some() {
                    btns.push(DetailButton::CopyIp);
                }
                if self.ws_connected {
                    btns.push(DetailButton::ProbePeers);
                }
                if p.account_status == "active" {
                    btns.push(DetailButton::RevokePeer);
                }
                btns
            }
        }
    }

    pub fn set_toast(&mut self, ok: bool, msg: impl Into<String>) {
        self.toast = Some((msg.into(), ok, Instant::now() + Duration::from_secs(4)));
    }

    pub fn spinner_glyph(&self) -> &'static str {
        const FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        FRAMES[(self.tick_count as usize) % FRAMES.len()]
    }

    pub fn cancel_pair_task(&mut self) {
        if let Some(tx) = self.pair_decision_tx.take() {
            let _ = tx.send(false);
        }
        if let Some(handle) = self.pair_abort.take() {
            handle.abort();
        }
    }

    pub fn close_modal(&mut self) {
        if let Some(Modal::SudoPrompt(ref mut s)) = self.modal {
            s.password.zeroize_clear();
        }
        if let Some(Modal::RevokeConfirm(ref mut r)) = self.modal {
            r.recovery.zeroize_clear();
        }
        if matches!(self.modal, Some(Modal::Pair(_))) {
            self.cancel_pair_task();
        }
        self.modal = None;
        self.modal_area = None;
    }

    pub fn save_prefs(&self, data_dir: &Path) {
        prefs::save(
            data_dir,
            &ConsolePrefs {
                theme: self.theme.label().to_string(),
                show_sidebar: self.sidebar_visible,
                sidebar_width: self.divider.width_override,
            },
        );
    }
}
