//! Jade-aligned full-lifecycle Terminal UI (`topaz` / `topaz tui`).
//!
//! Pure client: closing the TUI never stops a running `topaz run` daemon.
//! Seamlessly adapts across Onboarding (no account), Standby (daemon stopped),
//! and Live Mesh (connected over `control.sock`).

mod actions;
mod bar;
mod clipboard;
mod input;
mod modals;
mod mouse;
mod prefs;
mod state;
mod terminal;
pub mod theme;
mod view;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Result;
use futures::StreamExt;
use ratatui::crossterm::event::{self, Event, KeyEventKind};
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::client::ControlClient;
use crate::run::ElevationError;

use actions::{spawn_refresh_devices, spawn_refresh_local, spawn_reload_logs};
use state::{
    AppState, LocalSnapshot, Modal, OnboardingStep, PairStatus, StatusSnapshot, SudoModal, UiEvent,
};
use terminal::TerminalGuard;
pub use theme::ThemeKind;

#[derive(Debug, Clone, Deserialize)]
struct EventEnvelope {
    #[serde(rename = "type")]
    kind: String,
    status: StatusSnapshot,
}

pub async fn cmd_tui(data_dir: PathBuf, theme_override: Option<&str>) -> Result<()> {
    let saved = prefs::load(&data_dir);
    let theme = match theme_override {
        Some(name) => ThemeKind::from_name(name),
        None => ThemeKind::from_name(&saved.theme),
    };
    let local = LocalSnapshot::load(&data_dir);
    let mut guard = TerminalGuard::enter()?;
    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel::<UiEvent>();

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(events_loop(
        data_dir.clone(),
        ev_tx.clone(),
        shutdown_rx.clone(),
    ));
    tokio::spawn(devices_poll_loop(
        data_dir.clone(),
        ev_tx.clone(),
        shutdown_rx.clone(),
    ));
    tokio::spawn(uptime_poll_loop(
        data_dir.clone(),
        ev_tx.clone(),
        shutdown_rx.clone(),
    ));
    spawn_input_reader(ev_tx.clone(), shutdown_rx);

    let mut app = AppState::new(theme, &saved, local);
    app.mouse_capture = guard.mouse_capture;
    let mut tick = tokio::time::interval(Duration::from_millis(120));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        if let Some(next_mouse) = app.pending_mouse_toggle.take() {
            guard.set_mouse_capture(next_mouse);
        }

        guard.terminal.draw(|f| view::draw_ui(f, &mut app))?;
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
            _ = tick.tick() => {
                app.tick_count = app.tick_count.wrapping_add(1);
                // Live-refresh daemon log viewer roughly every ~1.2s while open.
                if matches!(app.modal, Some(Modal::Logs(_))) && app.tick_count % 10 == 0 {
                    spawn_reload_logs(data_dir.clone(), ev_tx.clone());
                }
            }
        }

        if let Some((_, _, until)) = app.toast {
            if Instant::now() >= until {
                app.toast = None;
            }
        }
    }

    app.cancel_pair_task();
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
        match event::poll(Duration::from_millis(80)) {
            Ok(true) => match event::read() {
                Ok(Event::Key(key))
                    if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) =>
                {
                    if tx.send(UiEvent::Key(key)).is_err() {
                        break;
                    }
                }
                Ok(Event::Mouse(m)) => {
                    if tx.send(UiEvent::Mouse(m)).is_err() {
                        break;
                    }
                }
                Ok(Event::Paste(text)) => {
                    if tx.send(UiEvent::Paste(text)).is_err() {
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
        UiEvent::Key(key) => input::handle_key(app, key, data_dir, ev_tx),
        UiEvent::Mouse(m) => mouse::handle_mouse(app, m, data_dir, ev_tx),
        UiEvent::Paste(text) => input::handle_paste(app, &text),
        UiEvent::Resize => {}
        other => handle_ui_event(app, other, data_dir, ev_tx),
    }
}

fn handle_ui_event(
    app: &mut AppState,
    ev: UiEvent,
    data_dir: &Path,
    ev_tx: &mpsc::UnboundedSender<UiEvent>,
) {
    match ev {
        UiEvent::WsConnected => {
            app.ws_connected = true;
            app.busy_banner = None;
            spawn_refresh_local(data_dir.to_path_buf(), ev_tx.clone());
        }
        UiEvent::WsDisconnected => {
            app.ws_connected = false;
            app.local.uptime_s = None;
            app.status = StatusSnapshot::default();
            app.reconcile_selection();
        }
        UiEvent::UptimeUpdated(up) => {
            app.local.uptime_s = up;
        }
        UiEvent::StatusUpdated(next) => {
            app.status = *next;
            app.reconcile_selection();
        }
        UiEvent::DevicesUpdated(rows) => {
            app.devices = rows;
            app.reconcile_selection();
        }
        UiEvent::LocalRefreshed(snap) => {
            let uptime = app.local.uptime_s;
            app.local = snap;
            app.local.uptime_s = uptime;
        }
        UiEvent::ActionResult { ok, message } => {
            app.busy_banner = None;
            app.set_toast(ok, message);
        }
        UiEvent::DaemonStarted { ok, message } => {
            app.busy_banner = None;
            app.set_toast(ok, message);
            if ok {
                spawn_refresh_local(data_dir.to_path_buf(), ev_tx.clone());
            }
        }
        UiEvent::NeedSudoPrompt { restart_first } => {
            app.busy_banner = None;
            app.modal = Some(Modal::SudoPrompt(SudoModal::new(data_dir, restart_first)));
        }
        UiEvent::SudoResult(res) => match res {
            Ok(msg) => {
                app.close_modal();
                app.set_toast(true, msg);
                spawn_refresh_local(data_dir.to_path_buf(), ev_tx.clone());
            }
            Err(ElevationError::IncorrectPassword) => {
                if let Some(Modal::SudoPrompt(ref mut s)) = app.modal {
                    s.busy = false;
                    s.password.zeroize_clear();
                    s.error = Some("Incorrect password — please try again".into());
                }
            }
            Err(ElevationError::PasswordRequired) => {
                if let Some(Modal::SudoPrompt(ref mut s)) = app.modal {
                    s.busy = false;
                    s.error = Some("Administrator password required".into());
                }
            }
            Err(ElevationError::Failed(err)) => {
                if let Some(Modal::SudoPrompt(ref mut s)) = app.modal {
                    s.busy = false;
                    s.error = Some(err);
                }
            }
        },
        UiEvent::PairCodeReady { code, setup } => {
            if let Some(Modal::Pair(ref mut p)) = app.modal {
                p.status = PairStatus::WaitingBundle { code, setup };
            }
        }
        UiEvent::PairPeerIncoming {
            device_name,
            device_id,
            sas,
            decision_tx,
        } => {
            app.pair_decision_tx = Some(decision_tx);
            if let Some(Modal::Pair(ref mut p)) = app.modal {
                p.status = PairStatus::ConfirmPeer {
                    device_name,
                    device_id,
                    sas,
                };
            }
        }
        UiEvent::PairFinished(res) => {
            app.pair_abort = None;
            app.pair_decision_tx = None;
            match res {
                Ok((name, device_id)) => {
                    app.set_toast(true, format!("Added {name} ({device_id})"));
                    if let Some(Modal::Pair(ref mut p)) = app.modal {
                        p.status = PairStatus::Added { name, device_id };
                    }
                }
                Err(err) => {
                    app.set_toast(false, format!("Pairing failed: {err}"));
                    if let Some(Modal::Pair(ref mut p)) = app.modal {
                        p.status = PairStatus::Failed(err);
                    }
                }
            }
        }
        UiEvent::OnboardingPinProbed(res) => {
            if let Some(Modal::OnboardingForm(ref mut ob)) = app.modal {
                match res {
                    Ok((coord_url, pin)) => {
                        ob.step = OnboardingStep::TofuConfirm { coord_url, pin };
                    }
                    Err(err) => {
                        ob.step = OnboardingStep::Form;
                        ob.error = Some(format!("Failed to probe coord: {err}"));
                    }
                }
            }
        }
        UiEvent::OnboardingDone {
            account_id,
            recovery_code,
        } => {
            app.local = LocalSnapshot::load(data_dir);
            if let Some(code) = recovery_code {
                if let Some(Modal::OnboardingForm(ref mut ob)) = app.modal {
                    ob.step = OnboardingStep::RecoveryBackup {
                        account_id,
                        recovery_code: code,
                    };
                }
            } else {
                app.close_modal();
                app.set_toast(
                    true,
                    format!("Joined account {account_id} — start TUN or Session Mode to connect"),
                );
                spawn_refresh_devices(data_dir.to_path_buf(), ev_tx.clone());
            }
        }
        UiEvent::OnboardingFailed(err) => {
            if let Some(Modal::OnboardingForm(ref mut ob)) = app.modal {
                ob.step = OnboardingStep::Form;
                ob.error = Some(err);
            }
        }
        UiEvent::DoctorUpdate(report) => {
            if let Some(Modal::Doctor(ref mut d)) = app.modal {
                d.report = report;
            }
        }
        UiEvent::DoctorError(err) => {
            app.set_toast(false, format!("Doctor error: {err}"));
        }
        UiEvent::LogsLoaded(lines) => {
            if let Some(Modal::Logs(ref mut l)) = app.modal {
                l.lines = lines;
            }
        }
        UiEvent::SettingsPinProbed(res) => {
            if let Some(Modal::Settings(ref mut s)) = app.modal {
                s.probing_pin = false;
                match res {
                    Ok(pin) => {
                        s.coord_pin = state::TextField::new("32-char base32 TLS pin").with_value(pin);
                        s.error = None;
                        app.set_toast(true, "Probed coord TLS pin — press Save to apply");
                    }
                    Err(err) => {
                        s.error = Some(format!("Pin probe failed: {err}"));
                    }
                }
            }
        }
        UiEvent::RevokeFinished(res) => match res {
            Ok(msg) => {
                app.close_modal();
                app.set_toast(true, msg);
            }
            Err(err) => {
                if let Some(Modal::RevokeConfirm(ref mut r)) = app.modal {
                    r.busy = false;
                    r.error = Some(err);
                } else {
                    app.set_toast(false, format!("Revoke failed: {err}"));
                }
            }
        },
        UiEvent::Key(_) | UiEvent::Mouse(_) | UiEvent::Paste(_) | UiEvent::Resize => {}
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
            Ok(stream) => {
                match tokio_tungstenite::client_async("ws://localhost/v1/events", stream).await {
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
                                        Some(Ok(WsMessage::Close(_))) | None | Some(Err(_)) => {
                                            let _ = tx.send(UiEvent::WsDisconnected);
                                            break;
                                        }
                                        Some(Ok(_)) => {}
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => {
                        let _ = tx.send(UiEvent::WsDisconnected);
                    }
                }
            }
            Err(_) => {
                let _ = tx.send(UiEvent::WsDisconnected);
            }
        }
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = tokio::time::sleep(Duration::from_millis(800)) => {}
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

async fn uptime_poll_loop(
    data_dir: PathBuf,
    tx: mpsc::UnboundedSender<UiEvent>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        if *shutdown.borrow() {
            break;
        }
        let client = ControlClient::new(&data_dir);
        if let Ok(v) = client.get("/healthz").await {
            let _ = tx.send(UiEvent::UptimeUpdated(v["uptime_s"].as_u64()));
        }
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::DeviceRow;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
    use ratatui::Terminal;
    use state::{
        merge_peers, AppMode, FocusArea, HitTarget, LocalServiceSnapshot, OnboardingChoice,
        PeerServiceSnapshot, PeerSnapshot, TunSnapshot,
    };

    fn render_string(app: &mut AppState, w: u16, h: u16) -> String {
        let backend = TestBackend::new(w, h);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| view::draw_ui(f, app)).unwrap();
        let buf = terminal.backend().buffer();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn sample_live_app(kind: ThemeKind) -> AppState {
        let local = LocalSnapshot {
            device_id: "me11223344556677".into(),
            device_name: "workstation".into(),
            account_user_id: Some("acct_test".into()),
            coord_url: "https://1.2.3.4:7722".into(),
            uptime_s: Some(3725),
            service_status: "systemd installed=true active=active".into(),
            ..Default::default()
        };

        let mut app = AppState::new(kind, &prefs::ConsolePrefs::default(), local);
        app.ws_connected = true;
        app.status = StatusSnapshot {
            account: "acct_test".into(),
            device_id: "me11223344556677".into(),
            device_name: "workstation".into(),
            dns_name: Some("workstation".into()),
            virtual_ip: Some("100.64.0.1".into()),
            tun: TunSnapshot {
                enabled: true,
                interface: Some("topaz0".into()),
                cidr: "100.64.0.0/10".into(),
                mtu: 1280,
                dns_listen: Some("100.64.0.1:53".into()),
                error: None,
            },
            connection: Some("direct".into()),
            peers: vec![PeerSnapshot {
                device_id: "p1aabbccddeeff00".into(),
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
        app.devices = vec![
            DeviceRow {
                device_id: "me11223344556677".into(),
                name: "workstation".into(),
                dns_name: Some("workstation".into()),
                virtual_ip: Some("100.64.0.1".into()),
                status: "active".into(),
                issuer: "recovery code".into(),
                me: true,
            },
            DeviceRow {
                device_id: "p1aabbccddeeff00".into(),
                name: "macbook".into(),
                dns_name: Some("macbook".into()),
                virtual_ip: Some("100.64.0.2".into()),
                status: "active".into(),
                issuer: "me11223344556677".into(),
                me: false,
            },
            DeviceRow {
                device_id: "p299887766554433".into(),
                name: "nas".into(),
                dns_name: Some("nas".into()),
                virtual_ip: Some("100.64.0.3".into()),
                status: "active".into(),
                issuer: "me11223344556677".into(),
                me: false,
            },
        ];
        app.reconcile_selection();
        app
    }

    #[test]
    fn merges_live_peers_and_offline_devices_with_filter() {
        let app = sample_live_app(ThemeKind::Ink);
        let all = merge_peers(&app.status, &app.devices, "");
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].name, "macbook");
        assert_eq!(all[1].name, "nas");
        assert_eq!(all[1].path, None);

        let by_service = merge_peers(&app.status, &app.devices, "jade");
        assert_eq!(by_service.len(), 1);
        assert_eq!(by_service[0].name, "macbook");
    }

    #[test]
    fn renders_onboarding_standby_and_live_across_all_themes() {
        for kind in [ThemeKind::Ink, ThemeKind::TokyoNight, ThemeKind::Light] {
            // 1. Onboarding mode (no account)
            let local = LocalSnapshot {
                device_id: "newdev1234567890".into(),
                ..Default::default()
            };
            let mut ob = AppState::new(kind, &prefs::ConsolePrefs::default(), local);
            assert_eq!(ob.mode(), AppMode::Onboarding);
            let out_ob = render_string(&mut ob, 100, 30);
            assert!(out_ob.contains("Pair with Phrase"));
            assert!(out_ob.contains("Create New Account"));
            assert!(ob
                .hit_regions
                .iter()
                .any(|h| h.target == HitTarget::OnboardingPick(OnboardingChoice::JoinPhrase)));

            // 2. Standby mode (account exists, daemon stopped)
            let mut st = sample_live_app(kind);
            st.ws_connected = false;
            st.status = StatusSnapshot::default();
            assert_eq!(st.mode(), AppMode::Standby);
            let out_st = render_string(&mut st, 110, 32);
            assert!(out_st.contains("standby"));
            assert!(out_st.contains("Start VPN (TUN)"));

            // 3. Live mode (This Device + Peer detail + offline peer shows `offline` not `active`)
            let mut live = sample_live_app(kind);
            assert_eq!(live.mode(), AppMode::Live);
            let out_self = render_string(&mut live, 110, 32);
            assert!(out_self.contains("topaz0"));
            assert!(out_self.contains("100.64.0.1"));
            assert!(out_self.contains("offline"));

            // Select peer `macbook`
            live.select_sidebar_index(1);
            let out_peer = render_string(&mut live, 110, 32);
            assert!(out_peer.contains("macbook"));
            assert!(out_peer.contains("DIRECT"));
            assert!(out_peer.contains("100.64.0.2"));
            assert!(out_peer.contains("jade"));
            // Verify internal debug jargon was removed
            assert!(!out_peer.contains("service 4 discovery"));
            assert!(!out_peer.contains("ready via control.sock"));
        }
    }

    #[test]
    fn surfaces_tun_error_instead_of_claiming_no_tun() {
        let mut live = sample_live_app(ThemeKind::Ink);
        live.status.tun.enabled = false;
        live.status.tun.interface = None;
        live.status.tun.error = Some("Operation not permitted (/dev/net/tun)".into());
        let out = render_string(&mut live, 110, 32);
        assert!(out.contains("TUN err"));
        assert!(out.contains("Operation not permitted"));
    }

    #[tokio::test]
    async fn modern_keyboard_and_mouse_interactions_work() {
        let mut app = sample_live_app(ThemeKind::Ink);
        let dir = std::env::temp_dir().join("topaz-tui-test-dir");
        let (tx, _rx) = mpsc::unbounded_channel();

        // Render once so hit_regions are populated
        let _ = render_string(&mut app, 110, 32);

        // Mouse click on second row (peer `macbook`, sidebar idx 1)
        let peer_region = app
            .hit_regions
            .iter()
            .find(|h| h.target == HitTarget::SelectSidebarRow(1))
            .expect("peer row hit region")
            .rect;
        let down = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: peer_region.x + 1,
            row: peer_region.y,
            modifiers: KeyModifiers::NONE,
        };
        let up = MouseEvent {
            kind: MouseEventKind::Up(MouseButton::Left),
            column: peer_region.x + 1,
            row: peer_region.y,
            modifiers: KeyModifiers::NONE,
        };
        mouse::handle_mouse(&mut app, down, &dir, &tx);
        mouse::handle_mouse(&mut app, up, &dir, &tx);
        assert_eq!(app.selected_idx, 1);

        // Modern shortcut Ctrl+F opens inline filter
        input::handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('f'), KeyModifiers::CONTROL),
            &dir,
            &tx,
        );
        assert!(app.filter_open);
        assert_eq!(app.focus, FocusArea::Filter);

        // Paste into filter
        input::handle_paste(&mut app, "nas");
        assert_eq!(app.filter.value, "nas");
        assert_eq!(app.filtered_peers().len(), 1);

        // Esc clears filter
        input::handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
            &dir,
            &tx,
        );
        assert!(!app.filter_open);
        assert!(app.filter.value.is_empty());

        // Ctrl+N opens unified Pair modal & renders cleanly
        input::handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('n'), KeyModifiers::CONTROL),
            &dir,
            &tx,
        );
        assert!(matches!(app.modal, Some(Modal::Pair(_))));
        let pair_out = render_string(&mut app, 110, 32);
        assert!(pair_out.contains("Phrase Pairing"));
        assert!(pair_out.contains("Setup Bundle"));

        // Sudo password modal renders masked password & command preview
        app.modal = Some(Modal::SudoPrompt(SudoModal::new(&dir, false)));
        input::handle_paste(&mut app, "secret123");
        let sudo_out = render_string(&mut app, 110, 32);
        assert!(sudo_out.contains("Administrator Password"));
        assert!(sudo_out.contains("•••••••••"));
        assert!(!sudo_out.contains("secret123"));

        // Wrong sudo password keeps modal open, clears password, and displays inline error
        handle_ui_event(
            &mut app,
            UiEvent::SudoResult(Err(ElevationError::IncorrectPassword)),
            &dir,
            &tx,
        );
        if let Some(Modal::SudoPrompt(ref s)) = app.modal {
            assert!(s.password.value.is_empty());
            assert!(s.error.as_deref().unwrap_or("").contains("Incorrect password"));
        } else {
            panic!("expected SudoPrompt to stay open on wrong password");
        }
        app.close_modal();
    }

    #[tokio::test]
    async fn renders_all_modals_and_handles_narrow_layout_and_divider_drag() {
        let mut app = sample_live_app(ThemeKind::TokyoNight);
        let dir = std::env::temp_dir().join(format!("topaz-tui-modals-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (tx, _rx) = mpsc::unbounded_channel();

        // 1. Narrow screen: starts in list view, click peer enters detail, click Back returns
        let narrow_list = render_string(&mut app, 60, 22);
        assert!(narrow_list.contains("Devices"));
        assert!(narrow_list.contains("macbook"));
        assert!(!app.narrow_showing_detail);

        let peer_rect = app
            .hit_regions
            .iter()
            .find(|h| h.target == HitTarget::SelectSidebarRow(1))
            .expect("narrow peer row")
            .rect;
        mouse::handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: peer_rect.x + 1,
                row: peer_rect.y,
                modifiers: KeyModifiers::NONE,
            },
            &dir,
            &tx,
        );
        mouse::handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Up(MouseButton::Left),
                column: peer_rect.x + 1,
                row: peer_rect.y,
                modifiers: KeyModifiers::NONE,
            },
            &dir,
            &tx,
        );
        assert!(app.narrow_showing_detail);
        let narrow_detail = render_string(&mut app, 60, 22);
        assert!(narrow_detail.contains("← Devices"));
        assert!(narrow_detail.contains("macbook"));

        // 2. Wide screen divider drag-resize
        app.narrow_showing_detail = false;
        let _ = render_string(&mut app, 110, 32);
        let dx = app.divider.x.expect("divider x");
        mouse::handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: dx,
                row: 5,
                modifiers: KeyModifiers::NONE,
            },
            &dir,
            &tx,
        );
        assert!(app.divider.dragging);
        mouse::handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Drag(MouseButton::Left),
                column: 44,
                row: 5,
                modifiers: KeyModifiers::NONE,
            },
            &dir,
            &tx,
        );
        mouse::handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Up(MouseButton::Left),
                column: 44,
                row: 5,
                modifiers: KeyModifiers::NONE,
            },
            &dir,
            &tx,
        );
        assert!(!app.divider.dragging);
        assert_eq!(app.divider.width_override, Some(44));

        // 3. Interactive phrase pairing incoming approval
        actions::open_pair_modal(&mut app);
        let (d_tx, mut d_rx) = tokio::sync::oneshot::channel();
        handle_ui_event(
            &mut app,
            UiEvent::PairPeerIncoming {
                device_name: "ipad".into(),
                device_id: "aa11bb22cc33dd44".into(),
                sas: "482-917".into(),
                decision_tx: d_tx,
            },
            &dir,
            &tx,
        );
        let confirm_out = render_string(&mut app, 110, 32);
        assert!(confirm_out.contains("Approve Device"));
        assert!(confirm_out.contains("ipad"));
        input::handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &dir,
            &tx,
        );
        assert_eq!(d_rx.try_recv(), Ok(true));
        app.close_modal();

        // 4. Doctor, Logs, Settings, Revoke, Palette, StopConfirm, Help modals all render cleanly
        actions::open_doctor_modal(&mut app, &dir, &tx);
        assert!(render_string(&mut app, 110, 32).contains("Network Doctor"));

        actions::open_logs_modal(&mut app, &dir, &tx);
        handle_ui_event(
            &mut app,
            UiEvent::LogsLoaded(vec![
                "INFO topaz engine ready".into(),
                "WARN relay fallback active".into(),
                "ERROR tun open failed".into(),
            ]),
            &dir,
            &tx,
        );
        let log_out = render_string(&mut app, 110, 32);
        assert!(log_out.contains("Daemon Logs"));
        assert!(log_out.contains("tun open failed"));

        actions::open_settings_modal(&mut app, &dir, &tx);
        let set_out = render_string(&mut app, 110, 32);
        assert!(set_out.contains("Settings & Autostart"));
        assert!(set_out.contains("Force Relay"));

        app.close_modal();
        app.select_sidebar_index(1);
        actions::prompt_revoke_selected(&mut app);
        let rev_out = render_string(&mut app, 110, 32);
        assert!(rev_out.contains("Confirm Device Revocation"));

        actions::open_palette(&mut app);
        assert!(render_string(&mut app, 110, 32).contains("Command Palette"));

        app.modal = Some(Modal::StopConfirm);
        assert!(render_string(&mut app, 110, 32).contains("Stop Topaz Daemon"));

        app.modal = Some(Modal::Help);
        assert!(render_string(&mut app, 110, 32).contains("Keyboard & Mouse Shortcuts"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
