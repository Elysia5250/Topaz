//! Unified action dispatcher & background task spawners shared by keyboard,
//! mouse hit-regions, command palette, and modal buttons.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use crate::client::ControlClient;
use crate::doctor::{run_doctor, DoctorReport};
use crate::ops::{
    coord_client, coord_short_host, create_account_direct, join_with_phrase_direct,
    join_with_recovery_direct, join_with_setup_bundle, join_with_short_code, list_devices_direct,
    normalize_coord_arg, revoke_device_direct, save_config_values, setup_bundle, DeviceRow,
};
use crate::run::{
    is_elevated, read_log_tail, spawn_detached_elevated, spawn_detached_quiet, stop_daemon_quiet,
    sudo_cached, ElevationError,
};
use crate::service;

use super::clipboard;
use super::state::{
    AppMode, AppState, DetailButton, DoctorModal, FocusArea, HitTarget, LocalSnapshot, LogFilter,
    LogsModal, Modal, OnboardingChoice, OnboardingModal, OnboardingStep, PairModal, PairStatus,
    PairTab, PaletteAction, RevokeModal, SettingsModal, UiEvent, NARROW_WIDTH,
};

pub fn spawn_refresh_devices(data_dir: PathBuf, tx: mpsc::UnboundedSender<UiEvent>) {
    tokio::spawn(async move {
        let client = ControlClient::new(&data_dir);
        if let Ok(v) = client.get("/v1/devices").await {
            if let Some(arr) = v.get("devices").cloned() {
                if let Ok(rows) = serde_json::from_value::<Vec<DeviceRow>>(arr) {
                    let _ = tx.send(UiEvent::DevicesUpdated(rows));
                    return;
                }
            }
        }
        // Fallback when daemon is in Standby: fetch directly from coord if configured.
        if let Ok((_, rows)) = list_devices_direct(&data_dir).await {
            let _ = tx.send(UiEvent::DevicesUpdated(rows));
        }
    });
}

pub fn spawn_refresh_local(data_dir: PathBuf, tx: mpsc::UnboundedSender<UiEvent>) {
    tokio::spawn(async move {
        let snap = tokio::task::spawn_blocking(move || LocalSnapshot::load(&data_dir))
            .await
            .unwrap_or_default();
        let _ = tx.send(UiEvent::LocalRefreshed(snap));
    });
}

pub fn spawn_kick(data_dir: PathBuf, announce: bool, tx: mpsc::UnboundedSender<UiEvent>) {
    tokio::spawn(async move {
        let client = ControlClient::new(&data_dir);
        let path = format!("/v1/kick?announce={announce}");
        let res = client.post(&path, None).await;
        let _ = tx.send(match res {
            Ok(_) => UiEvent::ActionResult {
                ok: true,
                message: if announce {
                    "Probed peers (announced)".into()
                } else {
                    "Probed peers (local)".into()
                },
            },
            Err(e) => UiEvent::ActionResult {
                ok: false,
                message: format!("Probe failed: {e}"),
            },
        });
    });
}

pub fn request_start_tun(
    app: &mut AppState,
    restart_first: bool,
    data_dir: &Path,
    tx: &mpsc::UnboundedSender<UiEvent>,
) {
    if is_elevated() {
        spawn_start_daemon(
            data_dir.to_path_buf(),
            false,
            restart_first,
            app.local.force_relay,
            None,
            tx.clone(),
        );
        app.busy_banner = Some("Starting VPN TUN daemon…".into());
        return;
    }

    let dir = data_dir.to_path_buf();
    let force_relay = app.local.force_relay;
    let tx = tx.clone();
    app.busy_banner = Some("Checking sudo session…".into());
    tokio::spawn(async move {
        if sudo_cached().await {
            if restart_first {
                let _ = stop_daemon_quiet(&dir).await;
            }
            let vpn_cfg = topaz_vpn::VpnConfig::default();
            match spawn_detached_elevated(dir, force_relay, true, vpn_cfg, None).await {
                Ok(msg) => {
                    let _ = tx.send(UiEvent::DaemonStarted {
                        ok: true,
                        message: msg,
                    });
                }
                Err(ElevationError::PasswordRequired | ElevationError::IncorrectPassword) => {
                    let _ = tx.send(UiEvent::NeedSudoPrompt { restart_first });
                }
                Err(ElevationError::Failed(err)) => {
                    let _ = tx.send(UiEvent::DaemonStarted {
                        ok: false,
                        message: err,
                    });
                }
            }
        } else {
            let _ = tx.send(UiEvent::NeedSudoPrompt { restart_first });
        }
    });
}

pub fn start_no_tun(
    app: &mut AppState,
    restart_first: bool,
    data_dir: &Path,
    tx: &mpsc::UnboundedSender<UiEvent>,
) {
    app.busy_banner = Some(if restart_first {
        "Restarting in session mode (--no-tun)…".into()
    } else {
        "Starting session mode (--no-tun)…".into()
    });
    spawn_start_daemon(
        data_dir.to_path_buf(),
        true,
        restart_first,
        app.local.force_relay,
        None,
        tx.clone(),
    );
}

fn spawn_start_daemon(
    data_dir: PathBuf,
    no_tun: bool,
    restart_first: bool,
    force_relay: bool,
    password: Option<String>,
    tx: mpsc::UnboundedSender<UiEvent>,
) {
    tokio::spawn(async move {
        if restart_first {
            if let Err(e) = stop_daemon_quiet(&data_dir).await {
                let _ = tx.send(UiEvent::DaemonStarted {
                    ok: false,
                    message: format!("Failed to stop existing daemon: {e}"),
                });
                return;
            }
        }
        let vpn_cfg = topaz_vpn::VpnConfig {
            disabled: no_tun,
            ..Default::default()
        };
        if no_tun {
            match spawn_detached_quiet(data_dir, None, force_relay, true, vpn_cfg).await {
                Ok(_) => {
                    let _ = tx.send(UiEvent::DaemonStarted {
                        ok: true,
                        message: "Session daemon started (--no-tun)".into(),
                    });
                }
                Err(e) => {
                    let _ = tx.send(UiEvent::DaemonStarted {
                        ok: false,
                        message: e.to_string(),
                    });
                }
            }
        } else {
            match spawn_detached_elevated(data_dir, force_relay, true, vpn_cfg, password).await {
                Ok(_) => {
                    let _ = tx.send(UiEvent::DaemonStarted {
                        ok: true,
                        message: "VPN TUN daemon started".into(),
                    });
                }
                Err(e) => {
                    let _ = tx.send(UiEvent::DaemonStarted {
                        ok: false,
                        message: e.to_string(),
                    });
                }
            }
        }
    });
}

pub fn submit_sudo_password(
    app: &mut AppState,
    data_dir: &Path,
    tx: &mpsc::UnboundedSender<UiEvent>,
) {
    let Some(Modal::SudoPrompt(ref mut sudo)) = app.modal else {
        return;
    };
    if sudo.busy {
        return;
    }
    if sudo.password.value.is_empty() {
        sudo.error = Some("Please enter your sudo password".into());
        return;
    }
    let pw = sudo.password.value.clone();
    sudo.password.zeroize_clear();
    sudo.busy = true;
    sudo.error = None;
    let restart_first = sudo.restart_first;
    let force_relay = app.local.force_relay;
    let dir = data_dir.to_path_buf();
    let tx = tx.clone();

    tokio::spawn(async move {
        if restart_first {
            // Only stop the existing daemon AFTER sudo auth succeeds? Better: validate password first
            // by running `sudo -S -v` so a wrong password never drops the user's running session!
            let validated = validate_sudo_password(&pw).await;
            if let Err(e) = validated {
                let _ = tx.send(UiEvent::SudoResult(Err(e)));
                return;
            }
            if let Err(e) = stop_daemon_quiet(&dir).await {
                let _ = tx.send(UiEvent::SudoResult(Err(ElevationError::Failed(format!(
                    "failed to stop previous daemon: {e}"
                )))));
                return;
            }
            let vpn_cfg = topaz_vpn::VpnConfig::default();
            let res = spawn_detached_elevated(dir, force_relay, true, vpn_cfg, Some(pw)).await;
            let _ = tx.send(UiEvent::SudoResult(res));
        } else {
            let vpn_cfg = topaz_vpn::VpnConfig::default();
            let res = spawn_detached_elevated(dir, force_relay, true, vpn_cfg, Some(pw)).await;
            let _ = tx.send(UiEvent::SudoResult(res));
        }
    });
}

async fn validate_sudo_password(pw: &str) -> std::result::Result<(), ElevationError> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;

    let mut child = tokio::process::Command::new("sudo")
        .env("LC_ALL", "C")
        .args(["-S", "-p", "", "-v"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ElevationError::Failed(format!("failed to invoke sudo: {e}")))?;

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(pw.as_bytes()).await;
        let _ = stdin.write_all(b"\n").await;
        let _ = stdin.flush().await;
    }
    let out = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .map_err(|_| ElevationError::Failed("sudo validation timed out".into()))?
        .map_err(|e| ElevationError::Failed(format!("sudo wait failed: {e}")))?;
    if out.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let lower = stderr.to_ascii_lowercase();
        if lower.contains("incorrect password")
            || lower.contains("sorry, try again")
            || lower.contains("authentication failure")
        {
            Err(ElevationError::IncorrectPassword)
        } else if !stderr.is_empty() {
            Err(ElevationError::Failed(stderr))
        } else {
            Err(ElevationError::IncorrectPassword)
        }
    }
}

pub fn spawn_stop_daemon(data_dir: PathBuf, tx: mpsc::UnboundedSender<UiEvent>) {
    tokio::spawn(async move {
        match stop_daemon_quiet(&data_dir).await {
            Ok(true) => {
                let _ = tx.send(UiEvent::ActionResult {
                    ok: true,
                    message: "Topaz daemon stopped".into(),
                });
            }
            Ok(false) => {
                let _ = tx.send(UiEvent::ActionResult {
                    ok: true,
                    message: "Daemon was not running".into(),
                });
            }
            Err(e) => {
                let _ = tx.send(UiEvent::ActionResult {
                    ok: false,
                    message: format!("Stop failed: {e}"),
                });
            }
        }
    });
}

pub fn open_pair_modal(app: &mut AppState) {
    if app.mode() == AppMode::Onboarding {
        app.set_toast(false, "Join or create an account first");
        return;
    }
    app.cancel_pair_task();
    app.modal = Some(Modal::Pair(PairModal::new()));
}

pub fn switch_pair_tab(
    app: &mut AppState,
    tab: PairTab,
    data_dir: &Path,
    tx: &mpsc::UnboundedSender<UiEvent>,
) {
    app.cancel_pair_task();
    let Some(Modal::Pair(ref mut pair)) = app.modal else {
        return;
    };
    pair.tab = tab;
    match tab {
        PairTab::Phrase => {
            pair.status = PairStatus::Idle;
        }
        PairTab::Bundle => {
            pair.status = PairStatus::Starting;
            spawn_bundle_pair(app, data_dir, tx);
        }
    }
}

pub fn start_phrase_pair(
    app: &mut AppState,
    data_dir: &Path,
    tx: &mpsc::UnboundedSender<UiEvent>,
) {
    let phrase = match &app.modal {
        Some(Modal::Pair(p)) => p.phrase.value.clone(),
        _ => return,
    };
    let clean = match topaz_net::normalize_secret(&phrase) {
        Ok(c) => c,
        Err(e) => {
            if let Some(Modal::Pair(ref mut p)) = app.modal {
                p.status = PairStatus::Failed(e.to_string());
            }
            return;
        }
    };

    let host = coord_short_host(&app.local.coord_url);
    let peer_cmd = if host.is_empty() {
        format!("topaz pair <server-ip> {clean}")
    } else {
        format!("topaz pair {host} {clean}")
    };

    app.cancel_pair_task();
    if let Some(Modal::Pair(ref mut p)) = app.modal {
        p.status = PairStatus::WaitingPhrase {
            phrase: clean.clone(),
            peer_cmd,
        };
    }

    let dir = data_dir.to_path_buf();
    let tx = tx.clone();
    let handle = tokio::spawn(async move {
        let (coord, identity, account) = match topaz_core::Store::open(dir.clone()) {
            Ok(store) => {
                let acct = match store.require_account() {
                    Ok(a) => a.clone(),
                    Err(e) => {
                        let _ = tx.send(UiEvent::PairFinished(Err(e.to_string())));
                        return;
                    }
                };
                match coord_client(&store) {
                    Ok(c) => (c, store.identity.clone(), acct),
                    Err(e) => {
                        let _ = tx.send(UiEvent::PairFinished(Err(e.to_string())));
                        return;
                    }
                }
            }
            Err(e) => {
                let _ = tx.send(UiEvent::PairFinished(Err(e.to_string())));
                return;
            }
        };

        let pending = match topaz_net::wait_secret_pair_request(&coord, &identity, &account, &clean)
            .await
        {
            Ok(p) => p,
            Err(e) => {
                let _ = tx.send(UiEvent::PairFinished(Err(e.to_string())));
                return;
            }
        };

        let (decision_tx, decision_rx) = oneshot::channel::<bool>();
        let _ = tx.send(UiEvent::PairPeerIncoming {
            device_name: pending.device_name.clone(),
            device_id: pending.device_id.clone(),
            sas: pending.sas.clone(),
            decision_tx,
        });

        match decision_rx.await {
            Ok(true) => match pending.approve().await {
                Ok(cert) => {
                    let _ = tx.send(UiEvent::PairFinished(Ok((cert.name, cert.device_id))));
                    let _ = ControlClient::new(&dir).post("/v1/kick?announce=true", None).await;
                    spawn_refresh_devices(dir, tx);
                }
                Err(e) => {
                    let _ = tx.send(UiEvent::PairFinished(Err(e.to_string())));
                }
            },
            _ => {
                let _ = tx.send(UiEvent::PairFinished(Err("Pairing rejected".into())));
            }
        }
    });
    app.pair_abort = Some(handle.abort_handle());
}

fn spawn_bundle_pair(
    app: &mut AppState,
    data_dir: &Path,
    tx: &mpsc::UnboundedSender<UiEvent>,
) {
    let dir = data_dir.to_path_buf();
    let tx = tx.clone();
    let handle = tokio::spawn(async move {
        // Use daemon API if live, otherwise direct coord approval.
        if let Some(client) = ControlClient::try_daemon(&dir).await {
            match client.post("/v1/devices/add", None).await {
                Ok(v) => {
                    let code = v["code"].as_str().unwrap_or_default().to_string();
                    let setup = v["setup"].as_str().unwrap_or_default().to_string();
                    let _ = tx.send(UiEvent::PairCodeReady {
                        code: code.clone(),
                        setup,
                    });
                    match client
                        .get_with_timeout(&format!("/v1/devices/add/{code}"), Duration::from_secs(330))
                        .await
                    {
                        Ok(done) => {
                            let name = done["name"].as_str().unwrap_or("?").to_string();
                            let id = done["device_id"].as_str().unwrap_or("?").to_string();
                            let _ = tx.send(UiEvent::PairFinished(Ok((name, id))));
                            spawn_refresh_devices(dir, tx);
                        }
                        Err(e) => {
                            let _ = tx.send(UiEvent::PairFinished(Err(e.to_string())));
                        }
                    }
                    return;
                }
                Err(e) => {
                    let _ = tx.send(UiEvent::PairFinished(Err(e.to_string())));
                    return;
                }
            }
        }

        // Offline / Standby direct path
        let store = match topaz_core::Store::open(dir.clone()) {
            Ok(s) => s,
            Err(e) => {
                let _ = tx.send(UiEvent::PairFinished(Err(e.to_string())));
                return;
            }
        };
        let account = match store.require_account() {
            Ok(a) => a.clone(),
            Err(e) => {
                let _ = tx.send(UiEvent::PairFinished(Err(e.to_string())));
                return;
            }
        };
        let coord = match coord_client(&store) {
            Ok(c) => c,
            Err(e) => {
                let _ = tx.send(UiEvent::PairFinished(Err(e.to_string())));
                return;
            }
        };
        let tx_code = tx.clone();
        match topaz_net::approve_new_device(&coord, &store.identity, &account, |code| {
            let setup = setup_bundle(&store, code);
            let _ = tx_code.send(UiEvent::PairCodeReady {
                code: code.to_string(),
                setup,
            });
        })
        .await
        {
            Ok(cert) => {
                let _ = tx.send(UiEvent::PairFinished(Ok((cert.name, cert.device_id))));
                spawn_refresh_devices(dir, tx);
            }
            Err(e) => {
                let _ = tx.send(UiEvent::PairFinished(Err(e.to_string())));
            }
        }
    });
    app.pair_abort = Some(handle.abort_handle());
}

pub fn open_onboarding_form(app: &mut AppState, choice: OnboardingChoice) {
    app.modal = Some(Modal::OnboardingForm(OnboardingModal::new(
        choice,
        &app.local,
    )));
}

pub fn submit_onboarding_form(
    app: &mut AppState,
    data_dir: &Path,
    tx: &mpsc::UnboundedSender<UiEvent>,
) {
    let Some(Modal::OnboardingForm(ref mut ob)) = app.modal else {
        return;
    };
    if ob.step != OnboardingStep::Form {
        return;
    }
    ob.error = None;

    let kind = ob.kind;
    let coord_raw = ob.coord_url.value.trim().to_string();
    let pin_raw = ob.coord_pin.value.trim().to_string();
    let secret = ob.secret.value.trim().to_string();
    let dev_name = ob.device_name.value.trim().to_string();

    match kind {
        OnboardingChoice::JoinBundle => {
            if secret.is_empty() {
                ob.error = Some("Paste a `topaz-setup:v1:...` bundle or short code".into());
                return;
            }
            ob.step = OnboardingStep::Submitting("Joining account…".into());
            let dir = data_dir.to_path_buf();
            let tx = tx.clone();
            tokio::spawn(async move {
                let name_opt = (!dev_name.is_empty()).then_some(dev_name.as_str());
                let res = if secret.starts_with("topaz-setup:v1:")
                    || secret.trim_matches(|c| c == '\'' || c == '"').starts_with("topaz-setup:v1:")
                {
                    join_with_setup_bundle(&dir, &secret, name_opt).await
                } else {
                    join_with_short_code(&dir, None, None, &secret, name_opt).await
                };
                match res {
                    Ok(info) => {
                        let _ = tx.send(UiEvent::OnboardingDone {
                            account_id: info.user_id,
                            recovery_code: None,
                        });
                    }
                    Err(e) => {
                        let _ = tx.send(UiEvent::OnboardingFailed(e.to_string()));
                    }
                }
            });
            return;
        }
        OnboardingChoice::JoinPhrase => {
            if coord_raw.is_empty() {
                ob.error = Some("Enter the coord server IP or URL".into());
                return;
            }
            if let Err(e) = topaz_net::normalize_secret(&secret) {
                ob.error = Some(e.to_string());
                return;
            }
        }
        OnboardingChoice::CreateAccount => {
            if coord_raw.is_empty() {
                ob.error = Some("Enter the coord server IP or URL".into());
                return;
            }
            if secret.is_empty() {
                ob.error = Some("Enter the VPS invite code".into());
                return;
            }
        }
        OnboardingChoice::JoinRecovery => {
            if coord_raw.is_empty() {
                ob.error = Some("Enter the coord server IP or URL".into());
                return;
            }
            if secret.is_empty() {
                ob.error = Some("Enter your account recovery code".into());
                return;
            }
        }
    }

    let norm_url = normalize_coord_arg(&coord_raw);
    if !norm_url.starts_with("https://") {
        ob.error = Some(format!("Coord URL must start with https:// (got {norm_url})"));
        return;
    }

    let effective_pin = if !pin_raw.is_empty() {
        Some(pin_raw)
    } else if app.local.coord_url == norm_url && !app.local.coord_pin.is_empty() {
        Some(app.local.coord_pin.clone())
    } else {
        None
    };

    if let Some(pin) = effective_pin {
        execute_onboarding_with_pin(ob, norm_url, pin, data_dir, tx);
    } else {
        ob.step = OnboardingStep::ProbingPin;
        let tx = tx.clone();
        tokio::spawn(async move {
            match topaz_net::probe_coord_pin(&norm_url).await {
                Ok(pin) => {
                    let _ = tx.send(UiEvent::OnboardingPinProbed(Ok((norm_url, pin))));
                }
                Err(e) => {
                    let _ = tx.send(UiEvent::OnboardingPinProbed(Err(e.to_string())));
                }
            }
        });
    }
}

pub fn confirm_onboarding_tofu(
    app: &mut AppState,
    data_dir: &Path,
    tx: &mpsc::UnboundedSender<UiEvent>,
) {
    let Some(Modal::OnboardingForm(ref mut ob)) = app.modal else {
        return;
    };
    let OnboardingStep::TofuConfirm { coord_url, pin } = ob.step.clone() else {
        return;
    };
    ob.coord_url = super::state::TextField::new("").with_value(coord_url.clone());
    ob.coord_pin = super::state::TextField::new("").with_value(pin.clone());
    execute_onboarding_with_pin(ob, coord_url, pin, data_dir, tx);
}

fn execute_onboarding_with_pin(
    ob: &mut OnboardingModal,
    coord_url: String,
    pin: String,
    data_dir: &Path,
    tx: &mpsc::UnboundedSender<UiEvent>,
) {
    let kind = ob.kind;
    let secret = ob.secret.value.trim().to_string();
    let dev_name = ob.device_name.value.trim().to_string();
    ob.step = OnboardingStep::Submitting(match kind {
        OnboardingChoice::JoinPhrase => {
            format!("Waiting for existing device to approve phrase '{secret}'…")
        }
        OnboardingChoice::CreateAccount => "Creating account on coord…".into(),
        OnboardingChoice::JoinRecovery => "Joining account with recovery code…".into(),
        OnboardingChoice::JoinBundle => "Joining account…".into(),
    });

    let dir = data_dir.to_path_buf();
    let tx = tx.clone();
    tokio::spawn(async move {
        let name_opt = (!dev_name.is_empty()).then_some(dev_name.as_str());
        match kind {
            OnboardingChoice::JoinPhrase => {
                match join_with_phrase_direct(&dir, Some(&coord_url), Some(&pin), &secret, name_opt)
                    .await
                {
                    Ok(info) => {
                        let _ = tx.send(UiEvent::OnboardingDone {
                            account_id: info.user_id,
                            recovery_code: None,
                        });
                    }
                    Err(e) => {
                        let _ = tx.send(UiEvent::OnboardingFailed(e.to_string()));
                    }
                }
            }
            OnboardingChoice::CreateAccount => {
                match create_account_direct(&dir, &secret, Some(&coord_url), Some(&pin), name_opt)
                    .await
                {
                    Ok((info, recovery)) => {
                        let _ = tx.send(UiEvent::OnboardingDone {
                            account_id: info.user_id,
                            recovery_code: Some(recovery),
                        });
                    }
                    Err(e) => {
                        let _ = tx.send(UiEvent::OnboardingFailed(e.to_string()));
                    }
                }
            }
            OnboardingChoice::JoinRecovery => {
                match join_with_recovery_direct(
                    &dir,
                    Some(&coord_url),
                    Some(&pin),
                    &secret,
                    name_opt,
                )
                .await
                {
                    Ok(info) => {
                        let _ = tx.send(UiEvent::OnboardingDone {
                            account_id: info.user_id,
                            recovery_code: None,
                        });
                    }
                    Err(e) => {
                        let _ = tx.send(UiEvent::OnboardingFailed(e.to_string()));
                    }
                }
            }
            OnboardingChoice::JoinBundle => {}
        }
    });
}

pub fn open_doctor_modal(
    app: &mut AppState,
    data_dir: &Path,
    tx: &mpsc::UnboundedSender<UiEvent>,
) {
    app.modal = Some(Modal::Doctor(DoctorModal {
        report: DoctorReport::default(),
        scroll: 0,
        max_scroll: 0,
    }));
    spawn_doctor(data_dir.to_path_buf(), tx.clone());
}

pub fn spawn_doctor(data_dir: PathBuf, tx: mpsc::UnboundedSender<UiEvent>) {
    tokio::spawn(async move {
        let (prog_tx, mut prog_rx) = mpsc::unbounded_channel::<DoctorReport>();
        let forward_tx = tx.clone();
        let forwarder = tokio::spawn(async move {
            while let Some(rep) = prog_rx.recv().await {
                let _ = forward_tx.send(UiEvent::DoctorUpdate(rep));
            }
        });
        match run_doctor(&data_dir, Some(prog_tx)).await {
            Ok(final_rep) => {
                let _ = forwarder.await;
                let _ = tx.send(UiEvent::DoctorUpdate(final_rep));
            }
            Err(e) => {
                let _ = tx.send(UiEvent::DoctorError(e.to_string()));
            }
        }
    });
}

pub fn open_logs_modal(
    app: &mut AppState,
    data_dir: &Path,
    tx: &mpsc::UnboundedSender<UiEvent>,
) {
    let log_path = data_dir.join("topaz.log");
    app.modal = Some(Modal::Logs(LogsModal {
        lines: Vec::new(),
        filter: LogFilter::All,
        follow: true,
        scroll: 0,
        max_scroll: 0,
        log_path,
    }));
    spawn_reload_logs(data_dir.to_path_buf(), tx.clone());
}

pub fn spawn_reload_logs(data_dir: PathBuf, tx: mpsc::UnboundedSender<UiEvent>) {
    tokio::spawn(async move {
        let path = data_dir.join("topaz.log");
        let lines = tokio::task::spawn_blocking(move || {
            let tail = read_log_tail(&path, 300);
            if tail.is_empty() {
                Vec::new()
            } else {
                tail.lines().map(|l| l.to_string()).collect()
            }
        })
        .await
        .unwrap_or_default();
        let _ = tx.send(UiEvent::LogsLoaded(lines));
    });
}

pub fn open_settings_modal(app: &mut AppState, data_dir: &Path, tx: &mpsc::UnboundedSender<UiEvent>) {
    app.local = LocalSnapshot::load(data_dir);
    app.modal = Some(Modal::Settings(SettingsModal::from_local(&app.local)));
    spawn_refresh_local(data_dir.to_path_buf(), tx.clone());
}

pub fn probe_settings_pin(app: &mut AppState, tx: &mpsc::UnboundedSender<UiEvent>) {
    let Some(Modal::Settings(ref mut set)) = app.modal else {
        return;
    };
    let raw = set.coord_url.value.trim().to_string();
    if raw.is_empty() {
        set.error = Some("Enter a Coord Server URL first".into());
        return;
    }
    let url = normalize_coord_arg(&raw);
    set.probing_pin = true;
    set.error = None;
    let tx = tx.clone();
    tokio::spawn(async move {
        let res = topaz_net::probe_coord_pin(&url)
            .await
            .map_err(|e| e.to_string());
        let _ = tx.send(UiEvent::SettingsPinProbed(res));
    });
}

pub fn save_settings_modal(
    app: &mut AppState,
    data_dir: &Path,
    tx: &mpsc::UnboundedSender<UiEvent>,
) {
    let Some(Modal::Settings(ref mut set)) = app.modal else {
        return;
    };
    let res = save_config_values(
        data_dir,
        Some(&set.coord_url.value),
        Some(&set.coord_pin.value),
        Some(&set.device_name.value),
        Some(set.force_relay),
    );
    match res {
        Ok(()) => {
            app.local = LocalSnapshot::load(data_dir);
            let msg = if app.ws_connected {
                "Config saved — restart daemon to apply".to_string()
            } else {
                "Config saved".to_string()
            };
            app.close_modal();
            app.set_toast(true, msg);
            spawn_refresh_local(data_dir.to_path_buf(), tx.clone());
        }
        Err(e) => {
            set.error = Some(e.to_string());
        }
    }
}

pub fn spawn_install_autostart(
    data_dir: PathBuf,
    no_tun: bool,
    tx: mpsc::UnboundedSender<UiEvent>,
) {
    tokio::spawn(async move {
        let dir_for_local = data_dir.clone();
        let res = tokio::task::spawn_blocking(move || {
            let exe = std::env::current_exe()?;
            service::install(&exe, &data_dir, no_tun)
        })
        .await;
        match res {
            Ok(Ok(msg)) => {
                let _ = tx.send(UiEvent::ActionResult {
                    ok: true,
                    message: msg,
                });
            }
            Ok(Err(e)) => {
                let _ = tx.send(UiEvent::ActionResult {
                    ok: false,
                    message: format!("Autostart install failed: {e}"),
                });
            }
            Err(e) => {
                let _ = tx.send(UiEvent::ActionResult {
                    ok: false,
                    message: format!("Autostart task error: {e}"),
                });
            }
        }
        spawn_refresh_local(dir_for_local, tx);
    });
}

pub fn spawn_uninstall_autostart(data_dir: PathBuf, tx: mpsc::UnboundedSender<UiEvent>) {
    tokio::spawn(async move {
        let res = tokio::task::spawn_blocking(service::uninstall).await;
        match res {
            Ok(Ok(msg)) => {
                let _ = tx.send(UiEvent::ActionResult {
                    ok: true,
                    message: msg,
                });
            }
            Ok(Err(e)) => {
                let _ = tx.send(UiEvent::ActionResult {
                    ok: false,
                    message: format!("Autostart uninstall failed: {e}"),
                });
            }
            Err(e) => {
                let _ = tx.send(UiEvent::ActionResult {
                    ok: false,
                    message: format!("Autostart task error: {e}"),
                });
            }
        }
        spawn_refresh_local(data_dir, tx);
    });
}

pub fn prompt_revoke_selected(app: &mut AppState) {
    let Some(peer) = app.selected_peer() else {
        app.set_toast(false, "Select a peer device to revoke");
        return;
    };
    if peer.account_status != "active" {
        app.set_toast(false, format!("{} is already {}", peer.name, peer.account_status));
        return;
    }
    app.modal = Some(Modal::RevokeConfirm(RevokeModal::new(
        peer.device_id,
        peer.name,
    )));
}

pub fn submit_revoke_modal(
    app: &mut AppState,
    data_dir: &Path,
    tx: &mpsc::UnboundedSender<UiEvent>,
) {
    let Some(Modal::RevokeConfirm(ref mut rev)) = app.modal else {
        return;
    };
    if rev.busy {
        return;
    }
    let recovery = if rev.use_recovery {
        let code = rev.recovery.value.trim().to_string();
        if code.is_empty() {
            rev.error = Some("Enter your account recovery code".into());
            return;
        }
        Some(code)
    } else {
        None
    };
    rev.busy = true;
    rev.error = None;
    let device_id = rev.device_id.clone();
    let name = rev.name.clone();
    let dir = data_dir.to_path_buf();
    let tx = tx.clone();

    tokio::spawn(async move {
        let res = if let Some(ref rec) = recovery {
            revoke_device_direct(&dir, &device_id, Some(rec)).await
        } else if let Some(daemon) = ControlClient::try_daemon(&dir).await {
            daemon
                .post(&format!("/v1/devices/{device_id}/revoke"), None)
                .await
                .map(|_| ())
        } else {
            revoke_device_direct(&dir, &device_id, None).await
        };

        match res {
            Ok(()) => {
                let _ = tx.send(UiEvent::RevokeFinished(Ok(format!(
                    "Revoked {name} ({device_id})"
                ))));
                spawn_refresh_devices(dir, tx);
            }
            Err(e) => {
                let _ = tx.send(UiEvent::RevokeFinished(Err(e.to_string())));
            }
        }
    });
}

pub fn copy_selected_peer_dns(app: &mut AppState) {
    let Some(peer) = app.selected_peer() else {
        if let Some(ref d) = app.status.dns_name {
            let fqdn = format!("{d}.topaz");
            let dest = clipboard::copy_text(&fqdn);
            app.set_toast(true, format!("Copied {fqdn} to {dest}"));
            return;
        }
        app.set_toast(false, "No domain available to copy");
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

pub fn copy_selected_peer_ip(app: &mut AppState) {
    let ip = match app.selected_peer() {
        Some(p) => p.virtual_ip,
        None => app.status.virtual_ip.clone(),
    };
    if let Some(ip) = ip {
        let dest = clipboard::copy_text(&ip);
        app.set_toast(true, format!("Copied {ip} to {dest}"));
    } else {
        app.set_toast(false, "No virtual IP assigned");
    }
}

pub fn open_palette(app: &mut AppState) {
    app.modal = Some(Modal::Palette {
        query: super::state::TextField::new("Type to search commands…"),
        selected: 0,
    });
}

pub fn run_palette_action(
    app: &mut AppState,
    action: PaletteAction,
    data_dir: &Path,
    tx: &mpsc::UnboundedSender<UiEvent>,
) {
    match action {
        PaletteAction::StartTun => {
            if app.mode() == AppMode::Onboarding {
                app.set_toast(false, "Set up an account first");
            } else {
                request_start_tun(app, app.ws_connected, data_dir, tx);
            }
        }
        PaletteAction::StartNoTun => {
            if app.mode() == AppMode::Onboarding {
                app.set_toast(false, "Set up an account first");
            } else {
                start_no_tun(app, app.ws_connected, data_dir, tx);
            }
        }
        PaletteAction::RestartTun => request_start_tun(app, true, data_dir, tx),
        PaletteAction::RestartNoTun => start_no_tun(app, true, data_dir, tx),
        PaletteAction::StopDaemon => {
            if app.ws_connected {
                app.modal = Some(Modal::StopConfirm);
            } else {
                app.set_toast(false, "Daemon is already stopped");
            }
        }
        PaletteAction::PairDevice => open_pair_modal(app),
        PaletteAction::KickAnnounce => spawn_kick(data_dir.to_path_buf(), true, tx.clone()),
        PaletteAction::KickLocal => spawn_kick(data_dir.to_path_buf(), false, tx.clone()),
        PaletteAction::RefreshDevices => {
            spawn_refresh_devices(data_dir.to_path_buf(), tx.clone());
            if app.ws_connected {
                spawn_kick(data_dir.to_path_buf(), true, tx.clone());
            } else {
                app.set_toast(true, "Refreshing devices from coord…");
            }
        }
        PaletteAction::CopyPeerDns => copy_selected_peer_dns(app),
        PaletteAction::CopyPeerIp => copy_selected_peer_ip(app),
        PaletteAction::RevokeSelected => prompt_revoke_selected(app),
        PaletteAction::OpenDoctor => open_doctor_modal(app, data_dir, tx),
        PaletteAction::OpenLogs => open_logs_modal(app, data_dir, tx),
        PaletteAction::OpenSettings => open_settings_modal(app, data_dir, tx),
        PaletteAction::InstallAutostartTun => {
            spawn_install_autostart(data_dir.to_path_buf(), false, tx.clone());
            app.set_toast(true, "Installing autostart service (TUN)…");
        }
        PaletteAction::InstallAutostartNoTun => {
            spawn_install_autostart(data_dir.to_path_buf(), true, tx.clone());
            app.set_toast(true, "Installing autostart service (No-TUN)…");
        }
        PaletteAction::UninstallAutostart => {
            spawn_uninstall_autostart(data_dir.to_path_buf(), tx.clone());
            app.set_toast(true, "Uninstalling autostart service…");
        }
        PaletteAction::ToggleFilter => {
            app.filter_open = true;
            app.focus = FocusArea::Filter;
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
        PaletteAction::ToggleMouseCapture => {
            let next = !app.mouse_capture;
            app.mouse_capture = next;
            app.pending_mouse_toggle = Some(next);
            app.set_toast(
                true,
                if next {
                    "Mouse capture enabled"
                } else {
                    "Mouse capture disabled (native select active)"
                },
            );
        }
        PaletteAction::OpenHelp => {
            app.modal = Some(Modal::Help);
        }
        PaletteAction::Quit => {
            app.should_quit = true;
        }
    }
}

pub fn run_detail_button(
    app: &mut AppState,
    btn: DetailButton,
    data_dir: &Path,
    tx: &mpsc::UnboundedSender<UiEvent>,
) {
    match btn {
        DetailButton::StartTun => request_start_tun(app, false, data_dir, tx),
        DetailButton::StartNoTun => start_no_tun(app, false, data_dir, tx),
        DetailButton::RestartTun => request_start_tun(app, true, data_dir, tx),
        DetailButton::RestartNoTun => start_no_tun(app, true, data_dir, tx),
        DetailButton::StopDaemon => app.modal = Some(Modal::StopConfirm),
        DetailButton::ProbePeers => {
            spawn_kick(data_dir.to_path_buf(), true, tx.clone());
            spawn_refresh_devices(data_dir.to_path_buf(), tx.clone());
        }
        DetailButton::OpenPair => open_pair_modal(app),
        DetailButton::OpenDoctor => open_doctor_modal(app, data_dir, tx),
        DetailButton::OpenLogs => open_logs_modal(app, data_dir, tx),
        DetailButton::OpenSettings => open_settings_modal(app, data_dir, tx),
        DetailButton::CopyDns => copy_selected_peer_dns(app),
        DetailButton::CopyIp => copy_selected_peer_ip(app),
        DetailButton::RevokePeer => prompt_revoke_selected(app),
    }
}

pub fn apply_hit_target(
    app: &mut AppState,
    target: HitTarget,
    data_dir: &Path,
    tx: &mpsc::UnboundedSender<UiEvent>,
) {
    match target {
        HitTarget::SelectSelf => {
            app.select_sidebar_index(0);
            app.focus = FocusArea::Sidebar;
            if app.last_area.width < NARROW_WIDTH {
                app.narrow_showing_detail = true;
            }
        }
        HitTarget::TopTunPill => {
            if !app.ws_connected {
                request_start_tun(app, false, data_dir, tx);
            } else if !app.status.tun.enabled {
                request_start_tun(app, true, data_dir, tx);
            } else {
                app.select_sidebar_index(0);
                app.focus = FocusArea::Detail;
            }
        }
        HitTarget::OpenPair => open_pair_modal(app),
        HitTarget::OpenDoctor => open_doctor_modal(app, data_dir, tx),
        HitTarget::OpenLogs => open_logs_modal(app, data_dir, tx),
        HitTarget::OpenSettings => open_settings_modal(app, data_dir, tx),
        HitTarget::OpenPalette => open_palette(app),
        HitTarget::OpenHelp => app.modal = Some(Modal::Help),
        HitTarget::ToggleSidebar => {
            app.sidebar_visible = !app.sidebar_visible;
            app.save_prefs(data_dir);
        }
        HitTarget::CycleTheme => {
            app.theme = app.theme.cycle();
            app.save_prefs(data_dir);
            app.set_toast(true, format!("Theme: {}", app.theme.label()));
        }
        HitTarget::Quit => {
            app.should_quit = true;
        }
        HitTarget::FocusFilter => {
            app.filter_open = true;
            app.focus = FocusArea::Filter;
        }
        HitTarget::ClearFilter => {
            app.filter.clear();
            app.filter_open = false;
            app.focus = FocusArea::Sidebar;
            app.reconcile_selection();
        }
        HitTarget::SelectSidebarRow(idx) => {
            app.select_sidebar_index(idx);
            app.focus = FocusArea::Sidebar;
            if app.last_area.width < NARROW_WIDTH {
                app.narrow_showing_detail = true;
            }
        }
        HitTarget::NarrowBackToList => {
            app.narrow_showing_detail = false;
            app.focus = FocusArea::Sidebar;
        }
        HitTarget::DetailAction(btn) => run_detail_button(app, btn, data_dir, tx),
        HitTarget::CopyText { label, text } => {
            let dest = clipboard::copy_text(&text);
            app.set_toast(true, format!("Copied {label} ({text}) to {dest}"));
        }
        HitTarget::OnboardingPick(choice) => {
            if let Some(pos) = OnboardingChoice::ALL.iter().position(|c| *c == choice) {
                app.onboarding_idx = pos;
            }
            open_onboarding_form(app, choice);
        }
        HitTarget::ModalBackdrop => {
            // Do not accidentally dismiss blocking progress or recovery-code backup screens!
            let can_dismiss = match &app.modal {
                Some(Modal::SudoPrompt(s)) => !s.busy,
                Some(Modal::RevokeConfirm(r)) => !r.busy,
                Some(Modal::OnboardingForm(o)) => !matches!(
                    o.step,
                    OnboardingStep::ProbingPin
                        | OnboardingStep::Submitting(_)
                        | OnboardingStep::RecoveryBackup { .. }
                ),
                _ => true,
            };
            if can_dismiss {
                app.close_modal();
            }
        }
        HitTarget::ModalClose => {
            // Even on RecoveryBackup, require clicking the explicit continue button.
            if matches!(
                app.modal,
                Some(Modal::OnboardingForm(OnboardingModal {
                    step: OnboardingStep::RecoveryBackup { .. },
                    ..
                }))
            ) {
                return;
            }
            app.close_modal();
        }
        HitTarget::PaletteRow(idx) => {
            let action = if let Some(Modal::Palette { ref query, .. }) = app.modal {
                super::state::filtered_palette(&query.value)
                    .get(idx)
                    .map(|(_, _, _, a)| *a)
            } else {
                None
            };
            app.close_modal();
            if let Some(a) = action {
                run_palette_action(app, a, data_dir, tx);
            }
        }
        HitTarget::SudoToggleReveal => {
            if let Some(Modal::SudoPrompt(ref mut s)) = app.modal {
                s.password.reveal = !s.password.reveal;
            }
        }
        HitTarget::SudoSubmit => submit_sudo_password(app, data_dir, tx),
        HitTarget::SudoFallbackNoTun => {
            let restart_first = match &app.modal {
                Some(Modal::SudoPrompt(s)) => s.restart_first,
                _ => false,
            };
            app.close_modal();
            start_no_tun(app, restart_first, data_dir, tx);
        }
        HitTarget::PairSelectTab(tab) => switch_pair_tab(app, tab, data_dir, tx),
        HitTarget::PairStartPhrase => start_phrase_pair(app, data_dir, tx),
        HitTarget::PairApprovePeer(allow) => {
            if let Some(decision_tx) = app.pair_decision_tx.take() {
                let _ = decision_tx.send(allow);
            }
            if !allow {
                if let Some(Modal::Pair(ref mut p)) = app.modal {
                    p.status = PairStatus::Failed("Rejected by user".into());
                }
            }
        }
        HitTarget::PairCopyCmd(cmd) => {
            let dest = clipboard::copy_text(&cmd);
            app.set_toast(true, format!("Copied to {dest}"));
        }
        HitTarget::PairRestart => {
            app.cancel_pair_task();
            let tab = match &app.modal {
                Some(Modal::Pair(p)) => p.tab,
                _ => PairTab::Phrase,
            };
            app.modal = Some(Modal::Pair(PairModal::new()));
            switch_pair_tab(app, tab, data_dir, tx);
        }
        HitTarget::OnboardingFocusField(idx) => {
            if let Some(Modal::OnboardingForm(ref mut ob)) = app.modal {
                ob.focus_field = idx.min(ob.field_count().saturating_sub(1));
            }
        }
        HitTarget::OnboardingToggleReveal => {
            if let Some(Modal::OnboardingForm(ref mut ob)) = app.modal {
                ob.secret.reveal = !ob.secret.reveal;
            }
        }
        HitTarget::OnboardingSubmit => submit_onboarding_form(app, data_dir, tx),
        HitTarget::OnboardingTofuTrust => confirm_onboarding_tofu(app, data_dir, tx),
        HitTarget::OnboardingCopyRecovery(code) => {
            let dest = clipboard::copy_text(&code);
            app.set_toast(true, format!("Recovery code copied to {dest}"));
        }
        HitTarget::OnboardingFinishRecovery => {
            app.close_modal();
            app.local = LocalSnapshot::load(data_dir);
            app.set_toast(true, "Account ready — start TUN or Session Mode to connect");
            spawn_refresh_devices(data_dir.to_path_buf(), tx.clone());
        }
        HitTarget::DoctorRerun => {
            if let Some(Modal::Doctor(ref mut d)) = app.modal {
                d.report = DoctorReport::default();
                d.scroll = 0;
            }
            spawn_doctor(data_dir.to_path_buf(), tx.clone());
        }
        HitTarget::DoctorCopy => {
            if let Some(Modal::Doctor(ref d)) = app.modal {
                let text = d.report.to_plain_summary();
                let dest = clipboard::copy_text(&text);
                app.set_toast(true, format!("Doctor summary copied to {dest}"));
            }
        }
        HitTarget::LogsFilter(flt) => {
            if let Some(Modal::Logs(ref mut l)) = app.modal {
                l.filter = flt;
                l.scroll = 0;
            }
        }
        HitTarget::LogsToggleFollow => {
            if let Some(Modal::Logs(ref mut l)) = app.modal {
                l.follow = !l.follow;
            }
        }
        HitTarget::LogsCopy => {
            if let Some(Modal::Logs(ref l)) = app.modal {
                let text = l.filtered_lines().join("\n");
                let dest = clipboard::copy_text(&text);
                app.set_toast(true, format!("Copied {} log lines to {dest}", l.filtered_lines().len()));
            }
        }
        HitTarget::SettingsFocus(idx) => {
            if let Some(Modal::Settings(ref mut s)) = app.modal {
                s.focus_idx = idx;
                if idx == 3 {
                    s.force_relay = !s.force_relay;
                }
            }
        }
        HitTarget::SettingsProbePin => probe_settings_pin(app, tx),
        HitTarget::SettingsSave => save_settings_modal(app, data_dir, tx),
        HitTarget::SettingsInstallAutostart(no_tun) => {
            spawn_install_autostart(data_dir.to_path_buf(), no_tun, tx.clone());
            app.set_toast(true, "Installing autostart service…");
        }
        HitTarget::SettingsUninstallAutostart => {
            spawn_uninstall_autostart(data_dir.to_path_buf(), tx.clone());
            app.set_toast(true, "Uninstalling autostart service…");
        }
        HitTarget::SettingsCycleTheme => {
            app.theme = app.theme.cycle();
            app.save_prefs(data_dir);
            app.set_toast(true, format!("Theme: {}", app.theme.label()));
        }
        HitTarget::SettingsToggleMouse => {
            let next = !app.mouse_capture;
            app.mouse_capture = next;
            app.pending_mouse_toggle = Some(next);
            app.set_toast(
                true,
                if next {
                    "Mouse capture enabled"
                } else {
                    "Mouse capture off (native select)"
                },
            );
        }
        HitTarget::RevokeToggleRecovery => {
            if let Some(Modal::RevokeConfirm(ref mut r)) = app.modal {
                r.use_recovery = !r.use_recovery;
                r.error = None;
            }
        }
        HitTarget::RevokeToggleReveal => {
            if let Some(Modal::RevokeConfirm(ref mut r)) = app.modal {
                r.recovery.reveal = !r.recovery.reveal;
            }
        }
        HitTarget::RevokeSubmit => submit_revoke_modal(app, data_dir, tx),
        HitTarget::StopConfirmSubmit => {
            app.close_modal();
            app.busy_banner = Some("Stopping daemon…".into());
            spawn_stop_daemon(data_dir.to_path_buf(), tx.clone());
        }
    }
}
