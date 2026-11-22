//! Modern, intuitive keyboard & bracketed-paste handling (no Vim bindings).

use std::path::Path;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tokio::sync::mpsc;

use super::actions::{
    apply_hit_target, copy_selected_peer_dns, open_doctor_modal, open_logs_modal,
    open_onboarding_form, open_pair_modal, open_palette, open_settings_modal,
    prompt_revoke_selected, run_detail_button, run_palette_action, save_settings_modal,
    spawn_kick, spawn_refresh_devices, start_phrase_pair, submit_onboarding_form,
    submit_revoke_modal, submit_sudo_password, switch_pair_tab,
};
use super::state::{
    filtered_palette, AppMode, AppState, FocusArea, HitTarget, LogFilter, Modal, OnboardingChoice,
    OnboardingStep, PairStatus, PairTab, TextField, UiEvent, NARROW_WIDTH,
};

pub fn handle_paste(app: &mut AppState, text: &str) {
    if let Some(ref mut modal) = app.modal {
        match modal {
            Modal::Palette { query, selected } => {
                query.insert_str(text);
                *selected = 0;
            }
            Modal::SudoPrompt(s) if !s.busy => {
                s.password.insert_str(text);
            }
            Modal::Pair(p) if p.tab == PairTab::Phrase && p.status == PairStatus::Idle => {
                p.phrase.insert_str(text);
            }
            Modal::OnboardingForm(ob) if ob.step == OnboardingStep::Form => {
                if let Some(f) = ob.active_field_mut() {
                    f.insert_str(text);
                }
            }
            Modal::Settings(s) => {
                if let Some(f) = s.active_field_mut() {
                    f.insert_str(text);
                }
            }
            Modal::RevokeConfirm(r) if r.use_recovery && !r.busy => {
                r.recovery.insert_str(text);
            }
            _ => {}
        }
        return;
    }

    if app.focus == FocusArea::Filter {
        app.filter.insert_str(text);
        app.reconcile_selection();
    }
}

pub fn handle_key(
    app: &mut AppState,
    key: KeyEvent,
    data_dir: &Path,
    tx: &mpsc::UnboundedSender<UiEvent>,
) {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

    // Universal safe exits.
    if ctrl && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('q')) {
        app.should_quit = true;
        return;
    }

    if app.modal.is_some() {
        handle_modal_key(app, key, data_dir, tx);
        return;
    }

    // Global modern shortcuts (available in Onboarding, Standby, and Live).
    if ctrl {
        match key.code {
            KeyCode::Char('p') => {
                open_palette(app);
                return;
            }
            KeyCode::Char('t') => {
                app.theme = app.theme.cycle();
                app.save_prefs(data_dir);
                app.set_toast(true, format!("Theme: {}", app.theme.label()));
                return;
            }
            KeyCode::Char('d') => {
                open_doctor_modal(app, data_dir, tx);
                return;
            }
            KeyCode::Char('l') => {
                open_logs_modal(app, data_dir, tx);
                return;
            }
            KeyCode::Char('o') => {
                open_settings_modal(app, data_dir, tx);
                return;
            }
            _ => {}
        }
    }

    match key.code {
        KeyCode::F(1) => {
            app.modal = Some(Modal::Help);
            return;
        }
        KeyCode::F(2) => {
            open_settings_modal(app, data_dir, tx);
            return;
        }
        _ => {}
    }

    if app.mode() == AppMode::Onboarding {
        handle_onboarding_screen_key(app, key);
        return;
    }

    // Workbench-wide modern Ctrl shortcuts.
    if ctrl {
        match key.code {
            KeyCode::Char('f') => {
                app.filter_open = true;
                app.focus = FocusArea::Filter;
                return;
            }
            KeyCode::Char('n') => {
                open_pair_modal(app);
                return;
            }
            KeyCode::Char('r') => {
                spawn_refresh_devices(data_dir.to_path_buf(), tx.clone());
                if app.ws_connected {
                    spawn_kick(data_dir.to_path_buf(), true, tx.clone());
                } else {
                    app.set_toast(true, "Refreshing devices…");
                }
                return;
            }
            KeyCode::Char('b') => {
                app.sidebar_visible = !app.sidebar_visible;
                app.save_prefs(data_dir);
                return;
            }
            KeyCode::Char('y') => {
                copy_selected_peer_dns(app);
                return;
            }
            _ => {}
        }
    }

    if key.code == KeyCode::F(5) {
        spawn_refresh_devices(data_dir.to_path_buf(), tx.clone());
        if app.ws_connected {
            spawn_kick(data_dir.to_path_buf(), true, tx.clone());
        } else {
            app.set_toast(true, "Refreshing devices…");
        }
        return;
    }

    match app.focus {
        FocusArea::Filter => handle_filter_key(app, key),
        FocusArea::Sidebar => handle_sidebar_key(app, key, data_dir, tx),
        FocusArea::Detail => handle_detail_key(app, key, data_dir, tx),
    }
}

fn handle_onboarding_screen_key(app: &mut AppState, key: KeyEvent) {
    let count = OnboardingChoice::ALL.len();
    match key.code {
        KeyCode::Up => {
            app.onboarding_idx = app.onboarding_idx.saturating_sub(1);
        }
        KeyCode::Down => {
            app.onboarding_idx = (app.onboarding_idx + 1).min(count - 1);
        }
        KeyCode::Home => app.onboarding_idx = 0,
        KeyCode::End => app.onboarding_idx = count - 1,
        KeyCode::Enter | KeyCode::Char(' ') => {
            if let Some(&choice) = OnboardingChoice::ALL.get(app.onboarding_idx) {
                open_onboarding_form(app, choice);
            }
        }
        KeyCode::Char('1') => open_onboarding_form(app, OnboardingChoice::JoinPhrase),
        KeyCode::Char('2') => open_onboarding_form(app, OnboardingChoice::JoinBundle),
        KeyCode::Char('3') => open_onboarding_form(app, OnboardingChoice::CreateAccount),
        KeyCode::Char('4') => open_onboarding_form(app, OnboardingChoice::JoinRecovery),
        KeyCode::Char('?') => app.modal = Some(Modal::Help),
        _ => {}
    }
}

fn handle_filter_key(app: &mut AppState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.filter.clear();
            app.filter_open = false;
            app.focus = FocusArea::Sidebar;
            app.reconcile_selection();
        }
        KeyCode::Enter | KeyCode::Tab | KeyCode::Down => {
            app.focus = FocusArea::Sidebar;
            if app.filter.value.is_empty() {
                app.filter_open = false;
            }
        }
        _ => {
            if handle_text_field_key(&mut app.filter, key) {
                app.reconcile_selection();
            }
        }
    }
}

fn handle_sidebar_key(
    app: &mut AppState,
    key: KeyEvent,
    _data_dir: &Path,
    _tx: &mpsc::UnboundedSender<UiEvent>,
) {
    match key.code {
        KeyCode::Down => app.move_selection(1),
        KeyCode::Up => app.move_selection(-1),
        KeyCode::PageDown => app.move_selection(6),
        KeyCode::PageUp => app.move_selection(-6),
        KeyCode::Home => app.select_sidebar_index(0),
        KeyCode::End => {
            let last = app.sidebar_entries().len().saturating_sub(1);
            app.select_sidebar_index(last);
        }
        KeyCode::Tab | KeyCode::Right => {
            if app.last_area.width < NARROW_WIDTH {
                app.narrow_showing_detail = true;
            }
            app.focus = FocusArea::Detail;
            app.detail_btn_idx = 0;
        }
        KeyCode::Enter => {
            if app.last_area.width < NARROW_WIDTH {
                app.narrow_showing_detail = true;
            }
            app.focus = FocusArea::Detail;
            app.detail_btn_idx = 0;
        }
        KeyCode::Delete => prompt_revoke_selected(app),
        KeyCode::Esc => {
            if !app.filter.value.is_empty() || app.filter_open {
                app.filter.clear();
                app.filter_open = false;
                app.reconcile_selection();
            }
        }
        KeyCode::Char('?') => app.modal = Some(Modal::Help),
        _ => {}
    }
}

fn handle_detail_key(
    app: &mut AppState,
    key: KeyEvent,
    data_dir: &Path,
    tx: &mpsc::UnboundedSender<UiEvent>,
) {
    let buttons = app.detail_buttons();
    match key.code {
        KeyCode::Esc => {
            if app.last_area.width < NARROW_WIDTH {
                app.narrow_showing_detail = false;
            }
            app.focus = FocusArea::Sidebar;
        }
        KeyCode::BackTab => {
            if app.detail_btn_idx > 0 {
                app.detail_btn_idx -= 1;
            } else {
                app.focus = FocusArea::Sidebar;
            }
        }
        KeyCode::Tab => {
            if buttons.is_empty() || app.detail_btn_idx + 1 >= buttons.len() {
                app.focus = FocusArea::Sidebar;
            } else {
                app.detail_btn_idx += 1;
            }
        }
        KeyCode::Left => {
            if app.detail_btn_idx > 0 {
                app.detail_btn_idx -= 1;
            } else {
                app.focus = FocusArea::Sidebar;
            }
        }
        KeyCode::Right => {
            if !buttons.is_empty() {
                app.detail_btn_idx = (app.detail_btn_idx + 1).min(buttons.len() - 1);
            }
        }
        KeyCode::Up => {
            app.move_selection(-1);
        }
        KeyCode::Down => {
            app.move_selection(1);
        }
        KeyCode::Enter | KeyCode::Char(' ') => {
            if let Some(&btn) = buttons.get(app.detail_btn_idx.min(buttons.len().saturating_sub(1)))
            {
                run_detail_button(app, btn, data_dir, tx);
            }
        }
        KeyCode::Delete => prompt_revoke_selected(app),
        KeyCode::Char('?') => app.modal = Some(Modal::Help),
        _ => {}
    }
}

fn handle_modal_key(
    app: &mut AppState,
    key: KeyEvent,
    data_dir: &Path,
    tx: &mpsc::UnboundedSender<UiEvent>,
) {
    let Some(modal_kind) = app.modal.clone() else {
        return;
    };
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

    match modal_kind {
        Modal::Palette { .. } => match key.code {
            KeyCode::Esc => app.close_modal(),
            KeyCode::Down => {
                if let Some(Modal::Palette { query, selected }) = &mut app.modal {
                    let len = filtered_palette(&query.value).len();
                    if len > 0 {
                        *selected = (*selected + 1).min(len - 1);
                    }
                }
            }
            KeyCode::Up => {
                if let Some(Modal::Palette { selected, .. }) = &mut app.modal {
                    *selected = selected.saturating_sub(1);
                }
            }
            KeyCode::Enter => {
                let picked = if let Some(Modal::Palette { query, selected }) = &app.modal {
                    filtered_palette(&query.value)
                        .get(*selected)
                        .map(|(_, _, _, a)| *a)
                } else {
                    None
                };
                app.close_modal();
                if let Some(action) = picked {
                    run_palette_action(app, action, data_dir, tx);
                }
            }
            _ => {
                if let Some(Modal::Palette { query, selected }) = &mut app.modal {
                    if handle_text_field_key(query, key) {
                        *selected = 0;
                    }
                }
            }
        },
        Modal::SudoPrompt(s) => {
            if s.busy {
                return;
            }
            match key.code {
                KeyCode::Esc => app.close_modal(),
                KeyCode::Tab => {
                    if let Some(Modal::SudoPrompt(ref mut m)) = app.modal {
                        m.focus = (m.focus + 1) % 4;
                    }
                }
                KeyCode::BackTab => {
                    if let Some(Modal::SudoPrompt(ref mut m)) = app.modal {
                        m.focus = if m.focus == 0 { 3 } else { m.focus - 1 };
                    }
                }
                KeyCode::Enter => match s.focus {
                    0 | 1 => submit_sudo_password(app, data_dir, tx),
                    2 => apply_hit_target(app, HitTarget::SudoFallbackNoTun, data_dir, tx),
                    _ => app.close_modal(),
                },
                KeyCode::Char(' ') if s.focus != 0 => match s.focus {
                    1 => submit_sudo_password(app, data_dir, tx),
                    2 => apply_hit_target(app, HitTarget::SudoFallbackNoTun, data_dir, tx),
                    _ => app.close_modal(),
                },
                KeyCode::Char('r') if ctrl => {
                    if let Some(Modal::SudoPrompt(ref mut m)) = app.modal {
                        m.password.reveal = !m.password.reveal;
                    }
                }
                _ => {
                    if let Some(Modal::SudoPrompt(ref mut m)) = app.modal {
                        m.focus = 0;
                        handle_text_field_key(&mut m.password, key);
                    }
                }
            }
        }
        Modal::Pair(p) => match &p.status {
            PairStatus::Idle if p.tab == PairTab::Phrase => match key.code {
                KeyCode::Esc => app.close_modal(),
                KeyCode::Tab => switch_pair_tab(app, PairTab::Bundle, data_dir, tx),
                KeyCode::Enter => start_phrase_pair(app, data_dir, tx),
                _ => {
                    if let Some(Modal::Pair(ref mut m)) = app.modal {
                        handle_text_field_key(&mut m.phrase, key);
                    }
                }
            },
            PairStatus::ConfirmPeer { .. } => match key.code {
                KeyCode::Enter => {
                    apply_hit_target(app, HitTarget::PairApprovePeer(true), data_dir, tx)
                }
                KeyCode::Esc => {
                    apply_hit_target(app, HitTarget::PairApprovePeer(false), data_dir, tx)
                }
                _ => {}
            },
            PairStatus::WaitingPhrase { peer_cmd, .. } => match key.code {
                KeyCode::Esc => app.close_modal(),
                KeyCode::Tab => switch_pair_tab(app, PairTab::Bundle, data_dir, tx),
                KeyCode::Char('y') if ctrl => {
                    apply_hit_target(app, HitTarget::PairCopyCmd(peer_cmd.clone()), data_dir, tx);
                }
                _ => {}
            },
            PairStatus::WaitingBundle { setup, .. } => match key.code {
                KeyCode::Esc => app.close_modal(),
                KeyCode::Tab => switch_pair_tab(app, PairTab::Phrase, data_dir, tx),
                KeyCode::Char('y') if ctrl => {
                    let cmd = format!("topaz setup '{setup}' --start");
                    apply_hit_target(app, HitTarget::PairCopyCmd(cmd), data_dir, tx);
                }
                _ => {}
            },
            PairStatus::Added { .. } | PairStatus::Failed(_) => match key.code {
                KeyCode::Esc | KeyCode::Enter => app.close_modal(),
                KeyCode::Tab => {
                    let next = if p.tab == PairTab::Phrase {
                        PairTab::Bundle
                    } else {
                        PairTab::Phrase
                    };
                    switch_pair_tab(app, next, data_dir, tx);
                }
                _ => {}
            },
            _ => {
                if key.code == KeyCode::Esc {
                    app.close_modal();
                }
            }
        },
        Modal::OnboardingForm(ob) => match ob.step {
            OnboardingStep::Form => match key.code {
                KeyCode::Esc => app.close_modal(),
                KeyCode::Tab | KeyCode::Down => {
                    if let Some(Modal::OnboardingForm(ref mut m)) = app.modal {
                        let n = m.field_count();
                        m.focus_field = (m.focus_field + 1) % n;
                    }
                }
                KeyCode::BackTab | KeyCode::Up => {
                    if let Some(Modal::OnboardingForm(ref mut m)) = app.modal {
                        let n = m.field_count();
                        m.focus_field = if m.focus_field == 0 {
                            n - 1
                        } else {
                            m.focus_field - 1
                        };
                    }
                }
                KeyCode::Enter => submit_onboarding_form(app, data_dir, tx),
                KeyCode::Char('r') if ctrl => {
                    if let Some(Modal::OnboardingForm(ref mut m)) = app.modal {
                        m.secret.reveal = !m.secret.reveal;
                    }
                }
                _ => {
                    if let Some(Modal::OnboardingForm(ref mut m)) = app.modal {
                        if let Some(f) = m.active_field_mut() {
                            handle_text_field_key(f, key);
                        }
                    }
                }
            },
            OnboardingStep::TofuConfirm { .. } => match key.code {
                KeyCode::Esc => app.close_modal(),
                KeyCode::Enter => {
                    apply_hit_target(app, HitTarget::OnboardingTofuTrust, data_dir, tx)
                }
                _ => {}
            },
            OnboardingStep::RecoveryBackup {
                ref recovery_code, ..
            } => match key.code {
                KeyCode::Enter => {
                    apply_hit_target(app, HitTarget::OnboardingFinishRecovery, data_dir, tx)
                }
                KeyCode::Char('y') if ctrl => {
                    apply_hit_target(
                        app,
                        HitTarget::OnboardingCopyRecovery(recovery_code.clone()),
                        data_dir,
                        tx,
                    );
                }
                _ => {}
            },
            OnboardingStep::ProbingPin | OnboardingStep::Submitting(_) => {
                if key.code == KeyCode::Esc {
                    app.close_modal();
                }
            }
        },
        Modal::Doctor(_) => match key.code {
            KeyCode::Esc => app.close_modal(),
            KeyCode::Up => {
                if let Some(Modal::Doctor(ref mut d)) = app.modal {
                    d.scroll = d.scroll.saturating_sub(1);
                }
            }
            KeyCode::Down => {
                if let Some(Modal::Doctor(ref mut d)) = app.modal {
                    d.scroll = (d.scroll + 1).min(d.max_scroll);
                }
            }
            KeyCode::PageUp => {
                if let Some(Modal::Doctor(ref mut d)) = app.modal {
                    d.scroll = d.scroll.saturating_sub(8);
                }
            }
            KeyCode::PageDown => {
                if let Some(Modal::Doctor(ref mut d)) = app.modal {
                    d.scroll = d.scroll.saturating_add(8).min(d.max_scroll);
                }
            }
            KeyCode::Char('r') if ctrl => {
                apply_hit_target(app, HitTarget::DoctorRerun, data_dir, tx);
            }
            KeyCode::F(5) => {
                apply_hit_target(app, HitTarget::DoctorRerun, data_dir, tx);
            }
            KeyCode::Char('y') if ctrl => {
                apply_hit_target(app, HitTarget::DoctorCopy, data_dir, tx);
            }
            _ => {}
        },
        Modal::Logs(_) => match key.code {
            KeyCode::Esc => app.close_modal(),
            KeyCode::Up => {
                if let Some(Modal::Logs(ref mut l)) = app.modal {
                    l.follow = false;
                    l.scroll = l.scroll.saturating_sub(1);
                }
            }
            KeyCode::Down => {
                if let Some(Modal::Logs(ref mut l)) = app.modal {
                    l.scroll = (l.scroll + 1).min(l.max_scroll);
                    if l.scroll >= l.max_scroll {
                        l.follow = true;
                    }
                }
            }
            KeyCode::PageUp => {
                if let Some(Modal::Logs(ref mut l)) = app.modal {
                    l.follow = false;
                    l.scroll = l.scroll.saturating_sub(10);
                }
            }
            KeyCode::PageDown => {
                if let Some(Modal::Logs(ref mut l)) = app.modal {
                    l.scroll = l.scroll.saturating_add(10).min(l.max_scroll);
                    if l.scroll >= l.max_scroll {
                        l.follow = true;
                    }
                }
            }
            KeyCode::Home => {
                if let Some(Modal::Logs(ref mut l)) = app.modal {
                    l.follow = false;
                    l.scroll = 0;
                }
            }
            KeyCode::End => {
                if let Some(Modal::Logs(ref mut l)) = app.modal {
                    l.follow = true;
                    l.scroll = l.max_scroll;
                }
            }
            KeyCode::Char('1') => {
                apply_hit_target(app, HitTarget::LogsFilter(LogFilter::All), data_dir, tx)
            }
            KeyCode::Char('2') => {
                apply_hit_target(app, HitTarget::LogsFilter(LogFilter::Warn), data_dir, tx)
            }
            KeyCode::Char('3') => {
                apply_hit_target(app, HitTarget::LogsFilter(LogFilter::Error), data_dir, tx)
            }
            KeyCode::Char('y') if ctrl => {
                apply_hit_target(app, HitTarget::LogsCopy, data_dir, tx)
            }
            _ => {}
        },
        Modal::Settings(_) => match key.code {
            KeyCode::Esc => app.close_modal(),
            KeyCode::Tab | KeyCode::Down => {
                if let Some(Modal::Settings(ref mut s)) = app.modal {
                    s.focus_idx = (s.focus_idx + 1) % 6;
                }
            }
            KeyCode::BackTab | KeyCode::Up => {
                if let Some(Modal::Settings(ref mut s)) = app.modal {
                    s.focus_idx = if s.focus_idx == 0 { 5 } else { s.focus_idx - 1 };
                }
            }
            KeyCode::Enter => {
                let focus = match &app.modal {
                    Some(Modal::Settings(s)) => s.focus_idx,
                    _ => 0,
                };
                match focus {
                    3 => apply_hit_target(app, HitTarget::SettingsFocus(3), data_dir, tx),
                    4 => apply_hit_target(app, HitTarget::SettingsCycleTheme, data_dir, tx),
                    5 => apply_hit_target(app, HitTarget::SettingsToggleMouse, data_dir, tx),
                    _ => save_settings_modal(app, data_dir, tx),
                }
            }
            KeyCode::Char(' ') => {
                let focus = match &app.modal {
                    Some(Modal::Settings(s)) => s.focus_idx,
                    _ => 0,
                };
                match focus {
                    3 => apply_hit_target(app, HitTarget::SettingsFocus(3), data_dir, tx),
                    4 => apply_hit_target(app, HitTarget::SettingsCycleTheme, data_dir, tx),
                    5 => apply_hit_target(app, HitTarget::SettingsToggleMouse, data_dir, tx),
                    _ => {
                        if let Some(Modal::Settings(ref mut s)) = app.modal {
                            if let Some(f) = s.active_field_mut() {
                                handle_text_field_key(f, key);
                            }
                        }
                    }
                }
            }
            KeyCode::Char('s') if ctrl => save_settings_modal(app, data_dir, tx),
            _ => {
                if let Some(Modal::Settings(ref mut s)) = app.modal {
                    if let Some(f) = s.active_field_mut() {
                        handle_text_field_key(f, key);
                    }
                }
            }
        },
        Modal::RevokeConfirm(r) => {
            if r.busy {
                return;
            }
            match key.code {
                KeyCode::Esc => app.close_modal(),
                KeyCode::Tab => {
                    apply_hit_target(app, HitTarget::RevokeToggleRecovery, data_dir, tx);
                }
                KeyCode::Enter => submit_revoke_modal(app, data_dir, tx),
                KeyCode::Char('r') if ctrl => {
                    apply_hit_target(app, HitTarget::RevokeToggleReveal, data_dir, tx);
                }
                _ => {
                    if let Some(Modal::RevokeConfirm(ref mut m)) = app.modal {
                        if m.use_recovery {
                            handle_text_field_key(&mut m.recovery, key);
                        }
                    }
                }
            }
        }
        Modal::StopConfirm => match key.code {
            KeyCode::Esc => app.close_modal(),
            KeyCode::Enter => {
                apply_hit_target(app, HitTarget::StopConfirmSubmit, data_dir, tx);
            }
            _ => {}
        },
        Modal::Help => match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::F(1) | KeyCode::Char('?') => app.close_modal(),
            _ => {}
        },
    }
}

pub fn handle_text_field_key(field: &mut TextField, key: KeyEvent) -> bool {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    match key.code {
        KeyCode::Left => {
            field.move_left();
            false
        }
        KeyCode::Right => {
            field.move_right();
            false
        }
        KeyCode::Home => {
            field.move_home();
            false
        }
        KeyCode::End => {
            field.move_end();
            false
        }
        KeyCode::Backspace => {
            field.backspace();
            true
        }
        KeyCode::Delete => {
            field.delete();
            true
        }
        KeyCode::Char('a') if ctrl => {
            field.move_home();
            false
        }
        KeyCode::Char('e') if ctrl => {
            field.move_end();
            false
        }
        KeyCode::Char('u') if ctrl => {
            field.clear();
            true
        }
        KeyCode::Char('w') if ctrl => {
            field.delete_word();
            true
        }
        KeyCode::Char(c) if !ctrl && !alt => {
            field.insert_char(c);
            true
        }
        _ => false,
    }
}
