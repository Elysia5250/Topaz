//! Rounded, padded modals with backdrop dimming and full mouse hit-regions
//! (Jade-aligned design language).

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Padding, Paragraph, Wrap};
use ratatui::Frame;

use crate::doctor::CheckStatus;

use super::bar::{display_width, truncate_width};
use super::state::{
    filtered_palette, AppState, HitRegion, HitTarget, LogFilter, Modal, OnboardingChoice,
    OnboardingModal, OnboardingStep, PairModal, PairStatus, PairTab, RevokeModal, SettingsModal,
    SudoModal, TextField,
};
use super::theme::Theme;

pub fn centered_rect(area: Rect, want_w: u16, want_h: u16) -> Rect {
    let w = want_w.min(area.width.saturating_sub(2).max(1)).max(1);
    let h = want_h.min(area.height.saturating_sub(2).max(1)).max(1);
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    Rect::new(x, y, w, h)
}

/// Gently dim the underlying screen buffer so the active modal visually pops.
fn dim_backdrop(f: &mut Frame, area: Rect) {
    let buf = f.buffer_mut();
    for y in area.y..area.y.saturating_add(area.height) {
        for x in area.x..area.x.saturating_add(area.width) {
            let cell = &mut buf[(x, y)];
            cell.modifier.insert(Modifier::DIM);
        }
    }
}

pub fn draw_modal(f: &mut Frame, app: &mut AppState, theme: Theme, area: Rect) {
    let Some(modal) = app.modal.clone() else {
        app.modal_area = None;
        return;
    };
    if area.width < 12 || area.height < 6 {
        return;
    }

    dim_backdrop(f, area);
    // Register backdrop hit target before modal widgets so clicks outside dismiss.
    app.hit_regions.push(HitRegion {
        rect: area,
        target: HitTarget::ModalBackdrop,
    });

    match modal {
        Modal::Palette { query, selected } => draw_palette(f, app, theme, area, &query, selected),
        Modal::SudoPrompt(ref s) => draw_sudo_modal(f, app, theme, area, s),
        Modal::Pair(ref p) => draw_pair_modal(f, app, theme, area, p),
        Modal::OnboardingForm(ref o) => draw_onboarding_modal(f, app, theme, area, o),
        Modal::Doctor(ref d) => draw_doctor_modal(f, app, theme, area, d),
        Modal::Logs(ref l) => draw_logs_modal(f, app, theme, area, l),
        Modal::Settings(ref s) => draw_settings_modal(f, app, theme, area, s),
        Modal::RevokeConfirm(ref r) => draw_revoke_modal(f, app, theme, area, r),
        Modal::StopConfirm => draw_stop_confirm(f, app, theme, area),
        Modal::Help => draw_help_modal(f, app, theme, area),
    }
}

fn modal_frame(
    f: &mut Frame,
    app: &mut AppState,
    popup: Rect,
    title: &str,
    hint: &str,
    border_color: Color,
    theme: Theme,
) -> Rect {
    app.modal_area = Some(popup);
    f.render_widget(Clear, popup);
    let mut block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(border_color))
        .padding(Padding::new(2, 2, 1, 1))
        .title(Span::styled(
            format!(" {title} "),
            Style::default()
                .fg(border_color)
                .add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(theme.panel));
    if !hint.is_empty() {
        block = block.title_top(
            Line::from(Span::styled(
                format!(" {hint} "),
                Style::default().fg(theme.dim),
            ))
            .right_aligned(),
        );
    }
    let inner = block.inner(popup);
    f.render_widget(block, popup);

    // Clicking the [Esc] / top-right close area closes the modal.
    if popup.width >= 8 {
        let close_w = (display_width(hint) as u16 + 2).min(popup.width / 2);
        if close_w > 0 {
            app.hit_regions.push(HitRegion {
                rect: Rect::new(popup.x + popup.width.saturating_sub(close_w + 1), popup.y, close_w, 1),
                target: HitTarget::ModalClose,
            });
        }
    }

    inner
}

#[derive(Clone, Copy)]
enum ButtonKind {
    Primary,
    Secondary,
    Danger,
}

struct ButtonSpec<'a> {
    label: &'a str,
    kind: ButtonKind,
    target: HitTarget,
}

fn render_buttons(
    f: &mut Frame,
    app: &mut AppState,
    area: Rect,
    theme: Theme,
    buttons: &[ButtonSpec<'_>],
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let mut spans = Vec::new();
    let mut cx = area.x;
    let right_edge = area.x + area.width;

    for (idx, btn) in buttons.iter().enumerate() {
        if idx > 0 {
            spans.push(Span::styled("  ", Style::default().bg(theme.panel)));
            cx = cx.saturating_add(2);
        }
        let text = format!(" {} ", btn.label);
        let w = display_width(&text) as u16;
        if cx >= right_edge {
            break;
        }
        let style = match btn.kind {
            ButtonKind::Primary => Style::default()
                .fg(theme.accent_fg)
                .bg(theme.accent)
                .add_modifier(Modifier::BOLD),
            ButtonKind::Secondary => Style::default().fg(theme.text).bg(theme.surface),
            ButtonKind::Danger => Style::default()
                .fg(theme.bad)
                .bg(theme.bad_bg)
                .add_modifier(Modifier::BOLD),
        };
        let hit_w = w.min(right_edge.saturating_sub(cx));
        app.hit_regions.push(HitRegion {
            rect: Rect::new(cx, area.y, hit_w, 1),
            target: btn.target.clone(),
        });
        spans.push(Span::styled(text, style));
        cx = cx.saturating_add(w);
    }
    f.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(theme.panel)),
        area,
    );
}

#[allow(clippy::too_many_arguments)]
fn render_field(
    f: &mut Frame,
    app: &mut AppState,
    area: Rect,
    label: &str,
    field: &TextField,
    focused: bool,
    hit: Option<HitTarget>,
    right_action: Option<(&str, HitTarget)>,
    theme: Theme,
) {
    if area.height < 2 || area.width < 8 {
        return;
    }
    // Label line (row 0)
    let label_area = Rect::new(area.x, area.y, area.width, 1);
    let label_fg = if focused { theme.accent } else { theme.dim };
    let mut label_spans = vec![Span::styled(
        label.to_string(),
        Style::default()
            .fg(label_fg)
            .bg(theme.panel)
            .add_modifier(if focused { Modifier::BOLD } else { Modifier::empty() }),
    )];
    if let Some((act_label, act_target)) = right_action {
        let act_text = format!(" [{act_label}]");
        let act_w = display_width(&act_text) as u16;
        let used = display_width(label) as u16;
        let gap = area.width.saturating_sub(used + act_w);
        if gap > 0 {
            label_spans.push(Span::styled(
                " ".repeat(gap as usize),
                Style::default().bg(theme.panel),
            ));
        }
        let ax = area.x + used + gap;
        app.hit_regions.push(HitRegion {
            rect: Rect::new(ax, area.y, act_w.min(area.width), 1),
            target: act_target,
        });
        label_spans.push(Span::styled(
            act_text,
            Style::default().fg(theme.secondary).bg(theme.panel),
        ));
    }
    f.render_widget(
        Paragraph::new(Line::from(label_spans)).style(Style::default().bg(theme.panel)),
        label_area,
    );

    // Input row (row 1)
    let input_area = Rect::new(area.x, area.y + 1, area.width, 1);
    if let Some(target) = hit {
        app.hit_regions.push(HitRegion {
            rect: Rect::new(area.x, area.y, area.width, 2),
            target,
        });
    }
    let bg = if focused {
        theme.selection
    } else {
        theme.surface
    };
    let bar = if focused { "▎ " } else { "  " };
    let bar_fg = if focused { theme.accent } else { theme.border };
    let inner_w = area.width.saturating_sub(3) as usize;

    let display = field.display_text();
    let (shown, text_fg, cursor_offset) = if display.is_empty() {
        (
            truncate_width(&field.placeholder, inner_w),
            theme.dim,
            0usize,
        )
    } else {
        // Horizontal scroll window around cursor when value is wider than the field.
        let cursor_w = field.cursor_display_width();
        let total_w = display_width(&display);
        if total_w <= inner_w {
            (display, theme.text, cursor_w)
        } else {
            let skip_w = cursor_w.saturating_sub(inner_w.saturating_sub(2));
            let mut acc_w = 0usize;
            let mut sliced = String::new();
            let mut shown_w = 0usize;
            for ch in display.chars() {
                let mut buf = [0u8; 4];
                let cw = display_width(ch.encode_utf8(&mut buf));
                if acc_w + cw <= skip_w {
                    acc_w += cw;
                    continue;
                }
                if shown_w + cw > inner_w {
                    break;
                }
                sliced.push(ch);
                shown_w += cw;
                acc_w += cw;
            }
            (sliced, theme.text, cursor_w.saturating_sub(skip_w).min(inner_w))
        }
    };

    let line = Line::from(vec![
        Span::styled(bar, Style::default().fg(bar_fg).bg(bg)),
        Span::styled(shown, Style::default().fg(text_fg).bg(bg)),
    ]);
    f.render_widget(Paragraph::new(line).style(Style::default().bg(bg)), input_area);

    if focused {
        let cx = (input_area.x + 2 + cursor_offset as u16)
            .min(input_area.x + input_area.width.saturating_sub(1));
        f.set_cursor_position((cx, input_area.y));
    }
}

fn draw_palette(
    f: &mut Frame,
    app: &mut AppState,
    theme: Theme,
    area: Rect,
    query: &TextField,
    selected: usize,
) {
    let matches = filtered_palette(&query.value);
    let want_h = ((matches.len() as u16) + 7).clamp(11, 22);
    let popup = centered_rect(area, 72, want_h);
    let inner = modal_frame(
        f,
        app,
        popup,
        "Command Palette",
        "Esc",
        theme.accent,
        theme,
    );
    if inner.height < 4 {
        return;
    }

    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Length(1), Constraint::Min(2)])
        .split(inner);

    render_field(
        f,
        app,
        parts[0],
        "Search commands",
        query,
        true,
        None,
        None,
        theme,
    );

    f.render_widget(
        Paragraph::new(Line::styled(
            "─".repeat(parts[1].width as usize),
            Style::default().fg(theme.border).bg(theme.panel),
        )),
        parts[1],
    );

    let list_area = parts[2];
    let visible = list_area.height as usize;
    if matches.is_empty() {
        f.render_widget(
            Paragraph::new(Line::styled(
                " No matching commands",
                Style::default().fg(theme.dim).bg(theme.panel),
            )),
            list_area,
        );
        return;
    }

    let sel = selected.min(matches.len() - 1);
    let offset = if sel >= visible && visible > 0 {
        sel + 1 - visible
    } else {
        0
    };

    for (row_idx, (idx, (label, desc, key, _))) in matches
        .iter()
        .enumerate()
        .skip(offset)
        .take(visible)
        .enumerate()
    {
        let y = list_area.y + row_idx as u16;
        let row_rect = Rect::new(list_area.x, y, list_area.width, 1);
        let is_sel = idx == sel;
        let bg = if is_sel { theme.selection } else { theme.panel };
        app.hit_regions.push(HitRegion {
            rect: row_rect,
            target: HitTarget::PaletteRow(idx),
        });

        let key_text = if key.is_empty() {
            String::new()
        } else {
            format!(" {key} ")
        };
        let key_w = display_width(&key_text);
        let marker = if is_sel { "▸ " } else { "  " };
        let label_part = format!("{marker}{label}");
        let label_w = display_width(&label_part);
        let desc_budget = (list_area.width as usize)
            .saturating_sub(label_w + key_w + 3);
        let desc_shown = if desc_budget >= 8 {
            truncate_width(desc, desc_budget)
        } else {
            String::new()
        };
        let used = label_w
            + if desc_shown.is_empty() {
                0
            } else {
                2 + display_width(&desc_shown)
            }
            + key_w;
        let gap = (list_area.width as usize).saturating_sub(used);

        let mut spans = vec![Span::styled(
            label_part,
            Style::default()
                .fg(if is_sel { theme.accent } else { theme.text })
                .bg(bg)
                .add_modifier(if is_sel { Modifier::BOLD } else { Modifier::empty() }),
        )];
        if !desc_shown.is_empty() {
            spans.push(Span::styled("  ", Style::default().bg(bg)));
            spans.push(Span::styled(desc_shown, Style::default().fg(theme.dim).bg(bg)));
        }
        if gap > 0 {
            spans.push(Span::styled(" ".repeat(gap), Style::default().bg(bg)));
        }
        if !key_text.is_empty() {
            spans.push(Span::styled(
                key_text,
                Style::default().fg(theme.secondary).bg(theme.surface),
            ));
        }
        f.render_widget(
            Paragraph::new(Line::from(spans)).style(Style::default().bg(bg)),
            row_rect,
        );
    }
}

fn draw_sudo_modal(
    f: &mut Frame,
    app: &mut AppState,
    theme: Theme,
    area: Rect,
    sudo: &SudoModal,
) {
    let popup = centered_rect(area, 64, 15);
    let inner = modal_frame(
        f,
        app,
        popup,
        "Administrator Password · VPN TUN",
        "Esc",
        theme.accent,
        theme,
    );
    if inner.height < 8 {
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // description
            Constraint::Length(1), // command preview
            Constraint::Length(1), // spacer
            Constraint::Length(2), // password field
            Constraint::Length(2), // error / spinner
            Constraint::Min(1),    // buttons
        ])
        .split(inner);

    f.render_widget(
        Paragraph::new(Line::styled(
            "Creating the 100.64.0.0/10 TUN interface requires sudo privileges.",
            Style::default().fg(theme.text).bg(theme.panel),
        ))
        .wrap(Wrap { trim: false }),
        chunks[0],
    );

    let cmd_preview = truncate_width(&sudo.command_preview, chunks[1].width.saturating_sub(4) as usize);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" $ ", Style::default().fg(theme.accent).bg(theme.surface)),
            Span::styled(
                format!("{cmd_preview} "),
                Style::default().fg(theme.dim).bg(theme.surface),
            ),
        ]))
        .style(Style::default().bg(theme.surface)),
        chunks[1],
    );

    let reveal_lbl = if sudo.password.reveal { "Hide" } else { "Show" };
    render_field(
        f,
        app,
        chunks[3],
        "sudo password",
        &sudo.password,
        !sudo.busy && sudo.focus == 0,
        None,
        Some((reveal_lbl, HitTarget::SudoToggleReveal)),
        theme,
    );

    if sudo.busy {
        let spin = app.spinner_glyph();
        let label = if sudo.restart_first {
            format!("{spin} Stopping previous daemon and launching VPN TUN…")
        } else {
            format!("{spin} Authenticating & starting VPN TUN daemon…")
        };
        f.render_widget(
            Paragraph::new(Line::styled(
                label,
                Style::default().fg(theme.warn).bg(theme.panel),
            )),
            chunks[4],
        );
    } else if let Some(ref err) = sudo.error {
        f.render_widget(
            Paragraph::new(Line::styled(
                format!("✕ {err}"),
                Style::default()
                    .fg(theme.bad)
                    .bg(theme.panel)
                    .add_modifier(Modifier::BOLD),
            ))
            .wrap(Wrap { trim: false }),
            chunks[4],
        );
    }

    if !sudo.busy {
        render_buttons(
            f,
            app,
            chunks[5],
            theme,
            &[
                ButtonSpec {
                    label: "Start TUN  ↵",
                    kind: if sudo.focus == 0 || sudo.focus == 1 {
                        ButtonKind::Primary
                    } else {
                        ButtonKind::Secondary
                    },
                    target: HitTarget::SudoSubmit,
                },
                ButtonSpec {
                    label: "Start No-TUN",
                    kind: if sudo.focus == 2 {
                        ButtonKind::Primary
                    } else {
                        ButtonKind::Secondary
                    },
                    target: HitTarget::SudoFallbackNoTun,
                },
                ButtonSpec {
                    label: "Cancel",
                    kind: if sudo.focus == 3 {
                        ButtonKind::Primary
                    } else {
                        ButtonKind::Secondary
                    },
                    target: HitTarget::ModalClose,
                },
            ],
        );
    }
}

fn draw_pair_modal(
    f: &mut Frame,
    app: &mut AppState,
    theme: Theme,
    area: Rect,
    pair: &PairModal,
) {
    let popup = centered_rect(area, 76, 17);
    let inner = modal_frame(
        f,
        app,
        popup,
        "Pair / Add New Device",
        "Esc",
        theme.accent,
        theme,
    );
    if inner.height < 8 {
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // tabs
            Constraint::Length(1), // separator
            Constraint::Min(6),    // content
            Constraint::Length(1), // bottom buttons
        ])
        .split(inner);

    // Tab bar
    let tab_specs = [
        (PairTab::Phrase, "Phrase Pairing (Recommended)"),
        (PairTab::Bundle, "Setup Bundle / Code"),
    ];
    let mut tab_spans = Vec::new();
    let mut cx = chunks[0].x;
    for (idx, (t, lbl)) in tab_specs.iter().enumerate() {
        if idx > 0 {
            tab_spans.push(Span::styled("  ", Style::default().bg(theme.panel)));
            cx = cx.saturating_add(2);
        }
        let active = pair.tab == *t;
        let text = format!(" {lbl} ");
        let w = display_width(&text) as u16;
        app.hit_regions.push(HitRegion {
            rect: Rect::new(cx, chunks[0].y, w.min(chunks[0].width), 1),
            target: HitTarget::PairSelectTab(*t),
        });
        tab_spans.push(Span::styled(
            text,
            if active {
                Style::default()
                    .fg(theme.accent)
                    .bg(theme.accent_bg)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.dim).bg(theme.panel)
            },
        ));
        cx = cx.saturating_add(w);
    }
    f.render_widget(
        Paragraph::new(Line::from(tab_spans)).style(Style::default().bg(theme.panel)),
        chunks[0],
    );

    f.render_widget(
        Paragraph::new(Line::styled(
            "─".repeat(chunks[1].width as usize),
            Style::default().fg(theme.border).bg(theme.panel),
        )),
        chunks[1],
    );

    let body = chunks[2];
    let spin = app.spinner_glyph();

    match &pair.status {
        PairStatus::Idle if pair.tab == PairTab::Phrase => {
            let sub = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(2),
                    Constraint::Length(1),
                    Constraint::Length(2),
                    Constraint::Min(1),
                ])
                .split(body);
            f.render_widget(
                Paragraph::new(Line::styled(
                    "Choose any short phrase (4+ chars). Type the same phrase on the new device — zero copy-paste.",
                    Style::default().fg(theme.dim).bg(theme.panel),
                ))
                .wrap(Wrap { trim: false }),
                sub[0],
            );
            render_field(
                f,
                app,
                sub[2],
                "Shared pairing phrase",
                &pair.phrase,
                true,
                None,
                None,
                theme,
            );
            render_buttons(
                f,
                app,
                chunks[3],
                theme,
                &[
                    ButtonSpec {
                        label: "Start Pairing  ↵",
                        kind: ButtonKind::Primary,
                        target: HitTarget::PairStartPhrase,
                    },
                    ButtonSpec {
                        label: "Close",
                        kind: ButtonKind::Secondary,
                        target: HitTarget::ModalClose,
                    },
                ],
            );
        }
        PairStatus::Idle | PairStatus::Starting => {
            f.render_widget(
                Paragraph::new(Line::styled(
                    format!("{spin} Preparing pairing session on coord…"),
                    Style::default().fg(theme.warn).bg(theme.panel),
                )),
                body,
            );
            render_buttons(
                f,
                app,
                chunks[3],
                theme,
                &[ButtonSpec {
                    label: "Cancel",
                    kind: ButtonKind::Secondary,
                    target: HitTarget::ModalClose,
                }],
            );
        }
        PairStatus::WaitingPhrase { phrase, peer_cmd } => {
            let lines = vec![
                Line::from(vec![
                    Span::styled("Phrase  ", Style::default().fg(theme.dim)),
                    Span::styled(
                        format!(" {phrase} "),
                        Style::default()
                            .fg(theme.accent)
                            .bg(theme.accent_bg)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    "On the new device, open `topaz` → Pair with Phrase, or run:",
                    Style::default().fg(theme.dim),
                )),
                Line::from(Span::styled(
                    format!("  {peer_cmd}"),
                    Style::default()
                        .fg(theme.text)
                        .bg(theme.surface)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    format!("{spin} Waiting up to 5 minutes for the new device…"),
                    Style::default().fg(theme.warn),
                )),
            ];
            f.render_widget(
                Paragraph::new(lines)
                    .style(Style::default().bg(theme.panel))
                    .wrap(Wrap { trim: false }),
                body,
            );
            render_buttons(
                f,
                app,
                chunks[3],
                theme,
                &[
                    ButtonSpec {
                        label: "Copy Command",
                        kind: ButtonKind::Primary,
                        target: HitTarget::PairCopyCmd(peer_cmd.clone()),
                    },
                    ButtonSpec {
                        label: "Cancel",
                        kind: ButtonKind::Secondary,
                        target: HitTarget::ModalClose,
                    },
                ],
            );
        }
        PairStatus::ConfirmPeer {
            device_name,
            device_id,
            sas,
        } => {
            let lines = vec![
                Line::from(Span::styled(
                    "Incoming pairing request verified via SPAKE2:",
                    Style::default().fg(theme.ok).add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(vec![
                    Span::styled("  Device Name  ", Style::default().fg(theme.dim)),
                    Span::styled(
                        device_name.clone(),
                        Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("  Device ID    ", Style::default().fg(theme.dim)),
                    Span::styled(device_id.clone(), Style::default().fg(theme.secondary)),
                ]),
                Line::from(vec![
                    Span::styled("  Verify Code  ", Style::default().fg(theme.dim)),
                    Span::styled(
                        sas.clone(),
                        Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    "Confirm code matches the new device, then approve?",
                    Style::default().fg(theme.text),
                )),
            ];
            f.render_widget(
                Paragraph::new(lines)
                    .style(Style::default().bg(theme.panel))
                    .wrap(Wrap { trim: false }),
                body,
            );
            render_buttons(
                f,
                app,
                chunks[3],
                theme,
                &[
                    ButtonSpec {
                        label: "Approve Device  ↵",
                        kind: ButtonKind::Primary,
                        target: HitTarget::PairApprovePeer(true),
                    },
                    ButtonSpec {
                        label: "Reject",
                        kind: ButtonKind::Danger,
                        target: HitTarget::PairApprovePeer(false),
                    },
                ],
            );
        }
        PairStatus::WaitingBundle { code, setup } => {
            let cmd = format!("topaz setup '{setup}' --start");
            let lines = vec![
                Line::from(vec![
                    Span::styled("Short Code  ", Style::default().fg(theme.dim)),
                    Span::styled(
                        format!(" {code} "),
                        Style::default()
                            .fg(theme.accent)
                            .bg(theme.accent_bg)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    "Paste the bundle in the new device's TUI, or run:",
                    Style::default().fg(theme.dim),
                )),
                Line::from(Span::styled(
                    cmd.clone(),
                    Style::default().fg(theme.text).bg(theme.surface),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    format!("{spin} Waiting up to 5 minutes for the new device…"),
                    Style::default().fg(theme.warn),
                )),
            ];
            f.render_widget(
                Paragraph::new(lines)
                    .style(Style::default().bg(theme.panel))
                    .wrap(Wrap { trim: false }),
                body,
            );
            render_buttons(
                f,
                app,
                chunks[3],
                theme,
                &[
                    ButtonSpec {
                        label: "Copy Setup Command",
                        kind: ButtonKind::Primary,
                        target: HitTarget::PairCopyCmd(cmd),
                    },
                    ButtonSpec {
                        label: "Copy Bundle Only",
                        kind: ButtonKind::Secondary,
                        target: HitTarget::PairCopyCmd(setup.clone()),
                    },
                    ButtonSpec {
                        label: "Cancel",
                        kind: ButtonKind::Secondary,
                        target: HitTarget::ModalClose,
                    },
                ],
            );
        }
        PairStatus::Added { name, device_id } => {
            let lines = vec![
                Line::from(""),
                Line::from(Span::styled(
                    format!("✓ Added {name}"),
                    Style::default().fg(theme.ok).add_modifier(Modifier::BOLD),
                )),
                Line::from(Span::styled(
                    format!("  Device ID: {device_id}"),
                    Style::default().fg(theme.dim),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "The new device can now start Topaz and join the mesh.",
                    Style::default().fg(theme.text),
                )),
            ];
            f.render_widget(
                Paragraph::new(lines).style(Style::default().bg(theme.panel)),
                body,
            );
            render_buttons(
                f,
                app,
                chunks[3],
                theme,
                &[
                    ButtonSpec {
                        label: "Pair Another",
                        kind: ButtonKind::Secondary,
                        target: HitTarget::PairRestart,
                    },
                    ButtonSpec {
                        label: "Done  ↵",
                        kind: ButtonKind::Primary,
                        target: HitTarget::ModalClose,
                    },
                ],
            );
        }
        PairStatus::Failed(err) => {
            let lines = vec![
                Line::from(""),
                Line::from(Span::styled(
                    format!("✕ {err}"),
                    Style::default().fg(theme.bad).add_modifier(Modifier::BOLD),
                )),
            ];
            f.render_widget(
                Paragraph::new(lines)
                    .style(Style::default().bg(theme.panel))
                    .wrap(Wrap { trim: false }),
                body,
            );
            render_buttons(
                f,
                app,
                chunks[3],
                theme,
                &[
                    ButtonSpec {
                        label: "Try Again",
                        kind: ButtonKind::Primary,
                        target: HitTarget::PairRestart,
                    },
                    ButtonSpec {
                        label: "Close",
                        kind: ButtonKind::Secondary,
                        target: HitTarget::ModalClose,
                    },
                ],
            );
        }
    }
}

fn draw_onboarding_modal(
    f: &mut Frame,
    app: &mut AppState,
    theme: Theme,
    area: Rect,
    ob: &OnboardingModal,
) {
    let want_h = match &ob.step {
        OnboardingStep::Form => match ob.kind {
            OnboardingChoice::JoinBundle => 14,
            OnboardingChoice::JoinPhrase => 17,
            _ => 20,
        },
        OnboardingStep::RecoveryBackup { .. } => 17,
        OnboardingStep::TofuConfirm { .. } => 15,
        _ => 11,
    };
    let popup = centered_rect(area, 74, want_h);
    let inner = modal_frame(
        f,
        app,
        popup,
        ob.kind.title(),
        "Esc",
        theme.accent,
        theme,
    );
    if inner.height < 6 {
        return;
    }

    let spin = app.spinner_glyph();
    match &ob.step {
        OnboardingStep::ProbingPin => {
            f.render_widget(
                Paragraph::new(vec![
                    Line::from(""),
                    Line::styled(
                        format!("{spin} Probing coordination server TLS fingerprint…"),
                        Style::default().fg(theme.warn).bg(theme.panel),
                    ),
                ]),
                inner,
            );
        }
        OnboardingStep::Submitting(msg) => {
            f.render_widget(
                Paragraph::new(vec![
                    Line::from(""),
                    Line::styled(
                        format!("{spin} {msg}"),
                        Style::default().fg(theme.warn).bg(theme.panel),
                    ),
                    Line::from(""),
                    Line::styled(
                        "Press Esc to cancel.",
                        Style::default().fg(theme.dim).bg(theme.panel),
                    ),
                ]),
                inner,
            );
        }
        OnboardingStep::TofuConfirm { coord_url, pin } => {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(5), Constraint::Length(1)])
                .split(inner);
            let lines = vec![
                Line::from(Span::styled(
                    "Verify coordination server TLS fingerprint (TOFU):",
                    Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(vec![
                    Span::styled("  Server  ", Style::default().fg(theme.dim)),
                    Span::styled(coord_url.clone(), Style::default().fg(theme.link)),
                ]),
                Line::from(vec![
                    Span::styled("  Pin     ", Style::default().fg(theme.dim)),
                    Span::styled(
                        pin.clone(),
                        Style::default()
                            .fg(theme.accent)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    "Match this pin with `topaz-coord fingerprint` on your VPS.",
                    Style::default().fg(theme.dim),
                )),
            ];
            f.render_widget(
                Paragraph::new(lines)
                    .style(Style::default().bg(theme.panel))
                    .wrap(Wrap { trim: false }),
                chunks[0],
            );
            render_buttons(
                f,
                app,
                chunks[1],
                theme,
                &[
                    ButtonSpec {
                        label: "Trust & Continue  ↵",
                        kind: ButtonKind::Primary,
                        target: HitTarget::OnboardingTofuTrust,
                    },
                    ButtonSpec {
                        label: "Cancel",
                        kind: ButtonKind::Secondary,
                        target: HitTarget::ModalClose,
                    },
                ],
            );
        }
        OnboardingStep::RecoveryBackup {
            account_id,
            recovery_code,
        } => {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(7), Constraint::Length(1)])
                .split(inner);
            let lines = vec![
                Line::from(Span::styled(
                    format!("✓ Account {account_id} created!"),
                    Style::default().fg(theme.ok).add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "Save your Recovery Code now — it is NOT stored anywhere on disk:",
                    Style::default()
                        .fg(theme.warn)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    format!("  {recovery_code}  "),
                    Style::default()
                        .fg(theme.accent)
                        .bg(theme.surface)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "Use it to add devices when all other devices are offline, or to revoke a lost device.",
                    Style::default().fg(theme.dim),
                )),
            ];
            f.render_widget(
                Paragraph::new(lines)
                    .style(Style::default().bg(theme.panel))
                    .wrap(Wrap { trim: false }),
                chunks[0],
            );
            render_buttons(
                f,
                app,
                chunks[1],
                theme,
                &[
                    ButtonSpec {
                        label: "Copy Recovery Code",
                        kind: ButtonKind::Secondary,
                        target: HitTarget::OnboardingCopyRecovery(recovery_code.clone()),
                    },
                    ButtonSpec {
                        label: "I Saved It · Continue  ↵",
                        kind: ButtonKind::Primary,
                        target: HitTarget::OnboardingFinishRecovery,
                    },
                ],
            );
        }
        OnboardingStep::Form => {
            let mut constraints = Vec::new();
            for _ in 0..ob.field_count() {
                constraints.push(Constraint::Length(3));
            }
            constraints.push(Constraint::Min(2)); // error
            constraints.push(Constraint::Length(1)); // buttons
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints(constraints)
                .split(inner);

            let reveal_action = if ob.secret.masked {
                Some((
                    if ob.secret.reveal { "Hide" } else { "Show" },
                    HitTarget::OnboardingToggleReveal,
                ))
            } else {
                None
            };

            match ob.kind {
                OnboardingChoice::JoinPhrase => {
                    render_field(
                        f,
                        app,
                        chunks[0],
                        "Coord Server (IP or https://host:7722)",
                        &ob.coord_url,
                        ob.focus_field == 0,
                        Some(HitTarget::OnboardingFocusField(0)),
                        None,
                        theme,
                    );
                    render_field(
                        f,
                        app,
                        chunks[1],
                        "Shared Pairing Phrase",
                        &ob.secret,
                        ob.focus_field == 1,
                        Some(HitTarget::OnboardingFocusField(1)),
                        None,
                        theme,
                    );
                    render_field(
                        f,
                        app,
                        chunks[2],
                        "This Device Name",
                        &ob.device_name,
                        ob.focus_field == 2,
                        Some(HitTarget::OnboardingFocusField(2)),
                        None,
                        theme,
                    );
                }
                OnboardingChoice::JoinBundle => {
                    render_field(
                        f,
                        app,
                        chunks[0],
                        "Setup Bundle (`topaz-setup:v1:...`) or Short Code",
                        &ob.secret,
                        ob.focus_field == 0,
                        Some(HitTarget::OnboardingFocusField(0)),
                        None,
                        theme,
                    );
                    render_field(
                        f,
                        app,
                        chunks[1],
                        "This Device Name",
                        &ob.device_name,
                        ob.focus_field == 1,
                        Some(HitTarget::OnboardingFocusField(1)),
                        None,
                        theme,
                    );
                }
                OnboardingChoice::CreateAccount => {
                    render_field(
                        f,
                        app,
                        chunks[0],
                        "Coord Server (IP or https://host:7722)",
                        &ob.coord_url,
                        ob.focus_field == 0,
                        Some(HitTarget::OnboardingFocusField(0)),
                        None,
                        theme,
                    );
                    render_field(
                        f,
                        app,
                        chunks[1],
                        "Coord TLS Pin (optional — blank auto-probes)",
                        &ob.coord_pin,
                        ob.focus_field == 1,
                        Some(HitTarget::OnboardingFocusField(1)),
                        None,
                        theme,
                    );
                    render_field(
                        f,
                        app,
                        chunks[2],
                        "Invite Code",
                        &ob.secret,
                        ob.focus_field == 2,
                        Some(HitTarget::OnboardingFocusField(2)),
                        None,
                        theme,
                    );
                    render_field(
                        f,
                        app,
                        chunks[3],
                        "This Device Name",
                        &ob.device_name,
                        ob.focus_field == 3,
                        Some(HitTarget::OnboardingFocusField(3)),
                        None,
                        theme,
                    );
                }
                OnboardingChoice::JoinRecovery => {
                    render_field(
                        f,
                        app,
                        chunks[0],
                        "Coord Server (IP or https://host:7722)",
                        &ob.coord_url,
                        ob.focus_field == 0,
                        Some(HitTarget::OnboardingFocusField(0)),
                        None,
                        theme,
                    );
                    render_field(
                        f,
                        app,
                        chunks[1],
                        "Coord TLS Pin (optional — blank auto-probes)",
                        &ob.coord_pin,
                        ob.focus_field == 1,
                        Some(HitTarget::OnboardingFocusField(1)),
                        None,
                        theme,
                    );
                    render_field(
                        f,
                        app,
                        chunks[2],
                        "Account Recovery Code",
                        &ob.secret,
                        ob.focus_field == 2,
                        Some(HitTarget::OnboardingFocusField(2)),
                        reveal_action,
                        theme,
                    );
                    render_field(
                        f,
                        app,
                        chunks[3],
                        "This Device Name",
                        &ob.device_name,
                        ob.focus_field == 3,
                        Some(HitTarget::OnboardingFocusField(3)),
                        None,
                        theme,
                    );
                }
            }

            let err_chunk = chunks[ob.field_count()];
            if let Some(ref err) = ob.error {
                f.render_widget(
                    Paragraph::new(Line::styled(
                        format!("✕ {err}"),
                        Style::default().fg(theme.bad).bg(theme.panel),
                    ))
                    .wrap(Wrap { trim: false }),
                    err_chunk,
                );
            } else {
                f.render_widget(
                    Paragraph::new(Line::styled(
                        "Tab / Click to switch fields · Paste works directly · Enter to continue",
                        Style::default().fg(theme.dim).bg(theme.panel),
                    )),
                    err_chunk,
                );
            }

            render_buttons(
                f,
                app,
                chunks[ob.field_count() + 1],
                theme,
                &[
                    ButtonSpec {
                        label: "Continue  ↵",
                        kind: ButtonKind::Primary,
                        target: HitTarget::OnboardingSubmit,
                    },
                    ButtonSpec {
                        label: "Cancel",
                        kind: ButtonKind::Secondary,
                        target: HitTarget::ModalClose,
                    },
                ],
            );
        }
    }
}

fn draw_doctor_modal(
    f: &mut Frame,
    app: &mut AppState,
    theme: Theme,
    area: Rect,
    doc: &super::state::DoctorModal,
) {
    let popup = centered_rect(area, 82, area.height.saturating_sub(4).clamp(16, 28));
    let inner = modal_frame(
        f,
        app,
        popup,
        "Network Doctor",
        "Esc",
        theme.accent,
        theme,
    );
    if inner.height < 6 {
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(4), Constraint::Length(1), Constraint::Length(1)])
        .split(inner);

    let spin = app.spinner_glyph();
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(Span::styled(
        "CONNECTIVITY CHECKS",
        Style::default().fg(theme.dim).add_modifier(Modifier::BOLD),
    )));
    for c in &doc.report.checks {
        let (glyph, color) = match c.status {
            CheckStatus::Ok => ("✓", theme.ok),
            CheckStatus::Warn => ("!", theme.warn),
            CheckStatus::Fail => ("✕", theme.bad),
            CheckStatus::Running => (spin, theme.accent),
            CheckStatus::Skipped => ("–", theme.dim),
        };
        let latency = c
            .latency_ms
            .map(|ms| format!("  {ms}ms"))
            .unwrap_or_default();
        lines.push(Line::from(vec![
            Span::styled(format!(" {glyph} "), Style::default().fg(color).add_modifier(Modifier::BOLD)),
            Span::styled(format!("{:<14} ", c.label), Style::default().fg(theme.text)),
            Span::styled(c.detail.clone(), Style::default().fg(if c.status == CheckStatus::Fail { theme.bad } else { theme.dim })),
            Span::styled(latency, Style::default().fg(theme.secondary)),
        ]));
    }

    if !doc.report.local_addrs.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "LOCAL INTERFACES",
            Style::default().fg(theme.dim).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(Span::styled(
            format!("  {}", doc.report.local_addrs.join("  ·  ")),
            Style::default().fg(theme.text),
        )));
    }

    if !doc.report.peers.is_empty() || doc.report.peers_error.is_some() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "PEERS & ENDPOINTS",
            Style::default().fg(theme.dim).add_modifier(Modifier::BOLD),
        )));
        if let Some(ref err) = doc.report.peers_error {
            lines.push(Line::from(Span::styled(
                format!("  ✕ {err}"),
                Style::default().fg(theme.bad),
            )));
        }
        for p in &doc.report.peers {
            let sess = p.session_path.as_deref().unwrap_or("offline");
            let sess_color = match p.session_path.as_deref() {
                Some("direct") => theme.ok,
                Some(_) => theme.warn,
                None => theme.dim,
            };
            let rtt = p
                .rtt_ms
                .map(|m| format!(" {m}ms"))
                .unwrap_or_default();
            lines.push(Line::from(vec![
                Span::styled(format!("  {} ", p.name), Style::default().fg(theme.text).add_modifier(Modifier::BOLD)),
                Span::styled(format!("{sess}{rtt}"), Style::default().fg(sess_color)),
                Span::styled(
                    p.lan_addr
                        .as_deref()
                        .map(|a| format!("  · LAN {a}"))
                        .unwrap_or_default(),
                    Style::default().fg(theme.secondary),
                ),
            ]));
            if let Some(ref eps) = p.udp_endpoints {
                if !eps.is_empty() {
                    lines.push(Line::from(Span::styled(
                        format!("    udp: {}", eps.join("  ")),
                        Style::default().fg(theme.dim),
                    )));
                }
            }
        }
    }

    let content_h = lines.len() as u16;
    let max_scroll = content_h.saturating_sub(chunks[0].height);
    let scroll = doc.scroll.min(max_scroll);
    if let Some(Modal::Doctor(ref mut m)) = app.modal {
        m.max_scroll = max_scroll;
        m.scroll = scroll;
    }

    f.render_widget(
        Paragraph::new(lines)
            .style(Style::default().bg(theme.panel))
            .scroll((scroll, 0))
            .wrap(Wrap { trim: false }),
        chunks[0],
    );

    render_buttons(
        f,
        app,
        chunks[2],
        theme,
        &[
            ButtonSpec {
                label: "Re-run  Ctrl+R",
                kind: ButtonKind::Primary,
                target: HitTarget::DoctorRerun,
            },
            ButtonSpec {
                label: "Copy Summary",
                kind: ButtonKind::Secondary,
                target: HitTarget::DoctorCopy,
            },
            ButtonSpec {
                label: "Close",
                kind: ButtonKind::Secondary,
                target: HitTarget::ModalClose,
            },
        ],
    );
}

fn draw_logs_modal(
    f: &mut Frame,
    app: &mut AppState,
    theme: Theme,
    area: Rect,
    logs: &super::state::LogsModal,
) {
    let popup = centered_rect(
        area,
        area.width.saturating_sub(6).clamp(64, 110),
        area.height.saturating_sub(4).clamp(16, 30),
    );
    let inner = modal_frame(
        f,
        app,
        popup,
        "Daemon Logs (topaz.log)",
        "Esc",
        theme.accent,
        theme,
    );
    if inner.height < 6 {
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(4),
            Constraint::Length(1),
        ])
        .split(inner);

    // Filter toolbar
    let mut cx = chunks[0].x;
    let mut bar_spans = Vec::new();
    for (idx, flt) in [LogFilter::All, LogFilter::Warn, LogFilter::Error]
        .iter()
        .enumerate()
    {
        if idx > 0 {
            bar_spans.push(Span::styled(" ", Style::default().bg(theme.panel)));
            cx = cx.saturating_add(1);
        }
        let active = logs.filter == *flt;
        let text = format!(" {} ", flt.label());
        let w = display_width(&text) as u16;
        app.hit_regions.push(HitRegion {
            rect: Rect::new(cx, chunks[0].y, w, 1),
            target: HitTarget::LogsFilter(*flt),
        });
        bar_spans.push(Span::styled(
            text,
            if active {
                Style::default()
                    .fg(theme.accent)
                    .bg(theme.accent_bg)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.dim).bg(theme.surface)
            },
        ));
        cx = cx.saturating_add(w);
    }

    bar_spans.push(Span::styled("   ", Style::default().bg(theme.panel)));
    cx = cx.saturating_add(3);
    let follow_txt = if logs.follow { " Follow: ON " } else { " Follow: OFF " };
    let fw = display_width(follow_txt) as u16;
    app.hit_regions.push(HitRegion {
        rect: Rect::new(cx, chunks[0].y, fw, 1),
        target: HitTarget::LogsToggleFollow,
    });
    bar_spans.push(Span::styled(
        follow_txt,
        Style::default()
            .fg(if logs.follow { theme.ok } else { theme.dim })
            .bg(theme.surface),
    ));

    f.render_widget(
        Paragraph::new(Line::from(bar_spans)).style(Style::default().bg(theme.panel)),
        chunks[0],
    );

    f.render_widget(
        Paragraph::new(Line::styled(
            "─".repeat(chunks[1].width as usize),
            Style::default().fg(theme.border).bg(theme.panel),
        )),
        chunks[1],
    );

    let filtered = logs.filtered_lines();
    let rendered_lines: Vec<Line> = if filtered.is_empty() {
        vec![Line::styled(
            format!(" (no log lines in {})", logs.log_path.display()),
            Style::default().fg(theme.dim).bg(theme.surface),
        )]
    } else {
        filtered
            .iter()
            .map(|l| {
                let upper = l.to_ascii_uppercase();
                let color = if upper.contains("ERROR") || upper.contains("FAILED") {
                    theme.bad
                } else if upper.contains("WARN") {
                    theme.warn
                } else {
                    theme.text
                };
                Line::styled((*l).to_string(), Style::default().fg(color).bg(theme.surface))
            })
            .collect()
    };

    let max_scroll = (rendered_lines.len() as u16).saturating_sub(chunks[2].height);
    let scroll = if logs.follow {
        max_scroll
    } else {
        logs.scroll.min(max_scroll)
    };
    if let Some(Modal::Logs(ref mut m)) = app.modal {
        m.max_scroll = max_scroll;
        m.scroll = scroll;
    }

    f.render_widget(
        Paragraph::new(rendered_lines)
            .style(Style::default().bg(theme.surface))
            .scroll((scroll, 0)),
        chunks[2],
    );

    render_buttons(
        f,
        app,
        chunks[3],
        theme,
        &[
            ButtonSpec {
                label: "Copy Tail",
                kind: ButtonKind::Secondary,
                target: HitTarget::LogsCopy,
            },
            ButtonSpec {
                label: "Close",
                kind: ButtonKind::Primary,
                target: HitTarget::ModalClose,
            },
        ],
    );
}

fn draw_settings_modal(
    f: &mut Frame,
    app: &mut AppState,
    theme: Theme,
    area: Rect,
    set: &SettingsModal,
) {
    let popup = centered_rect(area, 76, area.height.saturating_sub(3).clamp(22, 29));
    let inner = modal_frame(
        f,
        app,
        popup,
        "Settings & Autostart",
        "Esc",
        theme.accent,
        theme,
    );
    if inner.height < 14 {
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // device_name
            Constraint::Length(3), // coord_url
            Constraint::Length(3), // coord_pin + probe
            Constraint::Length(1), // force_relay + appearance toggles
            Constraint::Length(1), // spacer
            Constraint::Length(3), // autostart service block
            Constraint::Length(2), // copyable paths
            Constraint::Min(1),    // error/status
            Constraint::Length(1), // save/close
        ])
        .split(inner);

    render_field(
        f,
        app,
        chunks[0],
        "Device Name",
        &set.device_name,
        set.focus_idx == 0,
        Some(HitTarget::SettingsFocus(0)),
        None,
        theme,
    );
    render_field(
        f,
        app,
        chunks[1],
        "Coord Server URL",
        &set.coord_url,
        set.focus_idx == 1,
        Some(HitTarget::SettingsFocus(1)),
        None,
        theme,
    );
    let probe_lbl = if set.probing_pin { "Probing…" } else { "Probe Pin" };
    render_field(
        f,
        app,
        chunks[2],
        "Coord TLS Pin",
        &set.coord_pin,
        set.focus_idx == 2,
        Some(HitTarget::SettingsFocus(2)),
        Some((probe_lbl, HitTarget::SettingsProbePin)),
        theme,
    );

    // Toggles row: Force Relay · Theme · Mouse Capture
    let mut tx = chunks[3].x;
    let mut toggle_spans = Vec::new();
    let toggle_items = [
        (
            format!(" Force Relay: {} ", if set.force_relay { "ON" } else { "OFF" }),
            if set.force_relay { theme.warn } else { theme.dim },
            set.focus_idx == 3,
            HitTarget::SettingsFocus(3),
        ),
        (
            format!(" Theme: {} ", app.theme.label()),
            theme.accent,
            set.focus_idx == 4,
            HitTarget::SettingsCycleTheme,
        ),
        (
            format!(" Mouse: {} ", if app.mouse_capture { "ON" } else { "OFF" }),
            if app.mouse_capture { theme.ok } else { theme.warn },
            set.focus_idx == 5,
            HitTarget::SettingsToggleMouse,
        ),
    ];
    for (idx, (lbl, fg, focused, target)) in toggle_items.into_iter().enumerate() {
        if idx > 0 {
            toggle_spans.push(Span::styled("  ", Style::default().bg(theme.panel)));
            tx = tx.saturating_add(2);
        }
        let w = display_width(&lbl) as u16;
        app.hit_regions.push(HitRegion {
            rect: Rect::new(tx, chunks[3].y, w, 1),
            target,
        });
        toggle_spans.push(Span::styled(
            lbl,
            Style::default()
                .fg(fg)
                .bg(if focused { theme.selection } else { theme.surface })
                .add_modifier(if focused { Modifier::BOLD } else { Modifier::empty() }),
        ));
        tx = tx.saturating_add(w);
    }
    f.render_widget(
        Paragraph::new(Line::from(toggle_spans)).style(Style::default().bg(theme.panel)),
        chunks[3],
    );

    // Autostart section
    let svc_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1), Constraint::Length(1)])
        .split(chunks[5]);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                "AUTOSTART  ",
                Style::default().fg(theme.dim).add_modifier(Modifier::BOLD),
            ),
            Span::styled(app.local.service_status.clone(), Style::default().fg(theme.secondary)),
        ]))
        .style(Style::default().bg(theme.panel)),
        svc_chunks[0],
    );
    render_buttons(
        f,
        app,
        svc_chunks[2],
        theme,
        &[
            ButtonSpec {
                label: "Install Autostart (TUN)",
                kind: ButtonKind::Secondary,
                target: HitTarget::SettingsInstallAutostart(false),
            },
            ButtonSpec {
                label: "Install (No-TUN)",
                kind: ButtonKind::Secondary,
                target: HitTarget::SettingsInstallAutostart(true),
            },
            ButtonSpec {
                label: "Uninstall",
                kind: ButtonKind::Danger,
                target: HitTarget::SettingsUninstallAutostart,
            },
        ],
    );

    // Copyable paths
    let path_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .split(chunks[6]);
    let data_str = app.local.data_dir.display().to_string();
    let sock_str = app.local.socket_path.display().to_string();
    app.hit_regions.push(HitRegion {
        rect: path_chunks[0],
        target: HitTarget::CopyText {
            label: "data dir".into(),
            text: data_str.clone(),
        },
    });
    app.hit_regions.push(HitRegion {
        rect: path_chunks[1],
        target: HitTarget::CopyText {
            label: "control.sock path".into(),
            text: sock_str.clone(),
        },
    });
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Data Dir   ", Style::default().fg(theme.dim)),
            Span::styled(
                truncate_width(&data_str, path_chunks[0].width.saturating_sub(20) as usize),
                Style::default().fg(theme.text),
            ),
            Span::styled("  [copy]", Style::default().fg(theme.dim)),
        ]))
        .style(Style::default().bg(theme.panel)),
        path_chunks[0],
    );
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Socket     ", Style::default().fg(theme.dim)),
            Span::styled(
                truncate_width(&sock_str, path_chunks[1].width.saturating_sub(20) as usize),
                Style::default().fg(theme.text),
            ),
            Span::styled("  [copy]", Style::default().fg(theme.dim)),
        ]))
        .style(Style::default().bg(theme.panel)),
        path_chunks[1],
    );

    if let Some(ref err) = set.error {
        f.render_widget(
            Paragraph::new(Line::styled(
                format!("✕ {err}"),
                Style::default().fg(theme.bad).bg(theme.panel),
            )),
            chunks[7],
        );
    }

    render_buttons(
        f,
        app,
        chunks[8],
        theme,
        &[
            ButtonSpec {
                label: "Save Config  ↵",
                kind: ButtonKind::Primary,
                target: HitTarget::SettingsSave,
            },
            ButtonSpec {
                label: "Close",
                kind: ButtonKind::Secondary,
                target: HitTarget::ModalClose,
            },
        ],
    );
}

fn draw_revoke_modal(
    f: &mut Frame,
    app: &mut AppState,
    theme: Theme,
    area: Rect,
    rev: &RevokeModal,
) {
    let want_h = if rev.use_recovery { 15 } else { 12 };
    let popup = centered_rect(area, 64, want_h);
    let inner = modal_frame(
        f,
        app,
        popup,
        "Confirm Device Revocation",
        "Esc",
        theme.bad,
        theme,
    );
    if inner.height < 6 {
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(1),
            Constraint::Length(if rev.use_recovery { 3 } else { 0 }),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(inner);

    f.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled("Permanently revoke ", Style::default().fg(theme.text)),
                Span::styled(
                    rev.name.clone(),
                    Style::default().fg(theme.bad).add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!(" ({})?", rev.device_id), Style::default().fg(theme.dim)),
            ]),
            Line::styled(
                "Its certificate will be rejected across all peers in your account.",
                Style::default().fg(theme.dim),
            ),
        ])
        .style(Style::default().bg(theme.panel)),
        chunks[0],
    );

    let chk = if rev.use_recovery { "[✓]" } else { "[ ]" };
    let chk_line = format!("{chk} Sign with account recovery code");
    app.hit_regions.push(HitRegion {
        rect: chunks[1],
        target: HitTarget::RevokeToggleRecovery,
    });
    f.render_widget(
        Paragraph::new(Line::styled(
            chk_line,
            Style::default()
                .fg(if rev.use_recovery { theme.accent } else { theme.dim })
                .bg(theme.panel),
        )),
        chunks[1],
    );

    if rev.use_recovery {
        let rev_lbl = if rev.recovery.reveal { "Hide" } else { "Show" };
        render_field(
            f,
            app,
            chunks[2],
            "Recovery code",
            &rev.recovery,
            !rev.busy,
            None,
            Some((rev_lbl, HitTarget::RevokeToggleReveal)),
            theme,
        );
    }

    if rev.busy {
        f.render_widget(
            Paragraph::new(Line::styled(
                format!("{} Publishing revocation…", app.spinner_glyph()),
                Style::default().fg(theme.warn).bg(theme.panel),
            )),
            chunks[3],
        );
    } else if let Some(ref err) = rev.error {
        f.render_widget(
            Paragraph::new(Line::styled(
                format!("✕ {err}"),
                Style::default().fg(theme.bad).bg(theme.panel),
            )),
            chunks[3],
        );
    }

    if !rev.busy {
        render_buttons(
            f,
            app,
            chunks[4],
            theme,
            &[
                ButtonSpec {
                    label: "Revoke Device  ↵",
                    kind: ButtonKind::Danger,
                    target: HitTarget::RevokeSubmit,
                },
                ButtonSpec {
                    label: "Cancel",
                    kind: ButtonKind::Secondary,
                    target: HitTarget::ModalClose,
                },
            ],
        );
    }
}

fn draw_stop_confirm(f: &mut Frame, app: &mut AppState, theme: Theme, area: Rect) {
    let popup = centered_rect(area, 58, 10);
    let inner = modal_frame(f, app, popup, "Stop Topaz Daemon", "Esc", theme.warn, theme);
    if inner.height < 4 {
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(1)])
        .split(inner);

    f.render_widget(
        Paragraph::new(vec![
            Line::styled(
                "Shut down the background `topaz run` daemon?",
                Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
            ),
            Line::from(""),
            Line::styled(
                "Active mesh sessions, TUN routing, and control.sock bridges will stop.",
                Style::default().fg(theme.dim),
            ),
        ])
        .style(Style::default().bg(theme.panel))
        .wrap(Wrap { trim: false }),
        chunks[0],
    );

    render_buttons(
        f,
        app,
        chunks[1],
        theme,
        &[
            ButtonSpec {
                label: "Stop Daemon  ↵",
                kind: ButtonKind::Danger,
                target: HitTarget::StopConfirmSubmit,
            },
            ButtonSpec {
                label: "Cancel",
                kind: ButtonKind::Secondary,
                target: HitTarget::ModalClose,
            },
        ],
    );
}

fn draw_help_modal(f: &mut Frame, app: &mut AppState, theme: Theme, area: Rect) {
    let popup = centered_rect(area, 76, 20);
    let inner = modal_frame(
        f,
        app,
        popup,
        "Keyboard & Mouse Shortcuts",
        "Esc",
        theme.accent,
        theme,
    );
    if inner.height < 8 {
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(1)])
        .split(inner);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
        .split(chunks[0]);

    let kb_rows = [
        ("↑ / ↓ / PgUp / PgDn", "Navigate devices or scroll"),
        ("Tab / Shift+Tab", "Switch pane or action button"),
        ("← / → / Enter", "Select action or confirm"),
        ("Ctrl+P", "Open Command Palette"),
        ("Ctrl+F", "Filter devices"),
        ("Ctrl+N", "Pair / Add new device"),
        ("Ctrl+R / F5", "Refresh & probe peers"),
        ("Ctrl+D", "Open Network Doctor"),
        ("Ctrl+L", "Open Daemon Logs"),
        ("Ctrl+O / F2", "Settings & Autostart"),
        ("Ctrl+B", "Toggle device sidebar"),
        ("Ctrl+T", "Cycle theme (ink/tokyo/light)"),
        ("Ctrl+Y", "Copy selected peer address"),
        ("Delete", "Revoke selected peer"),
        ("Ctrl+Q / Ctrl+C", "Quit TUI (daemon stays up)"),
    ];
    let left_lines: Vec<Line> = kb_rows
        .iter()
        .map(|(k, d)| {
            Line::from(vec![
                Span::styled(
                    format!("{k:<19} "),
                    Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
                ),
                Span::styled(*d, Style::default().fg(theme.text)),
            ])
        })
        .collect();
    f.render_widget(
        Paragraph::new(left_lines).style(Style::default().bg(theme.panel)),
        cols[0],
    );

    let mouse_rows = [
        "MOUSE GESTURES",
        "• Click any device or `This Device`",
        "• Click top bar pills (TUN, Pair, Doctor…)",
        "• Click `[Copy]` badges or action buttons",
        "• Drag `│` divider to resize sidebar",
        "• Scroll wheel inside lists & modals",
        "• Drag across text to copy to clipboard",
        "• Click outside a modal to close it",
    ];
    let right_lines: Vec<Line> = mouse_rows
        .iter()
        .enumerate()
        .map(|(i, s)| {
            if i == 0 {
                Line::styled(
                    (*s).to_string(),
                    Style::default()
                        .fg(theme.secondary)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Line::styled((*s).to_string(), Style::default().fg(theme.dim))
            }
        })
        .collect();
    f.render_widget(
        Paragraph::new(right_lines)
            .style(Style::default().bg(theme.panel))
            .wrap(Wrap { trim: false }),
        cols[1],
    );

    render_buttons(
        f,
        app,
        chunks[1],
        theme,
        &[ButtonSpec {
            label: "Close  Esc",
            kind: ButtonKind::Primary,
            target: HitTarget::ModalClose,
        }],
    );
}
