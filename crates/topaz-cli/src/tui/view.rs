//! Jade-aligned workbench renderer for `topaz tui`.
//!
//! Layout:
//! - Full-screen explicit `theme.bg` background
//! - Top bar (`theme.panel`) + 1px `─` separator
//! - Dual-pane body split by a 1px `|` divider (collapsible left peer list on
//!   `theme.panel`, right mesh/service detail + activity log on `theme.bg` / `theme.surface`)
//! - Compact filter/command input row (`theme.surface`)
//! - Bottom status bar (`theme.panel`) with badges, hints, leader bar & toast

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use super::theme::Theme;
use super::{filtered_palette, AppState, FocusPane, Modal, PairingState};

pub fn draw_ui(f: &mut Frame, app: &AppState) {
    let theme = Theme::for_kind(app.theme);
    let area = f.area();
    if area.width == 0 || area.height == 0 {
        return;
    }

    // Explicit full-screen background so transparent terminals stay clean.
    f.render_widget(Block::default().style(Style::default().bg(theme.bg)), area);

    let show_top_sep = area.height >= 16;
    let top_h = if show_top_sep { 2 } else { 1 };
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(top_h),
            Constraint::Min(8),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(area);

    draw_top_bar(f, root[0], app, theme, show_top_sep);
    draw_body(f, root[1], app, theme);
    draw_input_box(f, root[2], app, theme);
    draw_status_bar(f, root[3], app, theme);

    if let Some(modal) = &app.modal {
        draw_modal(f, area, modal, theme);
    }
}

fn draw_top_bar(f: &mut Frame, area: Rect, app: &AppState, theme: Theme, show_sep: bool) {
    let bar_area = Rect {
        x: area.x,
        y: area.y,
        width: area.width,
        height: 1,
    };
    f.render_widget(
        Block::default().style(Style::default().bg(theme.panel)),
        bar_area,
    );

    let name = if app.status.device_name.is_empty() {
        "topaz".to_string()
    } else {
        app.status.device_name.clone()
    };
    let vip = app.status.virtual_ip.as_deref().unwrap_or("-");
    let fqdn = app
        .status
        .dns_name
        .as_deref()
        .map(|d| format!("{d}.topaz"))
        .unwrap_or_else(|| "-".into());

    let left = Line::from(vec![
        Span::styled(
            " topaz ",
            Style::default()
                .fg(theme.accent)
                .bg(theme.panel)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("· ", Style::default().fg(theme.dim).bg(theme.panel)),
        Span::styled(
            name,
            Style::default()
                .fg(theme.text)
                .bg(theme.panel)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  {vip}  "),
            Style::default().fg(theme.secondary).bg(theme.panel),
        ),
        Span::styled(fqdn, Style::default().fg(theme.dim).bg(theme.panel)),
    ]);

    let (conn_label, conn_color) = if !app.ws_connected {
        ("● disconnected", theme.bad)
    } else {
        match app.status.connection.as_deref() {
            Some("direct") => ("● direct", theme.ok),
            Some("relay") => ("● relay", theme.warn),
            Some(_) => ("● connected", theme.ok),
            None => ("● standby", theme.dim),
        }
    };
    let panel_fg = if app.sidebar_visible {
        theme.accent
    } else {
        theme.dim
    };
    let right = Line::from(vec![
        Span::styled(
            conn_label,
            Style::default()
                .fg(conn_color)
                .bg(theme.panel)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  {}  ", app.theme.label()),
            Style::default().fg(theme.dim).bg(theme.panel),
        ),
        Span::styled("[panel] ", Style::default().fg(panel_fg).bg(theme.panel)),
    ]);

    let right_w = (right.width() as u16).min(bar_area.width);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(1), Constraint::Length(right_w)])
        .split(bar_area);
    f.render_widget(Paragraph::new(left), cols[0]);
    f.render_widget(Paragraph::new(right).alignment(Alignment::Right), cols[1]);

    if show_sep && area.height >= 2 {
        let sep_area = Rect {
            x: area.x,
            y: area.y + 1,
            width: area.width,
            height: 1,
        };
        let sep = "─".repeat(sep_area.width as usize);
        f.render_widget(
            Paragraph::new(Line::styled(
                sep,
                Style::default().fg(theme.border).bg(theme.bg),
            )),
            sep_area,
        );
    }
}

fn draw_body(f: &mut Frame, area: Rect, app: &AppState, theme: Theme) {
    if app.sidebar_visible && area.width >= 68 {
        let side_w = (area.width / 3).clamp(28, 38);
        let left_area = Rect {
            x: area.x,
            y: area.y,
            width: side_w,
            height: area.height,
        };
        let div_area = Rect {
            x: area.x + side_w,
            y: area.y,
            width: 1,
            height: area.height,
        };
        let main_area = Rect {
            x: area.x + side_w + 1,
            y: area.y,
            width: area.width.saturating_sub(side_w + 1),
            height: area.height,
        };

        draw_sidebar(f, left_area, app, theme);
        let div_lines: Vec<Line> = (0..div_area.height)
            .map(|_| Line::styled("│", Style::default().fg(theme.border).bg(theme.bg)))
            .collect();
        f.render_widget(Paragraph::new(div_lines), div_area);
        draw_main_pane(f, main_area, app, theme);
    } else {
        draw_main_pane(f, area, app, theme);
    }
}

fn draw_sidebar(f: &mut Frame, area: Rect, app: &AppState, theme: Theme) {
    f.render_widget(
        Block::default().style(Style::default().bg(theme.panel)),
        area,
    );

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(3)])
        .split(area);

    let peers = app.filtered_peers();
    let online_cnt = peers.iter().filter(|p| p.path.is_some()).count();
    let hdr_fg = if app.focus == FocusPane::Peers && app.modal.is_none() {
        theme.accent
    } else {
        theme.dim
    };
    let header_lines = vec![
        Line::from(vec![
            Span::styled(
                format!(" Devices ({online_cnt}/{})", peers.len()),
                Style::default()
                    .fg(hdr_fg)
                    .bg(theme.panel)
                    .add_modifier(Modifier::BOLD),
            ),
            if !app.filter_query().is_empty() {
                Span::styled(
                    format!("  /{}", app.filter_query()),
                    Style::default().fg(theme.secondary).bg(theme.panel),
                )
            } else {
                Span::raw("")
            },
        ]),
        Line::styled(
            "─".repeat(chunks[0].width as usize),
            Style::default().fg(theme.border).bg(theme.panel),
        ),
    ];
    f.render_widget(Paragraph::new(header_lines), chunks[0]);

    let items: Vec<ListItem> = if peers.is_empty() {
        vec![ListItem::new(Line::styled(
            "  (no matching peers)",
            Style::default().fg(theme.dim).bg(theme.panel),
        ))]
    } else {
        peers
            .iter()
            .map(|p| {
                let (dot, dot_color) = if p.account_status != "active" {
                    ("✕", theme.bad)
                } else {
                    match p.path.as_deref() {
                        Some("direct") => ("●", theme.ok),
                        Some(_) => ("●", theme.warn),
                        None => ("○", theme.dim),
                    }
                };
                let vip = p.virtual_ip.as_deref().unwrap_or("-");
                let rtt = p
                    .rtt_ms
                    .map(|ms| format!("{ms}ms"))
                    .unwrap_or_else(|| "-".into());
                let plugin_badges: Vec<Span> = p
                    .services
                    .iter()
                    .map(|s| {
                        Span::styled(
                            format!(" [{}]", s.name),
                            Style::default().fg(theme.accent),
                        )
                    })
                    .collect();

                let mut line1 = vec![
                    Span::styled(format!(" {dot} "), Style::default().fg(dot_color)),
                    Span::styled(
                        p.name.clone(),
                        Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
                    ),
                ];
                line1.extend(plugin_badges);

                let status_label = p.path.as_deref().unwrap_or(p.account_status.as_str());
                let line2 = vec![
                    Span::styled(format!("   {vip:<13} "), Style::default().fg(theme.dim)),
                    Span::styled(
                        format!("{status_label} {rtt}"),
                        Style::default().fg(dot_color),
                    ),
                ];
                ListItem::new(vec![Line::from(line1), Line::from(line2)])
            })
            .collect()
    };

    let mut list_state = ListState::default();
    if !peers.is_empty() {
        list_state.select(Some(app.selected_idx.min(peers.len() - 1)));
    }
    let list = List::new(items)
        .style(Style::default().bg(theme.panel))
        .highlight_style(
            Style::default()
                .bg(theme.selection)
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(list, chunks[1], &mut list_state);
}

fn draw_main_pane(f: &mut Frame, area: Rect, app: &AppState, theme: Theme) {
    let inner = Rect {
        x: area.x.saturating_add(1),
        y: area.y,
        width: area.width.saturating_sub(2),
        height: area.height,
    };
    if inner.width < 10 || inner.height < 6 {
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(10),
            Constraint::Length(1),
            Constraint::Length(7),
        ])
        .split(inner);

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
            None => theme.dim,
        };

        lines.push(Line::from(vec![
            Span::styled(
                peer.name.clone(),
                Style::default()
                    .fg(theme.text)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  [{}]", peer.account_status),
                Style::default().fg(if peer.account_status == "active" {
                    theme.ok
                } else {
                    theme.bad
                }),
            ),
            Span::styled("   (y copy address)", Style::default().fg(theme.dim)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Device ID   ", Style::default().fg(theme.dim)),
            Span::styled(peer.device_id.clone(), Style::default().fg(theme.text)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Address     ", Style::default().fg(theme.dim)),
            Span::styled(vip, Style::default().fg(theme.accent)),
            Span::styled("   DNS  ", Style::default().fg(theme.dim)),
            Span::styled(fqdn, Style::default().fg(theme.link)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Session     ", Style::default().fg(theme.dim)),
            Span::styled(path_str, Style::default().fg(path_color)),
            Span::styled("   RTT  ", Style::default().fg(theme.dim)),
            Span::styled(rtt_str, Style::default().fg(theme.text)),
        ]));
        if let Some(issuer) = peer.issuer {
            lines.push(Line::from(vec![
                Span::styled("Issued By   ", Style::default().fg(theme.dim)),
                Span::styled(issuer, Style::default().fg(theme.dim)),
            ]));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Remote Services (service 4 discovery)",
            Style::default()
                .fg(theme.secondary)
                .add_modifier(Modifier::BOLD),
        )));
        if peer.services.is_empty() {
            let message = if peer.path.is_none() {
                "  (offline — services unknown until session connects)"
            } else {
                "  (online — no services advertised)"
            };
            lines.push(Line::from(Span::styled(
                message,
                Style::default().fg(theme.dim),
            )));
        } else {
            for svc in &peer.services {
                lines.push(Line::from(vec![
                    Span::styled("  ● ", Style::default().fg(theme.ok)),
                    Span::styled(
                        format!("service {} ({})", svc.service_id, svc.name),
                        Style::default().fg(theme.text),
                    ),
                    Span::styled(
                        " — ready via control.sock",
                        Style::default().fg(theme.dim),
                    ),
                ]));
            }
        }
    } else {
        lines.push(Line::from(Span::styled(
            "No remote peers in account yet. Press `a` or `:add` to pair a device.",
            Style::default().fg(theme.dim),
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Local Node · TUN & Control Bridge",
        Style::default()
            .fg(theme.secondary)
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
        Style::default().fg(theme.text),
    )));
    if app.status.services.is_empty() {
        lines.push(Line::from(Span::styled(
            "  local services: none attached",
            Style::default().fg(theme.dim),
        )));
    } else {
        for s in &app.status.services {
            lines.push(Line::from(vec![
                Span::styled(
                    if s.online { "  ● " } else { "  ○ " },
                    Style::default().fg(if s.online { theme.ok } else { theme.dim }),
                ),
                Span::styled(
                    format!(
                        "service {} ({}) — {} idle accept listeners",
                        s.service_id, s.name, s.listeners
                    ),
                    Style::default().fg(theme.text),
                ),
            ]));
        }
    }

    f.render_widget(
        Paragraph::new(lines)
            .style(Style::default().bg(theme.bg))
            .wrap(Wrap { trim: false }),
        chunks[0],
    );

    // Subtle separator above activity panel.
    f.render_widget(
        Paragraph::new(Line::styled(
            "─".repeat(chunks[1].width as usize),
            Style::default().fg(theme.border).bg(theme.bg),
        )),
        chunks[1],
    );

    // Bottom activity feed on `theme.surface`.
    let max_lines = chunks[2].height.saturating_sub(1) as usize;
    let start = app.activity.len().saturating_sub(max_lines);
    let mut log_lines = vec![Line::styled(
        " Activity",
        Style::default()
            .fg(theme.dim)
            .bg(theme.surface)
            .add_modifier(Modifier::BOLD),
    )];
    for s in &app.activity[start..] {
        log_lines.push(Line::styled(
            format!("  {s}"),
            Style::default().fg(theme.dim).bg(theme.surface),
        ));
    }
    f.render_widget(
        Paragraph::new(log_lines).style(Style::default().bg(theme.surface)),
        chunks[2],
    );
}

fn draw_input_box(f: &mut Frame, area: Rect, app: &AppState, theme: Theme) {
    let focused = app.focus == FocusPane::Input && app.modal.is_none();
    let border_color = if focused { theme.accent } else { theme.border };
    let title = if app.input.starts_with(':') {
        " Command (:kick, :add, :revoke, :copy, :theme, :stop, :quit) "
    } else {
        " Filter / Command (`/` filter · `:` command) "
    };
    let display = if app.input.is_empty() && !focused {
        Span::styled(
            "Press `/` to filter devices or `:` to run a command…",
            Style::default().fg(theme.dim),
        )
    } else {
        Span::styled(app.input.clone(), Style::default().fg(theme.text))
    };
    let block = Block::default()
        .title(Span::styled(title, Style::default().fg(border_color)))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .style(Style::default().bg(theme.surface));
    f.render_widget(Paragraph::new(Line::from(display)).block(block), area);

    if focused {
        let text_w = Span::raw(app.input.as_str()).width() as u16;
        let cursor_x = (area.x + 1 + text_w).min(area.x + area.width.saturating_sub(2));
        f.set_cursor_position((cursor_x, area.y + 1));
    }
}

fn draw_status_bar(f: &mut Frame, area: Rect, app: &AppState, theme: Theme) {
    f.render_widget(
        Block::default().style(Style::default().bg(theme.panel)),
        area,
    );

    let (tun_badge, tun_color) = if app.status.tun.enabled {
        ("tun:on", theme.ok)
    } else {
        ("tun:off", theme.dim)
    };
    let svc_count = app.status.services.iter().filter(|s| s.online).count();
    let left = Line::from(vec![
        Span::styled(
            format!(" {tun_badge} "),
            Style::default()
                .fg(tun_color)
                .bg(theme.panel)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" svc:{svc_count} "),
            Style::default().fg(theme.secondary).bg(theme.panel),
        ),
    ]);

    let right = if let Some((ref msg, ok, _)) = app.toast {
        Line::from(Span::styled(
            format!(" {msg} "),
            Style::default()
                .fg(if ok { theme.ok } else { theme.bad })
                .bg(theme.panel)
                .add_modifier(Modifier::BOLD),
        ))
    } else if app.leader_until.is_some() {
        Line::from(Span::styled(
            " Ctrl+X …  b panel · t theme · a add · k kick · p palette · q quit ",
            Style::default()
                .fg(theme.accent)
                .bg(theme.panel)
                .add_modifier(Modifier::BOLD),
        ))
    } else {
        Line::from(Span::styled(
            " Ctrl+P commands · Ctrl+B panel · Ctrl+X leader · a add · y copy · q quit ",
            Style::default().fg(theme.dim).bg(theme.panel),
        ))
    };

    let left_w = (left.width() as u16).min(area.width);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(left_w), Constraint::Min(1)])
        .split(area);
    f.render_widget(Paragraph::new(left), cols[0]);
    f.render_widget(Paragraph::new(right).alignment(Alignment::Right), cols[1]);
}

fn draw_modal(f: &mut Frame, area: Rect, modal: &Modal, theme: Theme) {
    match modal {
        Modal::Palette { query, selected } => {
            let popup = centered_rect(66, 16, area);
            f.render_widget(Clear, popup);
            let block = Block::default()
                .title(Span::styled(
                    " Command Palette (Enter run · Esc close) ",
                    Style::default().fg(theme.accent),
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.accent))
                .style(Style::default().bg(theme.panel));
            let inner = block.inner(popup);
            f.render_widget(block, popup);

            let parts = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(2), Constraint::Min(3)])
                .split(inner);

            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled(" Search: ", Style::default().fg(theme.dim)),
                    Span::styled(query.clone(), Style::default().fg(theme.text)),
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
                            Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(*desc, Style::default().fg(theme.dim)),
                    ]))
                })
                .collect();
            let mut state = ListState::default();
            if !matches.is_empty() {
                state.select(Some((*selected).min(matches.len() - 1)));
            }
            f.render_stateful_widget(
                List::new(items)
                    .style(Style::default().bg(theme.panel))
                    .highlight_style(
                        Style::default()
                            .bg(theme.selection)
                            .add_modifier(Modifier::BOLD),
                    ),
                parts[1],
                &mut state,
            );
        }
        Modal::Pairing { code, setup, state } => {
            let popup = centered_rect(76, 15, area);
            f.render_widget(Clear, popup);
            let block = Block::default()
                .title(Span::styled(
                    " Add Device (c copy setup · Esc close) ",
                    Style::default().fg(theme.accent),
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.accent))
                .style(Style::default().bg(theme.panel));
            let inner = block.inner(popup);
            f.render_widget(block, popup);

            let mut lines = Vec::new();
            match state {
                PairingState::Starting => {
                    lines.push(Line::from(Span::styled(
                        "Requesting one-time pairing code from coord…",
                        Style::default().fg(theme.warn),
                    )));
                }
                PairingState::Waiting => {
                    if let Some(c) = code {
                        lines.push(Line::from(vec![
                            Span::styled("Code:  ", Style::default().fg(theme.dim)),
                            Span::styled(
                                c.clone(),
                                Style::default()
                                    .fg(theme.accent)
                                    .add_modifier(Modifier::BOLD),
                            ),
                        ]));
                    }
                    if let Some(s) = setup {
                        lines.push(Line::from(""));
                        lines.push(Line::from(Span::styled(
                            "Run on the new device (press `c` to copy):",
                            Style::default().fg(theme.dim),
                        )));
                        lines.push(Line::from(Span::styled(
                            format!("topaz setup '{s}' --start"),
                            Style::default().fg(theme.text),
                        )));
                    }
                    lines.push(Line::from(""));
                    lines.push(Line::from(Span::styled(
                        "Waiting up to 5 minutes for the new device to join…",
                        Style::default().fg(theme.warn),
                    )));
                }
                PairingState::Added { name, device_id } => {
                    lines.push(Line::from(Span::styled(
                        format!("✓ Added {name} ({device_id})"),
                        Style::default()
                            .fg(theme.ok)
                            .add_modifier(Modifier::BOLD),
                    )));
                    lines.push(Line::from(""));
                    lines.push(Line::from(Span::styled(
                        "Press Esc or Enter to return.",
                        Style::default().fg(theme.dim),
                    )));
                }
                PairingState::Failed(err) => {
                    lines.push(Line::from(Span::styled(
                        format!("✕ Pairing failed: {err}"),
                        Style::default()
                            .fg(theme.bad)
                            .add_modifier(Modifier::BOLD),
                    )));
                    lines.push(Line::from(""));
                    lines.push(Line::from(Span::styled(
                        "Press Esc or Enter to return.",
                        Style::default().fg(theme.dim),
                    )));
                }
            }
            f.render_widget(
                Paragraph::new(lines)
                    .style(Style::default().bg(theme.panel))
                    .wrap(Wrap { trim: false }),
                inner,
            );
        }
        Modal::RevokeConfirm { device_id, name } => {
            let popup = centered_rect(58, 9, area);
            f.render_widget(Clear, popup);
            let block = Block::default()
                .title(Span::styled(
                    " Confirm Revocation ",
                    Style::default().fg(theme.bad),
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.bad))
                .style(Style::default().bg(theme.panel));
            let inner = block.inner(popup);
            f.render_widget(block, popup);

            let lines = vec![
                Line::from(vec![
                    Span::styled("Revoke ", Style::default().fg(theme.text)),
                    Span::styled(
                        name.clone(),
                        Style::default()
                            .fg(theme.bad)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(format!(" ({device_id})?"), Style::default().fg(theme.dim)),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    "This device will be permanently removed from the account.",
                    Style::default().fg(theme.dim),
                )),
                Line::from(""),
                Line::from(vec![
                    Span::styled(
                        " [y/Enter] Revoke ",
                        Style::default()
                            .fg(theme.bad)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("   [n/Esc] Cancel ", Style::default().fg(theme.dim)),
                ]),
            ];
            f.render_widget(
                Paragraph::new(lines)
                    .style(Style::default().bg(theme.panel))
                    .wrap(Wrap { trim: false }),
                inner,
            );
        }
    }
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let w = width.min(area.width.saturating_sub(2)).max(1);
    let h = height.min(area.height.saturating_sub(2)).max(1);
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    Rect::new(x, y, w, h)
}
