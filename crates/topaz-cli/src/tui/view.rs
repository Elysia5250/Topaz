//! Jade-aligned workbench & onboarding renderer for `topaz`.
//!
//! Layout principles:
//! - Explicit `bg` / `panel` / `surface` tones across `ink`, `tokyonight`, `light`
//! - Zero permanent input box or duplicate activity log (reclaiming 11 rows)
//! - Unified sidebar (`This Device` pinned + peers) + single-focus detail card
//! - Priority-based top & bottom bars with automatic mouse `HitRegion`s

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Padding, Paragraph, Wrap};
use ratatui::Frame;

use crate::ops::coord_short_host;

use super::bar::{display_width, render_split_bar, truncate_width, BarSegment};
use super::modals::{centered_rect, draw_modal};
use super::state::{
    format_uptime, AppMode, AppState, DetailButton, FocusArea, HitRegion, HitTarget, MergedPeer,
    OnboardingChoice, SidebarEntry, NARROW_WIDTH,
};
use super::theme::Theme;

pub fn draw_ui(f: &mut Frame, app: &mut AppState) {
    let theme = Theme::for_kind(app.theme);
    let area = f.area();
    app.last_area = area;
    app.hit_regions.clear();
    app.sidebar_area = Rect::default();
    app.detail_area = Rect::default();
    app.divider.x = None;

    if area.width == 0 || area.height == 0 {
        return;
    }

    // Explicit full-screen canvas background.
    f.render_widget(Block::default().style(Style::default().bg(theme.bg)), area);

    if app.mode() == AppMode::Onboarding {
        draw_onboarding_screen(f, app, theme, area);
    } else {
        draw_workbench(f, app, theme, area);
    }

    // Capture screen text for Jade-style drag-to-copy selection when no modal is open.
    if app.modal.is_none() {
        capture_screen_lines(f, app);
        apply_drag_selection_highlight(f, app, theme);
    } else {
        app.screen_lines.clear();
        draw_modal(f, app, theme, area);
    }
}

fn draw_onboarding_screen(f: &mut Frame, app: &mut AppState, theme: Theme, area: Rect) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(1)])
        .split(area);

    let main_area = root[0];
    let max_w = 84u16.min(main_area.width.saturating_sub(2).max(1));
    let max_h = 24u16.min(main_area.height.saturating_sub(2).max(1));
    let container = centered_rect(main_area, max_w, max_h);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header card
            Constraint::Length(1), // gap
            Constraint::Min(12),   // 4 choices
            Constraint::Length(1), // quick links
        ])
        .split(container);

    // Header card (Jade Hub style)
    let version = env!("CARGO_PKG_VERSION");
    let dev_short = truncate_width(&app.local.device_id, 12);
    let hdr_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme.border))
        .title(Line::from(vec![
            Span::styled(
                " ◆ topaz ",
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("v{version} "), Style::default().fg(theme.dim)),
        ]))
        .title_top(
            Line::from(Span::styled(
                format!(" device {dev_short} "),
                Style::default().fg(theme.dim),
            ))
            .right_aligned(),
        )
        .style(Style::default().bg(theme.panel));
    let hdr_inner = hdr_block.inner(chunks[0]);
    f.render_widget(hdr_block, chunks[0]);
    if hdr_inner.width > 0 && hdr_inner.height > 0 {
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    " Welcome · ",
                    Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "Choose how to connect this device to a Topaz mesh",
                    Style::default().fg(theme.dim),
                ),
            ]))
            .style(Style::default().bg(theme.panel)),
            hdr_inner,
        );
    }

    // Choice cards
    let card_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme.border))
        .padding(Padding::new(1, 1, 1, 0))
        .title(Span::styled(
            " Get Started ",
            Style::default()
                .fg(theme.secondary)
                .add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(theme.panel));
    let card_inner = card_block.inner(chunks[2]);
    f.render_widget(card_block, chunks[2]);

    let mut y = card_inner.y;
    let max_y = card_inner.y + card_inner.height;
    let step = if card_inner.height >= 11 { 3 } else { 2 };
    for (idx, choice) in OnboardingChoice::ALL.iter().copied().enumerate() {
        if y + 1 >= max_y {
            break;
        }
        let selected = app.onboarding_idx == idx;
        let bg = if selected {
            theme.selection
        } else {
            theme.panel
        };
        let row_rect = Rect::new(card_inner.x, y, card_inner.width, 2);
        app.hit_regions.push(HitRegion {
            rect: row_rect,
            target: HitTarget::OnboardingPick(choice),
        });

        let marker = if selected { "▸" } else { " " };
        let mut line1 = vec![
            Span::styled(
                format!(" {marker} {} ", choice.title()),
                Style::default()
                    .fg(if selected { theme.accent } else { theme.text })
                    .bg(bg)
                    .add_modifier(Modifier::BOLD),
            ),
        ];
        if let Some(badge) = choice.badge() {
            line1.push(Span::styled(
                format!(" {badge} "),
                Style::default()
                    .fg(theme.accent)
                    .bg(theme.accent_bg)
                    .add_modifier(Modifier::BOLD),
            ));
        }
        let desc = truncate_width(
            choice.description(),
            card_inner.width.saturating_sub(4) as usize,
        );
        let line2 = vec![Span::styled(
            format!("   {desc}"),
            Style::default().fg(theme.dim).bg(bg),
        )];
        f.render_widget(
            Paragraph::new(vec![Line::from(line1), Line::from(line2)])
                .style(Style::default().bg(bg)),
            row_rect,
        );
        y += step;
    }

    // Bottom quick actions inside onboarding container
    let left_quick = vec![
        BarSegment::clickable(
            vec![Span::styled(
                " Doctor ",
                Style::default().fg(theme.text).bg(theme.surface),
            )],
            HitTarget::OpenDoctor,
            1,
        ),
        BarSegment::clickable(
            vec![Span::styled(
                " Settings ",
                Style::default().fg(theme.text).bg(theme.surface),
            )],
            HitTarget::OpenSettings,
            1,
        ),
        BarSegment::clickable(
            vec![Span::styled(
                format!(" Theme: {} ", app.theme.label()),
                Style::default().fg(theme.dim).bg(theme.surface),
            )],
            HitTarget::CycleTheme,
            2,
        ),
    ];
    let right_quick = vec![BarSegment::plain(
        vec![Span::styled(
            "↑↓ select · Enter open · Click any option",
            Style::default().fg(theme.dim),
        )],
        1,
    )];
    render_split_bar(f, app, chunks[3], Some(theme.bg), 0, "  ", left_quick, right_quick);

    draw_bottom_bar(f, app, theme, root[1]);
}

fn draw_workbench(f: &mut Frame, app: &mut AppState, theme: Theme, area: Rect) {
    let show_top_sep = area.height >= 14;
    let top_h = if show_top_sep { 2 } else { 1 };
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(top_h),
            Constraint::Min(8),
            Constraint::Length(1),
        ])
        .split(area);

    draw_top_bar(f, app, theme, root[0], show_top_sep);
    draw_body(f, app, theme, root[1]);
    draw_bottom_bar(f, app, theme, root[2]);
}

fn draw_top_bar(f: &mut Frame, app: &mut AppState, theme: Theme, area: Rect, show_sep: bool) {
    let name = app.effective_device_name().to_string();
    let vip = app.status.virtual_ip.as_deref().unwrap_or("");

    let mut left = Vec::new();
    if area.width >= NARROW_WIDTH && !app.sidebar_visible {
        left.push(BarSegment::clickable(
            vec![Span::styled(
                " ☰ Devices ",
                Style::default().fg(theme.accent).bg(theme.surface),
            )],
            HitTarget::ToggleSidebar,
            0,
        ));
    }
    left.push(BarSegment::clickable(
        vec![
            Span::styled(
                "◆ topaz",
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" · ", Style::default().fg(theme.dim)),
            Span::styled(
                name,
                Style::default()
                    .fg(theme.text)
                    .add_modifier(Modifier::BOLD),
            ),
        ],
        HitTarget::SelectSelf,
        0,
    ));
    if !vip.is_empty() {
        left.push(BarSegment::clickable(
            vec![Span::styled(vip.to_string(), Style::default().fg(theme.secondary))],
            HitTarget::CopyText {
                label: "local IP".into(),
                text: vip.to_string(),
            },
            1,
        ));
    }

    let mut right = Vec::new();
    let peers = app.all_peers();
    let online_cnt = peers.iter().filter(|p| p.path.is_some()).count();

    if app.ws_connected {
        let (dot_color, label) = if online_cnt > 0 {
            (theme.ok, format!("● {online_cnt}/{} online", peers.len()))
        } else {
            (theme.dim, format!("● 0/{} online", peers.len()))
        };
        right.push(BarSegment::plain(
            vec![Span::styled(
                label,
                Style::default().fg(dot_color).add_modifier(Modifier::BOLD),
            )],
            0,
        ));

        // Clickable TUN status pill
        let (tun_text, tun_fg, tun_bg) = if app.status.tun.enabled {
            let iface = app.status.tun.interface.as_deref().unwrap_or("tun");
            (format!(" TUN {iface} "), theme.ok, theme.ok_bg)
        } else if app.status.tun.error.is_some() {
            (" TUN err ".to_string(), theme.bad, theme.bad_bg)
        } else {
            (" no-tun ".to_string(), theme.dim, theme.surface)
        };
        right.push(BarSegment::clickable(
            vec![Span::styled(
                tun_text,
                Style::default()
                    .fg(tun_fg)
                    .bg(tun_bg)
                    .add_modifier(Modifier::BOLD),
            )],
            HitTarget::TopTunPill,
            0,
        ));
    } else {
        right.push(BarSegment::plain(
            vec![Span::styled(
                "○ standby",
                Style::default().fg(theme.warn).add_modifier(Modifier::BOLD),
            )],
            0,
        ));
        right.push(BarSegment::clickable(
            vec![Span::styled(
                " ▶ Start TUN ",
                Style::default()
                    .fg(theme.accent_fg)
                    .bg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            )],
            HitTarget::TopTunPill,
            0,
        ));
    }

    right.push(BarSegment::clickable(
        vec![Span::styled(
            " + Pair ",
            Style::default().fg(theme.accent).bg(theme.accent_bg),
        )],
        HitTarget::OpenPair,
        1,
    ));
    right.push(BarSegment::clickable(
        vec![Span::styled(
            " Doctor ",
            Style::default().fg(theme.text).bg(theme.surface),
        )],
        HitTarget::OpenDoctor,
        2,
    ));
    right.push(BarSegment::clickable(
        vec![Span::styled(
            " Logs ",
            Style::default().fg(theme.text).bg(theme.surface),
        )],
        HitTarget::OpenLogs,
        3,
    ));
    right.push(BarSegment::clickable(
        vec![Span::styled(
            " Settings ",
            Style::default().fg(theme.text).bg(theme.surface),
        )],
        HitTarget::OpenSettings,
        2,
    ));

    render_split_bar(f, app, area, Some(theme.panel), 1, " ", left, right);

    if show_sep && area.height >= 2 {
        let sep_area = Rect::new(area.x, area.y + 1, area.width, 1);
        f.render_widget(
            Paragraph::new(Line::styled(
                "─".repeat(sep_area.width as usize),
                Style::default().fg(theme.border).bg(theme.bg),
            )),
            sep_area,
        );
    }
}

fn draw_body(f: &mut Frame, app: &mut AppState, theme: Theme, area: Rect) {
    let narrow = area.width < NARROW_WIDTH;
    if narrow {
        if app.narrow_showing_detail {
            app.detail_area = area;
            draw_detail_pane(f, app, theme, area, true);
        } else {
            app.sidebar_area = area;
            draw_sidebar(f, app, theme, area);
        }
        return;
    }

    if app.sidebar_visible {
        let default_w = (area.width / 3).clamp(28, 38);
        let max_w = area.width.saturating_sub(36).max(24);
        let side_w = app
            .divider
            .width_override
            .unwrap_or(default_w)
            .clamp(24, max_w);
        let left_area = Rect::new(area.x, area.y, side_w, area.height);
        let div_area = Rect::new(area.x + side_w, area.y, 1, area.height);
        let right_area = Rect::new(
            area.x + side_w + 1,
            area.y,
            area.width.saturating_sub(side_w + 1),
            area.height,
        );

        app.sidebar_area = left_area;
        app.detail_area = right_area;
        app.divider.x = Some(div_area.x);

        draw_sidebar(f, app, theme, left_area);
        let div_fg = if app.divider.dragging || app.divider.hover {
            theme.accent
        } else {
            theme.border
        };
        let div_lines: Vec<Line> = (0..div_area.height)
            .map(|_| Line::styled("│", Style::default().fg(div_fg).bg(theme.bg)))
            .collect();
        f.render_widget(Paragraph::new(div_lines), div_area);
        draw_detail_pane(f, app, theme, right_area, false);
    } else {
        app.detail_area = area;
        draw_detail_pane(f, app, theme, area, false);
    }
}

fn draw_sidebar(f: &mut Frame, app: &mut AppState, theme: Theme, area: Rect) {
    f.render_widget(
        Block::default().style(Style::default().bg(theme.panel)),
        area,
    );
    if area.width < 12 || area.height < 4 {
        return;
    }

    let filter_row_h = if app.filter_open || !app.filter.value.is_empty() {
        1
    } else {
        0
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),            // header
            Constraint::Length(filter_row_h), // optional inline filter
            Constraint::Length(1),            // hairline
            Constraint::Min(2),               // unified list
        ])
        .split(area);

    let peers = app.filtered_peers();
    let all_peers = app.all_peers();
    let online_cnt = all_peers.iter().filter(|p| p.path.is_some()).count();
    let hdr_fg = if app.focus == FocusArea::Sidebar && app.modal.is_none() {
        theme.accent
    } else {
        theme.text
    };

    let left_hdr = vec![BarSegment::plain(
        vec![
            Span::styled(
                "Devices",
                Style::default().fg(hdr_fg).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  {online_cnt}/{}", all_peers.len()),
                Style::default().fg(theme.dim),
            ),
        ],
        0,
    )];
    let right_hdr = vec![BarSegment::clickable(
        vec![Span::styled(
            if app.filter_open { " ✕ " } else { " Filter " },
            Style::default()
                .fg(if app.filter_open || !app.filter.value.is_empty() {
                    theme.accent
                } else {
                    theme.dim
                })
                .bg(theme.surface),
        )],
        if app.filter_open {
            HitTarget::ClearFilter
        } else {
            HitTarget::FocusFilter
        },
        0,
    )];
    render_split_bar(f, app, chunks[0], Some(theme.panel), 1, " ", left_hdr, right_hdr);

    // Inline filter bar (only shown when filtering or filter has text)
    if filter_row_h > 0 {
        let f_area = chunks[1];
        let focused = app.focus == FocusArea::Filter && app.modal.is_none();
        let bg = if focused {
            theme.selection
        } else {
            theme.surface
        };
        app.hit_regions.push(HitRegion {
            rect: f_area,
            target: HitTarget::FocusFilter,
        });
        let clear_w = 3u16;
        let text_budget = f_area.width.saturating_sub(5 + clear_w) as usize;
        let shown = if app.filter.value.is_empty() {
            Span::styled(
                truncate_width(&app.filter.placeholder, text_budget),
                Style::default().fg(theme.dim).bg(bg),
            )
        } else {
            Span::styled(
                truncate_width(&app.filter.value, text_budget),
                Style::default().fg(theme.text).bg(bg),
            )
        };
        let used = 3 + display_width(&shown.content);
        let pad = (f_area.width as usize).saturating_sub(used + clear_w as usize);
        let line = Line::from(vec![
            Span::styled(" / ", Style::default().fg(theme.accent).bg(bg)),
            shown,
            Span::styled(" ".repeat(pad), Style::default().bg(bg)),
            Span::styled(" × ", Style::default().fg(theme.dim).bg(bg)),
        ]);
        f.render_widget(Paragraph::new(line).style(Style::default().bg(bg)), f_area);
        if f_area.width >= clear_w {
            app.hit_regions.push(HitRegion {
                rect: Rect::new(f_area.x + f_area.width - clear_w, f_area.y, clear_w, 1),
                target: HitTarget::ClearFilter,
            });
        }
        if focused {
            let cw = app.filter.cursor_display_width() as u16;
            let cx = (f_area.x + 3 + cw).min(f_area.x + f_area.width.saturating_sub(clear_w + 1));
            f.set_cursor_position((cx, f_area.y));
        }
    }

    f.render_widget(
        Paragraph::new(Line::styled(
            "─".repeat(chunks[2].width as usize),
            Style::default().fg(theme.border).bg(theme.panel),
        )),
        chunks[2],
    );

    // Unified list: row 0 = This Device (height 2 + 1 separator), then peers (height 2 each)
    let list_area = chunks[3];
    let entries = app.sidebar_entries();
    let mut y = list_area.y;
    let max_y = list_area.y + list_area.height;

    // Pinned SelfDevice entry (always visible at top of sidebar)
    if y + 1 < max_y {
        let is_sel = app.selected_idx == 0;
        let bg = if is_sel { theme.selection } else { theme.panel };
        let row_rect = Rect::new(list_area.x, y, list_area.width, 2);
        app.hit_regions.push(HitRegion {
            rect: row_rect,
            target: HitTarget::SelectSidebarRow(0),
        });

        let state_badge = if app.ws_connected {
            if app.status.tun.enabled {
                ("live · tun", theme.ok)
            } else if app.status.tun.error.is_some() {
                ("tun err", theme.bad)
            } else {
                ("live", theme.accent)
            }
        } else {
            ("standby", theme.warn)
        };
        let self_name = app.effective_device_name();
        let name_budget = (list_area.width as usize).saturating_sub(display_width(state_badge.0) + 6);
        let name_shown = truncate_width(self_name, name_budget);
        let pad1 = (list_area.width as usize)
            .saturating_sub(4 + display_width(&name_shown) + display_width(state_badge.0) + 1);
        let line1 = Line::from(vec![
            Span::styled(" ★ ", Style::default().fg(theme.accent).bg(bg)),
            Span::styled(
                name_shown,
                Style::default()
                    .fg(theme.text)
                    .bg(bg)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" ".repeat(pad1), Style::default().bg(bg)),
            Span::styled(format!("{} ", state_badge.0), Style::default().fg(state_badge.1).bg(bg)),
        ]);

        let vip = app
            .status
            .virtual_ip
            .as_deref()
            .unwrap_or("this device");
        let line2 = Line::from(vec![
            Span::styled("   ", Style::default().bg(bg)),
            Span::styled(vip.to_string(), Style::default().fg(theme.dim).bg(bg)),
        ]);
        f.render_widget(
            Paragraph::new(vec![line1, line2]).style(Style::default().bg(bg)),
            row_rect,
        );
        y += 2;
    }

    if y < max_y {
        let sep_rect = Rect::new(list_area.x, y, list_area.width, 1);
        f.render_widget(
            Paragraph::new(Line::styled(
                "─".repeat(sep_rect.width as usize),
                Style::default().fg(theme.border).bg(theme.panel),
            )),
            sep_rect,
        );
        y += 1;
    }

    if peers.is_empty() {
        if y < max_y {
            let msg = if !app.filter.value.is_empty() {
                "  No matching devices"
            } else {
                "  No peers yet — click + Pair"
            };
            f.render_widget(
                Paragraph::new(Line::styled(
                    msg,
                    Style::default().fg(theme.dim).bg(theme.panel),
                )),
                Rect::new(list_area.x, y, list_area.width, 1),
            );
        }
        return;
    }

    // Scroll calculation for peer rows (each peer occupies 2 rows)
    let peer_rows_avail = (max_y.saturating_sub(y) / 2) as usize;
    let selected_peer_pos = app.selected_idx.saturating_sub(1);
    if app.selected_idx > 0 && peer_rows_avail > 0 {
        if selected_peer_pos < app.sidebar_scroll {
            app.sidebar_scroll = selected_peer_pos;
        } else if selected_peer_pos >= app.sidebar_scroll + peer_rows_avail {
            app.sidebar_scroll = selected_peer_pos + 1 - peer_rows_avail;
        }
    }
    let max_scroll = peers.len().saturating_sub(peer_rows_avail);
    app.sidebar_scroll = app.sidebar_scroll.min(max_scroll);

    for (peer_idx, entry) in entries
        .iter()
        .enumerate()
        .skip(1 + app.sidebar_scroll)
    {
        if y + 1 >= max_y {
            break;
        }
        let SidebarEntry::Peer(p) = entry else {
            continue;
        };
        let is_sel = app.selected_idx == peer_idx;
        let bg = if is_sel { theme.selection } else { theme.panel };
        let row_rect = Rect::new(list_area.x, y, list_area.width, 2);
        app.hit_regions.push(HitRegion {
            rect: row_rect,
            target: HitTarget::SelectSidebarRow(peer_idx),
        });

        let (dot, dot_color, status_text) = peer_badge(p, theme);
        let status_w = display_width(&status_text);
        let name_budget = (list_area.width as usize).saturating_sub(status_w + 5);
        let name_shown = truncate_width(&p.name, name_budget);
        let pad1 = (list_area.width as usize)
            .saturating_sub(3 + display_width(&name_shown) + status_w + 1);

        let line1 = Line::from(vec![
            Span::styled(format!(" {dot} "), Style::default().fg(dot_color).bg(bg)),
            Span::styled(
                name_shown,
                Style::default()
                    .fg(if p.account_status == "active" {
                        theme.text
                    } else {
                        theme.dim
                    })
                    .bg(bg)
                    .add_modifier(if is_sel || p.path.is_some() {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    }),
            ),
            Span::styled(" ".repeat(pad1), Style::default().bg(bg)),
            Span::styled(
                format!("{status_text} "),
                Style::default().fg(dot_color).bg(bg),
            ),
        ]);

        let vip = p.virtual_ip.as_deref().unwrap_or("—");
        let mut line2 = vec![
            Span::styled(format!("   {vip}"), Style::default().fg(theme.dim).bg(bg)),
        ];
        for svc in p.services.iter().take(3) {
            line2.push(Span::styled(" ", Style::default().bg(bg)));
            line2.push(Span::styled(
                format!(" {} ", svc.name),
                Style::default().fg(theme.accent).bg(theme.accent_bg),
            ));
        }

        f.render_widget(
            Paragraph::new(vec![line1, Line::from(line2)]).style(Style::default().bg(bg)),
            row_rect,
        );
        y += 2;
    }
}

fn peer_badge(p: &MergedPeer, theme: Theme) -> (&'static str, Color, String) {
    if p.account_status != "active" {
        return ("✕", theme.bad, p.account_status.clone());
    }
    match p.path.as_deref() {
        Some("direct") => {
            let txt = match p.rtt_ms {
                Some(ms) => format!("direct {ms}ms"),
                None => "direct".into(),
            };
            ("●", theme.ok, txt)
        }
        Some(other) => {
            let txt = match p.rtt_ms {
                Some(ms) => format!("{other} {ms}ms"),
                None => other.into(),
            };
            ("●", theme.warn, txt)
        }
        None => ("○", theme.dim, "offline".into()),
    }
}

fn rtt_color(ms: u64, theme: Theme) -> Color {
    if ms < 35 {
        theme.ok
    } else if ms < 120 {
        theme.warn
    } else {
        theme.bad
    }
}

fn draw_detail_pane(
    f: &mut Frame,
    app: &mut AppState,
    theme: Theme,
    area: Rect,
    narrow: bool,
) {
    let inner = Rect::new(
        area.x.saturating_add(2),
        area.y.saturating_add(1),
        area.width.saturating_sub(4),
        area.height.saturating_sub(1),
    );
    if inner.width < 16 || inner.height < 6 {
        return;
    }

    let mut top_y = inner.y;
    if narrow {
        let back_rect = Rect::new(inner.x, top_y, 12.min(inner.width), 1);
        app.hit_regions.push(HitRegion {
            rect: back_rect,
            target: HitTarget::NarrowBackToList,
        });
        f.render_widget(
            Paragraph::new(Line::styled(
                " ← Devices ",
                Style::default().fg(theme.accent).bg(theme.surface),
            )),
            back_rect,
        );
        top_y += 2;
    }

    let work = Rect::new(
        inner.x,
        top_y,
        inner.width,
        inner.y.saturating_add(inner.height).saturating_sub(top_y),
    );
    if work.height < 4 {
        return;
    }

    match app.selected_entry() {
        SidebarEntry::SelfDevice => draw_self_detail(f, app, theme, work),
        SidebarEntry::Peer(peer) => draw_peer_detail(f, app, theme, work, &peer),
    }
}

fn draw_self_detail(f: &mut Frame, app: &mut AppState, theme: Theme, area: Rect) {
    if !app.ws_connected {
        draw_standby_detail(f, app, theme, area);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // title header
            Constraint::Length(6), // network card
            Constraint::Length(1), // gap
            Constraint::Min(3),    // local services
            Constraint::Length(2), // action buttons
            Constraint::Length(1), // muted metadata line
        ])
        .split(area);

    // 1. Header
    let uptime = app
        .local
        .uptime_s
        .map(|s| format!(" · up {}", format_uptime(s)))
        .unwrap_or_default();
    let header_line = Line::from(vec![
        Span::styled("★ ", Style::default().fg(theme.accent)),
        Span::styled(
            app.effective_device_name().to_string(),
            Style::default()
                .fg(theme.text)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("  ", Style::default()),
        Span::styled(
            format!(" ● live{uptime} "),
            Style::default()
                .fg(theme.ok)
                .bg(theme.ok_bg)
                .add_modifier(Modifier::BOLD),
        ),
    ]);
    f.render_widget(
        Paragraph::new(header_line).style(Style::default().bg(theme.bg)),
        chunks[0],
    );

    // 2. Network & TUN rounded card
    let card = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(if app.status.tun.error.is_some() {
            theme.bad
        } else {
            theme.border
        }))
        .padding(Padding::new(2, 2, 0, 0))
        .title(Span::styled(
            " Local Network ",
            Style::default().fg(theme.secondary),
        ))
        .style(Style::default().bg(theme.surface));
    let card_in = card.inner(chunks[1]);
    f.render_widget(card, chunks[1]);

    if card_in.height >= 3 {
        let vip_opt = app.status.virtual_ip.clone();
        let dns_opt = app.status.dns_name.clone();
        let vip = vip_opt.as_deref().unwrap_or("pending…");
        let fqdn = dns_opt
            .as_deref()
            .map(|d| format!("{d}.topaz"))
            .unwrap_or_else(|| "—".into());

        draw_kv_copy_row(
            f,
            app,
            Rect::new(card_in.x, card_in.y, card_in.width, 1),
            "Virtual IP",
            vip,
            theme.accent,
            vip_opt.as_deref(),
            theme,
        );
        draw_kv_copy_row(
            f,
            app,
            Rect::new(card_in.x, card_in.y + 1, card_in.width, 1),
            "Domain",
            &fqdn,
            theme.link,
            dns_opt.as_deref().map(|_| fqdn.as_str()),
            theme,
        );

        let tun_row = Rect::new(card_in.x, card_in.y + 2, card_in.width, 1);
        let tun_line = if app.status.tun.enabled {
            let iface = app.status.tun.interface.as_deref().unwrap_or("tun");
            let dns = app.status.tun.dns_listen.as_deref().unwrap_or("—");
            Line::from(vec![
                Span::styled(format!("{:<12}", "TUN"), Style::default().fg(theme.dim)),
                Span::styled(
                    format!("● {iface}  "),
                    Style::default().fg(theme.ok).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("MTU {} · DNS {dns}", app.status.tun.mtu),
                    Style::default().fg(theme.dim),
                ),
            ])
        } else if let Some(ref err) = app.status.tun.error {
            let budget = card_in.width.saturating_sub(14) as usize;
            Line::from(vec![
                Span::styled(format!("{:<12}", "TUN"), Style::default().fg(theme.dim)),
                Span::styled(
                    format!("✕ {}", truncate_width(err, budget)),
                    Style::default().fg(theme.bad).add_modifier(Modifier::BOLD),
                ),
            ])
        } else {
            Line::from(vec![
                Span::styled(format!("{:<12}", "TUN"), Style::default().fg(theme.dim)),
                Span::styled("○ disabled (--no-tun)", Style::default().fg(theme.dim)),
            ])
        };
        f.render_widget(
            Paragraph::new(tun_line).style(Style::default().bg(theme.surface)),
            tun_row,
        );
    }

    // 3. Local Services
    let mut svc_lines = vec![Line::styled(
        "LOCAL SERVICES",
        Style::default().fg(theme.dim).add_modifier(Modifier::BOLD),
    )];
    if app.status.services.is_empty() {
        svc_lines.push(Line::styled(
            "  No local services attached over control.sock",
            Style::default().fg(theme.dim),
        ));
    } else {
        for s in &app.status.services {
            svc_lines.push(Line::from(vec![
                Span::styled(
                    if s.online { "  ● " } else { "  ○ " },
                    Style::default().fg(if s.online { theme.ok } else { theme.dim }),
                ),
                Span::styled(
                    s.name.clone(),
                    Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("  #{}  ·  {} idle", s.service_id, s.listeners),
                    Style::default().fg(theme.dim),
                ),
            ]));
        }
    }
    f.render_widget(
        Paragraph::new(svc_lines).style(Style::default().bg(theme.bg)),
        chunks[3],
    );

    // 4. Contextual action buttons
    draw_detail_action_bar(f, app, theme, chunks[4]);

    // 5. Muted metadata footer
    let coord_short = coord_short_host(&app.local.coord_url);
    let meta = format!(
        "id {} · coord {} · {}",
        app.effective_device_id(),
        if coord_short.is_empty() { "—" } else { &coord_short },
        app.local.service_status
    );
    f.render_widget(
        Paragraph::new(Line::styled(
            truncate_width(&meta, chunks[5].width as usize),
            Style::default().fg(theme.dim).bg(theme.bg),
        )),
        chunks[5],
    );
}

fn draw_standby_detail(f: &mut Frame, app: &mut AppState, theme: Theme, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // title
            Constraint::Length(7), // standby banner card
            Constraint::Length(1), // gap
            Constraint::Min(4),    // summary
            Constraint::Length(1), // metadata
        ])
        .split(area);

    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("★ ", Style::default().fg(theme.accent)),
            Span::styled(
                app.effective_device_name().to_string(),
                Style::default()
                    .fg(theme.text)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("  ", Style::default()),
            Span::styled(
                " ○ standby ",
                Style::default()
                    .fg(theme.warn)
                    .bg(theme.warn_bg)
                    .add_modifier(Modifier::BOLD),
            ),
        ]))
        .style(Style::default().bg(theme.bg)),
        chunks[0],
    );

    let card = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme.border))
        .padding(Padding::new(2, 2, 1, 1))
        .title(Span::styled(
            " Daemon Not Running ",
            Style::default()
                .fg(theme.warn)
                .add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(theme.panel));
    let card_in = card.inner(chunks[1]);
    f.render_widget(card, chunks[1]);

    if card_in.height >= 3 {
        let inner_parts = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(2), Constraint::Min(1)])
            .split(card_in);
        f.render_widget(
            Paragraph::new(Line::styled(
                "Start the background node to join the mesh, or run diagnostics / pair devices offline.",
                Style::default().fg(theme.dim).bg(theme.panel),
            ))
            .wrap(Wrap { trim: false }),
            inner_parts[0],
        );
        draw_detail_action_bar(f, app, theme, inner_parts[1]);
    }

    let coord_short = coord_short_host(&app.local.coord_url);
    let acct = app.effective_account().unwrap_or("—");
    let relay_str = if app.local.force_relay { "forced" } else { "auto (direct + fallback)" };
    let info_lines = vec![
        Line::styled(
            "NODE CONFIGURATION",
            Style::default().fg(theme.dim).add_modifier(Modifier::BOLD),
        ),
        Line::from(vec![
            Span::styled("  Coord       ", Style::default().fg(theme.dim)),
            Span::styled(
                if coord_short.is_empty() { "—" } else { &coord_short },
                Style::default().fg(theme.text),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Account     ", Style::default().fg(theme.dim)),
            Span::styled(acct.to_string(), Style::default().fg(theme.secondary)),
        ]),
        Line::from(vec![
            Span::styled("  Relay       ", Style::default().fg(theme.dim)),
            Span::styled(relay_str, Style::default().fg(theme.text)),
        ]),
        Line::from(vec![
            Span::styled("  Autostart   ", Style::default().fg(theme.dim)),
            Span::styled(app.local.service_status.clone(), Style::default().fg(theme.dim)),
        ]),
    ];
    f.render_widget(
        Paragraph::new(info_lines).style(Style::default().bg(theme.bg)),
        chunks[3],
    );

    let meta = format!(
        "id {} · data {}",
        app.effective_device_id(),
        app.local.data_dir.display()
    );
    f.render_widget(
        Paragraph::new(Line::styled(
            truncate_width(&meta, chunks[4].width as usize),
            Style::default().fg(theme.dim).bg(theme.bg),
        )),
        chunks[4],
    );
}

fn draw_peer_detail(
    f: &mut Frame,
    app: &mut AppState,
    theme: Theme,
    area: Rect,
    peer: &MergedPeer,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // title + path pill
            Constraint::Length(6), // address & link card
            Constraint::Length(1), // gap
            Constraint::Min(3),    // remote services
            Constraint::Length(2), // action buttons
            Constraint::Length(1), // muted metadata line
        ])
        .split(area);

    // 1. Peer header
    let (pill_text, pill_fg, pill_bg) = if peer.account_status != "active" {
        (format!(" {} ", peer.account_status), theme.bad, theme.bad_bg)
    } else {
        match peer.path.as_deref() {
            Some("direct") => {
                let rtt = peer
                    .rtt_ms
                    .map(|m| format!(" · {m}ms"))
                    .unwrap_or_default();
                (format!(" ● DIRECT{rtt} "), theme.ok, theme.ok_bg)
            }
            Some(other) => {
                let rtt = peer
                    .rtt_ms
                    .map(|m| format!(" · {m}ms"))
                    .unwrap_or_default();
                (
                    format!(" ● {}{rtt} ", other.to_ascii_uppercase()),
                    theme.warn,
                    theme.warn_bg,
                )
            }
            None => (" ○ OFFLINE ".into(), theme.dim, theme.surface),
        }
    };

    let mut hdr_spans = vec![
        Span::styled(
            peer.name.clone(),
            Style::default()
                .fg(theme.text)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            pill_text,
            Style::default()
                .fg(pill_fg)
                .bg(pill_bg)
                .add_modifier(Modifier::BOLD),
        ),
    ];
    if peer.account_status != "active" {
        hdr_spans.push(Span::raw(" "));
    }
    f.render_widget(
        Paragraph::new(Line::from(hdr_spans)).style(Style::default().bg(theme.bg)),
        chunks[0],
    );

    // 2. Address & Link card
    let card = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme.border))
        .padding(Padding::new(2, 2, 0, 0))
        .title(Span::styled(
            " Address & Link ",
            Style::default().fg(theme.secondary),
        ))
        .style(Style::default().bg(theme.surface));
    let card_in = card.inner(chunks[1]);
    f.render_widget(card, chunks[1]);

    if card_in.height >= 3 {
        let vip = peer.virtual_ip.as_deref().unwrap_or("—");
        let fqdn = peer
            .dns_name
            .as_deref()
            .map(|d| format!("{d}.topaz"))
            .unwrap_or_else(|| "—".into());

        draw_kv_copy_row(
            f,
            app,
            Rect::new(card_in.x, card_in.y, card_in.width, 1),
            "Virtual IP",
            vip,
            theme.accent,
            peer.virtual_ip.as_deref(),
            theme,
        );
        draw_kv_copy_row(
            f,
            app,
            Rect::new(card_in.x, card_in.y + 1, card_in.width, 1),
            "Domain",
            &fqdn,
            theme.link,
            peer.dns_name.as_deref().map(|_| fqdn.as_str()),
            theme,
        );

        let link_row = Rect::new(card_in.x, card_in.y + 2, card_in.width, 1);
        let link_line = match peer.path.as_deref() {
            Some(path) => {
                let mut spans = vec![
                    Span::styled(format!("{:<12}", "Link"), Style::default().fg(theme.dim)),
                    Span::styled(
                        if path == "direct" {
                            "Direct QUIC"
                        } else {
                            "Relayed"
                        },
                        Style::default().fg(if path == "direct" { theme.ok } else { theme.warn }),
                    ),
                ];
                if let Some(ms) = peer.rtt_ms {
                    spans.push(Span::styled("  ·  ", Style::default().fg(theme.dim)));
                    spans.push(Span::styled(
                        format!("{ms} ms"),
                        Style::default()
                            .fg(rtt_color(ms, theme))
                            .add_modifier(Modifier::BOLD),
                    ));
                }
                Line::from(spans)
            }
            None => Line::from(vec![
                Span::styled(format!("{:<12}", "Link"), Style::default().fg(theme.dim)),
                Span::styled("Offline", Style::default().fg(theme.dim)),
            ]),
        };
        f.render_widget(
            Paragraph::new(link_line).style(Style::default().bg(theme.surface)),
            link_row,
        );
    }

    // 3. Remote Services (clean, zero protocol boilerplate)
    let mut svc_lines = vec![Line::styled(
        "SERVICES",
        Style::default().fg(theme.dim).add_modifier(Modifier::BOLD),
    )];
    if peer.services.is_empty() {
        let msg = if peer.path.is_none() {
            "  Offline"
        } else {
            "  No services advertised"
        };
        svc_lines.push(Line::styled(msg, Style::default().fg(theme.dim)));
    } else {
        for svc in &peer.services {
            svc_lines.push(Line::from(vec![
                Span::styled("  ● ", Style::default().fg(theme.ok)),
                Span::styled(
                    svc.name.clone(),
                    Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("  #{}", svc.service_id),
                    Style::default().fg(theme.dim),
                ),
            ]));
        }
    }
    f.render_widget(
        Paragraph::new(svc_lines).style(Style::default().bg(theme.bg)),
        chunks[3],
    );

    // 4. Contextual action buttons
    draw_detail_action_bar(f, app, theme, chunks[4]);

    // 5. Muted single-line metadata
    let issuer = peer
        .issuer
        .as_deref()
        .map(|i| format!(" · issued by {i}"))
        .unwrap_or_default();
    let meta = format!("id {}{issuer}", peer.device_id);
    f.render_widget(
        Paragraph::new(Line::styled(
            truncate_width(&meta, chunks[5].width as usize),
            Style::default().fg(theme.dim).bg(theme.bg),
        )),
        chunks[5],
    );
}

#[allow(clippy::too_many_arguments)]
fn draw_kv_copy_row(
    f: &mut Frame,
    app: &mut AppState,
    area: Rect,
    label: &str,
    value: &str,
    val_color: Color,
    copyable: Option<&str>,
    theme: Theme,
) {
    let copy_txt = if copyable.is_some() { " Copy " } else { "" };
    let copy_w = display_width(copy_txt) as u16;
    let val_budget = (area.width as usize).saturating_sub(12 + copy_w as usize + 1);
    let shown = truncate_width(value, val_budget);
    let pad = (area.width as usize)
        .saturating_sub(12 + display_width(&shown) + copy_w as usize);

    let mut spans = vec![
        Span::styled(
            format!("{label:<12}"),
            Style::default().fg(theme.dim).bg(theme.surface),
        ),
        Span::styled(
            shown,
            Style::default()
                .fg(val_color)
                .bg(theme.surface)
                .add_modifier(Modifier::BOLD),
        ),
    ];
    if let Some(copy_val) = copyable {
        if pad > 0 {
            spans.push(Span::styled(" ".repeat(pad), Style::default().bg(theme.surface)));
        }
        let cx = area.x + area.width.saturating_sub(copy_w);
        app.hit_regions.push(HitRegion {
            rect: Rect::new(cx, area.y, copy_w, 1),
            target: HitTarget::CopyText {
                label: label.to_ascii_lowercase(),
                text: copy_val.to_string(),
            },
        });
        spans.push(Span::styled(
            copy_txt,
            Style::default().fg(theme.dim).bg(theme.panel),
        ));
    }
    f.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(theme.surface)),
        area,
    );
}

fn detail_button_label(btn: DetailButton) -> (&'static str, bool, bool) {
    // (label, is_primary, is_danger)
    match btn {
        DetailButton::StartTun => ("▶ Start VPN (TUN)", true, false),
        DetailButton::StartNoTun => ("▶ Session Mode", false, false),
        DetailButton::RestartTun => ("Switch to TUN", true, false),
        DetailButton::RestartNoTun => ("Switch to No-TUN", false, false),
        DetailButton::StopDaemon => ("Stop", false, true),
        DetailButton::ProbePeers => ("Probe", false, false),
        DetailButton::OpenPair => ("+ Pair", false, false),
        DetailButton::OpenDoctor => ("Doctor", false, false),
        DetailButton::OpenLogs => ("Logs", false, false),
        DetailButton::OpenSettings => ("Settings", false, false),
        DetailButton::CopyDns => ("Copy .topaz", true, false),
        DetailButton::CopyIp => ("Copy IP", false, false),
        DetailButton::RevokePeer => ("Revoke", false, true),
    }
}

fn draw_detail_action_bar(f: &mut Frame, app: &mut AppState, theme: Theme, area: Rect) {
    let buttons = app.detail_buttons();
    if buttons.is_empty() || area.width == 0 || area.height == 0 {
        return;
    }
    let detail_focused = app.focus == FocusArea::Detail && app.modal.is_none();
    let active_idx = app.detail_btn_idx.min(buttons.len() - 1);

    let mut spans = Vec::new();
    let mut cx = area.x;
    let right_edge = area.x + area.width;

    for (idx, btn) in buttons.into_iter().enumerate() {
        let (lbl, primary, danger) = detail_button_label(btn);
        let text = format!(" {lbl} ");
        let w = display_width(&text) as u16;
        let gap = if idx > 0 { 1u16 } else { 0u16 };
        if cx + gap + w > right_edge {
            break;
        }
        if gap > 0 {
            spans.push(Span::raw(" "));
            cx += gap;
        }
        let is_focused_btn = detail_focused && idx == active_idx;
        let style = if is_focused_btn {
            Style::default()
                .fg(theme.accent_fg)
                .bg(theme.accent)
                .add_modifier(Modifier::BOLD)
        } else if primary {
            Style::default()
                .fg(theme.accent)
                .bg(theme.accent_bg)
                .add_modifier(Modifier::BOLD)
        } else if danger {
            Style::default().fg(theme.bad).bg(theme.bad_bg)
        } else {
            Style::default().fg(theme.text).bg(theme.surface)
        };
        app.hit_regions.push(HitRegion {
            rect: Rect::new(cx, area.y, w, 1),
            target: HitTarget::DetailAction(btn),
        });
        spans.push(Span::styled(text, style));
        cx += w;
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_bottom_bar(f: &mut Frame, app: &mut AppState, theme: Theme, area: Rect) {
    let mut left = Vec::new();

    if let Some((ref msg, ok, _)) = app.toast {
        let (dot, fg) = if ok { ("✓ ", theme.ok) } else { ("✕ ", theme.bad) };
        left.push(BarSegment::plain(
            vec![
                Span::styled(dot, Style::default().fg(fg).add_modifier(Modifier::BOLD)),
                Span::styled(msg.clone(), Style::default().fg(fg).add_modifier(Modifier::BOLD)),
            ],
            0,
        ));
    } else if let Some(ref busy) = app.busy_banner {
        left.push(BarSegment::plain(
            vec![Span::styled(
                format!("{} {busy}", app.spinner_glyph()),
                Style::default().fg(theme.warn).add_modifier(Modifier::BOLD),
            )],
            0,
        ));
    } else {
        if !app.mouse_capture {
            left.push(BarSegment::clickable(
                vec![Span::styled(
                    "mouse:off",
                    Style::default().fg(theme.warn).add_modifier(Modifier::BOLD),
                )],
                HitTarget::SettingsToggleMouse,
                0,
            ));
        }
        left.push(BarSegment::clickable(
            vec![
                Span::styled(
                    " Ctrl+P ",
                    Style::default().fg(theme.accent).bg(theme.surface),
                ),
                Span::styled(" Commands", Style::default().fg(theme.dim)),
            ],
            HitTarget::OpenPalette,
            0,
        ));
    }

    let right = vec![
        BarSegment::clickable(
            vec![
                Span::styled(" Ctrl+F ", Style::default().fg(theme.secondary).bg(theme.surface)),
                Span::styled(" Filter", Style::default().fg(theme.dim)),
            ],
            HitTarget::FocusFilter,
            3,
        ),
        BarSegment::clickable(
            vec![
                Span::styled(" Ctrl+N ", Style::default().fg(theme.secondary).bg(theme.surface)),
                Span::styled(" Pair", Style::default().fg(theme.dim)),
            ],
            HitTarget::OpenPair,
            2,
        ),
        BarSegment::clickable(
            vec![
                Span::styled(" Ctrl+T ", Style::default().fg(theme.secondary).bg(theme.surface)),
                Span::styled(" Theme", Style::default().fg(theme.dim)),
            ],
            HitTarget::CycleTheme,
            4,
        ),
        BarSegment::clickable(
            vec![
                Span::styled(" F1 ", Style::default().fg(theme.secondary).bg(theme.surface)),
                Span::styled(" Help", Style::default().fg(theme.dim)),
            ],
            HitTarget::OpenHelp,
            1,
        ),
        BarSegment::clickable(
            vec![
                Span::styled(" Ctrl+Q ", Style::default().fg(theme.dim).bg(theme.surface)),
                Span::styled(" Quit", Style::default().fg(theme.dim)),
            ],
            HitTarget::Quit,
            1,
        ),
    ];

    render_split_bar(f, app, area, Some(theme.panel), 1, "  ", left, right);
}

fn capture_screen_lines(f: &mut Frame, app: &mut AppState) {
    let buf = f.buffer_mut();
    let mut lines = Vec::with_capacity(buf.area.height as usize);
    for y in 0..buf.area.height {
        let mut row = Vec::with_capacity(buf.area.width as usize);
        for x in 0..buf.area.width {
            row.push(buf[(x, y)].symbol().to_string());
        }
        lines.push(row);
    }
    app.screen_lines = lines;
}

fn apply_drag_selection_highlight(f: &mut Frame, app: &AppState, theme: Theme) {
    let Some(sel) = app.selection else {
        return;
    };
    if !sel.active || sel.start == sel.end {
        return;
    }
    let (a, b) = if (sel.start.row, sel.start.col) <= (sel.end.row, sel.end.col) {
        (sel.start, sel.end)
    } else {
        (sel.end, sel.start)
    };
    let buf = f.buffer_mut();
    let max_y = buf.area.height.saturating_sub(1);
    let max_x = buf.area.width.saturating_sub(1);
    for row in a.row.min(max_y)..=b.row.min(max_y) {
        let lo = if row == a.row { a.col } else { 0 };
        let hi = if row == b.row { b.col.min(max_x) } else { max_x };
        for col in lo.min(max_x)..=hi {
            let cell = &mut buf[(col, row)];
            cell.set_bg(theme.accent_bg);
            cell.set_fg(theme.accent);
        }
    }
}
