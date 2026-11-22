//! Full mouse support (Jade-aligned): clickable hit-regions across bars,
//! lists, cards & modals, wheel scrolling, divider drag-resize, and drag-to-copy.

use std::path::Path;

use ratatui::crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
use ratatui::layout::Rect;
use tokio::sync::mpsc;

use super::actions::apply_hit_target;
use super::clipboard;
use super::state::{
    filtered_palette, AppMode, AppState, FocusArea, GridPos, HitTarget, Modal, MouseSelection,
    OnboardingChoice, UiEvent,
};

fn contains(r: Rect, col: u16, row: u16) -> bool {
    r.width > 0
        && r.height > 0
        && col >= r.x
        && col < r.x.saturating_add(r.width)
        && row >= r.y
        && row < r.y.saturating_add(r.height)
}

pub fn handle_mouse(
    app: &mut AppState,
    mouse: MouseEvent,
    data_dir: &Path,
    tx: &mpsc::UnboundedSender<UiEvent>,
) {
    let col = mouse.column;
    let row = mouse.row;

    match mouse.kind {
        MouseEventKind::Moved => {
            app.divider.dragging = false;
            app.divider.hover = app.modal.is_none()
                && app
                    .divider
                    .x
                    .is_some_and(|dx| col.abs_diff(dx) <= 1 && row >= app.sidebar_area.y);
        }
        MouseEventKind::Down(MouseButton::Left) => {
            app.divider.dragging = false;

            // If a modal is open, dispatch click immediately on press for snappy controls.
            if app.modal.is_some() {
                dispatch_click(app, col, row, data_dir, tx);
                return;
            }

            // Divider drag start
            if let Some(dx) = app.divider.x {
                if col.abs_diff(dx) <= 1 && row >= app.sidebar_area.y {
                    app.divider.dragging = true;
                    app.divider.hover = true;
                    app.selection = None;
                    app.drag_start = None;
                    return;
                }
            }

            app.selection = None;
            app.drag_start = Some(GridPos { col, row });
        }
        MouseEventKind::Drag(MouseButton::Left) => {
            if app.divider.dragging {
                let total_w = app.last_area.width;
                if total_w >= 60 {
                    let max_w = total_w.saturating_sub(36).max(24);
                    let new_w = col.saturating_sub(app.last_area.x).clamp(24, max_w);
                    app.divider.width_override = Some(new_w);
                }
                return;
            }
            if app.modal.is_none() {
                if let Some(start) = app.drag_start {
                    let end = GridPos { col, row };
                    if start != end {
                        app.selection = Some(MouseSelection {
                            start,
                            end,
                            active: true,
                        });
                    }
                }
            }
        }
        MouseEventKind::Up(MouseButton::Left) => {
            if app.divider.dragging {
                app.divider.dragging = false;
                app.save_prefs(data_dir);
                return;
            }
            let drag_start = app.drag_start.take();
            let finished_sel = if let Some(sel) = app.selection.as_mut() {
                if sel.active && sel.start != sel.end {
                    sel.active = false;
                    Some((sel.start, sel.end))
                } else {
                    None
                }
            } else {
                None
            };
            if let Some((a, b)) = finished_sel {
                let copied = extract_selected_text(app, a, b);
                if !copied.trim().is_empty() {
                    clipboard::copy_text(&copied);
                    let chars = copied.chars().count();
                    app.set_toast(true, format!("Copied {chars} chars"));
                }
                app.selection = None;
                return;
            }
            app.selection = None;
            if drag_start.is_some() && app.modal.is_none() {
                dispatch_click(app, col, row, data_dir, tx);
            }
        }
        MouseEventKind::ScrollUp => handle_scroll(app, col, row, -1),
        MouseEventKind::ScrollDown => handle_scroll(app, col, row, 1),
        _ => {}
    }
}

fn dispatch_click(
    app: &mut AppState,
    col: u16,
    row: u16,
    data_dir: &Path,
    tx: &mpsc::UnboundedSender<UiEvent>,
) {
    let hit = app
        .hit_regions
        .iter()
        .rev()
        .find(|hr| contains(hr.rect, col, row))
        .map(|hr| hr.target.clone());

    if let Some(target) = hit {
        // When clicking inside a modal area on empty background (not on any button),
        // do not let the click fall through to `ModalBackdrop`!
        if target == HitTarget::ModalBackdrop {
            if let Some(m_rect) = app.modal_area {
                if contains(m_rect, col, row) {
                    return;
                }
            }
        }
        apply_hit_target(app, target, data_dir, tx);
        return;
    }

    if app.modal.is_none() {
        if contains(app.sidebar_area, col, row) {
            app.focus = FocusArea::Sidebar;
        } else if contains(app.detail_area, col, row) {
            app.focus = FocusArea::Detail;
        }
    }
}

fn handle_scroll(app: &mut AppState, col: u16, row: u16, dir: i16) {
    if let Some(ref mut modal) = app.modal {
        match modal {
            Modal::Palette { query, selected } => {
                let len = filtered_palette(&query.value).len();
                if len == 0 {
                    return;
                }
                if dir < 0 {
                    *selected = selected.saturating_sub(1);
                } else {
                    *selected = (*selected + 1).min(len - 1);
                }
            }
            Modal::Doctor(d) => {
                if dir < 0 {
                    d.scroll = d.scroll.saturating_sub(3);
                } else {
                    d.scroll = d.scroll.saturating_add(3).min(d.max_scroll);
                }
            }
            Modal::Logs(l) => {
                if dir < 0 {
                    l.follow = false;
                    l.scroll = l.scroll.saturating_sub(3);
                } else {
                    l.scroll = l.scroll.saturating_add(3).min(l.max_scroll);
                    if l.scroll >= l.max_scroll {
                        l.follow = true;
                    }
                }
            }
            _ => {}
        }
        return;
    }

    if app.mode() == AppMode::Onboarding {
        let count = OnboardingChoice::ALL.len();
        if dir < 0 {
            app.onboarding_idx = app.onboarding_idx.saturating_sub(1);
        } else {
            app.onboarding_idx = (app.onboarding_idx + 1).min(count - 1);
        }
        return;
    }

    if contains(app.sidebar_area, col, row) {
        app.move_selection(dir as isize);
    } else if contains(app.detail_area, col, row) {
        if dir < 0 {
            app.detail_scroll = app.detail_scroll.saturating_sub(2);
        } else {
            app.detail_scroll = app
                .detail_scroll
                .saturating_add(2)
                .min(app.detail_max_scroll);
        }
    }
}

fn extract_selected_text(app: &AppState, a: GridPos, b: GridPos) -> String {
    let (start, end) = if (a.row, a.col) <= (b.row, b.col) {
        (a, b)
    } else {
        (b, a)
    };
    let mut out = Vec::new();
    for row in start.row..=end.row {
        let Some(cells) = app.screen_lines.get(row as usize) else {
            continue;
        };
        let lo = if row == start.row {
            (start.col as usize).min(cells.len())
        } else {
            0
        };
        let hi = if row == end.row {
            (end.col as usize + 1).min(cells.len())
        } else {
            cells.len()
        };
        if lo < hi {
            let mut line = String::new();
            for sym in &cells[lo..hi] {
                if !sym.is_empty() {
                    line.push_str(sym);
                }
            }
            out.push(line.trim_end().to_string());
        } else {
            out.push(String::new());
        }
    }
    out.join("\n").trim().to_string()
}
