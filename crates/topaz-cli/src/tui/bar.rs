//! Shared horizontal split-bar renderer with priority-based graceful dropping
//! and automatic mouse `HitRegion` registration (aligned with Jade's `bar.rs`).

use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;

use super::state::{AppState, HitRegion, HitTarget};

pub fn display_width(s: &str) -> usize {
    Span::raw(s).width()
}

pub fn truncate_width(s: &str, max_w: usize) -> String {
    if max_w == 0 {
        return String::new();
    }
    if display_width(s) <= max_w {
        return s.to_string();
    }
    if max_w == 1 {
        return "…".to_string();
    }
    let mut out = String::new();
    let mut used = 0usize;
    let budget = max_w - 1;
    for ch in s.chars() {
        let mut buf = [0u8; 4];
        let cw = display_width(ch.encode_utf8(&mut buf));
        if used + cw > budget {
            break;
        }
        out.push(ch);
        used += cw;
    }
    out.push('…');
    out
}

pub struct BarSegment {
    pub spans: Vec<Span<'static>>,
    pub target: Option<HitTarget>,
    /// `0` is never dropped; higher priorities are dropped first when space is tight.
    pub priority: u8,
}

impl BarSegment {
    pub fn plain(spans: Vec<Span<'static>>, priority: u8) -> Self {
        Self {
            spans,
            target: None,
            priority,
        }
    }

    pub fn clickable(spans: Vec<Span<'static>>, target: HitTarget, priority: u8) -> Self {
        Self {
            spans,
            target: Some(target),
            priority,
        }
    }

    pub fn width(&self) -> usize {
        self.spans.iter().map(|s| display_width(&s.content)).sum()
    }
}

#[allow(clippy::too_many_arguments)]
pub fn render_split_bar(
    frame: &mut Frame,
    app: &mut AppState,
    area: Rect,
    bg: Option<Color>,
    pad_x: u16,
    sep: &str,
    mut left: Vec<BarSegment>,
    mut right: Vec<BarSegment>,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let row_area = Rect {
        x: area.x,
        y: area.y,
        width: area.width,
        height: 1,
    };
    let inner_w = (row_area.width as usize).saturating_sub(pad_x as usize * 2);
    if inner_w == 0 {
        if let Some(c) = bg {
            frame.render_widget(Block::default().style(Style::default().bg(c)), row_area);
        }
        return;
    }

    let sep_w = display_width(sep);
    while !fits(&left, &right, sep_w, inner_w) {
        let Some((from_right, idx)) = lowest_importance(&left, &right) else {
            break;
        };
        if from_right {
            right.remove(idx);
        } else {
            left.remove(idx);
        }
    }

    let mut left_w = side_width(&left, sep_w);
    let mut right_w = side_width(&right, sep_w);
    let min_gap = usize::from(!left.is_empty() && !right.is_empty());
    if left_w + right_w + min_gap > inner_w {
        let right_budget = if left.is_empty() {
            inner_w
        } else {
            right_w.min((inner_w / 2).max(1))
        };
        let left_budget = inner_w.saturating_sub(right_budget + min_gap);
        clip_side(&mut left, sep_w, left_budget);
        clip_side(&mut right, sep_w, right_budget);
        left_w = side_width(&left, sep_w);
        right_w = side_width(&right, sep_w);
    }

    let gap = inner_w.saturating_sub(left_w + right_w);
    let mut all_spans: Vec<Span<'static>> = Vec::new();
    if pad_x > 0 {
        all_spans.push(Span::raw(" ".repeat(pad_x as usize)));
    }
    let mut cx = row_area.x + pad_x;
    emit_side(app, row_area, &left, sep, sep_w, &mut cx, &mut all_spans);
    if gap > 0 {
        all_spans.push(Span::raw(" ".repeat(gap)));
        cx = cx.saturating_add(gap as u16);
    }
    emit_side(app, row_area, &right, sep, sep_w, &mut cx, &mut all_spans);
    if pad_x > 0 {
        all_spans.push(Span::raw(" ".repeat(pad_x as usize)));
    }

    let mut p = Paragraph::new(Line::from(all_spans));
    if let Some(c) = bg {
        p = p.style(Style::default().bg(c));
    }
    frame.render_widget(p, row_area);
}

fn side_width(segs: &[BarSegment], sep_w: usize) -> usize {
    if segs.is_empty() {
        return 0;
    }
    let items: usize = segs.iter().map(BarSegment::width).sum();
    items + (segs.len() - 1) * sep_w
}

fn fits(left: &[BarSegment], right: &[BarSegment], sep_w: usize, inner_w: usize) -> bool {
    let min_gap = usize::from(!left.is_empty() && !right.is_empty());
    side_width(left, sep_w) + side_width(right, sep_w) + min_gap <= inner_w
}

fn lowest_importance(left: &[BarSegment], right: &[BarSegment]) -> Option<(bool, usize)> {
    let max_left = left.iter().map(|s| s.priority).max().unwrap_or(0);
    let max_right = right.iter().map(|s| s.priority).max().unwrap_or(0);
    let target = max_left.max(max_right);
    if target == 0 {
        return None;
    }
    if max_right == target {
        let idx = right.iter().rposition(|s| s.priority == target)?;
        Some((true, idx))
    } else {
        let idx = left.iter().rposition(|s| s.priority == target)?;
        Some((false, idx))
    }
}

fn clip_side(segs: &mut Vec<BarSegment>, sep_w: usize, budget: usize) {
    while segs.len() > 1 && side_width(segs, sep_w) > budget {
        segs.pop();
    }
    let Some(first) = segs.first_mut() else {
        return;
    };
    if first.width() <= budget {
        return;
    }
    let mut rem = budget;
    let mut kept = Vec::new();
    for sp in first.spans.drain(..) {
        if rem == 0 {
            break;
        }
        let w = display_width(&sp.content);
        if w <= rem {
            rem -= w;
            kept.push(sp);
        } else {
            let clipped = truncate_width(&sp.content, rem);
            rem = 0;
            kept.push(Span::styled(clipped, sp.style));
        }
    }
    first.spans = kept;
}

fn emit_side(
    app: &mut AppState,
    row_area: Rect,
    segs: &[BarSegment],
    sep: &str,
    sep_w: usize,
    cx: &mut u16,
    out: &mut Vec<Span<'static>>,
) {
    let right_edge = row_area.x + row_area.width;
    for (idx, seg) in segs.iter().enumerate() {
        if idx > 0 && !sep.is_empty() {
            out.push(Span::raw(sep.to_string()));
            *cx = cx.saturating_add(sep_w as u16);
        }
        let seg_w = seg.width() as u16;
        if let Some(target) = &seg.target {
            let clipped_w = seg_w.min(right_edge.saturating_sub(*cx));
            if clipped_w > 0 {
                app.hit_regions.push(HitRegion {
                    rect: Rect {
                        x: *cx,
                        y: row_area.y,
                        width: clipped_w,
                        height: 1,
                    },
                    target: target.clone(),
                });
            }
        }
        out.extend(seg.spans.iter().cloned());
        *cx = cx.saturating_add(seg_w);
    }
}
