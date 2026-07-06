//! The ratatui view — real widgets (Layout · Block · List · Paragraph), not hand-rolled ANSI.
//!
//! Draws the board: a row of column Blocks (rounded borders, accent titles), each a List of task
//! cards (id + summary + meta, the selected one highlighted); a detail Paragraph for the selected
//! task; and a footer line (filter/status/hints, or the current input mode). This is what "more
//! ratatuish" means — the layout and styling are ratatui's job, and `ansi::buffer_to_ansi` turns the
//! rendered buffer into the frame the host paints.

use crate::model::{Mode, Model};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, List, ListItem, ListState, Paragraph, Wrap};

const DIM: Color = Color::Indexed(240);
const SEL: Color = Color::Indexed(212);
const ID: Color = Color::Indexed(117);

pub fn render(f: &mut Frame, m: &Model) {
    // board (fills) · detail (fraction) · footer (1)
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(6),
            Constraint::Length((f.area().height / 3).clamp(5, 14)),
            Constraint::Length(2),
        ])
        .split(f.area());

    render_board(f, m, root[0]);
    render_detail(f, m, root[1]);
    render_footer(f, m, root[2]);
}

fn render_board(f: &mut Frame, m: &Model, area: Rect) {
    let n = m.cols.len().max(1);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(vec![Constraint::Ratio(1, n as u32); n])
        .split(area);

    for (ci, col) in m.cols.iter().enumerate() {
        let active = ci == m.col;
        let accent = Color::Indexed(col.accent);
        let cards = m.shown(ci);

        let title = Line::from(vec![
            Span::styled(
                if active { "▸ " } else { "  " },
                Style::default().fg(SEL),
            ),
            Span::styled(
                format!("{}  {}", col.title, cards.len()),
                Style::default().fg(accent).add_modifier(Modifier::BOLD),
            ),
        ]);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(if active { accent } else { Color::Indexed(238) }))
            .title(title);

        let inner_w = cols[ci].width.saturating_sub(2) as usize;
        let items: Vec<ListItem> = cards
            .iter()
            .map(|t| card_item(t, inner_w))
            .collect();
        let mut list = List::new(items).block(block);
        // highlight the cursor card only in the active column
        let mut state = ListState::default();
        if active && !cards.is_empty() {
            state.select(Some(m.card));
            list = list.highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        }
        f.render_stateful_widget(list, cols[ci], &mut state);
    }
}

/// One card = two lines: `id summary` and an indented meta line (project · state).
fn card_item<'a>(t: &'a crate::task::Task, w: usize) -> ListItem<'a> {
    let sum_w = w.saturating_sub(6).max(4);
    let mut meta = t.project.clone();
    if !t.state().is_empty() {
        meta = format!("{meta} · {}", t.state());
    }
    let sum_style = if t.status == "active" {
        Style::default().fg(Color::Indexed(213)).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Reset)
    };
    ListItem::new(vec![
        Line::from(vec![
            Span::styled(format!("{:>3} ", t.id), Style::default().fg(ID)),
            Span::styled(trunc(&t.summary, sum_w), sum_style),
        ]),
        Line::from(Span::styled(
            format!("    {}", trunc(&meta, w.saturating_sub(4))),
            Style::default().fg(DIM),
        )),
    ])
}

fn render_detail(f: &mut Frame, m: &Model, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(DIM))
        .title(Span::styled(" detail ", Style::default().fg(DIM)));
    let body: Vec<Line> = match m.selected() {
        None => vec![Line::from(Span::styled("no card selected", Style::default().fg(DIM)))],
        Some(t) => {
            let mut meta = format!("#{} · {}", t.id, t.project);
            if t.status == "active" {
                meta.push_str(" · ▶ active");
            }
            let mut lines = vec![
                Line::from(Span::styled(
                    t.summary.clone(),
                    Style::default().fg(SEL).add_modifier(Modifier::BOLD),
                )),
                Line::from(Span::styled(meta, Style::default().fg(DIM))),
            ];
            if !t.notes.trim().is_empty() {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled("📝 notes", Style::default().fg(SEL))));
                for n in t.notes.lines() {
                    lines.push(Line::from(n.to_string()));
                }
            }
            lines
        }
    };
    f.render_widget(Paragraph::new(body).block(block).wrap(Wrap { trim: false }), area);
}

fn render_footer(f: &mut Frame, m: &Model, area: Rect) {
    let line = match m.mode {
        Mode::Nav => {
            if !m.status.is_empty() {
                Line::from(Span::styled(format!("  {}", m.status), Style::default().fg(SEL)))
            } else {
                let hints = "h/l/j/k move · H/L drag · a add · d done · n today · / filter · q quit";
                let mut spans = vec![Span::styled(format!("  {hints}"), Style::default().fg(DIM))];
                if !m.filter.is_empty() {
                    spans.insert(0, Span::styled(format!("⦿ {}  ", m.filter), Style::default().fg(SEL)));
                }
                Line::from(spans)
            }
        }
        mode => {
            let (label, hint) = match mode {
                Mode::Add => ("add", "enter add · esc cancel"),
                Mode::Filter => ("filter", "enter apply · esc clear"),
                Mode::Note => ("note", "enter save · esc cancel"),
                Mode::Modify => ("modify", "+tag -tag P1 project:x · enter · esc"),
                Mode::Nav => unreachable!(),
            };
            Line::from(vec![
                Span::styled(format!("  {label} ▸ "), Style::default().fg(SEL).add_modifier(Modifier::BOLD)),
                Span::raw(format!("{}▌  ", m.input)),
                Span::styled(hint, Style::default().fg(DIM)),
            ])
        }
    };
    f.render_widget(Paragraph::new(line), area);
}

fn trunc(s: &str, n: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if n < 1 {
        return "…".into();
    }
    if chars.len() <= n {
        return s.to_string();
    }
    let mut out: String = chars[..n - 1].iter().collect();
    out.push('…');
    out
}
