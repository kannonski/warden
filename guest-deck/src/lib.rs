//! deck — a kanban over dstask, as a `kedi:app` WASM plugin with a real ratatui UI.
//!
//! Lifecycle (kedi:app): `init(cols,rows)` builds the model + paints; `on-key` drives nav/actions
//! and repaints; `on-resize` re-lays-out. The UI is ratatui rendered into a `TestBackend` buffer and
//! serialized to ANSI (ansi.rs) for `host.render`. Every task read/write goes through the governed
//! `dstask` capability via `host.invoke` (model/task.rs) — deck-in-WASM has no other door.

wit_bindgen::generate!({ path: "../wit/app", world: "app" });

mod ansi;
mod model;
mod task;
mod view;

use crate::kedi::app::host;
use crate::task::Task;
use model::{Mode, Model};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use std::cell::RefCell;

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

struct State {
    term: Terminal<TestBackend>,
    model: Model,
}

/// Render the model into the TestBackend buffer, then push it to the host as one ANSI frame.
fn paint(st: &mut State) {
    let _ = st.term.draw(|f| view::render(f, &st.model));
    let frame = ansi::buffer_to_ansi(st.term.backend().buffer());
    host::render(&frame);
}

/// Run a dstask mutating op through the governed capability, then reload + report. `args` is the
/// dstask-style argument string (e.g. "1 +now", "2 P1 project:x"); empty for whole-store ops.
fn dstask_do(m: &mut Model, op: &str, args: &str, ok: &str) {
    match host::invoke("dstask", op, args.as_bytes()) {
        Ok(_) => {
            m.reload();
            m.status = ok.to_string();
        }
        Err(e) => m.status = format!("⚠ {e}"),
    }
}

struct Deck;

impl Guest for Deck {
    fn init(cols: u32, rows: u32) {
        let backend = TestBackend::new(cols.max(20) as u16, rows.max(8) as u16);
        let term = Terminal::new(backend).expect("terminal");
        let mut model = Model::new();
        model.cols_w = cols as u16;
        model.cols_h = rows as u16;
        STATE.with(|s| {
            let mut st = State { term, model };
            paint(&mut st);
            *s.borrow_mut() = Some(st);
        });
    }

    fn on_key(k: Key) -> bool {
        let mut keep = true;
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            match st.model.mode {
                Mode::Nav => keep = on_nav_key(&mut st.model, k),
                Mode::Note => on_note_key(&mut st.model, k),
                _ => on_input_key(&mut st.model, k),
            }
            if keep {
                paint(st);
            }
        });
        keep
    }

    fn on_resize(cols: u32, rows: u32) {
        STATE.with(|s| {
            let mut guard = s.borrow_mut();
            let Some(st) = guard.as_mut() else { return };
            let _ = st.term.resize(ratatui::layout::Rect::new(0, 0, cols.max(20) as u16, rows.max(8) as u16));
            st.model.cols_w = cols as u16;
            st.model.cols_h = rows as u16;
            st.model.scroll();
            paint(st);
        });
    }

    fn on_tick() -> bool {
        true
    }
}

/// Navigation-mode keys. Returns false to close the pane (q).
fn on_nav_key(m: &mut Model, k: Key) -> bool {
    m.status.clear();
    match k {
        Key::Text('q') | Key::Escape => return false,
        Key::Text('h') | Key::Left => m.move_col(-1),
        Key::Text('l') | Key::Right => m.move_col(1),
        Key::Text('j') | Key::Down => m.move_card(1),
        Key::Text('k') | Key::Up => m.move_card(-1),
        Key::Text('g') => m.top(),
        Key::Text('G') => m.bottom(),
        Key::Text('r') => {
            m.reload();
            m.status = "↻ reloaded".into();
        }
        // drag the card across columns (retag / resolve based on the target)
        Key::Text('H') => drag(m, -1),
        Key::Text('L') => drag(m, 1),
        // do — actions below act on the cursor card by id, which resolved (DONE) cards don't have
        // (dstask reports id 0 for them), so `actionable` gates them out.
        Key::Text('d') => {
            if let Some(id) = cur_id(m) {
                dstask_do(m, "done", &id.to_string(), "✓ done");
            }
        }
        Key::Text('n') => {
            // toggle today (+now / -now)
            if let Some(t) = actionable(m) {
                let (op, args, msg) = if t.has_tag("now") {
                    ("modify", format!("{} -now", t.id), "○ off today")
                } else {
                    ("modify", format!("{} +now", t.id), "● today")
                };
                dstask_do(m, op, &args, msg);
            }
        }
        Key::Text('s') => {
            if let Some(t) = actionable(m) {
                let (op, id, msg) = if t.status == "active" {
                    ("stop", t.id, "⏸ stopped")
                } else {
                    ("start", t.id, "▶ started")
                };
                dstask_do(m, op, &id.to_string(), msg);
            }
        }
        // input modes
        Key::Text('a') => enter_mode(m, Mode::Add),
        Key::Text('/') => enter_mode(m, Mode::Filter),
        Key::Text('N') => open_note_editor(m),
        Key::Text('m') => {
            if actionable(m).is_some() {
                enter_mode(m, Mode::Modify);
            }
        }
        _ => {}
    }
    true
}

/// Input-mode keys: build `m.input`, commit on Enter, cancel on Escape.
fn on_input_key(m: &mut Model, k: Key) {
    match k {
        Key::Escape => {
            if m.mode == Mode::Filter {
                m.filter.clear();
            }
            m.mode = Mode::Nav;
            m.input.clear();
            m.card = model::clampi(m.card as isize, m.visn());
            m.scroll();
        }
        Key::Enter => commit_input(m),
        Key::Backspace => {
            m.input.pop();
            if m.mode == Mode::Filter {
                m.filter = m.input.clone(); // live filter
                m.scroll();
            }
        }
        Key::Text(c) => {
            m.input.push(c);
            if m.mode == Mode::Filter {
                m.filter = m.input.clone();
                m.card = model::clampi(m.card as isize, m.visn());
                m.scroll();
            }
        }
        _ => {}
    }
}

fn enter_mode(m: &mut Model, mode: Mode) {
    m.mode = mode;
    m.input.clear();
}

/// Open the in-place note editor for the selected card. The note blob is already in the loaded task
/// (dstask's `list` JSON carries `notes`), so we edit that directly — no extra capability round-trip.
/// No selection → no-op.
fn open_note_editor(m: &mut Model) {
    let Some(t) = actionable(m) else { return }; // resolved cards have id 0 → note-set can't target them
    let (id, text) = (t.id, t.notes.clone());
    m.note.open(id, &text);
    m.mode = Mode::Note;
}

/// Note-editor keys: a real multi-line editor. Esc saves the whole blob back (note-set), Ctrl+C
/// discards. Everything else edits the buffer in place; the detail pane renders it live.
fn on_note_key(m: &mut Model, k: Key) {
    match k {
        Key::Escape => {
            let (id, body) = (m.note.id, m.note.text());
            m.mode = Mode::Nav;
            let payload = format!("{id}\n{body}");
            match host::invoke("dstask", "note-set", payload.as_bytes()) {
                Ok(_) => {
                    m.reload();
                    m.status = "📝 note saved".into();
                }
                Err(e) => m.status = format!("⚠ {e}"),
            }
        }
        Key::Text('\u{3}') => {
            // Ctrl+C — discard, back to nav without saving
            m.mode = Mode::Nav;
            m.status = "note discarded".into();
        }
        Key::Enter => m.note.newline(),
        Key::Backspace => m.note.backspace(),
        Key::Left => m.note.left(),
        Key::Right => m.note.right(),
        Key::Up => m.note.up(),
        Key::Down => m.note.down(),
        Key::Tab => {
            m.note.insert(' ');
            m.note.insert(' ');
        }
        Key::Text(c) if !c.is_control() => m.note.insert(c),
        _ => {}
    }
}

fn commit_input(m: &mut Model) {
    let text = m.input.trim().to_string();
    let mode = m.mode;
    m.mode = Mode::Nav;
    m.input.clear();
    if text.is_empty() && mode != Mode::Filter {
        return;
    }
    match mode {
        Mode::Add => dstask_do(m, "add", &text, "+ captured"),
        Mode::Modify => {
            if let Some(id) = cur_id(m) {
                dstask_do(m, "modify", &format!("{id} {text}"), "✎ modified");
            }
        }
        // Note never reaches commit_input — the editor handles its own keys in on_note_key.
        Mode::Note => {}
        Mode::Filter => {
            m.filter = text;
            m.card = model::clampi(m.card as isize, m.visn());
            m.scroll();
        }
        Mode::Nav => {}
    }
}

/// The selected card, but only if it's actionable — resolved (DONE) cards aren't: dstask reports them
/// with id 0, so any by-id op would hit the wrong task. Guards all the mutating nav keys.
fn actionable(m: &Model) -> Option<&Task> {
    m.selected().filter(|t| t.status != "resolved")
}

fn cur_id(m: &Model) -> Option<i64> {
    actionable(m).map(|t| t.id)
}

/// Drag the selected card `d` columns over: derive the dstask change from the target column
/// (TODAY → +now, WAITING → +waiting, NEXT → clear both, DONE → resolve). Mirrors deck's H/L.
fn drag(m: &mut Model, d: isize) {
    let Some(t) = actionable(m) else { return }; // can't drag a resolved card (no id)
    let (id, from) = (t.id, m.col);
    let to = model::clampi(from as isize + d, m.cols.len());
    if to == from {
        return;
    }
    let (op, args, msg): (&str, String, &str) = match m.cols[to].title {
        "TODAY" => ("modify", format!("{id} +now -waiting"), "● → today"),
        "WAITING" => ("modify", format!("{id} +waiting -now"), "→ waiting"),
        "NEXT" => ("modify", format!("{id} -now -waiting"), "→ next"),
        "DONE" => ("done", id.to_string(), "✓ done"),
        _ => return,
    };
    m.col = to; // follow the card to its new column
    dstask_do(m, op, &args, msg);
}

export!(Deck);
