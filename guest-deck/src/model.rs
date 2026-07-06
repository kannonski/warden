//! deck's state + pure navigation logic (ported from the Go model). No IO here — `load()` (task.rs)
//! is the only thing that reaches the capability; everything in this file is cursor/filter math.

use crate::task::{Column, Task, load};

pub struct Model {
    pub cols: Vec<Column>,
    pub cols_w: u16,
    pub cols_h: u16,
    pub col: usize,  // cursor column
    pub card: usize, // cursor card (index within the filtered view)
    pub off: Vec<usize>, // per-column scroll offset
    pub mode: Mode,
    pub input: String,
    pub filter: String,
    pub status: String,
    /// note editor (Mode::Note): the note as lines, plus a (row, col) cursor and the id being edited.
    pub note: NoteEdit,
}

/// The in-place note editor's buffer + cursor. `lines` is never empty (at least one blank line so the
/// cursor always has a home). `row`/`col` are char offsets, both clamped to the buffer on every edit.
#[derive(Default)]
pub struct NoteEdit {
    pub id: i64,
    pub lines: Vec<String>,
    pub row: usize,
    pub col: usize,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Mode {
    Nav,
    Add,
    Filter,
    Note,
    Modify,
}

impl NoteEdit {
    /// Load `text` into the editor for task `id`, cursor at the end (where you resume writing).
    pub fn open(&mut self, id: i64, text: &str) {
        self.id = id;
        self.lines = if text.is_empty() {
            vec![String::new()]
        } else {
            text.split('\n').map(str::to_string).collect()
        };
        self.row = self.lines.len() - 1;
        self.col = self.lines[self.row].chars().count();
    }

    /// The buffer as one string (what we save back). Trailing blank lines are kept as the user left
    /// them — dstask normalizes its own whitespace.
    pub fn text(&self) -> String {
        self.lines.join("\n")
    }

    fn cur_len(&self) -> usize {
        self.lines[self.row].chars().count()
    }

    /// Split the current line at the cursor into two lines; cursor moves to the start of the new line.
    pub fn newline(&mut self) {
        let rest: String = self.lines[self.row].chars().skip(self.col).collect();
        let head: String = self.lines[self.row].chars().take(self.col).collect();
        self.lines[self.row] = head;
        self.lines.insert(self.row + 1, rest);
        self.row += 1;
        self.col = 0;
    }

    pub fn insert(&mut self, c: char) {
        let line = &mut self.lines[self.row];
        let byte = line.char_indices().nth(self.col).map(|(b, _)| b).unwrap_or(line.len());
        line.insert(byte, c);
        self.col += 1;
    }

    /// Delete the char before the cursor; at column 0, join with the previous line.
    pub fn backspace(&mut self) {
        if self.col > 0 {
            let line = &mut self.lines[self.row];
            let byte = line.char_indices().nth(self.col - 1).map(|(b, _)| b).unwrap_or(0);
            line.remove(byte);
            self.col -= 1;
        } else if self.row > 0 {
            let cur = self.lines.remove(self.row);
            self.row -= 1;
            self.col = self.cur_len();
            self.lines[self.row].push_str(&cur);
        }
    }

    pub fn left(&mut self) {
        if self.col > 0 {
            self.col -= 1;
        } else if self.row > 0 {
            self.row -= 1;
            self.col = self.cur_len();
        }
    }
    pub fn right(&mut self) {
        if self.col < self.cur_len() {
            self.col += 1;
        } else if self.row + 1 < self.lines.len() {
            self.row += 1;
            self.col = 0;
        }
    }
    pub fn up(&mut self) {
        if self.row > 0 {
            self.row -= 1;
            self.col = self.col.min(self.cur_len());
        }
    }
    pub fn down(&mut self) {
        if self.row + 1 < self.lines.len() {
            self.row += 1;
            self.col = self.col.min(self.cur_len());
        }
    }
}

pub fn clampi(v: isize, n: usize) -> usize {
    if n == 0 {
        0
    } else if v < 0 {
        0
    } else if (v as usize) >= n {
        n - 1
    } else {
        v as usize
    }
}

impl Model {
    pub fn new() -> Model {
        let mut m = Model {
            cols: Vec::new(),
            cols_w: 80,
            cols_h: 24,
            col: 0,
            card: 0,
            off: Vec::new(),
            mode: Mode::Nav,
            input: String::new(),
            filter: String::new(),
            status: String::new(),
            note: NoteEdit::default(),
        };
        m.reload();
        m
    }

    pub fn reload(&mut self) {
        match load() {
            Ok(cols) => {
                self.cols = cols;
                if self.off.len() != self.cols.len() {
                    self.off = vec![0; self.cols.len()];
                }
                self.col = clampi(self.col as isize, self.cols.len());
                let n = self.visn();
                self.card = clampi(self.card as isize, n);
                self.scroll();
            }
            Err(e) => self.status = format!("⚠ {e}"),
        }
    }

    /// Cards visible in column `ci` after the active filter (area/state/summary substring).
    pub fn shown(&self, ci: usize) -> Vec<&Task> {
        let Some(col) = self.cols.get(ci) else { return Vec::new() };
        if self.filter.is_empty() {
            return col.cards.iter().collect();
        }
        let f = self.filter.to_lowercase();
        col.cards
            .iter()
            .filter(|t| {
                format!("{} {} {}", t.project, t.state(), t.summary)
                    .to_lowercase()
                    .contains(&f)
            })
            .collect()
    }

    pub fn visn(&self) -> usize {
        self.shown(self.col).len()
    }

    /// The selected task's uuid (for actions), or None if the column is empty.
    #[allow(dead_code)] // for the planned move-follow-cursor feature
    pub fn selected_uuid(&self) -> Option<String> {
        self.shown(self.col).get(self.card).map(|t| t.uuid.clone())
    }

    pub fn selected(&self) -> Option<&Task> {
        self.shown(self.col).into_iter().nth(self.card)
    }

    /// Visible cards per column, from the current column height (title + blank + 2/card).
    pub fn visible_rows(&self) -> usize {
        (((self.cols_h as usize).saturating_sub(4)) / 2).max(3)
    }

    /// Keep the cursor inside its column's scroll window.
    pub fn scroll(&mut self) {
        if self.col >= self.off.len() {
            return;
        }
        let v = self.visible_rows();
        if self.card < self.off[self.col] {
            self.off[self.col] = self.card;
        }
        if self.card >= self.off[self.col] + v {
            self.off[self.col] = self.card + 1 - v;
        }
    }

    pub fn move_col(&mut self, d: isize) {
        self.col = clampi(self.col as isize + d, self.cols.len());
        self.card = clampi(self.card as isize, self.visn());
        self.scroll();
    }
    pub fn move_card(&mut self, d: isize) {
        self.card = clampi(self.card as isize + d, self.visn());
        self.scroll();
    }
    pub fn top(&mut self) {
        self.card = 0;
        self.scroll();
    }
    pub fn bottom(&mut self) {
        self.card = clampi(isize::MAX, self.visn());
        self.scroll();
    }
}
