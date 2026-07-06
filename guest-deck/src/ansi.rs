//! ratatui `Buffer` → ANSI string. The "ratatui→ANSI backend" the plugin design called for.
//!
//! We render the ratatui widget tree into a `TestBackend`'s in-memory `Buffer` (a grid of styled
//! `Cell`s), then serialize that grid to an ANSI/UTF-8 string the host paints via `host.render`.
//! Only the SGR attributes ratatui actually sets are emitted, and we reset+re-set style per cell run
//! so the frame is self-contained (no leakage from a previous frame). One `render` = one full frame.

use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier};

/// Serialize a ratatui buffer to a full-screen ANSI frame: clear, home, then each row with styled
/// runs. Rows are separated by `\r\n` so the terminal returns to column 0.
pub fn buffer_to_ansi(buf: &Buffer) -> String {
    let w = buf.area.width;
    let h = buf.area.height;
    let mut out = String::with_capacity((w as usize * h as usize) * 2 + 64);
    out.push_str("\x1b[2J\x1b[H"); // clear + home — a fresh frame each time
    let mut cur = Style::default();
    out.push_str("\x1b[0m");
    for y in 0..h {
        if y > 0 {
            out.push_str("\x1b[0m\r\n");
            cur = Style::default();
        }
        for x in 0..w {
            let cell = &buf[(x, y)];
            let want = Style::of(cell.fg, cell.bg, cell.modifier);
            if want != cur {
                out.push_str(&want.sgr());
                cur = want;
            }
            let sym = cell.symbol();
            out.push_str(if sym.is_empty() { " " } else { sym });
        }
    }
    out.push_str("\x1b[0m");
    out
}

// The subset of style we serialize, so we can diff cell-to-cell and only emit SGR on change.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Style {
    fg: Option<u8>, // 256-color index, resolved from ratatui's Color
    bg: Option<u8>,
    bold: bool,
    dim: bool,
    italic: bool,
    underline: bool,
    reverse: bool,
}

impl Default for Style {
    fn default() -> Self {
        Style { fg: None, bg: None, bold: false, dim: false, italic: false, underline: false, reverse: false }
    }
}

impl Style {
    fn of(fg: Color, bg: Color, m: Modifier) -> Style {
        Style {
            fg: color_index(fg),
            bg: color_index(bg),
            bold: m.contains(Modifier::BOLD),
            dim: m.contains(Modifier::DIM),
            italic: m.contains(Modifier::ITALIC),
            underline: m.contains(Modifier::UNDERLINED),
            reverse: m.contains(Modifier::REVERSED),
        }
    }

    /// The SGR sequence for this style (reset first, so runs are independent).
    fn sgr(&self) -> String {
        let mut s = String::from("\x1b[0");
        if self.bold {
            s.push_str(";1");
        }
        if self.dim {
            s.push_str(";2");
        }
        if self.italic {
            s.push_str(";3");
        }
        if self.underline {
            s.push_str(";4");
        }
        if self.reverse {
            s.push_str(";7");
        }
        if let Some(c) = self.fg {
            s.push_str(&format!(";38;5;{c}"));
        }
        if let Some(c) = self.bg {
            s.push_str(&format!(";48;5;{c}"));
        }
        s.push('m');
        s
    }
}

/// Resolve a ratatui `Color` to a 256-color index (`None` = terminal default). deck's palette is
/// 256-color indices already (lipgloss "117", "212", …), so `Indexed` is the common case; the named
/// ANSI colors map to their 0–15 slots; RGB is quantized to the 6×6×6 cube.
fn color_index(c: Color) -> Option<u8> {
    Some(match c {
        Color::Reset => return None,
        Color::Black => 0,
        Color::Red => 1,
        Color::Green => 2,
        Color::Yellow => 3,
        Color::Blue => 4,
        Color::Magenta => 5,
        Color::Cyan => 6,
        Color::Gray => 7,
        Color::DarkGray => 8,
        Color::LightRed => 9,
        Color::LightGreen => 10,
        Color::LightYellow => 11,
        Color::LightBlue => 12,
        Color::LightMagenta => 13,
        Color::LightCyan => 14,
        Color::White => 15,
        Color::Indexed(i) => i,
        Color::Rgb(r, g, b) => {
            let q = |v: u8| (v as u16 * 5 / 255) as u8;
            16 + 36 * q(r) + 6 * q(g) + q(b)
        }
    })
}
