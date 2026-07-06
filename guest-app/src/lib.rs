//! A minimal `kedi:app` guest — the WASM-TUI spine proof.
//!
//! No ratatui yet (that lands with deck): this just paints a greeting + a live keypress count via
//! `host.render`, on init / every key / every resize, and quits on `q` or Escape. It exercises the
//! whole pipeline — load the component, `init(cols,rows)`, frames stream out as `Event::Output`,
//! keys arrive via `on-key`, the app closes the pane by returning `false`.

wit_bindgen::generate!({ path: "../wit/app", world: "app" });

use crate::kedi::app::host;
use std::cell::RefCell;

// tiny bit of state: the current size and how many keys we've seen
thread_local! {
    static SIZE: RefCell<(u32, u32)> = const { RefCell::new((80, 24)) };
    static KEYS: RefCell<u32> = const { RefCell::new(0) };
}

/// Paint the screen: clear, home the cursor, draw a centered-ish greeting. ANSI only — the host
/// forwards this string straight to the pane (it becomes one governed `Event::Output` frame).
fn paint() {
    let (cols, rows) = SIZE.with(|s| *s.borrow());
    let keys = KEYS.with(|k| *k.borrow());
    let mut s = String::new();
    s.push_str("\x1b[2J\x1b[H"); // clear + home
    let title = "🐱  hello from a kedi WASM app";
    let sub = format!("running in a governed pane · {cols}×{rows} · keys: {keys}");
    let hint = "press any key (counts) · q or Esc to close";
    // rough vertical centering
    let top = (rows / 2).saturating_sub(2);
    for _ in 0..top {
        s.push_str("\r\n");
    }
    let pad = |t: &str| " ".repeat((cols as usize).saturating_sub(t.chars().count()) / 2);
    s.push_str(&format!("\x1b[1;35m{}{title}\x1b[0m\r\n", pad(title)));
    s.push_str(&format!("\x1b[2m{}{sub}\x1b[0m\r\n\r\n", pad(&sub)));
    s.push_str(&format!("\x1b[36m{}{hint}\x1b[0m", pad(hint)));
    host::render(&s);
}

struct App;

impl Guest for App {
    fn init(cols: u32, rows: u32) {
        SIZE.with(|s| *s.borrow_mut() = (cols, rows));
        paint();
    }

    fn on_key(k: Key) -> bool {
        match k {
            Key::Text('q') | Key::Escape => return false, // close the pane
            _ => KEYS.with(|c| *c.borrow_mut() += 1),
        }
        paint();
        true
    }

    fn on_resize(cols: u32, rows: u32) {
        SIZE.with(|s| *s.borrow_mut() = (cols, rows));
        paint();
    }

    fn on_tick() -> bool {
        true // no time-based UI here; deck will use this for its focus countdown
    }
}

export!(App);
