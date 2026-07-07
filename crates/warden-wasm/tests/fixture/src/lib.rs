//! A minimal `kedi:app` fixture guest — warden's own proof of the WASM-TUI spine, with no dependency
//! on any real plugin. It:
//!   - renders a greeting frame on `init` (proves init → render),
//!   - calls `host.invoke("probe", "ping", …)` once and reports whether the cap answered (proves the
//!     governed host.invoke path: granted → reachable, ungranted → refused),
//!   - counts keystrokes and repaints on each (proves on-key → render),
//!   - quits on `q` (proves the app can end the pane).
//!
//! The WIT is warden's own `wit/app` (this fixture lives inside the warden repo).

wit_bindgen::generate!({ path: "../../../../wit/app", world: "app" });

use crate::kedi::app::host;
use std::cell::RefCell;

thread_local! {
    static STATE: RefCell<State> = const { RefCell::new(State { keys: 0, ticks: 0, probe: None }) };
}

struct State {
    keys: u32,
    ticks: u32,
    probe: Option<String>, // the probe cap's answer, or an error string
}

fn paint(s: &State) {
    let probe = match &s.probe {
        Some(ans) => format!("probe: {ans}"),
        None => "probe: (none)".to_string(),
    };
    // one plain frame — enough for the host tests to assert on
    host::render(&format!(
        "\x1b[2J\x1b[Hkedi:app fixture\r\nkeys: {}\r\nticks: {}\r\n{probe}\r\n",
        s.keys, s.ticks
    ));
}

struct Fixture;

impl Guest for Fixture {
    fn init(_cols: u32, _rows: u32) {
        // reach the granted "probe" capability once; record its answer (or the refusal error).
        let probe = match host::invoke("probe", "ping", b"") {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(e) => format!("err: {e}"),
        };
        STATE.with(|s| {
            let mut st = s.borrow_mut();
            st.probe = Some(probe);
            paint(&st);
        });
    }

    fn on_key(k: Key) -> bool {
        if matches!(k, Key::Text('q')) || matches!(k, Key::Escape) {
            return false; // quit
        }
        STATE.with(|s| {
            let mut st = s.borrow_mut();
            st.keys += 1;
            paint(&st);
        });
        true
    }

    fn on_resize(_cols: u32, _rows: u32) {
        STATE.with(|s| paint(&s.borrow()));
    }

    fn on_tick() -> bool {
        // count ticks + repaint, so a host test can prove the host is actually driving on_tick.
        STATE.with(|s| {
            let mut st = s.borrow_mut();
            st.ticks += 1;
            paint(&st);
        });
        true
    }
}

export!(Fixture);
