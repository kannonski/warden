//! `app` — an interactive WASM-TUI plugin as a warden capability.
//!
//! This is the substrate for kedi plugins: a ratatui-style app compiled to a `kedi:app` WASM
//! component (see `wit/app.wit`) runs *inside a capability*, structurally identical to the `pty`
//! capability. Its rendered frames are the capability's `output()` stream (→ recorded, masked, sent
//! to the browser); `perform("key"/"resize")` drives the guest's `on-key`/`on-resize`. Because it's
//! a plain capability, an app pane reuses kedi's whole pty machinery (attach loop, output pump,
//! kill, record) with no kernel or runtime change — the "shell" is just a WASM app.
//!
//! wasmtime is driven SYNC on a dedicated worker thread (blocking OS I/O's right home), bridged to
//! the async world by channels — the same thread↔async pattern the pty reader uses. The guest's only
//! door to the world is the `host.invoke` import: it dispatches to the app's granted capabilities
//! (governed exactly like `warden:action`), so a plugin like deck reaches the task store only through
//! a `dstask` capability. An ungranted kind is refused — the sandbox stance.

use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::{self, UnboundedReceiver};
use warden_core::{
    Broker, CapKind, CapRequest, Capability, OpSpec, OutputStream, Result, WardenError,
};
use wasmtime::component::{Component, Linker};
use wasmtime::{Engine, Store};
use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxBuilder, WasiView};

// Generate host/guest bindings for the `kedi:app` world from wit/app.wit.
wasmtime::component::bindgen!({ world: "app", path: "../../wit/app" });

pub const APP: CapKind = CapKind("app");

const OPS: &[OpSpec] = &[
    OpSpec {
        op: "input",
        doc: "deliver a keystroke to the app (utf-8; alias of `key`, so a pane's attach loop is cap-agnostic)",
        mutates: true,
    },
    OpSpec {
        op: "key",
        doc: "deliver a keystroke to the app (utf-8 bytes; see the key mapping)",
        mutates: true,
    },
    OpSpec {
        op: "resize",
        doc: "resize the app to `COLSxROWS` and repaint",
        mutates: true,
    },
    OpSpec {
        op: "tick",
        doc: "deliver a periodic tick (for time-based UIs)",
        mutates: true,
    },
];

/// A message from `perform` to the wasm worker thread.
enum AppMsg {
    Key(String), // utf-8 of the keystroke (mapped to a `key` variant on the worker)
    Resize(u32, u32),
    Tick,
}

pub struct AppCap {
    tx: Mutex<Option<Sender<AppMsg>>>, // to the worker; dropped on revoke → worker exits
    output: Mutex<Option<UnboundedReceiver<Vec<u8>>>>, // rendered frames → the kernel's output pump
    exited: Arc<AtomicBool>,           // set when the guest quit (on-key/on-tick returned false)
}

/// wasmtime store data: WASI (the component's std needs it), the frame sender, and the app's granted
/// capabilities so `host.invoke` can reach the world through them (governed — each is a real warden
/// `Capability`, so its `perform` does the mediated op).
struct Host {
    wasi: WasiCtx,
    table: ResourceTable,
    frames: mpsc::UnboundedSender<Vec<u8>>,
    caps: Vec<Box<dyn Capability>>,
}

impl WasiView for Host {
    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi
    }
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }
}

// `types` only defines the `key` variant (no functions), but bindgen still wants the impl.
impl kedi::app::types::Host for Host {}

// The host side of the `kedi:app` `host` interface.
impl kedi::app::host::Host for Host {
    // the guest paints a frame → forward it to the capability's output stream (→ Event::Output)
    fn render(&mut self, frame: String) {
        let _ = self.frames.send(frame.into_bytes());
    }

    // the app's only door to the world: dispatch to the granted capability of this kind. Each is a
    // real warden `Capability`, so `perform` does the mediated op (e.g. dstask → the CLI). The
    // callback is sync (wasmtime is driven sync here), so we block on the async `perform` — same as
    // the component runtime's host invoke. An ungranted kind is refused, exactly like the sandbox
    // stance: a capability the app wasn't given simply doesn't exist for it.
    fn invoke(
        &mut self,
        cap: String,
        op: String,
        input: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, String> {
        let Some(c) = self.caps.iter().find(|c| c.kind().0 == cap) else {
            return Err(format!("capability `{cap}` not granted"));
        };
        futures::executor::block_on(c.perform(&op, &input)).map_err(|e| e.to_string())
    }
}

#[async_trait]
impl Capability for AppCap {
    fn kind(&self) -> CapKind {
        APP
    }
    fn ops(&self) -> &'static [OpSpec] {
        OPS
    }
    async fn perform(&self, op: &str, input: &[u8]) -> Result<Vec<u8>> {
        let send = |m: AppMsg| -> Result<Vec<u8>> {
            match self.tx.lock().unwrap().as_ref() {
                Some(tx) => {
                    let _ = tx.send(m);
                    Ok(Vec::new())
                }
                None => Err(WardenError::Cap("app has exited".into())),
            }
        };
        match op {
            // `input` is the pty's op name; accept it as an alias for `key` so a kedi pane's attach
            // loop drives a pty or an app identically (it just forwards `input` frames).
            "key" | "input" => {
                let s = std::str::from_utf8(input)
                    .map_err(|e| WardenError::Cap(format!("key utf8: {e}")))?;
                send(AppMsg::Key(s.to_string()))
            }
            "resize" => {
                let spec = std::str::from_utf8(input)
                    .map_err(|e| WardenError::Cap(format!("resize utf8: {e}")))?;
                let (cols, rows) = spec
                    .split_once('x')
                    .and_then(|(c, r)| Some((c.trim().parse().ok()?, r.trim().parse().ok()?)))
                    .ok_or_else(|| {
                        WardenError::Cap(format!("resize expects `COLSxROWS`, got `{spec}`"))
                    })?;
                send(AppMsg::Resize(cols, rows))
            }
            "tick" => send(AppMsg::Tick),
            other => Err(warden_core::no_such_op(APP, other)),
        }
    }
    fn revoke(&self) {
        // drop the sender → the worker's `for msg in rx` ends → it leaves and drops the store
        *self.tx.lock().unwrap() = None;
    }
    fn output(&self) -> Option<OutputStream> {
        self.output.lock().unwrap().take().map(|rx| {
            Box::pin(tokio_stream::wrappers::UnboundedReceiverStream::new(rx)) as OutputStream
        })
    }
    fn finished(&self) -> bool {
        self.exited.load(Ordering::SeqCst)
    }
}

impl AppCap {
    /// Load a `kedi:app` component at `path` and run it, granting it `caps` as its world (the app
    /// reaches each via `host.invoke(kind, op, input)`). This is how a host wires a plugin to real
    /// capabilities — e.g. kedi gives the deck plugin a `dstask` cap. `AppBroker` uses the no-caps
    /// form; a caps-aware host builds the `AppCap` directly.
    pub fn spawn(path: &str, caps: Vec<Box<dyn Capability>>) -> Result<AppCap> {
        let engine = Engine::default();
        let component = Component::from_file(&engine, path)
            .map_err(|e| WardenError::Cap(format!("load app {path}: {e}")))?;

        let (frames_tx, frames_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (msg_tx, msg_rx) = channel::<AppMsg>();
        let exited = Arc::new(AtomicBool::new(false));
        let exited_worker = exited.clone();

        // the wasm worker: sync wasmtime driving the component; keys in via msg_rx, frames out via
        // frames_tx, granted caps in the Host. Ends when the guest quits or the sender is dropped.
        std::thread::spawn(move || {
            let mut linker: Linker<Host> = Linker::new(&engine);
            if wasmtime_wasi::add_to_linker_sync(&mut linker).is_err() {
                return;
            }
            if App::add_to_linker(&mut linker, |h: &mut Host| h).is_err() {
                return;
            }
            let host = Host {
                wasi: WasiCtxBuilder::new().inherit_stderr().build(),
                table: ResourceTable::new(),
                frames: frames_tx,
                caps,
            };
            let mut store = Store::new(&engine, host);
            let Ok(bindings) = App::instantiate(&mut store, &component, &linker) else {
                return;
            };
            // start at a default size; the client's first `resize` re-paints at the true size
            let _ = bindings.call_init(&mut store, 80, 24);
            for msg in msg_rx {
                let keep = match msg {
                    AppMsg::Key(s) => bindings
                        .call_on_key(&mut store, str_to_key(&s))
                        .unwrap_or(false),
                    AppMsg::Resize(c, r) => {
                        let _ = bindings.call_on_resize(&mut store, c, r);
                        true
                    }
                    AppMsg::Tick => bindings.call_on_tick(&mut store).unwrap_or(true),
                };
                if !keep {
                    break;
                }
            }
            exited_worker.store(true, Ordering::SeqCst);
        });

        Ok(AppCap {
            tx: Mutex::new(Some(msg_tx)),
            output: Mutex::new(Some(frames_rx)),
            exited,
        })
    }
}

/// Grants an `app` capability with **no** sub-capabilities (the app can render + take keys, but
/// `host.invoke` finds nothing granted). The request `arg` is the path to a `kedi:app` `.wasm`
/// component. A host that wants to grant the app real capabilities builds [`AppCap::spawn`] directly.
pub struct AppBroker;

#[async_trait]
impl Broker for AppBroker {
    fn handles(&self, req: &CapRequest) -> bool {
        req.kind == APP
    }
    async fn grant(&self, req: &CapRequest) -> Result<Box<dyn Capability>> {
        Ok(Box::new(AppCap::spawn(&req.arg, Vec::new())?))
    }
}

/// Map a client keystroke (utf-8, as kedi already sends for the pty) to a `kedi:app` `key`. kedi
/// sends raw bytes for printable input and short escape sequences for special keys; the common ones
/// map here, the rest fall through to `Other`.
fn str_to_key(s: &str) -> Key {
    match s {
        "\r" | "\n" => Key::Enter,
        "\x7f" | "\x08" => Key::Backspace,
        "\t" => Key::Tab,
        "\x1b" => Key::Escape,
        "\x1b[A" => Key::Up,
        "\x1b[B" => Key::Down,
        "\x1b[C" => Key::Right,
        "\x1b[D" => Key::Left,
        _ => {
            let mut chars = s.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) => Key::Text(c), // exactly one char
                _ => Key::Other(0),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    // A mock "dstask"-kind capability returning a fixed two-task JSON — so the invoke path is tested
    // hermetically (no real dstask CLI). Proves: guest host.invoke → chokepoint → this cap → back.
    // Mutating ops (note-set, done, …) are recorded so tests can assert what the guest sent.
    #[derive(Clone, Default)]
    struct MockDsTask {
        calls: std::sync::Arc<std::sync::Mutex<Vec<(String, Vec<u8>)>>>,
    }
    #[async_trait]
    impl Capability for MockDsTask {
        fn kind(&self) -> CapKind {
            CapKind("dstask")
        }
        fn ops(&self) -> &'static [OpSpec] {
            &[
                OpSpec { op: "list", doc: "mock", mutates: false },
                OpSpec { op: "note-set", doc: "mock", mutates: true },
                OpSpec { op: "note", doc: "mock", mutates: true },
                OpSpec { op: "add", doc: "mock", mutates: true },
                OpSpec { op: "modify", doc: "mock", mutates: true },
                OpSpec { op: "done", doc: "mock", mutates: true },
                OpSpec { op: "start", doc: "mock", mutates: true },
                OpSpec { op: "stop", doc: "mock", mutates: true },
                OpSpec { op: "list-resolved", doc: "mock", mutates: false },
                OpSpec { op: "today", doc: "mock", mutates: false },
            ]
        }
        async fn perform(&self, op: &str, input: &[u8]) -> Result<Vec<u8>> {
            self.calls.lock().unwrap().push((op.to_string(), input.to_vec()));
            match op {
                // two pending tasks (bucket into NEXT / TODAY) with the fields deck reads
                "list" => Ok(br#"[
                  {"uuid":"a","id":1,"summary":"write the report","status":"pending","priority":"P2","tags":[],"project":"work","notes":"","resolved":"0001-01-01T00:00:00Z"},
                  {"uuid":"b","id":2,"summary":"call the plumber","status":"pending","priority":"P2","tags":["now"],"project":"home","notes":"","resolved":"0001-01-01T00:00:00Z"}
                ]"#.to_vec()),
                // resolved tasks (id 0, as dstask reports them): one stamped "today", one older. Only
                // the today one should land in DONE.
                "list-resolved" => Ok(br#"[
                  {"uuid":"c","id":0,"summary":"shipped it","status":"resolved","priority":"P2","tags":[],"project":"work","notes":"","resolved":"2026-07-06T09:00:00+02:00"},
                  {"uuid":"d","id":0,"summary":"ancient history","status":"resolved","priority":"P2","tags":[],"project":"work","notes":"","resolved":"2026-01-01T09:00:00+02:00"}
                ]"#.to_vec()),
                "today" => Ok(b"2026-07-06".to_vec()),
                _ => Ok(Vec::new()),
            }
        }
        fn revoke(&self) {}
    }

    // The deck plugin lives in its own repo (the Go deck's `guest-wasm/`), so the tests that exercise
    // the real plugin locate its built `.wasm`: `$DECK_WASM` if set, else the deck repo checked out
    // as a sibling of warden. Absent → the test skips (deck isn't required to build warden).
    fn deck_wasm() -> Option<String> {
        if let Ok(p) = std::env::var("DECK_WASM") {
            return std::path::Path::new(&p).exists().then_some(p);
        }
        let p = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../deck/guest-wasm/target/wasm32-wasip2/release/kedi_app_deck.wasm"
        );
        std::path::Path::new(p).exists().then(|| p.to_string())
    }

    // The real deck plugin: a ratatui kanban rendered to ANSI, reading tasks through the dstask
    // capability. Assert the board (column titles + a bucketed task) renders end to end.
    #[tokio::test]
    async fn deck_plugin_renders_a_ratatui_board() {
        let Some(path) = deck_wasm() else {
            eprintln!(
                "skip: build the deck wasm first (cd ../deck/guest-wasm && cargo build --release --target wasm32-wasip2), or set DECK_WASM"
            );
            return;
        };
        let cap = AppCap::spawn(&path, vec![Box::new(MockDsTask::default())]).expect("spawn deck");
        let mut frames = cap.output().expect("output");
        // resize to a real board size so ratatui has room to lay out the columns
        cap.perform("resize", b"120x40").await.expect("resize");

        // collect a couple of frames (init + resize repaint) and check the latest
        let mut latest = String::new();
        for _ in 0..2 {
            if let Ok(Some(f)) =
                tokio::time::timeout(std::time::Duration::from_millis(500), frames.next()).await
            {
                latest = String::from_utf8_lossy(&f).into_owned();
            }
        }
        // the ratatui board: all four column titles + the two mock tasks bucketed (one TODAY via
        // +now, one NEXT). Summaries are width-truncated in the narrow columns, so match a prefix.
        for want in ["TODAY", "NEXT", "WAITING", "DONE"] {
            assert!(
                latest.contains(want),
                "column {want} missing from board: {latest:?}"
            );
        }
        assert!(
            latest.contains("write the r"),
            "NEXT task (write the report) missing"
        );
        assert!(
            latest.contains("call the pl"),
            "TODAY task (call the plumber) missing"
        );
        // DONE = resolved-today only: "shipped it" (resolved 2026-07-06, matches the mock `today`) is
        // in; "ancient history" (resolved January) is filtered out. This is the reappearing-done fix.
        assert!(
            latest.contains("shipped it"),
            "DONE task resolved today (shipped it) missing"
        );
        assert!(
            !latest.contains("ancient history"),
            "DONE showed a task NOT resolved today (the reappearing-done bug): {latest:?}"
        );
    }

    // The note editor end to end: N opens the in-place editor on the cursor card, typed keys build a
    // multi-line buffer, Esc saves it via the `note-set` op. Assert the guest sent the full blob (with
    // the id on the first line and a newline from Enter) through the governed capability.
    #[tokio::test]
    async fn deck_note_editor_saves_via_note_set() {
        let Some(path) = deck_wasm() else {
            eprintln!("skip: build the deck wasm first (cd ../deck/guest-wasm && cargo build --release --target wasm32-wasip2), or set DECK_WASM");
            return;
        };
        let mock = MockDsTask::default();
        let calls = mock.calls.clone();
        let cap = AppCap::spawn(&path, vec![Box::new(mock)]).expect("spawn deck");
        let _frames = cap.output().expect("output");
        cap.perform("resize", b"120x40").await.expect("resize");

        // cursor starts on the first (TODAY) card. Open the note editor, type "hi", Enter, "there".
        for k in ["N", "h", "i", "\r", "t", "h", "e", "r", "e"] {
            cap.perform("key", k.as_bytes()).await.expect("key");
        }
        // Esc saves; give the worker a beat to run note-set + the reload's list.
        cap.perform("key", b"\x1b").await.expect("esc");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let recorded = calls.lock().unwrap().clone();
        let note_set = recorded
            .iter()
            .find(|(op, _)| op == "note-set")
            .unwrap_or_else(|| panic!("no note-set recorded; calls were: {:?}",
                recorded.iter().map(|(o, _)| o).collect::<Vec<_>>()));
        let payload = String::from_utf8_lossy(&note_set.1);
        // the TODAY card is id 2 ("call the plumber", +now); the blob is "<id>\nhi\nthere".
        assert_eq!(payload, "2\nhi\nthere", "note-set payload wrong: {payload:?}");
    }

    // Render deck at `WxH` and return the ANSI frame after the resize. Drains the init frame(s) first,
    // then resizes and takes the LAST frame that arrives (the resize repaint at the requested size).
    async fn deck_frame_at(path: &str, size: &str) -> String {
        let cap = AppCap::spawn(path, vec![Box::new(MockDsTask::default())]).expect("spawn deck");
        let mut frames = cap.output().expect("output");
        // drain the init frame(s)
        while tokio::time::timeout(std::time::Duration::from_millis(200), frames.next())
            .await
            .is_ok()
        {}
        cap.perform("resize", size.as_bytes()).await.expect("resize");
        // take the last frame that shows up after the resize
        let mut latest = String::new();
        while let Ok(Some(f)) =
            tokio::time::timeout(std::time::Duration::from_millis(300), frames.next()).await
        {
            latest = String::from_utf8_lossy(&f).into_owned();
        }
        latest
    }

    // Responsive: a narrow pane collapses to a single focused column (with a "N/M" position strip),
    // not four cramped ones. Assert only the focused column's title shows, plus the strip.
    #[tokio::test]
    async fn deck_narrow_shows_single_column() {
        let Some(path) = deck_wasm() else {
            eprintln!("skip: build the deck wasm first (cd ../deck/guest-wasm && cargo build --release --target wasm32-wasip2), or set DECK_WASM");
            return;
        };
        let wide = deck_frame_at(&path, "120x40").await;
        assert!(wide.contains("NEXT") && wide.contains("WAITING"), "wide should show all columns");

        let narrow = deck_frame_at(&path, "48x30").await;
        // cursor starts in column 0 (TODAY); the others are off-screen in single-column mode.
        assert!(narrow.contains("TODAY"), "narrow should show the focused column: {narrow:?}");
        assert!(narrow.contains("1/4"), "narrow should show the column position strip: {narrow:?}");
        assert!(!narrow.contains("WAITING"), "narrow should NOT show non-focused columns: {narrow:?}");
    }

    // Responsive: a short pane drops the detail pane so the board keeps its rows. Assert the board
    // (a column title) still renders and the "detail" pane title does not.
    #[tokio::test]
    async fn deck_short_drops_detail_pane() {
        let Some(path) = deck_wasm() else {
            eprintln!("skip: build the deck wasm first (cd ../deck/guest-wasm && cargo build --release --target wasm32-wasip2), or set DECK_WASM");
            return;
        };
        let tall = deck_frame_at(&path, "120x40").await;
        assert!(tall.contains("detail"), "tall should show the detail pane");

        let short = deck_frame_at(&path, "120x12").await;
        assert!(short.contains("TODAY"), "short should still show the board: {short:?}");
        assert!(!short.contains("detail"), "short should drop the detail pane: {short:?}");
    }
}
