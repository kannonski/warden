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
//! door to the world is the `host.invoke` import, which crosses the warden chokepoint via a callback
//! the host wires in (governed exactly like `warden:action`); step 1 wires a deny-all stub so the
//! spine is provable before real capabilities are threaded through.

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

/// wasmtime store data: WASI (the component's std needs it) + the frame sender + a quit flag so the
/// `host.render`/`host.invoke` callbacks can reach the outside world.
struct Host {
    wasi: WasiCtx,
    table: ResourceTable,
    frames: mpsc::UnboundedSender<Vec<u8>>,
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

    // the app's only door to the world. Step 1: deny everything (no capabilities threaded yet) so the
    // spine is provable in isolation; a later step wires this to `ctx.invoke` (the governed chokepoint).
    fn invoke(
        &mut self,
        cap: String,
        op: String,
        _input: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, String> {
        Err(format!(
            "capability `{cap}` op `{op}` not granted (app capability wiring is a later step)"
        ))
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
            "key" => {
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

/// Grants an `app` capability. The request `arg` is the path to a `kedi:app` `.wasm` component (a
/// later step resolves a plugin *name* → its installed path, like chatons' home).
pub struct AppBroker;

#[async_trait]
impl Broker for AppBroker {
    fn handles(&self, req: &CapRequest) -> bool {
        req.kind == APP
    }
    async fn grant(&self, req: &CapRequest) -> Result<Box<dyn Capability>> {
        let path = req.arg.clone();
        let engine = Engine::default();
        let component = Component::from_file(&engine, &path)
            .map_err(|e| WardenError::Cap(format!("load app {path}: {e}")))?;

        let (frames_tx, frames_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (msg_tx, msg_rx) = channel::<AppMsg>();
        let exited = Arc::new(AtomicBool::new(false));
        let exited_worker = exited.clone();

        // the wasm worker: sync wasmtime driving the component; keys in via msg_rx, frames out via
        // frames_tx (captured in the Host). Ends when the guest quits or the sender is dropped.
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

        Ok(Box::new(AppCap {
            tx: Mutex::new(Some(msg_tx)),
            output: Mutex::new(Some(frames_rx)),
            exited,
        }))
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

    // The hello guest component, built from ../../guest-app. Skips gracefully if it isn't built yet
    // (so `cargo test` never hard-fails on a missing wasm artifact).
    fn hello_wasm() -> Option<String> {
        let p = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../guest-app/target/wasm32-wasip2/release/kedi_app_hello.wasm"
        );
        std::path::Path::new(p).exists().then(|| p.to_string())
    }

    #[tokio::test]
    async fn app_capability_runs_a_wasm_tui_end_to_end() {
        let Some(path) = hello_wasm() else {
            eprintln!("skip: build guest-app first (cargo build --release --target wasm32-wasip2)");
            return;
        };
        // grant the app capability on the hello component
        let cap = AppBroker
            .grant(&CapRequest {
                kind: APP,
                arg: path,
            })
            .await
            .expect("grant app");
        let mut frames = cap.output().expect("app has an output stream");

        // init paints a first frame; assert the greeting reaches us as a governed frame
        let first = frames.next().await.expect("a frame after init");
        let text = String::from_utf8_lossy(&first);
        assert!(
            text.contains("hello from a kedi WASM app"),
            "unexpected frame: {text:?}"
        );

        // drive it: a key repaints (keys: 1), then `q` quits → finished()
        cap.perform("key", b"x").await.expect("key");
        let after_key = frames.next().await.expect("a frame after a key");
        assert!(
            String::from_utf8_lossy(&after_key).contains("keys: 1"),
            "key count not shown"
        );

        cap.perform("key", b"q").await.expect("q");
        // give the worker a moment to process the quit
        for _ in 0..50 {
            if cap.finished() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(cap.finished(), "app should have quit on `q`");
    }
}
