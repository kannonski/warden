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

    // A mock "dstask"-kind capability returning a fixed two-task JSON — so the invoke path is tested
    // hermetically (no real dstask CLI). Proves: guest host.invoke → chokepoint → this cap → back.
    struct MockDsTask;
    #[async_trait]
    impl Capability for MockDsTask {
        fn kind(&self) -> CapKind {
            CapKind("dstask")
        }
        fn ops(&self) -> &'static [OpSpec] {
            &[OpSpec {
                op: "list",
                doc: "mock",
                mutates: false,
            }]
        }
        async fn perform(&self, op: &str, _input: &[u8]) -> Result<Vec<u8>> {
            assert_eq!(op, "list");
            Ok(br#"[{"uuid":"a","summary":"one"},{"uuid":"b","summary":"two"}]"#.to_vec())
        }
        fn revoke(&self) {}
    }

    #[tokio::test]
    async fn app_reaches_a_granted_capability_via_host_invoke() {
        let Some(path) = hello_wasm() else {
            eprintln!("skip: build guest-app first");
            return;
        };
        // grant the app a dstask capability; the guest calls host.invoke("dstask","list") on init
        let cap = AppCap::spawn(&path, vec![Box::new(MockDsTask)]).expect("spawn app with caps");
        let mut frames = cap.output().expect("output");
        let first = frames.next().await.expect("frame after init");
        let text = String::from_utf8_lossy(&first);
        // the guest counts "uuid" keys → 2 tasks, rendered via the governed capability
        assert!(
            text.contains("dstask: 2 tasks"),
            "app did not reach the dstask capability: {text:?}"
        );
    }
}
