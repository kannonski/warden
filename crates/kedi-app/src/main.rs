// kedi-app — the native (Tauri) shell for the governed terminal. Replaces kedi's browser +
// WebTransport delivery with a native window and Tauri IPC. The warden backend is embedded in-process
// (no gateway, no QUIC): panes are driven by the SAME transport-agnostic `kedi::run_pane` the WT
// server uses — here its byte channels are bridged to Tauri IPC instead of a WebTransport stream.
//
// Hot-swap: the UI is not embedded in the running window — on first run we seed <app_data>/kedi/ui/
// from the baked-in default (include_dir), serve that dir fresh over a `kedi://` scheme, and reload
// the window when a file changes. Edit HTML/CSS/JS on disk → see it, no rebuild.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tauri::ipc::Channel;
use tauri::{Emitter, Manager, State, WebviewUrl, WebviewWindowBuilder};
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};

/// Baked-in default UI, copied out to the on-disk ui/ dir on first run (also the crate's frontendDist).
/// Once seeded, the on-disk copy wins and is hot-swappable.
static DEFAULT_UI: include_dir::Dir = include_dir::include_dir!("$CARGO_MANIFEST_DIR/ui");

/// In-process warden + the machinery to drive panes over IPC. One dedicated multi-thread tokio runtime
/// runs every pane's `run_pane` (and its internal spawns/timers), decoupled from Tauri's own runtime.
struct AppState {
    warden: Arc<warden_core::Warden>,
    rec: kedi::RecordControl,
    rt: tokio::runtime::Runtime,
    next_sid: AtomicU64,
    /// paneId → the control-line sender feeding that pane's `run_pane`.
    panes: Mutex<HashMap<u32, UnboundedSender<Vec<u8>>>>,
}

/// The hot-swappable UI directory: ~/Library/Application Support/com.unblu.kedi/ui (macOS).
fn ui_dir(app: &tauri::AppHandle) -> PathBuf {
    app.path().app_data_dir().expect("app_data_dir").join("ui")
}

/// Seed the ui/ dir from baked-in defaults, never overwriting — your edits stick. (Deleting the dir
/// re-seeds the current defaults; a future slice can version this to push updates.)
fn seed_ui(dir: &Path) {
    std::fs::create_dir_all(dir).ok();
    seed_dir(&DEFAULT_UI, dir);
}

fn seed_dir(src: &include_dir::Dir, dst: &Path) {
    for f in src.files() {
        if let Some(name) = f.path().file_name() {
            let target = dst.join(name);
            if !target.exists() {
                std::fs::write(&target, f.contents()).ok();
            }
        }
    }
    for d in src.dirs() {
        if let Some(name) = d.path().file_name() {
            let sub = dst.join(name);
            std::fs::create_dir_all(&sub).ok();
            seed_dir(d, &sub);
        }
    }
}

/// Minimal content-type by extension — enough for the UI asset set (html/css/js/wasm/png/svg).
fn mime_for(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("wasm") => "application/wasm",
        Some("png") => "image/png",
        Some("svg") => "image/svg+xml",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

// ── pane IPC: the transport that replaces the WebTransport bidi stream ────────────────────────────

/// Open a pane: start a warden session and stream its output back over `on_output`. `app = Some(name)`
/// opens a WASM plugin pane (a `kedi:app` component) instead of a shell — the same run_pane path, it
/// just sends `{"app":name}` before the hello. The frontend creates one Channel per pane.
#[tauri::command]
fn open_pane(
    state: State<AppState>,
    pane_id: u32,
    on_output: Channel<Vec<u8>>,
    app: Option<String>,
) -> Result<(), String> {
    let (msg_tx, msg_rx) = unbounded_channel::<Vec<u8>>();
    let (out_tx, mut out_rx) = unbounded_channel::<Vec<u8>>();
    let handle = state.rt.handle().clone();

    // output pump: warden pane bytes → the webview channel. Ends when run_pane drops `out_tx`.
    handle.spawn(async move {
        while let Some(bytes) = out_rx.recv().await {
            if on_output.send(bytes).is_err() {
                break;
            }
        }
    });

    let sid = state.next_sid.fetch_add(1, Ordering::Relaxed);
    let warden = state.warden.clone();
    // "" → run_pane's pty broker spawns $SHELL; pass an explicit fallback for GUI launches where
    // $SHELL may be unset. (Ignored for a plugin pane — an app cap doesn't run a shell.)
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/zsh".to_string());
    handle.spawn(async move {
        kedi::run_pane(warden, sid, shell, msg_rx, out_tx).await;
    });

    // introduce the pane: optional {"app":name} (plugin pane) then the hello that opens the session.
    if let Some(name) = app {
        let _ = msg_tx.send(serde_json::json!({ "app": name }).to_string().into_bytes());
    }
    let _ = msg_tx.send(br#"{"hello":"kedi-app"}"#.to_vec());
    state.panes.lock().unwrap().insert(pane_id, msg_tx);
    Ok(())
}

#[tauri::command]
fn pane_input(state: State<AppState>, pane_id: u32, data: String) {
    send_line(&state, pane_id, serde_json::json!({ "input": data }));
}

#[tauri::command]
fn pane_resize(state: State<AppState>, pane_id: u32, cols: u32, rows: u32) {
    send_line(&state, pane_id, serde_json::json!({ "resize": [cols, rows] }));
}

#[tauri::command]
fn pane_close(state: State<AppState>, pane_id: u32) {
    if let Some(tx) = state.panes.lock().unwrap().remove(&pane_id) {
        let _ = tx.send(br#"{"close":null}"#.to_vec());
    }
}

/// Send one newline-JSON control line to a pane's run_pane (the same wire the browser used).
fn send_line(state: &AppState, pane_id: u32, v: serde_json::Value) {
    if let Some(tx) = state.panes.lock().unwrap().get(&pane_id) {
        let _ = tx.send(v.to_string().into_bytes());
    }
}

// ── audit / governance IPC (ports of the old HTTP routes; same JSON shapes) ───────────────────────

/// Live session list (JSON array of SessionView) — the palette + audit panel data source.
#[tauri::command]
fn sessions_json(state: State<AppState>) -> String {
    kedi::sessions_json(&state.warden)
}

/// The verified record stream from index `since` on ({ok,count,since,events}) — audit timeline; poll
/// incrementally as the browser did with `/record?since=N`.
#[tauri::command]
fn record_json(state: State<AppState>, since: usize) -> String {
    kedi::record_json(&state.rec.path, since)
}

/// Recording toggle state / flip — governed ≠ surveilled, so it's opt-in and runtime-flippable.
#[tauri::command]
fn get_recording(state: State<AppState>) -> bool {
    state.rec.on.load(Ordering::Relaxed)
}

#[tauri::command]
fn set_recording(state: State<AppState>, on: bool) -> bool {
    state.rec.on.store(on, Ordering::Relaxed);
    on
}

/// Attributed kill from the console — records Event::Killed{by} and ends the session.
#[tauri::command]
fn kill_session(state: State<AppState>, session: u64, by: String) -> bool {
    state.warden.kill(warden_core::SessionId(session), &by)
}

/// Installed WASM-TUI plugins (name + icon), read fresh from plugins.toml each call.
#[tauri::command]
fn plugins_json() -> String {
    kedi::plugins_json()
}

/// Install a plugin: copy the .wasm into the plugin dir + register it (comment-preserving). Reuses the
/// same code path as `kedi plugin install`. The plugins-dir watcher then emits `plugins-changed`.
#[tauri::command]
fn install_plugin(
    path: String,
    name: Option<String>,
    icon: Option<String>,
    caps: Option<String>,
) -> Result<(), String> {
    let mut args = vec!["install".to_string(), path];
    if let Some(n) = name {
        args.push("--name".into());
        args.push(n);
    }
    if let Some(g) = icon {
        args.push("--icon".into());
        args.push(g);
    }
    if let Some(c) = caps {
        args.push("--caps".into());
        args.push(c);
    }
    kedi::plugin_cli::run(&args).map_err(|e| e.to_string())
}

/// Remove a plugin from the registry (and delete its .wasm with `purge`). Reuses `kedi plugin remove`.
#[tauri::command]
fn remove_plugin(name: String, purge: bool) -> Result<(), String> {
    let mut args = vec!["remove".to_string(), name];
    if purge {
        args.push("--purge".into());
    }
    kedi::plugin_cli::run(&args).map_err(|e| e.to_string())
}

/// Watch `dir` and run `on_change` on any content change — hot-swap plumbing. The watcher is owned by
/// its own thread (kept alive by the recv loop) and coalesces bursts so one save = one callback. Used
/// for both the ui/ dir (→ reload the window) and the plugins/ dir (→ emit `plugins-changed`).
fn spawn_watcher(dir: PathBuf, mut on_change: impl FnMut() + Send + 'static) {
    use notify::{RecursiveMode, Watcher};
    std::thread::spawn(move || {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = match notify::recommended_watcher(move |res| {
            let _ = tx.send(res);
        }) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("kedi-app: watcher on {} disabled: {e}", dir.display());
                return;
            }
        };
        if let Err(e) = watcher.watch(&dir, RecursiveMode::Recursive) {
            eprintln!("kedi-app: cannot watch {}: {e}", dir.display());
            return;
        }
        for first in rx.iter() {
            if !matches!(first, Ok(ref ev) if is_content_change(ev)) {
                continue;
            }
            // coalesce the rest of the burst (editors write several events per save)
            while rx.recv_timeout(std::time::Duration::from_millis(120)).is_ok() {}
            on_change();
        }
    });
}

fn is_content_change(ev: &notify::Event) -> bool {
    use notify::EventKind::*;
    matches!(ev.kind, Modify(_) | Create(_) | Remove(_))
}

fn main() {
    tauri::Builder::default()
        // Serve the hot-swappable ui/ dir. Read fresh + no-store so edits show on reload.
        .register_asynchronous_uri_scheme_protocol("kedi", |ctx, request, responder| {
            let base = ui_dir(ctx.app_handle());
            let rel = request.uri().path().trim_start_matches('/');
            let rel = if rel.is_empty() { "index.html" } else { rel };
            let full = base.join(rel);
            std::thread::spawn(move || {
                let resp = match std::fs::read(&full) {
                    Ok(data) => tauri::http::Response::builder()
                        .header(tauri::http::header::CONTENT_TYPE, mime_for(&full))
                        .header(tauri::http::header::CACHE_CONTROL, "no-store")
                        .body(data)
                        .unwrap(),
                    Err(_) => tauri::http::Response::builder()
                        .status(tauri::http::StatusCode::NOT_FOUND)
                        .header(tauri::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
                        .body(format!("kedi: not found: {}", full.display()).into_bytes())
                        .unwrap(),
                };
                responder.respond(resp);
            });
        })
        .setup(|app| {
            let dir = ui_dir(&app.handle());
            seed_ui(&dir);

            // The in-process warden (pty capability, recorder, policy) — same backend the WT kedi uses.
            let record_path = app
                .path()
                .app_data_dir()
                .expect("app_data_dir")
                .join("record.jsonl");
            std::fs::create_dir_all(record_path.parent().unwrap()).ok();
            let (warden, rec) =
                kedi::terminal_warden(&record_path.to_string_lossy(), false, Vec::new())
                    .expect("kedi-app: warden init failed");
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("kedi-app: tokio runtime");
            app.manage(AppState {
                warden: Arc::new(warden),
                rec,
                rt,
                next_sid: AtomicU64::new(1),
                panes: Mutex::new(HashMap::new()),
            });

            println!("kedi-app: serving hot-swappable UI from {}", dir.display());
            WebviewWindowBuilder::new(
                app,
                "main",
                WebviewUrl::External("kedi://localhost/index.html".parse().unwrap()),
            )
            .title("kedi — governed terminal")
            .inner_size(960.0, 640.0)
            .build()?;

            // hot-swap watchers: ui/ → reload the window; plugins/ → notify the frontend (live list).
            let ui_app = app.handle().clone();
            spawn_watcher(dir, move || {
                if let Some(w) = ui_app.get_webview_window("main") {
                    let _ = w.eval("location.reload()");
                }
            });
            let plugin_dir = kedi::plugin_dir();
            std::fs::create_dir_all(&plugin_dir).ok();
            let plug_app = app.handle().clone();
            spawn_watcher(plugin_dir, move || {
                let _ = plug_app.emit("plugins-changed", ());
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            open_pane,
            pane_input,
            pane_resize,
            pane_close,
            sessions_json,
            record_json,
            get_recording,
            set_recording,
            kill_session,
            plugins_json,
            install_plugin,
            remove_plugin
        ])
        .run(tauri::generate_context!())
        .expect("kedi-app: fatal error while running the Tauri application");
}
