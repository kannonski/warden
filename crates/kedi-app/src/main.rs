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
    next_win: AtomicU64,
    /// sid → the control-line sender feeding that pane's `run_pane`. Keyed by the backend-assigned sid
    /// (globally unique), so panes never collide across multiple windows.
    panes: Mutex<HashMap<u64, UnboundedSender<Vec<u8>>>>,
}

/// The hot-swappable UI directory: ~/Library/Application Support/dev.kedi.terminal/ui (macOS).
fn ui_dir(app: &tauri::AppHandle) -> PathBuf {
    app.path().app_data_dir().expect("app_data_dir").join("ui")
}

/// Seed / update the ui/ dir from baked-in defaults, versioned so shipped changes propagate past first
/// run WITHOUT clobbering the user's hot-swap edits. `.kedi-seed.json` records the hash of each default
/// we last wrote. Per file: missing → write; unchanged-by-user (on-disk == last-shipped) → overwrite
/// with the new default; user-edited AND default changed → keep theirs, drop `<file>.new` to diff.
/// Vendored assets (vendor/) are library code, always refreshed.
fn seed_ui(dir: &Path) {
    std::fs::create_dir_all(dir).ok();
    let seed_file = dir.join(".kedi-seed.json");
    let mut baseline: std::collections::BTreeMap<String, String> = std::fs::read(&seed_file)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    reconcile_ui(&DEFAULT_UI, dir, "", &mut baseline);
    if let Ok(bytes) = serde_json::to_vec_pretty(&baseline) {
        std::fs::write(&seed_file, bytes).ok();
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

fn reconcile_ui(
    src: &include_dir::Dir,
    root: &Path,
    prefix: &str,
    baseline: &mut std::collections::BTreeMap<String, String>,
) {
    for f in src.files() {
        let Some(name) = f.path().file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let rel = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        let target = root.join(&rel);
        let emb = f.contents();
        let emb_hash = sha256_hex(emb);
        let is_vendor = rel.starts_with("vendor/");
        match std::fs::read(&target) {
            Err(_) => {
                if let Some(p) = target.parent() {
                    std::fs::create_dir_all(p).ok();
                }
                std::fs::write(&target, emb).ok();
            }
            Ok(disk) => {
                let disk_hash = sha256_hex(&disk);
                let default_changed = baseline.get(&rel) != Some(&emb_hash);
                if disk_hash == emb_hash {
                    // already current
                } else if is_vendor {
                    // library asset: keep it exactly as shipped (don't let edits break xterm)
                    std::fs::write(&target, emb).ok();
                } else if !default_changed {
                    // the default is unchanged since last ship — the difference is the user's edit → keep it
                } else if baseline.get(&rel) == Some(&disk_hash) {
                    // default changed AND the user hadn't touched it → push the update
                    std::fs::write(&target, emb).ok();
                } else {
                    // default changed AND the user edited it → keep theirs, drop the new default to diff
                    let side = target.with_file_name(format!("{name}.new"));
                    std::fs::write(&side, emb).ok();
                }
            }
        }
        baseline.insert(rel, emb_hash);
    }
    for d in src.dirs() {
        let Some(name) = d.path().file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let rel = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        std::fs::create_dir_all(root.join(&rel)).ok();
        reconcile_ui(d, root, &rel, baseline);
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
        Some("ttf") => "font/ttf",
        _ => "application/octet-stream",
    }
}

// ── pane IPC: the transport that replaces the WebTransport bidi stream ────────────────────────────

/// Open a pane's transport: start a warden session driver and stream its output back over `on_output`
/// (base64-framed). This is setup only — the frontend then drives the pane with `pane_send` (hello,
/// optional app/attach/tab, input, resize, …), exactly as the browser wrote control lines to the
/// WebTransport stream. One Channel per pane.
#[tauri::command]
fn open_pane(
    app: tauri::AppHandle,
    state: State<AppState>,
    on_output: Channel<String>,
) -> Result<u64, String> {
    let (msg_tx, msg_rx) = unbounded_channel::<Vec<u8>>();
    let (out_tx, mut out_rx) = unbounded_channel::<Vec<u8>>();
    let handle = state.rt.handle().clone();

    // output pump: warden pane bytes → the webview channel, base64-framed (pty output is binary and
    // not always valid UTF-8; base64 is ~1.33x vs a ~3-6x JSON number array). Ends when out_tx drops.
    handle.spawn(async move {
        use base64::{Engine, engine::general_purpose::STANDARD};
        while let Some(bytes) = out_rx.recv().await {
            if on_output.send(STANDARD.encode(&bytes)).is_err() {
                break;
            }
        }
    });

    let sid = state.next_sid.fetch_add(1, Ordering::Relaxed);
    let warden = state.warden.clone();
    // "" → run_pane's pty broker spawns $SHELL; explicit fallback for GUI launches where $SHELL may
    // be unset. Ignored for a plugin pane (the frontend sends {"app":name} → an app cap, not a shell).
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/zsh".to_string());
    handle.spawn(async move {
        kedi::run_pane(warden, sid, shell, msg_rx, out_tx).await;
        // session ended (shell exit / kill / self-exit) → tell the frontend to close this pane
        let _ = app.emit("pane-exit", sid);
    });

    state.panes.lock().unwrap().insert(sid, msg_tx);
    Ok(sid)
}

/// Forward one newline-JSON control line to a pane's run_pane — the generic mirror of the browser's
/// `pane.send(obj)` over the WebTransport stream ({"hello"|"app"|"attach"|"tab"|"input"|"resize"|
/// "title"|"kill"|"close"|"pasteImage"}). A `{"close"}`/`{"kill"}` ends the session; drop the sender.
#[tauri::command]
fn pane_send(state: State<AppState>, sid: u64, line: String) {
    let ends = {
        let panes = state.panes.lock().unwrap();
        match panes.get(&sid) {
            Some(tx) => {
                let _ = tx.send(line.clone().into_bytes());
                line.contains("\"close\"") || line.contains("\"kill\"")
            }
            None => false,
        }
    };
    if ends {
        state.panes.lock().unwrap().remove(&sid);
    }
}

/// Open another kedi window — a full, independent canvas sharing the same in-process warden (so its
/// sessions appear in every window's palette/audit). Panes are keyed by backend sid, so no collision.
#[tauri::command]
fn new_window(app: tauri::AppHandle, state: State<AppState>) -> Result<(), String> {
    let n = state.next_win.fetch_add(1, Ordering::Relaxed);
    let label = format!("kedi-{n}");
    tauri::WebviewWindowBuilder::new(
        &app,
        &label,
        WebviewUrl::External("kedi://localhost/index.html".parse().unwrap()),
    )
    .title("kedi — governed terminal")
    .inner_size(960.0, 640.0)
    .build()
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// {clients, sessions} — the browser polled this to decide "am I the last tab?" before offering to
/// stop the server. A native window is a single client; report 1 + the live session count.
#[tauri::command]
fn clients_json(state: State<AppState>) -> String {
    format!(
        "{{\"clients\":1,\"sessions\":{}}}",
        state.warden.session_views().len()
    )
}

/// Stop kedi — the last-pane "stop" path. Closing the native window quits the app anyway; this lets
/// the UI's explicit stop affordance work too.
#[tauri::command]
fn shutdown(app: tauri::AppHandle) {
    app.exit(0);
}

/// Open a URL in the system browser. Uses the OS opener directly (`open` on macOS, `xdg-open` on
/// Linux) — dead simple and reliable, no plugin/permission/JS-global dependency.
#[tauri::command]
fn open_url(url: String) {
    // only http(s) — don't hand arbitrary schemes/args to the OS opener from terminal content.
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return;
    }
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("/usr/bin/open").arg(&url).spawn();
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
}

// ── audit / governance IPC (ports of the old HTTP routes; same JSON shapes) ───────────────────────

/// Live sessions, in the browser's `/sessions` shape ({warden, sessions:[SessionView]}) — the palette
/// + audit panel data source.
#[tauri::command]
fn sessions_json(state: State<AppState>) -> String {
    format!(
        "{{\"warden\":\"live\",\"sessions\":{}}}",
        kedi::sessions_json(&state.warden)
    )
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
        .plugin(tauri_plugin_clipboard_manager::init()) // copy/paste (navigator.clipboard is blocked on kedi://)
        .plugin(tauri_plugin_opener::init()) // open clicked links in the system browser
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
                next_win: AtomicU64::new(2), // window 1 is "main"; extras are kedi-2, kedi-3, …
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
            pane_send,
            new_window,
            clients_json,
            shutdown,
            open_url,
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
