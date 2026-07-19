// kedi-app — the native (Tauri) shell for the governed terminal. Replaces kedi's browser +
// WebTransport delivery with a native window and Tauri IPC. The warden backend is embedded in-process
// (no gateway, no QUIC): panes are driven by the SAME transport-agnostic `kedi::run_pane` the WT
// server uses — here its byte channels are bridged to Tauri IPC instead of a WebTransport stream.
//
// Hot-swap: the UI is not embedded in the running window — on first run we seed <app_data>/kedi/ui/
// from the baked-in default (include_dir), serve that dir fresh over a `kedi://` scheme, and reload
// the window when a file changes. Edit HTML/CSS/JS on disk → see it, no rebuild.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tauri::ipc::Channel;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::{Emitter, Manager, State, WebviewUrl, WebviewWindowBuilder};
use tokio::sync::Notify;
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
    /// window label → the sids opened by that window, so closing a window can drop its panes (else the
    /// senders linger, `run_pane` loops forever, and the sessions never close → leaked palette entries).
    win_panes: Mutex<HashMap<String, Vec<u64>>>,
    /// per-pane output flow control (backpressure): how many bytes we've sent the webview that it hasn't
    /// yet acked (rendered), + a waker. The output pump pauses when this exceeds the window, so a fast
    /// producer can't flood the webview into a freeze.
    flow: Mutex<HashMap<u64, Arc<PaneFlow>>>,
    /// Recall (command timeline) persistence. `hist_dir` is <app_data>/history; each logical session gets
    /// its own append-only `<launch_id>-<session>.jsonl`. `launch_id` (unix secs at boot) disambiguates
    /// sessions across restarts — the numeric session id resets to 1 each launch, so without it a fresh
    /// session would inherit a prior run's history.
    hist_dir: PathBuf,
    launch_id: u64,
}

struct PaneFlow {
    inflight: AtomicI64, // bytes sent to the webview but not yet acked
    notify: Notify,      // pane_ack wakes the paused pump
}

/// A window is gone: drop its panes' senders. Each `run_pane` then sees its client disconnect and, if it
/// still owned the session, closes it (a session teleported elsewhere is left running). Idempotent.
fn cleanup_window(state: &AppState, label: &str) {
    let sids = state
        .win_panes
        .lock()
        .unwrap()
        .remove(label)
        .unwrap_or_default();
    if sids.is_empty() {
        return;
    }
    let mut panes = state.panes.lock().unwrap();
    let mut flow = state.flow.lock().unwrap();
    for sid in sids {
        panes.remove(&sid); // dropping the sender ends run_pane's msg loop → disconnect → close if owner
        flow.remove(&sid);
    }
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

/// Shell integration (zsh): point ZDOTDIR at a kedi dir whose .zshenv/.zshrc SOURCE the user's real
/// config first, then add precmd/preexec hooks that emit OSC 133 (command marks A/C/D + exit code) and
/// OSC 7 (cwd). Set process-wide so every pane's pty inherits it. Opt out with KEDI_NO_SHELL_INTEGRATION=1.
/// Only touches zsh (bash/others ignore ZDOTDIR) and always falls back to the user's config, so a broken
/// hook can't lose their environment. `KEDI_UZDOTDIR` carries their original ZDOTDIR (or $HOME).
fn setup_shell_integration(app: &tauri::AppHandle) {
    let dir = app
        .path()
        .app_data_dir()
        .expect("app_data_dir")
        .join("shell");
    // opt out via env, or the persisted Settings toggle (a `.disabled` flag file in the shell dir)
    if std::env::var_os("KEDI_NO_SHELL_INTEGRATION").is_some() || dir.join(".disabled").exists() {
        return;
    }
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    // .zshenv runs for every zsh; source the user's first (PATH etc. live here for many setups).
    let zshenv = "[ -n \"$KEDI_UZDOTDIR\" ] && [ -f \"$KEDI_UZDOTDIR/.zshenv\" ] && \
                  source \"$KEDI_UZDOTDIR/.zshenv\"\n";
    // .zprofile runs for LOGIN shells (we launch login) BEFORE .zshrc, while ZDOTDIR is still ours —
    // source the user's so login-only PATH additions aren't lost. (.zlogin is read after .zshrc restores
    // ZDOTDIR to the user's dir, so zsh picks up their .zlogin directly — no shim needed for it.)
    let zprofile = "[ -n \"$KEDI_UZDOTDIR\" ] && [ -f \"$KEDI_UZDOTDIR/.zprofile\" ] && \
                    source \"$KEDI_UZDOTDIR/.zprofile\"\n";
    // .zshrc: restore ZDOTDIR, source the user's .zshrc, then install the integration hooks.
    let zshrc = r#"KEDI_UZDOTDIR="${KEDI_UZDOTDIR:-$HOME}"
ZDOTDIR="$KEDI_UZDOTDIR"
[ -f "$KEDI_UZDOTDIR/.zshrc" ] && source "$KEDI_UZDOTDIR/.zshrc"
# ── kedi shell integration (OSC 133 command marks + OSC 7 cwd) ──
__kedi_osc() { printf '\033]%s\007' "$1"; }
__kedi_precmd() { local e=$?; __kedi_osc "133;D;$e"; __kedi_osc "7;file://${HOST}${PWD}"; __kedi_osc "133;A"; }
# preexec: mark command start (C), then ship the command line itself (E), base64'd so any bytes
# survive the OSC transport (once per command — not the output hot path, so the subshell is cheap).
__kedi_preexec() { __kedi_osc "133;C"; __kedi_osc "133;E;$(printf '%s' "$1" | base64 | tr -d '\n')"; }
if autoload -Uz add-zsh-hook 2>/dev/null && whence add-zsh-hook >/dev/null 2>&1; then
  add-zsh-hook precmd __kedi_precmd
  add-zsh-hook preexec __kedi_preexec
fi
"#;
    if std::fs::write(dir.join(".zshenv"), zshenv).is_err()
        || std::fs::write(dir.join(".zprofile"), zprofile).is_err()
        || std::fs::write(dir.join(".zshrc"), zshrc).is_err()
    {
        return;
    }
    // remember the user's original ZDOTDIR so our scripts can source it, then redirect zsh to ours.
    let user_zdotdir = std::env::var("ZDOTDIR").unwrap_or_default();
    let user_zdotdir = if user_zdotdir.is_empty() {
        std::env::var("HOME").unwrap_or_default()
    } else {
        user_zdotdir
    };
    unsafe {
        std::env::set_var("KEDI_UZDOTDIR", user_zdotdir);
        std::env::set_var("ZDOTDIR", &dir);
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
    window: tauri::WebviewWindow,
    state: State<AppState>,
    on_output: Channel<String>,
) -> Result<u64, String> {
    let (msg_tx, msg_rx) = unbounded_channel::<Vec<u8>>();
    let (out_tx, mut out_rx) = unbounded_channel::<Vec<u8>>();
    let handle = state.rt.handle().clone();

    let sid = state.next_sid.fetch_add(1, Ordering::Relaxed);
    let flow = Arc::new(PaneFlow {
        inflight: AtomicI64::new(0),
        notify: Notify::new(),
    });
    state.flow.lock().unwrap().insert(sid, flow.clone());

    // Output pump with backpressure. Each frame is base64 (kept ~8KB so it takes Tauri's fast direct-
    // eval Channel path). We never run more than WINDOW bytes ahead of what the webview has acked
    // (rendered) — that's what stops a fast producer (`cat`, `yes`) from flooding the webview into a
    // freeze. Output is buffered locally, capped at BACKLOG_MAX; a runaway infinite flood drops OLDEST
    // to stay alive (can't push backpressure to the shell through the sync governed sink — see notes).
    handle.spawn(async move {
        use base64::{Engine, engine::general_purpose::STANDARD};
        const WINDOW: i64 = 1 << 20; // 1 MB the webview may be behind before we pause
        const BACKLOG_MAX: usize = 8 << 20; // 8 MB local cap; beyond it, drop oldest (unsustainable flood)
        let mut backlog: VecDeque<u8> = VecDeque::new();
        loop {
            if backlog.is_empty() {
                match out_rx.recv().await {
                    Some(b) => backlog.extend(b),
                    None => break, // pane gone
                }
            }
            while let Ok(b) = out_rx.try_recv() {
                backlog.extend(b);
            }
            if backlog.len() > BACKLOG_MAX {
                backlog.drain(..backlog.len() - BACKLOG_MAX); // drop oldest to stay bounded
            }
            // send while the webview has room in the window
            while !backlog.is_empty() && flow.inflight.load(Ordering::Relaxed) < WINDOW {
                let take = backlog.len().min(6000);
                let chunk: Vec<u8> = backlog.drain(..take).collect();
                flow.inflight
                    .fetch_add(chunk.len() as i64, Ordering::Relaxed);
                if on_output.send(STANDARD.encode(&chunk)).is_err() {
                    return;
                }
            }
            // webview is behind → wait for an ack (or more output) before looping
            if flow.inflight.load(Ordering::Relaxed) >= WINDOW {
                tokio::select! {
                    _ = flow.notify.notified() => {}
                    b = out_rx.recv() => match b { Some(x) => backlog.extend(x), None => break },
                }
            }
        }
    });

    let warden = state.warden.clone();
    // Empty command → the pty broker launches $SHELL directly as a LOGIN shell (see pty.rs). Launching
    // as login is what makes a Dock/launcher-started terminal inherit the user's real PATH/env (brew,
    // mise, …) — GUI processes otherwise get a minimal environment. (Plugin panes send {"app"} instead.)
    handle.spawn(async move {
        kedi::run_pane(warden, sid, String::new(), msg_rx, out_tx).await;
        // session ended (shell exit / kill / self-exit) → tell the frontend to close this pane
        let _ = app.emit("pane-exit", sid);
    });

    state.panes.lock().unwrap().insert(sid, msg_tx);
    state
        .win_panes
        .lock()
        .unwrap()
        .entry(window.label().to_string())
        .or_default()
        .push(sid);
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
        state.flow.lock().unwrap().remove(&sid);
    }
}

/// Keystroke fast-path: a dedicated input command so the hot path (every keypress) skips building a
/// JS object + `JSON.stringify` on the frontend. We frame the `{"input":…}` control line here in Rust
/// (cheap) and hand it straight to the pane's run_pane. Same effect as `pane_send({input})`.
#[tauri::command]
fn pane_input(state: State<AppState>, sid: u64, data: String) {
    if let Some(tx) = state.panes.lock().unwrap().get(&sid) {
        let payload = serde_json::to_string(&data).unwrap_or_else(|_| "\"\"".into());
        let _ = tx.send(format!("{{\"input\":{payload}}}\n").into_bytes());
    }
}

/// Output flow control: the webview acks bytes it has rendered so the pump can send more. Keeps the
/// backend from running more than a window ahead of the display (the anti-freeze backpressure).
#[tauri::command]
fn pane_ack(state: State<AppState>, sid: u64, bytes: u32) {
    if let Some(flow) = state.flow.lock().unwrap().get(&sid) {
        flow.inflight.fetch_sub(bytes as i64, Ordering::Relaxed);
        flow.notify.notify_one();
    }
}

/// Open another kedi window — a full, independent canvas sharing the same in-process warden (so its
/// sessions appear in every window's palette/audit). Panes are keyed by backend sid, so no collision.
/// `query` is appended to the URL (e.g. `?attach=5&solo=1` to pop a session out into its own window).
fn open_window_url(app: &tauri::AppHandle, query: &str) -> Result<(), String> {
    let state = app.state::<AppState>();
    let n = state.next_win.fetch_add(1, Ordering::Relaxed);
    let label = format!("kedi-{n}");
    let url = format!("kedi://localhost/index.html{query}");
    let win = WebviewWindowBuilder::new(app, &label, WebviewUrl::External(url.parse().unwrap()))
        .title("kedi — governed terminal")
        .inner_size(960.0, 640.0)
        .build()
        .map_err(|e| e.to_string())?;
    watch_window_close(&win);
    Ok(())
}

/// When a window is destroyed, drop the panes it opened so their sessions don't leak (otherwise the
/// senders live on, `run_pane` never sees a disconnect, and stale sessions pile up in the palette).
fn watch_window_close(win: &tauri::WebviewWindow) {
    let app = win.app_handle().clone();
    let label = win.label().to_string();
    win.on_window_event(move |event| {
        if matches!(event, tauri::WindowEvent::Destroyed)
            && let Some(state) = app.try_state::<AppState>()
        {
            cleanup_window(&state, &label);
        }
    });
}

/// Shared by the `new_window` command and the native File ▸ New Window menu item.
fn open_new_window(app: &tauri::AppHandle) -> Result<(), String> {
    open_window_url(app, "")
}

#[tauri::command]
fn new_window(app: tauri::AppHandle) -> Result<(), String> {
    open_new_window(&app)
}

/// Pop a running session out into its own native OS window: open a new window that re-attaches to
/// session `sid` (a teleport — the warden hands ownership to the new viewer; the old window drops its
/// view without closing). The new window then gets native tabbing / Stage Manager for free.
#[tauri::command]
fn pop_out(app: tauri::AppHandle, sid: u64) -> Result<(), String> {
    open_window_url(&app, &format!("?attach={sid}&solo=1"))
}

/// The native application menu bar (macOS gets a real top menu; win/linux get a window menu). Custom
/// items carry an id we dispatch in `on_menu_event`; the ⌘ accelerators are handled natively by the
/// OS *before* the webview sees them, so they don't collide with the browser-reserved combos that
/// forced the in-app Ctrl+Shift shortcuts. New Window is handled in-process; the rest are emitted to
/// the focused window as a `menu` event the frontend acts on.
fn build_menu(app: &tauri::AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let app_menu = Submenu::with_items(
        app,
        "kedi",
        true,
        &[
            &PredefinedMenuItem::about(app, None, None)?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, "settings", "Settings…", true, Some("CmdOrCtrl+Comma"))?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::hide(app, None)?,
            &PredefinedMenuItem::hide_others(app, None)?,
            &PredefinedMenuItem::show_all(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::quit(app, None)?,
        ],
    )?;
    let file_menu = Submenu::with_items(
        app,
        "File",
        true,
        &[
            &MenuItem::with_id(
                app,
                "new_terminal",
                "New Terminal",
                true,
                Some("CmdOrCtrl+T"),
            )?,
            &MenuItem::with_id(app, "new_window", "New Window", true, Some("CmdOrCtrl+N"))?,
            &MenuItem::with_id(
                app,
                "pop_out_pane",
                "Pop Out Terminal",
                true,
                Some("CmdOrCtrl+Shift+O"),
            )?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(
                app,
                "close_pane",
                "Close Terminal",
                true,
                Some("CmdOrCtrl+W"),
            )?,
        ],
    )?;
    let view_menu = Submenu::with_items(
        app,
        "View",
        true,
        &[
            &MenuItem::with_id(
                app,
                "palette",
                "Command Palette…",
                true,
                Some("CmdOrCtrl+K"),
            )?,
            &MenuItem::with_id(app, "find", "Find…", true, Some("CmdOrCtrl+F"))?,
            &MenuItem::with_id(app, "recall", "Recall Commands…", true, Some("CmdOrCtrl+R"))?,
        ],
    )?;
    let window_menu = Submenu::with_items(
        app,
        "Window",
        true,
        &[
            &PredefinedMenuItem::minimize(app, None)?,
            &PredefinedMenuItem::maximize(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::close_window(app, Some("Close Window"))?,
        ],
    )?;
    Menu::with_items(app, &[&app_menu, &file_menu, &view_menu, &window_menu])
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
    let _ = std::process::Command::new("/usr/bin/open")
        .arg(&url)
        .spawn();
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("cmd")
        .args(["/C", "start", "", &url])
        .spawn();
}

/// Open a file path (optionally at a line) from a ⌘-clicked link in the terminal. Runs through the
/// user's LOGIN shell so PATH resolves their editor (`code`, `$VISUAL`/`$EDITOR`), falling back to the
/// OS opener. Path & line are passed as positional args (never interpolated) — no shell injection.
#[tauri::command]
fn open_path(path: String, line: u32) {
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "sh".to_string());
    let script = r#"f="$1"; l="$2"; [ "$l" = "0" ] && l=""
if command -v code >/dev/null 2>&1; then
  [ -n "$l" ] && code -g "$f:$l" || code -g "$f"
elif [ -n "${VISUAL}${EDITOR}" ]; then
  ed="${VISUAL:-$EDITOR}"; [ -n "$l" ] && "$ed" "+$l" "$f" || "$ed" "$f"
elif [ "$(uname)" = "Darwin" ]; then open "$f"
else xdg-open "$f"; fi"#;
    let _ = std::process::Command::new(shell)
        .args(["-lc", script, "kedi", &path, &line.to_string()])
        .spawn();
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

// ── Recall persistence: a per-session command timeline on disk (survives pop-out + restart) ──────────
const HIST_KEEP: usize = 50; // commands retained per session
const HIST_SESSIONS_KEEP: usize = 30; // session files retained (newest by mtime)

/// This launch's on-disk file for one logical session (`<app_data>/history/<launch>-<session>.jsonl`).
fn session_file(state: &AppState, session: u64) -> PathBuf {
    state
        .hist_dir
        .join(format!("{}-{}.jsonl", state.launch_id, session))
}

/// Keep only the newest HIST_SESSIONS_KEEP `*.jsonl` files (by mtime); delete the rest. Bounds disk use.
fn prune_sessions(dir: &Path) {
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .flatten()
            .filter_map(|e| {
                let p = e.path();
                if p.extension().map(|x| x == "jsonl").unwrap_or(false) {
                    let m = e.metadata().ok()?.modified().ok()?;
                    Some((m, p))
                } else {
                    None
                }
            })
            .collect(),
        Err(_) => return,
    };
    if files.len() <= HIST_SESSIONS_KEEP {
        return;
    }
    files.sort_by_key(|(m, _)| *m); // oldest first
    for (_, p) in files.iter().take(files.len() - HIST_SESSIONS_KEEP) {
        let _ = std::fs::remove_file(p);
    }
}

/// Append one finished command (a JSON-serialized entry, already a single line) to its session's file.
/// The frontend built the entry from OSC 133 marks (clean, xterm-rendered output — no ANSI). Compacts
/// to the last HIST_KEEP once the file drifts past a slack threshold, so appends stay cheap.
#[tauri::command]
fn history_push(state: State<AppState>, session: u64, entry: String) {
    use std::io::Write;
    let path = session_file(&state, session);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "{entry}");
    }
    if let Ok(data) = std::fs::read_to_string(&path) {
        let lines: Vec<&str> = data.lines().filter(|l| !l.is_empty()).collect();
        if lines.len() > HIST_KEEP + 10 {
            let kept = lines[lines.len() - HIST_KEEP..].join("\n");
            let _ = std::fs::write(&path, kept + "\n");
        }
    }
    prune_sessions(&state.hist_dir);
}

/// This launch's persisted entries for one session (oldest→newest) — reloaded when a window opens or a
/// popped-out session re-attaches, so its output stays copyable even though the live buffer is gone.
#[tauri::command]
fn history_load(state: State<AppState>, session: u64) -> Vec<String> {
    std::fs::read_to_string(session_file(&state, session))
        .map(|d| {
            d.lines()
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Every persisted entry across all sessions (this launch and prior ones still on disk) — the "earlier"
/// scope in Recall. The frontend sorts by timestamp and caps; here we just bound by the retained files.
#[tauri::command]
fn history_recent(state: State<AppState>) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&state.hist_dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().map(|x| x == "jsonl").unwrap_or(false)
                && let Ok(d) = std::fs::read_to_string(&p)
            {
                out.extend(d.lines().filter(|l| !l.is_empty()).map(String::from));
            }
        }
    }
    out
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

/// Whether shell integration is currently enabled (env not set + no `.disabled` flag). Read at boot to
/// sync the Settings toggle.
#[tauri::command]
fn shell_integration_state(app: tauri::AppHandle) -> bool {
    if std::env::var_os("KEDI_NO_SHELL_INTEGRATION").is_some() {
        return false;
    }
    let dir = app
        .path()
        .app_data_dir()
        .map(|p| p.join("shell"))
        .unwrap_or_default();
    !dir.join(".disabled").exists()
}

/// Persist the shell-integration preference (takes effect on next launch — injection happens at startup).
#[tauri::command]
fn set_shell_integration(app: tauri::AppHandle, enabled: bool) -> Result<(), String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join("shell");
    std::fs::create_dir_all(&dir).ok();
    let flag = dir.join(".disabled");
    if enabled {
        let _ = std::fs::remove_file(&flag);
    } else {
        std::fs::write(&flag, b"disabled by Settings\n").map_err(|e| e.to_string())?;
    }
    Ok(())
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
            while rx
                .recv_timeout(std::time::Duration::from_millis(120))
                .is_ok()
            {}
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
        .plugin(tauri_plugin_notification::init()) // "command finished" notifications
        .menu(build_menu) // native menu bar: ⌘T/⌘N/⌘W/⌘K/⌘F/⌘, handled by the OS
        .on_menu_event(|app, event| match event.id().as_ref() {
            "new_window" => {
                let _ = open_new_window(app);
            }
            // dispatched to the focused window; the frontend guards on document.hasFocus()
            id @ ("settings" | "new_terminal" | "close_pane" | "find" | "palette" | "recall"
            | "pop_out_pane") => {
                let _ = app.emit("menu", id);
            }
            _ => {}
        })
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
                        .header(
                            tauri::http::header::CONTENT_TYPE,
                            "text/plain; charset=utf-8",
                        )
                        .body(format!("kedi: not found: {}", full.display()).into_bytes())
                        .unwrap(),
                };
                responder.respond(resp);
            });
        })
        .setup(|app| {
            let dir = ui_dir(app.handle());
            seed_ui(&dir);
            setup_shell_integration(app.handle()); // zsh: emit OSC 133 (command marks) + OSC 7 (cwd)

            // The in-process warden (pty capability, recorder, policy) — same backend the WT kedi uses.
            let record_path = app
                .path()
                .app_data_dir()
                .expect("app_data_dir")
                .join("record.jsonl");
            std::fs::create_dir_all(record_path.parent().unwrap()).ok();
            // Recall history store: <app_data>/history, stamped with this launch's epoch.
            let hist_dir = record_path.parent().unwrap().join("history");
            std::fs::create_dir_all(&hist_dir).ok();
            let launch_id = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
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
                win_panes: Mutex::new(HashMap::new()),
                flow: Mutex::new(HashMap::new()),
                hist_dir,
                launch_id,
            });

            println!("kedi-app: serving hot-swappable UI from {}", dir.display());
            let main = WebviewWindowBuilder::new(
                app,
                "main",
                WebviewUrl::External("kedi://localhost/index.html".parse().unwrap()),
            )
            .title("kedi — governed terminal")
            .inner_size(960.0, 640.0)
            .build()?;
            watch_window_close(&main); // drop this window's panes when it closes → its sessions close

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
            pane_input,
            pane_ack,
            new_window,
            pop_out,
            open_path,
            clients_json,
            shutdown,
            open_url,
            sessions_json,
            record_json,
            get_recording,
            set_recording,
            kill_session,
            history_push,
            history_load,
            history_recent,
            plugins_json,
            install_plugin,
            remove_plugin,
            shell_integration_state,
            set_shell_integration
        ])
        .run(tauri::generate_context!())
        .expect("kedi-app: fatal error while running the Tauri application");
}
