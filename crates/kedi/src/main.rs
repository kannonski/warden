//! kedi — governed web terminal. Serves the xterm.js page over HTTP (localhost = a secure context,
//! so the browser's WebTransport is allowed) and the terminal I/O over WebTransport (QUIC/HTTP3).

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

const INDEX_HTML: &str = include_str!("index.html");
const RAW_HTML: &str = include_str!("raw.html");

// PWA assets — installing kedi (Chrome ▸ "Install page as app…") builds a real, chromeless macOS app
// with its own Dock/Launchpad icon (the cat), instead of a Chrome-branded --app window. The manifest
// points at these PNGs; the icons + a trivial service worker are what make the page installable.
const ICON_192: &[u8] = include_bytes!("icon-192.png");
const ICON_512: &[u8] = include_bytes!("icon-512.png");
const MANIFEST: &str = r##"{"name":"kedi — governed terminal","short_name":"kedi","description":"Your shell in the browser — recorded, replayable, killable.","start_url":"/","scope":"/","display":"standalone","background_color":"#1e1e2e","theme_color":"#1e1e2e","icons":[{"src":"/icon-192.png","sizes":"192x192","type":"image/png","purpose":"any maskable"},{"src":"/icon-512.png","sizes":"512x512","type":"image/png","purpose":"any maskable"}]}"##;
// Minimal pass-through service worker: its mere presence (with a fetch handler) satisfies Chrome's
// installability check. It does not cache — kedi is a live localhost app, offline caching is pointless.
const SERVICE_WORKER: &str = "self.addEventListener('fetch', () => {});\n";

/// macOS launchd socket activation. When kedi is started **on-demand** by its LaunchAgent, launchd
/// has already bound + is listening on the http port and hands us the socket(s) here; we serve on
/// them and skip binding the port ourselves (the WT/QUIC port we still bind directly). Started
/// manually (no launchd), `launch_activate_socket` returns non-zero (ESRCH) → `None` → bind normally.
/// This is what lets the *installed PWA* "launch everything": opening it connects to :8788, launchd
/// wakes kedi, and kedi's existing 90s idle-exit stops it again — nothing runs while unused.
#[cfg(target_os = "macos")]
fn launchd_sockets(name: &str) -> Option<Vec<TcpListener>> {
    use std::os::unix::io::FromRawFd;
    // From <launch.h>; resolved from libSystem, so no extra link directive is needed.
    unsafe extern "C" {
        fn launch_activate_socket(
            name: *const std::os::raw::c_char,
            fds: *mut *mut std::os::raw::c_int,
            count: *mut usize,
        ) -> std::os::raw::c_int;
    }
    let cname = std::ffi::CString::new(name).ok()?;
    let mut fds: *mut std::os::raw::c_int = std::ptr::null_mut();
    let mut count: usize = 0;
    let rc = unsafe { launch_activate_socket(cname.as_ptr(), &mut fds, &mut count) };
    if rc != 0 || fds.is_null() || count == 0 {
        return None; // not managed by launchd (or no such socket) → caller binds the port itself
    }
    // SAFETY: launchd returns a malloc'd array of `count` valid, already-listening socket fds; we own
    // them (turn each into a TcpListener) and free the array launchd allocated.
    let listeners = unsafe {
        let v: Vec<TcpListener> = std::slice::from_raw_parts(fds, count)
            .iter()
            .map(|&fd| TcpListener::from_raw_fd(fd))
            .collect();
        libc::free(fds as *mut libc::c_void);
        v
    };
    Some(listeners)
}

#[cfg(not(target_os = "macos"))]
fn launchd_sockets(_name: &str) -> Option<Vec<TcpListener>> {
    None
}

/// Serve the console page over plain HTTP on every given address — the cert hash + WebTransport URL
/// are injected so the browser can accept kedi's self-signed cert via `serverCertificateHashes`.
struct Pages {
    index: String,
    raw: String,         // /raw — a minimal single-terminal diagnostic page
    record_path: String, // /record — the audit log (always present; toggle governs writes)
    rec: Arc<std::sync::atomic::AtomicBool>, // /rec — the recording switch (flip from the UI)
    warden: Arc<warden_core::Warden>, // /sessions + /kill — the warden's live state
    clients: Arc<std::sync::atomic::AtomicUsize>, // /clients — live WT connection (tab) count
    // /shutdown — stop the whole server: `notify` wakes the main task (which closes sessions +
    // exits); the AtomicBool makes the route idempotent under a two-tabs-both-hit-stop race.
    shutdown: Arc<tokio::sync::Notify>,
    shutdown_started: Arc<std::sync::atomic::AtomicBool>,
}

#[allow(clippy::too_many_arguments)] // a startup wiring fn; grouping into a struct buys nothing here
fn serve_page(
    http_listeners: Vec<TcpListener>,
    wt_url: String,
    cert_hash: [u8; 32],
    rec_ctl: kedi::RecordControl,
    font_size: u8,
    warden_name: &str,
    warden: Arc<warden_core::Warden>,
    clients: Arc<std::sync::atomic::AtomicUsize>,
    shutdown: Arc<tokio::sync::Notify>,
    shutdown_started: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<()> {
    let hash_js = cert_hash
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let rec0 = if rec_ctl.on.load(std::sync::atomic::Ordering::Relaxed) {
        "1"
    } else {
        "0"
    };
    // the name is injected into a JS string literal — keep it to a safe charset so an odd hostname
    // can't break (or inject into) the page
    let name_safe: String = warden_name
        .chars()
        .filter(|c| c.is_alphanumeric() || "-._@ ".contains(*c))
        .take(40)
        .collect();
    let inject = |tpl: &str| {
        tpl.replace("__WT_URL__", &wt_url)
            .replace("__CERT_HASH__", &hash_js)
            .replace("__REC__", rec0)
            .replace("__WARDEN__", &name_safe)
            .replace("__FONT_SIZE__", &font_size.to_string())
    };
    let pages = Arc::new(Pages {
        index: inject(INDEX_HTML),
        raw: inject(RAW_HTML),
        record_path: rec_ctl.path.clone(),
        rec: rec_ctl.on.clone(),
        warden,
        clients,
        shutdown,
        shutdown_started,
    });
    for listener in http_listeners {
        let pages = pages.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let pages = pages.clone();
                std::thread::spawn(move || serve_one(stream, &pages));
            }
        });
    }
    Ok(())
}

fn serve_one(mut stream: TcpStream, pages: &Pages) {
    // read the request line (for routing), drain headers, then respond
    let mut reader = match stream.try_clone() {
        Ok(s) => BufReader::new(s),
        Err(_) => return,
    };
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let method = line.split_whitespace().next().unwrap_or("GET").to_string();
    let path = line.split_whitespace().nth(1).unwrap_or("/");
    // Binary PWA icons: served as raw bytes, so they take a dedicated write path (the text branches
    // below all yield a String). Drain the request headers first, then stream the PNG.
    if path.starts_with("/icon-192.png") || path.starts_with("/icon-512.png") {
        let bytes: &[u8] = if path.starts_with("/icon-512") { ICON_512 } else { ICON_192 };
        loop {
            let mut h = String::new();
            match reader.read_line(&mut h) {
                Ok(0) => return,
                Ok(_) if h.trim().is_empty() => break,
                Ok(_) => {}
                Err(_) => return,
            }
        }
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\nCache-Control: max-age=86400\r\nConnection: close\r\n\r\n",
            bytes.len(),
        );
        let _ = stream.write_all(bytes);
        return;
    }
    let (body, ctype): (String, &str) = if path.starts_with("/record") {
        // GET /record[?since=N] — the verified stream from index N on (audit panel polls incrementally)
        let since = path
            .split_once('?')
            .and_then(|(_, q)| q.split('&').find_map(|kv| kv.strip_prefix("since=")))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        (
            kedi::record_json(&pages.record_path, since),
            "application/json",
        )
    } else if path.starts_with("/sessions") {
        // GET /sessions — the warden's live sessions (record-independent; powers the list + kill)
        (
            format!(
                "{{\"warden\":\"live\",\"sessions\":{}}}",
                kedi::sessions_json(&pages.warden)
            ),
            "application/json",
        )
    } else if path.starts_with("/plugins") {
        // GET /plugins — the installed WASM-TUI plugins (name + icon) from plugins.toml, for the
        // launcher. Read fresh each request → drop a plugin in and it appears, no restart.
        (kedi::plugins_json(), "application/json")
    } else if path.starts_with("/rec") {
        // GET /rec → current state; POST /rec?on=1|0 → flip the recording switch from the UI
        use std::sync::atomic::Ordering;
        if method == "POST"
            && let Some(v) = path
                .split_once('?')
                .and_then(|(_, q)| q.split('&').find_map(|kv| kv.strip_prefix("on=")))
        {
            pages.rec.store(v == "1" || v == "true", Ordering::Relaxed);
        }
        (
            format!("{{\"on\":{}}}", pages.rec.load(Ordering::Relaxed)),
            "application/json",
        )
    } else if path.starts_with("/kill") {
        // POST /kill?session=N[&by=who] — attributed kill from the operator console. Records
        // Event::Killed{by} and ends the session (→ pty child terminated, stream closed).
        // Loopback-only like everything else here; auth-on-the-wire is the product tier.
        if method != "POST" {
            (
                "{\"ok\":false,\"error\":\"POST required\"}".into(),
                "application/json",
            )
        } else {
            let q = path.split_once('?').map(|(_, q)| q).unwrap_or("");
            let mut sid: Option<u64> = None;
            let mut by = "web-console".to_string();
            for kv in q.split('&') {
                if let Some((k, v)) = kv.split_once('=') {
                    match k {
                        "session" => sid = v.parse().ok(),
                        "by" => by = v.to_string(),
                        _ => {}
                    }
                }
            }
            match sid {
                Some(id) => {
                    pages.warden.kill(warden_core::SessionId(id), &by);
                    ("{\"ok\":true}".into(), "application/json")
                }
                None => (
                    "{\"ok\":false,\"error\":\"session required\"}".into(),
                    "application/json",
                ),
            }
        }
    } else if path.starts_with("/clients") {
        // GET /clients — {"clients":N,"sessions":M}. N = live WT connections (browser tabs), M =
        // open sessions. The closing tab reads this to decide if it's the last client (offer to stop
        // the server) and to warn if sessions are still running. Source of truth for "am I last?" —
        // only the server sees the other tabs.
        use std::sync::atomic::Ordering;
        (
            format!(
                "{{\"clients\":{},\"sessions\":{}}}",
                pages.clients.load(Ordering::SeqCst),
                pages.warden.session_views().len()
            ),
            "application/json",
        )
    } else if path.starts_with("/shutdown") {
        // POST /shutdown — stop the whole server (last tab chose "stop", or the idle-timeout fired).
        // Idempotent via the swap guard so two tabs racing "stop" don't double-trigger. Wakes the
        // main task, which closes all sessions (→ pty children killed) then exits. Loopback-only.
        use std::sync::atomic::Ordering;
        if method != "POST" {
            (
                "{\"ok\":false,\"error\":\"POST required\"}".into(),
                "application/json",
            )
        } else {
            if !pages.shutdown_started.swap(true, Ordering::SeqCst) {
                pages.shutdown.notify_one();
            }
            ("{\"ok\":true}".into(), "application/json")
        }
    } else if path.starts_with("/manifest.webmanifest") {
        // PWA manifest — makes the page installable as a standalone app with the kedi icon.
        (MANIFEST.to_string(), "application/manifest+json")
    } else if path.starts_with("/sw.js") {
        // Service worker (scope "/") — its fetch handler satisfies Chrome's installability check.
        (SERVICE_WORKER.to_string(), "text/javascript")
    } else if path.starts_with("/raw") {
        (pages.raw.clone(), "text/html; charset=utf-8")
    } else {
        (pages.index.clone(), "text/html; charset=utf-8")
    };
    loop {
        let mut h = String::new();
        match reader.read_line(&mut h) {
            Ok(0) => return,
            Ok(_) if h.trim().is_empty() => break,
            Ok(_) => {}
            Err(_) => return,
        }
    }
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
}

/// kedi [--config PATH] [--host HOST] [--bind IP] [--http-port N] [--wt-port N] [--shell CMD]
///      [--deny NAME|-] [--record PATH|-]
/// Settings resolve as defaults < ~/.config/kedi/kedi.toml < CLI flags. HOST is the domain the
/// browser uses (default `localhost`; try `kedi.localhost`). BIND is the interface to listen on.
/// Recording is OPT-IN (a local terminal isn't surveilled by default): `record = "PATH"` / --record.
struct Config {
    host: String,
    bind: Option<String>,
    http_port: u16,
    wt_port: u16,
    shell: String, // "" → $SHELL; else run `sh -c <shell>` (e.g. "bash --norc" to isolate config)
    deny: Vec<String>, // identities refused by policy (repeatable --deny NAME; `--deny -` clears)
    record: Option<String>, // explicit --record/config path → recording starts ON; None → OFF (toggle in UI)
    name: String, // this warden's display name (shown in the header: "which warden am I on")
    open: bool,   // --open: launcher mode — ensure a background server, open the browser, exit
    font_size: u8, // [ui] font_size — injected into the page
    ai_cmd: String, // [ai] cmd — backend for the `ai` capability; exported as $KEDI_AI_CMD so a
    // desktop-launched kedi (which won't inherit your shell env) still has an AI backend
    config_used: Option<String>, // which kedi.toml was loaded (for the startup banner)
}

/// The optional settings file — every field optional, mirroring the CLI flags.
#[derive(serde::Deserialize, Default)]
struct FileConfig {
    host: Option<String>,
    bind: Option<String>,
    http_port: Option<u16>,
    wt_port: Option<u16>,
    shell: Option<String>,
    deny: Option<Vec<String>>, // replaces the default blocklist ([] clears it)
    record: Option<String>,    // path enables recording; "" keeps it off
    name: Option<String>,      // warden display name
    ui: Option<UiConfig>,
    ai: Option<AiConfig>,
}
#[derive(serde::Deserialize, Default)]
struct AiConfig {
    cmd: Option<String>, // backend command for the `ai` capability (prompt on stdin → answer stdout)
}
#[derive(serde::Deserialize, Default)]
struct UiConfig {
    font_size: Option<u8>,
}

/// Best-effort machine hostname for the default warden name (Linux); falls back to "local".
fn default_warden_name() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| std::fs::read_to_string("/etc/hostname"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "local".into())
}

/// Default audit record path when recording is toggled on without an explicit --record.
fn default_record_path() -> String {
    let base = std::env::var("XDG_STATE_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()))
                .join(".local/state")
        });
    let dir = base.join("kedi");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("record.jsonl").to_string_lossy().into_owned()
}

fn config_path(cli: Option<&str>) -> Option<std::path::PathBuf> {
    if let Some(p) = cli {
        return Some(p.into());
    }
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|_| std::env::var("HOME").map(|h| std::path::PathBuf::from(h).join(".config")))
        .ok()?;
    Some(base.join("kedi").join("kedi.toml"))
}

fn parse_config() -> Config {
    // host default `localhost` (the browser's URL); bind default = dual loopback (127.0.0.1 + ::1),
    // because names like localhost/kedi.localhost resolve to ::1 for QUIC on many systems while a
    // v4-only server never sees those packets. `--bind <ip>` pins a single address.
    let mut c = Config {
        host: "localhost".into(),
        bind: None,
        http_port: 8788,
        wt_port: 4433,
        shell: String::new(),
        deny: vec!["root".into()], // demo default: `root` is refused; kedi.toml `deny = []` clears
        record: None,              // recording is opt-in on a local terminal
        name: default_warden_name(),
        open: false,
        font_size: 15,
        ai_cmd: String::new(),
        config_used: None,
    };
    let args: Vec<String> = std::env::args().skip(1).collect();

    // the settings file first (CLI wins over it)
    let cli_config = args
        .iter()
        .position(|a| a == "--config")
        .and_then(|i| args.get(i + 1).cloned());
    if let Some(path) = config_path(cli_config.as_deref()) {
        if let Ok(text) = std::fs::read_to_string(&path) {
            match toml::from_str::<FileConfig>(&text) {
                Ok(f) => {
                    if let Some(v) = f.host {
                        c.host = v;
                    }
                    if f.bind.is_some() {
                        c.bind = f.bind;
                    }
                    if let Some(v) = f.http_port {
                        c.http_port = v;
                    }
                    if let Some(v) = f.wt_port {
                        c.wt_port = v;
                    }
                    if let Some(v) = f.shell {
                        c.shell = v;
                    }
                    if let Some(v) = f.deny {
                        c.deny = v;
                    }
                    if let Some(v) = f.record
                        && !v.is_empty()
                    {
                        c.record = Some(v);
                    }
                    if let Some(v) = f.name
                        && !v.is_empty()
                    {
                        c.name = v;
                    }
                    if let Some(ui) = f.ui
                        && let Some(v) = ui.font_size
                    {
                        c.font_size = v.clamp(8, 28);
                    }
                    if let Some(ai) = f.ai
                        && let Some(v) = ai.cmd
                    {
                        c.ai_cmd = v;
                    }
                    c.config_used = Some(path.display().to_string());
                }
                Err(e) => {
                    eprintln!("kedi: {} is not valid TOML: {e}", path.display());
                    std::process::exit(2);
                }
            }
        } else if cli_config.is_some() {
            eprintln!("kedi: --config {} not readable", path.display());
            std::process::exit(2);
        }
    }

    // `--dev` shifts both ports to a dev pair so a dev instance never collides with a prod one
    // (prod keeps 8788/4433). Applied here, before the main loop, so an explicit --http-port/
    // --wt-port still overrides it. Only shifts a port left at its default — a port set by the
    // config file is respected (the file is the deployment's own choice).
    if args.iter().any(|a| a == "--dev") {
        if c.http_port == 8788 {
            c.http_port = 8790;
        }
        if c.wt_port == 4433 {
            c.wt_port = 4435;
        }
    }

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--open" {
            c.open = true;
            i += 1;
            continue;
        }
        if args[i] == "--dev" {
            i += 1;
            continue; // handled above; skip so it isn't an "unknown arg"
        }
        let val = args.get(i + 1).cloned();
        match args[i].as_str() {
            "--config" => {} // handled above
            "--host" => c.host = val.unwrap_or(c.host),
            "--bind" => c.bind = val,
            "--http-port" => c.http_port = val.and_then(|v| v.parse().ok()).unwrap_or(c.http_port),
            "--wt-port" => c.wt_port = val.and_then(|v| v.parse().ok()).unwrap_or(c.wt_port),
            "--shell" => c.shell = val.unwrap_or_default(),
            "--deny" => match val.as_deref() {
                Some("-") => c.deny.clear(), // `--deny -` clears the blocklist
                Some(name) => c.deny.push(name.to_string()),
                None => {}
            },
            "--record" => match val.as_deref() {
                Some("-") | None => c.record = None,
                Some(path) => c.record = Some(path.to_string()),
            },
            "--name" => {
                if let Some(v) = val {
                    c.name = v;
                }
            }
            other => {
                eprintln!(
                    "kedi: unknown arg `{other}` (use --open/--dev/--config/--host/--bind/--http-port/--wt-port/--shell/--deny/--record/--name)"
                );
                std::process::exit(2);
            }
        }
        i += 2;
    }
    c
}

/// Is a kedi already serving on the http port? (loopback probe, short timeout)
fn already_serving(http_port: u16) -> bool {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], http_port));
    std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(300)).is_ok()
}

/// Open a URL in a Chromium-family browser (kedi needs WebTransport), falling back to the OS default.
fn open_in_browser(url: &str) {
    let try_spawn = |prog: &str, args: &[&str]| {
        std::process::Command::new(prog)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .is_ok()
    };
    // Launch Chromium in APP mode (`--app=<url>`): a standalone, chromeless window (no tab strip or
    // omnibox) — a dedicated kedi window rather than a browser tab, and it releases more shortcuts to
    // the page. kedi's own bindings (Ctrl+Shift+Enter new pane, Ctrl+Shift+P sessions) work either
    // way; Ctrl+T stays the browser's. Falls back to a normal tab if no Chromium is found.
    let app = format!("--app={url}");
    #[cfg(target_os = "macos")]
    {
        // macOS `open -a` can't pass --app flags to Chrome cleanly; try the binary directly first.
        for chrome in [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ] {
            if try_spawn(chrome, &[app.as_str()]) {
                return;
            }
        }
        if try_spawn("open", &["-a", "Google Chrome", url]) || try_spawn("open", &[url]) {
            return;
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        for chrome in [
            "google-chrome",
            "google-chrome-stable",
            "chromium",
            "chromium-browser",
            "brave-browser",
            "microsoft-edge",
        ] {
            if try_spawn(chrome, &[app.as_str()]) {
                return;
            }
        }
        try_spawn("xdg-open", &[url]); // last resort: the OS default (may not be Chromium → normal tab)
    }
}

/// `--open`: the click-an-icon path. Ensure a background kedi is serving (spawn one detached if not),
/// then open the browser and exit — the server outlives this launcher. Idempotent: clicking again
/// when it's already up just opens another tab.
fn launch(cfg: &Config) -> std::io::Result<()> {
    let url = format!("http://{}:{}", cfg.host, cfg.http_port);
    if !already_serving(cfg.http_port) {
        // spawn ourselves in serve mode, detached: no controlling terminal (setsid), no stdio, so it
        // survives this process exiting AND a terminal close.
        let exe = std::env::current_exe()?;
        let fwd: Vec<String> = std::env::args().skip(1).filter(|a| a != "--open").collect();
        let mut cmd = std::process::Command::new(exe);
        cmd.args(&fwd)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        #[cfg(unix)]
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        cmd.spawn()?;
        // wait until it's actually serving before opening the tab (up to ~5s)
        for _ in 0..50 {
            if already_serving(cfg.http_port) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        println!("kedi: started a background server on {url}");
    } else {
        println!("kedi: already running — opening {url}");
    }
    open_in_browser(&url);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `kedi plugin …` is a standalone CLI action (manage the plugin registry), not a serve — handle it
    // before any server/config setup. It only touches the plugin dir + plugins.toml.
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.first().map(String::as_str) == Some("plugin") {
        if let Err(e) = kedi::plugin_cli::run(&raw[1..]) {
            eprintln!("kedi plugin: {e}");
            std::process::exit(1);
        }
        return Ok(());
    }

    let cfg = parse_config();

    // launcher mode: ensure a detached server, open the browser, done.
    if cfg.open {
        launch(&cfg)?;
        return Ok(());
    }

    // Wire the AI backend for the `ai` capability: export the config's [ai] cmd as $KEDI_AI_CMD so
    // the AiBroker (which reads that env var) finds it — even when kedi was desktop-launched and thus
    // didn't inherit your shell env. A shell-set $KEDI_AI_CMD still wins (only set it if unset).
    if !cfg.ai_cmd.is_empty() && std::env::var_os("KEDI_AI_CMD").is_none() {
        // SAFETY: single-threaded startup, before the tokio runtime / any session threads exist.
        unsafe { std::env::set_var("KEDI_AI_CMD", &cfg.ai_cmd) };
    }

    // bind targets: an explicit --bind, else dual loopback (127.0.0.1 + ::1) so name-based hosts
    // that resolve to ::1 AND literal 127.0.0.1 all reach us, loopback-only.
    let ips: Vec<std::net::IpAddr> = match &cfg.bind {
        Some(b) => vec![b.parse()?],
        None => vec!["127.0.0.1".parse()?, "::1".parse()?],
    };

    // recording is opt-in: an explicit --record/config path starts ON; otherwise a default path
    // exists (created empty) so the UI toggle can turn it on later, but it starts OFF.
    let initial_on = cfg.record.is_some();
    let record_path = cfg.record.clone().unwrap_or_else(default_record_path);
    let (w, rec_ctl) = kedi::terminal_warden(&record_path, initial_on, cfg.deny.clone())?;
    let warden = Arc::new(w);
    let (identity, cert_hash) = kedi::wt_identity(&cfg.host);

    // Shutdown plumbing. `clients` counts live WT connections (browser tabs) across BOTH bind
    // endpoints — created once here and shared, so it isn't split per-endpoint. `shutdown` wakes the
    // main task to tear down + exit; `shutdown_started` makes the trigger idempotent (racing tabs /
    // idle-timeout + a manual stop).
    let clients = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let shutdown_started = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let wt_url = format!("https://{}:{}/pty", cfg.host, cfg.wt_port);
    // http listeners: prefer sockets handed to us by launchd (on-demand PWA launch); otherwise bind
    // the loopback address(es) ourselves. `via_launchd` only tweaks the startup banner.
    let (http_listeners, via_launchd) = match launchd_sockets("KediHTTP") {
        Some(l) => (l, true),
        None => {
            let mut v = Vec::new();
            for ip in &ips {
                let addr = std::net::SocketAddr::new(*ip, cfg.http_port);
                match TcpListener::bind(addr) {
                    Ok(l) => v.push(l),
                    Err(e) => {
                        eprintln!("kedi: http bind {addr} failed: {e}  (a stray kedi? `pkill -x kedi`)");
                        std::process::exit(1);
                    }
                }
            }
            (v, false)
        }
    };
    serve_page(
        http_listeners,
        wt_url.clone(),
        cert_hash,
        rec_ctl.clone(),
        cfg.font_size,
        &cfg.name,
        warden.clone(),
        clients.clone(),
        shutdown.clone(),
        shutdown_started.clone(),
    )
    .unwrap_or_else(|e| {
        eprintln!("kedi: http serve failed: {e}");
        std::process::exit(1);
    });

    println!("kedi — governed web terminal · warden `{}`", cfg.name);
    println!("  open   http://{}:{}", cfg.host, cfg.http_port);
    println!("  wt     {wt_url}  (QUIC/WebTransport)");
    println!(
        "  bind   {ips:?} (http :{}{} · wt :{})",
        cfg.http_port,
        if via_launchd { " via launchd" } else { "" },
        cfg.wt_port
    );
    println!(
        "  config {}",
        cfg.config_used
            .as_deref()
            .unwrap_or("(none — ~/.config/kedi/kedi.toml to create one)")
    );
    if initial_on {
        println!("  record ON → {record_path}  (toggle from the audit panel)");
    } else {
        println!("  record off (toggle on from the audit panel) → {record_path}");
    }
    println!(
        "  policy identity required · denied: {}  (--deny NAME to add, --deny - to clear)",
        if cfg.deny.is_empty() {
            "(none)".to_string()
        } else {
            cfg.deny.join(", ")
        }
    );

    // one WebTransport endpoint per bind address (sharing the single cert); "" → the session spawns
    // your $SHELL, every keystroke and byte of output governed
    for ip in &ips {
        let addr = std::net::SocketAddr::new(*ip, cfg.wt_port);
        let endpoint = kedi::wt_server(identity.clone_identity(), addr).unwrap_or_else(|e| {
            eprintln!("kedi: wt bind {addr} failed: {e}  (a stray kedi? `pkill -x kedi`)");
            std::process::exit(1);
        });
        tokio::spawn(kedi::serve(
            endpoint,
            warden.clone(),
            cfg.shell.clone(),
            clients.clone(),
        ));
    }

    // Stay alive until either an explicit stop (last tab chose "stop", or a manual POST /shutdown) or
    // the idle-timeout fires. The idle-timeout is the fallback for a HARD browser-close (window X /
    // Cmd-Q / crash) — there's no reliable way to run the confirm dialog in `unload`, so instead the
    // server self-exits once it's been idle a while: NO live connections AND NO open sessions. Gating
    // on sessions-empty (not just connections==0) protects a detached/teleported session left running
    // with no viewer — the daemon design deliberately outlives a tab, so we only reap when truly idle.
    const IDLE_GRACE: std::time::Duration = std::time::Duration::from_secs(90);
    let reason = {
        use std::sync::atomic::Ordering;
        loop {
            let idle = clients.load(Ordering::SeqCst) == 0 && warden.session_views().is_empty();
            if idle {
                // arm the grace timer; a reconnect or new session before it elapses cancels the exit.
                tokio::select! {
                    _ = shutdown.notified() => break "stop",
                    _ = tokio::time::sleep(IDLE_GRACE) => {
                        if clients.load(Ordering::SeqCst) == 0 && warden.session_views().is_empty() {
                            break "idle";
                        }
                        // something reconnected during the grace window → keep serving.
                    }
                }
            } else {
                // busy: wait for an explicit stop, or re-poll periodically to catch the busy→idle edge.
                tokio::select! {
                    _ = shutdown.notified() => break "stop",
                    _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
                }
            }
        }
    };

    // Graceful teardown: close every session FIRST so pty children are killed (via cap revoke — there
    // is no Drop), then exit. A bare exit would orphan shells. A short grace lets the kills propagate.
    let n = kedi::close_all_sessions(&warden, "server-shutdown");
    if n > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }
    println!("kedi: shutting down ({reason}) — closed {n} session(s)");
    std::process::exit(0);
}
