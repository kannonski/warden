//! kedi — governed web terminal. Serves the xterm.js page over HTTP (localhost = a secure context,
//! so the browser's WebTransport is allowed) and the terminal I/O over WebTransport (QUIC/HTTP3).

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

const INDEX_HTML: &str = include_str!("index.html");
const RAW_HTML: &str = include_str!("raw.html");

/// Serve the console page over plain HTTP on every given address — the cert hash + WebTransport URL
/// are injected so the browser can accept kedi's self-signed cert via `serverCertificateHashes`.
struct Pages {
    index: String,
    raw: String,         // /raw — a minimal single-terminal diagnostic page
    record_path: String, // /record — the audit log (always present; toggle governs writes)
    rec: Arc<std::sync::atomic::AtomicBool>, // /rec — the recording switch (flip from the UI)
    warden: Arc<warden_core::Warden>, // /sessions + /kill — the warden's live state
}

fn serve_page(
    http_addrs: &[std::net::SocketAddr],
    wt_url: String,
    cert_hash: [u8; 32],
    rec_ctl: kedi::RecordControl,
    font_size: u8,
    warden_name: &str,
    warden: Arc<warden_core::Warden>,
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
    });
    for addr in http_addrs {
        let listener = TcpListener::bind(addr)?;
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
    let mut shutdown = false;
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
    } else if path.starts_with("/shutdown") {
        // POST /shutdown — the explicit quit-from-the-UI: ack, flush, then exit the process. A
        // relaunch (`kedi --open` / the app icon) starts a fresh one.
        if method == "POST" {
            shutdown = true;
            ("{\"ok\":true}".into(), "application/json")
        } else {
            (
                "{\"ok\":false,\"error\":\"POST required\"}".into(),
                "application/json",
            )
        }
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
    if shutdown {
        let _ = stream.flush(); // let the ack reach the browser, then quit
        std::process::exit(0);
    }
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
    #[cfg(target_os = "macos")]
    {
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
            if try_spawn(chrome, &[url]) {
                return;
            }
        }
        try_spawn("xdg-open", &[url]); // last resort: the OS default (may not be Chromium)
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
    let cfg = parse_config();

    // launcher mode: ensure a detached server, open the browser, done.
    if cfg.open {
        launch(&cfg)?;
        return Ok(());
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

    let wt_url = format!("https://{}:{}/pty", cfg.host, cfg.wt_port);
    let http_addrs: Vec<std::net::SocketAddr> = ips
        .iter()
        .map(|ip| std::net::SocketAddr::new(*ip, cfg.http_port))
        .collect();
    serve_page(
        &http_addrs,
        wt_url.clone(),
        cert_hash,
        rec_ctl.clone(),
        cfg.font_size,
        &cfg.name,
        warden.clone(),
    )
    .unwrap_or_else(|e| {
        eprintln!("kedi: http bind failed: {e}  (a stray kedi? `pkill -x kedi`)");
        std::process::exit(1);
    });

    println!("kedi — governed web terminal · warden `{}`", cfg.name);
    println!("  open   http://{}:{}", cfg.host, cfg.http_port);
    println!("  wt     {wt_url}  (QUIC/WebTransport)");
    println!(
        "  bind   {ips:?} (http :{} · wt :{})",
        cfg.http_port, cfg.wt_port
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
        tokio::spawn(kedi::serve(endpoint, warden.clone(), cfg.shell.clone()));
    }

    std::future::pending::<()>().await; // serve tasks run in the background
    Ok(())
}
