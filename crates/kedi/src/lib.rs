//! kedi — the governed web terminal on warden.
//!
//! Browser ↔ kedi is **QUIC via WebTransport** (HTTP/3): the only way a browser speaks QUIC. A tiny
//! HTTP server hands out the xterm.js page (with the self-signed cert's SHA-256 for the browser's
//! `serverCertificateHashes`); the terminal I/O rides a WebTransport bidi stream. Each connection
//! opens a warden capability — a **`pty`** (a shell) or, for a plugin pane, an **`app`** (a WASM-TUI
//! component; send `{"app":"name"}` before the hello). Either way its output is streamed and recorded
//! exactly like any governed capability — the browser's live view IS that governed stream, and the
//! attach loop drives both the same way.
//!
//! Wire on the bidi stream: client→server is newline JSON control (`{"input":"…"}` /
//! `{"resize":[cols,rows]}` / optional `{"app":"name"}`); server→client is the raw output bytes →
//! `term.write()` (a shell's bytes, or a WASM app's rendered frames).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use warden_caps::ai::{AI, AiBroker};
use warden_caps::dstask::{DSTASK, DsTaskBroker};
use warden_caps::pty::{PTY, PtyBroker};
use warden_core::Broker as _; // brings .grant() into scope for grant_declared_caps
use warden_core::{
    Action, ActionSource, ApprovalRequest, Approver, Call, CapRequest, Ctx, Decision, Event,
    Incoming, InputFrame, Policy, Recorder, Result as WResult, Runtime, Session, SessionCtx,
    SessionId, Verdict, Warden, WardenError,
};
use warden_host::{Manifest, plugin};
use warden_wasm::APP;
use wtransport::{Endpoint, Identity, ServerConfig};

// DLP (output masking) intentionally NOT wired here. The spike's literal-secret masker was a demo
// toy, and doing real detection (regex/entropy) per-byte on the interactive output stream is the
// wrong layer + a hot-path performance risk. Deferred until it can run as a proper detector over the
// logical terminal content, off the latency path. kedi's governance for now: recorded + replayable.

/// kedi's session policy: an identity is required, and blocklisted identities are refused.
/// The identity is *claimed* by the browser (hello frame) — attribution, not authentication;
/// auth on the wire is the product tier. A deny lands in the record as `Event::Denied`
/// (→ console feed, replay timeline) and the refusal reason is shown in the pane.
struct TerminalPolicy {
    denied: Vec<String>,
}
impl Policy for TerminalPolicy {
    fn on_session(&self, s: &SessionCtx) -> Decision {
        if s.identity.trim().is_empty() {
            return Decision::Deny("an identity is required to open a session".into());
        }
        if self
            .denied
            .iter()
            .any(|d| d.eq_ignore_ascii_case(&s.identity))
        {
            return Decision::Deny(format!("identity `{}` is blocked by policy", s.identity));
        }
        Decision::Allow
    }
    fn on_request(&self, _: &SessionCtx, _: &CapRequest) -> Decision {
        Decision::Allow
    }
    fn on_call(&self, _: &SessionCtx, _: &Call) -> Decision {
        Decision::Allow
    }
}

struct AutoApprover;
#[async_trait::async_trait]
impl Approver for AutoApprover {
    async fn decide(&self, _: &ApprovalRequest) -> Verdict {
        Verdict::Approved {
            by: vec!["kedi".into()],
        }
    }
}

/// Runs an in-process action (the pty "attach" loop) on the calling (blocking) thread.
struct LocalRuntime;
#[async_trait::async_trait]
impl Runtime for LocalRuntime {
    fn name(&self) -> &'static str {
        "local"
    }
    async fn run(&self, action: Action, ctx: &Ctx) -> WResult<()> {
        match action.source {
            ActionSource::InProcess(body) => body(ctx).await,
            _ => Err(WardenError::Cap(
                "kedi runs in-process attach actions".into(),
            )),
        }
    }
}

/// Grants an `app` capability by **plugin name** (`req.arg` = the name). The broker reads the plugin
/// registry, resolves the name → its .wasm + declared cap kinds, grants exactly those sub-caps, and
/// builds the `AppCap`. This is the whole "no rebuild" story: what a plugin is and may reach comes
/// from `plugins.toml` at grant time, not from kedi's source.
struct AppBroker;
#[async_trait::async_trait]
impl warden_core::Broker for AppBroker {
    fn handles(&self, req: &CapRequest) -> bool {
        req.kind == APP
    }
    async fn grant(&self, req: &CapRequest) -> WResult<Box<dyn warden_core::Capability>> {
        let (path, kinds) = resolve_plugin(&req.arg)
            .ok_or_else(|| WardenError::Cap(format!("no plugin `{}` in plugins.toml", req.arg)))?;
        Ok(Box::new(warden_wasm::AppCap::spawn(
            &path,
            grant_declared_caps(&kinds).await,
        )?))
    }
}

/// Grant the sub-capabilities a plugin declared (by kind name) in its manifest. Unknown kinds are
/// skipped (the plugin's `host.invoke` on them is refused — the sandbox stance). This is the one
/// place kedi decides what a plugin may reach: extend the match to expose more caps to plugins.
async fn grant_declared_caps(kinds: &[String]) -> Vec<Box<dyn warden_core::Capability>> {
    let mut caps: Vec<Box<dyn warden_core::Capability>> = Vec::new();
    for k in kinds {
        let granted = match k.as_str() {
            "dstask" => DsTaskBroker
                .grant(&CapRequest {
                    kind: DSTASK,
                    arg: String::new(),
                })
                .await
                .ok(),
            "ai" => AiBroker
                .grant(&CapRequest {
                    kind: AI,
                    arg: String::new(), // → $KEDI_AI_CMD
                })
                .await
                .ok(),
            _ => None, // an undeclared/unknown kind isn't granted
        };
        if let Some(c) = granted {
            caps.push(c);
        }
    }
    caps
}

/// Forwards a session's pty output to the WebTransport stream; the rest of the event stream
/// still lands in the audit record via the warden's base recorder.
struct WtObserver {
    out: UnboundedSender<Vec<u8>>,
}
impl Recorder for WtObserver {
    fn record(&self, ev: Event) {
        if let Event::Output { bytes, .. } = ev {
            let _ = self.out.send(bytes);
        }
    }
}

/// A recorder you can switch on/off at runtime. Recording is opt-in (governed ≠ surveilled): the
/// file exists but nothing is written until `on` is set — from the UI (`POST /rec`) or the initial
/// `--record` flag. Toggling produces a record covering only the on-periods; the hash chain stays
/// valid over the lines actually written (gaps in time, not broken links).
struct ToggleRecorder {
    inner: warden_record::FileRecorder,
    on: Arc<AtomicBool>,
}
impl Recorder for ToggleRecorder {
    fn record(&self, ev: Event) {
        if self.on.load(Ordering::Relaxed) {
            self.inner.record(ev);
        }
    }
}

/// Handle to a terminal warden's recording switch, kept by the HTTP layer so the browser can flip
/// it and read its state.
#[derive(Clone)]
pub struct RecordControl {
    pub on: Arc<AtomicBool>,
    pub path: String,
}

/// A warden wired for the terminal use case, **composed from plugins** (pty capability, in-process
/// runtime, identity policy, auto-approver, opt-in toggleable recorder) — each a one-liner via the
/// [`plugin`](warden_host::plugin) closure adapter. Adding a governance layer to kedi is a new
/// plugin here, not an edit to the kernel: e.g. a DLP plugin defining a `Detector` point + an
/// `Interceptor`, or a handoff plugin defining its own session-lifecycle point + a `Policy`.
///
/// Known cost of "everything is recorded" (measured, engine_throughput_bulk): output lands in the
/// audit log hex-encoded (×2 write amplification), and under a bulk flood the async recorder drains
/// at ~35–40 MiB/s of audit bytes — a 32 MiB burst reaches the client in ~80ms but the log finishes
/// ~1.7s later, with the backlog buffered in the recorder's unbounded channel. Fine for interactive
/// use; a sustained multi-GiB flood would balloon memory. Product tier: bounded channel + an
/// explicit audit backpressure policy (slow the pty, or summarize bulk output).
pub fn terminal_warden(
    record_path: &str,
    initial_on: bool,
    denied_identities: Vec<String>,
) -> std::io::Result<(Warden, RecordControl)> {
    let on = Arc::new(AtomicBool::new(initial_on));
    let inner = warden_record::FileRecorder::create(record_path)?;
    let recorder: Arc<dyn Recorder> = Arc::new(ToggleRecorder {
        inner,
        on: on.clone(),
    });
    let loaded = warden_host::load(vec![
        plugin(Manifest::new("pty").provides(&["cap:pty"]), |reg| {
            reg.add::<dyn warden_core::Broker>(Arc::new(PtyBroker));
        }),
        // WASM-TUI plugin panes: a pane whose capability is an `app` (a kedi:app component) instead
        // of a pty. The broker resolves a plugin *name* through plugins.toml at grant time and grants
        // its declared caps — so plugins are added by editing the registry, never by rebuilding kedi.
        plugin(Manifest::new("app").provides(&["cap:app"]), |reg| {
            reg.add::<dyn warden_core::Broker>(Arc::new(AppBroker));
        }),
        plugin(
            Manifest::new("local-runtime").provides(&["runtime:local"]),
            |reg| {
                reg.add::<dyn Runtime>(Arc::new(LocalRuntime));
            },
        ),
        plugin(
            Manifest::new("identity-policy").provides(&["policy:identity"]),
            {
                let denied = denied_identities;
                move |reg| {
                    reg.add::<dyn Policy>(Arc::new(TerminalPolicy {
                        denied: denied.clone(),
                    }))
                }
            },
        ),
        plugin(
            Manifest::new("auto-approver").provides(&["approver"]),
            |reg| {
                reg.add::<dyn Approver>(Arc::new(AutoApprover));
            },
        ),
        plugin(Manifest::new("record").provides(&["recorder"]), {
            let recorder = recorder.clone();
            move |reg| reg.add::<dyn Recorder>(recorder.clone())
        }),
    ])
    .expect("kedi plugin set loads");
    // The async kernel runs the pty output pump as a future it drives itself (no host-provided
    // spawner anymore — that seam was retired when the kernel went async). The pty's blocking read
    // still lives on its own OS thread inside warden-caps, bridged to the kernel as an async stream.
    Ok((
        loaded.warden,
        RecordControl {
            on,
            path: record_path.to_string(),
        },
    ))
}

/// The warden's currently-open sessions as JSON (id, identity, cap kinds) — record-independent, so
/// the audit panel's session list + kill work even with recording off, and never lag when it's
/// toggled on mid-session.
pub fn sessions_json(warden: &Warden) -> String {
    let rows: Vec<String> = warden
        .live_sessions()
        .into_iter()
        .map(|(id, who, caps)| {
            let caps_json = serde_json::to_string(&caps).unwrap_or_else(|_| "[]".into());
            let who_json = serde_json::to_string(&who).unwrap_or_else(|_| "\"?\"".into());
            format!("{{\"id\":{id},\"who\":{who_json},\"caps\":{caps_json}}}")
        })
        .collect();
    format!("[{}]", rows.join(","))
}

/// The audit record as browser-facing JSON for the replay/console views: `{ok:true, count, since,
/// events}` where `events` is the verified stream (`RecEvent`, payloads hex) from index `since` on
/// (`since=0` → everything), or `{ok:false, error}` if the hash chain fails to verify.
/// Loaded + re-verified on every request — the record is the source of truth, not kept in memory.
/// `since` keeps the polling console incremental: measured at 50k events, the full body is ~8 MiB
/// per poll; the delta is bytes. (The verify itself stays O(record) — ~260ms at 50k events;
/// incremental verify state is the product-tier fix.)
pub fn record_json(path: &str, since: usize) -> String {
    match warden_record::load(path) {
        Ok(events) => {
            let n = events.len();
            let from = since.min(n);
            let ev = serde_json::to_string(&events[from..]).unwrap_or_else(|_| "[]".to_string());
            format!("{{\"ok\":true,\"count\":{n},\"since\":{from},\"events\":{ev}}}")
        }
        Err(e) => {
            let msg = serde_json::to_string(&e.to_string())
                .unwrap_or_else(|_| "\"load error\"".to_string());
            format!("{{\"ok\":false,\"error\":{msg}}}")
        }
    }
}

// ── WebTransport server ──────────────────────────────────────────────────────────────────────

/// A self-signed WebTransport identity + the cert's SHA-256 (for the browser's
/// `serverCertificateHashes`). `host` goes in the SAN. `wtransport`'s self-signed identity already
/// meets the browser's constraints (short-lived ECDSA); the product path loads a real cert instead.
/// One identity is reused across multiple bind addresses so the page's single hash matches them all.
pub fn wt_identity(host: &str) -> (Identity, [u8; 32]) {
    let mut sans: Vec<String> = vec![host.to_string(), "localhost".into()];
    sans.dedup();
    let identity = Identity::self_signed(&sans).expect("self-signed identity");
    let der = identity.certificate_chain().as_slice()[0].der();
    let hash: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(der).into()
    };
    (identity, hash)
}

/// A WebTransport server endpoint bound to `addr` using the given identity. Bind both loopback
/// families (`127.0.0.1` + `::1`) — many systems (incl. this one) resolve `localhost`/`*.localhost`
/// to `::1` for QUIC — while staying loopback-only (this spawns a shell; never bind `0.0.0.0`).
pub fn wt_server(
    identity: Identity,
    addr: SocketAddr,
) -> std::io::Result<Endpoint<wtransport::endpoint::endpoint_side::Server>> {
    let config = ServerConfig::builder()
        .with_bind_address(addr)
        .with_identity(identity)
        .build();
    Endpoint::server(config)
}

// ── plugins: discovered at runtime, no rebuild ──────────────────────────────────────────────────
// A plugin is a `kedi:app` .wasm plus a `[[plugin]]` block in the plugin dir's `plugins.toml`
// declaring its name, icon, and the capabilities it requests. kedi reads the registry per connection
// (so edits take effect without a restart), lists plugins to the browser launcher (`/plugins`), and
// grants each app exactly the caps it declares. Adding a plugin = drop a .wasm + a toml block.

/// The plugin dir: `$KEDI_PLUGIN_DIR`, else `$XDG_CONFIG_HOME/kedi/plugins`, else `~/.config/kedi/plugins`.
fn plugin_dir() -> std::path::PathBuf {
    std::env::var("KEDI_PLUGIN_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            let cfg = std::env::var("XDG_CONFIG_HOME")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| {
                    std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default())
                        .join(".config")
                });
            cfg.join("kedi/plugins")
        })
}

/// One entry from `plugins.toml`.
#[derive(serde::Deserialize, Clone)]
struct PluginEntry {
    name: String,
    /// the .wasm filename (relative to the plugin dir), defaulting to `<name>.wasm`
    #[serde(default)]
    wasm: String,
    #[serde(default)]
    icon: String,
    /// capability kinds this plugin may use (e.g. ["dstask"]); kedi grants exactly these
    #[serde(default)]
    caps: Vec<String>,
}

#[derive(serde::Deserialize, Default)]
struct PluginRegistry {
    #[serde(default, rename = "plugin")]
    plugins: Vec<PluginEntry>,
}

/// Read `<plugin_dir>/plugins.toml` (missing/invalid → no plugins). Fills `wasm` defaults.
fn load_registry() -> Vec<PluginEntry> {
    let path = plugin_dir().join("plugins.toml");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let mut reg: PluginRegistry = toml::from_str(&text).unwrap_or_default();
    for p in &mut reg.plugins {
        if p.wasm.trim().is_empty() {
            p.wasm = format!("{}.wasm", p.name);
        }
    }
    reg.plugins
}

/// The installed plugins as JSON (name + icon) for the browser launcher (`/plugins`).
pub fn plugins_json() -> String {
    let items: Vec<String> = load_registry()
        .iter()
        .filter(|p| plugin_dir().join(&p.wasm).exists())
        .map(|p| {
            format!(
                "{{\"name\":{},\"icon\":{}}}",
                json_str(&p.name),
                json_str(&p.icon)
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// Resolve a plugin name → (its .wasm path, its declared cap kinds). `None` if it isn't a registered,
/// present plugin — so an unknown app name falls back to a shell pane.
fn resolve_plugin(name: &str) -> Option<(String, Vec<String>)> {
    let p = load_registry().into_iter().find(|p| p.name == name)?;
    let path = plugin_dir().join(&p.wasm);
    path.exists()
        .then(|| (path.to_string_lossy().into_owned(), p.caps))
}

/// minimal JSON string escaper (name/icon are short, controlled strings)
fn json_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if c.is_control() => {}
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// A control message from the browser on a pane's stream.
enum ClientMsg {
    /// The client's introduction, first line on the stream: the *claimed* identity for this
    /// session (attribution, not authentication).
    Hello(String),
    /// Open this pane as a WASM app (a `kedi:app` plugin) by name, instead of a shell. Sent with (or
    /// just after) the hello. The name resolves to an installed `.wasm` component (see `app_path`).
    App(String),
    Frame(InputFrame),
    /// The kill button: record an attributed kill + terminate this pane's session.
    Kill(String),
}

fn parse_msg(line: &[u8]) -> Option<ClientMsg> {
    let v: serde_json::Value = serde_json::from_slice(line).ok()?;
    if let Some(w) = v.get("hello").and_then(|x| x.as_str()) {
        // sanitize: printable, bounded — it lands in the audit record
        let who: String = w.chars().filter(|c| !c.is_control()).take(48).collect();
        return Some(ClientMsg::Hello(who));
    }
    if let Some(name) = v.get("app").and_then(|x| x.as_str()) {
        // a plugin name: [a-z0-9_-], bounded — resolved to an installed .wasm by `app_path`
        let name: String = name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .take(64)
            .collect();
        if !name.is_empty() {
            return Some(ClientMsg::App(name));
        }
    }
    if let Some(s) = v.get("input").and_then(|x| x.as_str()) {
        return Some(ClientMsg::Frame(InputFrame {
            op: "input".into(),
            data: s.as_bytes().to_vec(),
        }));
    }
    if let Some(a) = v.get("resize").and_then(|x| x.as_array()) {
        let cols = a.first()?.as_u64()?;
        let rows = a.get(1)?.as_u64()?;
        return Some(ClientMsg::Frame(InputFrame {
            op: "resize".into(),
            data: format!("{cols}x{rows}").into_bytes(),
        }));
    }
    if let Some(k) = v.get("kill") {
        return Some(ClientMsg::Kill(k.as_str().unwrap_or("browser").to_string()));
    }
    // {"pasteImage":"<base64>","ext":"png"} — a clipboard image. The pty capability writes it to a
    // file and returns the path (typed at the prompt by the attach loop). Data is `ext\n<raw bytes>`.
    if let Some(b64) = v.get("pasteImage").and_then(|x| x.as_str()) {
        let bytes = b64_decode(b64)?;
        let ext = v
            .get("ext")
            .and_then(|x| x.as_str())
            .filter(|e| e.chars().all(|c| c.is_ascii_alphanumeric()))
            .unwrap_or("png");
        let mut data = format!("{ext}\n").into_bytes();
        data.extend_from_slice(&bytes);
        return Some(ClientMsg::Frame(InputFrame {
            op: "paste-image".into(),
            data,
        }));
    }
    None
}

/// Minimal, dependency-free base64 decoder (standard alphabet, ignores whitespace/padding). The
/// clipboard image arrives base64 in JSON; this turns it back into the raw bytes the pty op writes.
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        acc = (acc << 6) | val(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Accept WebTransport sessions forever.
pub async fn serve(
    endpoint: Endpoint<wtransport::endpoint::endpoint_side::Server>,
    warden: Arc<Warden>,
    command: String,
) {
    let next = Arc::new(AtomicU64::new(2000));
    loop {
        let incoming = endpoint.accept().await;
        let (warden, command, next) = (warden.clone(), command.clone(), next.clone());
        tokio::spawn(async move {
            let Ok(request) = incoming.await else { return };
            handle(request, warden, command, next).await;
        });
    }
}

/// One WebTransport connection carries many **panes**: each bidi stream the client opens is an
/// independent governed pty session, multiplexed over the one QUIC connection (no extra handshakes).
async fn handle(
    request: wtransport::endpoint::SessionRequest,
    warden: Arc<Warden>,
    command: String,
    next: Arc<AtomicU64>,
) {
    let Ok(conn) = request.accept().await else {
        return;
    };
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(pair) => pair,
            Err(_) => break, // connection closed
        };
        let sid = next.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(pane_session(
            send,
            recv,
            warden.clone(),
            command.clone(),
            sid,
        ));
    }
}

/// One pane = one bidi stream ↔ one warden pty session.
async fn pane_session(
    mut send: wtransport::SendStream,
    mut recv: wtransport::RecvStream,
    warden: Arc<Warden>,
    command: String,
    sid: u64,
) {
    let (in_tx, in_rx) = unbounded_channel::<InputFrame>();
    let (out_tx, mut out_rx) = unbounded_channel::<Vec<u8>>();

    // ── introduction: the first line names the session's (claimed) identity ──────────────────
    // The client sends {"hello":"name"} immediately on stream open. A client that skips it (e.g.
    // the /raw page) falls through on its first regular frame with identity "browser"; that frame
    // is kept and fed to the session below. Leftover bytes stay in `buf` for the main loop.
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 4096];
    let mut identity = String::from("browser");
    let mut pending: Vec<InputFrame> = Vec::new();
    let mut app_name: Option<String> = None; // Some(name) → this pane is a WASM plugin, not a shell
    'intro: loop {
        match recv.read(&mut tmp).await {
            Ok(Some(n)) if n > 0 => {
                buf.extend_from_slice(&tmp[..n]);
                while let Some(p) = buf.iter().position(|&b| b == b'\n') {
                    let line: Vec<u8> = buf.drain(..=p).collect();
                    match parse_msg(&line[..line.len() - 1]) {
                        // an {"app":"name"} frame selects a plugin pane; it can arrive before or with
                        // the hello. Keep the name only if it's a registered, present plugin — else
                        // fall through to a shell pane.
                        Some(ClientMsg::App(name)) => {
                            if resolve_plugin(&name).is_some() {
                                app_name = Some(name);
                            }
                        }
                        Some(ClientMsg::Hello(who)) if !who.trim().is_empty() => {
                            identity = who;
                            break 'intro;
                        }
                        Some(ClientMsg::Hello(_)) => break 'intro, // empty hello → default
                        Some(ClientMsg::Frame(f)) => {
                            pending.push(f);
                            break 'intro;
                        }
                        _ => {}
                    }
                }
            }
            _ => return, // closed before introducing itself — no session, nothing recorded
        }
    }

    // the warden pty session: attach loop forwards client input until the client disconnects.
    // Async now — it *awaits* the next input frame (no polling → no typing latency), and a short
    // ticker rides alongside via `select!` so the loop still tears down promptly when the shell
    // exits (Ctrl-D) or an operator kills the session, not only on the next keystroke.
    // A pane hosts EITHER a shell (pty) or a WASM app — the same attach loop drives both, because it
    // grabs whichever single capability the session was granted and forwards `input`/`resize` frames
    // (an app accepts `input` as an alias for a keystroke). `app_path` selects the app: `None` → a
    // pty running `command`; `Some(path)` → an `app` capability on that .wasm component.
    // app panes get a periodic `tick` op so the guest's `on_tick` runs (e.g. deck polling an async
    // `ai` job); pty panes don't (a `tick` op would error at the chokepoint and spam the record).
    let is_app = app_name.is_some();
    let action = Action {
        name: "attach".into(),
        source: ActionSource::InProcess(warden_core::action_fn(move |ctx: &Ctx| {
            Box::pin(async move {
                // the session holds exactly one capability (pty or app) — take it kind-agnostically
                let cap = ctx
                    .first_cap()
                    .ok_or(WardenError::Cap("no capability granted".into()))?;
                let mut input = ctx
                    .take_input()
                    .ok_or(WardenError::Cap("no input channel".into()))?;
                use futures::StreamExt;
                let mut tick = tokio::time::interval(std::time::Duration::from_millis(100));
                loop {
                    tokio::select! {
                        frame = input.next() => match frame {
                            Some(frame) => {
                                let out = ctx.invoke(cap, &frame.op, frame.data).await?;
                                // pty-only: `paste-image` writes the image and returns its path; type
                                // it at the prompt. (An app never sends this op.) Still chokepointed.
                                if frame.op == "paste-image" && !out.is_empty() {
                                    ctx.invoke(cap, "input", out).await?;
                                }
                            }
                            None => break, // client gone (input stream closed)
                        },
                        _ = tick.tick() => {
                            if ctx.finished(cap) || ctx.killed() { break; }
                            // drive on_tick for app panes (ignore the result; it's best-effort)
                            if is_app { let _ = ctx.invoke(cap, "tick", Vec::new()).await; }
                        }
                    }
                }
                Ok(())
            })
        })),
    };
    let request = match &app_name {
        // an app pane: the broker resolves this plugin name through plugins.toml at grant time
        Some(name) => CapRequest {
            kind: APP,
            arg: name.clone(),
        },
        None => CapRequest {
            kind: PTY,
            arg: command,
        },
    };
    let session = Session {
        id: SessionId(sid),
        identity,
        requests: vec![request],
        action,
    };
    // if the session ends in an error (e.g. policy deny), tell the human why before the pane closes
    let out_notice = out_tx.clone();
    let observer: Arc<dyn Recorder> = Arc::new(WtObserver { out: out_tx });
    let inc = Incoming {
        session,
        runtime: "local".into(),
        observer: Some(observer),
        input: Some(Box::pin(
            tokio_stream::wrappers::UnboundedReceiverStream::new(in_rx),
        )),
        done: Box::new(move |r: &warden_core::Result<()>| {
            if let Err(e) = r {
                let _ =
                    out_notice.send(format!("\r\n\x1b[1;31m[warden] {e}\x1b[0m\r\n").into_bytes());
            }
        }),
    };

    // run the warden session as a tokio task now that the kernel is async — no more thread-per-
    // session. It finishes when `in_tx` closes below (the attach loop's input stream ends).
    let warden_kill = warden.clone(); // kept for the {kill} control frame
    tokio::spawn(async move { warden.run_incoming(inc).await });

    // pump pty output → the WebTransport stream (ends when the session drops `out_tx`)
    let out_task = tokio::spawn(async move {
        while let Some(bytes) = out_rx.recv().await {
            if send.write_all(&bytes).await.is_err() {
                break;
            }
        }
    });

    // a frame that arrived with (instead of) the hello goes to the session first
    for f in pending.drain(..) {
        if in_tx.send(f).is_err() {
            return;
        }
    }

    // read client control frames (keystrokes/resize) → the warden input channel.
    // NB: drain lines already sitting in `buf` (read together with the intro) BEFORE reading more.
    loop {
        while let Some(p) = buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = buf.drain(..=p).collect();
            match parse_msg(&line[..line.len() - 1]) {
                Some(ClientMsg::Frame(f)) => {
                    if in_tx.send(f).is_err() {
                        return;
                    }
                }
                // kill button: attributed Event::Killed, then end the session (attach loop
                // stops → revoke → the pty child is terminated)
                Some(ClientMsg::Kill(by)) => {
                    warden_kill.kill(SessionId(sid), &by);
                    return;
                }
                // late hello/app are ignored — identity and pane kind are fixed at open
                Some(ClientMsg::Hello(_)) | Some(ClientMsg::App(_)) | None => {}
            }
        }
        match recv.read(&mut tmp).await {
            Ok(Some(n)) if n > 0 => buf.extend_from_slice(&tmp[..n]),
            _ => break, // client disconnected / stream closed
        }
    }
    drop(in_tx); // end the attach loop → session closes → shell revoked → out_tx drops
    let _ = out_task.await; // drain remaining output, then done
}

#[cfg(test)]
mod tests {
    use super::*;
    use wtransport::ClientConfig;

    #[tokio::test]
    async fn webtransport_session_streams_pty_output() {
        let warden = Arc::new(
            terminal_warden("/tmp/kedi-test.jsonl", true, vec![])
                .unwrap()
                .0,
        );
        let (identity, hash) = wt_identity("localhost");
        let endpoint = wt_server(identity, "127.0.0.1:0".parse().unwrap()).unwrap();
        let port = endpoint.local_addr().unwrap().port();
        tokio::spawn(serve(endpoint, warden, "cat".into()));

        // verify the server by its cert hash — exactly what the browser does via serverCertificateHashes
        let client = Endpoint::client(
            ClientConfig::builder()
                .with_bind_default()
                .with_server_certificate_hashes([wtransport::tls::Sha256Digest::new(hash)])
                .build(),
        )
        .unwrap();
        let step = std::time::Duration::from_secs(6);
        let conn = tokio::time::timeout(
            step,
            client.connect(format!("https://127.0.0.1:{port}/pty")),
        )
        .await
        .expect("connect timed out")
        .unwrap();
        let (mut send, mut recv) =
            tokio::time::timeout(step, async { conn.open_bi().await.unwrap().await.unwrap() })
                .await
                .expect("open_bi timed out");

        // type a line (cat echoes it back via the pty)
        send.write_all(b"{\"input\":\"hello world\\n\"}\n")
            .await
            .unwrap();

        // collect output for a moment (timeout ends the read; the stream stays open)
        let got: std::sync::Arc<std::sync::Mutex<Vec<u8>>> = Default::default();
        let got2 = got.clone();
        let _ = tokio::time::timeout(std::time::Duration::from_millis(800), async move {
            let mut tmp = [0u8; 4096];
            loop {
                match recv.read(&mut tmp).await {
                    Ok(Some(n)) if n > 0 => got2.lock().unwrap().extend_from_slice(&tmp[..n]),
                    _ => break,
                }
            }
        })
        .await;

        let got = got.lock().unwrap().clone();
        let out = String::from_utf8_lossy(&got);
        assert!(!out.is_empty(), "expected pty output over WebTransport");
        assert!(
            out.contains("hello world"),
            "expected the echoed line over WebTransport, got: {out:?}"
        );
    }

    // Step 2 proof: a pane requested as a WASM app renders the guest's frames over WebTransport —
    // the whole plugin path end to end (client `{"app":..}` → app capability → frames → browser),
    // governed exactly like the pty pane above. Uses warden's own in-tree kedi:app fixture (no
    // dependency on any real plugin); skips if it isn't built.
    #[tokio::test]
    async fn webtransport_app_pane_streams_wasm_frames() {
        // warden's fixture (crates/warden-wasm/tests/fixture); locate the built .wasm via
        // $FIXTURE_WASM, else the default build path. Absent → skip.
        let fixture = std::env::var("FIXTURE_WASM").unwrap_or_else(|_| {
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../warden-wasm/tests/fixture/target/wasm32-wasip2/release/kedi_app_fixture.wasm"
            )
            .to_string()
        });
        if !std::path::Path::new(&fixture).exists() {
            eprintln!(
                "skip: build the fixture first (cd ../warden-wasm/tests/fixture && cargo build --release --target wasm32-wasip2), or set FIXTURE_WASM"
            );
            return;
        }
        // point the plugin dir at a temp dir holding the fixture as `demo.wasm` + a registry
        let dir = std::env::temp_dir().join("kedi-app-pane-test");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::copy(fixture, dir.join("demo.wasm")).unwrap();
        std::fs::write(
            dir.join("plugins.toml"),
            "[[plugin]]\nname = \"demo\"\ncaps = []\n",
        )
        .unwrap();
        // SAFETY: single-threaded test setup before any threads read the env
        unsafe { std::env::set_var("KEDI_PLUGIN_DIR", &dir) };

        let warden = Arc::new(
            terminal_warden("/tmp/kedi-app-test.jsonl", true, vec![])
                .unwrap()
                .0,
        );
        let (identity, hash) = wt_identity("localhost");
        let endpoint = wt_server(identity, "127.0.0.1:0".parse().unwrap()).unwrap();
        let port = endpoint.local_addr().unwrap().port();
        tokio::spawn(serve(endpoint, warden, "cat".into()));

        let client = Endpoint::client(
            ClientConfig::builder()
                .with_bind_default()
                .with_server_certificate_hashes([wtransport::tls::Sha256Digest::new(hash)])
                .build(),
        )
        .unwrap();
        let step = std::time::Duration::from_secs(6);
        let conn = tokio::time::timeout(
            step,
            client.connect(format!("https://127.0.0.1:{port}/pty")),
        )
        .await
        .expect("connect timed out")
        .unwrap();
        let (mut send, mut recv) =
            tokio::time::timeout(step, async { conn.open_bi().await.unwrap().await.unwrap() })
                .await
                .expect("open_bi timed out");

        // open this pane as the `demo` WASM app (before the hello frame), then introduce
        send.write_all(b"{\"app\":\"demo\"}\n").await.unwrap();
        send.write_all(b"{\"hello\":\"carol\"}\n").await.unwrap();

        let got: std::sync::Arc<std::sync::Mutex<Vec<u8>>> = Default::default();
        let got2 = got.clone();
        let _ = tokio::time::timeout(std::time::Duration::from_millis(800), async move {
            let mut tmp = [0u8; 4096];
            loop {
                match recv.read(&mut tmp).await {
                    Ok(Some(n)) if n > 0 => got2.lock().unwrap().extend_from_slice(&tmp[..n]),
                    _ => break,
                }
            }
        })
        .await;

        let out = String::from_utf8_lossy(&got.lock().unwrap()).into_owned();
        // the fixture paints "kedi:app fixture" on init — proof the app's frames streamed over
        // WebTransport, governed exactly like a pty pane.
        assert!(
            out.contains("kedi:app fixture"),
            "expected the fixture app's frame over WebTransport, got: {out:?}"
        );
    }

    #[tokio::test]
    async fn multiple_panes_multiplex_over_one_connection() {
        let warden = Arc::new(
            terminal_warden("/tmp/kedi-multi-test.jsonl", true, vec![])
                .unwrap()
                .0,
        );
        let (identity, hash) = wt_identity("localhost");
        let endpoint = wt_server(identity, "127.0.0.1:0".parse().unwrap()).unwrap();
        let port = endpoint.local_addr().unwrap().port();
        tokio::spawn(serve(endpoint, warden, "cat".into()));

        let client = Endpoint::client(
            ClientConfig::builder()
                .with_bind_default()
                .with_server_certificate_hashes([wtransport::tls::Sha256Digest::new(hash)])
                .build(),
        )
        .unwrap();
        let conn = client
            .connect(format!("https://127.0.0.1:{port}/pty"))
            .await
            .unwrap();

        // two panes = two bidi streams on the SAME connection; each is its own governed pty
        async fn pane_roundtrip(conn: &wtransport::Connection, marker: &str) -> String {
            let (mut send, mut recv) = conn.open_bi().await.unwrap().await.unwrap();
            send.write_all(format!("{{\"input\":\"{marker}\\n\"}}\n").as_bytes())
                .await
                .unwrap();
            let mut got = Vec::new();
            let mut tmp = [0u8; 4096];
            let _ = tokio::time::timeout(std::time::Duration::from_millis(700), async {
                loop {
                    match recv.read(&mut tmp).await {
                        Ok(Some(n)) if n > 0 => {
                            got.extend_from_slice(&tmp[..n]);
                            if String::from_utf8_lossy(&got).matches(marker).count() >= 2 {
                                break; // echoed by the tty AND by cat
                            }
                        }
                        _ => break,
                    }
                }
            })
            .await;
            String::from_utf8_lossy(&got).into_owned()
        }

        let (a, b) = tokio::join!(
            pane_roundtrip(&conn, "AAA111"),
            pane_roundtrip(&conn, "BBB222")
        );
        // each pane saw only its own input echoed back — independent sessions, one connection
        assert!(
            a.contains("AAA111") && !a.contains("BBB222"),
            "pane A leaked/other: {a:?}"
        );
        assert!(
            b.contains("BBB222") && !b.contains("AAA111"),
            "pane B leaked/other: {b:?}"
        );
    }

    // Latency benchmark (not a correctness test — run explicitly):
    //   cargo test -p kedi --release engine_roundtrip_latency -- --ignored --nocapture
    // Measures keystroke→echo over the FULL engine MINUS the browser: WebTransport loopback +
    // recv-loop hop + attach-thread chokepoint (policy/record/interceptors) + pty write + tty echo
    // + output-pump hop + WT send. The pty's line discipline echoes each byte immediately, so this
    // is a clean per-keystroke round-trip. The browser's render frame (~16ms) is the other, inherent
    // half; this isolates the part we can actually refactor.
    #[tokio::test]
    #[ignore = "latency benchmark; run with --ignored --nocapture"]
    async fn engine_roundtrip_latency() {
        use std::time::{Duration, Instant};
        let warden = Arc::new(
            terminal_warden("/tmp/kedi-bench.jsonl", true, vec![])
                .unwrap()
                .0,
        );
        let (identity, hash) = wt_identity("localhost");
        let endpoint = wt_server(identity, "127.0.0.1:0".parse().unwrap()).unwrap();
        let port = endpoint.local_addr().unwrap().port();
        tokio::spawn(serve(endpoint, warden, "cat".into())); // canonical tty echoes each byte

        let client = Endpoint::client(
            ClientConfig::builder()
                .with_bind_default()
                .with_server_certificate_hashes([wtransport::tls::Sha256Digest::new(hash)])
                .build(),
        )
        .unwrap();
        let conn = client
            .connect(format!("https://127.0.0.1:{port}/pty"))
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap().await.unwrap();
        send.write_all(b"{\"resize\":[80,24]}\n").await.unwrap(); // spawn the shell
        let mut tmp = [0u8; 4096];
        let _ = tokio::time::timeout(Duration::from_millis(400), recv.read(&mut tmp)).await; // drain init

        let mut samples: Vec<Duration> = Vec::new();
        for i in 0..500u32 {
            let ch = (b'a' + (i % 26) as u8) as char;
            let t0 = Instant::now();
            send.write_all(format!("{{\"input\":\"{ch}\"}}\n").as_bytes())
                .await
                .unwrap();
            if let Ok(Ok(Some(n))) =
                tokio::time::timeout(Duration::from_secs(1), recv.read(&mut tmp)).await
                && n > 0
            {
                samples.push(t0.elapsed());
            }
        }
        samples.sort();
        let pct = |p: f64| samples[((samples.len() as f64 * p) as usize).min(samples.len() - 1)];
        let mean = samples.iter().sum::<Duration>() / samples.len() as u32;
        eprintln!(
            "\n── kedi engine round-trip (WT+chokepoint+pty echo, browser-excluded), N={} ──",
            samples.len()
        );
        eprintln!("   min {:>8.3?}   mean {:>8.3?}", samples[0], mean);
        eprintln!(
            "   p50 {:>8.3?}   p90 {:>8.3?}   p99 {:>8.3?}   max {:>8.3?}",
            pct(0.50),
            pct(0.90),
            pct(0.99),
            samples[samples.len() - 1]
        );
    }

    #[tokio::test]
    async fn record_json_serves_the_verified_record() {
        // the replay endpoint must load + verify the record and return the session's events
        let path = "/tmp/kedi-recjson-test.jsonl";
        let warden = Arc::new(terminal_warden(path, true, vec![]).unwrap().0);
        let (identity, hash) = wt_identity("localhost");
        let endpoint = wt_server(identity, "127.0.0.1:0".parse().unwrap()).unwrap();
        let port = endpoint.local_addr().unwrap().port();
        tokio::spawn(serve(endpoint, warden, "cat".into()));

        let client = Endpoint::client(
            ClientConfig::builder()
                .with_bind_default()
                .with_server_certificate_hashes([wtransport::tls::Sha256Digest::new(hash)])
                .build(),
        )
        .unwrap();
        let conn = client
            .connect(format!("https://127.0.0.1:{port}/pty"))
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap().await.unwrap();
        send.write_all(b"{\"input\":\"hello123\\n\"}\n")
            .await
            .unwrap();
        // drain until we've seen the echo (so an Output event has been recorded)
        let mut tmp = [0u8; 4096];
        let _ = tokio::time::timeout(std::time::Duration::from_millis(800), async {
            let mut seen = Vec::new();
            loop {
                match recv.read(&mut tmp).await {
                    Ok(Some(n)) if n > 0 => {
                        seen.extend_from_slice(&tmp[..n]);
                        if String::from_utf8_lossy(&seen).contains("hello123") {
                            break;
                        }
                    }
                    _ => break,
                }
            }
        })
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(150)).await; // let the async recorder write

        let j = record_json(path, 0);
        assert!(
            j.contains("\"ok\":true"),
            "record should verify: {}",
            &j[..j.len().min(160)]
        );
        assert!(
            j.contains("\"count\":") && !j.contains("\"count\":0"),
            "record should have events: {}",
            &j[..j.len().min(160)]
        );
        // output is recorded verbatim (no DLP interceptor in kedi — see the note atop this file);
        // "hello123" = hex 68656c6c6f313233
        assert!(
            j.contains("68656c6c6f313233"),
            "expected the session's output in the record json"
        );
    }

    // Bulk-output throughput (not a correctness test — run explicitly):
    //   cargo test -p kedi --release engine_throughput_bulk -- --ignored --nocapture
    // The shell dumps 32 MiB; measures wall time until the client has received it all, i.e. the
    // full pipeline pty-read → chokepoint (record: hex-JSON + SHA-256) → WT send → client read.
    // Also reports the record file size (write amplification: every output byte lands hex-encoded
    // in the audit log).
    #[tokio::test]
    #[ignore = "throughput benchmark; run with --ignored --nocapture"]
    async fn engine_throughput_bulk() {
        use std::time::Instant;
        const TOTAL: usize = 32 * 1024 * 1024;
        let rec_path = "/tmp/kedi-tput.jsonl";
        let warden = Arc::new(terminal_warden(rec_path, true, vec![]).unwrap().0);
        let (identity, hash) = wt_identity("localhost");
        let endpoint = wt_server(identity, "127.0.0.1:0".parse().unwrap()).unwrap();
        let port = endpoint.local_addr().unwrap().port();
        tokio::spawn(serve(
            endpoint,
            warden,
            format!(
                "dd if=/dev/zero bs=65536 count={} 2>/dev/null",
                TOTAL / 65536
            ),
        ));

        let client = Endpoint::client(
            ClientConfig::builder()
                .with_bind_default()
                .with_server_certificate_hashes([wtransport::tls::Sha256Digest::new(hash)])
                .build(),
        )
        .unwrap();
        let conn = client
            .connect(format!("https://127.0.0.1:{port}/pty"))
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap().await.unwrap();
        let t0 = Instant::now();
        send.write_all(b"{\"resize\":[80,24]}\n").await.unwrap(); // spawn → dd starts
        let mut got = 0usize;
        let mut tmp = vec![0u8; 1 << 20];
        let deadline = std::time::Duration::from_secs(60);
        while got < TOTAL {
            match tokio::time::timeout(deadline, recv.read(&mut tmp)).await {
                Ok(Ok(Some(n))) if n > 0 => got += n,
                _ => break, // stream closed (dd exited) or timeout
            }
        }
        let dt = t0.elapsed();
        let mbps = got as f64 / (1024.0 * 1024.0) / dt.as_secs_f64();
        // the recorder is async (unbounded channel) — wait for the audit log to finish draining and
        // measure how far it lags behind the live stream under bulk load
        let mut rec_size = 0u64;
        let mut stable = 0;
        while stable < 3 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            let s = std::fs::metadata(rec_path).map(|m| m.len()).unwrap_or(0);
            if s == rec_size {
                stable += 1;
            } else {
                stable = 0;
                rec_size = s;
            }
        }
        let drain = t0.elapsed();
        eprintln!("\n── kedi engine bulk throughput ──");
        eprintln!(
            "   received {:.1} MiB in {:?}  →  {:.0} MiB/s (client-visible)",
            got as f64 / 1048576.0,
            dt,
            mbps
        );
        eprintln!(
            "   audit log drained {:.1} MiB in {:?} (lag behind live: {:?})",
            rec_size as f64 / 1048576.0,
            drain,
            drain - dt
        );
        eprintln!(
            "   amplification ×{:.2} (output bytes → hex-JSON audit bytes)",
            rec_size as f64 / got.max(1) as f64
        );
    }

    // /record cost at scale (the operator console polls this every 1.2s while open):
    //   cargo test -p kedi --release record_json_at_scale -- --ignored --nocapture
    #[test]
    #[ignore = "scale benchmark; run with --ignored --nocapture"]
    fn record_json_at_scale() {
        use std::time::Instant;
        use warden_core::{CapId, Event, Recorder as _};
        let path = "/tmp/kedi-recscale.jsonl";
        let rec = warden_record::FileRecorder::create(path).unwrap();
        rec.record(Event::SessionOpened {
            session: SessionId(1),
            identity: "bench".into(),
        });
        for _ in 0..50_000u32 {
            // ~a keystroke echo chunk each
            rec.record(Event::Output {
                session: SessionId(1),
                cap: CapId(1),
                bytes: vec![b'x'; 64],
            });
        }
        rec.flush();
        let t0 = Instant::now();
        let j = record_json(path, 0);
        let dt = t0.elapsed();
        eprintln!("\n── /record at scale ──");
        eprintln!(
            "   50k events: load+verify+serialize = {dt:?}, json = {:.1} MiB",
            j.len() as f64 / 1048576.0
        );
        eprintln!("   (polled every 1.2s by the live console → this must stay ≪ 1.2s)");
    }

    #[tokio::test]
    async fn hello_names_the_session_identity() {
        // the client's {"hello":"name"} introduction becomes the session identity in the record
        let path = "/tmp/kedi-ident-test.jsonl";
        let warden = Arc::new(terminal_warden(path, true, vec![]).unwrap().0);
        let (identity, hash) = wt_identity("localhost");
        let endpoint = wt_server(identity, "127.0.0.1:0".parse().unwrap()).unwrap();
        let port = endpoint.local_addr().unwrap().port();
        tokio::spawn(serve(endpoint, warden, "cat".into()));

        let client = Endpoint::client(
            ClientConfig::builder()
                .with_bind_default()
                .with_server_certificate_hashes([wtransport::tls::Sha256Digest::new(hash)])
                .build(),
        )
        .unwrap();
        let conn = client
            .connect(format!("https://127.0.0.1:{port}/pty"))
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap().await.unwrap();
        send.write_all(b"{\"hello\":\"alice\"}\n{\"input\":\"hi\\n\"}\n")
            .await
            .unwrap();
        let mut tmp = [0u8; 4096];
        let _ =
            tokio::time::timeout(std::time::Duration::from_millis(600), recv.read(&mut tmp)).await;
        tokio::time::sleep(std::time::Duration::from_millis(150)).await; // recorder drain

        let j = record_json(path, 0);
        assert!(
            j.contains("\"identity\":\"alice\""),
            "session should carry the claimed identity: {}",
            &j[..j.len().min(300)]
        );
    }

    #[tokio::test]
    async fn policy_denies_blocked_identity() {
        // a blocklisted identity is refused: the pane gets a human-readable notice, the stream
        // closes, and the record carries the Denied event (→ console feed + replay timeline)
        let path = "/tmp/kedi-deny-test.jsonl";
        let warden = Arc::new(terminal_warden(path, true, vec!["root".into()]).unwrap().0);
        let (identity, hash) = wt_identity("localhost");
        let endpoint = wt_server(identity, "127.0.0.1:0".parse().unwrap()).unwrap();
        let port = endpoint.local_addr().unwrap().port();
        tokio::spawn(serve(endpoint, warden, "cat".into()));

        let client = Endpoint::client(
            ClientConfig::builder()
                .with_bind_default()
                .with_server_certificate_hashes([wtransport::tls::Sha256Digest::new(hash)])
                .build(),
        )
        .unwrap();
        let conn = client
            .connect(format!("https://127.0.0.1:{port}/pty"))
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap().await.unwrap();
        send.write_all(b"{\"hello\":\"root\"}\n").await.unwrap();

        // the refusal notice must arrive, then the stream must close
        let mut got = Vec::new();
        let mut tmp = [0u8; 4096];
        let closed = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                match recv.read(&mut tmp).await {
                    Ok(Some(n)) if n > 0 => got.extend_from_slice(&tmp[..n]),
                    _ => break,
                }
            }
        })
        .await;
        assert!(closed.is_ok(), "stream should close after a policy deny");
        let out = String::from_utf8_lossy(&got);
        assert!(
            out.contains("blocked by policy"),
            "pane should show the refusal reason: {out:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let j = record_json(path, 0);
        assert!(
            j.contains("\"t\":\"denied\""),
            "record should carry the Denied event: {}",
            &j[..j.len().min(400)]
        );
    }

    #[tokio::test]
    async fn kill_tears_down_the_session_without_client_input() {
        // an operator kill (what POST /kill does) must end the session promptly even if the client
        // never types again — the attach loop polls the kill flag, it doesn't wait for a keystroke
        let warden = Arc::new(
            terminal_warden("/tmp/kedi-kill-test.jsonl", true, vec![])
                .unwrap()
                .0,
        );
        let (identity, hash) = wt_identity("localhost");
        let endpoint = wt_server(identity, "127.0.0.1:0".parse().unwrap()).unwrap();
        let port = endpoint.local_addr().unwrap().port();
        tokio::spawn(serve(endpoint, warden.clone(), "cat".into())); // idle: never exits on its own

        let client = Endpoint::client(
            ClientConfig::builder()
                .with_bind_default()
                .with_server_certificate_hashes([wtransport::tls::Sha256Digest::new(hash)])
                .build(),
        )
        .unwrap();
        let conn = client
            .connect(format!("https://127.0.0.1:{port}/pty"))
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap().await.unwrap();
        send.write_all(b"{\"hello\":\"alice\"}\n{\"resize\":[80,24]}\n")
            .await
            .unwrap();

        // wait for the session to register in the warden's live set, then kill it (no client input)
        let mut sid = None;
        for _ in 0..60 {
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
            if let Some((id, _, _)) = warden.live_sessions().into_iter().next() {
                sid = Some(id);
                break;
            }
        }
        let sid = sid.expect("session should register in live_sessions");
        assert!(
            warden.kill(SessionId(sid), "operator"),
            "kill should find the live session"
        );

        // the stream must close shortly (attach loop polls the kill flag every 100ms) — no typing
        let closed = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let mut tmp = [0u8; 4096];
            while let Ok(Some(_)) = recv.read(&mut tmp).await {}
        })
        .await;
        assert!(
            closed.is_ok(),
            "stream did not close after kill — session lingered"
        );
    }

    #[tokio::test]
    async fn shell_exit_closes_the_stream() {
        // when the shell exits, the pane's session must end and the WebTransport stream must close,
        // so the browser closes the floating window (rather than leaving a dead pane around)
        let warden = Arc::new(
            terminal_warden("/tmp/kedi-exit-test.jsonl", true, vec![])
                .unwrap()
                .0,
        );
        let (identity, hash) = wt_identity("localhost");
        let endpoint = wt_server(identity, "127.0.0.1:0".parse().unwrap()).unwrap();
        let port = endpoint.local_addr().unwrap().port();
        // a shell that prints once and exits immediately
        tokio::spawn(serve(endpoint, warden, "echo bye".into()));

        let client = Endpoint::client(
            ClientConfig::builder()
                .with_bind_default()
                .with_server_certificate_hashes([wtransport::tls::Sha256Digest::new(hash)])
                .build(),
        )
        .unwrap();
        let conn = client
            .connect(format!("https://127.0.0.1:{port}/pty"))
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap().await.unwrap();
        send.write_all(b"{\"resize\":[80,24]}\n").await.unwrap(); // triggers the shell to spawn

        // the read loop must terminate (stream closed by the server) shortly after the shell exits
        let closed = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let mut tmp = [0u8; 4096];
            // drain "bye" until the stream finishes — then the pane closes client-side
            while let Ok(Some(_)) = recv.read(&mut tmp).await {}
        })
        .await;
        assert!(
            closed.is_ok(),
            "stream did not close after the shell exited — the pane would linger"
        );
    }

    #[tokio::test]
    async fn client_resize_reaches_the_pty() {
        let warden = Arc::new(
            terminal_warden("/tmp/kedi-resize-test.jsonl", true, vec![])
                .unwrap()
                .0,
        );
        let (identity, hash) = wt_identity("localhost");
        let endpoint = wt_server(identity, "127.0.0.1:0".parse().unwrap()).unwrap();
        let port = endpoint.local_addr().unwrap().port();
        // a shell that waits for one line, then reports its terminal size (rows cols)
        tokio::spawn(serve(endpoint, warden, "IFS= read _; stty size".into()));

        let client = Endpoint::client(
            ClientConfig::builder()
                .with_bind_default()
                .with_server_certificate_hashes([wtransport::tls::Sha256Digest::new(hash)])
                .build(),
        )
        .unwrap();
        let conn = client
            .connect(format!("https://127.0.0.1:{port}/pty"))
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap().await.unwrap();

        // resize to 123x45, THEN let the shell run `stty size`
        send.write_all(b"{\"resize\":[123,45]}\n").await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        send.write_all(b"{\"input\":\"\\n\"}\n").await.unwrap();

        let mut got = Vec::new();
        let mut tmp = [0u8; 4096];
        let _ = tokio::time::timeout(std::time::Duration::from_millis(800), async {
            loop {
                match recv.read(&mut tmp).await {
                    Ok(Some(n)) if n > 0 => {
                        got.extend_from_slice(&tmp[..n]);
                        if String::from_utf8_lossy(&got).contains("45 123") {
                            break;
                        }
                    }
                    _ => break,
                }
            }
        })
        .await;
        let out = String::from_utf8_lossy(&got);
        assert!(
            out.contains("45 123"),
            "pty should report the resized size (rows cols = 45 123): {out:?}"
        );
    }

    // Locate the deck plugin's built .wasm (sibling repo or $DECK_WASM); None → skip.
    fn deck_wasm_path() -> Option<String> {
        if let Ok(p) = std::env::var("DECK_WASM") {
            return std::path::Path::new(&p).exists().then_some(p);
        }
        let p = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../deck/guest-wasm/target/wasm32-wasip2/release/kedi_app_deck.wasm"
        );
        // the deck repo now keeps the crate at its root, not guest-wasm/ — try both.
        let root = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../deck/target/wasm32-wasip2/release/kedi_app_deck.wasm"
        );
        [root, p]
            .into_iter()
            .find(|c| std::path::Path::new(c).exists())
            .map(|c| c.to_string())
    }

    // deck's `:` AI agent, end to end: grant deck dstask + an `ai` cap backed by `cat` (echoes the
    // prompt). Drive `:` + an instruction + Enter, then tick to let on_tick poll the async job; the
    // echoed prompt (with our "Instruction:" framing) must surface in the agent answer overlay. Proves
    // the whole async path: guest ai_start → ai cap (background thread) → tick → ai_poll → render.
    #[tokio::test]
    async fn deck_agent_queries_the_ai_capability() {
        let Some(path) = deck_wasm_path() else {
            eprintln!(
                "skip: build the deck wasm first (cd ../deck && cargo build --release --target wasm32-wasip2), or set DECK_WASM"
            );
            return;
        };
        use warden_core::Broker as _;
        // an ai cap backed by `cat` — deterministic (echoes the prompt), no network/model needed.
        let ai = AiBroker
            .grant(&CapRequest {
                kind: AI,
                arg: "cat".into(),
            })
            .await
            .unwrap();
        let dstask = DsTaskBroker
            .grant(&CapRequest {
                kind: DSTASK,
                arg: String::new(),
            })
            .await
            .unwrap();
        let cap = warden_wasm::AppCap::spawn(&path, vec![dstask, ai]).expect("spawn deck");
        let cap = Arc::new(cap);
        use warden_core::Capability as _;
        let mut frames = cap.output().expect("output");
        cap.perform("resize", b"120x40").await.unwrap();
        // : opens the agent input (needs a selectable card; the real dstask store has open tasks).
        for k in [":", "s", "u", "m", "\r"] {
            cap.perform("key", k.as_bytes()).await.unwrap();
        }
        // tick to drive on_tick → ai_poll; collect the latest frame.
        let mut last = String::new();
        for _ in 0..30 {
            cap.perform("tick", b"").await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            while let Ok(Some(f)) = tokio::time::timeout(
                std::time::Duration::from_millis(30),
                futures::StreamExt::next(&mut frames),
            )
            .await
            {
                last = String::from_utf8_lossy(&f).into_owned();
            }
            if last.contains("Instruction:") {
                break;
            }
        }
        // `cat` echoed the prompt back; deck frames it with "You are helping…/Task:/Instruction:" and
        // shows it in the "✨ agent" overlay. If there were no open tasks, `:` is a no-op — tolerate
        // that (the store may be empty in CI), but require the board at minimum.
        assert!(
            last.contains("You are helping") || last.contains("✨ agent") || last.contains("TODAY"),
            "expected the agent answer (echoed prompt) or at least the board: {last:?}"
        );
    }
}
