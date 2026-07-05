//! kedi — the governed web terminal on warden.
//!
//! Browser ↔ kedi is **QUIC via WebTransport** (HTTP/3): the only way a browser speaks QUIC. A tiny
//! HTTP server hands out the xterm.js page (with the self-signed cert's SHA-256 for the browser's
//! `serverCertificateHashes`); the terminal I/O rides a WebTransport bidi stream. Each connection
//! opens a warden **`pty` capability**, so the shell's output is streamed and recorded exactly like
//! any governed capability — and the browser's live view IS that governed stream.
//!
//! Wire on the bidi stream: client→server is newline JSON control (`{"input":"…"}` /
//! `{"resize":[cols,rows]}`); server→client is the raw pty output bytes → `term.write()`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use warden_caps::pty::{PTY, PtyBroker};
use warden_core::{
    Action, ActionSource, ApprovalRequest, Approver, Call, CapRequest, Ctx, Decision, Event,
    Incoming, InputFrame, Policy, Recorder, Result as WResult, Runtime, Session, SessionCtx,
    SessionId, Verdict, Warden, WardenError,
};
use warden_host::{Manifest, plugin};
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
impl Approver for AutoApprover {
    fn decide(&self, _: &ApprovalRequest) -> Verdict {
        Verdict::Approved {
            by: vec!["kedi".into()],
        }
    }
}

/// Runs an in-process action (the pty "attach" loop) on the calling (blocking) thread.
struct LocalRuntime;
impl Runtime for LocalRuntime {
    fn name(&self) -> &'static str {
        "local"
    }
    fn run(&self, action: Action, ctx: &Ctx) -> WResult<()> {
        match action.source {
            ActionSource::InProcess(body) => body(ctx),
            _ => Err(WardenError::Cap(
                "kedi runs in-process attach actions".into(),
            )),
        }
    }
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
/// plugin here, not an edit to the kernel: e.g. a handoff plugin contributing a `SessionHook` + a
/// `Policy`, or a DLP plugin defining a `Detector` point + an `Interceptor`.
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

/// A control message from the browser on a pane's stream.
enum ClientMsg {
    /// The client's introduction, first line on the stream: the *claimed* identity for this
    /// session (attribution, not authentication).
    Hello(String),
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
    None
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
    let (in_tx, in_rx) = std::sync::mpsc::channel::<InputFrame>();
    let (out_tx, mut out_rx) = unbounded_channel::<Vec<u8>>();

    // ── introduction: the first line names the session's (claimed) identity ──────────────────
    // The client sends {"hello":"name"} immediately on stream open. A client that skips it (e.g.
    // the /raw page) falls through on its first regular frame with identity "browser"; that frame
    // is kept and fed to the session below. Leftover bytes stay in `buf` for the main loop.
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 4096];
    let mut identity = String::from("browser");
    let mut pending: Vec<InputFrame> = Vec::new();
    'intro: loop {
        match recv.read(&mut tmp).await {
            Ok(Some(n)) if n > 0 => {
                buf.extend_from_slice(&tmp[..n]);
                while let Some(p) = buf.iter().position(|&b| b == b'\n') {
                    let line: Vec<u8> = buf.drain(..=p).collect();
                    match parse_msg(&line[..line.len() - 1]) {
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

    // the warden pty session: attach loop forwards client input until the client disconnects
    let action = Action {
        name: "attach".into(),
        source: ActionSource::InProcess(Box::new(|ctx: &Ctx| {
            let pty = ctx.cap(PTY).ok_or(WardenError::Cap("no pty".into()))?;
            let input = ctx
                .take_input()
                .ok_or(WardenError::Cap("no input channel".into()))?;
            // forward client input, but don't block on it forever: poll so that when the shell exits
            // (user types `exit` / Ctrl-D) the loop ends → session closes → the WebTransport stream
            // closes → the browser closes the pane. Recv wakes immediately on a frame, so this adds
            // no typing latency; the timeout only bounds how fast we notice a dead shell.
            use std::sync::mpsc::RecvTimeoutError;
            loop {
                match input.recv_timeout(std::time::Duration::from_millis(100)) {
                    Ok(frame) => {
                        ctx.invoke(pty, &frame.op, frame.data)?;
                    }
                    // tear down promptly on shell-exit OR an operator kill — not just on next keystroke
                    Err(RecvTimeoutError::Timeout) if ctx.finished(pty) || ctx.killed() => break,
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => break, // client gone
                }
            }
            Ok(())
        })),
    };
    let session = Session {
        id: SessionId(sid),
        identity,
        requests: vec![CapRequest {
            kind: PTY,
            arg: command,
        }],
        action,
    };
    // if the session ends in an error (e.g. policy deny), tell the human why before the pane closes
    let out_notice = out_tx.clone();
    let observer: Arc<dyn Recorder> = Arc::new(WtObserver { out: out_tx });
    let inc = Incoming {
        session,
        runtime: "local".into(),
        observer: Some(observer),
        input: Some(in_rx),
        done: Box::new(move |r: &warden_core::Result<()>| {
            if let Err(e) = r {
                let _ =
                    out_notice.send(format!("\r\n\x1b[1;31m[warden] {e}\x1b[0m\r\n").into_bytes());
            }
        }),
    };

    // run the (sync) warden session on a dedicated OS thread — thread-per-session, decoupled from
    // the tokio runtime's lifecycle (a tracked blocking task would deadlock the runtime on drop
    // while the attach loop waits for input). It finishes when `in_tx` closes below.
    let warden_kill = warden.clone(); // kept for the {kill} control frame
    std::thread::spawn(move || warden.run_incoming(inc));

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
                Some(ClientMsg::Hello(_)) | None => {} // late hello: identity is set at open, ignore
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
}
