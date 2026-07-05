//! warden spike — governed execution, end to end.
//!
//! The composition root: capabilities from `warden-caps`, runtimes in-process + `warden-wasm`,
//! persistence from `warden-record`, wire from `warden-transport`, interceptors/policy/approvers
//! here, composed via `warden_host::load`. Ten demos over ONE warden:
//!   1. fs.read via the in-process runtime — grant → mediate (log + DLP mask) → record → refuse
//!      an un-granted op → revoke.
//!   2. the SAME session through the wasm runtime — proving the `Runtime` seam is swappable.
//!   3. exec — a hash-pinned binary: wrong pin = grant refused; right pin = quorum-approved, the
//!      child runs, and its stdout comes back through the same chokepoint (masked, recorded).
//!   4. escalation — exec grants are held for a 2-of-2 quorum; an intern's request is rejected.
//!   5. secret as a capability — the action signs with a vaulted key it can never read; unknown
//!      secret = grant refused.
//!   6. the component-model ABI — a sandboxed guest (wit/warden.wit) holding capabilities as
//!      resource handles; empty WASI, `caps` is its only door.
//!   7. transport — the same guest session over QUIC; the client's live view is the event stream.
//!   8. gateway — the remote axis: a warden dials OUT, a client routes to it by name, spliced.
//!   9. pty — a real shell's I/O through the chokepoint (masked, recorded).
//!  10. the record — hash-chain verified, replayed, rewound, and a doctored copy caught.
//!
//! CLI: `warden replay <file> [at]` · `serve <addr>` · `connect <addr> <action> …` · `kill …` ·
//!      `gateway <addr>` · `tunnel <gw> <name>` · `rconnect <gw> <name> <action> …`.

use async_trait::async_trait;
use std::sync::Arc;
use warden_caps::exec::{ARG_SEP, EXEC, ExecBroker, sha256_hex_of};
use warden_caps::fs::{FS_READ, FsReadBroker};
use warden_caps::pty::{PTY, PtyBroker};
use warden_core::*;
use warden_host::{Manifest, plugin};
use warden_record::{FileRecorder, RecEvent, RecordError, state_at};
use warden_secret::{MemVault, SIGN, SignBroker};
use warden_transport::{QuicTransport, QuicTunnel, WireCapRequest, WireRequest};
// Accepted + Catalog come from warden_core::* above.

/// Drive a future to completion on THIS thread with a bare parker executor — no tokio runtime, no
/// `futures::executor` thread-local guard. The component (WASI) runtime needs both: wasmtime's sync
/// linker refuses to run under an ambient tokio runtime (it falls back to its own), and the guest's
/// capability calls bridge back to the async kernel with `futures::executor::block_on`, which panics
/// if nested inside another `futures::executor::block_on`. A guard-free parker sidesteps both, so a
/// component session runs on a plain `std::thread` exactly as it did before the kernel went async.
fn block_on_bare<F: std::future::Future>(mut fut: F) -> F::Output {
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};
    struct ThreadWaker(std::thread::Thread);
    impl Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker: Waker = Arc::new(ThreadWaker(std::thread::current())).into();
    let mut cx = Context::from_waker(&waker);
    // SAFETY: `fut` lives on this stack frame and is never moved after being pinned.
    let mut fut = unsafe { std::pin::Pin::new_unchecked(&mut fut) };
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(out) => return out,
            Poll::Pending => std::thread::park(),
        }
    }
}

/// Run one accepted session on a dedicated OS thread with [`block_on_bare`], awaiting its completion
/// without blocking a tokio worker. Sessions may run the component (WASI) runtime, which must not
/// execute under an ambient tokio runtime (see [`block_on_bare`]); routing every `run_incoming` here
/// keeps the accept loop uniform. The tokio `Handle` is entered on the session thread so tokio-based
/// capabilities (fs.read) still find a reactor.
async fn run_incoming_bare(warden: Arc<Warden>, inc: warden_core::Incoming) {
    let h = tokio::runtime::Handle::current();
    let jh = std::thread::spawn(move || {
        let _enter = h.enter();
        block_on_bare(warden.run_incoming(inc));
    });
    tokio::task::spawn_blocking(move || jh.join().expect("session thread"))
        .await
        .expect("session join");
}

// ── interceptors: the chokepoint, composed. audit + DLP are just interceptors. ──────────────────

struct LogInterceptor;
#[async_trait]
impl Interceptor for LogInterceptor {
    async fn intercept(&self, call: Call, next: Next<'_>) -> Result<CallResult> {
        eprintln!(
            "  → {}::{} ({} bytes in)",
            call.kind.0,
            call.op,
            call.input.len()
        );
        let res = next.run(call).await?;
        eprintln!("  ← {} bytes out", res.output.len());
        Ok(res)
    }
}

/// DLP/masking as an interceptor: it masks a call's whole result, and — via a stateful
/// `output_masker` — a capability's live output stream, catching a secret even when a read()
/// boundary splits it across chunks. (Spike: one literal secret; real DLP is detectors + regex.)
const SECRET: &[u8] = b"hunter2";
const MASK: &[u8] = b"*******"; // same length → offset-preserving replacement

struct MaskInterceptor;
impl MaskInterceptor {
    /// Replace every full occurrence of `SECRET` in `buf` (equal-length mask, in place).
    fn mask_all(mut buf: Vec<u8>) -> Vec<u8> {
        let n = SECRET.len();
        let mut i = 0;
        while i + n <= buf.len() {
            if &buf[i..i + n] == SECRET {
                buf[i..i + n].copy_from_slice(MASK);
                i += n;
            } else {
                i += 1;
            }
        }
        buf
    }
}
#[async_trait]
impl Interceptor for MaskInterceptor {
    async fn intercept(&self, call: Call, next: Next<'_>) -> Result<CallResult> {
        Ok(CallResult {
            output: Self::mask_all(next.run(call).await?.output),
        })
    }
    fn output_masker(&self) -> warden_core::OutputMasker {
        // catch a secret split across chunks WITHOUT delaying an interactive stream: after masking
        // the joined buffer, hold back only a trailing PREFIX of the secret (something that might
        // complete next chunk) — usually zero bytes, so output flushes immediately. Holding a fixed
        // tail off every chunk delays trailing cursor escapes and makes live typing lag (learned
        // the hard way in kedi).
        let hold_len = |buf: &[u8]| -> usize {
            let max = (SECRET.len() - 1).min(buf.len());
            (1..=max)
                .rev()
                .find(|&k| buf.ends_with(&SECRET[..k]))
                .unwrap_or(0)
        };
        let mut carry: Vec<u8> = Vec::new();
        Box::new(move |chunk: Vec<u8>| {
            // an empty chunk is the stream-close flush signal: emit whatever's carried, unheld
            if chunk.is_empty() {
                return MaskInterceptor::mask_all(std::mem::take(&mut carry));
            }
            let mut buf = std::mem::take(&mut carry);
            buf.extend_from_slice(&chunk);
            buf = MaskInterceptor::mask_all(buf);
            let hold = hold_len(&buf);
            carry = buf.split_off(buf.len() - hold);
            buf
        })
    }
}

// ── recorders ───────────────────────────────────────────────────────────────────────────────────

struct StdoutRecorder;
impl Recorder for StdoutRecorder {
    fn record(&self, ev: Event) {
        // summarize payload-carrying events; Result shows its payload — proof the record itself
        // only ever holds the post-mask view of what crossed the chokepoint
        match &ev {
            Event::Call {
                session,
                seq,
                op,
                input,
                ..
            } => {
                println!(
                    "  [rec] Call s{}#{} `{op}` ({} B in)",
                    session.0,
                    seq,
                    input.len()
                )
            }
            Event::Result {
                session,
                seq,
                output,
            } => {
                println!(
                    "  [rec] Result s{}#{} -> {:?}",
                    session.0,
                    seq,
                    String::from_utf8_lossy(output)
                )
            }
            Event::Output { session, bytes, .. } => {
                println!(
                    "  [rec] Output s{} -> {:?}",
                    session.0,
                    String::from_utf8_lossy(bytes)
                )
            }
            other => println!("  [rec] {other:?}"),
        }
    }
}

// (recorder fan-out is the host's job now: every contributed `dyn Recorder` receives every event.)

// ── policy: everything flows except exec grants, which escalate to the approvers ─────────────────

struct DemoPolicy;
impl Policy for DemoPolicy {
    fn on_session(&self, _: &SessionCtx) -> Decision {
        Decision::Allow
    }
    fn on_request(&self, _: &SessionCtx, req: &CapRequest) -> Decision {
        if req.kind == EXEC {
            Decision::Escalate("binary execution requires approval".into())
        } else {
            Decision::Allow
        }
    }
    fn on_call(&self, _: &SessionCtx, _: &Call) -> Decision {
        Decision::Allow // per-call escalation uses the exact same gate — policy's choice
    }
}

// ── approver: an N-of-M quorum; each member votes, every vote is auditable ───────────────────────

type Vote = Box<dyn Fn(&ApprovalRequest) -> std::result::Result<(), String> + Send + Sync>;

struct Quorum {
    members: Vec<(String, Vote)>,
    need: usize,
}
#[async_trait]
impl Approver for Quorum {
    async fn decide(&self, req: &ApprovalRequest) -> Verdict {
        let mut yes = Vec::new();
        for (name, vote) in &self.members {
            match vote(req) {
                Ok(()) => {
                    eprintln!("  [approval] {name}: approve — {}", req.subject);
                    yes.push(name.clone());
                }
                Err(why) => {
                    eprintln!("  [approval] {name}: REJECT — {why}");
                    return Verdict::Rejected {
                        by: name.clone(),
                        why,
                    };
                }
            }
            if yes.len() >= self.need {
                return Verdict::Approved { by: yes };
            }
        }
        Verdict::Rejected {
            by: "quorum".into(),
            why: format!("{}/{} approvals", yes.len(), self.need),
        }
    }
}

fn demo_approver() -> Arc<dyn Approver> {
    // alice approves anything; bob refuses interns. product: humans behind the gateway UI, async.
    Arc::new(Quorum {
        members: vec![
            (
                "alice".to_string(),
                Box::new(|_: &ApprovalRequest| Ok(())) as Vote,
            ),
            (
                "bob".to_string(),
                Box::new(|req: &ApprovalRequest| {
                    if req.identity.contains("intern") {
                        Err(format!("{} may not run binaries", req.identity))
                    } else {
                        Ok(())
                    }
                }) as Vote,
            ),
        ],
        need: 2,
    })
}

// ── runtimes: in-process (here) + the real wasm runtime (warden-wasm), both behind the seam ──────

struct DemoRuntime;
#[async_trait]
impl Runtime for DemoRuntime {
    fn name(&self) -> &'static str {
        "demo"
    }
    async fn run(&self, action: Action, ctx: &Ctx) -> Result<()> {
        match action.source {
            ActionSource::InProcess(body) => body(ctx).await,
            _ => Err(WardenError::Cap(
                "demo runtime requires an in-process action".into(),
            )),
        }
    }
}

// ── the demo warden as plugins ─────────────────────────────────────────────────────────────────
// Each layer is a plugin, assembled by warden_host::load — adding a governance layer to the demo is
// a new plugin, not an edit to a composition root. Trivial single-contribution layers use the
// `plugin` closure adapter; the recorder fan-out is the host's.
fn build_warden(recorders: Vec<Arc<dyn Recorder>>) -> Warden {
    warden_host::load(vec![
        plugin(
            Manifest::new("runtimes").provides(&[
                "runtime:demo",
                "runtime:wasm",
                "runtime:component",
            ]),
            |reg| {
                reg.add::<dyn Runtime>(Arc::new(DemoRuntime));
                reg.add::<dyn Runtime>(Arc::new(warden_wasm::WasmRuntime));
                reg.add::<dyn Runtime>(Arc::new(warden_wasm::ComponentRuntime));
            },
        ),
        plugin(Manifest::new("demo-policy").provides(&["policy"]), |reg| {
            reg.add::<dyn Policy>(Arc::new(DemoPolicy));
        }),
        plugin(
            Manifest::new("quorum-approver").provides(&["approver"]),
            |reg| {
                reg.add::<dyn Approver>(demo_approver());
            },
        ),
        plugin(
            Manifest::new("interceptors").provides(&["log", "dlp"]),
            |reg| {
                // priority = chain order: Log is OUTER (logs the masked byte counts), Mask is inner
                // (nearer the capability) — preserving the original [Log, Mask] slice order.
                reg.add_with_priority::<dyn Interceptor>(0, Arc::new(LogInterceptor));
                reg.add_with_priority::<dyn Interceptor>(10, Arc::new(MaskInterceptor));
            },
        ),
        plugin(
            Manifest::new("caps").provides(&["cap:fs.read", "cap:exec", "cap:sign", "cap:pty"]),
            |reg| {
                // the spike's "vault": one signing key. product: a real vault + short-lived leases.
                let vault = Arc::new(MemVault::new([(
                    "deploy-key".to_string(),
                    b"k9-signing-key-material".to_vec(),
                )]));
                reg.add::<dyn Broker>(Arc::new(FsReadBroker));
                reg.add::<dyn Broker>(Arc::new(ExecBroker));
                reg.add::<dyn Broker>(Arc::new(SignBroker::new(vault)));
                reg.add::<dyn Broker>(Arc::new(PtyBroker));
            },
        ),
        plugin(
            Manifest::new("record").provides(&["recorder"]),
            move |reg| {
                for r in &recorders {
                    reg.add::<dyn Recorder>(r.clone());
                }
            },
        ),
    ])
    .expect("warden demo plugin set loads")
    .warden
}

/// The demo action component (see guest/): built with
/// `(cd guest && cargo build --release --target wasm32-wasip2)`.
const GUEST_WASM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../guest/target/wasm32-wasip2/release/warden_guest_demo.wasm"
);

/// The server-side action catalog: named, validated actions only — nothing is uploaded.
fn catalog() -> Catalog {
    Arc::new(|name| match name {
        "guest-demo" => {
            let bytes = std::fs::read(GUEST_WASM)
                .map_err(|e| WardenError::Cap(format!("guest not built ({e}) — see README")))?;
            Ok((ActionSource::Wasm(bytes), "component".to_string()))
        }
        // a deliberately long-running action — the kill-switch demo target
        "slow-read" => Ok((
            ActionSource::InProcess(warden_core::action_fn(|ctx: &Ctx| {
                Box::pin(async move {
                    let fs = ctx
                        .cap(FS_READ)
                        .ok_or(WardenError::Cap("no fs.read granted".into()))?;
                    for _ in 0..50 {
                        ctx.invoke(fs, "read", vec![]).await?; // dies here once the session is killed
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                    Ok(())
                })
            })),
            "demo".to_string(),
        )),
        other => Err(WardenError::Cap(format!("not in catalog: {other}"))),
    })
}

// ── replay: verify a record file's chain, print the timeline, reconstruct state at a point ──────

fn short(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes)
        .replace(ARG_SEP, " ")
        .replace('\n', "⏎");
    if s.len() > 48 {
        format!("{}…", &s[..48])
    } else {
        s
    }
}

fn describe(e: &RecEvent) -> String {
    match e {
        RecEvent::SessionOpened { session, identity } => {
            format!("session {session} opened by {identity}")
        }
        RecEvent::CapGranted { session, cap, kind } => {
            format!("session {session}: cap {cap} granted · {kind}")
        }
        RecEvent::Call {
            session,
            seq,
            op,
            input,
            ..
        } => {
            format!("session {session} call {seq}: `{op}` ← {:?}", short(input))
        }
        RecEvent::Result {
            session,
            seq,
            output,
        } => {
            format!("session {session} call {seq}: → {:?}", short(output))
        }
        RecEvent::Output { session, bytes, .. } => {
            format!("session {session} output: {:?}", short(bytes))
        }
        RecEvent::Failed {
            session,
            seq,
            error,
        } => format!("session {session} call {seq}: FAILED — {error}"),
        RecEvent::Denied {
            session,
            subject,
            why,
        } => format!("session {session}: {subject} DENIED — {why}"),
        RecEvent::EscalationRequested {
            session,
            subject,
            reason,
        } => {
            format!("session {session}: {subject} HELD — {reason}")
        }
        RecEvent::Approved {
            session,
            subject,
            by,
        } => {
            format!("session {session}: {subject} approved by {}", by.join("+"))
        }
        RecEvent::Rejected {
            session,
            subject,
            by,
            why,
        } => {
            format!("session {session}: {subject} REJECTED by {by} — {why}")
        }
        RecEvent::Killed { session, by } => format!("session {session} KILLED by {by}"),
        RecEvent::Revoked { session, cap } => format!("session {session}: cap {cap} revoked"),
        RecEvent::SessionClosed { session } => format!("session {session} closed"),
    }
}

fn print_state(events: &[RecEvent], at: usize) {
    let s = state_at(events, at);
    println!(
        "  state at #{at}: sessions open {:?} · caps held {:?} · {} calls · {} denied/failed",
        s.sessions_open, s.caps_held, s.calls, s.denied_or_failed
    );
    if let Some(o) = &s.last_output {
        println!("  last output seen: {:?}", short(o));
    }
}

fn replay(path: &str, at: Option<usize>) -> std::result::Result<(), RecordError> {
    let events = warden_record::load(path)?;
    println!("  chain verified — {} events", events.len());
    for (i, e) in events.iter().enumerate() {
        println!("  #{:>3}  {}", i + 1, describe(e));
    }
    print_state(&events, at.unwrap_or(events.len()));
    Ok(())
}

/// `warden serve <addr>` — a warden accepting sessions over QUIC, task per session.
async fn serve(addr: &str) -> ! {
    let rec_path = std::env::temp_dir().join("warden-serve.jsonl");
    let file_rec = Arc::new(FileRecorder::create(&rec_path).expect("create record file"));
    let recorders: Vec<Arc<dyn Recorder>> = vec![Arc::new(StdoutRecorder), file_rec];
    let warden = Arc::new(build_warden(recorders));

    let transport = QuicTransport::bind(addr, catalog(), 1000).expect("bind");
    println!(
        "warden serving on {} — record: {}",
        transport.local_addr(),
        rec_path.display()
    );
    println!(
        "try:  warden connect {} guest-demo sign=deploy-key fs.read=<some file>",
        transport.local_addr()
    );
    loop {
        match transport.accept().await {
            Ok(Accepted::Session(inc)) => {
                let w = warden.clone();
                tokio::spawn(async move { w.run_incoming(inc).await });
            }
            Ok(Accepted::Kill { session, by, ack }) => ack(warden.kill(session, &by)),
            Err(e) => eprintln!("[serve] refused: {e}"),
        }
    }
}

/// `warden gateway <addr>` — the remote axis: wardens dial in, clients route to them by name.
fn gateway(addr: &str) -> ! {
    warden_gateway::serve(addr)
}

/// `warden tunnel <gateway-addr> <name>` — a warden that dials OUT to the gateway (no inbound
/// ports) and serves sessions routed to `<name>`.
async fn tunnel(args: &[String]) -> ! {
    let (Some(gw), Some(name)) = (args.first(), args.get(1)) else {
        eprintln!("usage: warden tunnel <gateway-addr> <name>");
        std::process::exit(2);
    };
    let rec_path = std::env::temp_dir().join(format!("warden-tunnel-{name}.jsonl"));
    let file_rec = Arc::new(FileRecorder::create(&rec_path).expect("create record file"));
    let recorders: Vec<Arc<dyn Recorder>> = vec![Arc::new(StdoutRecorder), file_rec];
    let warden = build_warden(recorders);

    let t = QuicTunnel::connect(gw.as_str(), name, catalog(), 3000).expect("connect to gateway");
    println!(
        "warden '{name}' tunneled via {gw} — no inbound ports. record: {}",
        rec_path.display()
    );
    loop {
        match t.accept().await {
            Ok(Accepted::Session(inc)) => {
                // NB: sequential accept in the spike — one dial-back served before the next; fine
                // for the demo. Product tunnel multiplexes concurrent sessions over one connection.
                warden.run_incoming(inc).await;
            }
            Ok(Accepted::Kill { session, by, ack }) => ack(warden.kill(session, &by)),
            Err(e) => {
                eprintln!("[tunnel] {e}");
                std::process::exit(1);
            }
        }
    }
}

/// `warden rconnect <gateway-addr> <warden> <action> [--as id] [kind=arg ...]` — run a session on a
/// remote warden, routed through the gateway.
fn rconnect_cmd(args: &[String]) -> i32 {
    let (Some(gw), Some(warden), Some(action)) = (args.first(), args.get(1), args.get(2)) else {
        eprintln!(
            "usage: warden rconnect <gateway-addr> <warden> <action> [--as id] [kind=arg ...]"
        );
        return 2;
    };
    let (identity, requests) = parse_session_args(&args[3..]);
    let request = WireRequest::Session {
        identity,
        requests,
        action: action.clone(),
    };
    match warden_transport::connect_via(gw.as_str(), warden, &request, |ev| {
        println!("{}", describe(ev))
    }) {
        Ok((_, Ok(()))) => 0,
        Ok((_, Err(e))) => {
            eprintln!("session failed: {e}");
            1
        }
        Err(e) => {
            eprintln!("rconnect: {e}");
            1
        }
    }
}

// (the `web` subcommand — the old SSE browser console, crate warden-web — was removed; kedi is the
// browser console now: WebTransport/QUIC, a real pty capability, the full governance UI.)

/// Parse `[--as identity] [kind=arg ...]` into an identity + capability requests.
fn parse_session_args(args: &[String]) -> (String, Vec<WireCapRequest>) {
    let mut identity = std::env::var("USER").unwrap_or_else(|_| "anonymous".into());
    let mut requests = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--as" {
            if let Some(id) = args.get(i + 1) {
                identity = id.clone();
            }
            i += 2;
        } else {
            if let Some((k, v)) = args[i].split_once('=') {
                requests.push(WireCapRequest {
                    kind: k.to_string(),
                    arg: v.to_string(),
                });
            }
            i += 1;
        }
    }
    (identity, requests)
}

/// `warden connect <addr> <action> [--as identity] [kind=arg ...]` — run a session on a remote warden.
fn connect_cmd(args: &[String]) -> i32 {
    let (Some(addr), Some(action)) = (args.first(), args.get(1)) else {
        eprintln!("usage: warden connect <addr> <action> [--as identity] [kind=arg ...]");
        return 2;
    };
    let (identity, requests) = parse_session_args(&args[2..]);
    let request = WireRequest::Session {
        identity,
        requests,
        action: action.clone(),
    };
    match warden_transport::connect(addr.as_str(), &request, |ev| println!("{}", describe(ev))) {
        Ok((_, Ok(()))) => 0,
        Ok((_, Err(e))) => {
            eprintln!("session failed: {e}");
            1
        }
        Err(e) => {
            eprintln!("connect: {e}");
            1
        }
    }
}

/// `warden kill <addr> <session-id> [--as identity]` — kill a live session on a remote warden.
fn kill_cmd(args: &[String]) -> i32 {
    let (Some(addr), Some(session)) = (
        args.first(),
        args.get(1).and_then(|s| s.parse::<u64>().ok()),
    ) else {
        eprintln!("usage: warden kill <addr> <session-id> [--as identity]");
        return 2;
    };
    let by = match args.get(2).map(String::as_str) {
        Some("--as") => args.get(3).cloned().unwrap_or_else(|| "operator".into()),
        _ => std::env::var("USER").unwrap_or_else(|_| "operator".into()),
    };
    match warden_transport::kill(addr.as_str(), session, &by) {
        Ok(true) => {
            println!("session {session} killed");
            0
        }
        Ok(false) => {
            eprintln!("session {session} is not live");
            1
        }
        Err(e) => {
            eprintln!("kill: {e}");
            1
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        // `warden replay <file> [at]` — verify + replay any record, optionally rewound to event #at
        Some("replay") => {
            let Some(path) = args.get(1) else {
                eprintln!("usage: warden replay <file> [at]");
                std::process::exit(2);
            };
            let at = args.get(2).and_then(|s| s.parse().ok());
            if let Err(e) = replay(path, at) {
                eprintln!("replay: {e}");
                std::process::exit(1);
            }
            return Ok(());
        }
        Some("serve") => serve(args.get(1).map(String::as_str).unwrap_or("127.0.0.1:4747")).await,
        Some("gateway") => gateway(args.get(1).map(String::as_str).unwrap_or("127.0.0.1:4748")),
        Some("tunnel") => tunnel(&args[1..]).await,
        Some("connect") => std::process::exit(connect_cmd(&args[1..])),
        Some("rconnect") => std::process::exit(rconnect_cmd(&args[1..])),
        Some("kill") => std::process::exit(kill_cmd(&args[1..])),
        _ => {} // fall through to the demos
    }

    // a target file with a secret in it
    let path = std::env::temp_dir().join("warden-spike.txt");
    std::fs::write(&path, "hello from the target\nAPI_TOKEN=hunter2\ngoodbye\n").unwrap();
    let path_s = path.to_string_lossy().into_owned();

    // live view + persistent hash-chained record, fed by the same event stream
    let rec_path = std::env::temp_dir().join("warden-session.jsonl");
    let file_rec = Arc::new(FileRecorder::create(&rec_path).expect("create record file"));
    let recorders: Vec<Arc<dyn Recorder>> = vec![Arc::new(StdoutRecorder), file_rec.clone()];
    let warden = Arc::new(build_warden(recorders));

    // ── 1. fs.read, in-process runtime ──────────────────────────────────────────────────────────
    let action = Action {
        name: "read-config".into(),
        source: ActionSource::InProcess(warden_core::action_fn(|ctx: &Ctx| {
            Box::pin(async move {
                let fs = ctx
                    .cap(FS_READ)
                    .ok_or(WardenError::Cap("no fs.read granted".into()))?;

                println!("\n-- action: read the file (mediated) --");
                let bytes = ctx.invoke(fs, "read", vec![]).await?;
                println!("  got (masked): {:?}", String::from_utf8_lossy(&bytes));

                println!("\n-- action: try to WRITE (least-privilege: fs.read cannot) --");
                match ctx.invoke(fs, "write", b"evil".to_vec()).await {
                    Err(e) => println!("  correctly refused: {e}"),
                    Ok(_) => println!("  !! unexpectedly allowed"),
                }
                Ok(())
            })
        })),
    };
    let session = Session {
        id: SessionId(1),
        identity: "carol@laptop".into(),
        requests: vec![CapRequest {
            kind: FS_READ,
            arg: path_s.clone(),
        }],
        action,
    };
    println!("== 1. governed fs.read (in-process runtime) ==");
    warden.run_session(session, "demo").await?;

    // ── 2. same warden, same capability — executed by the WASM runtime ──────────────────────────
    // The guest is a real wasm module; its one import `warden::invoke` is wired into `Ctx::invoke`,
    // so its read is masked+recorded and its write is refused, exactly like the in-process action.
    const GUEST_WAT: &str = r#"
        (module
          (import "warden" "invoke" (func $invoke (param i32) (result i32)))
          (func (export "run") (result i32)
            (drop (call $invoke (i32.const 0)))    ;; op 0 = read  → mediated, masked, recorded
            (call $invoke (i32.const 1))))         ;; op 1 = write → refused (-1) by the fs.read cap
    "#;
    let wasm = wat::parse_str(GUEST_WAT).expect("valid WAT");
    let wasm_session = Session {
        id: SessionId(2),
        identity: "carol@laptop".into(),
        requests: vec![CapRequest {
            kind: FS_READ,
            arg: path_s,
        }],
        action: Action {
            name: "wasm-read".into(),
            source: ActionSource::Wasm(wasm),
        },
    };
    println!("\n== 2. same warden, WASM runtime (the `Runtime` seam is swappable) ==");
    warden.run_session(wasm_session, "wasm").await?;

    // ── 3. exec: a hash-pinned binary ────────────────────────────────────────────────────────────
    let echo = "/bin/echo";
    let pin = sha256_hex_of(echo)?; // in the real product: pinned in a validated-binary catalog

    println!("\n== 3. exec capability: hash-validated binary ==");
    println!("\n-- wrong pin → the broker refuses the grant (binary validation) --");
    let bad = Session {
        id: SessionId(3),
        identity: "carol@laptop".into(),
        requests: vec![CapRequest {
            kind: EXEC,
            arg: format!("{echo}@sha256:{}", "0".repeat(64)),
        }],
        action: Action {
            name: "never-runs".into(),
            source: ActionSource::InProcess(warden_core::action_fn(|_| {
                Box::pin(async move { Ok(()) })
            })),
        },
    };
    match warden.run_session(bad, "demo").await {
        Err(e) => println!("  correctly refused: {e}"),
        Ok(_) => println!("  !! unexpectedly granted"),
    }

    println!("\n-- right pin → child runs; its stdout flows back through the chokepoint --");
    let exec_action = Action {
        name: "run-echo".into(),
        source: ActionSource::InProcess(warden_core::action_fn(|ctx: &Ctx| {
            Box::pin(async move {
                let x = ctx
                    .cap(EXEC)
                    .ok_or(WardenError::Cap("no exec granted".into()))?;
                let args = format!("deploy{ARG_SEP}API_TOKEN=hunter2");
                let out = ctx.invoke(x, "run", args.into_bytes()).await?;
                println!(
                    "  child stdout (masked): {:?}",
                    String::from_utf8_lossy(&out)
                );

                match ctx.invoke(x, "shell", vec![]).await {
                    Err(e) => println!("  `shell` correctly refused: {e}"),
                    Ok(_) => println!("  !! unexpectedly allowed"),
                }
                Ok(())
            })
        })),
    };
    let exec_session = Session {
        id: SessionId(4),
        identity: "carol@laptop".into(),
        requests: vec![CapRequest {
            kind: EXEC,
            arg: format!("{echo}@sha256:{pin}"),
        }],
        action: exec_action,
    };
    warden.run_session(exec_session, "demo").await?;

    // ── 4. escalation: the same grant, held for approval — and a rejection ───────────────────────
    println!("\n== 4. escalation: exec grants go through the approvers ==");
    println!(
        "  (you saw it above: alice+bob approved carol's exec — the quorum ran before the grant)"
    );
    println!("\n-- same request as an intern → bob rejects, the grant never happens --");
    let intern = Session {
        id: SessionId(5),
        identity: "intern@laptop".into(),
        requests: vec![CapRequest {
            kind: EXEC,
            arg: format!("{echo}@sha256:{pin}"),
        }],
        action: Action {
            name: "never-runs".into(),
            source: ActionSource::InProcess(warden_core::action_fn(|_| {
                Box::pin(async move { Ok(()) })
            })),
        },
    };
    match warden.run_session(intern, "demo").await {
        Err(e) => println!("  correctly rejected: {e}"),
        Ok(_) => println!("  !! unexpectedly approved"),
    }

    // ── 5. secret as a capability: sign without ever seeing the key ─────────────────────────────
    println!("\n== 5. secret as a capability: sign, never see the key ==");
    println!("\n-- unknown secret → the broker refuses the grant --");
    let bad_secret = Session {
        id: SessionId(6),
        identity: "carol@laptop".into(),
        requests: vec![CapRequest {
            kind: SIGN,
            arg: "missing-key".into(),
        }],
        action: Action {
            name: "never-runs".into(),
            source: ActionSource::InProcess(warden_core::action_fn(|_| {
                Box::pin(async move { Ok(()) })
            })),
        },
    };
    match warden.run_session(bad_secret, "demo").await {
        Err(e) => println!("  correctly refused: {e}"),
        Ok(_) => println!("  !! unexpectedly granted"),
    }

    println!("\n-- vaulted key → the action signs; no op returns the key --");
    let sign_session = Session {
        id: SessionId(7),
        identity: "carol@laptop".into(),
        requests: vec![CapRequest {
            kind: SIGN,
            arg: "deploy-key".into(),
        }],
        action: Action {
            name: "sign-release".into(),
            source: ActionSource::InProcess(warden_core::action_fn(|ctx: &Ctx| {
                Box::pin(async move {
                    let sign = ctx
                        .cap(SIGN)
                        .ok_or(WardenError::Cap("no sign granted".into()))?;
                    let mac = ctx
                        .invoke(sign, "sign", b"release manifest v1.2.3".to_vec())
                        .await?;
                    println!("  signature: {}", String::from_utf8_lossy(&mac));
                    match ctx.invoke(sign, "reveal", vec![]).await {
                        Err(e) => println!("  `reveal` correctly refused: {e}"),
                        Ok(_) => println!("  !! unexpectedly allowed"),
                    }
                    Ok(())
                })
            })),
        },
    };
    warden.run_session(sign_session, "demo").await?;

    // ── 6. component-model ABI: capabilities as resource handles (wit/warden.wit) ───────────────
    println!("\n== 6. component-model ABI: a sandboxed guest holding capability handles ==");
    let guest_bytes = std::fs::read(GUEST_WASM).ok();
    match &guest_bytes {
        None => {
            println!("  guest not built — run:");
            println!("    (cd guest && cargo build --release --target wasm32-wasip2)");
        }
        Some(component_bytes) => {
            let component_session = Session {
                id: SessionId(8),
                identity: "carol@laptop".into(),
                requests: vec![
                    CapRequest {
                        kind: SIGN,
                        arg: "deploy-key".into(),
                    },
                    CapRequest {
                        kind: FS_READ,
                        arg: path.to_string_lossy().into_owned(),
                    },
                ],
                action: Action {
                    name: "guest-demo".into(),
                    source: ActionSource::Wasm(component_bytes.clone()),
                },
            };
            // The component (WASI) runtime uses wasmtime's SYNC linker, which refuses to run under an
            // ambient tokio runtime. Run it on a plain thread with a bare parker executor (tokio
            // Handle *entered* only so tokio-based caps like fs.read still find a reactor).
            let w = warden.clone();
            let h = tokio::runtime::Handle::current();
            std::thread::spawn(move || {
                let _enter = h.enter();
                block_on_bare(w.run_session(component_session, "component"))
            })
            .join()
            .expect("component thread")?;
        }
    }

    // ── 7. transport: the same governed session, over the wire ──────────────────────────────────
    // A client connects, names an action from the catalog, and watches the event stream come back —
    // the client's live view IS the record (post-mask). Same warden, same chokepoint, now remote.
    println!("\n== 7. transport: the session boundary over QUIC ==");
    if guest_bytes.is_none() {
        println!("  (skipped — needs the guest build, see above)");
    } else {
        // `bind` drives its own internal runtime with `block_on`, which cannot run on a tokio worker
        // thread — do it off-worker via spawn_blocking.
        let transport = Arc::new(
            tokio::task::spawn_blocking(|| QuicTransport::bind("127.0.0.1:0", catalog(), 100))
                .await
                .expect("bind task")
                .expect("bind"),
        );
        let addr = transport.local_addr();
        println!("  warden listening on {addr} (one session)");
        {
            let (w, t) = (warden.clone(), transport.clone());
            let server = tokio::spawn(async move {
                match t.accept().await {
                    Ok(Accepted::Session(inc)) => run_incoming_bare(w, inc).await,
                    Ok(Accepted::Kill { .. }) => {}
                    Err(e) => eprintln!("  [server] refused: {e}"),
                }
            });
            let request = WireRequest::Session {
                identity: "carol@web".into(),
                requests: vec![
                    WireCapRequest {
                        kind: "sign".into(),
                        arg: "deploy-key".into(),
                    },
                    WireCapRequest {
                        kind: "fs.read".into(),
                        arg: path.to_string_lossy().into_owned(),
                    },
                ],
                action: "guest-demo".into(),
            };
            let (events, outcome) = tokio::task::spawn_blocking(move || {
                warden_transport::connect(addr, &request, |ev| {
                    println!("  [client] {}", describe(ev))
                })
            })
            .await
            .expect("client task")
            .expect("connect");
            println!(
                "  [client] outcome: {outcome:?} — {} events streamed",
                events.len()
            );
            server.await.expect("server task");
        }

        // ── the kill switch: a runaway session, stopped mid-flight ──────────────────────────────
        // The kill lands in the session's own stream (the watching client sees it), and the next
        // capability call is refused — the action keeps its CPU, loses the world.
        println!("\n-- kill: a runaway `slow-read` session, killed by an operator --");
        {
            let (w, t) = (warden.clone(), transport.clone());
            let server = tokio::spawn(async move {
                for _ in 0..2 {
                    match t.accept().await {
                        Ok(Accepted::Session(inc)) => {
                            let w = w.clone();
                            tokio::spawn(async move { run_incoming_bare(w, inc).await });
                        }
                        Ok(Accepted::Kill { session, by, ack }) => ack(w.kill(session, &by)),
                        Err(e) => eprintln!("  [server] refused: {e}"),
                    }
                }
            });
            let victim = {
                let victim_path = path.to_string_lossy().into_owned();
                tokio::task::spawn_blocking(move || {
                    let request = WireRequest::Session {
                        identity: "carol@web".into(),
                        requests: vec![WireCapRequest {
                            kind: "fs.read".into(),
                            arg: victim_path,
                        }],
                        action: "slow-read".into(),
                    };
                    warden_transport::connect(addr, &request, |ev| {
                        println!("  [client] {}", describe(ev))
                    })
                    .expect("connect")
                })
            };
            tokio::time::sleep(std::time::Duration::from_millis(350)).await;
            let found = tokio::task::spawn_blocking(move || {
                warden_transport::kill(addr, 101, "operator@gateway").expect("kill")
            })
            .await
            .expect("kill task");
            println!("  [operator] kill session 101 → delivered: {found}");
            let (_, outcome) = victim.await.expect("client task");
            println!("  [client] outcome: {outcome:?}");
            server.await.expect("server task");
        }
    }

    // ── 8. the gateway: the remote axis (warden dials out, client routes by name) ───────────────
    println!("\n== 8. gateway: the remote axis — reverse tunnel + fleet routing ==");
    if guest_bytes.is_none() {
        println!("  (skipped — needs the guest build, see above)");
    } else {
        // gateway on its own UDP port; a warden dials OUT to it (no inbound port on the warden)
        let gw = warden_transport::free_udp_addr().expect("free udp port");
        std::thread::spawn(move || warden_gateway::serve(&gw.to_string()));
        std::thread::sleep(std::time::Duration::from_millis(150));

        // this warden already served demos 1-7 locally; now it also tunnels out as "prod-1".
        // `connect` drives its own internal runtime with `block_on` → run it off the tokio worker.
        let tunnel = Arc::new(
            tokio::task::spawn_blocking(move || QuicTunnel::connect(gw, "prod-1", catalog(), 3000))
                .await
                .expect("tunnel task")
                .expect("tunnel connect"),
        );
        println!(
            "  warden 'prod-1' dialed out to the gateway at {gw} (no inbound port on the warden)"
        );
        {
            // serve exactly the one session the client routes here (the ghost request below is
            // refused at the gateway and never reaches this warden)
            let (w, t) = (warden.clone(), tunnel.clone());
            let server = tokio::spawn(async move {
                match t.accept().await {
                    Ok(Accepted::Session(inc)) => run_incoming_bare(w, inc).await,
                    Ok(Accepted::Kill { session, by, ack }) => ack(w.kill(session, &by)),
                    Err(e) => eprintln!("  [prod-1] {e}"),
                }
            });

            let client_path = path.to_string_lossy().into_owned();
            let client = tokio::task::spawn_blocking(move || {
                let request = WireRequest::Session {
                    identity: "carol@web".into(),
                    requests: vec![
                        WireCapRequest {
                            kind: "sign".into(),
                            arg: "deploy-key".into(),
                        },
                        WireCapRequest {
                            kind: "fs.read".into(),
                            arg: client_path,
                        },
                    ],
                    action: "guest-demo".into(),
                };

                println!("\n-- client routes to 'prod-1' through the gateway --");
                let (events, outcome) =
                    warden_transport::connect_via(gw, "prod-1", &request, |ev| {
                        println!("  [client] {}", describe(ev))
                    })
                    .expect("connect_via");
                println!(
                    "  [client] outcome: {outcome:?} — {} events, all through the tunnel",
                    events.len()
                );

                println!("\n-- client routes to an unknown warden → gateway refuses --");
                let (_, bad) = warden_transport::connect_via(gw, "ghost", &request, |_| {})
                    .expect("connect_via");
                println!("  [client] outcome: {bad:?}");
            });
            client.await.expect("client task");
            server.await.expect("server task");
        }
    }

    // ── 9. pty: a real shell's I/O flows through the chokepoint (masked, recorded) ───────────────
    // This is the kedi substrate: keystrokes would be `input` ops, the output stream is governed
    // exactly like any capability result. Here a one-shot shell command prints a secret → masked.
    println!("\n== 9. pty capability: a shell session, governed ==");
    let pty_session = Session {
        id: SessionId(9),
        identity: "carol@laptop".into(),
        requests: vec![CapRequest {
            kind: PTY,
            arg: "printf 'hello from the shell\\nAWS_SECRET=hunter2\\n'".into(),
        }],
        action: Action {
            name: "shell".into(),
            source: ActionSource::InProcess(warden_core::action_fn(|ctx: &Ctx| {
                Box::pin(async move {
                    let pty = ctx
                        .cap(PTY)
                        .ok_or(WardenError::Cap("no pty granted".into()))?;
                    ctx.invoke(pty, "wait", vec![]).await?; // let the one-shot shell run to completion
                    Ok(())
                })
            })),
        },
    };
    warden.run_session(pty_session, "demo").await?;
    println!("  (the shell's stdout streamed through warden — the secret masked in the record)");

    // ── 10. the record: verify the chain, replay the timeline, rewind, catch tampering ──────────
    println!("\n== 10. the record: verify · replay · rewind · tamper-evidence ==");
    file_rec.flush(); // recording is async — drain the queue before reading the file back
    println!("  file: {}", rec_path.display());
    println!("  chain head (anchor this externally): {}", file_rec.head());
    println!();
    if let Err(e) = replay(rec_path.to_str().unwrap(), None) {
        println!("  !! record did not verify: {e}");
    }

    // rewind: the moment the exec child's output landed — session still open, cap still held
    let events = warden_record::load(&rec_path).expect("just verified");
    let k = events
        .iter()
        .rposition(|e| matches!(e, RecEvent::Result { .. }))
        .map(|i| i + 1)
        .unwrap_or(events.len());
    println!("\n-- rewind to #{k}: the moment the last output landed --");
    print_state(&events, k);

    // tamper: doctor the recorded exec args ("deploy" -> "delete", same length, valid hex+JSON) —
    // the forged line parses fine, but the next line's prev-hash betrays it
    println!("\n-- tamper: a doctored copy claims `delete` was run instead of `deploy` --");
    let tampered = std::env::temp_dir().join("warden-session-tampered.jsonl");
    let txt = std::fs::read_to_string(&rec_path).unwrap();
    let doctored = txt.replacen("6465706c6f79", "64656c657465", 1); // hex("deploy") -> hex("delete")
    std::fs::write(&tampered, doctored).unwrap();
    match warden_record::load(&tampered) {
        Err(e) => println!("  detected: {e}"),
        Ok(_) => println!("  !! tamper not detected"),
    }

    println!(
        "\nok — fs + exec governed · runtimes interchangeable · record verified, rewindable, tamper-evident."
    );
    println!(
        "     (replay it yourself: cargo run -q -- replay {} [at])",
        rec_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Clone, Default)]
    struct VecRecorder(Arc<Mutex<Vec<Event>>>);
    impl Recorder for VecRecorder {
        fn record(&self, ev: Event) {
            self.0.lock().unwrap().push(ev);
        }
    }

    fn ev_kinds(evs: &[Event]) -> Vec<&'static str> {
        evs.iter()
            .map(|e| match e {
                Event::SessionOpened { .. } => "open",
                Event::CapGranted { .. } => "grant",
                Event::Call { .. } => "call",
                Event::Result { .. } => "result",
                Event::Output { .. } => "output",
                Event::Failed { .. } => "failed",
                Event::Denied { .. } => "denied",
                Event::EscalationRequested { .. } => "escalate",
                Event::Approved { .. } => "approved",
                Event::Rejected { .. } => "rejected",
                Event::Killed { .. } => "killed",
                Event::Revoked { .. } => "revoked",
                Event::SessionClosed { .. } => "close",
            })
            .collect()
    }

    #[tokio::test]
    async fn mediates_records_and_masks() {
        let path = std::env::temp_dir().join("warden-spike-test.txt");
        std::fs::write(&path, "x\nSECRET=hunter2\n").unwrap();

        let rec = VecRecorder::default();
        let warden = build_warden(vec![Arc::new(rec.clone())]);

        let got: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let got2 = got.clone();
        let action = Action {
            name: "t".into(),
            source: ActionSource::InProcess(warden_core::action_fn(move |ctx: &Ctx| {
                let got2 = got2.clone();
                Box::pin(async move {
                    let fs = ctx.cap(FS_READ).unwrap();
                    *got2.lock().unwrap() = ctx.invoke(fs, "read", vec![]).await?;
                    Ok(())
                })
            })),
        };
        let session = Session {
            id: SessionId(7),
            identity: "test".into(),
            requests: vec![CapRequest {
                kind: FS_READ,
                arg: path.to_string_lossy().into_owned(),
            }],
            action,
        };
        warden.run_session(session, "demo").await.unwrap();

        // the masked output reached the action; the raw secret never did
        let out = String::from_utf8(got.lock().unwrap().clone()).unwrap();
        assert!(out.contains("*******"), "secret should be masked: {out}");
        assert!(!out.contains("hunter2"), "raw secret leaked: {out}");

        // the structured record captured the full governed flow, in order
        let evs = rec.0.lock().unwrap();
        assert_eq!(
            ev_kinds(&evs),
            vec!["open", "grant", "call", "result", "revoked", "close"]
        );
    }

    #[tokio::test]
    async fn exec_grant_refused_on_hash_mismatch() {
        let rec = VecRecorder::default();
        let warden = build_warden(vec![Arc::new(rec.clone())]);

        let session = Session {
            id: SessionId(8),
            identity: "test".into(),
            requests: vec![CapRequest {
                kind: EXEC,
                arg: format!("/bin/echo@sha256:{}", "0".repeat(64)),
            }],
            action: Action {
                name: "n".into(),
                source: ActionSource::InProcess(warden_core::action_fn(|_| {
                    Box::pin(async move { Ok(()) })
                })),
            },
        };
        let err = warden.run_session(session, "demo").await.unwrap_err();
        assert!(
            err.to_string().contains("grant refused"),
            "unexpected error: {err}"
        );

        // audit integrity: the failed session is still opened AND closed in the record — with the
        // escalation round-trip (exec grants are policy-escalated) on record before the refusal
        let evs = rec.0.lock().unwrap();
        assert_eq!(
            ev_kinds(&evs),
            vec!["open", "escalate", "approved", "close"]
        );
    }

    #[tokio::test]
    async fn pty_output_streams_through_the_chokepoint_masked() {
        let rec = VecRecorder::default();
        let warden = build_warden(vec![Arc::new(rec.clone())]);

        let session = Session {
            id: SessionId(14),
            identity: "test".into(),
            requests: vec![CapRequest {
                kind: PTY,
                arg: "printf 'X\\nSECRET=hunter2\\n'".into(),
            }],
            action: Action {
                name: "t".into(),
                source: ActionSource::InProcess(warden_core::action_fn(|ctx: &Ctx| {
                    Box::pin(async move {
                        let pty = ctx.cap(PTY).unwrap();
                        ctx.invoke(pty, "wait", vec![]).await?; // one-shot shell self-exits
                        Ok(())
                    })
                })),
            },
        };
        warden.run_session(session, "demo").await.unwrap();

        // the shell's stdout arrived as Output events, DLP-masked, and never held the raw secret
        let evs = rec.0.lock().unwrap();
        let out: String = evs
            .iter()
            .filter_map(|e| match e {
                Event::Output { bytes, .. } => Some(String::from_utf8_lossy(bytes).into_owned()),
                _ => None,
            })
            .collect();
        assert!(out.contains('X'), "expected shell output, got: {out:?}");
        assert!(
            out.contains("SECRET=*******"),
            "pty output should be masked: {out:?}"
        );
        assert!(
            !out.contains("hunter2"),
            "raw secret leaked from the pty: {out:?}"
        );
    }

    #[tokio::test]
    async fn pty_interactive_input_round_trips_masked() {
        use futures::StreamExt;
        use warden_core::{Incoming, InputFrame};

        let rec = VecRecorder::default();
        let warden = build_warden(vec![Arc::new(rec.clone())]);

        // `cat` as a minimal, portable interactive "shell": the pty echoes typed input and cat
        // re-emits each line; ^D (EOF) ends it. The "attach" action loops client input into the pty
        // until the client disconnects (input channel closes).
        let session = Session {
            id: SessionId(15),
            identity: "test".into(),
            requests: vec![CapRequest {
                kind: PTY,
                arg: "cat".into(),
            }],
            action: Action {
                name: "attach".into(),
                source: ActionSource::InProcess(warden_core::action_fn(|ctx: &Ctx| {
                    Box::pin(async move {
                        let pty = ctx.cap(PTY).ok_or(WardenError::Cap("no pty".into()))?;
                        let mut input = ctx
                            .take_input()
                            .ok_or(WardenError::Cap("no input channel".into()))?;
                        while let Some(frame) = input.next().await {
                            ctx.invoke(pty, &frame.op, frame.data).await?;
                        }
                        Ok(())
                    })
                })),
            },
        };

        let (tx, rx) = futures::channel::mpsc::unbounded::<InputFrame>();
        let inc = Incoming {
            session,
            runtime: "demo".to_string(),
            observer: None,
            input: Some(Box::pin(rx)),
            done: Box::new(|_| {}),
        };

        let feed = async move {
            // type a line containing a secret, then ^D to end cat; drop tx → attach loop ends
            tx.unbounded_send(InputFrame {
                op: "input".into(),
                data: b"token=hunter2\n".to_vec(),
            })
            .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            tx.unbounded_send(InputFrame {
                op: "input".into(),
                data: vec![0x04],
            })
            .unwrap(); // ^D
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            drop(tx);
        };
        tokio::join!(warden.run_incoming(inc), feed);

        // the shell's echoed keystrokes + command output streamed back through the chokepoint,
        // DLP-masked; the raw secret is nowhere in the record
        let evs = rec.0.lock().unwrap();
        let out: String = evs
            .iter()
            .filter_map(|e| match e {
                Event::Output { bytes, .. } => Some(String::from_utf8_lossy(bytes).into_owned()),
                _ => None,
            })
            .collect();
        assert!(
            out.contains("*******"),
            "expected masked output, got: {out:?}"
        );
        assert!(
            !out.contains("hunter2"),
            "raw secret leaked from interactive pty: {out:?}"
        );
    }

    #[tokio::test]
    async fn intern_exec_is_rejected_by_quorum() {
        let rec = VecRecorder::default();
        let warden = build_warden(vec![Arc::new(rec.clone())]);
        let pin = sha256_hex_of("/bin/echo").unwrap();

        let session = Session {
            id: SessionId(12),
            identity: "intern@laptop".into(),
            requests: vec![CapRequest {
                kind: EXEC,
                arg: format!("/bin/echo@sha256:{pin}"),
            }],
            action: Action {
                name: "n".into(),
                source: ActionSource::InProcess(warden_core::action_fn(|_| {
                    Box::pin(async move { Ok(()) })
                })),
            },
        };
        let err = warden.run_session(session, "demo").await.unwrap_err();
        assert!(
            err.to_string().contains("may not run binaries"),
            "unexpected error: {err}"
        );

        // the rejection is a first-class, attributed audit event — no grant ever happened
        let evs = rec.0.lock().unwrap();
        assert_eq!(
            ev_kinds(&evs),
            vec!["open", "escalate", "rejected", "close"]
        );
        assert!(
            evs.iter()
                .any(|e| matches!(e, Event::Rejected { by, .. } if by == "bob")),
            "rejection must name the rejecting approver"
        );
    }

    #[tokio::test]
    async fn session_routed_through_gateway_still_enforces() {
        let path = std::env::temp_dir().join("warden-gw-test.txt");
        std::fs::write(&path, "gw\nTOKEN=hunter2\n").unwrap();

        let rec = VecRecorder::default();
        let warden = build_warden(vec![Arc::new(rec.clone())]);
        let cat: Catalog = Arc::new(|name| match name {
            "read-config" => Ok((
                ActionSource::InProcess(warden_core::action_fn(|ctx: &Ctx| {
                    Box::pin(async move {
                        let fs = ctx.cap(FS_READ).unwrap();
                        ctx.invoke(fs, "read", vec![]).await.map(drop)
                    })
                })),
                "demo".to_string(),
            )),
            other => Err(WardenError::Cap(format!("not in catalog: {other}"))),
        });

        // gateway on a free port
        let gw = warden_transport::free_udp_addr().unwrap();
        std::thread::spawn(move || warden_gateway::serve(&gw.to_string()));
        std::thread::sleep(std::time::Duration::from_millis(150));

        // warden dials out and registers "prod-1" (own runtime `block_on` → off the tokio worker)
        let tunnel = tokio::task::spawn_blocking(move || {
            QuicTunnel::connect(gw, "prod-1", cat, 3000).unwrap()
        })
        .await
        .unwrap();

        let server = async {
            match tunnel.accept().await.unwrap() {
                Accepted::Session(inc) => warden.run_incoming(inc).await,
                Accepted::Kill { .. } => panic!("expected a session"),
            }
        };
        let client = tokio::task::spawn_blocking(move || {
            let request = WireRequest::Session {
                identity: "web-user".into(),
                requests: vec![WireCapRequest {
                    kind: "fs.read".into(),
                    arg: path.to_string_lossy().into_owned(),
                }],
                action: "read-config".into(),
            };
            let (events, outcome) =
                warden_transport::connect_via(gw, "prod-1", &request, |_| {}).unwrap();
            assert!(outcome.is_ok(), "routed session failed: {outcome:?}");

            // the warden enforced end-to-end over the tunnel: masked output, no raw secret
            let outputs: Vec<String> = events
                .iter()
                .filter_map(|e| match e {
                    RecEvent::Result { output, .. } => {
                        Some(String::from_utf8_lossy(output).into_owned())
                    }
                    _ => None,
                })
                .collect();
            assert!(
                outputs.iter().any(|o| o.contains("TOKEN=*******")),
                "masked output missing: {outputs:?}"
            );
            assert!(
                outputs.iter().all(|o| !o.contains("hunter2")),
                "raw secret through gateway: {outputs:?}"
            );

            // routing to an unknown warden is refused by the gateway
            let (_, bad) = warden_transport::connect_via(gw, "ghost", &request, |_| {}).unwrap();
            assert!(bad.is_err(), "unknown warden must be refused");
        });
        let (_, client) = tokio::join!(server, client);
        client.expect("client task");
    }

    #[tokio::test]
    async fn session_over_quic_streams_the_masked_record() {
        let path = std::env::temp_dir().join("warden-wire-test.txt");
        std::fs::write(&path, "wire\nPIN=hunter2\n").unwrap();

        let rec = VecRecorder::default();
        let warden = build_warden(vec![Arc::new(rec.clone())]);

        // catalog with an in-process action so this test doesn't depend on the guest artifact
        let catalog: Catalog = Arc::new(|name| match name {
            "read-config" => Ok((
                ActionSource::InProcess(warden_core::action_fn(|ctx: &Ctx| {
                    Box::pin(async move {
                        let fs = ctx.cap(FS_READ).unwrap();
                        ctx.invoke(fs, "read", vec![]).await.map(drop)
                    })
                })),
                "demo".to_string(),
            )),
            other => Err(WardenError::Cap(format!("not in catalog: {other}"))),
        });
        // `bind` drives its own runtime with `block_on`; keep it off the tokio worker.
        let transport = tokio::task::spawn_blocking(move || {
            QuicTransport::bind("127.0.0.1:0", catalog, 500).unwrap()
        })
        .await
        .unwrap();
        let addr = transport.local_addr();

        let server = async {
            let inc = match transport.accept().await.unwrap() {
                Accepted::Session(inc) => inc,
                Accepted::Kill { .. } => panic!("expected a session"),
            };
            warden.run_incoming(inc).await;
        };
        let client = tokio::task::spawn_blocking(move || {
            let request = WireRequest::Session {
                identity: "wire-test".into(),
                requests: vec![WireCapRequest {
                    kind: "fs.read".into(),
                    arg: path.to_string_lossy().into_owned(),
                }],
                action: "read-config".into(),
            };
            let (events, outcome) = warden_transport::connect(addr, &request, |_| {}).unwrap();
            assert!(outcome.is_ok(), "session failed: {outcome:?}");

            // the client's stream is the record: masked result present, raw secret absent
            let outputs: Vec<String> = events
                .iter()
                .filter_map(|e| match e {
                    RecEvent::Result { output, .. } => {
                        Some(String::from_utf8_lossy(output).into_owned())
                    }
                    _ => None,
                })
                .collect();
            assert!(
                outputs.iter().any(|o| o.contains("PIN=*******")),
                "masked output missing: {outputs:?}"
            );
            assert!(
                outputs.iter().all(|o| !o.contains("hunter2")),
                "raw secret crossed the wire: {outputs:?}"
            );
            // unknown action is refused autonomously by the transport (never reaches accept())
            let bad = WireRequest::Session {
                identity: "wire-test".into(),
                requests: vec![],
                action: "nope".into(),
            };
            let (_, bad_outcome) = warden_transport::connect(addr, &bad, |_| {}).unwrap();
            assert!(bad_outcome.is_err(), "unknown action must be refused");
        });
        let (_, client) = tokio::join!(server, client);
        client.expect("client task");
    }

    #[tokio::test]
    async fn kill_severs_a_live_session_mid_flight() {
        let path = std::env::temp_dir().join("warden-kill-test.txt");
        std::fs::write(&path, "x\n").unwrap();

        let rec = VecRecorder::default();
        let warden = Arc::new(build_warden(vec![Arc::new(rec.clone())]));

        // an action that loops on a capability until the world stops answering
        let catalog: Catalog = Arc::new(|name| match name {
            "loop-read" => Ok((
                ActionSource::InProcess(warden_core::action_fn(|ctx: &Ctx| {
                    Box::pin(async move {
                        let fs = ctx.cap(FS_READ).unwrap();
                        loop {
                            ctx.invoke(fs, "read", vec![]).await?; // Err once killed → action ends
                            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                        }
                    })
                })),
                "demo".to_string(),
            )),
            other => Err(WardenError::Cap(format!("not in catalog: {other}"))),
        });
        let transport = Arc::new(
            tokio::task::spawn_blocking(move || {
                QuicTransport::bind("127.0.0.1:0", catalog, 900).unwrap()
            })
            .await
            .unwrap(),
        );
        let addr = transport.local_addr();

        let server = {
            let (w, t) = (warden.clone(), transport.clone());
            tokio::spawn(async move {
                for _ in 0..2 {
                    match t.accept().await {
                        Ok(Accepted::Session(inc)) => {
                            let w = w.clone();
                            tokio::spawn(async move { w.run_incoming(inc).await });
                        }
                        Ok(Accepted::Kill { session, by, ack }) => ack(w.kill(session, &by)),
                        Err(e) => panic!("accept: {e}"),
                    }
                }
            })
        };
        let victim = {
            let victim_path = path.to_string_lossy().into_owned();
            tokio::task::spawn_blocking(move || {
                let request = WireRequest::Session {
                    identity: "runaway".into(),
                    requests: vec![WireCapRequest {
                        kind: "fs.read".into(),
                        arg: victim_path,
                    }],
                    action: "loop-read".into(),
                };
                warden_transport::connect(addr, &request, |_| {}).unwrap()
            })
        };
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let killed =
            tokio::task::spawn_blocking(move || warden_transport::kill(addr, 900, "op").unwrap())
                .await
                .expect("kill task");
        assert!(killed, "session should be live");
        let (events, outcome) = victim.await.expect("victim task");

        // the loop was cut: session failed with the kill, and the client's own stream shows it
        assert!(
            matches!(&outcome, Err(e) if e.contains("killed by op")),
            "outcome: {outcome:?}"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, RecEvent::Killed { by, .. } if by == "op")),
            "kill must appear in the session's stream"
        );
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn exec_child_stdout_is_masked() {
        let rec = VecRecorder::default();
        let warden = build_warden(vec![Arc::new(rec.clone())]);
        let pin = sha256_hex_of("/bin/echo").unwrap();

        let got: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let got2 = got.clone();
        let session = Session {
            id: SessionId(9),
            identity: "test".into(),
            requests: vec![CapRequest {
                kind: EXEC,
                arg: format!("/bin/echo@sha256:{pin}"),
            }],
            action: Action {
                name: "t".into(),
                source: ActionSource::InProcess(warden_core::action_fn(move |ctx: &Ctx| {
                    let got2 = got2.clone();
                    Box::pin(async move {
                        let x = ctx.cap(EXEC).unwrap();
                        *got2.lock().unwrap() =
                            ctx.invoke(x, "run", b"PASS=hunter2".to_vec()).await?;
                        Ok(())
                    })
                })),
            },
        };
        warden.run_session(session, "demo").await.unwrap();

        let out = String::from_utf8(got.lock().unwrap().clone()).unwrap();
        assert!(
            out.contains("PASS=*******"),
            "child stdout should be masked: {out}"
        );
        assert!(
            !out.contains("hunter2"),
            "raw secret leaked from child: {out}"
        );
    }

    #[tokio::test]
    async fn sign_works_but_key_never_reaches_action_or_record() {
        let rec = VecRecorder::default();
        let warden = build_warden(vec![Arc::new(rec.clone())]);

        let session = Session {
            id: SessionId(10),
            identity: "test".into(),
            requests: vec![CapRequest {
                kind: SIGN,
                arg: "deploy-key".into(),
            }],
            action: Action {
                name: "t".into(),
                source: ActionSource::InProcess(warden_core::action_fn(|ctx: &Ctx| {
                    Box::pin(async move {
                        let s = ctx.cap(SIGN).unwrap();
                        let mac = ctx.invoke(s, "sign", b"payload".to_vec()).await?;
                        assert_eq!(mac.len(), 64, "hex hmac-sha256");
                        assert!(
                            ctx.invoke(s, "reveal", vec![]).await.is_err(),
                            "reveal must be refused"
                        );
                        Ok(())
                    })
                })),
            },
        };
        warden.run_session(session, "demo").await.unwrap();

        // the key material appears in NO recorded event, in no form
        for ev in rec.0.lock().unwrap().iter() {
            let dump = format!("{ev:?}");
            assert!(
                !dump.contains("k9-signing-key-material"),
                "key leaked into the record: {dump}"
            );
        }
    }

    #[tokio::test]
    async fn component_guest_holds_handles_not_secrets() {
        let guest_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../guest/target/wasm32-wasip2/release/warden_guest_demo.wasm"
        );
        let Ok(component) = std::fs::read(guest_path) else {
            eprintln!(
                "skipped: guest not built (cd guest && cargo build --release --target wasm32-wasip2)"
            );
            return;
        };

        let path = std::env::temp_dir().join("warden-component-test.txt");
        std::fs::write(&path, "cfg\nTOKEN=hunter2\n").unwrap();

        let rec = VecRecorder::default();
        let warden = build_warden(vec![Arc::new(rec.clone())]);
        let session = Session {
            id: SessionId(11),
            identity: "test".into(),
            requests: vec![
                CapRequest {
                    kind: SIGN,
                    arg: "deploy-key".into(),
                },
                CapRequest {
                    kind: FS_READ,
                    arg: path.to_string_lossy().into_owned(),
                },
            ],
            action: Action {
                name: "guest".into(),
                source: ActionSource::Wasm(component),
            },
        };
        let warden = Arc::new(warden);
        {
            let w = warden.clone();
            let h = tokio::runtime::Handle::current();
            std::thread::spawn(move || {
                let _enter = h.enter(); // reactor for tokio-based caps (fs.read); not a driver ctx
                block_on_bare(w.run_session(session, "component"))
            })
            .join()
            .expect("component thread")
            .unwrap();
        }

        // every byte that crossed into the guest is on record — masked, and key-free
        let evs = rec.0.lock().unwrap();
        let outputs: Vec<String> = evs
            .iter()
            .filter_map(|e| match e {
                Event::Result { output, .. } => Some(String::from_utf8_lossy(output).into_owned()),
                _ => None,
            })
            .collect();
        assert!(
            outputs.iter().any(|o| o.contains("TOKEN=*******")),
            "masked read missing: {outputs:?}"
        );
        for o in &outputs {
            assert!(!o.contains("hunter2"), "raw secret reached the guest: {o}");
            assert!(
                !o.contains("k9-signing-key-material"),
                "key reached the guest: {o}"
            );
        }
        // and the guest's refused `reveal` is in the trail — now a governance Denied (the op isn't
        // in `sign`'s published contract), recorded centrally by the kernel, not a per-cap error
        assert!(
            evs.iter()
                .any(|e| matches!(e, Event::Denied { why, .. } if why.contains("no op `reveal`"))),
            "refused reveal not recorded"
        );
    }
}
