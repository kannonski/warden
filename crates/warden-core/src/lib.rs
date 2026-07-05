//! warden-core — the sans-IO kernel.
//!
//! One primitive: an **action can only touch the world through capabilities the warden grants,
//! mediates, and logs**. That single chokepoint is [`Ctx::invoke`], which drives the [`Interceptor`]
//! chain (audit · DLP · record · policy) around a [`Capability`]'s raw op. Everything else is a seam:
//! [`Runtime`], [`Broker`], [`Policy`], [`Approver`], [`Interceptor`], [`Recorder`], [`Transport`],
//! [`Capability`].
//!
//! No IO lives here — concrete impls live in sibling crates. Sync in this spike for clarity; the real
//! thing is async (streams + IO), which changes the signatures, not the shape.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

// ── ids & core types ────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(pub u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CapId(pub u64);
/// The kind of a capability — the extension axis. `"fs.read"`, `"exec"`, `"sql"`, `"http"`, `"sign"`…
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapKind(pub &'static str);

#[derive(Debug)]
pub enum WardenError {
    Denied(String),
    NotGranted(CapId),
    NoBroker(CapKind),
    NoRuntime(String),
    Cap(String),
}
impl fmt::Display for WardenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WardenError::Denied(w) => write!(f, "denied: {w}"),
            WardenError::NotGranted(c) => write!(f, "capability {c:?} not granted"),
            WardenError::NoBroker(k) => write!(f, "no broker for capability {}", k.0),
            WardenError::NoRuntime(n) => write!(f, "no runtime {n}"),
            WardenError::Cap(m) => write!(f, "capability error: {m}"),
        }
    }
}
impl std::error::Error for WardenError {}
pub type Result<T> = std::result::Result<T, WardenError>;

/// One capability operation crossing the chokepoint.
#[derive(Clone, Debug)]
pub struct Call {
    pub session: SessionId,
    pub cap: CapId,
    pub kind: CapKind,
    pub op: String,
    /// Whether this op mutates the world, from the capability's [`OpSpec`]. Lets [`Policy::on_call`]
    /// reason about read-vs-write without matching op strings it can't verify.
    pub mutates: bool,
    pub input: Vec<u8>,
}
#[derive(Clone, Debug)]
pub struct CallResult {
    pub output: Vec<u8>,
}

/// A policy outcome. `Escalate` suspends the operation until an [`Approver`] resolves it —
/// approval is a *policy verb*, not a subsystem.
#[derive(Clone, Debug)]
pub enum Decision {
    Allow,
    Deny(String),
    /// Needs approval before proceeding; the string is the reason shown to approvers.
    Escalate(String),
}

/// An escalation in flight, as shown to approvers.
#[derive(Clone, Debug)]
pub struct ApprovalRequest {
    pub session: SessionId,
    pub identity: String,
    /// What is being asked ("grant exec /bin/echo@sha256:…", "call `drop` on sql").
    pub subject: String,
    /// Why policy escalated it.
    pub reason: String,
}

/// An approver's verdict. Multi-party quorums, timeouts, and per-approver audit live in impls.
#[derive(Clone, Debug)]
pub enum Verdict {
    Approved { by: Vec<String> },
    Rejected { by: String, why: String },
}

/// What an action asks for before it runs — resolved by a [`Broker`] into a live [`Capability`].
#[derive(Clone, Debug)]
pub struct CapRequest {
    pub kind: CapKind,
    pub arg: String, // e.g. the file path for fs.read
}

/// The structured, append-only event stream → the audit trail and the basis for replay/rewind.
///
/// Payloads are recorded, not just lengths — rewind means re-showing what was seen. `Result`
/// carries the *post-interceptor* output (masked — the trail never holds the raw secret on the way
/// out). `Call` carries the action's true request; if that request itself embeds a secret, that's
/// the secrets-in-args antipattern the secret-broker capability exists to remove (args then carry
/// a handle, never the secret). Every call ends in exactly one of `Result` / `Failed` / `Denied`.
#[derive(Clone, Debug)]
pub enum Event {
    SessionOpened {
        session: SessionId,
        identity: String,
    },
    CapGranted {
        session: SessionId,
        cap: CapId,
        kind: CapKind,
    },
    Call {
        session: SessionId,
        seq: u64,
        cap: CapId,
        op: String,
        input: Vec<u8>,
    },
    Result {
        session: SessionId,
        seq: u64,
        output: Vec<u8>,
    },
    /// A chunk of a capability's *streamed* output (e.g. a pty), post-mask, as it is produced.
    Output {
        session: SessionId,
        cap: CapId,
        bytes: Vec<u8>,
    },
    Failed {
        session: SessionId,
        seq: u64,
        error: String,
    },
    Denied {
        session: SessionId,
        subject: String,
        why: String,
    },
    EscalationRequested {
        session: SessionId,
        subject: String,
        reason: String,
    },
    Approved {
        session: SessionId,
        subject: String,
        by: Vec<String>,
    },
    Rejected {
        session: SessionId,
        subject: String,
        by: String,
        why: String,
    },
    /// The session was killed mid-flight; every later capability call is refused.
    Killed {
        session: SessionId,
        by: String,
    },
    Revoked {
        session: SessionId,
        cap: CapId,
    },
    SessionClosed {
        session: SessionId,
    },
}

// ── the seams (nine traits, five concerns — see docs/DESIGN.md §4) ────────────────────────────

/// One operation a capability accepts — its self-description. A capability publishes its full op set
/// via [`Capability::ops`], which makes ops *enumerable* (a UI/audit can list them), lets the kernel
/// reject an unknown op centrally (§ `Ctx::invoke`) instead of every impl hand-rolling the check, and
/// gives [`Policy`] a typed handle (`mutates`) so it can reason about read-vs-write without matching
/// on op strings it can't verify. The `op` stays a string because ops cross the wire and the WASM
/// ABI as strings; `ops()` is the *contract* those strings are validated against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpSpec {
    /// The op name — the string passed to [`Capability::perform`].
    pub op: &'static str,
    /// One line for a human, a UI, or the audit trail.
    pub doc: &'static str,
    /// Whether the op changes the world (write/exec/spawn) vs. only observes it (read). Policy can
    /// key on this — e.g. deny every mutating op for a read-only identity — without knowing op names.
    pub mutates: bool,
}

/// The uniform "unknown op" error, shared so every capability rejects an out-of-contract op the same
/// way. The kernel validates ops centrally before calling `perform` (so this is the primary guard),
/// but a capability can call this as defense-in-depth — which also keeps it testable in isolation,
/// outside a kernel that would have rejected the op first.
pub fn no_such_op(kind: CapKind, op: &str) -> WardenError {
    WardenError::Cap(format!("`{}` has no op `{op}`", kind.0))
}

/// A granted, mediated resource — THE extension axis. `perform` is the *raw* op; the kernel wraps
/// every call through the interceptor chain, so impls never do policy/audit/masking themselves.
pub trait Capability: Send + Sync {
    fn kind(&self) -> CapKind;
    /// The operations this capability accepts — its published contract (see [`OpSpec`]). The kernel
    /// validates every `perform`'s `op` against this set, so impls no longer hand-roll an
    /// "unknown op" arm. Should be a stable `&'static` slice.
    fn ops(&self) -> &'static [OpSpec];
    fn perform(&self, op: &str, input: &[u8]) -> Result<Vec<u8>>;
    fn revoke(&self);
    /// An optional *continuous output* stream (e.g. a pty's byte stream). The kernel takes it once,
    /// drains it through the interceptor chain (masking), and records each chunk as `Event::Output`
    /// — so streamed output is governed exactly like a call's result. Default: no stream.
    fn output(&self) -> Option<std::sync::mpsc::Receiver<Vec<u8>>> {
        None
    }
    /// Whether the capability's underlying resource has ended on its own — e.g. a pty whose shell
    /// exited. An attach-style action that otherwise blocks waiting for client input polls this so
    /// the session ends (and the client's stream closes) when the shell dies, rather than lingering.
    /// Default: never self-finishes.
    fn finished(&self) -> bool {
        false
    }
}

/// Turns a [`CapRequest`] into a live [`Capability`] (for secrets: pull a short-lived cred from a
/// vault and return a handle the action can use but not read).
pub trait Broker: Send + Sync {
    fn handles(&self, req: &CapRequest) -> bool;
    fn grant(&self, req: &CapRequest) -> Result<Box<dyn Capability>>;
}

/// Decisions at session open · each cap request · each call. Pure logic, no IO.
pub trait Policy: Send + Sync {
    fn on_session(&self, s: &SessionCtx) -> Decision;
    fn on_request(&self, s: &SessionCtx, req: &CapRequest) -> Decision;
    fn on_call(&self, s: &SessionCtx, call: &Call) -> Decision;
}

/// Resolves escalations. The spike blocks synchronously; the product approver is asynchronous —
/// it parks the operation, pushes the request to humans (gateway UI, chat), and resumes on quorum.
/// Multi-party (N-of-M) approval is an impl of this seam, not a kernel feature.
pub trait Approver: Send + Sync {
    fn decide(&self, req: &ApprovalRequest) -> Verdict;
}

/// A stateful transform over one output stream's chunks (e.g. DLP masking a pty's bytes).
pub type OutputMasker = Box<dyn FnMut(Vec<u8>) -> Vec<u8> + Send>;

/// The mediation middleware — the chokepoint. Sees every call; may log, mask, meter, or deny.
pub trait Interceptor: Send + Sync {
    fn intercept(&self, call: Call, next: Next<'_>) -> Result<CallResult>;
    /// Build a fresh, STATEFUL masker for one output stream (e.g. a pty). It's per-stream so it can
    /// carry a tail across chunks and still catch a secret split across a read() boundary — the
    /// thing a stateless per-chunk transform cannot. Default: pass-through. The kernel folds every
    /// interceptor's masker over each chunk before recording it as `Event::Output`.
    fn output_masker(&self) -> OutputMasker {
        Box::new(|b| b)
    }
}

/// Append-only structured event sink → replay/rewind. Backend-pluggable.
pub trait Recorder: Send + Sync {
    fn record(&self, ev: Event);
}

// NOTE: there was a `SessionHook` seam here (on_open/on_close). It was parked — removed as a
// reserved kernel seam — because it had no real implementation (only a test counter), and a seam is
// a contract the kernel must keep stable: an unproven one is a liability, not an asset. The
// open/close *boundary* still exists in `run_full` (it records SessionOpened / SessionClosed via the
// SessionGuard); session-level governance (quotas, idle-timeout, handoff) will attach there when a
// real user forces the hook's shape. See docs/boundary.md.

/// How an action executes. Impls: an in-process demo (here), a WASM component host, a native process.
pub trait Runtime: Send + Sync {
    fn name(&self) -> &'static str;
    fn run(&self, action: Action, ctx: &Ctx) -> Result<()>;
}

/// How sessions arrive: local loopback, TCP, or a gateway reverse-tunnel. `accept` blocks until a
/// client has delivered a full request, then hands the kernel everything it needs to act on it.
/// The wire protocol is the transport's business; the kernel never sees bytes.
pub trait Transport: Send + Sync {
    fn accept(&self) -> Result<Accepted>;
}

/// What a transport accepted: a session to run, or a control verb.
pub enum Accepted {
    Session(Incoming),
    /// An operator kills a live session; `ack` tells them whether it was found.
    Kill {
        session: SessionId,
        by: String,
        ack: Box<dyn FnOnce(bool) + Send>,
    },
}

/// One accepted session, ready to run.
pub struct Incoming {
    pub session: Session,
    /// Which registered runtime executes it (the transport/catalog decides, not the client).
    pub runtime: String,
    /// The client's live view: observes this session's events as they happen (the client's
    /// "terminal" IS the event stream — it sees exactly what the record sees, post-mask).
    pub observer: Option<Arc<dyn Recorder>>,
    /// Async client→session input arriving DURING the session (keystrokes/resize for an interactive
    /// pty). The action drains it via [`Ctx::take_input`]. `None` for one-shot sessions.
    pub input: Option<std::sync::mpsc::Receiver<InputFrame>>,
    /// Called with the outcome once the session closes (reply + hang up).
    pub done: DoneCallback,
}

/// Callback invoked with the session outcome once it closes.
pub type DoneCallback = Box<dyn FnOnce(&Result<()>) + Send>;

/// A client→session message delivered mid-session (a terminal's keystrokes, a resize). `op`/`data`
/// map straight onto a capability op: `{op:"input", data:keystrokes}`, `{op:"resize", data:"80x24"}`.
#[derive(Clone, Debug)]
pub struct InputFrame {
    pub op: String,
    pub data: Vec<u8>,
}

// ── session & action ────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SessionCtx {
    pub id: SessionId,
    pub identity: String,
}

/// An action = something a [`Runtime`] runs. In the spike it's an in-process closure that uses the
/// [`Ctx`] to invoke capabilities; the WASM runtime will instead drive a component's WASI imports
/// into the same `ctx.invoke`.
pub type ActionFn = Box<dyn Fn(&Ctx) -> Result<()> + Send + Sync>;

/// Where an action's code comes from — runtime-agnostic. Each [`Runtime`] handles the variant(s) it
/// supports. A *new runtime* over an existing variant needs no core change (that's the swappability);
/// only a genuinely new code form adds a variant. Note: `Wasm` is just bytes — core has no wasm dep.
pub enum ActionSource {
    /// In-process Rust closure — the demo/test runtime.
    InProcess(ActionFn),
    /// A WebAssembly module/component — the wasm runtime.
    Wasm(Vec<u8>),
}
pub struct Action {
    pub name: String,
    pub source: ActionSource,
}

/// Resolves an action *name* into (source, runtime) — actions are named and validated server-side
/// (the same stance as exec's hash pin), never uploaded by clients. The composition root decides
/// what's runnable; transports and front-ends just look names up.
pub type Catalog = Arc<dyn Fn(&str) -> Result<(ActionSource, String)> + Send + Sync>;

pub struct Session {
    pub id: SessionId,
    pub identity: String,
    pub requests: Vec<CapRequest>,
    pub action: Action,
}

// ── the interceptor chain (the chokepoint) ────────────────────────────────────────────────────

/// The continuation handed to each [`Interceptor`]: call the next one, or the terminal (the raw op).
pub struct Next<'a> {
    rest: &'a [Arc<dyn Interceptor>],
    terminal: &'a (dyn Fn(Call) -> Result<CallResult> + 'a),
}
impl<'a> Next<'a> {
    pub fn run(self, call: Call) -> Result<CallResult> {
        match self.rest.split_first() {
            Some((head, tail)) => head.intercept(
                call,
                Next {
                    rest: tail,
                    terminal: self.terminal,
                },
            ),
            None => (self.terminal)(call),
        }
    }
}

// ── the gate: one path for allow / deny / escalate→approve, wherever a decision is made ─────────

/// Resolve a [`Decision`] into proceed-or-error, recording denials and the full escalation
/// round-trip. Used at session open, at each grant, and at each call — the verbs are uniform.
fn gate(
    recorder: &dyn Recorder,
    approver: &dyn Approver,
    session: SessionId,
    identity: &str,
    subject: String,
    decision: Decision,
) -> Result<()> {
    match decision {
        Decision::Allow => Ok(()),
        Decision::Deny(why) => {
            recorder.record(Event::Denied {
                session,
                subject,
                why: why.clone(),
            });
            Err(WardenError::Denied(why))
        }
        Decision::Escalate(reason) => {
            recorder.record(Event::EscalationRequested {
                session,
                subject: subject.clone(),
                reason: reason.clone(),
            });
            let req = ApprovalRequest {
                session,
                identity: identity.to_string(),
                subject: subject.clone(),
                reason,
            };
            match approver.decide(&req) {
                Verdict::Approved { by } => {
                    recorder.record(Event::Approved {
                        session,
                        subject,
                        by,
                    });
                    Ok(())
                }
                Verdict::Rejected { by, why } => {
                    recorder.record(Event::Rejected {
                        session,
                        subject,
                        by,
                        why: why.clone(),
                    });
                    Err(WardenError::Denied(why))
                }
            }
        }
    }
}

// ── Ctx: the running action's handle; every capability op goes through invoke() ────────────────

pub struct Ctx {
    pub session: SessionCtx,
    caps: HashMap<CapId, Box<dyn Capability>>,
    interceptors: Vec<Arc<dyn Interceptor>>,
    policy: Arc<dyn Policy>,
    approver: Arc<dyn Approver>,
    recorder: Arc<dyn Recorder>,
    /// Set (to the killer's name) when the session is killed — every later invoke is refused.
    killed: Arc<OnceLock<String>>,
    input: Mutex<Option<std::sync::mpsc::Receiver<InputFrame>>>,
    seq: AtomicU64,
}

impl Ctx {
    /// Whether this session has been killed. An interactive action that blocks on input (a pty
    /// attach) should poll this so it tears down promptly on kill, not only on its next `invoke`.
    pub fn killed(&self) -> bool {
        self.killed.get().is_some()
    }

    /// The chokepoint. Refuse if killed, policy-gate the call (allow / deny / escalate→approve),
    /// record it, run it through the interceptor chain (which may mask/transform), then record the
    /// result. The action can *only* touch the world here.
    pub fn invoke(&self, cap: CapId, op: &str, input: Vec<u8>) -> Result<Vec<u8>> {
        // the kill switch bites exactly here: a killed action keeps its CPU, loses the world
        if let Some(by) = self.killed.get() {
            let why = format!("session killed by {by}");
            self.recorder.record(Event::Denied {
                session: self.session.id,
                subject: format!("call `{op}`"),
                why: why.clone(),
            });
            return Err(WardenError::Denied(why));
        }
        let cap_obj = self.caps.get(&cap).ok_or(WardenError::NotGranted(cap))?;

        // Central op validation: an op the capability doesn't publish (§ `Capability::ops`) is
        // refused here, once, for every capability — so impls never hand-roll an "unknown op" arm,
        // and the refusal is a recorded governance denial, not a per-impl error string.
        let Some(spec) = cap_obj.ops().iter().find(|s| s.op == op) else {
            let why = format!("`{}` has no op `{op}`", cap_obj.kind().0);
            self.recorder.record(Event::Denied {
                session: self.session.id,
                subject: format!("call `{op}` on {}", cap_obj.kind().0),
                why: why.clone(),
            });
            return Err(WardenError::Denied(why));
        };

        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let call = Call {
            session: self.session.id,
            cap,
            kind: cap_obj.kind(),
            op: op.to_string(),
            mutates: spec.mutates,
            input,
        };

        gate(
            self.recorder.as_ref(),
            self.approver.as_ref(),
            self.session.id,
            &self.session.identity,
            format!("call `{op}` on {}", call.kind.0),
            self.policy.on_call(&self.session, &call),
        )?;
        self.recorder.record(Event::Call {
            session: self.session.id,
            seq,
            cap,
            op: op.to_string(),
            input: call.input.clone(),
        });

        let cap_ref: &dyn Capability = cap_obj.as_ref();
        let terminal = move |c: Call| -> Result<CallResult> {
            Ok(CallResult {
                output: cap_ref.perform(&c.op, &c.input)?,
            })
        };
        let next = Next {
            rest: self.interceptors.as_slice(),
            terminal: &terminal,
        };
        // every recorded Call gets a recorded outcome — a refused/failed op must not leave a
        // dangling call in the trail
        let res = match next.run(call) {
            Ok(r) => r,
            Err(e) => {
                self.recorder.record(Event::Failed {
                    session: self.session.id,
                    seq,
                    error: e.to_string(),
                });
                return Err(e);
            }
        };

        self.recorder.record(Event::Result {
            session: self.session.id,
            seq,
            output: res.output.clone(),
        });
        Ok(res.output)
    }

    /// Find a granted capability of a given kind (an action's convenience).
    pub fn cap(&self, kind: CapKind) -> Option<CapId> {
        self.cap_by_name(kind.0)
    }

    /// Same, by kind name — for runtimes whose guests name kinds as runtime strings (the component
    /// ABI's `get("sign")` can't construct a `CapKind`, which wraps a `&'static str`).
    pub fn cap_by_name(&self, kind: &str) -> Option<CapId> {
        self.caps
            .iter()
            .find(|(_, c)| c.kind().0 == kind)
            .map(|(id, _)| *id)
    }

    /// The first granted capability, kind-agnostic. Lets a runtime that hasn't yet grown a cap-by-id
    /// ABI (e.g. the spike's wasm host shim) reach the session's capability without hardcoding a kind.
    pub fn first_cap(&self) -> Option<CapId> {
        self.caps.keys().next().copied()
    }

    /// Whether a capability's underlying resource has ended on its own (e.g. a pty's shell exited).
    /// An attach loop polls this so the session ends when the shell dies. Unknown id → `false`.
    pub fn finished(&self, cap: CapId) -> bool {
        self.caps.get(&cap).is_some_and(|c| c.finished())
    }

    /// Take the session's client→session input stream (keystrokes/resize), once. An interactive
    /// action loops it into `invoke` (e.g. a pty attach: `frame → invoke(pty, &frame.op, data)`);
    /// the loop ends when the client disconnects (stream closes).
    pub fn take_input(&self) -> Option<std::sync::mpsc::Receiver<InputFrame>> {
        self.input.lock().unwrap().take()
    }

    fn revoke_all(&self) {
        for (id, cap) in &self.caps {
            cap.revoke();
            self.recorder.record(Event::Revoked {
                session: self.session.id,
                cap: *id,
            });
        }
    }
}

// ── the kernel ────────────────────────────────────────────────────────────────────────────────

/// Fans one event stream to the persistent recorder and a session's live observer.
struct Tee(Arc<dyn Recorder>, Arc<dyn Recorder>);
impl Recorder for Tee {
    fn record(&self, ev: Event) {
        self.0.record(ev.clone());
        self.1.record(ev);
    }
}

/// A live session's control surface: its kill flag and its (tee'd) recorder, so a kill lands in
/// the session's own stream — the client watching sees it happen.
struct LiveSession {
    killed: Arc<OnceLock<String>>,
    recorder: Arc<dyn Recorder>,
    identity: String,
    caps: Vec<String>, // requested capability kinds — for a record-independent live view
}

/// Owns the registries (wired explicitly at the composition root) and runs sessions through the
/// grant → run → mediate → revoke loop.
pub struct Warden {
    policy: Arc<dyn Policy>,
    approver: Arc<dyn Approver>,
    interceptors: Vec<Arc<dyn Interceptor>>,
    brokers: Vec<Arc<dyn Broker>>,
    runtimes: HashMap<&'static str, Arc<dyn Runtime>>,
    recorder: Arc<dyn Recorder>,
    live: Mutex<HashMap<u64, LiveSession>>,
    next_cap: AtomicU64,
}

/// Ensures a session leaves the live registry and gets its `SessionClosed` record on EVERY exit from
/// `run_full` — including a panic inside a hook, runtime, or interceptor. Without it an unwind would
/// leave a phantom "live" session forever: killable, counted by `live_sessions()`, never closed in
/// the audit trail. (A panicking runtime still won't run capabilities' `revoke()` side effects —
/// caps are dropped, not revoked — but the world-access is severed and the trail stays consistent.)
struct SessionGuard<'a> {
    live: &'a Mutex<HashMap<u64, LiveSession>>,
    recorder: Arc<dyn Recorder>,
    id: SessionId,
}
impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        // recover from a poisoned lock rather than double-panic during an unwind
        self.live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id.0);
        self.recorder
            .record(Event::SessionClosed { session: self.id });
    }
}

/// Holds capabilities granted during `drive` and revokes any still held if `drive` unwinds before
/// the action receives them — a denied/failed grant or a missing runtime. This keeps the
/// grant→revoke invariant and each cap's cleanup (kill a child, zeroize a key) on the failure path
/// exactly as `revoke_all` does on success. [`disarm`](GrantGuard::disarm) hands ownership to the `Ctx`.
struct GrantGuard {
    caps: HashMap<CapId, Box<dyn Capability>>,
    recorder: Arc<dyn Recorder>,
    session: SessionId,
    armed: bool,
}
impl GrantGuard {
    fn disarm(mut self) -> HashMap<CapId, Box<dyn Capability>> {
        self.armed = false;
        std::mem::take(&mut self.caps)
    }
}
impl Drop for GrantGuard {
    fn drop(&mut self) {
        if self.armed {
            for (id, cap) in self.caps.drain() {
                cap.revoke();
                self.recorder.record(Event::Revoked {
                    session: self.session,
                    cap: id,
                });
            }
        }
    }
}

impl Warden {
    pub fn new(
        policy: Arc<dyn Policy>,
        approver: Arc<dyn Approver>,
        interceptors: Vec<Arc<dyn Interceptor>>,
        brokers: Vec<Arc<dyn Broker>>,
        runtimes: HashMap<&'static str, Arc<dyn Runtime>>,
        recorder: Arc<dyn Recorder>,
    ) -> Self {
        Self {
            policy,
            approver,
            interceptors,
            brokers,
            runtimes,
            recorder,
            live: Mutex::new(HashMap::new()),
            next_cap: AtomicU64::new(0),
        }
    }

    /// Kill a live session: record the kill in its stream and refuse every later capability call.
    /// Returns false if the session isn't live. Honest scope: this severs the session's access to
    /// the world (the chokepoint), it does not preempt pure CPU inside a guest — that's the wasm
    /// runtime's epoch-interruption tier, later.
    pub fn kill(&self, session: SessionId, by: &str) -> bool {
        let live = self.live.lock().unwrap();
        match live.get(&session.0) {
            Some(ls) => {
                if ls.killed.set(by.to_string()).is_ok() {
                    ls.recorder.record(Event::Killed {
                        session,
                        by: by.to_string(),
                    });
                }
                true
            }
            None => false,
        }
    }

    /// Snapshot of currently-open sessions (id, identity, requested capability kinds), sorted by id.
    /// Independent of the record, so a UI can list and kill live sessions even with recording off.
    pub fn live_sessions(&self) -> Vec<(u64, String, Vec<String>)> {
        let mut v: Vec<_> = self
            .live
            .lock()
            .unwrap()
            .iter()
            .map(|(id, ls)| (*id, ls.identity.clone(), ls.caps.clone()))
            .collect();
        v.sort_by_key(|(id, _, _)| *id);
        v
    }

    pub fn run_session(&self, session: Session, runtime: &str) -> Result<()> {
        self.run_session_observed(session, runtime, None)
    }

    /// Run a session with an optional per-session observer (a transport's live client view). The
    /// observer sees exactly what the record sees — post-mask, nothing extra.
    pub fn run_session_observed(
        &self,
        session: Session,
        runtime: &str,
        observer: Option<Arc<dyn Recorder>>,
    ) -> Result<()> {
        self.run_full(session, runtime, observer, None)
    }

    /// Accept-and-run loop body for a [`Transport`]: run the incoming session (with its client
    /// observer and mid-session input), then tell the client the outcome.
    pub fn run_incoming(&self, inc: Incoming) {
        let result = self.run_full(inc.session, &inc.runtime, inc.observer, inc.input);
        (inc.done)(&result);
    }

    fn run_full(
        &self,
        session: Session,
        runtime: &str,
        observer: Option<Arc<dyn Recorder>>,
        input: Option<std::sync::mpsc::Receiver<InputFrame>>,
    ) -> Result<()> {
        let recorder: Arc<dyn Recorder> = match observer {
            Some(obs) => Arc::new(Tee(self.recorder.clone(), obs)),
            None => self.recorder.clone(),
        };
        let id = session.id;
        let killed: Arc<OnceLock<String>> = Arc::new(OnceLock::new());
        self.live.lock().unwrap().insert(
            id.0,
            LiveSession {
                killed: killed.clone(),
                recorder: recorder.clone(),
                identity: session.identity.clone(),
                caps: session
                    .requests
                    .iter()
                    .map(|r| r.kind.0.to_string())
                    .collect(),
            },
        );

        recorder.record(Event::SessionOpened {
            session: id,
            identity: session.identity.clone(),
        });
        // Audit integrity on EVERY exit (normal, error, OR panic): the guard removes the session from
        // the live registry and records SessionClosed when this scope unwinds — so a grant refusal, a
        // policy deny, or a panic in a hook/runtime never leaves a dangling-open session in the trail.
        let _guard = SessionGuard {
            live: &self.live,
            recorder: recorder.clone(),
            id,
        };
        // The open/close boundary: SessionOpened is recorded above, SessionClosed by the guard on
        // exit. Session-level governance (quotas, idle-timeout, handoff) will attach here when a real
        // user forces its shape — the parked SessionHook seam lived here (see docs/boundary.md).
        self.drive(session, runtime, recorder.clone(), killed, input)
    }

    fn drive(
        &self,
        session: Session,
        runtime: &str,
        recorder: Arc<dyn Recorder>,
        killed: Arc<OnceLock<String>>,
        input: Option<std::sync::mpsc::Receiver<InputFrame>>,
    ) -> Result<()> {
        let sctx = SessionCtx {
            id: session.id,
            identity: session.identity.clone(),
        };
        let gate_here = |subject: String, decision: Decision| {
            gate(
                recorder.as_ref(),
                self.approver.as_ref(),
                session.id,
                &sctx.identity,
                subject,
                decision,
            )
        };

        gate_here("open session".into(), self.policy.on_session(&sctx))?;

        // caps live in the guard until handed to the Ctx: any early return below (a denied/failed
        // grant, a missing runtime) drops it, revoking whatever was already granted.
        let mut guard = GrantGuard {
            caps: HashMap::new(),
            recorder: recorder.clone(),
            session: session.id,
            armed: true,
        };
        for req in &session.requests {
            gate_here(
                format!("grant {} {}", req.kind.0, req.arg),
                self.policy.on_request(&sctx, req),
            )?;
            let broker = self
                .brokers
                .iter()
                .find(|b| b.handles(req))
                .ok_or(WardenError::NoBroker(req.kind))?;
            let cap = broker.grant(req)?;
            let id = CapId(self.next_cap.fetch_add(1, Ordering::Relaxed) + 1);
            recorder.record(Event::CapGranted {
                session: session.id,
                cap: id,
                kind: cap.kind(),
            });
            guard.caps.insert(id, cap);
        }

        let rt = self
            .runtimes
            .get(runtime)
            .ok_or_else(|| WardenError::NoRuntime(runtime.to_string()))?
            .clone();

        // An output pump per streaming capability (e.g. a pty): drain raw chunks, mask them through
        // the interceptor chain, record each as Event::Output → the observer/client. Streamed output
        // is governed at the same chokepoint as call results.
        let mut pumps = Vec::new();
        for (id, cap) in &guard.caps {
            if let Some(rx) = cap.output() {
                let rec = recorder.clone();
                let interceptors = self.interceptors.clone();
                let (sid, cid) = (session.id, *id);
                pumps.push(std::thread::spawn(move || {
                    // one stateful masker per interceptor, per stream (carries across chunk bounds)
                    let mut maskers: Vec<OutputMasker> =
                        interceptors.iter().map(|i| i.output_masker()).collect();
                    for chunk in rx {
                        let masked = maskers.iter_mut().fold(chunk, |b, m| m(b));
                        rec.record(Event::Output {
                            session: sid,
                            cap: cid,
                            bytes: masked,
                        });
                    }
                    // stream closed: flush any carried tail (an empty chunk means "flush")
                    let tail = maskers.iter_mut().fold(Vec::new(), |b, m| m(b));
                    if !tail.is_empty() {
                        rec.record(Event::Output {
                            session: sid,
                            cap: cid,
                            bytes: tail,
                        });
                    }
                }));
            }
        }

        let ctx = Ctx {
            session: sctx,
            caps: guard.disarm(), // hand caps to the Ctx; success path revokes via ctx.revoke_all()
            interceptors: self.interceptors.clone(),
            policy: self.policy.clone(),
            approver: self.approver.clone(),
            recorder,
            killed,
            input: Mutex::new(input),
            seq: AtomicU64::new(0),
        };

        let result = rt.run(session.action, &ctx);
        // Revoke FIRST, then join. A streaming capability's pump only ends when its source hits EOF
        // (e.g. a pty closes) — which for a still-live child happens on revoke. Joining before revoke
        // would deadlock when the action ends while the child is alive (an operator kill, or a client
        // disconnect): the pump waits for EOF that only revoke produces. Revoking closes the child,
        // the reader drains its trailing bytes then EOFs, and the join drains them onto the record.
        ctx.revoke_all();
        for p in pumps {
            let _ = p.join();
        }
        result
    }
}
