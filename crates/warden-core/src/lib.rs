//! warden-core — the sans-IO kernel.
//!
//! One primitive: an **action can only touch the world through capabilities the warden grants,
//! mediates, and logs**. That single chokepoint is [`Ctx::invoke`], which drives the [`Interceptor`]
//! chain (audit · DLP · record · policy) around a [`Capability`]'s raw op. Everything else is a seam:
//! [`Runtime`], [`Broker`], [`Policy`], [`Approver`], [`Interceptor`], [`Recorder`], [`Transport`],
//! [`Capability`].
//!
//! No IO lives here — concrete impls live in sibling crates. The kernel is **async** (the seam
//! methods that touch the world — `perform`, `grant`, `run`, `accept`, `intercept`, `decide`, and
//! `invoke` — are `async`; the cheap/pure ones — `kind`, `ops`, `finished`, `handles`, `Policy`,
//! `Recorder::record`, `revoke` — stay sync). It still performs no IO and *schedules nothing*: the
//! output pump is a future the kernel runs concurrently via `futures::join`, not a thread it spawns.

use async_trait::async_trait;
use futures::StreamExt;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
///
/// Async note: only the methods that touch the world are async. `perform` (does the IO) and `revoke`
/// (releases the resource) await; `kind`/`ops`/`finished` are cheap and pure, so they stay sync.
#[async_trait]
pub trait Capability: Send + Sync {
    fn kind(&self) -> CapKind;
    /// The operations this capability accepts — its published contract (see [`OpSpec`]). The kernel
    /// validates every `perform`'s `op` against this set, so impls no longer hand-roll an
    /// "unknown op" arm. Should be a stable `&'static` slice.
    fn ops(&self) -> &'static [OpSpec];
    async fn perform(&self, op: &str, input: &[u8]) -> Result<Vec<u8>>;
    /// Release the resource — kill the child, zeroize the key. Kept **sync**: revocation is cheap
    /// local cleanup (no IO to await), and a sync `revoke` is what lets the failure-path drop guard
    /// (`GrantGuard`) run it from `Drop`, which cannot be async.
    fn revoke(&self);
    /// An optional *continuous output* stream (e.g. a pty's byte stream). The kernel takes it once,
    /// drains it through the interceptor chain (masking), and records each chunk as `Event::Output`
    /// — so streamed output is governed exactly like a call's result. Default: no stream. The getter
    /// is sync (it just hands over the stream); the *draining* is async (the kernel awaits chunks).
    fn output(&self) -> Option<OutputStream> {
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

/// A capability's continuous output as an async stream of byte chunks (e.g. a pty's bytes). The
/// kernel awaits chunks off it, masks each, and records them as `Event::Output`.
pub type OutputStream = std::pin::Pin<Box<dyn futures::Stream<Item = Vec<u8>> + Send>>;

/// Turns a [`CapRequest`] into a live [`Capability`] (for secrets: pull a short-lived cred from a
/// vault and return a handle the action can use but not read). `grant` is async — it may do IO
/// (open a pty, fetch from a vault); `handles` is a cheap sync predicate.
#[async_trait]
pub trait Broker: Send + Sync {
    fn handles(&self, req: &CapRequest) -> bool;
    async fn grant(&self, req: &CapRequest) -> Result<Box<dyn Capability>>;
}

/// Decisions at session open · each cap request · each call. **Pure logic, no IO — so it stays
/// sync.** (If a policy ever needs to consult an external system, that's an `Escalate` resolved by
/// an async [`Approver`], not IO inside the policy.)
pub trait Policy: Send + Sync {
    fn on_session(&self, s: &SessionCtx) -> Decision;
    fn on_request(&self, s: &SessionCtx, req: &CapRequest) -> Decision;
    fn on_call(&self, s: &SessionCtx, call: &Call) -> Decision;
}

/// Resolves escalations — **the seam that most wants async.** The real approver parks the operation,
/// pushes the request to humans (gateway UI, chat), and resumes on quorum; `decide` awaits that.
/// Multi-party (N-of-M) approval is an impl of this seam, not a kernel feature.
#[async_trait]
pub trait Approver: Send + Sync {
    async fn decide(&self, req: &ApprovalRequest) -> Verdict;
}

/// A stateful transform over one output stream's chunks (e.g. DLP masking a pty's bytes).
pub type OutputMasker = Box<dyn FnMut(Vec<u8>) -> Vec<u8> + Send>;

/// The mediation middleware — the chokepoint. Sees every call; may log, mask, meter, or deny.
/// `intercept` is async (it wraps the async `perform`); `output_masker` is a sync per-chunk fn.
#[async_trait]
pub trait Interceptor: Send + Sync {
    async fn intercept(&self, call: Call, next: Next<'_>) -> Result<CallResult>;
    /// Build a fresh, STATEFUL masker for one output stream (e.g. a pty). It's per-stream so it can
    /// carry a tail across chunks and still catch a secret split across a read() boundary — the
    /// thing a stateless per-chunk transform cannot. Default: pass-through. The kernel folds every
    /// interceptor's masker over each chunk before recording it as `Event::Output`.
    fn output_masker(&self) -> OutputMasker {
        Box::new(|b| b)
    }
}

/// Append-only structured event sink → replay/rewind. Backend-pluggable. **Stays sync**: `record`
/// is fire-and-forget (the file recorder already hands off to a background writer), so making it
/// async would infect every call site — including the hot chokepoint — for no gain.
pub trait Recorder: Send + Sync {
    fn record(&self, ev: Event);
}

// NOTE: there was a `SessionHook` seam here (on_open/on_close). It was parked — removed as a
// reserved kernel seam — because it had no real implementation (only a test counter), and a seam is
// a contract the kernel must keep stable: an unproven one is a liability, not an asset. The
// open/close *boundary* still exists in `run_full` (it records SessionOpened / SessionClosed via the
// SessionGuard); session-level governance (quotas, idle-timeout, handoff) will attach there when a
// real user forces the hook's shape. See docs/boundary.md.

// NOTE: there was a `Spawner` seam here (a host-provided thread/task scheduler for the output pump).
// Async retired it: the pump is now a *future* the kernel runs concurrently with the action via
// `futures::join` — no thread, no runtime choice, nothing to schedule. Async is itself the
// mechanism-neutral concurrency the Spawner seam was reaching for. See docs/boundary.md.

/// How an action executes. Impls: an in-process demo (here), a WASM component host, a native process.
#[async_trait]
pub trait Runtime: Send + Sync {
    fn name(&self) -> &'static str;
    async fn run(&self, action: Action, ctx: &Ctx) -> Result<()>;
}

/// How sessions arrive: local loopback, TCP, or a gateway reverse-tunnel. `accept` awaits until a
/// client has delivered a full request, then hands the kernel everything it needs to act on it.
/// The wire protocol is the transport's business; the kernel never sees bytes.
#[async_trait]
pub trait Transport: Send + Sync {
    async fn accept(&self) -> Result<Accepted>;
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
    pub input: Option<InputStream>,
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

/// The mid-session client→session input as an async stream of frames. An interactive action awaits
/// frames off it and loops them into `invoke` (a pty attach); the stream ends when the client
/// disconnects. Async, so the attach loop `.await`s a frame instead of polling a blocking recv.
pub type InputStream = std::pin::Pin<Box<dyn futures::Stream<Item = InputFrame> + Send>>;

/// A detachable session's long-lived output pump, returned by [`Warden::open_session`] for the CALLER
/// to drive (spawn on its runtime — the kernel schedules nothing). It resolves when the session's
/// capabilities are revoked (their output streams EOF) on close/kill.
pub type SessionPump = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

// ── session & action ────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SessionCtx {
    pub id: SessionId,
    pub identity: String,
}

/// An action = something a [`Runtime`] runs. In-process it's an async closure that uses the [`Ctx`]
/// to invoke capabilities; the WASM runtime drives a component's imports into the same `ctx.invoke`.
/// The closure borrows the `Ctx` for the lifetime of the future it returns, so it can `.await`
/// invocations against it. Build one with [`action_fn`].
pub type ActionFn = Box<
    dyn for<'a> Fn(
            &'a Ctx,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>
        + Send
        + Sync,
>;

/// Wrap a closure that returns an already-boxed, `ctx`-borrowing future into an [`ActionFn`]. Write
/// actions as `action_fn(|ctx| Box::pin(async move { … ctx.invoke(…).await? … Ok(()) }))`. The
/// explicit `Box::pin` is what lets the returned future borrow `ctx` for its own lifetime — a plain
/// `async fn`-returning closure can't express that higher-ranked borrow through one type parameter.
pub fn action_fn<F>(f: F) -> ActionFn
where
    F: for<'a> Fn(
            &'a Ctx,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>
        + Send
        + Sync
        + 'static,
{
    Box::new(f)
}

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

/// A UI-facing snapshot of a live session (for the cross-tab palette). Richer than `live_sessions()`:
/// carries the client-pushed title + owner-tab id + whether the session can be detached/teleported.
#[derive(Clone, Debug)]
pub struct SessionView {
    pub id: u64,
    pub identity: String,
    pub caps: Vec<String>,
    pub title: String,
    pub tab: String,
    pub detachable: bool,
    /// The last non-blank line of the session's recent output (ANSI-stripped) — a human preview for
    /// the exposé card, so a pane is recognizable even from another tab (via the server-side ring).
    pub preview: String,
}

// ── the interceptor chain (the chokepoint) ────────────────────────────────────────────────────

/// The terminal of the interceptor chain: the raw async op (`capability.perform`). Returns a boxed
/// future so it's a plain trait object the chain can hold.
type Terminal<'a> = dyn Fn(Call) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<CallResult>> + Send + 'a>>
    + Send
    + Sync
    + 'a;

/// The continuation handed to each [`Interceptor`]: call the next one, or the terminal (the raw op).
pub struct Next<'a> {
    rest: &'a [Arc<dyn Interceptor>],
    terminal: &'a Terminal<'a>,
}
impl<'a> Next<'a> {
    /// Run the rest of the chain. Async and self-recursive (each interceptor awaits the next), so the
    /// future is boxed — the standard shape for a recursive `async fn`.
    pub fn run(
        self,
        call: Call,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<CallResult>> + Send + 'a>> {
        Box::pin(async move {
            match self.rest.split_first() {
                Some((head, tail)) => {
                    head.intercept(
                        call,
                        Next {
                            rest: tail,
                            terminal: self.terminal,
                        },
                    )
                    .await
                }
                None => (self.terminal)(call).await,
            }
        })
    }
}

// ── the gate: one path for allow / deny / escalate→approve, wherever a decision is made ─────────

/// Resolve a [`Decision`] into proceed-or-error, recording denials and the full escalation
/// round-trip. Used at session open, at each grant, and at each call — the verbs are uniform. Async
/// because the escalate path awaits the [`Approver`].
async fn gate(
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
            match approver.decide(&req).await {
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
//
// Ctx has ONE public role: the action-facing handle (`invoke`, `cap`, `finished`, `take_input`,
// `killed`, plus the `session` identity). That's the whole surface an action needs. The mediation
// machinery it drives — the interceptor chain, policy, approver, recorder, kill flag, seq — are
// PRIVATE fields, not exposed: an action can touch the world only through `invoke`, never reach the
// wiring behind it. (Two extra methods, `cap_by_name`/`first_cap`, are runtime-plumbing, grouped in
// a separate impl block below and documented as such.)

pub struct Ctx {
    pub session: SessionCtx,
    // Arc, not Box: a detachable session's caps live in the registry and are SHARED with each viewer's
    // Ctx (they outlive any one attach). Non-detachable sessions still hold the sole reference here and
    // revoke on action end — the difference is who calls `revoke_all`, not the type.
    caps: HashMap<CapId, Arc<dyn Capability>>,
    interceptors: Vec<Arc<dyn Interceptor>>,
    policy: Arc<dyn Policy>,
    approver: Arc<dyn Approver>,
    recorder: Arc<dyn Recorder>,
    /// Set (to the killer's name) when the session is killed — every later invoke is refused.
    killed: Arc<OnceLock<String>>,
    input: Mutex<Option<InputStream>>,
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
    pub async fn invoke(&self, cap: CapId, op: &str, input: Vec<u8>) -> Result<Vec<u8>> {
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
        )
        .await?;
        self.recorder.record(Event::Call {
            session: self.session.id,
            seq,
            cap,
            op: op.to_string(),
            input: call.input.clone(),
        });

        let cap_ref: &dyn Capability = cap_obj.as_ref();
        let terminal = move |c: Call| {
            let cap_ref = cap_ref;
            Box::pin(async move {
                Ok(CallResult {
                    output: cap_ref.perform(&c.op, &c.input).await?,
                })
            })
                as std::pin::Pin<Box<dyn std::future::Future<Output = Result<CallResult>> + Send>>
        };
        let next = Next {
            rest: self.interceptors.as_slice(),
            terminal: &terminal,
        };
        // every recorded Call gets a recorded outcome — a refused/failed op must not leave a
        // dangling call in the trail
        let res = match next.run(call).await {
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

    /// Whether a capability's underlying resource has ended on its own (e.g. a pty's shell exited).
    /// An attach loop polls this so the session ends when the shell dies. Unknown id → `false`.
    pub fn finished(&self, cap: CapId) -> bool {
        self.caps.get(&cap).is_some_and(|c| c.finished())
    }

    /// Take the session's client→session input stream (keystrokes/resize), once. An interactive
    /// action loops it into `invoke` (e.g. a pty attach: `frame → invoke(pty, &frame.op, data)`);
    /// the loop ends when the client disconnects (stream closes).
    pub fn take_input(&self) -> Option<InputStream> {
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

// ── Ctx: the runtime-facing surface ────────────────────────────────────────────────────────────
// These exist for a *runtime* bridging a guest ABI to the session's capabilities — NOT for actions,
// which use the typed `cap(CapKind)` above. They're grouped and named apart so the action API stays
// small and clean, and so it's obvious these are host/runtime plumbing that a richer guest cap-by-id
// ABI would eventually retire.
impl Ctx {
    /// Resolve a capability by kind *name* — for a runtime whose guest names kinds as runtime strings
    /// (the component ABI's `get("sign")` can't construct a `CapKind`, which wraps a `&'static str`).
    pub fn cap_by_name(&self, kind: &str) -> Option<CapId> {
        self.caps
            .iter()
            .find(|(_, c)| c.kind().0 == kind)
            .map(|(id, _)| *id)
    }

    /// The first granted capability, kind-agnostic — for a runtime that hasn't grown a cap-by-id ABI
    /// yet (the spike's minimal wasm core-module host shim) and just needs *the* granted capability.
    pub fn first_cap(&self) -> Option<CapId> {
        self.caps.keys().next().copied()
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

/// The upper bound on a detachable session's replay ring — enough recent output that a re-attach
/// (teleport) shows meaningful scrollback, without unbounded memory per idle session.
const RING_CAP: usize = 256 * 1024;

/// A **swappable** live observer for a detachable session: the currently-attached viewer's output
/// sink, behind a slot that a re-attach can replace (exclusive-move today; shaped to hold a `Vec` for
/// mirroring later). It also keeps a bounded ring of recent `Output` bytes so a fresh viewer can be
/// replayed the recent screen on attach. As a `Recorder` it's the second arm of the session's `Tee`:
/// every event is offered to the current sink (if any) and `Output` bytes are appended to the ring.
struct SwapSink {
    sink: Mutex<Option<Arc<dyn Recorder>>>,
    ring: Mutex<VecDeque<u8>>,
}
impl SwapSink {
    fn new() -> Self {
        SwapSink {
            sink: Mutex::new(None),
            ring: Mutex::new(VecDeque::new()),
        }
    }
    /// Install `obs` as the live viewer, first replaying the recent-output ring to it so the new
    /// viewer sees scrollback. Any previous viewer is dropped (its transport stream then ends —
    /// the exclusive-move that makes teleport work). `session`/`cap` stamp the replayed Output events.
    fn attach(&self, obs: Arc<dyn Recorder>, session: SessionId, cap: CapId) {
        let replay: Vec<u8> = self.ring.lock().unwrap().iter().copied().collect();
        if !replay.is_empty() {
            obs.record(Event::Output {
                session,
                cap,
                bytes: replay,
            });
        }
        *self.sink.lock().unwrap() = Some(obs);
    }
    /// Detach the current viewer (keep the session + ring alive).
    fn detach(&self) {
        *self.sink.lock().unwrap() = None;
    }

    /// A short human preview of the session's recent output — the last non-blank visible line, ANSI
    /// stripped, bounded. Feeds the exposé/palette card so you recognize a pane by what's on it. Only
    /// the tail of the ring is scanned (cheap); a fully-blank ring yields "".
    fn preview(&self) -> String {
        let ring = self.ring.lock().unwrap();
        // scan the last chunk of the ring (a preview never needs the whole 256 KiB)
        let tail: Vec<u8> = {
            let n = ring.len();
            let start = n.saturating_sub(8192);
            ring.iter().skip(start).copied().collect()
        };
        let text = String::from_utf8_lossy(&tail);
        // strip ANSI CSI/OSC escapes + control chars, split into lines, take the last non-blank one.
        let mut last = String::new();
        for raw in strip_ansi(&text).lines() {
            let line = raw.trim_end();
            if !line.trim().is_empty() {
                last = line.to_string();
            }
        }
        last.chars().take(120).collect()
    }
}

/// Strip ANSI escape sequences (CSI `ESC[…`, OSC `ESC]…BEL/ST`) and other control chars from `s`,
/// leaving printable text — enough to make a terminal-output line human-readable for a preview.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            match chars.next() {
                Some('[') => {
                    // CSI: consume until a final byte in @..~
                    for n in chars.by_ref() {
                        if ('\x40'..='\x7e').contains(&n) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    // OSC: consume until BEL or ESC\ (ST)
                    while let Some(n) = chars.next() {
                        if n == '\x07' {
                            break;
                        }
                        if n == '\x1b' {
                            chars.next(); // the '\'
                            break;
                        }
                    }
                }
                _ => {} // a lone ESC or a 2-char sequence we don't care about
            }
        } else if c == '\n' || !c.is_control() {
            out.push(c);
        }
        // other control chars (\r, \t, etc.) dropped
    }
    out
}
impl Recorder for SwapSink {
    fn record(&self, ev: Event) {
        if let Event::Output { ref bytes, .. } = ev {
            let mut ring = self.ring.lock().unwrap();
            ring.extend(bytes.iter().copied());
            let overflow = ring.len().saturating_sub(RING_CAP);
            if overflow > 0 {
                ring.drain(..overflow);
            }
        }
        if let Some(obs) = self.sink.lock().unwrap().as_ref() {
            obs.record(ev);
        }
    }
}

/// A live session's control surface: its kill flag and its (tee'd) recorder, so a kill lands in
/// the session's own stream — the client watching sees it happen. A **detachable** session also owns
/// its granted capabilities and its swappable sink here (so they outlive any one viewer/connection);
/// a non-detachable session leaves those `None` and behaves exactly as before (caps in the run's Ctx,
/// revoked when the action ends).
struct LiveSession {
    killed: Arc<OnceLock<String>>,
    recorder: Arc<dyn Recorder>,
    identity: String,
    caps: Vec<String>, // requested capability kinds — for a record-independent live view
    title: Mutex<String>,
    tab: Mutex<String>, // client-supplied owner-tab id (for the cross-tab palette)
    swap: Option<Arc<SwapSink>>, // Some → detachable: the swappable viewer sink + replay ring
    detachable: bool,
    // detachable-only: the granted caps live HERE (shared with each viewer's Ctx via Arc, so they
    // outlive any one attach). The long-lived output pump is a future the CALLER spawns (the kernel is
    // runtime-agnostic — it schedules nothing); it self-completes when the caps are revoked on close.
    held_caps: HashMap<CapId, Arc<dyn Capability>>,
    attached: Arc<AtomicBool>, // a viewer is currently bound (exclusive-move guard)
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
    caps: HashMap<CapId, Arc<dyn Capability>>,
    recorder: Arc<dyn Recorder>,
    session: SessionId,
    armed: bool,
}
impl GrantGuard {
    fn disarm(mut self) -> HashMap<CapId, Arc<dyn Capability>> {
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
    ///
    /// For a NON-detachable session the kill flag is enough: the attached action sees it (at the
    /// chokepoint / via `finished`-poll), ends, and `run_full` tears down (revoke + remove). A
    /// DETACHABLE session has no such action-owned teardown, so kill also revokes + removes it here
    /// (the `close_session` teardown) — otherwise a killed detachable session would linger live.
    pub fn kill(&self, session: SessionId, by: &str) -> bool {
        let detachable = {
            let live = self.live.lock().unwrap();
            match live.get(&session.0) {
                Some(ls) => {
                    if ls.killed.set(by.to_string()).is_ok() {
                        ls.recorder.record(Event::Killed {
                            session,
                            by: by.to_string(),
                        });
                    }
                    ls.detachable
                }
                None => return false,
            }
        };
        if detachable {
            self.close_session(session); // revoke + remove + SessionClosed
        }
        true
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

    /// Richer per-session snapshot for the cross-tab palette: adds the client-pushed title + owner-tab
    /// id + whether the session is detachable (teleportable). Sorted by id.
    pub fn session_views(&self) -> Vec<SessionView> {
        let mut v: Vec<SessionView> = self
            .live
            .lock()
            .unwrap()
            .iter()
            .map(|(id, ls)| SessionView {
                id: *id,
                identity: ls.identity.clone(),
                caps: ls.caps.clone(),
                title: ls.title.lock().unwrap().clone(),
                tab: ls.tab.lock().unwrap().clone(),
                detachable: ls.detachable,
                preview: ls.swap.as_ref().map(|s| s.preview()).unwrap_or_default(),
            })
            .collect();
        v.sort_by_key(|s| s.id);
        v
    }

    /// Set a live session's human title (client-pushed, e.g. the pane's OSC title). No-op if unknown.
    pub fn set_title(&self, session: SessionId, title: &str) {
        if let Some(ls) = self.live.lock().unwrap().get(&session.0) {
            *ls.title.lock().unwrap() = title.to_string();
        }
    }

    /// Tag a live session with the browser-tab id that currently owns it (for the palette's
    /// "here vs another tab" grouping). No-op if unknown.
    pub fn set_tab(&self, session: SessionId, tab: &str) {
        if let Some(ls) = self.live.lock().unwrap().get(&session.0) {
            *ls.tab.lock().unwrap() = tab.to_string();
        }
    }

    // ── detachable sessions: a session as a durable primitive (see docs/detachable-sessions.md) ──
    //
    // `open_session` grants caps + registers + starts a LONG-LIVED output pump, but runs no action and
    // never revokes — the session is live with no viewer. `attach` binds a viewer (observer + input),
    // runs the action, and on the action ending (viewer disconnect) DETACHES without revoking — the
    // session lives on. `close_session`/`kill` are the only paths that revoke + remove. The whole thing
    // is opt-in: `run_session*`/`run_incoming` (non-detachable, action-owns-lifetime) are unchanged.

    /// Open a durable, detachable session: grant its capabilities and register it. Returns a
    /// **pump future** the CALLER must drive (spawn on its runtime) — the kernel is runtime-agnostic,
    /// so it schedules nothing itself. The pump streams the session's output into the swappable sink +
    /// replay ring for as long as the caps live; it self-completes when the caps are revoked on
    /// `close_session`/`kill`. Governance (policy gates, grant records) is identical to a normal run;
    /// only the lifetime differs. On a grant/policy failure, whatever was granted is revoked and the
    /// error returned (nothing left registered, no pump).
    pub async fn open_session(&self, session: Session) -> Result<SessionPump> {
        let sctx = SessionCtx {
            id: session.id,
            identity: session.identity.clone(),
        };
        let killed: Arc<OnceLock<String>> = Arc::new(OnceLock::new());
        let swap = Arc::new(SwapSink::new());
        // the session recorder tees the base record and the swappable viewer sink (+ replay ring).
        let recorder: Arc<dyn Recorder> = Arc::new(Tee(self.recorder.clone(), swap.clone()));

        // gate + grant, revoking on any early failure (same invariant as `drive`).
        gate(
            recorder.as_ref(),
            self.approver.as_ref(),
            session.id,
            &sctx.identity,
            "open session".into(),
            self.policy.on_session(&sctx),
        )
        .await?;
        let mut guard = GrantGuard {
            caps: HashMap::new(),
            recorder: recorder.clone(),
            session: session.id,
            armed: true,
        };
        for req in &session.requests {
            gate(
                recorder.as_ref(),
                self.approver.as_ref(),
                session.id,
                &sctx.identity,
                format!("grant {} {}", req.kind.0, req.arg),
                self.policy.on_request(&sctx, req),
            )
            .await?;
            let broker = self
                .brokers
                .iter()
                .find(|b| b.handles(req))
                .ok_or(WardenError::NoBroker(req.kind))?;
            let cap: Arc<dyn Capability> = broker.grant(req).await?.into();
            let id = CapId(self.next_cap.fetch_add(1, Ordering::Relaxed) + 1);
            recorder.record(Event::CapGranted {
                session: session.id,
                cap: id,
                kind: cap.kind(),
            });
            guard.caps.insert(id, cap);
        }
        let caps = guard.disarm(); // success: caps now owned by the registry, revoked only on close

        // Build the long-lived pump FUTURE (the caller spawns it): drain each streaming cap → mask →
        // record (→ swap sink + ring). It captures output even while no viewer is attached, and ends
        // when the caps are revoked (streams EOF) on close/kill.
        let pump: SessionPump = {
            let interceptors = self.interceptors.clone();
            let rec = recorder.clone();
            let sid = session.id;
            let streams: Vec<(CapId, OutputStream)> = caps
                .iter()
                .filter_map(|(id, cap)| cap.output().map(|s| (*id, s)))
                .collect();
            Box::pin(async move {
                let mut pumps = futures::stream::FuturesUnordered::new();
                for (cid, mut stream) in streams {
                    let rec = rec.clone();
                    let interceptors = interceptors.clone();
                    pumps.push(async move {
                        let mut maskers: Vec<OutputMasker> =
                            interceptors.iter().map(|i| i.output_masker()).collect();
                        while let Some(chunk) = stream.next().await {
                            let masked = maskers.iter_mut().fold(chunk, |b, m| m(b));
                            rec.record(Event::Output {
                                session: sid,
                                cap: cid,
                                bytes: masked,
                            });
                        }
                        let tail = maskers.iter_mut().fold(Vec::new(), |b, m| m(b));
                        if !tail.is_empty() {
                            rec.record(Event::Output {
                                session: sid,
                                cap: cid,
                                bytes: tail,
                            });
                        }
                    });
                }
                while pumps.next().await.is_some() {}
            })
        };

        self.live.lock().unwrap().insert(
            session.id.0,
            LiveSession {
                killed,
                recorder: recorder.clone(),
                identity: session.identity.clone(),
                caps: session
                    .requests
                    .iter()
                    .map(|r| r.kind.0.to_string())
                    .collect(),
                title: Mutex::new(String::new()),
                tab: Mutex::new(String::new()),
                swap: Some(swap),
                detachable: true,
                held_caps: caps,
                attached: Arc::new(AtomicBool::new(false)),
            },
        );
        recorder.record(Event::SessionOpened {
            session: session.id,
            identity: session.identity,
        });
        Ok(pump)
    }

    /// Bind a viewer to a live detachable session and run its action. Installs `observer` as the
    /// session's live output sink (replaying the recent-output ring first — scrollback follows a
    /// teleport), dropping any prior viewer (exclusive move). `input` feeds keystrokes/resize to the
    /// SAME running capabilities. When the action returns (the viewer disconnected: input stream
    /// ended), the viewer is DETACHED — the session and its capabilities live on. Errors if the
    /// session is unknown or not detachable.
    pub async fn attach(
        &self,
        session: SessionId,
        runtime: &str,
        action: Action,
        observer: Arc<dyn Recorder>,
        input: Option<InputStream>,
    ) -> Result<()> {
        // snapshot what we need from the registry entry (recorder, caps, killed, swap), then release
        // the lock before running the action.
        let (recorder, caps, killed, swap, attached) = {
            let live = self.live.lock().unwrap();
            let ls = live
                .get(&session.0)
                .ok_or_else(|| WardenError::Cap(format!("no session {}", session.0)))?;
            if !ls.detachable {
                return Err(WardenError::Cap(format!(
                    "session {} is not detachable",
                    session.0
                )));
            }
            (
                ls.recorder.clone(),
                ls.held_caps.clone(),
                ls.killed.clone(),
                ls.swap.clone(),
                ls.attached.clone(),
            )
        };
        // install this viewer's sink (replay the ring to it, drop any prior viewer).
        if let Some(swap) = &swap {
            let cap_id = caps.keys().next().copied().unwrap_or(CapId(0));
            swap.attach(observer, session, cap_id);
        }
        attached.store(true, Ordering::SeqCst);

        let rt = self
            .runtimes
            .get(runtime)
            .ok_or_else(|| WardenError::NoRuntime(runtime.to_string()))?
            .clone();
        let sctx = SessionCtx {
            id: session,
            identity: self
                .live
                .lock()
                .unwrap()
                .get(&session.0)
                .map(|ls| ls.identity.clone())
                .unwrap_or_default(),
        };
        let ctx = Ctx {
            session: sctx,
            caps, // shared Arcs with the registry — the Ctx does NOT revoke them on the attach path
            interceptors: self.interceptors.clone(),
            policy: self.policy.clone(),
            approver: self.approver.clone(),
            recorder,
            killed,
            input: Mutex::new(input),
            seq: AtomicU64::new(0),
        };
        // run the viewer's action (the attach loop). No pump join here — the session's long-lived pump
        // already streams output to the sink we installed.
        let result = rt.run(action, &ctx).await;
        // viewer gone → detach (keep the session + caps alive). Only close/kill revoke.
        if let Some(swap) = &swap {
            swap.detach();
        }
        attached.store(false, Ordering::SeqCst);
        result
    }

    /// Explicitly end a detachable session: revoke its capabilities (each `revoke()` → recorded, and
    /// closes the cap's output stream → the pump future EOFs and completes), remove it from the
    /// registry, and record `SessionClosed`. The one deliberate teardown path (alongside `kill`).
    /// Returns false if the session isn't a live detachable one. Preserves the load-bearing order:
    /// revoke first (streams EOF) → the caller's pump future then finishes on its own.
    pub fn close_session(&self, session: SessionId) -> bool {
        let ls = self.live.lock().unwrap().remove(&session.0);
        match ls {
            Some(ls) if ls.detachable => {
                for (id, cap) in &ls.held_caps {
                    cap.revoke();
                    ls.recorder.record(Event::Revoked { session, cap: *id });
                }
                ls.recorder.record(Event::SessionClosed { session });
                true
            }
            // not detachable (or absent) → put it back if it was there; not ours to close this way.
            Some(ls) => {
                self.live.lock().unwrap().insert(session.0, ls);
                false
            }
            None => false,
        }
    }

    pub async fn run_session(&self, session: Session, runtime: &str) -> Result<()> {
        self.run_session_observed(session, runtime, None).await
    }

    /// Run a session with an optional per-session observer (a transport's live client view). The
    /// observer sees exactly what the record sees — post-mask, nothing extra.
    pub async fn run_session_observed(
        &self,
        session: Session,
        runtime: &str,
        observer: Option<Arc<dyn Recorder>>,
    ) -> Result<()> {
        self.run_full(session, runtime, observer, None).await
    }

    /// Accept-and-run loop body for a [`Transport`]: run the incoming session (with its client
    /// observer and mid-session input), then tell the client the outcome.
    pub async fn run_incoming(&self, inc: Incoming) {
        let result = self
            .run_full(inc.session, &inc.runtime, inc.observer, inc.input)
            .await;
        (inc.done)(&result);
    }

    async fn run_full(
        &self,
        session: Session,
        runtime: &str,
        observer: Option<Arc<dyn Recorder>>,
        input: Option<InputStream>,
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
                title: Mutex::new(String::new()),
                tab: Mutex::new(String::new()),
                swap: None, // non-detachable: caps live in the run's Ctx, revoked when the action ends
                detachable: false,
                held_caps: HashMap::new(),
                attached: Arc::new(AtomicBool::new(false)),
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
            .await
    }

    async fn drive(
        &self,
        session: Session,
        runtime: &str,
        recorder: Arc<dyn Recorder>,
        killed: Arc<OnceLock<String>>,
        input: Option<InputStream>,
    ) -> Result<()> {
        let sctx = SessionCtx {
            id: session.id,
            identity: session.identity.clone(),
        };
        // a small async helper so the three gate points read uniformly (closures can't be async and
        // borrow like this cleanly, so it's a plain async block per call)
        macro_rules! gate_here {
            ($subject:expr, $decision:expr) => {
                gate(
                    recorder.as_ref(),
                    self.approver.as_ref(),
                    session.id,
                    &sctx.identity,
                    $subject,
                    $decision,
                )
                .await
            };
        }

        gate_here!("open session".into(), self.policy.on_session(&sctx))?;

        // caps live in the guard until handed to the Ctx: any early return below (a denied/failed
        // grant, a missing runtime) drops it, revoking whatever was already granted.
        let mut guard = GrantGuard {
            caps: HashMap::new(),
            recorder: recorder.clone(),
            session: session.id,
            armed: true,
        };
        for req in &session.requests {
            gate_here!(
                format!("grant {} {}", req.kind.0, req.arg),
                self.policy.on_request(&sctx, req)
            )?;
            let broker = self
                .brokers
                .iter()
                .find(|b| b.handles(req))
                .ok_or(WardenError::NoBroker(req.kind))?;
            let cap: Arc<dyn Capability> = broker.grant(req).await?.into();
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

        // An output pump per streaming capability (e.g. a pty): drain the async chunk stream, mask
        // each chunk through the interceptors, record it as Event::Output → the observer/client.
        // Streamed output is governed at the same chokepoint as call results. Each pump is a *future*
        // the kernel runs concurrently with the action (via `join` below) — no thread, no spawn, no
        // runtime choice: async is itself the mechanism-neutral concurrency (the old `Spawner` seam,
        // now retired).
        let mut pump_futs = futures::stream::FuturesUnordered::new();
        for (id, cap) in &guard.caps {
            if let Some(mut stream) = cap.output() {
                let rec = recorder.clone();
                let interceptors = self.interceptors.clone();
                let (sid, cid) = (session.id, *id);
                pump_futs.push(async move {
                    // one stateful masker per interceptor, per stream (carries across chunk bounds)
                    let mut maskers: Vec<OutputMasker> =
                        interceptors.iter().map(|i| i.output_masker()).collect();
                    while let Some(chunk) = stream.next().await {
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
                });
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

        // Run the action; when it finishes, revoke (which closes streaming children → EOFs their
        // pumps). The pumps drain CONCURRENTLY the whole time — driven by the join below — so live
        // output streams to the client while the action runs, yet they only *complete* after revoke.
        // This preserves the sync version's load-bearing "revoke first, then finish the pumps"
        // ordering: joining before revoke would deadlock (a pump waits for an EOF only revoke makes).
        let run_side = async {
            let result = rt.run(session.action, &ctx).await;
            ctx.revoke_all();
            result
        };
        let drain_side = async { while pump_futs.next().await.is_some() {} };
        let (result, ()) = futures::future::join(run_side, drain_side).await;
        result
    }
}

#[cfg(test)]
mod detachable_tests {
    //! Stage-1 proof of detachable sessions (docs/detachable-sessions.md), in isolation — no kedi, no
    //! real pty. A mock streaming capability whose output we can push, a mock broker, a local runtime,
    //! and a capturing observer. Drives the pump future on the tokio test runtime (the test is the
    //! "caller" that would spawn it in production).

    #[test]
    fn strip_ansi_leaves_readable_text() {
        // a typical colored prompt line → the escapes vanish, the words remain
        let s = "\x1b[0;32mokkan@box\x1b[0m:\x1b[1;34m~/proj\x1b[0m$ cargo build";
        assert_eq!(super::strip_ansi(s), "okkan@box:~/proj$ cargo build");
        // OSC title sequence (ESC]0;…BEL) is dropped whole
        assert_eq!(super::strip_ansi("\x1b]0;my title\x07hello"), "hello");
        // bare control chars (\r, \t) dropped, newlines kept
        assert_eq!(super::strip_ansi("a\r\tb\nc"), "ab\nc");
    }

    use super::*;
    use std::sync::atomic::AtomicBool;
    use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};

    const MOCK: CapKind = CapKind("mock");
    const MOCK_OPS: &[OpSpec] = &[OpSpec {
        op: "input",
        doc: "feed input",
        mutates: true,
    }];

    /// A capability whose output stream we drive by pushing bytes; `revoke()` closes it (EOF). Records
    /// whether it was revoked so tests can assert cap lifetime.
    struct MockCap {
        out_tx: Mutex<Option<UnboundedSender<Vec<u8>>>>,
        out_rx: Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>>,
        revoked: Arc<AtomicBool>,
    }
    #[async_trait::async_trait]
    impl Capability for MockCap {
        fn kind(&self) -> CapKind {
            MOCK
        }
        fn ops(&self) -> &'static [OpSpec] {
            MOCK_OPS
        }
        async fn perform(&self, _op: &str, _input: &[u8]) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
        fn revoke(&self) {
            self.revoked.store(true, Ordering::SeqCst);
            *self.out_tx.lock().unwrap() = None; // drop the sender → stream EOFs → pump ends
        }
        fn output(&self) -> Option<OutputStream> {
            self.out_rx.lock().unwrap().take().map(|rx| {
                Box::pin(tokio_stream::wrappers::UnboundedReceiverStream::new(rx)) as OutputStream
            })
        }
    }

    /// A broker that hands out one MockCap and exposes its output sender + revoked flag so the test can
    /// push output and observe revocation.
    struct MockBroker {
        tx: std::sync::Mutex<Option<UnboundedSender<Vec<u8>>>>,
        revoked: Arc<AtomicBool>,
    }
    #[async_trait::async_trait]
    impl Broker for MockBroker {
        fn handles(&self, req: &CapRequest) -> bool {
            req.kind == MOCK
        }
        async fn grant(&self, _req: &CapRequest) -> Result<Box<dyn Capability>> {
            let (tx, rx) = unbounded_channel::<Vec<u8>>();
            *self.tx.lock().unwrap() = Some(tx.clone());
            Ok(Box::new(MockCap {
                out_tx: Mutex::new(Some(tx)),
                out_rx: Mutex::new(Some(rx)),
                revoked: self.revoked.clone(),
            }))
        }
    }

    /// Local runtime: runs an in-process action closure.
    struct Local;
    #[async_trait::async_trait]
    impl Runtime for Local {
        fn name(&self) -> &'static str {
            "local"
        }
        async fn run(&self, action: Action, ctx: &Ctx) -> Result<()> {
            match action.source {
                ActionSource::InProcess(body) => body(ctx).await,
                _ => Err(WardenError::Cap("local only".into())),
            }
        }
    }

    struct AllowAll;
    impl Policy for AllowAll {
        fn on_session(&self, _: &SessionCtx) -> Decision {
            Decision::Allow
        }
        fn on_request(&self, _: &SessionCtx, _: &CapRequest) -> Decision {
            Decision::Allow
        }
        fn on_call(&self, _: &SessionCtx, _: &Call) -> Decision {
            Decision::Allow
        }
    }
    struct AutoApprove;
    #[async_trait::async_trait]
    impl Approver for AutoApprove {
        async fn decide(&self, _: &ApprovalRequest) -> Verdict {
            Verdict::Approved { by: vec![] }
        }
    }

    /// A recorder that captures Output bytes it receives (a viewer's live view).
    #[derive(Clone, Default)]
    struct CapRec(Arc<Mutex<Vec<u8>>>);
    impl Recorder for CapRec {
        fn record(&self, ev: Event) {
            if let Event::Output { bytes, .. } = ev {
                self.0.lock().unwrap().extend_from_slice(&bytes);
            }
        }
    }
    impl CapRec {
        fn seen(&self) -> Vec<u8> {
            self.0.lock().unwrap().clone()
        }
    }

    struct NullRec;
    impl Recorder for NullRec {
        fn record(&self, _: Event) {}
    }

    fn warden_with(broker: Arc<MockBroker>) -> Warden {
        let mut runtimes: HashMap<&'static str, Arc<dyn Runtime>> = HashMap::new();
        runtimes.insert("local", Arc::new(Local));
        Warden::new(
            Arc::new(AllowAll),
            Arc::new(AutoApprove),
            vec![],
            vec![broker],
            runtimes,
            Arc::new(NullRec),
        )
    }

    fn mock_session(id: u64) -> Session {
        Session {
            id: SessionId(id),
            identity: "carol".into(),
            requests: vec![CapRequest {
                kind: MOCK,
                arg: String::new(),
            }],
            // open_session ignores session.action (it only grants + registers); a no-op placeholder.
            action: Action {
                name: "noop".into(),
                source: ActionSource::InProcess(action_fn(|_| Box::pin(async { Ok(()) }))),
            },
        }
    }

    /// An attach action that forwards input to the cap and ends when the input stream closes (the
    /// disconnect/detach signal) — like kedi's real attach loop.
    fn attach_action() -> Action {
        Action {
            name: "attach".into(),
            source: ActionSource::InProcess(action_fn(|ctx: &Ctx| {
                Box::pin(async move {
                    let cap = ctx.first_cap();
                    let mut input = match ctx.take_input() {
                        Some(i) => i,
                        None => return Ok(()),
                    };
                    use futures::StreamExt;
                    while let Some(frame) = input.next().await {
                        if let Some(c) = cap {
                            let _ = ctx.invoke(c, &frame.op, frame.data).await;
                        }
                    }
                    Ok(())
                })
            })),
        }
    }

    #[tokio::test]
    async fn open_detachable_session_is_live_with_no_viewer() {
        let revoked = Arc::new(AtomicBool::new(false));
        let broker = Arc::new(MockBroker {
            tx: std::sync::Mutex::new(None),
            revoked: revoked.clone(),
        });
        let w = Arc::new(warden_with(broker));
        let pump = w.open_session(mock_session(1)).await.expect("open");
        let _pump = tokio::spawn(pump);
        let views = w.session_views();
        assert_eq!(views.len(), 1);
        assert!(views[0].detachable);
        assert_eq!(views[0].id, 1);
        assert!(
            !revoked.load(Ordering::SeqCst),
            "cap must NOT be revoked while just open"
        );
    }

    #[tokio::test]
    async fn attach_replays_ring_and_streams_output() {
        let revoked = Arc::new(AtomicBool::new(false));
        let broker = Arc::new(MockBroker {
            tx: std::sync::Mutex::new(None),
            revoked,
        });
        let w = Arc::new(warden_with(broker.clone()));
        let pump = w.open_session(mock_session(1)).await.expect("open");
        tokio::spawn(pump);
        // push output BEFORE any viewer → it lands in the ring
        broker
            .tx
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .send(b"before\n".to_vec())
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;

        // attach a viewer; give it an input stream we keep open so the action doesn't end immediately
        let (in_tx, in_rx) = unbounded_channel::<InputFrame>();
        let obs = CapRec::default();
        let w2 = w.clone();
        let obs2 = obs.clone();
        let attach = tokio::spawn(async move {
            let input = Box::pin(tokio_stream::wrappers::UnboundedReceiverStream::new(in_rx))
                as InputStream;
            w2.attach(
                SessionId(1),
                "local",
                attach_action(),
                Arc::new(obs2),
                Some(input),
            )
            .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        // more output AFTER attach → streams live to the viewer
        broker
            .tx
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .send(b"after\n".to_vec())
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;

        let seen = String::from_utf8_lossy(&obs.seen()).into_owned();
        assert!(
            seen.contains("before"),
            "attach should replay the ring: {seen:?}"
        );
        assert!(
            seen.contains("after"),
            "live output should stream to the viewer: {seen:?}"
        );
        drop(in_tx); // detach
        let _ = attach.await;
    }

    #[tokio::test]
    async fn detach_keeps_session_alive() {
        let revoked = Arc::new(AtomicBool::new(false));
        let broker = Arc::new(MockBroker {
            tx: std::sync::Mutex::new(None),
            revoked: revoked.clone(),
        });
        let w = Arc::new(warden_with(broker));
        tokio::spawn(w.open_session(mock_session(1)).await.expect("open"));
        let (in_tx, in_rx) = unbounded_channel::<InputFrame>();
        let w2 = w.clone();
        let attach = tokio::spawn(async move {
            let input = Box::pin(tokio_stream::wrappers::UnboundedReceiverStream::new(in_rx))
                as InputStream;
            w2.attach(
                SessionId(1),
                "local",
                attach_action(),
                Arc::new(CapRec::default()),
                Some(input),
            )
            .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        drop(in_tx); // viewer disconnects → detach
        let _ = attach.await;
        assert_eq!(w.session_views().len(), 1, "session must survive a detach");
        assert!(
            !revoked.load(Ordering::SeqCst),
            "cap must NOT be revoked on detach"
        );
    }

    #[tokio::test]
    async fn reattach_moves_the_viewer() {
        let revoked = Arc::new(AtomicBool::new(false));
        let broker = Arc::new(MockBroker {
            tx: std::sync::Mutex::new(None),
            revoked,
        });
        let w = Arc::new(warden_with(broker.clone()));
        tokio::spawn(w.open_session(mock_session(1)).await.expect("open"));

        // viewer A
        let (in_tx_a, in_rx_a) = unbounded_channel::<InputFrame>();
        let obs_a = CapRec::default();
        let (w2, obs_a2) = (w.clone(), obs_a.clone());
        tokio::spawn(async move {
            let input = Box::pin(tokio_stream::wrappers::UnboundedReceiverStream::new(
                in_rx_a,
            )) as InputStream;
            w2.attach(
                SessionId(1),
                "local",
                attach_action(),
                Arc::new(obs_a2),
                Some(input),
            )
            .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        // viewer B attaches → A is dropped (exclusive move)
        let (in_tx_b, in_rx_b) = unbounded_channel::<InputFrame>();
        let obs_b = CapRec::default();
        let (w3, obs_b2) = (w.clone(), obs_b.clone());
        tokio::spawn(async move {
            let input = Box::pin(tokio_stream::wrappers::UnboundedReceiverStream::new(
                in_rx_b,
            )) as InputStream;
            w3.attach(
                SessionId(1),
                "local",
                attach_action(),
                Arc::new(obs_b2),
                Some(input),
            )
            .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let a_before = obs_a.seen().len();
        broker
            .tx
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .send(b"post-move\n".to_vec())
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(
            obs_a.seen().len(),
            a_before,
            "A must stop receiving after B attaches"
        );
        assert!(
            String::from_utf8_lossy(&obs_b.seen()).contains("post-move"),
            "B receives live output"
        );
        drop(in_tx_a);
        drop(in_tx_b);
    }

    #[tokio::test]
    async fn close_revokes_and_removes() {
        let revoked = Arc::new(AtomicBool::new(false));
        let broker = Arc::new(MockBroker {
            tx: std::sync::Mutex::new(None),
            revoked: revoked.clone(),
        });
        let w = Arc::new(warden_with(broker));
        tokio::spawn(w.open_session(mock_session(1)).await.expect("open"));
        assert_eq!(w.session_views().len(), 1);
        assert!(w.close_session(SessionId(1)), "close should succeed");
        assert!(w.session_views().is_empty(), "session gone after close");
        assert!(revoked.load(Ordering::SeqCst), "cap revoked on close");
    }

    #[tokio::test]
    async fn kill_detachable_tears_down() {
        let revoked = Arc::new(AtomicBool::new(false));
        let broker = Arc::new(MockBroker {
            tx: std::sync::Mutex::new(None),
            revoked: revoked.clone(),
        });
        let w = Arc::new(warden_with(broker));
        tokio::spawn(w.open_session(mock_session(1)).await.expect("open"));
        assert!(w.kill(SessionId(1), "operator"));
        assert!(
            w.session_views().is_empty(),
            "killed detachable session removed"
        );
        assert!(revoked.load(Ordering::SeqCst), "cap revoked on kill");
    }

    #[tokio::test]
    async fn title_and_tab_reflected_in_views() {
        let revoked = Arc::new(AtomicBool::new(false));
        let broker = Arc::new(MockBroker {
            tx: std::sync::Mutex::new(None),
            revoked,
        });
        let w = Arc::new(warden_with(broker));
        tokio::spawn(w.open_session(mock_session(1)).await.expect("open"));
        w.set_title(SessionId(1), "bash ~/proj");
        w.set_tab(SessionId(1), "tab-abc");
        let v = &w.session_views()[0];
        assert_eq!(v.title, "bash ~/proj");
        assert_eq!(v.tab, "tab-abc");
    }
}
