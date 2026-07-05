//! Tests for the plugin host: composition of reserved points, session-hook firing, requirement
//! validation, and — the load-bearing one — a plugin-*defined* point proving the set is open.

use super::*;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use warden_core::{
    Action, ActionSource, CapKind, CapRequest, Capability, Ctx, Result as WResult, Runtime,
    Session, SessionId, WardenError,
};

// ── a tiny real capability + broker to run a session end-to-end (no pty/shell needed) ──────────

const ECHO: CapKind = CapKind("echo");
const ECHO_OPS: &[warden_core::OpSpec] = &[
    warden_core::OpSpec {
        op: "echo",
        doc: "echo the input back",
        mutates: false,
    },
    warden_core::OpSpec {
        op: "poke",
        doc: "a mutating op (for the read-only-policy test)",
        mutates: true,
    },
];

struct EchoCap;
impl Capability for EchoCap {
    fn kind(&self) -> CapKind {
        ECHO
    }
    fn ops(&self) -> &'static [warden_core::OpSpec] {
        ECHO_OPS
    }
    fn perform(&self, _op: &str, input: &[u8]) -> WResult<Vec<u8>> {
        Ok(input.to_vec()) // echoes its input back
    }
    fn revoke(&self) {}
}

struct EchoPlugin;
impl Plugin for EchoPlugin {
    fn manifest(&self) -> Manifest {
        Manifest::new("echo").provides(&["echo-cap"])
    }
    fn contribute(&self, reg: &mut Registry) {
        struct EchoBroker;
        impl warden_core::Broker for EchoBroker {
            fn handles(&self, req: &CapRequest) -> bool {
                req.kind == ECHO
            }
            fn grant(&self, _req: &CapRequest) -> WResult<Box<dyn Capability>> {
                Ok(Box::new(EchoCap))
            }
        }
        reg.add::<dyn warden_core::Broker>(Arc::new(EchoBroker));
    }
}

/// An in-process runtime that runs an action's closure on the calling thread.
struct LocalRuntimePlugin;
impl Plugin for LocalRuntimePlugin {
    fn manifest(&self) -> Manifest {
        Manifest::new("local-runtime").provides(&["runtime:local"])
    }
    fn contribute(&self, reg: &mut Registry) {
        struct Local;
        impl Runtime for Local {
            fn name(&self) -> &'static str {
                "local"
            }
            fn run(&self, action: Action, ctx: &Ctx) -> WResult<()> {
                match action.source {
                    ActionSource::InProcess(body) => body(ctx),
                    _ => Err(WardenError::Cap("local runs in-process only".into())),
                }
            }
        }
        reg.add::<dyn Runtime>(Arc::new(Local));
    }
}

/// Collects the events it records, so tests can assert what crossed the chokepoint.
#[derive(Clone, Default)]
struct VecRec(Arc<Mutex<Vec<String>>>);
impl Recorder for VecRec {
    fn record(&self, ev: Event) {
        self.0.lock().unwrap().push(format!("{ev:?}"));
    }
}
struct RecorderPlugin(VecRec);
impl Plugin for RecorderPlugin {
    fn manifest(&self) -> Manifest {
        Manifest::new("recorder").provides(&["recorder"])
    }
    fn contribute(&self, reg: &mut Registry) {
        reg.add::<dyn Recorder>(Arc::new(self.0.clone()));
    }
}

fn run_echo(warden: &Warden, identity: &str, msg: &[u8]) -> WResult<()> {
    let msg = msg.to_vec();
    let action = Action {
        name: "echo-once".into(),
        source: ActionSource::InProcess(Box::new(move |ctx: &Ctx| {
            let cap = ctx.cap(ECHO).ok_or(WardenError::Cap("no echo".into()))?;
            ctx.invoke(cap, "echo", msg.clone())?;
            Ok(())
        })),
    };
    warden.run_session(
        Session {
            id: SessionId(1),
            identity: identity.into(),
            requests: vec![CapRequest {
                kind: ECHO,
                arg: String::new(),
            }],
            action,
        },
        "local",
    )
}

// ── a capability that records whether it was revoked, to prove failure-path cleanup ────────────

struct TrackCap(Arc<AtomicUsize>);
impl Capability for TrackCap {
    fn kind(&self) -> CapKind {
        ECHO
    }
    fn ops(&self) -> &'static [warden_core::OpSpec] {
        ECHO_OPS
    }
    fn perform(&self, _op: &str, input: &[u8]) -> WResult<Vec<u8>> {
        Ok(input.to_vec())
    }
    fn revoke(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// A broker for kind ECHO that grants a revoke-tracking cap.
fn tracking_echo_plugin(revoked: Arc<AtomicUsize>) -> Box<dyn Plugin> {
    plugin(Manifest::new("tracking-echo"), move |reg| {
        struct B(Arc<AtomicUsize>);
        impl warden_core::Broker for B {
            fn handles(&self, req: &CapRequest) -> bool {
                req.kind == ECHO
            }
            fn grant(&self, _req: &CapRequest) -> WResult<Box<dyn Capability>> {
                Ok(Box::new(TrackCap(self.0.clone())))
            }
        }
        reg.add::<dyn warden_core::Broker>(Arc::new(B(revoked.clone())));
    })
}

fn open_session(warden: &Warden, requests: Vec<CapRequest>, runtime: &str) -> WResult<()> {
    let action = Action {
        name: "noop".into(),
        source: ActionSource::InProcess(Box::new(|_ctx: &Ctx| Ok(()))),
    };
    warden.run_session(
        Session {
            id: SessionId(1),
            identity: "carol".into(),
            requests,
            action,
        },
        runtime,
    )
}

// ── 1. a warden composed purely from plugins runs a session end-to-end ─────────────────────────

#[test]
fn composes_and_runs_a_session_from_plugins() {
    let rec = VecRec::default();
    let loaded = load(vec![
        Box::new(EchoPlugin),
        Box::new(LocalRuntimePlugin),
        Box::new(RecorderPlugin(rec.clone())),
    ])
    .unwrap();
    run_echo(&loaded.warden, "carol", b"hi").unwrap();

    let evs = rec.0.lock().unwrap().join("\n");
    assert!(evs.contains("SessionOpened"));
    assert!(evs.contains("CapGranted"));
    assert!(evs.contains("Result")); // the echo crossed the chokepoint and was recorded
    assert!(evs.contains("SessionClosed"));
    assert_eq!(loaded.plugins, vec!["echo", "local-runtime", "recorder"]);

    // describe() is the auditable composition summary
    let d = loaded.describe();
    assert!(d.contains("plugins: echo, local-runtime, recorder"));
    assert!(d.contains("runtime")); // one runtime contributed
}

// ── 2. many policy plugins compose (most-restrictive-wins) ──────────────────────────────────────

#[test]
fn policies_compose_deny_wins() {
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
    struct DenyIdentity(&'static str);
    impl Policy for DenyIdentity {
        fn on_session(&self, s: &SessionCtx) -> Decision {
            if s.identity == self.0 {
                Decision::Deny(format!("`{}` blocked", self.0))
            } else {
                Decision::Allow
            }
        }
        fn on_request(&self, _: &SessionCtx, _: &CapRequest) -> Decision {
            Decision::Allow
        }
        fn on_call(&self, _: &SessionCtx, _: &Call) -> Decision {
            Decision::Allow
        }
    }
    struct P(&'static str, Arc<dyn Policy>);
    impl Plugin for P {
        fn manifest(&self) -> Manifest {
            Manifest::new(self.0)
        }
        fn contribute(&self, reg: &mut Registry) {
            reg.add::<dyn Policy>(self.1.clone());
        }
    }

    let loaded = load(vec![
        Box::new(EchoPlugin),
        Box::new(LocalRuntimePlugin),
        Box::new(P("allow", Arc::new(AllowAll))),
        Box::new(P("deny-root", Arc::new(DenyIdentity("root")))),
    ])
    .unwrap();
    assert_eq!(
        loaded
            .points
            .iter()
            .find(|p| p.point == "policy")
            .unwrap()
            .contributions,
        2
    );

    // carol allowed by both policies; root denied by one → chain denies
    assert!(run_echo(&loaded.warden, "carol", b"ok").is_ok());
    let err = run_echo(&loaded.warden, "root", b"nope").unwrap_err();
    assert!(
        matches!(err, WardenError::Denied(_)),
        "root must be denied by the policy chain"
    );
}

// ── 3. session-lifecycle hooks fire (the new seam) ─────────────────────────────────────────────

#[test]
fn session_hooks_fire_on_open_and_close() {
    #[derive(Default)]
    struct Counting {
        opened: AtomicUsize,
        closed: AtomicUsize,
    }
    impl SessionHook for Counting {
        fn on_open(&self, _: &SessionCtx) {
            self.opened.fetch_add(1, Ordering::SeqCst);
        }
        fn on_close(&self, _: &SessionCtx, _: &WResult<()>) {
            self.closed.fetch_add(1, Ordering::SeqCst);
        }
    }
    struct HookPlugin(Arc<Counting>);
    impl Plugin for HookPlugin {
        fn manifest(&self) -> Manifest {
            Manifest::new("hook")
        }
        fn contribute(&self, reg: &mut Registry) {
            reg.add::<dyn SessionHook>(self.0.clone());
        }
    }

    let counter = Arc::new(Counting::default());
    let loaded = load(vec![
        Box::new(EchoPlugin),
        Box::new(LocalRuntimePlugin),
        Box::new(HookPlugin(counter.clone())),
    ])
    .unwrap();
    run_echo(&loaded.warden, "carol", b"x").unwrap();
    assert_eq!(counter.opened.load(Ordering::SeqCst), 1);
    assert_eq!(counter.closed.load(Ordering::SeqCst), 1);
}

// ── 4. THE openness proof: a plugin DEFINES a point; others contribute; a third consumes it ─────
// `Detector` is not a kernel seam. The host never heard of it. Yet one plugin defines + consumes it
// in `assemble`, and two unrelated plugins extend it — with zero kernel/host changes. This is the
// "categories are just samples" property made concrete.

/// A plugin-defined extension point (a DLP-style detector), unknown to the kernel and the host.
trait Detector: Send + Sync {
    fn label(&self) -> &str;
}

#[test]
fn plugin_defined_point_is_open() {
    struct Regexy;
    impl Detector for Regexy {
        fn label(&self) -> &str {
            "regex"
        }
    }
    struct Entropy;
    impl Detector for Entropy {
        fn label(&self) -> &str {
            "entropy"
        }
    }
    // two plugins EXTEND a point neither the kernel nor the host defined
    struct RegexPlugin;
    impl Plugin for RegexPlugin {
        fn manifest(&self) -> Manifest {
            Manifest::new("regex-detector").provides(&["detector"])
        }
        fn contribute(&self, reg: &mut Registry) {
            reg.add::<dyn Detector>(Arc::new(Regexy));
        }
    }
    struct EntropyPlugin;
    impl Plugin for EntropyPlugin {
        fn manifest(&self) -> Manifest {
            Manifest::new("entropy-detector").provides(&["detector"])
        }
        fn contribute(&self, reg: &mut Registry) {
            reg.add::<dyn Detector>(Arc::new(Entropy));
        }
    }
    // a plugin that DEFINES the point consumes every contribution in assemble (phase 2), and turns
    // them into a kernel Interceptor — exactly the DlpCore pattern
    struct DlpCore(Arc<Mutex<Vec<String>>>); // captures which detectors it assembled, for the test
    impl Plugin for DlpCore {
        fn manifest(&self) -> Manifest {
            Manifest::new("dlp-core").requires(&["detector"])
        }
        fn contribute(&self, _reg: &mut Registry) {}
        fn assemble(&self, reg: &mut Registry) {
            let detectors = reg.all::<dyn Detector>();
            *self.0.lock().unwrap() = detectors.iter().map(|d| d.label().to_string()).collect();
            // (would build & register an Interceptor here from `detectors`)
        }
    }

    let seen = Arc::new(Mutex::new(Vec::new()));
    let loaded = load(vec![
        Box::new(RegexPlugin),
        Box::new(DlpCore(seen.clone())),
        Box::new(EntropyPlugin),
    ])
    .unwrap();
    // DlpCore saw BOTH detectors in assemble, regardless of plugin order (contribute ran first)
    let mut got = seen.lock().unwrap().clone();
    got.sort();
    assert_eq!(got, vec!["entropy", "regex"]);
    assert_eq!(loaded.plugins.len(), 3);
}

// ── 5. requires validation fails loudly ────────────────────────────────────────────────────────

#[test]
fn missing_requirement_fails_load() {
    struct Needy;
    impl Plugin for Needy {
        fn manifest(&self) -> Manifest {
            Manifest::new("needy").requires(&["a-vault"])
        }
        fn contribute(&self, _reg: &mut Registry) {}
    }
    match load(vec![Box::new(Needy)]) {
        Err(LoadError::MissingRequirement { plugin, needs }) => {
            assert_eq!(plugin, "needy");
            assert_eq!(needs, "a-vault");
        }
        Err(e) => panic!("expected MissingRequirement, got {e:?}"),
        Ok(_) => panic!("load should fail on a missing requirement"),
    }
}

// ── 6. interceptor priority orders the chain (mask-before-record semantics) ─────────────────────

#[test]
fn interceptor_priority_orders_the_chain() {
    use warden_core::{CallResult, Next};
    struct Tag(&'static str, Arc<Mutex<Vec<&'static str>>>);
    impl Interceptor for Tag {
        fn intercept(&self, call: Call, next: Next<'_>) -> WResult<CallResult> {
            self.1.lock().unwrap().push(self.0);
            next.run(call)
        }
    }
    struct TagPlugin(&'static str, i32, Arc<Mutex<Vec<&'static str>>>);
    impl Plugin for TagPlugin {
        fn manifest(&self) -> Manifest {
            Manifest::new(self.0)
        }
        fn contribute(&self, reg: &mut Registry) {
            reg.add_with_priority::<dyn Interceptor>(self.1, Arc::new(Tag(self.0, self.2.clone())));
        }
    }

    let order = Arc::new(Mutex::new(Vec::new()));
    // registered late-then-early, but priority (10, 1) must decide the chain order
    let loaded = load(vec![
        Box::new(EchoPlugin),
        Box::new(LocalRuntimePlugin),
        Box::new(TagPlugin("late", 10, order.clone())),
        Box::new(TagPlugin("early", 1, order.clone())),
    ])
    .unwrap();
    run_echo(&loaded.warden, "carol", b"x").unwrap();
    assert_eq!(
        *order.lock().unwrap(),
        vec!["early", "late"],
        "lower priority runs first"
    );
}

// ── 7. failure-path cleanup: a failed grant revokes the caps already granted ────────────────────

#[test]
fn failed_grant_revokes_already_granted_caps() {
    const MISSING: CapKind = CapKind("missing");
    let revoked = Arc::new(AtomicUsize::new(0));
    let rec = VecRec::default();
    let loaded = load(vec![
        tracking_echo_plugin(revoked.clone()),
        Box::new(LocalRuntimePlugin),
        Box::new(RecorderPlugin(rec.clone())),
    ])
    .unwrap();
    // grant ECHO (ok — a tracking cap), then a kind with NO broker → NoBroker mid-grant
    let err = open_session(
        &loaded.warden,
        vec![
            CapRequest {
                kind: ECHO,
                arg: String::new(),
            },
            CapRequest {
                kind: MISSING,
                arg: String::new(),
            },
        ],
        "local",
    )
    .unwrap_err();
    assert!(matches!(err, WardenError::NoBroker(_)));
    assert_eq!(
        revoked.load(Ordering::SeqCst),
        1,
        "the already-granted cap must be revoked"
    );
    let evs = rec.0.lock().unwrap().join("\n");
    assert!(
        evs.contains("Revoked"),
        "a Revoked event is recorded on the failure path"
    );
    assert!(
        evs.contains("SessionClosed"),
        "the session still closes in the trail"
    );
}

// ── 8. a missing runtime revokes every granted cap ─────────────────────────────────────────────

#[test]
fn missing_runtime_revokes_granted_caps() {
    let revoked = Arc::new(AtomicUsize::new(0));
    let loaded = load(vec![
        tracking_echo_plugin(revoked.clone()),
        Box::new(LocalRuntimePlugin),
    ])
    .unwrap();
    let err = open_session(
        &loaded.warden,
        vec![CapRequest {
            kind: ECHO,
            arg: String::new(),
        }],
        "does-not-exist",
    )
    .unwrap_err();
    assert!(matches!(err, WardenError::NoRuntime(_)));
    assert_eq!(
        revoked.load(Ordering::SeqCst),
        1,
        "granted caps revoked when the runtime is missing"
    );
}

// ── 9. a panic in the action still closes the session (no phantom live session) ─────────────────

#[test]
fn panic_in_action_still_closes_the_session() {
    let rec = VecRec::default();
    let loaded = load(vec![
        Box::new(EchoPlugin),
        Box::new(LocalRuntimePlugin),
        Box::new(RecorderPlugin(rec.clone())),
    ])
    .unwrap();
    let action = Action {
        name: "boom".into(),
        source: ActionSource::InProcess(Box::new(|_ctx: &Ctx| panic!("boom"))),
    };
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {})); // silence the expected panic
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        loaded.warden.run_session(
            Session {
                id: SessionId(7),
                identity: "carol".into(),
                requests: vec![CapRequest {
                    kind: ECHO,
                    arg: String::new(),
                }],
                action,
            },
            "local",
        )
    }));
    std::panic::set_hook(prev);
    assert!(outcome.is_err(), "the action panicked");
    assert!(
        loaded.warden.live_sessions().is_empty(),
        "no phantom live session after a panic"
    );
    assert!(
        rec.0.lock().unwrap().join("\n").contains("SessionClosed"),
        "SessionClosed recorded even on panic"
    );
}

// ── the OpSpec payoff: a policy that reasons about read-vs-mutate, not op strings ────────────────

/// Denies any op the capability marks `mutates` — the read-only tier. It never names an op; it keys
/// purely on `call.mutates`, which the kernel fills from the capability's published `OpSpec`. This is
/// the whole point of typing the op contract: a governance rule that works across every capability,
/// present and future, without knowing that pty's mutating op is "input" or exec's is "run".
#[test]
fn read_only_policy_denies_mutating_ops_by_contract() {
    struct ReadOnly;
    impl Policy for ReadOnly {
        fn on_session(&self, _: &SessionCtx) -> Decision {
            Decision::Allow
        }
        fn on_request(&self, _: &SessionCtx, _: &CapRequest) -> Decision {
            Decision::Allow
        }
        fn on_call(&self, _: &SessionCtx, call: &Call) -> Decision {
            if call.mutates {
                Decision::Deny(format!("read-only: `{}` mutates", call.op))
            } else {
                Decision::Allow
            }
        }
    }
    struct ReadOnlyPlugin;
    impl Plugin for ReadOnlyPlugin {
        fn manifest(&self) -> Manifest {
            Manifest::new("read-only").provides(&["policy:read-only"])
        }
        fn contribute(&self, reg: &mut Registry) {
            reg.add::<dyn Policy>(Arc::new(ReadOnly));
        }
    }

    // an action that tries a read op (echo) then a mutating op (poke) on the same capability
    fn probe() -> Action {
        Action {
            name: "probe".into(),
            source: ActionSource::InProcess(Box::new(|ctx: &Ctx| {
                let cap = ctx.cap(ECHO).ok_or(WardenError::Cap("no echo".into()))?;
                let read_ok = ctx.invoke(cap, "echo", b"hi".to_vec()).is_ok();
                let mutate_ok = ctx.invoke(cap, "poke", b"x".to_vec()).is_ok();
                assert!(read_ok, "read op should be allowed");
                assert!(
                    !mutate_ok,
                    "mutating op should be denied by the read-only policy"
                );
                Ok(())
            })),
        }
    }

    let rec = VecRec::default();
    let loaded = load(vec![
        Box::new(EchoPlugin),
        Box::new(LocalRuntimePlugin),
        Box::new(RecorderPlugin(rec.clone())),
        Box::new(ReadOnlyPlugin),
    ])
    .unwrap();
    loaded
        .warden
        .run_session(
            Session {
                id: SessionId(1),
                identity: "carol".into(),
                requests: vec![CapRequest {
                    kind: ECHO,
                    arg: String::new(),
                }],
                action: probe(),
            },
            "local",
        )
        .unwrap();

    let log = rec.0.lock().unwrap().join("\n");
    // the read produced a Result; the mutate produced a Denied citing the read-only rule
    assert!(
        log.contains("Result"),
        "the read op should have succeeded: {log}"
    );
    assert!(
        log.contains("read-only") && log.contains("mutates"),
        "the mutating op should have been denied by contract: {log}"
    );
}
