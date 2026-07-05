//! warden-host — the plugin composition layer for warden.
//!
//! The kernel (`warden-core`) is a small set of seam traits and one chokepoint. This crate is how
//! you *assemble* a `Warden` from independent, cross-cutting **plugins** without editing either the
//! kernel or a monolithic composition root.
//!
//! Two ideas make it extensible "from the beginning":
//!
//! 1. **Extension points are types; the registry is open.** An extension point is any
//!    `Send + Sync + 'static` trait. A [`Registry`] maps each point's type to the contributions
//!    registered against it. The kernel *reserves* the handful of points its own flow consumes
//!    (`Policy`, `Approver`, `Interceptor`, `Recorder`, `Broker`, `Runtime`) and
//!    reads those after load — but the registry itself is open: a plugin may **define a brand-new
//!    point** (its own trait) that other plugins contribute to and it consumes, none of which the
//!    kernel or the host ever enumerated. The category list is not closed.
//!
//! 2. **A plugin is a cross-layer bundle, loaded in two phases.** A [`Plugin`] declares a
//!    [`Manifest`] (name · provides · requires) and contributes in two phases:
//!    [`contribute`](Plugin::contribute) adds primitives (only writes — so plugin order never
//!    affects correctness), then [`assemble`](Plugin::assemble) may *read* the now-complete
//!    contribute-phase registry and add *derived* points (e.g. build one `Interceptor` out of every
//!    `Detector` any plugin registered). `requires` is then pure validation, not scheduling.
//!
//! The single-provider kernel points (`Policy`, `Approver`, `Recorder`) are composed into chains so
//! many plugins can each own a fragment: policy is **most-restrictive-wins**, approval is
//! **all-must-approve** (fail-closed if none), recording **fans out**.

use std::any::{Any, TypeId};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use warden_core::{
    ApprovalRequest, Approver, Broker, Call, Decision, Event, Interceptor, Policy, Recorder,
    Runtime, SessionCtx, Verdict, Warden,
};

// ── the open, type-keyed registry ─────────────────────────────────────────────────────────────

/// An open registry of extension-point contributions, keyed by the point's *type*.
///
/// A point is any `?Sized + Send + Sync + 'static` trait; contributions are `Arc<dyn Point>`.
/// Storage is type-erased (`TypeId` → `Vec<(priority, Arc<dyn Point>)>` inside a `Box<dyn Any>`),
/// so new points cost nothing and need no central registration. Kernel and plugins alike read a
/// point with [`all`](Registry::all); the kernel reads its reserved points after loading, plugins
/// read plugin-defined points in [`Plugin::assemble`].
#[derive(Default)]
pub struct Registry {
    points: HashMap<TypeId, Box<dyn Any + Send + Sync>>,
}

impl Registry {
    /// Contribute an implementation of point `P` (priority 0 — registration order otherwise).
    pub fn add<P: ?Sized + Send + Sync + 'static>(&mut self, item: Arc<P>) {
        self.add_with_priority(0, item);
    }

    /// Contribute with an explicit priority. Lower runs earlier where a point is an ordered chain
    /// (e.g. an interceptor that must mask *before* another records). Order-independent points
    /// (deny-wins policy) ignore it. Priority is the *chain* order and is deliberately separate from
    /// load order — conflating the two is how a secret ends up masked-after-it-was-recorded.
    pub fn add_with_priority<P: ?Sized + Send + Sync + 'static>(
        &mut self,
        priority: i32,
        item: Arc<P>,
    ) {
        let entry = self
            .points
            .entry(TypeId::of::<P>())
            .or_insert_with(|| Box::new(Vec::<(i32, Arc<P>)>::new()) as Box<dyn Any + Send + Sync>);
        entry
            .downcast_mut::<Vec<(i32, Arc<P>)>>()
            .expect("registry point type mismatch (a TypeId collision would be a std bug)")
            .push((priority, item));
    }

    /// Every contribution to point `P`, priority-ordered (stable within a priority).
    #[must_use]
    pub fn all<P: ?Sized + Send + Sync + 'static>(&self) -> Vec<Arc<P>> {
        match self.points.get(&TypeId::of::<P>()) {
            None => Vec::new(),
            Some(b) => {
                let v = b
                    .downcast_ref::<Vec<(i32, Arc<P>)>>()
                    .expect("registry point type mismatch");
                let mut items: Vec<(i32, Arc<P>)> = v.clone();
                items.sort_by_key(|(p, _)| *p); // stable sort keeps registration order within a priority
                items.into_iter().map(|(_, a)| a).collect()
            }
        }
    }

    /// How many contributions point `P` has (reads the length directly — no clone or sort).
    #[must_use]
    pub fn count<P: ?Sized + Send + Sync + 'static>(&self) -> usize {
        self.points
            .get(&TypeId::of::<P>())
            .and_then(|b| b.downcast_ref::<Vec<(i32, Arc<P>)>>())
            .map_or(0, Vec::len)
    }
}

// ── plugins ────────────────────────────────────────────────────────────────────────────────────

/// What a plugin is and depends on. `provides`/`requires` are free-form capability tags checked at
/// load; because contribution is order-independent (phase 1 only writes), `requires` is validation,
/// not scheduling — a missing requirement fails the load loudly instead of yielding an empty point.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub name: String,
    pub provides: Vec<String>,
    pub requires: Vec<String>,
}

impl Manifest {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            provides: Vec::new(),
            requires: Vec::new(),
        }
    }
    #[must_use]
    pub fn provides(mut self, tags: &[&str]) -> Self {
        self.provides.extend(tags.iter().map(|s| s.to_string()));
        self
    }
    #[must_use]
    pub fn requires(mut self, tags: &[&str]) -> Self {
        self.requires.extend(tags.iter().map(|s| s.to_string()));
        self
    }
}

/// A cross-layer extension bundle. One plugin can touch many layers (a Broker + a Policy + an
/// Interceptor, sharing state) and define its own points. Register contributions in [`contribute`]
/// (add primitives) and [`assemble`] (add points derived from other plugins' contributions).
///
/// Most plugins wrap a single contribution — for those, skip the trait and use the [`plugin`]
/// closure adapter.
pub trait Plugin: Send + Sync {
    fn manifest(&self) -> Manifest;
    /// Phase 1: add primitives to any point. **Only writes** — never read the registry here, so the
    /// order plugins are given never affects correctness.
    fn contribute(&self, reg: &mut Registry);
    /// Phase 2: the contribute-phase registry is complete; read points and add *derived* ones.
    /// Default: nothing. (Read only contribute-phase points here — don't build-on-build.)
    fn assemble(&self, _reg: &mut Registry) {}
}

/// A closure-based plugin for the common case: one manifest, a `contribute` body, no `assemble`.
/// Turns a five-line unit-struct-and-impl into one call.
///
/// ```
/// # use std::sync::Arc;
/// # use warden_host::{plugin, Manifest, load};
/// # use warden_core::{Recorder, Event};
/// struct Log;
/// impl Recorder for Log { fn record(&self, _ev: Event) {} }
///
/// let audit = plugin(Manifest::new("audit").provides(&["recorder"]), |reg| {
///     reg.add::<dyn Recorder>(Arc::new(Log));
/// });
/// let loaded = load(vec![audit]).unwrap();
/// assert_eq!(loaded.plugins, ["audit"]);
/// ```
#[must_use]
pub fn plugin(
    manifest: Manifest,
    contribute: impl Fn(&mut Registry) + Send + Sync + 'static,
) -> Box<dyn Plugin> {
    struct FnPlugin<F> {
        manifest: Manifest,
        contribute: F,
    }
    impl<F: Fn(&mut Registry) + Send + Sync + 'static> Plugin for FnPlugin<F> {
        fn manifest(&self) -> Manifest {
            self.manifest.clone()
        }
        fn contribute(&self, reg: &mut Registry) {
            (self.contribute)(reg);
        }
    }
    Box::new(FnPlugin {
        manifest,
        contribute,
    })
}

// ── composition of the single-provider kernel points ─────────────────────────────────────────

/// Most-restrictive-wins over every contributed policy: any `Deny` wins; else any `Escalate`; else
/// `Allow`. Empty → `Allow`. (An allow-overrides-deny tier is a future manifest flag.)
struct PolicyChain(Vec<Arc<dyn Policy>>);
impl PolicyChain {
    fn combine(it: impl Iterator<Item = Decision>) -> Decision {
        let mut pending = Decision::Allow;
        for d in it {
            match d {
                Decision::Deny(why) => return Decision::Deny(why),
                Decision::Escalate(r) => pending = Decision::Escalate(r),
                Decision::Allow => {}
            }
        }
        pending
    }
}
impl Policy for PolicyChain {
    fn on_session(&self, s: &SessionCtx) -> Decision {
        Self::combine(self.0.iter().map(|p| p.on_session(s)))
    }
    fn on_request(&self, s: &SessionCtx, req: &warden_core::CapRequest) -> Decision {
        Self::combine(self.0.iter().map(|p| p.on_request(s, req)))
    }
    fn on_call(&self, s: &SessionCtx, call: &Call) -> Decision {
        Self::combine(self.0.iter().map(|p| p.on_call(s, call)))
    }
}

/// All contributed approvers must approve (their approvers' attributions merge). Any rejection is
/// decisive. **Fail-closed:** no approver configured → reject (an escalation with nobody to approve
/// it must not silently pass).
struct ApproverChain(Vec<Arc<dyn Approver>>);
#[async_trait::async_trait]
impl Approver for ApproverChain {
    async fn decide(&self, req: &ApprovalRequest) -> Verdict {
        if self.0.is_empty() {
            return Verdict::Rejected {
                by: "warden".into(),
                why: "no approver configured (fail-closed)".into(),
            };
        }
        let mut merged = Vec::new();
        for a in &self.0 {
            match a.decide(req).await {
                Verdict::Approved { by } => merged.extend(by),
                rejected => return rejected,
            }
        }
        Verdict::Approved { by: merged }
    }
}

/// Fan one event stream out to every contributed recorder.
struct Fanout(Vec<Arc<dyn Recorder>>);
impl Recorder for Fanout {
    fn record(&self, ev: Event) {
        for r in &self.0 {
            r.record(ev.clone());
        }
    }
}

// ── the loader ────────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
#[non_exhaustive]
pub enum LoadError {
    /// A plugin's `requires` tag is provided by no loaded plugin.
    MissingRequirement { plugin: String, needs: String },
    /// Two plugins contributed a runtime with the same `name()` — one would silently shadow the
    /// other, so composition fails loudly instead.
    DuplicateRuntime { name: String },
}
impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::MissingRequirement { plugin, needs } => {
                write!(
                    f,
                    "plugin `{plugin}` requires `{needs}`, which no loaded plugin provides"
                )
            }
            LoadError::DuplicateRuntime { name } => {
                write!(f, "two plugins registered a runtime named `{name}`")
            }
        }
    }
}
impl std::error::Error for LoadError {}

/// The population of one reserved extension point, for the composition summary.
#[derive(Debug, Clone)]
pub struct PointCount {
    pub point: &'static str,
    pub contributions: usize,
}

/// A composed warden plus what went into it — the plugin set and reserved-point populations are an
/// auditable fact ("here is exactly how this warden is configured to govern"). Plugin-defined points
/// are not enumerated here (their types are only known to the plugins that use them).
pub struct Loaded {
    pub warden: Warden,
    pub plugins: Vec<String>,
    pub points: Vec<PointCount>,
}

impl Loaded {
    /// A one-line-per-fact summary for a startup banner or the audit panel.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut s = format!("plugins: {}\n", self.plugins.join(", "));
        for pc in &self.points {
            s.push_str(&format!("  {:<12} {}\n", pc.point, pc.contributions));
        }
        s
    }
}

/// Load plugins into a governed `Warden`: validate requirements, run both phases, then compose the
/// reserved points (policy/approver chains, recorder fan-out, interceptor chain, brokers, runtimes,
/// session hooks). Plugin-defined points stay in play for plugins to consume among themselves.
///
/// ```
/// # use std::sync::Arc;
/// # use warden_host::{plugin, Manifest, load};
/// # use warden_core::{Recorder, Event};
/// # struct Log; impl Recorder for Log { fn record(&self, _ev: Event) {} }
/// let loaded = load(vec![
///     plugin(Manifest::new("audit").provides(&["recorder"]), |reg| {
///         reg.add::<dyn Recorder>(Arc::new(Log));
///     }),
/// ])?;
/// assert!(loaded.points.iter().any(|p| p.point == "recorder" && p.contributions == 1));
/// # Ok::<(), warden_host::LoadError>(())
/// ```
pub fn load(plugins: Vec<Box<dyn Plugin>>) -> Result<Loaded, LoadError> {
    // 0) validate requires (order-independent, so this is the whole dependency check)
    let mut provided: HashSet<String> = HashSet::new();
    let mut names = Vec::new();
    let manifests: Vec<Manifest> = plugins.iter().map(|p| p.manifest()).collect();
    for m in &manifests {
        names.push(m.name.clone());
        for p in &m.provides {
            provided.insert(p.clone());
        }
    }
    for m in &manifests {
        for req in &m.requires {
            if !provided.contains(req) {
                return Err(LoadError::MissingRequirement {
                    plugin: m.name.clone(),
                    needs: req.clone(),
                });
            }
        }
    }

    // 1) contribute (writes only), then 2) assemble (read + derive)
    let mut reg = Registry::default();
    for p in &plugins {
        p.contribute(&mut reg);
    }
    for p in &plugins {
        p.assemble(&mut reg);
    }

    // compose the reserved points the kernel consumes
    let policy = Arc::new(PolicyChain(reg.all::<dyn Policy>()));
    let approver = Arc::new(ApproverChain(reg.all::<dyn Approver>()));
    let recorder = Arc::new(Fanout(reg.all::<dyn Recorder>()));
    let interceptors = reg.all::<dyn Interceptor>(); // priority-ordered
    let brokers = reg.all::<dyn Broker>();
    // build the runtime map by name — a name collision would silently shadow, so fail loudly
    let runtime_list = reg.all::<dyn Runtime>();
    let mut runtimes: HashMap<&'static str, Arc<dyn Runtime>> = HashMap::new();
    for r in runtime_list {
        let name = r.name();
        if runtimes.insert(name, r).is_some() {
            return Err(LoadError::DuplicateRuntime {
                name: name.to_string(),
            });
        }
    }
    let points = [
        ("policy", reg.count::<dyn Policy>()),
        ("approver", reg.count::<dyn Approver>()),
        ("interceptor", interceptors.len()),
        ("recorder", reg.count::<dyn Recorder>()),
        ("broker", brokers.len()),
        ("runtime", runtimes.len()),
    ]
    .into_iter()
    .map(|(point, contributions)| PointCount {
        point,
        contributions,
    })
    .collect();

    let warden = Warden::new(policy, approver, interceptors, brokers, runtimes, recorder);

    Ok(Loaded {
        warden,
        plugins: names,
        points,
    })
}

#[cfg(test)]
mod tests;
