# warden — design

> Living document. It starts with the one idea and builds outward, one layer at a
> time. Each section assumes the one before it. Read top to bottom the first time.

---

## 0. The whole thing, one picture

![warden architecture](architecture.svg)

> Source: [`architecture.d2`](architecture.d2). Render with
> `d2 docs/architecture.d2 docs/architecture.svg`. Every box maps to a section
> below: the chokepoint is §2, the seams around it are §4, the event-stream tee is
> §5, the arrival/kill flow is §6.

---

## 1. The one idea

**An action can only touch the world through capabilities the warden grants, mediates, and records.**

That's the whole thing. Everything else in warden is a consequence of taking that
sentence literally and refusing to add a second idea next to it.

Unpack the sentence:

- **action** — some code that wants to do something (run a command, read a file,
  sign a payload, open a shell). It could be a WASM guest, a native process, or an
  in-process closure. warden doesn't care what it is.
- **the world** — anything outside the action: the filesystem, the network, a
  process, a signing key, your terminal. Side effects.
- **capability** — a single, narrow, revocable grant of *one* way to touch the
  world. Not "filesystem access" — `fs.read` of *one path*. Not "a key" — the
  *ability to sign* with a key you never see.
- **grants** — the action gets capabilities only because the warden decided to hand
  them over, one at a time, each checked.
- **mediates** — every use of a capability passes back through the warden. It's not
  fire-and-forget; the warden is on the path of every single operation.
- **records** — every grant and every operation lands in an append-only, tamper-
  evident log. What happened is not a matter of opinion.

The payoff of having exactly one idea: **least-privilege, audit, DLP masking,
record/replay, approval, revocation, and kill are not seven features.** They are
seven *rules applied at the one place where an action meets the world*. Add them by
writing rules, not by bolting on subsystems.

---

## 2. The chokepoint

If every touch of the world goes through the warden, there must be exactly one
function that *is* "touching the world." There is:

```
  action code
      │
      │  ctx.invoke(cap, op, input)      ← the ONLY door to the world
      ▼
  ┌─────────────────────────────────────────────────────────┐
  │                    Ctx::invoke                            │
  │                                                           │
  │   1. killed?          → refuse, record Denied             │
  │   2. policy.on_call   → allow / deny / escalate→approve   │
  │   3. record Call                                          │
  │   4. interceptor chain (log · mask · meter · …)           │
  │   5. capability.perform(op, input)   ← the raw side effect│
  │   6. record Result (post-mask)                            │
  └─────────────────────────────────────────────────────────┘
      │
      ▼
  the world  (a file read, a process spawn, an HMAC, a keystroke to a pty)
```

An action holds capability *handles* (`CapId`), not resources. It cannot read a
file except by calling `invoke` with an `fs.read` handle. It cannot reach a handle
it wasn't granted. And it cannot bypass steps 1–6, because `perform` — the raw
effect — is only ever reached through `invoke`.

This is why the design is honest about the **kill switch**: kill sets a flag that
step 1 checks. A killed action *keeps its CPU* but *loses the world* — every
`invoke` from then on is refused and recorded. (Preempting pure computation inside
a guest is a separate, harder problem, deliberately left to a later tier.)

The kernel that owns this door is `warden-core`. It is **sans-IO**: it performs no
actual reads, writes, or network calls itself. It only orchestrates the flow around
`capability.perform`. That keeps it tiny, dependency-free, and fully unit-testable —
and it's why the same kernel drives a local terminal and a remote gateway without
change.

---

## 3. Where we're going

The rest of this document builds outward from the chokepoint:

- **§4 The eight seams** — the extension points that make everything else pluggable.
- **§5 The event stream** — what "records" actually produces, and how replay/rewind
  fall out of it.
- **§6 Sessions & the run loop** — grant → run → mediate → revoke, and the drop
  guards that keep it honest on the failure/panic paths.
- **§7 Composition & plugins** — how a real `Warden` is assembled from parts
  (`warden-host`), and why a plugin can add a whole new layer without touching the
  kernel.
- **§8 The crates** — the map of the workspace.
- **§9 kedi** — the governed web terminal, as the worked example that exercises
  every seam.
- **§10 Honest limits** — what this is not (yet).

---

## 4. The eight seams

The kernel defines the flow (§2). It defines almost no behavior. Every place where a
real decision or a real side effect happens is a **trait** — a seam you plug an
implementation into. There are eight, plus a ninth for session lifecycle.

Think of them in two groups: **the two structural seams** that decide *what runs and
how it arrives*, and **the six mediation seams** that sit on the path of every call.

```
                          a session arrives
                                │
            ┌───────────────────┴────────────────────┐
   [Transport]  how sessions arrive     [Runtime]  how the action executes
   loopback / QUIC / gateway            in-process / WASM / native process
            └───────────────────┬────────────────────┘
                                │  for each capability the action asked for:
                          [Broker]  turns a request into a live Capability
                                │
                                ▼
                        ┌──────────────┐
   the action calls ───►│  Ctx::invoke │  and here the six mediation seams act:
                        └──────────────┘
                          [Policy]      allow / deny / escalate      (per session, grant, call)
                          [Approver]    resolves an escalation       (quorum, timeout)
                          [Interceptor] log / mask / meter the call  (a chain)
                          [Recorder]    append every event           (fan-out)
                          [Capability]  THE raw side effect          (the thing being mediated)
                          [SessionHook] open / close lifecycle       (persistence, quotas, handoff)
```

Each seam below: **the concept**, **what a real impl looks like**, and **plug it
here** — the tag you provide and the registry line that adds it (see §7 for the
mechanics).

### 4.1 `Capability` — the mediated resource *(the extension axis)*

**Concept.** A capability is one narrow, revocable way to touch the world. Its
`perform(op, input) -> output` is the *raw* effect — no policy, no logging, no
masking inside it; the kernel wraps all of that around it. It also has `revoke()`
(release the resource — kill the child, zeroize the key) and two optional hooks:
`output()` for a *continuous stream* (a pty's bytes) and `finished()` for "my
resource ended on its own" (the shell exited).

The `kind` (a `CapKind("…")` string) is what makes this the main extension axis:
`fs.read`, `exec`, `sign`, `pty`, and any new one you invent — `sql`, `http`, `s3`.

**Real impls** (`warden-caps`, `warden-secret`): `fs.read` (read *one* path),
`exec` (run *one* hash-pinned binary), `pty` (an interactive shell — the substrate
for kedi), `sign` (HMAC with a key the action never sees).

**Plug it here.** A capability is created by a `Broker` (§4.2), so you don't add a
capability directly — you add the broker that grants it. Adding a new *kind* of
capability = adding a broker that `handles` that kind.

### 4.2 `Broker` — request → live capability

**Concept.** The action declares what it wants as a `CapRequest { kind, arg }` (e.g.
`{ kind: "fs.read", arg: "/etc/hosts" }`). A broker answers two questions:
`handles(req)` — "is this mine?" — and `grant(req) -> Capability` — "here's the live
thing." This is where a secret becomes a *handle*: the `sign` broker pulls the key
from a vault and returns a capability that can HMAC but never reveal it.

**Plug it here.**

```rust
plugin(Manifest::new("pty").provides(&["cap:pty"]), |reg| {
    reg.add::<dyn Broker>(Arc::new(PtyBroker));
})
```

Add a broker to teach the warden a new capability kind. Multiple brokers coexist;
the kernel routes each request to the first whose `handles` returns true.

### 4.3 `Policy` — allow / deny / escalate

**Concept.** Pure decision logic, no IO. Called at three moments: `on_session`
(should this identity get a session at all?), `on_request` (should this grant be
allowed?), `on_call` (should this specific operation proceed?). Each returns a
`Decision`: `Allow`, `Deny(why)`, or `Escalate(reason)` — where **escalate means
"pause and ask an approver"** (§4.4). Approval is a *policy verb*, not a separate
subsystem.

**Real impl.** kedi's `TerminalPolicy`: requires a non-empty identity and denies a
blocklist (try identity `root` — the session is visibly refused).

**Plug it here.**

```rust
plugin(Manifest::new("identity-policy").provides(&["policy:identity"]), move |reg| {
    reg.add::<dyn Policy>(Arc::new(TerminalPolicy { denied }));
})
```

Multiple policies **compose most-restrictive-wins**: any `Deny` wins; else any
`Escalate`; else `Allow`. So you can stack a coarse org policy and a fine per-team
policy and get the intersection for free.

### 4.4 `Approver` — resolve an escalation

**Concept.** When policy returns `Escalate`, the operation parks and an approver
decides: `Approved { by }` or `Rejected { by, why }`. This is where **N-of-M quorum,
timeouts, and push-to-a-human** live. The spike blocks synchronously; the product
approver parks the op, pushes to a UI/chat, and resumes on quorum — same seam,
async impl.

**Plug it here.**

```rust
plugin(Manifest::new("auto-approver").provides(&["approver"]), |reg| {
    reg.add::<dyn Approver>(Arc::new(AutoApprover));   // demo: approves; real: quorum
})
```

Multiple approvers **all must approve** (attributions merge), and it is
**fail-closed**: if policy escalates but no approver is configured, the op is
rejected — an escalation with nobody to answer it must never silently pass.

### 4.5 `Interceptor` — the mediation middleware

**Concept.** A chain that wraps every call. Each interceptor gets the `Call` and a
`Next` continuation; it can inspect, log, meter, rewrite, deny, or pass through —
then call `next`. It also builds a **per-stream stateful masker** (`output_masker`)
for streaming capabilities, so a secret split across two pty reads is still caught
(a stateless per-chunk filter can't do that).

**Real impls** (`warden` bin): a `Log` interceptor and a DLP `Mask` interceptor.

**Plug it here** — order matters, so interceptors take an explicit priority:

```rust
plugin(Manifest::new("audit-mw").provides(&["interceptor:log"]), |reg| {
    reg.add_with_priority::<dyn Interceptor>(Arc::new(Log), 0);    // runs first
    reg.add_with_priority::<dyn Interceptor>(Arc::new(Mask), 10);  // then this
})
```

They compose into one chain, ordered by priority (low runs first / outermost).

### 4.6 `Recorder` — the event sink

**Concept.** `record(Event)` — an append-only structured sink. This is the "records"
in the one idea. What the sink *does* is pluggable: write hash-chained JSONL to
disk, ship to a SIEM, or (for a live client) *be the client's view*. The kernel
tees the same stream to the durable recorder and a session's live observer, so **the
client's terminal sees exactly what the record sees, post-mask** — no separate,
un-audited display path.

**Real impl.** `warden-record`: append-only JSONL, hash-chained (line N carries the
SHA-256 of line N−1), on a background thread so the audit log is never on the hot
path. (What the events *are*, and how replay works, is §5.)

**Plug it here.**

```rust
plugin(Manifest::new("record").provides(&["recorder"]), move |reg| {
    reg.add::<dyn Recorder>(recorder.clone());
})
```

Multiple recorders **fan out** — the same event to all of them.

### 4.7 `Runtime` — how the action executes

**Concept.** A runtime takes an `Action` and a `Ctx` and runs it — routing whatever
the action does into `ctx.invoke`. The action's code form is runtime-agnostic
(`ActionSource::InProcess(closure)` or `Wasm(bytes)`); each runtime handles the
variant(s) it supports. A *new runtime over an existing code form* needs no kernel
change — that's the swappability.

**Real impls.** in-process (demo/tests), `WasmRuntime` (minimal core-module ABI),
`ComponentRuntime` (the real one: WASM component model + `wit/warden.wit`, where a
capability is an opaque *resource handle* the guest holds but whose backing resource
never enters guest memory, and WASI is granted empty — the `caps` interface is the
guest's only door).

**Plug it here** — runtimes are named; the name is how a session selects one:

```rust
plugin(Manifest::new("local-runtime").provides(&["runtime:local"]), |reg| {
    reg.add::<dyn Runtime>(Arc::new(LocalRuntime));
})
```

Two runtimes with the **same name** is a **hard load error** (`DuplicateRuntime`) —
one would silently shadow the other, so composition fails loudly instead.

### 4.8 `Transport` — how sessions arrive

**Concept.** `accept()` blocks until a client has delivered a full request, then
hands the kernel an `Incoming` (the session to run, which named runtime runs it, an
optional live `observer`, and an optional mid-session `input` stream for
keystrokes/resize). The wire format is the transport's business — **the kernel never
sees bytes.** A transport can also deliver a *control verb* like `Kill`.

**Real impls.** `warden-transport` (QUIC, TLS 1.3, one session = one bidi stream),
`warden-gateway` (the remote axis: wardens dial *out* and register a name, a client
asks for a warden by name, the gateway splices the two — no inbound ports on the
warden). kedi's transport is WebTransport (HTTP/3) from the browser.

**Plug it here.** In the current spike the transport is wired by the composition
root / front-end (kedi drives its own WebTransport loop into `run_incoming`), rather
than as a registry point — noted here as the one seam not yet expressed as a plugin.

### 4.9 `SessionHook` — the lifecycle layer *(the ninth seam)*

**Concept.** Not on the call path — on the *session* path. `on_open(session)` and
`on_close(session, outcome)` fire at the session boundary. This is where things that
govern **sessions rather than calls** live: persistence, quotas, idle-timeout, and
the planned user-to-user **session handoff**. Default: no-ops.

**Plug it here.**

```rust
plugin(Manifest::new("quotas").provides(&["session-hook"]), |reg| {
    reg.add::<dyn SessionHook>(Arc::new(QuotaTracker::new()));
})
```

Multiple hooks all fire, in registration order.

### The "what to plug where" cheat-sheet

| You want to… | Plug a… | Composes by… |
|---|---|---|
| add a new kind of world-access (`sql`, `http`, an S3 op) | `Broker` (grants a `Capability`) | first-match routing |
| decide who/what is allowed | `Policy` | most-restrictive-wins |
| require human/quorum sign-off | `Approver` (+ policy `Escalate`) | all-must-approve, fail-closed |
| log / mask / meter / rate-limit every call | `Interceptor` | priority-ordered chain |
| persist / ship / mirror the audit trail | `Recorder` | fan-out |
| run actions a new way (new sandbox, new ABI) | `Runtime` (unique name) | name lookup |
| accept sessions over a new wire | `Transport` | (front-end wired, for now) |
| govern sessions (quota, timeout, handoff) | `SessionHook` | all fire |

The key property: **adding any row is writing an impl + one registry line. None of
it edits the kernel.** That's what §7 makes concrete.

---

## 5. The event stream

"Records" (§1) means: every meaningful thing the kernel does is emitted as one
**`Event`**, into an append-only stream. This is not a logging afterthought — it is
the substrate that audit, the live client view, replay, and rewind all read from.
There is no second, un-audited path.

### 5.1 The events

Every event carries the `session` it belongs to. The full set:

```
  lifecycle          SessionOpened{identity} · SessionClosed
  grants             CapGranted{cap,kind}    · Revoked{cap}
  a call, in full    Call{seq,cap,op,input}  → exactly one of:
                        Result{seq,output}    (success, output POST-mask)
                        Failed{seq,error}     (the op errored)
                        Denied{subject,why}   (policy/kill refused it)
  streaming output   Output{cap,bytes}       (a pty chunk, POST-mask)
  approval round-trip EscalationRequested{subject,reason}
                        → Approved{subject,by[]}  or  Rejected{subject,by,why}
  kill               Killed{by}
```

Three invariants make the stream trustworthy:

1. **Every `Call` gets exactly one terminal event** — `Result`, `Failed`, or
   `Denied`. A refused or errored op never leaves a dangling call. (The kernel
   enforces this: see §6.)
2. **Payloads are recorded, not just their lengths.** `Result.output` and
   `Output.bytes` hold the actual bytes — because rewind means *re-showing what was
   seen*, not summarizing it.
3. **What's recorded is post-mask.** The output events carry what crossed the
   interceptor chain — the trail never holds the raw secret on the way out. (If a
   secret is in a *call's input*, that's the secrets-in-args antipattern the `sign`
   broker exists to remove: the arg carries a handle, never the secret.)

### 5.2 One stream, two readers

The kernel tees the same event stream to two sinks (§6 wires this):

```
                     ┌─► durable Recorder   (hash-chained JSONL on disk)
   Event ──► Tee ────┤
                     └─► live observer      (the client's terminal, this session only)
```

The consequence is the design's spine: **the client's live view IS the record,
post-mask.** The browser terminal isn't a privileged, pre-masking feed that the log
is a lossy copy of — they are the same stream. What you see is exactly what is
attested, and vice versa.

### 5.3 Persistence — hash-chained, off the hot path (`warden-record`)

`FileRecorder` writes one JSON line per event. Each line carries `prev` — **the
SHA-256 of the previous line's raw bytes**:

```
  line 1:  { "prev": "0000…0000",  "event": {SessionOpened…} }
  line 2:  { "prev": sha256(line1), "event": {CapGranted…} }
  line 3:  { "prev": sha256(line2), "event": {Call…} }        ← edit this line…
  line 4:  { "prev": sha256(line3), "event": {Result…} }      ← …and THIS prev no longer matches
```

Editing any line changes its hash, so the *next* line's `prev` no longer links —
and `load()` reports `ChainBroken { line }` at the first line after the edit. (The
in-crate test doctors a recorded `"deploy"` → `"delete"` and asserts the break is
caught at exactly that line.)

Two honest properties:

- **Tamper-evident, not tamper-proof.** In-file chaining catches *interior* edits.
  Catching *tail* truncation/rewrite needs the chain head (`FileRecorder::head`)
  **anchored externally** — signed, shipped to the gateway. That's the product tier.
- **Off the hot path.** For a governed *terminal*, `record` is called on every
  keystroke and every echo chunk. Hashing + `writeln` under a lock there would put
  SHA-256 squarely in typing latency. So `record` is a lock-free channel push; a
  single background thread owns the file and the chain. Because it's async, any
  reader (`load`, `replay`, kedi's `/record` endpoint) must `flush()` first.

### 5.4 Rewind — reconstruct, don't undo (`state_at`)

`state_at(events, k)` folds the first `k` events into the **observed state at that
moment**: which sessions were open, which capabilities were held (granted, not yet
revoked), how many calls/denials, any escalation pending approval, and the last
output that crossed the chokepoint — *what the operator last saw*. That's what a
replay scrubber shows at position `k`.

The critical distinction, stated plainly in the code's own docs:

> **Rewind is reconstruction of observed state, not undo of side effects.** Scrubbing
> back to before a file was deleted shows you the state then; it does not un-delete
> the file. Side effects only reverse for actions *designed* reversible
> (transactional, snapshot, dry-run-then-commit).

### 5.5 Why the record is a separate wire type

`RecEvent` (on disk) deliberately *mirrors* `warden_core::Event` rather than reusing
it. The record is a **versioned external format** that must stay stable while kernel
internals evolve — and payloads are hex-encoded (binary-safe, hash-friendly;
turning hex back into readable text is `warden replay`'s job). Decoupling the stored
format from the in-memory enum is what lets the kernel refactor without breaking
every historical record.

---

## 6. Sessions & the run loop

§2 was one call. This is the whole life of a **session**: the arc from "a client
arrived" to "everything is released," and the guarantees the kernel holds across
every exit — including the ugly ones (a denied grant, a panic).

### 6.1 The arc

```
  run_full(session, runtime, observer, input)
    │
    ├─ set up the recorder      Tee(durable, observer)  if there's a live client
    ├─ register as LIVE         (so kill / live_sessions can see it)
    ├─ record SessionOpened
    ├─ arm SessionGuard ────────────────────── fires on EVERY exit below ↓
    ├─ session_hooks.on_open()
    │
    │   drive():
    │     ├─ gate: policy.on_session      allow / deny / escalate→approve
    │     ├─ for each requested capability:
    │     │     ├─ gate: policy.on_request
    │     │     ├─ broker.grant()  → hold in GrantGuard   (revokes on early return)
    │     │     └─ record CapGranted
    │     ├─ resolve the named runtime     (unknown name → error, guard revokes)
    │     ├─ start an output pump per streaming capability (pty)
    │     ├─ hand caps to the Ctx          (GrantGuard.disarm)
    │     ├─ runtime.run(action, ctx)      ← the action runs; every touch = ctx.invoke
    │     ├─ ctx.revoke_all()              revoke FIRST…
    │     └─ join the output pumps         …THEN join (ordering matters — see 6.4)
    │
    ├─ session_hooks.on_close(outcome)
    └─ SessionGuard drops ──► remove from live registry + record SessionClosed
```

### 6.2 The gate — one path for allow / deny / escalate

Every decision point — session open, each grant, each call — funnels through one
`gate()` function. It turns a `Decision` into proceed-or-error and records the
outcome:

- `Allow` → proceed.
- `Deny(why)` → record `Denied`, return an error.
- `Escalate(reason)` → record `EscalationRequested`, ask the approver, then record
  `Approved` (proceed) or `Rejected` (error).

Because the verbs are uniform, escalation-and-approval works identically whether
it's a whole session, a single grant, or one operation being held for sign-off.
Approval isn't a special subsystem — it's what `gate` does with an `Escalate`.

### 6.3 The two drop guards — honesty on the failure path

The easy paths are easy. The design's rigor is in what happens when something goes
wrong *mid-setup* or the action *panics*. Two RAII guards hold the invariants:

**`GrantGuard`** — holds capabilities granted during setup. If `drive` returns early
*before* the action gets them — a denied grant, a broker that fails, an unknown
runtime name — the guard drops and **revokes everything already granted** (kills the
half-spawned child, zeroizes the key it pulled), recording each `Revoked`. On the
success path, `disarm()` hands the caps to the `Ctx`, which revokes them normally at
the end. Either way, no capability is ever leaked on a partial setup.

**`SessionGuard`** — armed right after `SessionOpened`. Its `Drop` removes the
session from the live registry and records `SessionClosed` — on **every** exit,
*including a panic* inside a hook, the runtime, or an interceptor. Without it, an
unwind would leave a phantom "live" session forever: killable, counted by
`live_sessions()`, never closed in the trail. (It even recovers from a poisoned lock
rather than double-panicking during the unwind.) Honest scope: a panicking runtime
still won't run each capability's `revoke()` side effect — the caps are *dropped*,
not gracefully revoked — but world-access is severed and the audit trail stays
consistent.

The result: **the audit trail can be trusted precisely because the failure paths
were designed, not hoped for.** A record that says a session is open means it is.

### 6.4 Streaming output & the revoke-before-join ordering

A streaming capability (a pty) exposes `output()` — a channel of raw chunks. The
kernel starts a **pump thread** per stream that drains it, folds every interceptor's
per-stream stateful masker over each chunk, and records the masked bytes as
`Event::Output`. So streamed output is governed at the *same* chokepoint as a call's
result — nothing reaches the client un-mediated.

The teardown order is load-bearing and commented as such in the code: **revoke
first, then join.** A pty's pump only ends when its source hits EOF, which for a
still-live shell happens on `revoke` (revoke closes the child → the reader drains
trailing bytes → EOF → the pump ends). Joining *before* revoking would deadlock when
the action ends while the child is alive (an operator kill, or a client disconnect):
the pump would wait for an EOF that only revoke produces.

### 6.5 Kill & the live registry

While a session runs it sits in a `live` registry (id → identity, held cap kinds,
kill flag, its tee'd recorder). Two operator surfaces read it:

- `kill(session, by)` sets the kill flag (an `OnceLock`) and records `Killed{by}`
  **into that session's own stream** — so the client watching *sees* the kill land.
  Every subsequent `ctx.invoke` is refused at step 1 of the chokepoint (§2).
- `live_sessions()` snapshots open sessions — independent of the record, so a console
  can list and kill live sessions **even with recording off** (governed ≠ surveilled).

Kill severs *world-access*, promptly: an interactive action polls `ctx.killed()`
(the kedi attach loop breaks on it within its 100 ms poll) so it tears down on kill,
not only on the victim's next keystroke.

---

## 7. Composition & plugins

![warden composition](composition.svg)

> Source: [`composition.d2`](composition.d2). Where §0's diagram is the *runtime*
> flow, this is the *build-time* assembly: plugins → registry → `load()`'s two
> phases → the composition rules → one `Warden`.

§4 showed *what* the seams are. This is *how a real `Warden` gets built* from them —
the job of `warden-host`.

### The problem it solves

The kernel's `Warden::new` takes one policy, one approver, one recorder, a list of
interceptors, brokers, and runtimes — all wired by hand at a composition root. That's
fine for one program, but it means "add a feature" = "edit the one big constructor,"
and it can't express *multiple* policies/recorders or a plugin that spans several
seams at once. `warden-host` replaces hand-wiring with a small, open plugin system.

### The registry — an open set of extension points

The core structure is a **type-keyed registry**. An extension point is *any*
`Send + Sync + 'static` trait; the registry stores, per trait, a priority-ordered
list of `Arc<dyn Trait>`.

```rust
reg.add::<dyn Recorder>(Arc::new(MyRecorder));        // contribute to a point
reg.add_with_priority::<dyn Interceptor>(arc, 10);    // …with ordering
let all: Vec<Arc<dyn Policy>> = reg.all::<dyn Policy>();
```

"Open" is the important word: the eight seams are just the points the *kernel*
reserves. A plugin can `add` to a **point the kernel has never heard of** — its own
trait — and other plugins can read it. New extension points cost nothing.

### A plugin — two phases

```rust
pub trait Plugin {
    fn manifest(&self) -> Manifest;      // name + provides[] + requires[]
    fn contribute(&self, reg: &mut Registry);         // phase 1: ONLY writes
    fn assemble(&self, reg: &mut Registry) {}          // phase 2: read + add derived
}
```

Two phases, and the split is deliberate:

- **`contribute`** may only *write* to the registry. Because no plugin reads during
  this phase, **the order plugins are loaded in cannot affect correctness.** That's a
  strong, cheap guarantee.
- **`assemble`** runs after every plugin has contributed. Now the registry is
  complete, so a plugin can *read* points and add **derived** ones (e.g. read all
  `Detector`s and register a combined one). Read only contribute-phase points here —
  don't build-on-build.

For the common case (one manifest, a `contribute` body, no `assemble`) the
`plugin(manifest, closure)` helper collapses the boilerplate to one call — which is
exactly what every example in §4 used.

### The manifest — `provides` / `requires`

```rust
Manifest::new("identity-policy")
    .provides(&["policy:identity"])
    .requires(&["recorder"])          // fail load if nobody provides "recorder"
```

`provides`/`requires` are **load-time validation**, not a scheduler. Because
`contribute` is order-independent, the *whole* dependency check is: "is every
`requires` tag provided by some loaded plugin?" If not, `load` returns
`MissingRequirement` — you learn at startup, not at 3 a.m.

### `load()` — validate, run both phases, compose

```rust
let loaded = load(vec![ /* plugins */ ])?;
let warden = loaded.warden;
println!("{}", loaded.describe());   // auditable: exactly how this warden governs
```

`load` does four things:

1. **validate** every `requires` against the union of `provides` (order-independent).
2. run **`contribute`** on all plugins, then **`assemble`** on all plugins.
3. **compose the reserved points** into the single values the kernel wants:
   - policies → **most-restrictive-wins** chain
   - approvers → **all-must-approve** chain (fail-closed if none)
   - recorders → **fan-out**
   - interceptors → one **priority-ordered** chain
   - brokers → the broker list; runtimes → the name map (**duplicate name = hard
     error**); session hooks → all wired
4. hand back a `Loaded { warden, plugins, points }` — where `plugins` and the
   per-point contribution counts are an **auditable fact**: "here is exactly how this
   warden is configured to govern," printable for a startup banner or the audit panel.

### Why single-provider points still "compose"

A subtle payoff: the kernel wants *one* policy, *one* recorder. Plugins contribute
*many*. The composition rules above (most-restrictive policy, fan-out recorder,
priority interceptor chain, all-must-approve approver) are what let many plugins
share one seam without any of them knowing about the others. **The safe default is
baked into the composition, not left to each plugin to get right** — most-restrictive
and fail-closed are the conservative choices, on purpose.

### Cross-layer plugins

The examples in §4 each touch one seam via the `plugin()` helper. When a feature
spans several seams that must **share state** — say session handoff = a
`SessionHook` + a `Policy` + an `Approver` over one shared handoff table — you
implement the `Plugin` trait directly on one struct, so a single object owns all its
hooks and their shared state. That's the case the two-phase trait exists for.

---

## 8. The crates

| crate | what it is |
|---|---|
| `warden-core` | The sans-IO kernel (§2, §4, §5, §6). The seam traits + the mediation flow. Zero dependencies. |
| `warden-host` | Composition (§7): the open registry + two-phase plugin loader. |
| `warden-caps` | Capability impls: `fs.read`, `exec` (hash-pinned), `pty`. |
| `warden-secret` | Secrets-as-capabilities: the `sign` broker + an in-memory `Vault`. |
| `warden-record` | The hash-chained JSONL recorder + `state_at()` rewind. |
| `warden-wasm` | The WASM runtimes (core-module + component model). |
| `warden-transport` | QUIC transport (TLS 1.3, one session = one bidi stream). |
| `warden-gateway` | The remote axis: dial-out, register-by-name, splice. |
| `warden-web` | A minimal browser console (xterm.js over HTTP+SSE). |
| `warden` | Composition root + demo binary (the ten demos). |
| `kedi` | The governed web terminal — the worked example (§9). |

---

## 9. kedi — the worked example

Everything above is abstract until something exercises it. **kedi** is a governed web
terminal built entirely on warden: your real `$SHELL`, in a browser, at native-feeling
latency — every session recordable, replayable, and killable. It is the proof that
the seams compose into a real product, and the best way to see the design move.

### 9.1 The mapping — a terminal *is* a session

kedi doesn't invent terminal-specific machinery. It maps the terminal onto warden's
existing primitives:

```
  a browser tab / pane      →   a warden SESSION
  the shell (bash/zsh)      →   a `pty` CAPABILITY (the one thing the session is granted)
  your keystrokes           →   InputFrame{op:"input", data} → ctx.invoke(pty, "input", …)
  a resize                  →   InputFrame{op:"resize", data:"80x24"} → ctx.invoke(pty, "resize", …)
  the shell's output        →   the pty's output() stream → Event::Output → your screen
  closing the pane / Ctrl-D →   the attach action returns → session closes → shell revoked
  the audit "kill" button   →   warden.kill(session, by)
```

The whole terminal is one small **in-process action** — an "attach loop":

```rust
source: ActionSource::InProcess(Box::new(|ctx: &Ctx| {
    let pty = ctx.cap(PTY).ok_or(…)?;        // the granted capability handle
    let input = ctx.take_input().ok_or(…)?;  // client → session frames
    loop {
        match input.recv_timeout(100ms) {
            Ok(frame)   => { ctx.invoke(pty, &frame.op, frame.data)?; }  // ← the chokepoint
            Timeout if ctx.finished(pty) || ctx.killed() => break,       // shell died / killed
            Timeout     => {}                                            // poll again
            Disconnected => break,                                       // client gone
        }
    }
    Ok(())
}))
```

Read that against §2: **every keystroke is a `ctx.invoke`.** It is policy-gated,
recorded as a `Call`, run through the interceptor chain, and its echo comes back as a
masked `Event::Output`. There is no keystroke path that skips the chokepoint —
because there is no way to reach the pty except through `invoke`.

### 9.2 The warden, composed from plugins

kedi's `terminal_warden()` is exactly the §7 story in practice — five one-line
plugins:

| plugin | seam | what it does |
|---|---|---|
| `pty` | `Broker` | grants the `pty` capability (spawns the shell) |
| `local-runtime` | `Runtime` | runs the in-process attach action |
| `identity-policy` | `Policy` | requires an identity; denies a blocklist |
| `auto-approver` | `Approver` | demo: approves (real deployments swap in quorum) |
| `record` | `Recorder` | opt-in, toggleable, hash-chained file recorder |

Adding a governance layer to kedi is a **new plugin here, not a kernel edit** — a
handoff plugin contributing a `SessionHook` + `Policy`, or a DLP plugin defining a
`Detector` point + an `Interceptor`. That extensibility is the point of §7, shown on
a live product.

### 9.3 The wire — browser to warden

```
  browser (xterm.js)  ──WebTransport/QUIC (HTTP/3)──►  kedi  ──►  ctx.invoke  ──►  pty
        ▲                                                                             │
        └──────────── raw pty bytes (Event::Output, post-mask) ◄──── output pump ◄────┘
```

- **WebTransport** because it's the only way a browser speaks QUIC. A tiny HTTP
  server hands out the xterm.js page (with the self-signed cert's SHA-256 for the
  browser's `serverCertificateHashes`); the terminal I/O rides one bidi stream.
- The **live view is the governed stream.** kedi's `WtObserver` is a `Recorder` that
  forwards `Event::Output` to the WebTransport stream. It's plugged in as the
  session's *observer* (§5.2) — so the browser sees precisely the post-mask event
  stream, the same bytes the durable record sees. Not a side-channel.

### 9.4 Governance you can see

Because the events (§5) are a first-class stream, kedi's UI is mostly a *view* of it:

- **Recording is opt-in** (`ToggleRecorder`): governed ≠ surveilled. The file exists
  but nothing is written until you flip it on (UI `POST /rec` or the `--record`
  flag). Toggling yields a record covering only the on-periods; the hash chain stays
  valid over the lines actually written (gaps in time, not broken links).
- **The audit panel** lists live sessions (`live_sessions()`, works with recording
  off), streams the event feed, and offers **attributed kill** — which lands
  `Event::Killed{by}` in the session's own stream, so it shows up live *and* in
  replay.
- **Replay** reads back the verified record (`/record`) and scrubs it with `state_at`
  (§5.4) — and the record turns red if a single byte was doctored (§5.3).
- **Policy is visible**: set your identity to `root` and the session is refused with
  the reason shown right in the pane — a `Decision::Deny` you can watch happen.

### 9.5 Measured

The engine adds microseconds; the gap to a native terminal is the browser's render
path, not warden. From the built-in benchmarks (release, Linux, loopback):

| what | number |
|---|---|
| keystroke → echo round-trip (engine, browser excluded) | **p50 ≈ 38 µs**, p99 < 1 ms |
| bulk output through the governed pipeline | **~400 MiB/s** |
| audit cost | ×2 bytes (hex), async drain ~35–40 MiB/s |

The known cost of "everything is recorded": output is hex-encoded in the log (×2
write amplification), and under a bulk flood the async recorder lags (a 32 MiB burst
reaches the client in ~80 ms but the log finishes ~1.7 s later, buffered in an
unbounded channel). Fine for interactive use; the product tier bounds the channel and
adds an explicit audit-backpressure policy.

---

## 10. Honest limits

The design is a working spike, kept deliberately honest. These are not bugs; they're
the seams where the spike-grade impl sits behind a real interface, so the product
tier is a swap, not a redesign.

- **Sync kernel.** `warden-core` is synchronous, thread-per-session, for clarity. The
  product is async throughout — that changes the trait *signatures* (streams + IO),
  not the *shape* (the seams, the chokepoint, the events all stand).
- **Wire security is spike-grade.** Self-signed certs, skip-verify clients, loopback
  binds. Identity is **claimed, not authenticated** — attribution, not auth. Real auth
  on the wire (mTLS / OIDC) is the next tier and lands behind the existing `Transport`
  seam.
- **Tamper-evident, not tamper-proof.** The hash chain catches interior edits;
  catching tail truncation needs the chain head anchored externally (§5.3).
- **Rewind is reconstruction, not undo** (§5.4). Observed state, not reversed side
  effects.
- **Kill severs the world, not the CPU.** A killed action loses every capability at
  the chokepoint immediately, but pure computation inside a WASM guest keeps running
  until it next calls out; true preemption is the wasm epoch-interruption tier, later.
- **Panic revokes by drop, not gracefully.** `SessionGuard` keeps the audit trail
  consistent through a panic (§6.3), but a panicking runtime drops caps rather than
  running their `revoke()` side effects.
- **In-memory vault, blocking approver, unbounded audit channel.** All three are the
  demo-grade impls behind their seams (`Vault`, `Approver`, `Recorder`); the product
  versions — real KMS/HSM, async quorum approver, bounded channel with backpressure —
  live behind the same traits.
- **DLP masking is not wired in kedi.** The spike's literal-secret masker was a demo
  toy; real detection (regex/entropy over logical terminal content, off the hot path)
  is deferred. The `Interceptor` seam and its per-stream stateful masker exist and are
  exercised by the `warden` demo bin — kedi's governance today is *recorded +
  replayable + killable*, not *masked*.
- **Transport isn't a plugin point yet.** The seven other seams compose via
  `warden-host`; the `Transport` is still wired by the front-end/composition root
  (§4.8).

---

*This document describes warden v0.1.0. It is the design as shipped — where the code
and this doc disagree, the code wins; fix the doc.*
