# The core/host boundary — where warden-core ends

> A design note, not a description of the shipped code. It maps where the
> `warden-core` / host boundary *should* be, against where it currently *is*, so
> refactors have a target to aim at. Companion to [DESIGN.md](DESIGN.md).

## The finding

Three separate smells — `SessionHook` has no real user, `Transport` is bypassed by
kedi, and the "sans-IO" kernel spawns OS threads — turn out to be **one mistake in
three places:**

> **`warden-core` reaches into the *outer loop* (ingress, concurrency, lifecycle
> wiring) when its real job is the *inner loop* — the chokepoint.**

The pure kernel is: *given a session and its granted capabilities, mediate every
`invoke` — policy-gate it, record it, run it through the interceptor chain, enforce
kill.* That is the one thing only the kernel can do. Everything about *how sessions
arrive*, *how concurrent work is scheduled*, and *how a host wires lifecycle* is the
host's business — and where the kernel decided those, the real host (kedi) either
bypassed it or was forced into a choice that doesn't fit.

## The evidence

| smell | what the code shows |
|---|---|
| `Transport` bypassed | kedi and the gateway call `endpoint.accept()` (wtransport/quinn), **not** the `Transport` trait. Only the `warden` demo bin uses `transport.accept()`. The flagship consumer routes around the seam. |
| kernel spawns threads | `run_full` does `std::thread::spawn` for each streaming capability's output pump. The kernel picks *one OS thread per stream* — a concurrency policy. kedi is async/tokio; the kernel forces its streaming onto blocking std threads. |
| `SessionHook` unused | the only `impl SessionHook` is a test counter. Zero real users; it's a guess at a host need (handoff/quotas) that no host has yet. |

Each is the kernel owning a decision the host should make.

## The boundary, drawn on purpose

### Core owns — the inner loop (the chokepoint and its invariants)

Only the kernel can do these; they *are* warden:

- **`Ctx::invoke`** — the chokepoint: kill-check → op-validation → policy gate →
  record Call → interceptor chain → `perform` → record Result. (§2 of DESIGN.md)
- **The gate** — `Allow`/`Deny`/`Escalate→Approve`, uniform across session/grant/call.
- **grant → run → revoke** — the capability lifecycle *within* a session, and the two
  drop guards (`GrantGuard`, `SessionGuard`) that keep it correct on failure/panic.
- **The event stream** — every `Event`, tee'd to recorders + the live observer.
- **The seam *contracts*** — `Capability`, `Broker`, `Policy`, `Approver`,
  `Interceptor`, `Recorder`, `Runtime` (the *traits*; impls live in sibling crates).
- **The kill switch & live registry** — `kill()`, `live_sessions()`, `killed()`.

The corresponding pub items — `Ctx`, `Warden` (minus the outer-loop methods),
`Decision`, `Verdict`, `Event`, `Call`, `OpSpec`, `CapRequest`, the seam traits — all
belong to core. They are the mediation vocabulary.

### Host owns — the outer loop (drive, schedule, wire)

The host decides these; the kernel should *describe the work*, not *do it*:

- **Ingress** — how sessions arrive and are accepted. kedi has an async WebTransport
  loop; the demo bin has a blocking QUIC loop. The kernel should take a *ready
  session* (`run_incoming`/`run_session`) and stay out of `accept()`. → **`Transport`
  is a host concern, not a kernel seam.**
- **Concurrency / scheduling** — how the output pump runs. The kernel should hand the
  host a *unit of work* ("drain this stream, fold these maskers over each chunk, emit
  `Output` events") and let the host run it on a thread, a tokio task, whatever fits.
  → **the kernel should not `thread::spawn`.**
- **Lifecycle wiring** — quotas, idle-timeout, handoff. Real, but host-level policy.
  Until a real user exists, this is a *host* responsibility, not a reserved kernel
  seam. → **`SessionHook` parks (or moves host-side) until something implements it.**

## What this implies (the target, not today's code)

1. **`Transport` leaves the kernel's seam list.** It stays a *useful trait* for hosts
   that want a uniform accept-loop (the demo bin), but DESIGN.md stops presenting it as
   a peer kernel seam. The kernel's contract is "give me a session"; getting the
   session is the host's job. (Net: the "structural seams" become just `Runtime`.)

2. **The output pump becomes a returned unit of work.** `run_full` stops spawning; it
   produces the pump closures (or an iterator of "streams to drain") and the caller
   runs them. The sync demo bin runs them on threads exactly as today; kedi runs them
   as tokio tasks. The kernel is then *actually* sans-IO — it schedules nothing.

3. **`SessionHook` parks.** Remove it from the reserved seams (keep the idea in
   DESIGN.md §6 as "where handoff/quotas will attach") until a real implementation
   forces its shape. A seam with one test-only impl is a liability, not an asset —
   it's an unproven contract the kernel must keep stable.

Net effect on the §4 seam story: **from "nine traits" toward a smaller, honest core** —
the capability axis (`Capability`+`Broker`), the decision (`Policy`+`Approver`), the
observer axis (`Interceptor`+`Recorder`), and `Runtime`. Ingress, scheduling, and
lifecycle-wiring are named as host concerns, on purpose.

## Why not just do it now

Two of the three are real refactors with blast radius:

- Removing `thread::spawn` changes `run_full`'s signature and *every* caller that runs
  a session (kedi's async loop, the demo bin, the transport/gateway paths, the tests).
  Worth doing, but it's a surgery, not a doc edit — and it wants to land with the async
  kernel work (the sync→async move touches the same code).
- Demoting `Transport`/`SessionHook` is cheaper (mostly reclassification + docs), and
  is the natural first step.

So the sequence is: **(1) this note** (done) → **(2) demote `Transport` + park
`SessionHook`** (docs + small code) → **(3) lift the output pump to the host** (with or
just before the async move). Draw the boundary first; cut to it deliberately.
