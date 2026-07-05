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

| smell (as originally found) | what the code showed |
|---|---|
| `Transport` bypassed | kedi and the gateway call `endpoint.accept()` (wtransport/quinn), **not** the `Transport` trait. Only the `warden` demo bin uses `transport.accept()`. The flagship consumer routed around the seam. |
| kernel spawns threads | `run_full` did `std::thread::spawn` for each streaming capability's output pump — the kernel picking *one OS thread per stream*, a concurrency policy that belongs to the host. |
| `SessionHook` unused | the only `impl SessionHook` was a test counter. Zero real users; a guess at a host need (handoff/quotas) that no host had. |

Each was the kernel owning a decision the host should make. **All three are now
resolved** (see Status, below); this note is kept as the record of the reasoning.

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

2. **The kernel stops spawning the pump — the async kernel runs it as a future.**
   *(Done, via the async conversion.)* `warden-core` no longer calls `thread::spawn`.
   There was a brief interim `Spawner` seam (a host-provided thread/task scheduler);
   the async move **retired it**: the pump is now a future the kernel drives
   concurrently with the action via `futures::join`. No thread, no seam, no host
   choice — async is itself the mechanism-neutral concurrency the Spawner was reaching
   for. `output()` returns an async `Stream`; the pty's genuinely-blocking OS read
   stays on its own thread inside `warden-caps`, bridged to that stream by a tokio
   mpsc. The kernel is now sans-IO in full: no reads/writes/network **and** it
   schedules nothing.

3. **`SessionHook` parks.** Remove it from the reserved seams (keep the idea in
   DESIGN.md §6 as "where handoff/quotas will attach") until a real implementation
   forces its shape. A seam with one test-only impl is a liability, not an asset —
   it's an unproven contract the kernel must keep stable.

Net effect on the §4 seam story: **from "nine traits" toward a smaller, honest core** —
the capability axis (`Capability`+`Broker`), the decision (`Policy`+`Approver`), the
observer axis (`Interceptor`+`Recorder`), and `Runtime`. Ingress, scheduling, and
lifecycle-wiring are named as host concerns, on purpose.

## Status — all done

Every cut the boundary implied is landed:

1. **Demote `Transport` + park `SessionHook`** — `SessionHook` removed (it had only a
   test impl); `Transport` reframed as a host concern (kedi bypasses the trait).
2. **Take pump scheduling out of the kernel** — done by the **async kernel**: the pump
   is a `futures::join`ed future, not a spawned thread (the interim `Spawner` seam was
   retired in the same move). `output()` returns an async `Stream`.
3. **The async kernel itself** — the seam methods that touch the world are `async`; the
   kernel schedules nothing and does no IO. This was the deeper move the boundary
   enabled, now complete.

The kernel over-reach is fully corrected: `warden-core` owns the inner loop (the
chokepoint, the gate, grant→revoke, the event stream, the seam contracts) and nothing
of the outer loop (ingress, scheduling, lifecycle wiring). The lesson stands: **draw
the boundary first, cut to it deliberately** — each cut was small and safe because this
note said where the line was before any code moved.

The lesson worth keeping: **draw the boundary first, cut to it deliberately.** Each cut
here was small and safe *because* the map (this note) said where the line was before any
code moved.
