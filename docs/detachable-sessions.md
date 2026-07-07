# Detachable sessions — the concrete kernel design (Stage 1)

Realizes "a session is a global warden primitive": a running capability + identity + record that
exists independently of any viewer. A viewer (browser stream = observer + input + attach action) binds
and unbinds. Detach/re-attach is intrinsic — it lives in **warden-core**, opt-in per session, with the
existing non-detachable path left byte-for-byte unchanged.

Decisions (locked): end only on close / kill / capability self-exit; exclusive-move attach now (sink
shaped for fan-out later); teleport = re-attach elsewhere.

## What's already built (foundation, committed to the working tree)
- `SwapSink` (lib.rs ~712): a `Recorder` = the swappable current-viewer sink + a bounded (`RING_CAP`
  256 KiB) replay ring of recent `Output` bytes. `attach(obs, sid, cap)` replays the ring to `obs`
  then installs it (dropping any prior — the exclusive move). `detach()` clears it. `record()` appends
  Output to the ring and forwards to the current sink if any.
- `LiveSession` (lib.rs ~760) gained: `title`, `tab` (Mutex<String>), `swap: Option<Arc<SwapSink>>`
  (Some = detachable), `detachable: bool`.
- `SessionView` + `Warden::session_views()` / `set_title` / `set_tab` — the palette's data source.
- Existing `run_full` builds a NON-detachable `LiveSession` (swap None) — unchanged behavior.

## The one invasive change: `Ctx.caps` Box → Arc
Today `Ctx.caps: HashMap<CapId, Box<dyn Capability>>` — the Ctx *owns* the caps; `revoke_all` runs when
the action ends. For a durable session the caps must outlive any one attach, so the **registry** owns
them and each per-attach `Ctx` shares them:

- Change `Ctx.caps` to `HashMap<CapId, Arc<dyn Capability>>`.
- `Capability` methods take `&self` already (invoke/output/revoke/finished) → `Arc` works unchanged at
  the call sites (`self.caps.get(&cap)` returns `&Arc<..>`; deref is transparent). Touch points:
  `invoke` (lib.rs:581), `finished` (666-667), `first_cap` (705-706), `revoke_all` (677-685),
  `GrantGuard.caps` (758) + `disarm` (764-767), the pump loop `for (id, cap) in &guard.caps` (~979),
  and `broker.grant()` returns `Box` → wrap in `Arc` at the grant site (956-963).
- `revoke_all` stays as-is (iterates, calls `cap.revoke()`), but WHEN it's called changes (below).
- `cap.output()` is single-shot `take()` — called ONCE when the durable pump starts, never again. Fine.

This is a mechanical, contained change: `Box`→`Arc` in ~8 spots, all in warden-core. No behavior change
for non-detachable sessions (they still revoke on action end).

## The durable lifecycle (new methods on `Warden`)

Split today's welded `drive` into **open** (grant + register + start the durable pump, once per
session) and **attach** (bind a viewer, run the action, detach-not-revoke on end, N times per session).

```
open_session(session, runtime, detachable=true) -> Result<()>
```
- Gate `on_session`, grant caps (as today: gate `on_request` per req → broker.grant → Arc-wrap →
  record CapGranted). On any grant failure: revoke what was granted, return (unchanged failure path).
- Build the session's recorder = `Tee(base, SwapSink)` where the `SwapSink` is stored in the
  `LiveSession.swap`. Register `LiveSession { swap: Some(sink), detachable: true, caps: <Arc map moved
  here>, recorder, killed, identity, title, tab, caps-kinds }`. Record `SessionOpened`.
- Start the **long-lived output pump** as a detached tokio task (NOT joined to any action): for each
  streaming cap, `cap.output()` → mask → `recorder.record(Event::Output)` (→ SwapSink → ring + current
  sink). The pump ends only when the cap's stream EOFs (i.e. on revoke at close/kill). Because the pump
  outlives attaches, output is captured to the ring even while detached (no viewer) — so a re-attach
  replays it.
- Do NOT run the action here; do NOT revoke. Return — the session is live + detached.

Caps ownership subtlety: the caps map is now in `LiveSession`. The pump task needs the cap Arcs (clone
them for the pump). Each attach's `Ctx` also needs them → clone the Arc map from the registry into the
Ctx at attach time. All share the same underlying capability objects (the pty child, the app worker).

```
attach(session_id, observer, input) -> Result<()>
```
- Look up the `LiveSession`; error if unknown or not detachable. Install `observer` into the SwapSink
  via `sink.attach(observer, sid, cap_id)` — replays the ring (scrollback) + drops any prior viewer
  (whose transport stream then ends → its tab closes the pane: the teleport move).
- Build a `Ctx` sharing the registry's cap Arcs, with `input` = this connection's input stream, the
  session recorder, killed flag. Run the action (`rt.run(session.action, &ctx)`) — the attach loop
  forwards input→invoke and relies on the durable pump for output.
- When the action returns (viewer disconnected: input stream ended), **detach** (`sink.detach()`) and
  return — do NOT revoke, do NOT remove from registry. The session lives on, detached.
- Guard: if the session was killed/closed while attached, the action ends (kill flag bites at the
  chokepoint / the loop polls `finished`), and close_session (below) does the revoke.

```
close_session(session_id) -> bool     // + existing kill(session_id, by)
```
- The ONLY paths that tear down. Revoke the caps (`cap.revoke()` each → records Revoked → cap streams
  EOF → the durable pump drains its tail and ends), then remove from `live` + record `SessionClosed`.
- Preserve the load-bearing "revoke first, THEN let the pump finish" ordering here: revoke, then await
  the pump task (or let it self-complete on EOF). kill() additionally sets the flag first (as today) so
  an attached action tears down promptly.

## Registration timing / SessionGuard
`SessionGuard` (lib.rs:736) currently removes from `live` + records SessionClosed on every `run_full`
exit. For durable sessions this must NOT fire on attach-return. Approach: durable sessions don't use
`run_full`/`SessionGuard` at all — they use `open_session` (registers, no guard) + `attach` (no
registry removal) + `close_session`/`kill` (explicit removal + SessionClosed). The guard stays for the
non-detachable `run_full` path only. So: two code paths, sharing the grant + gate + pump helpers,
differing in who owns the caps and when revoke fires.

Refactor to share code: extract `grant_caps(session, recorder, sctx) -> Result<Arc-cap-map>` and
`spawn_pump(caps, recorder, interceptors)` helpers used by both `drive` (non-detachable, caps in Ctx,
revoke on action end, pump joined) and `open_session` (detachable, caps in registry, revoke on close,
pump detached).

## Ctx: an `invoke`-only Ctx for attach
The attach action needs a Ctx to invoke + take input, but it must NOT own/revoke the caps. Simplest:
the Ctx holds the shared Arc caps (clone from registry) and its `revoke_all` is simply never called on
the attach path (attach ends with `sink.detach()`, not `ctx.revoke_all()`). The caps' real revoke is
in `close_session`. So `Ctx` is unchanged in shape (beyond Box→Arc); the difference is purely which
caller calls `revoke_all`.

## kill() interaction
`kill` (lib.rs:868) sets the flag + records Killed today. For durable sessions it must ALSO revoke +
remove (today it relied on the action ending → run_full teardown, which no longer happens). So `kill`
becomes: set flag + record Killed, then if the session is detachable, do the close_session teardown
(revoke + remove + SessionClosed). Non-detachable: unchanged (the action sees the flag, ends, run_full
tears down).

## Tests (warden-core, Stage 1 — prove in isolation, no kedi)
Use a mock streaming capability (like the pty: an output stream you can push to) + a mock broker.
1. `open_detachable_session_is_live_with_no_viewer`: open → `session_views()` has it, detachable=true,
   no panic; the cap's stream stays open (not revoked).
2. `attach_replays_ring_and_streams_output`: push output before attach → attach an observer → observer
   receives the ring replay + subsequent live output.
3. `detach_keeps_session_alive`: attach → end the input stream (detach) → session still in
   `session_views()`, cap NOT revoked; output still buffered to the ring.
4. `reattach_moves_the_viewer`: attach A, attach B → A's observer stops receiving, B receives (+ ring
   replay). (Exclusive move.)
5. `close_revokes_and_removes`: open → close_session → cap.revoke() called, session gone from
   `session_views()`, `SessionClosed` recorded.
6. `kill_detachable_tears_down`: open → kill → Killed recorded + revoked + removed.
7. `set_title`/`set_tab` reflected in `session_views()`.
8. Regression: existing non-detachable `run_session` tests unchanged (revoke on action end).

## Then (later stages, separate)
- Stage 2 (kedi server): pane_session → open_session + attach; detach on disconnect; `{"attach"}` /
  `{"title"}` / `{"tab"}` client frames + `{"session":id}` server→client; sessions_json + title/tab;
  close on explicit close/kill.
- Stage 3 (client): Ctrl+Shift+P palette from /sessions; focus local.
- Stage 4 (client): teleport = makePane attach-mode; origin-tab detach handling.

## Non-goals / preserved invariants
- Non-detachable sessions: byte-for-byte unchanged (one-shot actions, existing tests).
- Governance chokepoint unchanged: invoke still gates/records/masks; kill still bites at invoke.
- Revoke-first-then-drain ordering preserved at the close boundary.
- Mirror (multi-viewer) is future: SwapSink holds one sink now, but is the seam to make it a Vec.
