# kedi plugins — WASM-TUI apps as governed panes

> A design note (boundary-first, like [boundary.md](boundary.md)): map the pivot before cutting.
> Goal: a kedi pane can host a **WASM app** (a ratatui-style TUI compiled to a WASM component)
> instead of only a shell — governed by warden exactly like a pty session. `deck` becomes the first
> such plugin (rewritten Go→Rust/ratatui). Later: HTML panels as a second plugin kind.

## The one idea

> **A plugin is a WASM component that renders a screen and consumes keys. kedi hosts it in a pane;
> warden governs it like any session.**

Everything below follows from taking that literally — and from the fact that **three existing pieces
already do 80% of it**:

- **warden** — the governed async kernel with a `Runtime` seam (`run(action, ctx)`), a
  `ComponentRuntime` that already loads WASM components (`wit/warden.wit`, capabilities as resource
  handles, empty WASI), and record/replay/kill/policy for free at the chokepoint.
- **chatons** (`~/Project/gitlab/chatons`) — a working wasmtime component-model host + a plugin WIT
  world that is almost exactly the contract we need:
  ```
  world chaton { import host; export init: func(); export on-key: func(k: key) -> bool; }
  interface host { render: func(text: string); show-image; read/write-file; source-text; … }
  ```
  A plugin paints by calling `host.render(ansi)` and quits when `on-key` returns false. Seven example
  plugins already build (notepad, qr, fend, launcher, …).
- **kedi** — panes over WebTransport; a pane's bytes today come from a `pty` capability's
  `output()` stream and go to xterm.js. A plugin pane just swaps the *source* of those bytes.

The pivot is not a new system — it's **wiring chatons' host into warden as a Runtime, and letting a
kedi pane pick it.**

## Where it runs (decided)

**Host-side.** kedi's Rust server runs the WASM (wasmtime, reusing chatons' host). The plugin is a
warden `Runtime`; the pane's frames stream to the browser exactly like pty output. The plugin never
enters the browser. Consequences, all good:

- **Governed for free** — a plugin app is a warden session: recorded, replayable, killable,
  policy-gated at `Ctx::invoke`. A malicious/buggy plugin can only touch the world through granted
  capabilities (the WASI door is empty; the `host` interface is the only door — the warden stance).
- **Polyglot** — a plugin is a `.wasm` component; write it in Rust/ratatui, Go/TinyGo, Zig, …
- **Reuses the async kernel** — `Runtime::run` is already `async`; the render/key loop is an async
  task, no new concurrency machinery.

## The shape

```
  browser pane (xterm.js)                         kedi server (warden)
  ─────────────────────────                       ─────────────────────────────────────────
  keystrokes ──WebTransport──►  InputFrame ─────►  ctx.invoke(app, "key", bytes)
                                                        │  WasmTuiRuntime (wasmtime)
                                                        │    guest.on-key(k) -> bool
                                                        │    guest calls host.render(ansi)
  xterm.write(ansi) ◄──frames── Event::Output ◄────────┘    (a frame = one screen, ANSI)
                                                     recorded · maskable · killable (unchanged)
```

### The clean fit: an app is a *capability*, like `pty`

Investigating the kernel settled the integration point precisely: **output only flows through a
`Capability::output()` stream that the kernel pumps** (that's how pty bytes reach the browser). So a
WASM-TUI app is modelled as a **capability of kind `app`, structurally identical to `pty`**:

- `output()` → the stream of rendered frames (what the guest paints via `host.render`);
- `perform("key", bytes)` / `perform("resize", "COLSxROWS")` → drive the guest (`on-key`/`on-resize`);
- `finished()` → true when the guest's `on-key`/`on-tick` returned false (the app quit);
- inside, a worker runs **wasmtime** driving the component; the sync wasmtime callbacks bridge to the
  async output stream through a channel (the same thread→async bridge the pty already uses).

The payoff: **step 1 needs no kernel change, no new runtime, and no kedi change beyond letting a
pane request kind `app` instead of `pty`.** The attach-loop action, the output pump, record, kill,
and policy are all **reused verbatim** — a plugin pane is a pty-shaped session whose "shell" is a
WASM app. (The `Runtime` seam still hosts *headless* WASM actions via `warden:action`; interactive
apps ride the capability axis instead, because that's where streaming output lives.)

Everything downstream — the observer that forwards `Event::Output` to WebTransport, the kill switch,
the record — is **unchanged**, because a plugin frame is just another `Output` chunk.

## The layers ("different layers for different things")

This is where warden's seam model pays off. A "kedi plugin" is not one thing — it can contribute at
different **layers**, exactly the warden registry idea:

| layer | what a plugin contributes | seam it uses |
|---|---|---|
| **app** | a full-pane TUI (deck, a file browser, a dashboard) | `Runtime` — the WASM-TUI runtime; a pane runs it |
| **capability** | a new kind of world-access the app can request (`sql`, `http`, `notify`) | `Broker` + `Capability` — the plugin's app can only reach it if granted |
| **interceptor** | transform/observe what crosses a pane (DLP, a keylog-to-audit, a rewriter) | `Interceptor` |
| **recorder** | ship a plugin's events somewhere (a metrics sink) | `Recorder` |
| **panel (later)** | an HTML/DOM surface instead of a terminal grid | a browser-side kind, out of scope v1 |

So "layers for different things" = a plugin's manifest can declare *which seams it plugs*, and
warden's two-phase loader composes them. A plugin that's just deck plugs one `Runtime`. A plugin
that adds `notify` + a dashboard plugs a `Broker` **and** a `Runtime`. **The plugin system IS
warden's plugin system** — kedi doesn't invent a second one; it exposes warden's to the browser.

## The plugin contract (evolve chatons' WIT)

Start from `chatons:plugin` and adapt it to warden's world. A first cut, `kedi:app`:

```wit
package kedi:app@0.1.0;

interface host {
  render: func(frame: string);          // one full screen as ANSI (a ratatui buffer flush)
  // capabilities are requested through warden — the app can't touch the world directly:
  invoke: func(cap: string, op: string, input: list<u8>) -> result<list<u8>, string>;
}

world app {
  import host;
  export init: func(cols: u32, rows: u32);
  export on-key: func(k: key) -> bool;   // false → the pane closes
  export on-resize: func(cols: u32, rows: u32);
}
```

- `render(frame)` maps onto ratatui's `Terminal::draw` → serialize the buffer to ANSI → one
  `host.render`. (ratatui already renders to a cell buffer; we add a "buffer → ANSI string" backend,
  which is a small, well-trodden piece.)
- `invoke(cap, op, input)` is the **same chokepoint** the component runtime already exposes — a
  plugin's file read / http / notify goes through `ctx.invoke`, recorded and policy-gated. This is
  the crucial reuse: the plugin's *governed* actions ride warden's existing `HostCapability::invoke`.
- `on-key` / `on-resize` mirror what the pty attach loop already forwards.

## deck as plugin #1

deck is the ideal first plugin — it's a self-contained TUI over a task store:

1. **Rewrite deck Go→Rust/ratatui** as a `kedi:app` WASM component. The pure logic (column
   bucketing, the H/L drag→dstask mapping, parsing) ports directly; the Bubble Tea `Update` becomes
   ratatui + `on-key`.
2. **deck's world-access = warden capabilities.** deck reads/writes the dstask git store — that
   becomes a `dstask` **capability** (a `Broker` the deck plugin declares), so deck-in-WASM can't
   touch the filesystem except through that governed op. The hooks (agent/enrich/ingest/open) become
   capabilities too — each a governed `invoke`, not an ambient subprocess.
3. **kedi launches it** — a launcher pane (like chatons' launcher) lists installed plugins; pick
   `deck` → a pane runs `runtime: "wasm-tui:deck"`.

Net: deck stops being a standalone terminal binary and becomes a **governed app inside kedi** — and
the same slot hosts any future WASM-TUI.

## Migration path (cut deliberately, keep each step green)

1. **Land the WASM-TUI runtime in warden** — a new `WasmTuiRuntime` (adapt `warden-wasm`'s
   `ComponentRuntime`): loads a `kedi:app` component, runs `init`→loop(`on-key`)→`render`, streams
   frames as `Event::Output`, forwards keys via the input stream. Prove it with a tiny "hello"
   ratatui component (the chatons `hello` port).
2. **Teach kedi to open a plugin pane** — a pane whose `runtime` is the WASM-TUI one, selected by a
   launcher. The pty path is untouched; plugin panes are additive.
3. **Port deck** to a `kedi:app` component + a `dstask` capability. Ship it as the flagship plugin.
4. **(Later) HTML panels** — a second plugin kind for DOM surfaces; different renderer, same
   manifest/seam model.

## Open questions (decide as we build)

- **Where do plugins live?** A `~/.config/kedi/plugins/*.wasm` dir + a manifest (name, icon, seams
  it plugs, capabilities it requests) — mirrors chatons' manifest. The requested-capabilities list
  is the *governance surface*: kedi shows "deck wants: dstask, notify — allow?" (warden's escalate).
- **Which repo owns the WASM-TUI host?** Fold chatons' host into `warden-wasm` (one host, two WIT
  worlds: `warden:action` for headless guests, `kedi:app` for TUI guests)? Or keep chatons separate
  and depend on it? Leaning: fold it in — one governed host.
- **ratatui → ANSI backend** — write a `Backend` impl that flushes to a string (there are community
  ones; may just adopt/adapt). This is the only genuinely new rendering code.
- **Frame cadence** — push a frame on change (guest calls `render`) vs. a fixed tick. chatons pushes
  on init/on-key; deck's focus timer needs a tick → the host offers an optional `on-tick`.

## Why this is the right pivot

It doesn't add a system — it **unifies the three you already built**: warden's governed plugin
model, chatons' WASM-component host, kedi's terminal UI. A plugin is a warden session; the plugin
API is warden's seams; the sandbox is warden's capabilities. deck becomes the proof, and the same
slot turns kedi into a **governed, polyglot app platform in a terminal** — which is squarely the
access-platform direction.
