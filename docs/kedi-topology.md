# kedi topology — native client, local-embedded warden, remote gateway (proposal)

Reframes kedi from *a browser-served WebTransport page* into *a native (Tauri) client*, and pins down
which transport rides each hop. The guiding principle: **QUIC only where the network is actually
crossed.** Today kedi runs a browser-facing WebTransport server purely so a *tab* can reach a local
QUIC endpoint — an accidental hop, not part of warden's remote axis. A native client removes it.

Status: **proposal / design capture — no code yet.** Transport + secret crates stay untouched.

## Why move off the browser
- The browser tab has no native Dock identity: the Chrome `--app` window has no proper Dock icon and
  vanishes on minimize; a proper icon requires a PWA install dance (shipped, but a workaround).
- kedi's browser transport depends on WebTransport **`serverCertificateHashes`** (ephemeral self-signed
  cert pinned by SHA-256 — `lib.rs:313` `Identity::self_signed`). Safari 26.4 (Mar 2026) ships
  WebTransport but **WebKit has declined `serverCertificateHashes`**, so the zero-config cert flow is
  Chromium-only forever. A native client sidesteps the whole browser cert regime.

## Decisions (locked)
1. **kedi is a native (Tauri) app.** The webview ↔ kedi-core hop is **Tauri IPC** — always, in every
   mode. No WebTransport, no cert on this hop. xterm.js stays; only the byte pipe under it changes.
2. **Local = kedi owns the warden, no gateway.** kedi links `warden-host` + caps and drives
   `Ctx::invoke` directly (pty, ai, secret/sign, wasm plugins, record). The gateway is overkill on one
   box.
3. **"No gateway" ≠ "no governance."** Even local + in-process, every op still routes through
   `Ctx::invoke` (audit · DLP · record · policy). The record is written locally, anchorable to a
   gateway later.
4. **Remote is additive.** The gateway is a standalone crate (`warden_gateway::serve(addr)`), switched
   on only when a host is somewhere kedi can't reach directly. Local ships complete without it.
5. **Never embed the gateway in kedi.** It's a role inversion (see below).
6. **Keep `warden-transport` and `warden-secret` in the workspace** — the gateway-era foundation. The
   local build simply doesn't wire them; the crates stay first-class, built, and tested.

## Transport & cert, per hop

| Hop | Transport | Cert |
|---|---|---|
| kedi webview ↔ kedi core | **Tauri IPC** (always) | none |
| kedi core ↔ warden — **single box** | in-process `Ctx::invoke` (or sidecar, see below) | none |
| kedi core ↔ warden — **same LAN** | `warden_transport::connect(addr)` — native quinn | pin / mTLS (both ends owned) |
| kedi core ↔ warden — **cloud** | `warden_transport::connect_via(gateway, name)` — native quinn | — |
| warden host → cloud gateway | `QuicTunnel::connect` + `GatewayHello` (dials **out**, no inbound ports) | — |
| the gateway itself | `warden_gateway::serve(addr)` | **real Let's Encrypt** cert (HTTP-01/DNS-01 — it's a real public server) |

Because the client is now native, **every network hop is native quinn** — `serverCertificateHashes`
never reappears, and **LE only matters at one place: the public gateway** (the easy case). Local/LAN
use pinned/mTLS certs we fully control; local single-box uses no transport at all.

## Local: in-process vs sidecar (OPEN — hinges on survive-close)
"Embedded" hides one real decision — *should a local session survive closing the kedi window?*
- **In-process** (warden inside the Tauri process): simplest; quit = clean shutdown, but quitting kedi
  **kills sessions** — no survive-close, no reattach.
- **Local sidecar daemon** (Tauri attaches to a small local warden over a **unix socket** — no QUIC, no
  cert): sessions **outlive the window**, reattach works, and it exercises the *same* attach/move seam
  the remote path uses (only unix-socket vs quinn differs).

We currently *have* survive-close — PR #1 was `kedi-stop-server-on-last-tab` (the server outlives
viewers, stops on the last). Going fully in-process would regress that, so the **sidecar** shape is the
likely match. Left open pending a call.

## Remote: the gateway role
`warden-gateway` is "the remote axis over QUIC: reachability + fleet routing, nothing more." The host
**dials out** and registers a name (`GatewayHello`), so it needs no inbound ports; a client asks for a
warden by name and the gateway **splices** the streams, QUIC-multiplexed over the host's one
connection. kedi is just such a client via `connect_via`. Session teleport (attach/move in
`warden-core`) becomes cross-device through the gateway.

### Why not embed the gateway in kedi
The gateway must be a **neutral node both ends dial *out* to** — so it belongs on the stable, reachable
machine. kedi is the *client*: laptop, often NAT'd, not always on — the worst host for a rendezvous.
Embedding it there would (a) force *kedi* to be inbound-reachable for hosts to register, moving the
reachability problem onto the worst node; (b) collapse the trust boundary — the gateway is an authz
choke point (who may register / who may connect), and a client that *is* the gateway authorizes itself;
(c) balloon the attack surface of a routing node that is deliberately tiny (`serve(addr) -> !`) by
fusing it into the fat desktop app. If one artifact is desired, prefer a single workspace binary with
`kedi` / `host` / `gateway` subcommands (role chosen at launch) — not fusing the gateway *into* kedi.

## What this removes from kedi
- The `wtransport` dependency and the browser-facing WebTransport server.
- The in-page WebTransport client + cert-hash injection in `index.html`.
- The ephemeral self-signed identity flow *on the client hop* (`wt_identity` stays relevant only to the
  quinn axis, if reused there).

## What we keep, and why
- **`warden-transport`** — the entire remote axis: `QuicTunnel::connect`/`GatewayHello` (host dial-out),
  `connect` / `connect_via` (client direct vs via-gateway), `server_config`/`client_config`. Not wired
  locally; unchanged in the workspace.
- **`warden-secret`** — signing identities for the `GatewayHello` handshake (register/connect authz) and
  anchoring the record hash-chain head shipped to the gateway. Gateway authz is unbuildable without it.

## Open decisions
1. Local warden: **in-process vs sidecar daemon** (survive-close — see above).
2. Gateway **authz**: mTLS client certs vs signed tokens (`warden-secret`) for register/connect.
3. **Naming / discovery**: `connect_via` assumes kedi knows the name → a directory API on the gateway.
4. **Record anchoring** in the cloud world: gateway as tamper-evidence collector.
5. **kedi deploy shapes**: single-box Tauri (embeds warden) vs thin client (connects only) — one binary
   by config, or two.
