//! warden-transport — sessions over QUIC.
//!
//! The `Transport` seam on QUIC (quinn): TLS 1.3 on the wire, and **one session = one bidirectional
//! stream**, so many concurrent sessions multiplex over a single connection natively (no dial-back
//! rendezvous, unlike a TCP tunnel). The byte protocol is unchanged JSON lines: the client writes
//! one request line; the warden streams back this session's events as [`RecEvent`] lines, then a
//! `done` line. **The reply stream IS the record format** — a client's live view is exactly the
//! audit trail, post-mask, nothing more.
//!
//! QUIC forces async (quinn is tokio-based) and TLS. Both are confined to this crate: the kernel
//! and its `Transport`/`Recorder` seams stay sync, and a per-transport tokio runtime bridges the
//! sync `Recorder` observer to the async send stream over an unbounded channel. The spike uses a
//! self-signed cert + a skip-verify client (localhost only, called out below); the product path is
//! real certs / mTLS with pinning — same code shape, a real verifier.

use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::runtime::Runtime;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use warden_core::{
    Accepted, Action, CapKind, CapRequest, Catalog, Event, Incoming, Recorder, Session, SessionId,
    Transport, WardenError,
};
use warden_record::RecEvent;

use quinn::{Connection, Endpoint, RecvStream, SendStream};

const ALPN: &[u8] = b"warden/0";

// ── wire format ─────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "req", rename_all = "snake_case")]
pub enum WireRequest {
    /// Run a named action with these capabilities.
    Session {
        identity: String,
        requests: Vec<WireCapRequest>,
        /// Action by name — resolved by the server-side catalog, never uploaded.
        action: String,
    },
    /// Kill a live session mid-flight.
    Kill { session: u64, by: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WireCapRequest {
    pub kind: String,
    pub arg: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "msg", rename_all = "snake_case")]
pub enum WireReply {
    Event { event: RecEvent },
    Done { ok: bool, error: Option<String> },
}

/// First line on a gateway connection's control stream — declares the peer's role.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "hello", rename_all = "snake_case")]
pub enum GatewayHello {
    /// A warden registering a name (this connection then serves sessions the gateway opens on it).
    Warden { name: String },
    /// A client routing to a warden by name; the wire request follows on the same stream.
    Client { warden: String },
}

// ── TLS (spike): self-signed server cert + skip-verify client ────────────────────────────────────

mod tls {
    use super::ALPN;
    use std::sync::{Arc, Once};

    static PROVIDER: Once = Once::new();
    fn ensure_provider() {
        PROVIDER.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// A self-signed server config for `localhost`. Product path: real certs, loaded not generated.
    pub fn server_config() -> quinn::ServerConfig {
        ensure_provider();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("self-signed cert");
        let cert_der = cert.cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());

        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server tls");
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let qsc =
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("quic server config");
        quinn::ServerConfig::with_crypto(Arc::new(qsc))
    }

    /// A client config that skips server verification. SPIKE ONLY — localhost, no identity checks.
    /// The product replaces `SkipVerify` with a real verifier (pinned cert / mTLS); nothing else moves.
    pub fn client_config() -> quinn::ClientConfig {
        ensure_provider();
        let mut tls = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipVerify::new()))
            .with_no_client_auth();
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let qcc =
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("quic client config");
        quinn::ClientConfig::new(Arc::new(qcc))
    }

    #[derive(Debug)]
    struct SkipVerify(Arc<rustls::crypto::CryptoProvider>);
    impl SkipVerify {
        fn new() -> Self {
            Self(Arc::new(rustls::crypto::ring::default_provider()))
        }
    }
    impl rustls::client::danger::ServerCertVerifier for SkipVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
}

// ── endpoints ─────────────────────────────────────────────────────────────────────────────────

/// The spike's self-signed QUIC server config — reused by the gateway (also a QUIC server).
pub fn server_config() -> quinn::ServerConfig {
    tls::server_config()
}

fn io(e: impl std::fmt::Display) -> WardenError {
    WardenError::Cap(format!("transport: {e}"))
}

fn resolve(addr: impl ToSocketAddrs) -> std::io::Result<SocketAddr> {
    addr.to_socket_addrs()?.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "unresolvable addr")
    })
}

/// A client endpoint bound to an ephemeral local UDP port.
fn client_endpoint() -> std::io::Result<Endpoint> {
    let mut ep = Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    ep.set_default_client_config(tls::client_config());
    Ok(ep)
}

// ── stream framing helpers ───────────────────────────────────────────────────────────────────────

/// Reads `\n`-delimited lines off a QUIC recv stream, keeping any bytes past the newline (so the
/// remainder can be handed to a relay untouched).
struct LineReader {
    recv: RecvStream,
    buf: Vec<u8>,
}
impl LineReader {
    fn new(recv: RecvStream) -> Self {
        Self {
            recv,
            buf: Vec::new(),
        }
    }
    async fn line(&mut self) -> std::io::Result<Option<String>> {
        loop {
            if let Some(i) = self.buf.iter().position(|&b| b == b'\n') {
                let line = String::from_utf8_lossy(&self.buf[..i]).into_owned();
                self.buf.drain(..=i);
                return Ok(Some(line));
            }
            let mut tmp = [0u8; 8192];
            match self
                .recv
                .read(&mut tmp)
                .await
                .map_err(std::io::Error::other)?
            {
                Some(n) if n > 0 => self.buf.extend_from_slice(&tmp[..n]),
                _ => {
                    if self.buf.is_empty() {
                        return Ok(None);
                    }
                    let line = String::from_utf8_lossy(&self.buf).into_owned();
                    self.buf.clear();
                    return Ok(Some(line));
                }
            }
        }
    }
}

/// A frame queued for the writer task: a line, or the final line (then the stream is finished).
enum Frame {
    Line(String),
    Final(String),
}

/// Drains queued frames onto the send stream — the async half that the sync observer feeds.
async fn pump(mut send: SendStream, mut rx: UnboundedReceiver<Frame>) {
    while let Some(frame) = rx.recv().await {
        let (text, fin) = match frame {
            Frame::Line(s) => (s, false),
            Frame::Final(s) => (s, true),
        };
        if send.write_all(text.as_bytes()).await.is_err() || send.write_all(b"\n").await.is_err() {
            break;
        }
        if fin {
            let _ = send.finish();
            break;
        }
    }
}

/// The sync `Recorder` that a session's events flow through → queued to the writer task.
struct QuicObserver {
    tx: UnboundedSender<Frame>,
}
impl Recorder for QuicObserver {
    fn record(&self, ev: Event) {
        let line = serde_json::to_string(&WireReply::Event {
            event: RecEvent::from(&ev),
        })
        .expect("wire serialization");
        let _ = self.tx.send(Frame::Line(line));
    }
}

fn done_line(ok: bool, error: Option<String>) -> String {
    serde_json::to_string(&WireReply::Done { ok, error }).expect("wire serialization")
}

/// Read one wire request off a fresh bidi stream and build the [`Accepted`] the kernel runs. A
/// writer task is spawned to carry this session's events back over `send`; the sync observer/`done`
/// (and a Kill ack) feed it. Shared by the direct server and the reverse tunnel — identical either
/// way. Returns `None` if the request was malformed/unknown (already answered on the wire).
async fn accept_stream(
    send: SendStream,
    recv: RecvStream,
    peer: String,
    catalog: &Catalog,
    next_session: &AtomicU64,
) -> Option<Accepted> {
    let (tx, rx) = unbounded_channel::<Frame>();
    tokio::spawn(pump(send, rx));

    let mut lr = LineReader::new(recv);
    let line = match lr.line().await {
        Ok(Some(l)) => l,
        _ => {
            let _ = tx.send(Frame::Final(done_line(
                false,
                Some(format!("{peer}: no request")),
            )));
            return None;
        }
    };

    let req = match serde_json::from_str::<WireRequest>(&line) {
        Ok(r) => r,
        Err(e) => {
            let _ = tx.send(Frame::Final(done_line(
                false,
                Some(format!("{peer}: bad request: {e}")),
            )));
            return None;
        }
    };

    let (identity, requests, action) = match req {
        WireRequest::Kill { session, by } => {
            let tx = tx.clone();
            return Some(Accepted::Kill {
                session: SessionId(session),
                by,
                ack: Box::new(move |found| {
                    let err = (!found).then(|| "no such live session".to_string());
                    let _ = tx.send(Frame::Final(done_line(found, err)));
                }),
            });
        }
        WireRequest::Session {
            identity,
            requests,
            action,
        } => (identity, requests, action),
    };

    let (source, runtime) = match (catalog)(&action) {
        Ok(sr) => sr,
        Err(e) => {
            let _ = tx.send(Frame::Final(done_line(
                false,
                Some(format!("action `{action}`: {e}")),
            )));
            return None;
        }
    };

    let requests = requests
        .into_iter()
        // CapKind wraps &'static str; wire kinds are runtime strings. Leaked per request in the
        // spike (bounded by traffic); the product interns kinds in a registry.
        .map(|r| CapRequest {
            kind: CapKind(Box::leak(r.kind.into_boxed_str())),
            arg: r.arg,
        })
        .collect();

    let session = Session {
        id: SessionId(next_session.fetch_add(1, Ordering::Relaxed)),
        identity,
        requests,
        action: Action {
            name: action,
            source,
        },
    };

    let observer = Arc::new(QuicObserver { tx: tx.clone() });
    let done = Box::new(move |result: &warden_core::Result<()>| {
        let _ = tx.send(Frame::Final(done_line(
            result.is_ok(),
            result.as_ref().err().map(|e| e.to_string()),
        )));
    });

    // QUIC transport is one-shot request/stream today; interactive input (kedi) uses WebSocket
    Some(Accepted::Session(Incoming {
        session,
        runtime,
        observer: Some(observer),
        input: None,
        done,
    }))
}

// ── direct server: a warden that listens for QUIC connections ─────────────────────────────────

/// A warden accepting sessions directly over QUIC. Each bidi stream (across any connection) is one
/// session; a background task feeds ready [`Accepted`]s to the sync `accept()`.
pub struct QuicTransport {
    // owned so Drop can shut it down in the background — joining a multi-thread runtime that still
    // holds a quinn endpoint driver deadlocks, so we detach the workers instead
    rt: Option<Runtime>,
    addr: SocketAddr,
    rx: tokio::sync::Mutex<UnboundedReceiver<Accepted>>,
}

impl QuicTransport {
    pub fn bind(
        addr: impl ToSocketAddrs,
        catalog: Catalog,
        first_session_id: u64,
    ) -> std::io::Result<Self> {
        let addr = resolve(addr)?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let catalog = Arc::new(catalog);
        let next = Arc::new(AtomicU64::new(first_session_id));

        let (endpoint, bound) = rt.block_on(async move {
            let ep = Endpoint::server(tls::server_config(), addr)?;
            let bound = ep.local_addr()?;
            std::io::Result::Ok((ep, bound))
        })?;

        let (tx, rx) = unbounded_channel::<Accepted>();
        rt.spawn(accept_connections(endpoint, tx, catalog, next));

        Ok(Self {
            rt: Some(rt),
            addr: bound,
            rx: tokio::sync::Mutex::new(rx),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for QuicTransport {
    fn drop(&mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

async fn accept_connections(
    endpoint: Endpoint,
    tx: UnboundedSender<Accepted>,
    catalog: Arc<Catalog>,
    next: Arc<AtomicU64>,
) {
    while let Some(incoming) = endpoint.accept().await {
        let (tx, catalog, next) = (tx.clone(), catalog.clone(), next.clone());
        tokio::spawn(async move {
            let Ok(conn) = incoming.await else { return };
            let peer = conn.remote_address().to_string();
            while let Ok((send, recv)) = conn.accept_bi().await {
                let (tx, catalog, next, peer) =
                    (tx.clone(), catalog.clone(), next.clone(), peer.clone());
                tokio::spawn(async move {
                    if let Some(acc) = accept_stream(send, recv, peer, &catalog, &next).await {
                        let _ = tx.send(acc);
                    }
                });
            }
        });
    }
}

#[async_trait::async_trait]
impl Transport for QuicTransport {
    async fn accept(&self) -> warden_core::Result<Accepted> {
        self.rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io("endpoint closed"))
    }
}

// ── reverse tunnel: a warden that dials OUT to a gateway ─────────────────────────────────────────

/// A [`Transport`] that reaches clients through a gateway instead of listening. It dials the gateway
/// (one outbound QUIC connection, no inbound ports), registers a name over a control stream, then
/// serves the bidi streams the gateway opens on that connection — one per client session, natively
/// multiplexed. Identical protocol to [`QuicTransport`], reverse dialed.
pub struct QuicTunnel {
    rt: Option<Runtime>,
    conn: Connection,
    catalog: Arc<Catalog>,
    next: Arc<AtomicU64>,
    _endpoint: Endpoint,
}

impl QuicTunnel {
    /// Connect to the gateway and register `name`. Blocks until the gateway acknowledges, so a
    /// client routing to `name` immediately afterward is guaranteed to find it.
    pub fn connect(
        gateway: impl ToSocketAddrs,
        name: &str,
        catalog: Catalog,
        first_session_id: u64,
    ) -> std::io::Result<Self> {
        let gw = resolve(gateway)?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let name = name.to_string();

        let (endpoint, conn) = rt.block_on(async move {
            let ep = client_endpoint()?;
            let conn = ep
                .connect(gw, "localhost")
                .map_err(std::io::Error::other)?
                .await
                .map_err(std::io::Error::other)?;
            // register over a control stream and wait for the ack
            let (mut send, recv) = conn.open_bi().await.map_err(std::io::Error::other)?;
            let hello = serde_json::to_string(&GatewayHello::Warden { name }).unwrap();
            send.write_all(hello.as_bytes())
                .await
                .map_err(std::io::Error::other)?;
            send.write_all(b"\n").await.map_err(std::io::Error::other)?;
            let mut lr = LineReader::new(recv);
            lr.line().await?; // registration ack
            let _ = send.finish();
            std::io::Result::Ok((ep, conn))
        })?;

        Ok(Self {
            rt: Some(rt),
            conn,
            catalog: Arc::new(catalog),
            next: Arc::new(AtomicU64::new(first_session_id)),
            _endpoint: endpoint,
        })
    }
}

#[async_trait::async_trait]
impl Transport for QuicTunnel {
    async fn accept(&self) -> warden_core::Result<Accepted> {
        let conn = self.conn.clone();
        let (catalog, next) = (self.catalog.clone(), self.next.clone());
        // wait for the gateway to open a stream for the next session; loop past malformed ones.
        // The quinn driver runs on our own `rt`; awaiting from the caller's runtime is fine because
        // the connection is runtime-agnostic once that driver is alive.
        loop {
            let (send, recv) = conn.accept_bi().await.map_err(io)?;
            if let Some(acc) = accept_stream(send, recv, "gateway".into(), &catalog, &next).await {
                return Ok(acc);
            }
        }
    }
}

impl Drop for QuicTunnel {
    fn drop(&mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

// ── client ───────────────────────────────────────────────────────────────────────────────────

type Outcome = std::result::Result<(), String>;

async fn run_client_stream(
    mut send: SendStream,
    recv: RecvStream,
    request: &WireRequest,
    on_event: &mut dyn FnMut(&RecEvent),
) -> std::io::Result<(Vec<RecEvent>, Outcome)> {
    let line = serde_json::to_string(request).expect("wire serialization");
    send.write_all(line.as_bytes())
        .await
        .map_err(std::io::Error::other)?;
    send.write_all(b"\n").await.map_err(std::io::Error::other)?;
    let _ = send.finish();

    let mut events = Vec::new();
    let mut lr = LineReader::new(recv);
    while let Some(line) = lr.line().await? {
        match serde_json::from_str::<WireReply>(&line) {
            Ok(WireReply::Event { event }) => {
                on_event(&event);
                events.push(event);
            }
            Ok(WireReply::Done { ok, error }) => {
                let outcome = if ok {
                    Ok(())
                } else {
                    Err(error.unwrap_or_else(|| "unknown error".into()))
                };
                return Ok((events, outcome));
            }
            Err(e) => return Ok((events, Err(format!("bad reply line: {e}")))),
        }
    }
    Ok((events, Err("stream closed before done".into())))
}

/// Open a QUIC connection, run one session over a bidi stream. `route` (Some for a gateway) writes
/// a routing line first; the gateway splices the rest to the target warden.
fn client_session(
    addr: SocketAddr,
    route: Option<GatewayHello>,
    request: &WireRequest,
    mut on_event: impl FnMut(&RecEvent),
) -> std::io::Result<(Vec<RecEvent>, Outcome)> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let ep = client_endpoint()?;
        let conn = ep
            .connect(addr, "localhost")
            .map_err(std::io::Error::other)?
            .await
            .map_err(std::io::Error::other)?;
        let (mut send, recv) = conn.open_bi().await.map_err(std::io::Error::other)?;
        if let Some(hello) = route {
            let l = serde_json::to_string(&hello).unwrap();
            send.write_all(l.as_bytes())
                .await
                .map_err(std::io::Error::other)?;
            send.write_all(b"\n").await.map_err(std::io::Error::other)?;
        }
        let out = run_client_stream(send, recv, request, &mut on_event).await?;
        // we have the full reply (Done seen); close and return without waiting for full drain
        conn.close(0u32.into(), b"bye");
        Ok(out)
    })
}

/// Connect directly to a warden and run a session.
pub fn connect(
    addr: impl ToSocketAddrs,
    request: &WireRequest,
    on_event: impl FnMut(&RecEvent),
) -> std::io::Result<(Vec<RecEvent>, Outcome)> {
    client_session(resolve(addr)?, None, request, on_event)
}

/// Connect through a gateway to a named warden and run a session (the remote axis).
pub fn connect_via(
    gateway: impl ToSocketAddrs,
    warden: &str,
    request: &WireRequest,
    on_event: impl FnMut(&RecEvent),
) -> std::io::Result<(Vec<RecEvent>, Outcome)> {
    client_session(
        resolve(gateway)?,
        Some(GatewayHello::Client {
            warden: warden.to_string(),
        }),
        request,
        on_event,
    )
}

fn kill_session(
    addr: SocketAddr,
    route: Option<GatewayHello>,
    session: u64,
    by: &str,
) -> std::io::Result<bool> {
    let (_, outcome) = client_session(
        addr,
        route,
        &WireRequest::Kill {
            session,
            by: by.to_string(),
        },
        |_| {},
    )?;
    Ok(outcome.is_ok())
}

/// Kill a live session on a warden reached directly. Returns whether the session was found.
pub fn kill(addr: impl ToSocketAddrs, session: u64, by: &str) -> std::io::Result<bool> {
    kill_session(resolve(addr)?, None, session, by)
}

/// Kill a live session on a warden reached through a gateway.
pub fn kill_via(
    gateway: impl ToSocketAddrs,
    warden: &str,
    session: u64,
    by: &str,
) -> std::io::Result<bool> {
    kill_session(
        resolve(gateway)?,
        Some(GatewayHello::Client {
            warden: warden.to_string(),
        }),
        session,
        by,
    )
}

/// A free ephemeral UDP port (for tests/demos that need an addr before binding the server).
pub fn free_udp_addr() -> std::io::Result<SocketAddr> {
    UdpSocket::bind("127.0.0.1:0")?.local_addr()
}
