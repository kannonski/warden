//! warden-gateway — the remote axis over QUIC: reachability + fleet routing, nothing more.
//!
//! Wardens dial OUT and register a name (so a warden needs no inbound ports — only outbound to the
//! gateway). A client asks for a warden by name; the gateway opens a fresh bidi stream on that
//! warden's existing connection and **splices** the client stream to it. QUIC multiplexes those
//! per-session streams over the one warden connection natively — no dial-back rendezvous. From
//! there the warden runs and enforces the session end-to-end; the gateway only moves bytes.
//!
//! It is deliberately a dumb pipe: it does not parse the session. Because the stream it relays IS
//! the post-mask record format, a real gateway *could* tee it into fleet-wide audit without ever
//! seeing a raw secret — but that's a later tier; here it stays a router.

use quinn::{Connection, Endpoint, RecvStream, SendStream};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use warden_transport::{GatewayHello, WireReply, server_config};

type Registry = Arc<Mutex<HashMap<String, Connection>>>;

/// Read one `\n`-delimited line off a recv stream, returning it plus any bytes buffered past it.
async fn read_line(recv: &mut RecvStream) -> Option<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        if let Some(i) = buf.iter().position(|&b| b == b'\n') {
            let line = String::from_utf8_lossy(&buf[..i]).into_owned();
            return Some((line, buf[i + 1..].to_vec()));
        }
        match recv.read(&mut tmp).await {
            Ok(Some(n)) if n > 0 => buf.extend_from_slice(&tmp[..n]),
            _ => return None,
        }
    }
}

async fn refuse(mut send: SendStream, why: String) {
    let line = serde_json::to_string(&WireReply::Done {
        ok: false,
        error: Some(why),
    })
    .unwrap();
    let _ = send.write_all(line.as_bytes()).await;
    let _ = send.write_all(b"\n").await;
    let _ = send.finish();
}

/// Copy every byte from `recv` to `send` until EOF, then finish `send`. `prefix` is written first
/// (the client's request bytes the gateway already read while parsing the routing line).
async fn pipe(mut recv: RecvStream, mut send: SendStream, prefix: Vec<u8>) {
    if !prefix.is_empty() && send.write_all(&prefix).await.is_err() {
        return;
    }
    let mut buf = [0u8; 8192];
    loop {
        match recv.read(&mut buf).await {
            Ok(Some(n)) if n > 0 => {
                if send.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
            _ => break,
        }
    }
    let _ = send.finish();
}

async fn handle_conn(conn: Connection, reg: Registry) {
    // the first bidi stream carries the hello (warden registration or client routing)
    let Ok((send, mut recv)) = conn.accept_bi().await else {
        return;
    };
    let Some((hello, leftover)) = read_line(&mut recv).await else {
        return;
    };

    match serde_json::from_str::<GatewayHello>(hello.trim()) {
        Ok(GatewayHello::Warden { name }) => {
            reg.lock().unwrap().insert(name.clone(), conn.clone());
            let mut send = send;
            let _ = send
                .write_all(format!("{{\"registered\":\"{name}\"}}\n").as_bytes())
                .await;
            let _ = send.finish();
            println!("[gateway] warden '{name}' registered");
            conn.closed().await; // keep the entry alive until the warden connection drops
            reg.lock().unwrap().remove(&name);
            println!("[gateway] warden '{name}' disconnected");
        }

        Ok(GatewayHello::Client { warden }) => {
            let wconn = reg.lock().unwrap().get(&warden).cloned();
            let Some(wconn) = wconn else {
                refuse(send, format!("no warden '{warden}' connected")).await;
                // keep the connection up until the client has read the refusal, so the Done line
                // isn't lost to an abrupt connection close
                conn.closed().await;
                return;
            };
            let (wsend, wrecv) = match wconn.open_bi().await {
                Ok(pair) => pair,
                Err(e) => {
                    refuse(send, format!("warden '{warden}' unavailable: {e}")).await;
                    conn.closed().await;
                    return;
                }
            };
            println!("[gateway] routing client → warden '{warden}'");
            // splice: client → warden (with the already-read request bytes) and warden → client
            tokio::join!(pipe(recv, wsend, leftover), pipe(wrecv, send, Vec::new()));
            // let the client close first (after it has read the final Done) — closing the gateway
            // connection abruptly here would truncate the last bytes
            conn.closed().await;
        }

        Err(_) => {} // unparseable hello — drop
    }
}

/// Serve forever.
pub fn serve(addr: &str) -> ! {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let endpoint = Endpoint::server(server_config(), addr.parse().expect("gateway addr"))
            .expect("bind gateway");
        println!(
            "warden gateway on {}",
            endpoint.local_addr().expect("bound")
        );
        let reg: Registry = Arc::new(Mutex::new(HashMap::new()));
        while let Some(incoming) = endpoint.accept().await {
            let reg = reg.clone();
            tokio::spawn(async move {
                if let Ok(conn) = incoming.await {
                    handle_conn(conn, reg).await;
                }
            });
        }
    });
    std::process::exit(0)
}
