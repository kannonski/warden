//! warden-web — the browser console: xterm.js over the governed session model.
//!
//! Three endpoints, hand-rolled HTTP (threads, std):
//! - `GET /`                     → the console page (xterm.js renders; the warden governs)
//! - `GET /run?identity&action&caps` → Server-Sent Events: this session's record stream, live
//! - `GET /kill?session&by`      → kill a live session (the Killed event lands in its stream)
//!
//! The browser gets exactly what the TCP client gets: the post-mask event stream. There is no
//! richer, unmediated channel — the terminal IS a record viewer that happens to be live.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use warden_core::{
    Action, CapKind, CapRequest, Catalog, Event, Recorder, Session, SessionId, Warden,
};
use warden_record::RecEvent;

const INDEX_HTML: &str = include_str!("index.html");

/// Streams a session's events to the browser as SSE `data:` lines.
struct SseObserver {
    stream: Mutex<TcpStream>,
}
impl Recorder for SseObserver {
    fn record(&self, ev: Event) {
        let json = serde_json::to_string(&RecEvent::from(&ev)).expect("wire serialization");
        let mut s = self.stream.lock().unwrap();
        let _ = write!(s, "data: {json}\n\n");
        let _ = s.flush();
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn query_params(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (percent_decode(k), percent_decode(v)))
        .collect()
}

fn param<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn respond(stream: &mut TcpStream, status: &str, content_type: &str, body: &str) {
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

fn handle(warden: &Warden, catalog: &Catalog, next_session: &AtomicU64, mut stream: TcpStream) {
    // request line + drain the headers; GET only
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    loop {
        let mut h = String::new();
        match reader.read_line(&mut h) {
            Ok(_) if h.trim().is_empty() => break,
            Ok(0) | Err(_) => return,
            _ => {}
        }
    }
    let mut parts = request_line.split_whitespace();
    let (Some("GET"), Some(target)) = (parts.next(), parts.next()) else {
        respond(
            &mut stream,
            "405 Method Not Allowed",
            "text/plain",
            "GET only",
        );
        return;
    };
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let params = query_params(query);

    match path {
        "/" => respond(
            &mut stream,
            "200 OK",
            "text/html; charset=utf-8",
            INDEX_HTML,
        ),

        "/kill" => {
            let session = param(&params, "session").and_then(|s| s.parse::<u64>().ok());
            let by = param(&params, "by").unwrap_or("operator@web").to_string();
            let killed = session
                .map(|id| warden.kill(SessionId(id), &by))
                .unwrap_or(false);
            respond(
                &mut stream,
                "200 OK",
                "application/json",
                &format!("{{\"killed\":{killed}}}"),
            );
        }

        "/run" => {
            let identity = param(&params, "identity")
                .unwrap_or("anonymous@web")
                .to_string();
            let action_name = param(&params, "action").unwrap_or("").to_string();
            // caps=kind=arg,kind=arg
            let requests: Vec<CapRequest> = param(&params, "caps")
                .unwrap_or("")
                .split(',')
                .filter_map(|kv| kv.split_once('='))
                // spike: leaked per request, as in warden-transport; product interns kinds
                .map(|(k, v)| CapRequest {
                    kind: CapKind(Box::leak(k.trim().to_string().into_boxed_str())),
                    arg: v.trim().to_string(),
                })
                .collect();

            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
            );
            let done = |stream: &mut TcpStream, ok: bool, error: Option<String>| {
                let err_json = error
                    .map(|e| serde_json::to_string(&e).unwrap())
                    .unwrap_or_else(|| "null".into());
                let _ = write!(
                    stream,
                    "data: {{\"done\":true,\"ok\":{ok},\"error\":{err_json}}}\n\n"
                );
            };

            let (source, runtime) = match (catalog)(&action_name) {
                Ok(sr) => sr,
                Err(e) => {
                    done(&mut stream, false, Some(e.to_string()));
                    return;
                }
            };
            let session = Session {
                id: SessionId(next_session.fetch_add(1, Ordering::Relaxed)),
                identity,
                requests,
                action: Action {
                    name: action_name,
                    source,
                },
            };
            let observer = Arc::new(SseObserver {
                stream: Mutex::new(match stream.try_clone() {
                    Ok(s) => s,
                    Err(_) => return,
                }),
            });
            let result = warden.run_session_observed(session, &runtime, Some(observer));
            done(
                &mut stream,
                result.is_ok(),
                result.err().map(|e| e.to_string()),
            );
        }

        _ => respond(&mut stream, "404 Not Found", "text/plain", "not found"),
    }
}

/// Serve the console forever: thread per connection, sessions numbered from 2000.
pub fn serve(warden: Arc<Warden>, catalog: Catalog, addr: &str) -> ! {
    let listener = TcpListener::bind(addr).expect("bind web console");
    println!(
        "warden web console: http://{}",
        listener.local_addr().expect("bound")
    );
    let next_session = Arc::new(AtomicU64::new(2000));
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let (warden, catalog, next) =
                    (warden.clone(), catalog.clone(), next_session.clone());
                std::thread::spawn(move || handle(&warden, &catalog, &next, stream));
            }
            Err(e) => eprintln!("[web] accept: {e}"),
        }
    }
}
