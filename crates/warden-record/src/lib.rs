//! warden-record — persist the event stream; verify it; rewind through it.
//!
//! [`FileRecorder`] appends one JSON line per event, **hash-chained**: line N carries the SHA-256
//! of line N−1's raw bytes, so editing any line breaks every later link. That makes the record
//! tamper-EVIDENT, not tamper-proof — truncating or rewriting the *tail* is only caught if the
//! chain head ([`FileRecorder::head`]) is anchored externally (signed, shipped to the gateway);
//! that's the product tier, noted honestly here.
//!
//! The wire type [`RecEvent`] deliberately mirrors `warden_core::Event` instead of reusing it: the
//! record is a versioned external format that must stay stable while kernel internals evolve.
//! Payloads are hex-encoded (binary-safe, hash-friendly; readability is `warden replay`'s job).
//!
//! **Rewind** here = [`state_at`]: reconstruct the observed state at any point in the record —
//! which sessions were open, which capabilities were held, what the operator last saw. It is NOT
//! undo: side effects only reverse for actions designed reversible (transactional, snapshot,
//! dry-run-then-commit).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use warden_core::{Event, Recorder};

/// prev-hash of the first line.
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// hex <-> bytes for payload fields.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        if !s.len().is_multiple_of(2) {
            return Err(serde::de::Error::custom("odd hex length"));
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(serde::de::Error::custom))
            .collect()
    }
}

// ── the wire format ─────────────────────────────────────────────────────────────────────────────

/// One recorded event — the stable external mirror of `warden_core::Event`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum RecEvent {
    SessionOpened {
        session: u64,
        identity: String,
    },
    CapGranted {
        session: u64,
        cap: u64,
        kind: String,
    },
    Call {
        session: u64,
        seq: u64,
        cap: u64,
        op: String,
        #[serde(with = "hex_bytes")]
        input: Vec<u8>,
    },
    Result {
        session: u64,
        seq: u64,
        #[serde(with = "hex_bytes")]
        output: Vec<u8>,
    },
    Output {
        session: u64,
        cap: u64,
        #[serde(with = "hex_bytes")]
        bytes: Vec<u8>,
    },
    Failed {
        session: u64,
        seq: u64,
        error: String,
    },
    Denied {
        session: u64,
        subject: String,
        why: String,
    },
    EscalationRequested {
        session: u64,
        subject: String,
        reason: String,
    },
    Approved {
        session: u64,
        subject: String,
        by: Vec<String>,
    },
    Rejected {
        session: u64,
        subject: String,
        by: String,
        why: String,
    },
    Killed {
        session: u64,
        by: String,
    },
    Revoked {
        session: u64,
        cap: u64,
    },
    SessionClosed {
        session: u64,
    },
}

impl From<&Event> for RecEvent {
    fn from(e: &Event) -> Self {
        match e {
            Event::SessionOpened { session, identity } => RecEvent::SessionOpened {
                session: session.0,
                identity: identity.clone(),
            },
            Event::CapGranted { session, cap, kind } => RecEvent::CapGranted {
                session: session.0,
                cap: cap.0,
                kind: kind.0.to_string(),
            },
            Event::Call {
                session,
                seq,
                cap,
                op,
                input,
            } => RecEvent::Call {
                session: session.0,
                seq: *seq,
                cap: cap.0,
                op: op.clone(),
                input: input.clone(),
            },
            Event::Result {
                session,
                seq,
                output,
            } => RecEvent::Result {
                session: session.0,
                seq: *seq,
                output: output.clone(),
            },
            Event::Output {
                session,
                cap,
                bytes,
            } => RecEvent::Output {
                session: session.0,
                cap: cap.0,
                bytes: bytes.clone(),
            },
            Event::Failed {
                session,
                seq,
                error,
            } => RecEvent::Failed {
                session: session.0,
                seq: *seq,
                error: error.clone(),
            },
            Event::Denied {
                session,
                subject,
                why,
            } => RecEvent::Denied {
                session: session.0,
                subject: subject.clone(),
                why: why.clone(),
            },
            Event::EscalationRequested {
                session,
                subject,
                reason,
            } => RecEvent::EscalationRequested {
                session: session.0,
                subject: subject.clone(),
                reason: reason.clone(),
            },
            Event::Approved {
                session,
                subject,
                by,
            } => RecEvent::Approved {
                session: session.0,
                subject: subject.clone(),
                by: by.clone(),
            },
            Event::Rejected {
                session,
                subject,
                by,
                why,
            } => RecEvent::Rejected {
                session: session.0,
                subject: subject.clone(),
                by: by.clone(),
                why: why.clone(),
            },
            Event::Killed { session, by } => RecEvent::Killed {
                session: session.0,
                by: by.clone(),
            },
            Event::Revoked { session, cap } => RecEvent::Revoked {
                session: session.0,
                cap: cap.0,
            },
            Event::SessionClosed { session } => RecEvent::SessionClosed { session: session.0 },
        }
    }
}

/// One line on disk: the event plus the hash of the previous raw line.
#[derive(Serialize, Deserialize)]
struct Line {
    prev: String,
    event: RecEvent,
}

// ── the recorder ────────────────────────────────────────────────────────────────────────────────

/// Append-only, hash-chained event log. Hashing + disk I/O run on a **background thread** so the
/// hot path never blocks: for a governed *terminal*, [`record`](Recorder::record) is called on every
/// keystroke (a `Call`) and every echo chunk (an `Output`), and doing a SHA-256 + `writeln` under a
/// shared lock there put the audit log squarely in the typing latency path — with the input thread
/// and the output pump contending on the same mutex. Now `record` is a lock-free channel push; a
/// single writer thread owns the file and the chain. Because it's asynchronous, callers that read
/// the file back (`load`, `replay`, `head`-after-record) must [`flush`](Self::flush) first.
/// Best-effort in the spike; the product recorder adds fsync + a backpressure policy.
pub struct FileRecorder {
    tx: Sender<RecMsg>,
    head: Arc<Mutex<String>>,
}

enum RecMsg {
    Event(Event),
    Flush(Sender<()>),
}

impl FileRecorder {
    pub fn create(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let file = File::create(path)?;
        let (tx, rx) = mpsc::channel::<RecMsg>();
        let head = Arc::new(Mutex::new(GENESIS.to_string()));
        let head_bg = head.clone();
        std::thread::spawn(move || {
            // Write directly (not buffered): this thread is off the hot path, and writing each line
            // eagerly means a reader (e.g. kedi's /record replay endpoint) always sees current data.
            let mut w = file;
            let mut prev = GENESIS.to_string();
            for msg in rx {
                match msg {
                    RecMsg::Event(ev) => {
                        let line = serde_json::to_string(&Line {
                            prev: prev.clone(),
                            event: (&ev).into(),
                        })
                        .expect("event serialization is infallible");
                        prev = sha256_hex(line.as_bytes());
                        *head_bg.lock().unwrap() = prev.clone();
                        if let Err(e) = writeln!(w, "{line}") {
                            eprintln!("[warden-record] append failed: {e}");
                        }
                    }
                    RecMsg::Flush(reply) => {
                        let _ = w.flush();
                        let _ = reply.send(()); // queue drained → all prior events are on disk
                    }
                }
            }
        });
        Ok(Self { tx, head })
    }

    /// The current chain head — anchor this externally (sign it, ship it to the gateway) to also
    /// catch truncation/rewrite of the tail, which in-file chaining alone cannot. Reflects events
    /// processed so far; [`flush`](Self::flush) first if it must include a just-recorded event.
    pub fn head(&self) -> String {
        self.head.lock().unwrap().clone()
    }

    /// Block until every event queued before this call is written and flushed to disk. Recording is
    /// asynchronous, so callers that then read the file back (`load`, `replay`) must flush first.
    pub fn flush(&self) {
        let (rtx, rrx) = mpsc::channel();
        if self.tx.send(RecMsg::Flush(rtx)).is_ok() {
            let _ = rrx.recv();
        }
    }
}

impl Recorder for FileRecorder {
    fn record(&self, ev: Event) {
        let _ = self.tx.send(RecMsg::Event(ev)); // background thread hashes + writes; never blocks the caller
    }
}

// ── load + verify ───────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum RecordError {
    Io(std::io::Error),
    Parse {
        line: usize,
        err: String,
    },
    /// The hash chain does not link up at this line — the record was modified at or before it.
    ChainBroken {
        line: usize,
    },
}
impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordError::Io(e) => write!(f, "io: {e}"),
            RecordError::Parse { line, err } => write!(f, "line {line}: not a record line: {err}"),
            RecordError::ChainBroken { line } => {
                write!(
                    f,
                    "hash chain broken at line {line} — the record was modified at or before this line"
                )
            }
        }
    }
}
impl std::error::Error for RecordError {}

/// Read a record back, verifying the hash chain as it goes. Returns the events only if every link
/// holds; a doctored line surfaces as [`RecordError::ChainBroken`] at the first line after the edit.
pub fn load(path: impl AsRef<Path>) -> Result<Vec<RecEvent>, RecordError> {
    let file = File::open(path).map_err(RecordError::Io)?;
    let mut prev = GENESIS.to_string();
    let mut events = Vec::new();
    for (i, raw) in BufReader::new(file).lines().enumerate() {
        let raw = raw.map_err(RecordError::Io)?;
        let line: Line = serde_json::from_str(&raw).map_err(|e| RecordError::Parse {
            line: i + 1,
            err: e.to_string(),
        })?;
        if line.prev != prev {
            return Err(RecordError::ChainBroken { line: i + 1 });
        }
        prev = sha256_hex(raw.as_bytes());
        events.push(line.event);
    }
    Ok(events)
}

// ── rewind ──────────────────────────────────────────────────────────────────────────────────────

/// Observed state at a point in the record: what a rewind scrubber shows at position `k`.
#[derive(Debug, Default, PartialEq)]
pub struct StateAt {
    pub sessions_open: Vec<u64>,
    /// (cap id, kind) still held — granted and not yet revoked.
    pub caps_held: Vec<(u64, String)>,
    pub calls: u64,
    pub denied_or_failed: u64,
    /// Sessions killed by this point, with the killer's name (still open until their close event).
    pub killed: Vec<(u64, String)>,
    /// An escalation awaiting a verdict at this point (what a scrubber shows as "held for approval").
    pub pending_approval: Option<String>,
    /// The last output that crossed the chokepoint — i.e. what the operator last saw (post-mask).
    pub last_output: Option<Vec<u8>>,
}

/// Fold the first `upto` events into the state as-of that moment.
pub fn state_at(events: &[RecEvent], upto: usize) -> StateAt {
    let mut s = StateAt::default();
    for ev in &events[..upto.min(events.len())] {
        match ev {
            RecEvent::SessionOpened { session, .. } => s.sessions_open.push(*session),
            RecEvent::SessionClosed { session } => s.sessions_open.retain(|x| x != session),
            RecEvent::CapGranted { cap, kind, .. } => s.caps_held.push((*cap, kind.clone())),
            RecEvent::Revoked { cap, .. } => s.caps_held.retain(|(c, _)| c != cap),
            RecEvent::Call { .. } => s.calls += 1,
            RecEvent::Result { output, .. } => s.last_output = Some(output.clone()),
            RecEvent::Output { bytes, .. } => s.last_output = Some(bytes.clone()),
            RecEvent::Failed { .. } | RecEvent::Denied { .. } => s.denied_or_failed += 1,
            RecEvent::EscalationRequested { subject, .. } => {
                s.pending_approval = Some(subject.clone())
            }
            RecEvent::Approved { .. } => s.pending_approval = None,
            RecEvent::Rejected { .. } => {
                s.denied_or_failed += 1;
                s.pending_approval = None;
            }
            RecEvent::Killed { session, by } => s.killed.push((*session, by.clone())),
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use warden_core::{CapId, CapKind, SessionId};

    fn sample_events() -> Vec<Event> {
        vec![
            Event::SessionOpened {
                session: SessionId(1),
                identity: "t".into(),
            },
            Event::CapGranted {
                session: SessionId(1),
                cap: CapId(1),
                kind: CapKind("fs.read"),
            },
            Event::Call {
                session: SessionId(1),
                seq: 1,
                cap: CapId(1),
                op: "read".into(),
                input: b"deploy".to_vec(),
            },
            Event::Result {
                session: SessionId(1),
                seq: 1,
                output: b"OUT=*******".to_vec(),
            },
            Event::Revoked {
                session: SessionId(1),
                cap: CapId(1),
            },
            Event::SessionClosed {
                session: SessionId(1),
            },
        ]
    }

    #[test]
    fn roundtrip_verifies_and_rewinds() {
        let path = std::env::temp_dir().join("warden-record-test.jsonl");
        let rec = FileRecorder::create(&path).unwrap();
        for ev in sample_events() {
            rec.record(ev);
        }
        rec.flush(); // recording is async — drain before reading the file back

        let events = load(&path).unwrap();
        assert_eq!(events.len(), 6);
        assert!(matches!(&events[3], RecEvent::Result { output, .. } if output == b"OUT=*******"));

        // rewind to just after the result: session open, cap still held, output visible
        let s = state_at(&events, 4);
        assert_eq!(s.sessions_open, vec![1]);
        assert_eq!(s.caps_held, vec![(1, "fs.read".to_string())]);
        assert_eq!(s.last_output.as_deref(), Some(b"OUT=*******".as_slice()));
        // ...and at the end: everything released
        let end = state_at(&events, events.len());
        assert!(end.sessions_open.is_empty() && end.caps_held.is_empty());
    }

    #[test]
    fn tampering_breaks_the_chain() {
        let path = std::env::temp_dir().join("warden-record-tamper-test.jsonl");
        let rec = FileRecorder::create(&path).unwrap();
        for ev in sample_events() {
            rec.record(ev);
        }
        rec.flush(); // recording is async — drain before doctoring + reading the file

        // doctor the recorded call input: "deploy" -> "delete" (same length, valid hex, valid JSON)
        let txt = std::fs::read_to_string(&path).unwrap();
        let doctored = txt.replacen("6465706c6f79", "64656c657465", 1);
        assert_ne!(txt, doctored, "tamper target not found");
        std::fs::write(&path, doctored).unwrap();

        match load(&path) {
            Err(RecordError::ChainBroken { line }) => assert_eq!(line, 4), // first line after the edit
            other => panic!("tamper not detected: {other:?}"),
        }
    }
}
