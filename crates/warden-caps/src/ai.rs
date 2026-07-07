//! `ai` — an LLM query as a governed capability.
//!
//! A sandboxed `kedi:app` plugin (like deck) can't shell out or hit the network; it reaches a model
//! only through this capability. The backend is a **configurable command** (`$KEDI_AI_CMD`, run via
//! `sh -c`): the plugin's prompt is written to the command's stdin, and its stdout is the answer.
//! Point it at ollama, a Claude wrapper, or any script — backend-agnostic, exactly like the old deck
//! agent hook, but now chokepointed (recorded, policy-gated, killable).
//!
//! **Async by design.** The guest's `host.invoke` is blocking, and an LLM call takes seconds — so the
//! op is split `start` → `poll`. `start` spawns the command on a background thread and returns a job
//! id immediately; `poll` reads the job's state (pending / done+answer / failed). The guest fires
//! `start`, keeps painting, and picks up the answer from its `on_tick` loop — the pane never freezes.

use async_trait::async_trait;
use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use warden_core::{Broker, CapKind, CapRequest, Capability, OpSpec, Result, WardenError};

pub const AI: CapKind = CapKind("ai");

const OPS: &[OpSpec] = &[
    OpSpec {
        op: "start",
        doc: "start an LLM query; input = the prompt (utf-8). Returns a job id (ascii) immediately.",
        mutates: true,
    },
    OpSpec {
        op: "poll",
        doc: "poll a job by id. Returns `P` (pending), `D\\n<answer>` (done), or `E\\n<error>`.",
        mutates: false,
    },
];

/// A running or finished query.
enum Job {
    Pending,
    Done(String),
    Failed(String),
}

pub struct AiCap {
    /// the backend command line (`$KEDI_AI_CMD`), run via `sh -c`; empty → queries fail with a clear
    /// "not configured" message so the guest can tell the user.
    cmd: String,
    jobs: Arc<Mutex<HashMap<u64, Job>>>,
    next: Arc<Mutex<u64>>,
}

#[async_trait]
impl Capability for AiCap {
    fn kind(&self) -> CapKind {
        AI
    }
    fn ops(&self) -> &'static [OpSpec] {
        OPS
    }
    async fn perform(&self, op: &str, input: &[u8]) -> Result<Vec<u8>> {
        match op {
            "start" => {
                let prompt = String::from_utf8_lossy(input).into_owned();
                let id = {
                    let mut n = self.next.lock().unwrap();
                    *n += 1;
                    *n
                };
                self.jobs.lock().unwrap().insert(id, Job::Pending);
                let jobs = self.jobs.clone();
                let cmd = self.cmd.clone();
                // run the backend off the caller's thread; write the result into the job table.
                std::thread::spawn(move || {
                    let result = run_ai(&cmd, &prompt);
                    let mut j = jobs.lock().unwrap();
                    j.insert(
                        id,
                        match result {
                            Ok(answer) => Job::Done(answer),
                            Err(e) => Job::Failed(e),
                        },
                    );
                });
                Ok(id.to_string().into_bytes())
            }
            "poll" => {
                let id: u64 = std::str::from_utf8(input)
                    .ok()
                    .and_then(|s| s.trim().parse().ok())
                    .ok_or_else(|| WardenError::Cap(format!("ai poll: bad id {input:?}")))?;
                let jobs = self.jobs.lock().unwrap();
                let out = match jobs.get(&id) {
                    None => "E\nno such job".to_string(),
                    Some(Job::Pending) => "P".to_string(),
                    Some(Job::Done(answer)) => format!("D\n{answer}"),
                    Some(Job::Failed(e)) => format!("E\n{e}"),
                };
                Ok(out.into_bytes())
            }
            other => Err(warden_core::no_such_op(AI, other)),
        }
    }
    fn revoke(&self) {
        // nothing to release — background threads finish on their own and write into a table we drop.
        self.jobs.lock().unwrap().clear();
    }
}

/// Run the configured backend command with `prompt` on stdin, returning its stdout. Empty command →
/// a clear error. stderr is discarded so a chatty backend never leaks into kedi's terminal.
fn run_ai(cmd: &str, prompt: &str) -> std::result::Result<String, String> {
    if cmd.trim().is_empty() {
        return Err("KEDI_AI_CMD not set — configure an AI backend command".into());
    }
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("ai spawn: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(prompt.as_bytes());
        // drop stdin (close it) so the command sees EOF
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("ai wait: {e}"))?;
    if !out.status.success() {
        return Err(format!("ai command exited {}", out.status));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim_end().to_string())
}

/// Grants the `ai` capability. `req.arg` overrides the command; empty → `$KEDI_AI_CMD` (then "" if
/// unset, which surfaces as a "not configured" failure on the first query).
pub struct AiBroker;

#[async_trait]
impl Broker for AiBroker {
    fn handles(&self, req: &CapRequest) -> bool {
        req.kind == AI
    }
    async fn grant(&self, req: &CapRequest) -> Result<Box<dyn Capability>> {
        let cmd = if req.arg.trim().is_empty() {
            std::env::var("KEDI_AI_CMD").unwrap_or_default()
        } else {
            req.arg.clone()
        };
        Ok(Box::new(AiCap {
            cmd,
            jobs: Arc::new(Mutex::new(HashMap::new())),
            next: Arc::new(Mutex::new(0)),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // start → poll cycle with a trivial backend (`cat` echoes the prompt back). Poll until done.
    #[tokio::test]
    async fn start_then_poll_returns_the_answer() {
        let cap = AiCap {
            cmd: "cat".into(),
            jobs: Arc::new(Mutex::new(HashMap::new())),
            next: Arc::new(Mutex::new(0)),
        };
        let id = cap.perform("start", b"hello model").await.unwrap();
        let id = String::from_utf8(id).unwrap();
        // poll until the background thread finishes (cat is instant, but be robust)
        let mut answer = String::new();
        for _ in 0..100 {
            let out = cap.perform("poll", id.as_bytes()).await.unwrap();
            let s = String::from_utf8(out).unwrap();
            if let Some(rest) = s.strip_prefix("D\n") {
                answer = rest.to_string();
                break;
            }
            assert!(s == "P", "unexpected poll state: {s:?}");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(answer, "hello model", "cat should echo the prompt");
    }

    // an unset/empty command → the job fails with a clear message.
    #[tokio::test]
    async fn unconfigured_command_fails_clearly() {
        let cap = AiCap {
            cmd: String::new(),
            jobs: Arc::new(Mutex::new(HashMap::new())),
            next: Arc::new(Mutex::new(0)),
        };
        let id = String::from_utf8(cap.perform("start", b"hi").await.unwrap()).unwrap();
        let mut err = String::new();
        for _ in 0..100 {
            let s = String::from_utf8(cap.perform("poll", id.as_bytes()).await.unwrap()).unwrap();
            if let Some(rest) = s.strip_prefix("E\n") {
                err = rest.to_string();
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            err.contains("KEDI_AI_CMD not set"),
            "expected not-configured error, got {err:?}"
        );
    }

    // poll on an unknown id → error, not a panic.
    #[tokio::test]
    async fn poll_unknown_id() {
        let cap = AiCap {
            cmd: "cat".into(),
            jobs: Arc::new(Mutex::new(HashMap::new())),
            next: Arc::new(Mutex::new(0)),
        };
        let s = String::from_utf8(cap.perform("poll", b"999").await.unwrap()).unwrap();
        assert_eq!(s, "E\nno such job");
    }
}
