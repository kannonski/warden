//! `pty` — an interactive pseudo-terminal as a capability.
//!
//! Grant allocates a PTY but **defers spawning the shell until the first op** (a `resize` from the
//! client, or `input`/`wait`). This matters: fancy prompts (powerlevel10k / instant-prompt) compute
//! their cursor geometry at startup from the terminal size and get permanently confused by a
//! *post-init* resize — so the browser's first `resize` must arrive *before* the shell starts, and
//! the shell then initializes at the true size. The shell's continuous output is exposed as the
//! capability's [`output`](warden_core::Capability::output) stream — the kernel drains it through
//! the interceptor chain (masking, if wired) and records each chunk. Input/resize are ops; `wait`
//! blocks until the shell exits. Revoke (or a session kill) terminates the child.
//!
//! Substrate for the governed terminal (kedi): xterm.js keystrokes → `input`, the governed output
//! stream → the display, kill/rewind reuse the existing seams. Coarse authority (a governed shell).

use async_trait::async_trait;
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, SlavePty, native_pty_system};
use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc::{self, UnboundedReceiver};
use warden_core::{
    Broker, CapKind, CapRequest, Capability, OpSpec, OutputStream, Result, WardenError,
};

pub const PTY: CapKind = CapKind("pty");

struct PtyCap {
    master: Mutex<Box<dyn MasterPty + Send>>,
    writer: Mutex<Box<dyn Write + Send>>,
    slave: Mutex<Option<Box<dyn SlavePty + Send>>>, // consumed when the shell is spawned
    child: Mutex<Option<Box<dyn Child + Send + Sync>>>,
    command: String,
    spawned: AtomicBool,
    output: Mutex<Option<UnboundedReceiver<Vec<u8>>>>,
    exited: Arc<AtomicBool>, // set by the reader thread on EOF (shell gone); read via `finished()`
}

impl PtyCap {
    /// Start the shell (once). Called at the top of the first op, so the shell inherits whatever
    /// size the client set via `resize` before it initializes.
    fn ensure_shell(&self) -> Result<()> {
        if self.spawned.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let slave = self
            .slave
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| WardenError::Cap("pty slave already taken".into()))?;
        let mut cmd = if self.command.trim().is_empty() {
            CommandBuilder::new(std::env::var("SHELL").unwrap_or_else(|_| "bash".into()))
        } else {
            let mut c = CommandBuilder::new("sh");
            c.arg("-c");
            c.arg(&self.command);
            c
        };
        cmd.env("TERM", "xterm-256color");
        // identify the terminal to the shell (the convention iTerm/WezTerm/Apple Terminal use) —
        // lets shell config adapt, e.g. a leaner prompt inside the governed web terminal
        cmd.env("TERM_PROGRAM", "kedi");
        let child = slave
            .spawn_command(cmd)
            .map_err(|e| WardenError::Cap(format!("pty spawn: {e}")))?;
        drop(slave); // release our handle; the child keeps its own
        *self.child.lock().unwrap() = Some(child);
        Ok(())
    }
}

// input and resize change the terminal's state; wait only observes the exit code.
const OPS: &[OpSpec] = &[
    OpSpec {
        op: "input",
        doc: "write bytes to the shell's stdin (spawns the shell on first use)",
        mutates: true,
    },
    OpSpec {
        op: "resize",
        doc: "resize the pty to `COLSxROWS` (spawns the shell at that size on first use)",
        mutates: true,
    },
    OpSpec {
        op: "wait",
        doc: "block until the shell exits; returns its exit code",
        mutates: false,
    },
];

#[async_trait]
impl Capability for PtyCap {
    fn kind(&self) -> CapKind {
        PTY
    }
    fn ops(&self) -> &'static [OpSpec] {
        OPS
    }
    async fn perform(&self, op: &str, input: &[u8]) -> Result<Vec<u8>> {
        match op {
            "resize" => {
                let spec = std::str::from_utf8(input)
                    .map_err(|e| WardenError::Cap(format!("resize utf8: {e}")))?;
                let (cols, rows) = spec
                    .split_once('x')
                    .and_then(|(c, r)| Some((c.trim().parse().ok()?, r.trim().parse().ok()?)))
                    .ok_or_else(|| {
                        WardenError::Cap(format!("resize expects `COLSxROWS`, got `{spec}`"))
                    })?;
                // size the pty FIRST, then (on the first resize) spawn the shell AT that size
                self.master
                    .lock()
                    .unwrap()
                    .resize(PtySize {
                        rows,
                        cols,
                        pixel_width: 0,
                        pixel_height: 0,
                    })
                    .map_err(|e| WardenError::Cap(format!("pty resize: {e}")))?;
                self.ensure_shell()?;
                Ok(Vec::new())
            }
            "input" => {
                self.ensure_shell()?;
                let mut w = self.writer.lock().unwrap();
                w.write_all(input)
                    .map_err(|e| WardenError::Cap(format!("pty write: {e}")))?;
                let _ = w.flush();
                Ok(Vec::new())
            }
            "wait" => {
                self.ensure_shell()?;
                let status = self
                    .child
                    .lock()
                    .unwrap()
                    .as_mut()
                    .ok_or_else(|| WardenError::Cap("pty not running".into()))?
                    .wait()
                    .map_err(|e| WardenError::Cap(format!("pty wait: {e}")))?;
                Ok(status.exit_code().to_string().into_bytes())
            }
            // kernel validates first; this defends the cap in isolation too (see `no_such_op`)
            other => Err(warden_core::no_such_op(PTY, other)),
        }
    }
    fn revoke(&self) {
        if let Some(mut child) = self.child.lock().unwrap().take() {
            let _ = child.kill();
        }
    }
    fn output(&self) -> Option<OutputStream> {
        // hand the reader-thread's receiver to the kernel as an async Stream; the blocking pty read
        // stays on its dedicated OS thread (that's the right home for blocking OS I/O), bridged into
        // async by the unbounded tokio channel.
        self.output.lock().unwrap().take().map(|rx| {
            Box::pin(tokio_stream::wrappers::UnboundedReceiverStream::new(rx)) as OutputStream
        })
    }
    fn finished(&self) -> bool {
        self.exited.load(Ordering::SeqCst)
    }
}

pub struct PtyBroker;
#[async_trait]
impl Broker for PtyBroker {
    fn handles(&self, req: &CapRequest) -> bool {
        req.kind == PTY
    }
    async fn grant(&self, req: &CapRequest) -> Result<Box<dyn Capability>> {
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| WardenError::Cap(format!("openpty: {e}")))?;

        // reader + writer are wired now; the reader blocks until the (lazily-spawned) shell writes
        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| WardenError::Cap(format!("pty reader: {e}")))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|e| WardenError::Cap(format!("pty writer: {e}")))?;

        let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let exited = Arc::new(AtomicBool::new(false));
        let exited_reader = exited.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break, // EOF when the child (and thus the pty) closes
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                }
            }
            // pty closed → the shell has exited; tell `finished()` so an attach loop can end
            exited_reader.store(true, Ordering::SeqCst);
        });

        Ok(Box::new(PtyCap {
            master: Mutex::new(pair.master),
            writer: Mutex::new(writer),
            slave: Mutex::new(Some(pair.slave)),
            child: Mutex::new(None),
            command: req.arg.clone(),
            spawned: AtomicBool::new(false),
            output: Mutex::new(Some(rx)),
            exited,
        }))
    }
}
