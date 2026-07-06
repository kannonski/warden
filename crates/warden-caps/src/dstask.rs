//! `dstask` — the task store as a governed capability.
//!
//! deck (rewritten as a `kedi:app` WASM plugin) can't link the dstask Go library or touch the
//! filesystem — its WASI is empty. So it reaches the task store only through this capability: the
//! guest calls `host.invoke("dstask", op, input)`, which crosses the warden chokepoint and lands
//! here, where the host shells to the `dstask` CLI (JSON on stdout). Every task read/write is a
//! recorded, policy-gated, killable op — deck-in-a-sandbox governed exactly like anything else.
//!
//! Ops (grown as deck needs them): `list` (all tasks as JSON) to start; mutating ops (add, modify,
//! resolve, start/stop, note) land alongside as the UI port needs them.

use async_trait::async_trait;
use std::process::Command;
use warden_core::{Broker, CapKind, CapRequest, Capability, OpSpec, Result, WardenError};

pub const DSTASK: CapKind = CapKind("dstask");

const OPS: &[OpSpec] = &[
    OpSpec {
        op: "list",
        doc: "all tasks (incl. resolved) as the dstask JSON array on stdout",
        mutates: false,
    },
    OpSpec {
        op: "add",
        doc: "add a task; input = the summary + dstask tokens (+tag project: Pn)",
        mutates: true,
    },
    OpSpec {
        op: "modify",
        doc: "modify a task; input = `<id> <tokens>` (+tag -tag Pn project:x)",
        mutates: true,
    },
    OpSpec {
        op: "done",
        doc: "resolve a task; input = the id",
        mutates: true,
    },
    OpSpec {
        op: "start",
        doc: "mark a task active; input = the id",
        mutates: true,
    },
    OpSpec {
        op: "stop",
        doc: "pause an active task; input = the id",
        mutates: true,
    },
    OpSpec {
        op: "note",
        doc: "append a note; input = `<id> <text>`",
        mutates: true,
    },
];

pub struct DsTaskCap {
    /// the dstask binary (default `dstask`; overridable so a sandboxed/test host can point elsewhere)
    bin: String,
}

#[async_trait]
impl Capability for DsTaskCap {
    fn kind(&self) -> CapKind {
        DSTASK
    }
    fn ops(&self) -> &'static [OpSpec] {
        OPS
    }
    async fn perform(&self, op: &str, input: &[u8]) -> Result<Vec<u8>> {
        // the dstask subcommand + its args. `list` is the bare CLI (JSON out); the mutating ops map
        // to dstask subcommands, with the input string appended as whitespace-split arguments.
        let args: Vec<String> = match op {
            "list" => Vec::new(),
            "add" | "modify" | "done" | "start" | "stop" | "note" => {
                let mut a = vec![op.to_string()];
                let s = std::str::from_utf8(input)
                    .map_err(|e| WardenError::Cap(format!("dstask {op} utf8: {e}")))?;
                a.extend(s.split_whitespace().map(str::to_string));
                a
            }
            other => return Err(warden_core::no_such_op(DSTASK, other)),
        };
        let out = Command::new(&self.bin)
            .args(&args)
            .output()
            .map_err(|e| WardenError::Cap(format!("dstask spawn: {e}")))?;
        if !out.status.success() {
            return Err(WardenError::Cap(format!(
                "dstask {op} exited {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(out.stdout)
    }
    fn revoke(&self) {
        // nothing to release — each op is a fresh CLI call
    }
}

/// Grants the `dstask` capability. `req.arg` optionally overrides the binary (empty → `dstask`).
pub struct DsTaskBroker;

#[async_trait]
impl Broker for DsTaskBroker {
    fn handles(&self, req: &CapRequest) -> bool {
        req.kind == DSTASK
    }
    async fn grant(&self, req: &CapRequest) -> Result<Box<dyn Capability>> {
        let bin = if req.arg.trim().is_empty() {
            "dstask".to_string()
        } else {
            req.arg.clone()
        };
        Ok(Box::new(DsTaskCap { bin }))
    }
}
