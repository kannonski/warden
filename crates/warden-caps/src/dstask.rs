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

const OPS: &[OpSpec] = &[OpSpec {
    op: "list",
    doc: "all tasks (incl. resolved) as the dstask JSON array on stdout",
    mutates: false,
}];

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
    async fn perform(&self, op: &str, _input: &[u8]) -> Result<Vec<u8>> {
        match op {
            // `dstask` with no args prints the full task set as JSON (id, uuid, summary, status,
            // priority, tags, project, notes, created, resolved, due) — exactly what deck renders.
            "list" => {
                let out = Command::new(&self.bin)
                    .output()
                    .map_err(|e| WardenError::Cap(format!("dstask spawn: {e}")))?;
                if !out.status.success() {
                    return Err(WardenError::Cap(format!(
                        "dstask exited {}: {}",
                        out.status,
                        String::from_utf8_lossy(&out.stderr).trim()
                    )));
                }
                Ok(out.stdout)
            }
            other => Err(warden_core::no_such_op(DSTASK, other)),
        }
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
