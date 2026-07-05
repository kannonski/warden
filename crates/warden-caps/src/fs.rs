//! `fs.read` — read one file, nothing else.

use warden_core::{Broker, CapKind, CapRequest, Capability, OpSpec, Result, WardenError};

pub const FS_READ: CapKind = CapKind("fs.read");

const OPS: &[OpSpec] = &[OpSpec {
    op: "read",
    doc: "read the whole granted file",
    mutates: false,
}];

pub struct FsReadCap {
    path: std::path::PathBuf,
}
impl Capability for FsReadCap {
    fn kind(&self) -> CapKind {
        FS_READ
    }
    fn ops(&self) -> &'static [OpSpec] {
        OPS
    }
    fn perform(&self, op: &str, _input: &[u8]) -> Result<Vec<u8>> {
        // kernel validates first; this defends the cap in isolation too (see `no_such_op`)
        if op != "read" {
            return Err(warden_core::no_such_op(FS_READ, op));
        }
        std::fs::read(&self.path)
            .map_err(|e| WardenError::Cap(format!("read {}: {e}", self.path.display())))
    }
    fn revoke(&self) {
        // real impl: close file handles / drop the descriptor. spike: nothing to do.
    }
}

pub struct FsReadBroker;
impl Broker for FsReadBroker {
    fn handles(&self, req: &CapRequest) -> bool {
        req.kind == FS_READ
    }
    fn grant(&self, req: &CapRequest) -> Result<Box<dyn Capability>> {
        Ok(Box::new(FsReadCap {
            path: req.arg.clone().into(),
        }))
    }
}
