//! `fs.read` — read one file, nothing else.

use warden_core::{Broker, CapKind, CapRequest, Capability, Result, WardenError};

pub const FS_READ: CapKind = CapKind("fs.read");

pub struct FsReadCap {
    path: std::path::PathBuf,
}
impl Capability for FsReadCap {
    fn kind(&self) -> CapKind {
        FS_READ
    }
    fn perform(&self, op: &str, _input: &[u8]) -> Result<Vec<u8>> {
        match op {
            "read" => std::fs::read(&self.path)
                .map_err(|e| WardenError::Cap(format!("read {}: {e}", self.path.display()))),
            other => Err(WardenError::Cap(format!(
                "fs.read grants only `read`, not `{other}`"
            ))),
        }
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
