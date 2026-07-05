//! `exec` — run ONE hash-pinned binary, nothing else.
//!
//! The request names the binary *and* its expected SHA-256 (`/path/to/bin@sha256:<hex>` — in the
//! real product the pin comes from a validated-binary catalog, not the caller). The broker refuses
//! the grant if the on-disk binary doesn't match, and the capability re-verifies right before each
//! spawn, narrowing the grant→spawn TOCTOU window. (Real impl closes it fully: open the fd once at
//! grant, verify the fd's content, spawn via `fexecve` — same seam, better mechanics.)
//!
//! The op is `run`, input = arguments separated by `\x1f` (unit separator). stdout is the output —
//! and it flows back through the interceptor chain like any capability result, so the child's
//! output is DLP-masked and recorded without the child ever knowing.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use warden_core::{Broker, CapKind, CapRequest, Capability, Result, WardenError};

pub const EXEC: CapKind = CapKind("exec");

/// Argument separator inside `perform("run", input)`.
pub const ARG_SEP: char = '\x1f';

/// SHA-256 of a file, lowercase hex. (What a validated-binary catalog would store as the pin.)
pub fn sha256_hex_of(path: impl AsRef<Path>) -> Result<String> {
    let bytes = std::fs::read(path.as_ref())
        .map_err(|e| WardenError::Cap(format!("hash {}: {e}", path.as_ref().display())))?;
    let digest = Sha256::digest(&bytes);
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

pub struct ExecCap {
    program: PathBuf,
    pinned_sha256: String,
}
impl Capability for ExecCap {
    fn kind(&self) -> CapKind {
        EXEC
    }
    fn perform(&self, op: &str, input: &[u8]) -> Result<Vec<u8>> {
        match op {
            "run" => {
                // re-verify the pin at spawn time — the binary must not have changed since grant
                let now = sha256_hex_of(&self.program)?;
                if !now.eq_ignore_ascii_case(&self.pinned_sha256) {
                    return Err(WardenError::Cap(format!(
                        "{} changed since grant (hash mismatch) — refusing to spawn",
                        self.program.display()
                    )));
                }
                let args: Vec<&str> = match input {
                    [] => Vec::new(),
                    _ => std::str::from_utf8(input)
                        .map_err(|e| WardenError::Cap(format!("args not utf-8: {e}")))?
                        .split(ARG_SEP)
                        .collect(),
                };
                let out = std::process::Command::new(&self.program)
                    .args(&args)
                    .output()
                    .map_err(|e| {
                        WardenError::Cap(format!("spawn {}: {e}", self.program.display()))
                    })?;
                if !out.status.success() {
                    return Err(WardenError::Cap(format!(
                        "{} exited {}: {}",
                        self.program.display(),
                        out.status,
                        String::from_utf8_lossy(&out.stderr).trim()
                    )));
                }
                Ok(out.stdout)
            }
            other => Err(WardenError::Cap(format!(
                "exec grants only `run`, not `{other}`"
            ))),
        }
    }
    fn revoke(&self) {
        // real impl: kill any children still running under this grant. spike: run() is blocking.
    }
}

pub struct ExecBroker;
impl Broker for ExecBroker {
    fn handles(&self, req: &CapRequest) -> bool {
        req.kind == EXEC
    }
    fn grant(&self, req: &CapRequest) -> Result<Box<dyn Capability>> {
        let (path, want) = req.arg.split_once("@sha256:").ok_or_else(|| {
            WardenError::Cap(format!(
                "exec request must be `<path>@sha256:<hex>`, got `{}`",
                req.arg
            ))
        })?;
        let got = sha256_hex_of(path)?;
        if !got.eq_ignore_ascii_case(want) {
            return Err(WardenError::Cap(format!(
                "binary validation failed for {path}: sha256 is {got}, pinned {want} — grant refused"
            )));
        }
        Ok(Box::new(ExecCap {
            program: path.into(),
            pinned_sha256: want.to_string(),
        }))
    }
}
