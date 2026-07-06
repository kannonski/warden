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
    OpSpec {
        op: "note-set",
        doc: "replace the whole note blob; input = `<id>\\n<markdown>` (first line = id)",
        mutates: true,
    },
    OpSpec {
        op: "list-resolved",
        doc: "resolved tasks as the dstask JSON array on stdout (for the DONE column)",
        mutates: false,
    },
    OpSpec {
        op: "today",
        doc: "today's local date as `YYYY-MM-DD` (the sandbox has no clock; this is the host's)",
        mutates: false,
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
        // These ops don't fit the generic "subcommand + whitespace args" shape. note-set replaces the
        // whole note blob via dstask's editor hook; today reports the host's local date (the sandbox
        // has no clock). Handle them first; generic CLI path for the rest.
        match op {
            "note-set" => return self.note_set(input),
            "today" => return self.today(),
            _ => {}
        }
        // the dstask subcommand + its args. `list` is the bare CLI (JSON out); `list-resolved` reads
        // the resolved report; the mutating ops map to subcommands with the input as whitespace args.
        let args: Vec<String> = match op {
            "list" => Vec::new(),
            "list-resolved" => vec!["show-resolved".to_string()],
            "add" | "modify" | "done" | "start" | "stop" | "note" => {
                let mut a = vec![op.to_string()];
                let s = std::str::from_utf8(input)
                    .map_err(|e| WardenError::Cap(format!("dstask {op} utf8: {e}")))?;
                a.extend(s.split_whitespace().map(str::to_string));
                a
            }
            other => return Err(warden_core::no_such_op(DSTASK, other)),
        };
        let out = self.run(&args)?;
        Ok(out)
    }
    fn revoke(&self) {
        // nothing to release — each op is a fresh CLI call
    }
}

impl DsTaskCap {
    /// Run the dstask CLI with `args`, returning stdout on success or a `Cap` error carrying stderr.
    fn run(&self, args: &[String]) -> Result<Vec<u8>> {
        let out = Command::new(&self.bin)
            .args(args)
            .output()
            .map_err(|e| WardenError::Cap(format!("dstask spawn: {e}")))?;
        if !out.status.success() {
            return Err(WardenError::Cap(format!(
                "dstask {} exited {}: {}",
                args.first().map(String::as_str).unwrap_or("list"),
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(out.stdout)
    }

    /// Today's local date as `YYYY-MM-DD`. dstask stamps `resolved` in local time, so the DONE column
    /// filters by this prefix. We shell to `date` rather than pull a date crate: it's POSIX-ubiquitous
    /// and honors the host TZ (a UTC-from-epoch calc would be a day off near midnight).
    fn today(&self) -> Result<Vec<u8>> {
        let out = Command::new("date")
            .arg("+%Y-%m-%d")
            .output()
            .map_err(|e| WardenError::Cap(format!("date spawn: {e}")))?;
        if !out.status.success() {
            return Err(WardenError::Cap(format!("date exited {}", out.status)));
        }
        // trim the trailing newline so the guest gets a bare YYYY-MM-DD
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        Ok(s.into_bytes())
    }

    /// Replace the whole note blob for a task. `input` = `<id>\n<markdown…>` (first line is the id,
    /// the rest is the new note verbatim). dstask has no non-interactive "set note", but `dstask note
    /// <id>` dumps the note to a temp file, exec's `$EDITOR <file>`, then reads it back. dstask exec's
    /// `$EDITOR` directly as argv (not via a shell), so a multi-word command like `cp src` won't work;
    /// instead we drop a one-line editor script that copies our scratch content over whatever file
    /// dstask hands it as `$1` — a full replace with no tty. `DSTASK_FAKE_PTY=1` is required: without
    /// a tty dstask skips the editor step entirely. Best-effort cleanup of both temp files.
    fn note_set(&self, input: &[u8]) -> Result<Vec<u8>> {
        let s = std::str::from_utf8(input)
            .map_err(|e| WardenError::Cap(format!("dstask note-set utf8: {e}")))?;
        let (id, body) = s.split_once('\n').unwrap_or((s, ""));
        let id = id.trim();
        if id.is_empty() || id.parse::<i64>().is_err() {
            return Err(WardenError::Cap(format!("dstask note-set: bad id {id:?}")));
        }
        // unique-enough scratch paths without a clock/rng: pid + the task id.
        let tmp = std::env::temp_dir();
        let scratch = tmp.join(format!("kedi-note-{}-{id}.md", std::process::id()));
        let editor = tmp.join(format!("kedi-noteed-{}-{id}.sh", std::process::id()));
        std::fs::write(&scratch, body)
            .map_err(|e| WardenError::Cap(format!("dstask note-set scratch: {e}")))?;
        // the editor script: overwrite dstask's note file ($1) with our scratch content.
        let script = format!(
            "#!/bin/sh\ncat -- {} > \"$1\"\n",
            shell_quote(&scratch.to_string_lossy())
        );
        let run = (|| -> Result<std::process::Output> {
            std::fs::write(&editor, script)
                .map_err(|e| WardenError::Cap(format!("dstask note-set editor: {e}")))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&editor, std::fs::Permissions::from_mode(0o700))
                    .map_err(|e| WardenError::Cap(format!("dstask note-set chmod: {e}")))?;
            }
            Command::new(&self.bin)
                .args(["note", id])
                .env("EDITOR", &editor)
                .env("VISUAL", &editor)
                .env("DSTASK_FAKE_PTY", "1") // else dstask sees no tty and skips the editor entirely
                .output()
                .map_err(|e| WardenError::Cap(format!("dstask note-set spawn: {e}")))
        })();
        let _ = std::fs::remove_file(&scratch);
        let _ = std::fs::remove_file(&editor);
        let out = run?;
        if !out.status.success() {
            return Err(WardenError::Cap(format!(
                "dstask note-set exited {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(Vec::new())
    }
}

/// Single-quote a string for a POSIX shell, escaping any embedded single quotes. Used for the scratch
/// path baked into the editor script. Enough for a temp-file path we control.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

impl DsTaskCap {
    /// Construct a cap bound to a specific binary. Used by tests; production goes through the broker.
    #[cfg(test)]
    pub fn with_bin(bin: impl Into<String>) -> Self {
        DsTaskCap { bin: bin.into() }
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

#[cfg(test)]
mod tests {
    use super::*;

    // Both tests set the process-global DSTASK_GIT_REPO; serialize them so parallel test threads
    // don't clobber each other's env / store.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// note-set must REPLACE the whole note blob (not append), via the editor-script + fake-pty trick.
    /// Skips gracefully if `dstask` isn't installed. Runs against a throwaway store so it can't touch
    /// the user's tasks; sets DSTASK_GIT_REPO for the child dstask processes.
    #[tokio::test]
    async fn note_set_replaces_the_whole_blob() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if std::process::Command::new("dstask").arg("version").output().is_err() {
            eprintln!("skip: dstask not installed");
            return;
        }
        let repo = std::env::temp_dir().join(format!("kedi-dstask-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&repo);
        std::fs::create_dir_all(&repo).unwrap();
        assert!(std::process::Command::new("git").args(["init", "-q"]).current_dir(&repo).status().unwrap().success());
        // SAFETY: single-threaded test binary section; the child dstask processes read this env.
        unsafe { std::env::set_var("DSTASK_GIT_REPO", &repo) };

        let cap = DsTaskCap::with_bin("dstask");
        cap.perform("add", b"note editor probe").await.unwrap();

        // replace the (empty) note on task 1 with a multi-line blob, twice — the second must REPLACE,
        // not stack on the first (the whole point vs. the append-only `note` op).
        cap.perform("note-set", b"1\nfirst version\nline two").await.unwrap();
        cap.perform("note-set", b"1\nSECOND VERSION ONLY").await.unwrap();

        let json = cap.perform("list", b"").await.unwrap();
        let s = String::from_utf8_lossy(&json);
        assert!(s.contains("SECOND VERSION ONLY"), "note-set didn't land: {s}");
        assert!(!s.contains("first version"), "note-set appended instead of replacing: {s}");

        let _ = std::fs::remove_dir_all(&repo);
    }

    /// list-resolved returns resolved tasks (with timestamps), and `today` returns a YYYY-MM-DD the
    /// DONE column filters on. Proves the two ops the DONE-column fix depends on against real dstask.
    #[tokio::test]
    async fn list_resolved_and_today() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if std::process::Command::new("dstask").arg("version").output().is_err() {
            eprintln!("skip: dstask not installed");
            return;
        }
        let repo = std::env::temp_dir().join(format!("kedi-dstask-res-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&repo);
        std::fs::create_dir_all(&repo).unwrap();
        assert!(std::process::Command::new("git").args(["init", "-q"]).current_dir(&repo).status().unwrap().success());
        // SAFETY: single-threaded test binary section; child dstask processes read this env.
        unsafe { std::env::set_var("DSTASK_GIT_REPO", &repo) };

        let cap = DsTaskCap::with_bin("dstask");
        cap.perform("add", b"resolve me").await.unwrap();
        cap.perform("done", b"1").await.unwrap();

        let today = String::from_utf8(cap.perform("today", b"").await.unwrap()).unwrap();
        assert_eq!(today.len(), 10, "today should be YYYY-MM-DD, got {today:?}");
        assert_eq!(today.matches('-').count(), 2, "today format wrong: {today:?}");

        let resolved = cap.perform("list-resolved", b"").await.unwrap();
        let s = String::from_utf8_lossy(&resolved);
        assert!(s.contains("resolve me"), "list-resolved missing the resolved task: {s}");
        // the resolved timestamp should start with today (we just resolved it). dstask pretty-prints,
        // so match the timestamp value rather than an exact key/colon spacing.
        assert!(s.contains(&format!("\"{today}")), "resolved not stamped today ({today}): {s}");

        let _ = std::fs::remove_dir_all(&repo);
    }
}
