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
use std::collections::HashMap;
use std::process::Command;
use std::sync::{Arc, Mutex};
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
    OpSpec {
        op: "do",
        doc: "start a mutating op OFF the caller's thread; input = `<op>\\n<args>` (first line = one \
              of add/modify/done/start/stop/note/note-set). Returns a job id (ascii) immediately.",
        mutates: true,
    },
    OpSpec {
        op: "do-poll",
        doc: "poll a `do` job by id. Returns `P` (pending), `D` (done), or `E\\n<error>`.",
        mutates: false,
    },
];

/// A running or finished mutating op. `Done` carries no payload — dstask mutations return nothing the
/// guest needs; it reloads the board on completion.
enum Job {
    Pending,
    Done,
    Failed(String),
}

pub struct DsTaskCap {
    /// the dstask binary (default `dstask`; overridable so a sandboxed/test host can point elsewhere)
    bin: String,
    /// in-flight/finished `do` jobs, keyed by id. Mutating ops (git-committing, ~200-500ms) run on a
    /// background thread and write their result here; the guest polls via `do-poll` from `on_tick`.
    jobs: Arc<Mutex<HashMap<u64, Job>>>,
    next: Arc<Mutex<u64>>,
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
        // Async mutation path: `do` fires a mutating op on a background thread (git commits block
        // ~200-500ms; running them inline freezes the guest's whole pane), `do-poll` reads its state.
        match op {
            "do" => return self.start_mutation(input),
            "do-poll" => return self.poll_mutation(input),
            _ => {}
        }
        // These ops don't fit the generic "subcommand + whitespace args" shape. note-set replaces the
        // whole note blob via dstask's editor hook; today reports the host's local date (the sandbox
        // has no clock). Handle them first; generic CLI path for the rest.
        match op {
            "note-set" => return note_set(&self.bin, input),
            "today" => return self.today(),
            _ => {}
        }
        // the dstask subcommand + its args. `list` is the bare CLI (JSON out); `list-resolved` reads
        // the resolved report; the mutating ops map to subcommands with the input as whitespace args.
        // The mutating branch is retained for callers that still invoke ops synchronously (and for the
        // `do` thread, which routes back through `run_mutation`); the read ops stay synchronous.
        match op {
            "list" => self.run(&[]),
            "list-resolved" => self.run(&["show-resolved".to_string()]),
            "add" | "modify" | "done" | "start" | "stop" | "note" => {
                run_mutation(&self.bin, op, input)
            }
            other => Err(warden_core::no_such_op(DSTASK, other)),
        }
    }
    fn revoke(&self) {
        // background mutations finish on their own and write into a table we drop; clear it so a
        // revoked cap's poll returns "no such job" rather than a stale result.
        self.jobs.lock().unwrap().clear();
    }
}

impl DsTaskCap {
    /// Start a mutating op on a background thread. `input` = `<op>\n<args>` — the first line is the
    /// mutating subcommand (add/modify/done/start/stop/note/note-set), the rest is that op's own
    /// input verbatim (whitespace args, or for note/note-set the note text). Returns a job id.
    fn start_mutation(&self, input: &[u8]) -> Result<Vec<u8>> {
        let s = std::str::from_utf8(input)
            .map_err(|e| WardenError::Cap(format!("dstask do utf8: {e}")))?;
        let (op, rest) = s.split_once('\n').unwrap_or((s, ""));
        let op = op.trim().to_string();
        if !matches!(
            op.as_str(),
            "add" | "modify" | "done" | "start" | "stop" | "note" | "note-set"
        ) {
            return Err(WardenError::Cap(format!(
                "dstask do: not a mutating op {op:?}"
            )));
        }
        let rest = rest.as_bytes().to_vec();
        let id = {
            let mut n = self.next.lock().unwrap();
            *n += 1;
            *n
        };
        self.jobs.lock().unwrap().insert(id, Job::Pending);
        let jobs = self.jobs.clone();
        let bin = self.bin.clone();
        // run the mutation (and its git commit) off the caller's thread; record the outcome.
        std::thread::spawn(move || {
            let result = if op == "note-set" {
                note_set(&bin, &rest).map(|_| ())
            } else {
                run_mutation(&bin, &op, &rest).map(|_| ())
            };
            let mut j = jobs.lock().unwrap();
            j.insert(
                id,
                match result {
                    Ok(()) => Job::Done,
                    Err(e) => Job::Failed(e.to_string()),
                },
            );
        });
        Ok(id.to_string().into_bytes())
    }

    /// Poll a `do` job. `P` = still running, `D` = done, `E\n<error>` = failed / unknown id.
    fn poll_mutation(&self, input: &[u8]) -> Result<Vec<u8>> {
        let id: u64 = std::str::from_utf8(input)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .ok_or_else(|| WardenError::Cap(format!("dstask do-poll: bad id {input:?}")))?;
        let jobs = self.jobs.lock().unwrap();
        let out = match jobs.get(&id) {
            None => "E\nno such job".to_string(),
            Some(Job::Pending) => "P".to_string(),
            Some(Job::Done) => "D".to_string(),
            Some(Job::Failed(e)) => format!("E\n{e}"),
        };
        Ok(out.into_bytes())
    }

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
}

/// Run a mutating dstask subcommand (`add`/`modify`/`done`/`start`/`stop`/`note`) with `input` as
/// whitespace args. Free function (no `&self`) so the `do` background thread can call it. Returns the
/// CLI's stdout on success, or a `Cap` error carrying stderr.
fn run_mutation(bin: &str, op: &str, input: &[u8]) -> Result<Vec<u8>> {
    let mut args = vec![op.to_string()];
    let s = std::str::from_utf8(input)
        .map_err(|e| WardenError::Cap(format!("dstask {op} utf8: {e}")))?;
    args.extend(s.split_whitespace().map(str::to_string));
    let out = Command::new(bin)
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

/// Replace the whole note blob for a task. `input` = `<id>\n<markdown…>` (first line is the id,
/// the rest is the new note verbatim). dstask has no non-interactive "set note", but `dstask note
/// <id>` dumps the note to a temp file, exec's `$EDITOR <file>`, then reads it back. dstask exec's
/// `$EDITOR` directly as argv (not via a shell), so a multi-word command like `cp src` won't work;
/// instead we drop a one-line editor script that copies our scratch content over whatever file
/// dstask hands it as `$1` — a full replace with no tty. `DSTASK_FAKE_PTY=1` is required: without
/// a tty dstask skips the editor step entirely. Best-effort cleanup of both temp files. Free
/// function (no `&self`) so the `do` background thread can call it.
fn note_set(bin: &str, input: &[u8]) -> Result<Vec<u8>> {
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
        Command::new(bin)
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

/// Single-quote a string for a POSIX shell, escaping any embedded single quotes. Used for the scratch
/// path baked into the editor script. Enough for a temp-file path we control.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

impl DsTaskCap {
    /// Construct a cap bound to a specific binary. Used by tests; production goes through the broker.
    #[cfg(test)]
    pub fn with_bin(bin: impl Into<String>) -> Self {
        DsTaskCap {
            bin: bin.into(),
            jobs: Arc::new(Mutex::new(HashMap::new())),
            next: Arc::new(Mutex::new(0)),
        }
    }
}

/// Grants the `dstask` capability. `req.arg` optionally overrides the binary (empty → resolve
/// `dstask` on the host).
pub struct DsTaskBroker;

#[async_trait]
impl Broker for DsTaskBroker {
    fn handles(&self, req: &CapRequest) -> bool {
        req.kind == DSTASK
    }
    async fn grant(&self, req: &CapRequest) -> Result<Box<dyn Capability>> {
        let bin = if req.arg.trim().is_empty() {
            resolve_dstask()
        } else {
            req.arg.clone()
        };
        Ok(Box::new(DsTaskCap {
            bin,
            jobs: Arc::new(Mutex::new(HashMap::new())),
            next: Arc::new(Mutex::new(0)),
        }))
    }
}

/// Find the `dstask` binary as an ABSOLUTE path. kedi may be launched from a desktop/systemd context
/// whose `PATH` lacks the user's package dirs (e.g. linuxbrew), so `Command::new("dstask")` fails with
/// ENOENT. We search `$PATH` plus common install locations and return the first hit; if none, fall
/// back to the bare name so PATH resolution still gets a chance (and the error stays legible).
fn resolve_dstask() -> String {
    let mut dirs: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(path) = std::env::var("PATH") {
        dirs.extend(std::env::split_paths(&path));
    }
    // common spots not always on a login-less PATH
    for extra in [
        "/home/linuxbrew/.linuxbrew/bin",
        "/opt/homebrew/bin",
        "/usr/local/bin",
    ] {
        dirs.push(std::path::PathBuf::from(extra));
    }
    if let Some(home) = std::env::var_os("HOME") {
        for sub in [".local/bin", "go/bin", ".linuxbrew/bin"] {
            dirs.push(std::path::Path::new(&home).join(sub));
        }
    }
    for dir in dirs {
        let cand = dir.join("dstask");
        if cand.is_file() {
            return cand.to_string_lossy().into_owned();
        }
    }
    "dstask".to_string() // last resort — let the OS try PATH, and surface a clear ENOENT if absent
}

#[cfg(test)]
mod tests {
    use super::*;

    // Both tests set the process-global DSTASK_GIT_REPO; serialize them so parallel test threads
    // don't clobber each other's env / store.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// When dstask is installed, resolve it to an absolute existing path (not the bare fallback) — so
    /// kedi works even when launched with a PATH that lacks the user's package dirs.
    #[test]
    fn resolve_dstask_finds_an_absolute_path() {
        if std::process::Command::new("dstask")
            .arg("version")
            .output()
            .is_err()
        {
            eprintln!("skip: dstask not installed");
            return;
        }
        let bin = resolve_dstask();
        assert_ne!(
            bin, "dstask",
            "should resolve to an absolute path, not the bare fallback"
        );
        assert!(
            std::path::Path::new(&bin).is_file(),
            "resolved path is not a file: {bin}"
        );
    }

    /// note-set must REPLACE the whole note blob (not append), via the editor-script + fake-pty trick.
    /// Skips gracefully if `dstask` isn't installed. Runs against a throwaway store so it can't touch
    /// the user's tasks; sets DSTASK_GIT_REPO for the child dstask processes.
    #[tokio::test]
    async fn note_set_replaces_the_whole_blob() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if std::process::Command::new("dstask")
            .arg("version")
            .output()
            .is_err()
        {
            eprintln!("skip: dstask not installed");
            return;
        }
        let repo = std::env::temp_dir().join(format!("kedi-dstask-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&repo);
        std::fs::create_dir_all(&repo).unwrap();
        assert!(
            std::process::Command::new("git")
                .args(["init", "-q"])
                .current_dir(&repo)
                .status()
                .unwrap()
                .success()
        );
        // SAFETY: single-threaded test binary section; the child dstask processes read this env.
        unsafe { std::env::set_var("DSTASK_GIT_REPO", &repo) };

        let cap = DsTaskCap::with_bin("dstask");
        cap.perform("add", b"note editor probe").await.unwrap();

        // replace the (empty) note on task 1 with a multi-line blob, twice — the second must REPLACE,
        // not stack on the first (the whole point vs. the append-only `note` op).
        cap.perform("note-set", b"1\nfirst version\nline two")
            .await
            .unwrap();
        cap.perform("note-set", b"1\nSECOND VERSION ONLY")
            .await
            .unwrap();

        let json = cap.perform("list", b"").await.unwrap();
        let s = String::from_utf8_lossy(&json);
        assert!(
            s.contains("SECOND VERSION ONLY"),
            "note-set didn't land: {s}"
        );
        assert!(
            !s.contains("first version"),
            "note-set appended instead of replacing: {s}"
        );

        let _ = std::fs::remove_dir_all(&repo);
    }

    /// `do` runs a mutating op off-thread and `do-poll` reports its state. Proves the async action
    /// path deck relies on to stay responsive: add a task via `do`, poll to `D`, then confirm the
    /// task actually landed via a synchronous `list`. Also checks a failing op surfaces as `E`.
    #[tokio::test]
    async fn do_runs_mutation_off_thread_and_do_poll_reports_done() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if std::process::Command::new("dstask")
            .arg("version")
            .output()
            .is_err()
        {
            eprintln!("skip: dstask not installed");
            return;
        }
        let repo = std::env::temp_dir().join(format!("kedi-dstask-do-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&repo);
        std::fs::create_dir_all(&repo).unwrap();
        assert!(
            std::process::Command::new("git")
                .args(["init", "-q"])
                .current_dir(&repo)
                .status()
                .unwrap()
                .success()
        );
        // SAFETY: single-threaded test binary section; child dstask processes read this env.
        unsafe { std::env::set_var("DSTASK_GIT_REPO", &repo) };

        let cap = DsTaskCap::with_bin("dstask");

        // fire an async add; poll until Done.
        let id =
            String::from_utf8(cap.perform("do", b"add\nasync probe task").await.unwrap()).unwrap();
        let mut done = false;
        for _ in 0..200 {
            let s =
                String::from_utf8(cap.perform("do-poll", id.as_bytes()).await.unwrap()).unwrap();
            if s == "D" {
                done = true;
                break;
            }
            assert!(s == "P", "unexpected do-poll state: {s:?}");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(done, "do job never completed");

        let json = String::from_utf8(cap.perform("list", b"").await.unwrap()).unwrap();
        assert!(
            json.contains("async probe task"),
            "async add didn't land: {json}"
        );

        // a mutation on a nonexistent id fails → surfaces as `E\n…`, not a panic.
        let bad = String::from_utf8(cap.perform("do", b"done\n99999").await.unwrap()).unwrap();
        let mut err = String::new();
        for _ in 0..200 {
            let s =
                String::from_utf8(cap.perform("do-poll", bad.as_bytes()).await.unwrap()).unwrap();
            if let Some(rest) = s.strip_prefix("E\n") {
                err = rest.to_string();
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(!err.is_empty(), "failing op should report an error");

        let _ = std::fs::remove_dir_all(&repo);
    }

    /// `do` rejects a non-mutating op name up front (before spawning a thread).
    #[tokio::test]
    async fn do_rejects_non_mutating_op() {
        let cap = DsTaskCap::with_bin("dstask");
        let err = cap.perform("do", b"list\n").await.unwrap_err();
        assert!(
            matches!(err, WardenError::Cap(ref m) if m.contains("not a mutating op")),
            "expected a not-a-mutating-op error, got {err:?}"
        );
    }

    /// do-poll on an unknown id → error, not a panic.
    #[tokio::test]
    async fn do_poll_unknown_id() {
        let cap = DsTaskCap::with_bin("dstask");
        let s = String::from_utf8(cap.perform("do-poll", b"999").await.unwrap()).unwrap();
        assert_eq!(s, "E\nno such job");
    }

    /// list-resolved returns resolved tasks (with timestamps), and `today` returns a YYYY-MM-DD the
    /// DONE column filters on. Proves the two ops the DONE-column fix depends on against real dstask.
    #[tokio::test]
    async fn list_resolved_and_today() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if std::process::Command::new("dstask")
            .arg("version")
            .output()
            .is_err()
        {
            eprintln!("skip: dstask not installed");
            return;
        }
        let repo = std::env::temp_dir().join(format!("kedi-dstask-res-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&repo);
        std::fs::create_dir_all(&repo).unwrap();
        assert!(
            std::process::Command::new("git")
                .args(["init", "-q"])
                .current_dir(&repo)
                .status()
                .unwrap()
                .success()
        );
        // SAFETY: single-threaded test binary section; child dstask processes read this env.
        unsafe { std::env::set_var("DSTASK_GIT_REPO", &repo) };

        let cap = DsTaskCap::with_bin("dstask");
        cap.perform("add", b"resolve me").await.unwrap();
        cap.perform("done", b"1").await.unwrap();

        let today = String::from_utf8(cap.perform("today", b"").await.unwrap()).unwrap();
        assert_eq!(today.len(), 10, "today should be YYYY-MM-DD, got {today:?}");
        assert_eq!(
            today.matches('-').count(),
            2,
            "today format wrong: {today:?}"
        );

        let resolved = cap.perform("list-resolved", b"").await.unwrap();
        let s = String::from_utf8_lossy(&resolved);
        assert!(
            s.contains("resolve me"),
            "list-resolved missing the resolved task: {s}"
        );
        // the resolved timestamp should start with today (we just resolved it). dstask pretty-prints,
        // so match the timestamp value rather than an exact key/colon spacing.
        assert!(
            s.contains(&format!("\"{today}")),
            "resolved not stamped today ({today}): {s}"
        );

        let _ = std::fs::remove_dir_all(&repo);
    }
}
