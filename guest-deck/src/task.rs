//! Tasks + columns, read from dstask through the governed `dstask` capability.
//!
//! deck-in-WASM can't link dstask or touch the fs; `host::invoke("dstask", "list", …)` crosses the
//! warden chokepoint and returns the dstask JSON, which we deserialize here. Column bucketing (which
//! column a task lands in) is pure logic, ported straight from the Go deck.

use crate::kedi::app::host;
use serde::Deserialize;

/// A dstask task, as it appears in the CLI's JSON. Only the fields deck renders.
#[derive(Clone, Debug, Deserialize, Default)]
pub struct Task {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    #[allow(dead_code)] // uuid drives the planned "cursor follows a moved card" feature
    pub uuid: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub status: String, // "pending" | "active" | "paused" | "resolved" | …
    #[serde(default)]
    pub priority: String, // "P1" | "P2" | "P3"
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub project: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub resolved: String, // RFC3339; "0001-…" when unset
}

impl Task {
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }
    /// A short state marker for the card meta line (mirrors deck's `state()`).
    pub fn state(&self) -> &'static str {
        match self.status.as_str() {
            "active" => "▶",
            "paused" => "paused",
            _ => "",
        }
    }
    /// Was this resolved on `today` (a `YYYY-MM-DD` string the host supplies — the sandbox has no
    /// clock)? dstask stamps `resolved` as a local RFC3339 timestamp, so a date-prefix match is "today".
    pub fn resolved_today(&self, today: &str) -> bool {
        !today.is_empty() && self.resolved.starts_with(today)
    }
}

/// A board column: a title, an accent color index, and its cards.
pub struct Column {
    pub title: &'static str,
    pub accent: u8,
    pub cards: Vec<Task>,
}

/// Load tasks via the dstask capability and bucket them into columns:
///   TODAY (+now) · NEXT (actionable pool, P3 hidden) · WAITING (+waiting) · DONE (resolved today).
///
/// The DONE column is fed from a SEPARATE `list-resolved` op: the bare `list` returns only open tasks
/// (pending/paused), never resolved ones — so DONE has to come from `dstask show-resolved`, filtered
/// to today by a date the host supplies (`today` op — the sandbox has no clock). Without this, DONE
/// was always empty and resolved cards appeared to "come back" on reload.
/// On a capability error, returns empty columns (the UI shows the error).
pub fn load() -> Result<Vec<Column>, String> {
    let json = host::invoke("dstask", "list", &[])?;
    let open: Vec<Task> = serde_json::from_slice(&json).map_err(|e| format!("parse dstask json: {e}"))?;

    let mut today = Vec::new();
    let mut next = Vec::new();
    let mut waiting = Vec::new();
    for t in open {
        if t.status == "resolved" {
            continue; // open list shouldn't carry these, but be defensive
        }
        if t.has_tag("now") {
            today.push(t);
        } else if t.has_tag("waiting") {
            waiting.push(t);
        } else if t.priority != "P3" {
            // NEXT = the actionable pool; P3 is the hidden backlog (deck's `poolHidePriority`)
            next.push(t);
        }
    }

    // DONE: resolved tasks stamped today. `today`/`list-resolved` failing is non-fatal — better an
    // empty DONE than no board — so we fall back to empty rather than propagate the error.
    let today_date = host::invoke("dstask", "today", &[])
        .map(|b| String::from_utf8_lossy(&b).trim().to_string())
        .unwrap_or_default();
    let done = host::invoke("dstask", "list-resolved", &[])
        .ok()
        .and_then(|b| serde_json::from_slice::<Vec<Task>>(&b).ok())
        .map(|resolved| {
            resolved
                .into_iter()
                .filter(|t| t.resolved_today(&today_date))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Ok(vec![
        Column { title: "TODAY", accent: 212, cards: today },
        Column { title: "NEXT", accent: 117, cards: next },
        Column { title: "WAITING", accent: 214, cards: waiting },
        Column { title: "DONE", accent: 120, cards: done },
    ])
}
