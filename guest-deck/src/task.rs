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
    pub fn resolved_today(&self) -> bool {
        // dstask stamps resolved as an RFC3339 date; "today" = same YYYY-MM-DD as now. We don't have
        // a clock in the sandbox, so treat any resolved task as DONE-column material and let the host
        // filter by recency later; for now "resolved and not the zero date" counts.
        self.status == "resolved" && !self.resolved.starts_with("0001")
    }
}

/// A board column: a title, an accent color index, and its cards.
pub struct Column {
    pub title: &'static str,
    pub accent: u8,
    pub cards: Vec<Task>,
}

/// Load all tasks via the dstask capability and bucket them into columns:
///   TODAY (+now) · NEXT (actionable pool, P3 hidden) · WAITING (+waiting) · DONE (resolved).
/// Returns the four columns. On a capability error, returns empty columns (the UI shows the error).
pub fn load() -> Result<Vec<Column>, String> {
    let json = host::invoke("dstask", "list", &[])?;
    let tasks: Vec<Task> = serde_json::from_slice(&json).map_err(|e| format!("parse dstask json: {e}"))?;

    let mut today = Vec::new();
    let mut next = Vec::new();
    let mut waiting = Vec::new();
    let mut done = Vec::new();
    for t in tasks {
        if t.status == "resolved" {
            if t.resolved_today() {
                done.push(t);
            }
            continue;
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
    Ok(vec![
        Column { title: "TODAY", accent: 212, cards: today },
        Column { title: "NEXT", accent: 117, cards: next },
        Column { title: "WAITING", accent: 214, cards: waiting },
        Column { title: "DONE", accent: 120, cards: done },
    ])
}
