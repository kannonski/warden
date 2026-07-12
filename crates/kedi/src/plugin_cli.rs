//! `kedi plugin …` — the plugin manager.
//!
//! A kedi plugin is a `kedi:app` `.wasm` in the plugin dir plus a `[[plugin]]` block in that dir's
//! `plugins.toml` (name · wasm file · icon · the capability kinds it may reach). kedi reads the
//! registry live, so a change here takes effect on the next pane with no restart. This module is the
//! ONE owner of registry edits — install/remove edit `plugins.toml` structurally (comment-preserving,
//! via `toml_edit`) rather than the fragile grep/append the deck justfile used to do.
//!
//! Metadata on `install` comes from flags, defaulting to a sidecar manifest (`<file>.kedi.toml` next
//! to the `.wasm`) if present. Capabilities are NEVER granted implicitly: `install` prints exactly
//! what a plugin will be allowed to reach, and you pass `--caps` (or accept the manifest's, shown).
//!
//! CLI today; the same functions back a future in-browser manager pane.

use std::path::{Path, PathBuf};

use crate::plugin_dir;

type R<T> = Result<T, String>;

/// Entry point: dispatch `kedi plugin <subcommand> …`. Resolves the plugin dir once (from
/// $KEDI_PLUGIN_DIR / the default) and passes it down — the inner functions take the dir explicitly,
/// so they never touch global state (testable in isolation, and ready for a browser pane to target a
/// dir directly).
pub fn run(args: &[String]) -> R<()> {
    let dir = plugin_dir();
    match args.first().map(String::as_str) {
        Some("list") | None => list(&dir),
        Some("info") => info(
            &dir,
            args.get(1)
                .ok_or("info <name>: a plugin name is required")?,
        ),
        Some("remove") | Some("rm") => {
            let name = args
                .get(1)
                .filter(|a| !a.starts_with("--"))
                .ok_or("remove <name>: a plugin name is required")?;
            let purge = args.iter().any(|a| a == "--purge");
            remove(&dir, name, purge)
        }
        Some("install") | Some("add") => install(&dir, &args[1..]),
        Some("help") | Some("-h") | Some("--help") => {
            print!("{USAGE}");
            Ok(())
        }
        Some(other) => Err(format!("unknown subcommand `{other}`\n\n{USAGE}")),
    }
}

const USAGE: &str = "\
kedi plugin — manage kedi:app plugins (the plugin dir + plugins.toml)

  kedi plugin list                     list installed plugins (✓ = its .wasm is present)
  kedi plugin info <name>              show one plugin's file, icon, and granted capabilities
  kedi plugin install <file.wasm>      install a plugin; flags below (or a <file>.kedi.toml sidecar)
        [--name N] [--icon G] [--caps a,b,c] [--force]
  kedi plugin remove <name>            remove a plugin (its registry block; --purge also deletes .wasm)
        [--purge]

The plugin dir is $KEDI_PLUGIN_DIR, else ~/.config/kedi/plugins.
Capabilities are the plugin's ONLY doors to the world — `install` shows them before writing.
";

// ── read side (mirrors lib.rs's registry reader, but returns richer rows for the manager) ─────────

struct Row {
    name: String,
    wasm: String,
    icon: String,
    caps: Vec<String>,
    present: bool, // the .wasm file actually exists in the dir
}

fn registry_path(dir: &Path) -> PathBuf {
    dir.join("plugins.toml")
}

fn read_rows(dir: &Path) -> Vec<Row> {
    #[derive(serde::Deserialize)]
    struct Entry {
        name: String,
        #[serde(default)]
        wasm: String,
        #[serde(default)]
        icon: String,
        #[serde(default)]
        caps: Vec<String>,
    }
    #[derive(serde::Deserialize, Default)]
    struct Reg {
        #[serde(default, rename = "plugin")]
        plugin: Vec<Entry>,
    }
    let text = std::fs::read_to_string(registry_path(dir)).unwrap_or_default();
    let reg: Reg = toml::from_str(&text).unwrap_or_default();
    reg.plugin
        .into_iter()
        .map(|e| {
            let wasm = if e.wasm.trim().is_empty() {
                format!("{}.wasm", e.name)
            } else {
                e.wasm
            };
            let present = dir.join(&wasm).is_file();
            Row {
                name: e.name,
                wasm,
                icon: e.icon,
                caps: e.caps,
                present,
            }
        })
        .collect()
}

// ── subcommands ───────────────────────────────────────────────────────────────────────────────

fn list(dir: &Path) -> R<()> {
    let rows = read_rows(dir);
    if rows.is_empty() {
        println!("no plugins installed (dir: {})", dir.display());
        println!("install one:  kedi plugin install ./my-plugin.wasm --caps dstask");
        return Ok(());
    }
    println!("plugins in {}:", dir.display());
    for r in &rows {
        let mark = if r.present {
            "✓"
        } else {
            "✗ missing .wasm"
        };
        let icon = if r.icon.is_empty() { " " } else { &r.icon };
        let caps = if r.caps.is_empty() {
            "no capabilities".to_string()
        } else {
            r.caps.join(", ")
        };
        println!("  {mark}  {icon} {:<14} {caps}", r.name);
    }
    Ok(())
}

fn info(dir: &Path, name: &str) -> R<()> {
    let rows = read_rows(dir);
    let r = rows
        .iter()
        .find(|r| r.name == name)
        .ok_or_else(|| format!("no plugin `{name}` (see: kedi plugin list)"))?;
    println!("name   {}", r.name);
    println!(
        "icon   {}",
        if r.icon.is_empty() { "(none)" } else { &r.icon }
    );
    println!(
        "wasm   {}  {}",
        r.wasm,
        if r.present { "(present)" } else { "(MISSING)" }
    );
    println!(
        "caps   {}",
        if r.caps.is_empty() {
            "(none — reaches nothing)".to_string()
        } else {
            r.caps.join(", ")
        }
    );
    println!("path   {}", dir.join(&r.wasm).display());
    Ok(())
}

/// Flags parsed from an `install` invocation. Missing values fall back to a sidecar manifest.
#[derive(Default)]
struct InstallOpts {
    src: Option<PathBuf>,
    name: Option<String>,
    icon: Option<String>,
    caps: Option<Vec<String>>,
    force: bool,
}

fn parse_install(args: &[String]) -> R<InstallOpts> {
    let mut o = InstallOpts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--name" => {
                o.name = Some(next(args, &mut i, "--name")?);
            }
            "--icon" => {
                o.icon = Some(next(args, &mut i, "--icon")?);
            }
            "--caps" => {
                let v = next(args, &mut i, "--caps")?;
                o.caps = Some(
                    v.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect(),
                );
            }
            "--force" => o.force = true,
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            path => {
                if o.src.is_some() {
                    return Err(format!("unexpected extra argument `{path}`"));
                }
                o.src = Some(PathBuf::from(path));
            }
        }
        i += 1;
    }
    Ok(o)
}

fn next(args: &[String], i: &mut usize, flag: &str) -> R<String> {
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| format!("{flag} needs a value"))
}

/// A sidecar manifest `<file>.kedi.toml` next to the .wasm: `name = …`, `icon = …`, `caps = [ … ]`.
/// Optional — a plugin author ships it so `install` needs no flags. Flags always override it.
fn read_sidecar(src: &Path) -> (Option<String>, Option<String>, Option<Vec<String>>) {
    let sidecar = src.with_extension("kedi.toml");
    let Ok(text) = std::fs::read_to_string(&sidecar) else {
        return (None, None, None);
    };
    #[derive(serde::Deserialize, Default)]
    struct M {
        name: Option<String>,
        icon: Option<String>,
        caps: Option<Vec<String>>,
    }
    let m: M = toml::from_str(&text).unwrap_or_default();
    (m.name, m.icon, m.caps)
}

fn install(dir: &Path, args: &[String]) -> R<()> {
    let opts = parse_install(args)?;
    let src = opts
        .src
        .ok_or("install <file.wasm>: a source .wasm path is required")?;
    if !src.is_file() {
        return Err(format!("no such file: {}", src.display()));
    }

    // resolve metadata: flags win, else the sidecar manifest, else derive from the filename.
    let (sc_name, sc_icon, sc_caps) = read_sidecar(&src);
    let name = opts
        .name
        .or(sc_name)
        .or_else(|| {
            src.file_stem()
                .map(|s| s.to_string_lossy().replace(['.', ' '], "-"))
        })
        .ok_or("could not determine a plugin name — pass --name")?;
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(format!(
            "invalid plugin name `{name}` (use [a-z0-9_-]); pass --name"
        ));
    }
    let icon = opts.icon.or(sc_icon).unwrap_or_default();
    let caps = opts.caps.or(sc_caps).unwrap_or_default();

    let rows = read_rows(dir);
    let exists = rows.iter().any(|r| r.name == name);
    if exists && !opts.force {
        return Err(format!(
            "plugin `{name}` already installed — use --force to overwrite it"
        ));
    }

    // show what this grants BEFORE touching anything (caps are the plugin's only reach).
    let wasm_file = format!("{name}.wasm");
    println!("install `{name}`  {icon}");
    println!("  from   {}", src.display());
    println!(
        "  grants {}",
        if caps.is_empty() {
            "no capabilities (reaches nothing)".to_string()
        } else {
            caps.join(", ")
        }
    );

    // copy the .wasm into the plugin dir under a canonical <name>.wasm, then register it.
    std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    let dest = dir.join(&wasm_file);
    std::fs::copy(&src, &dest).map_err(|e| format!("copy → {}: {e}", dest.display()))?;

    upsert_registry(dir, &name, &wasm_file, &icon, &caps)?;
    println!("installed → {}", dest.display());
    println!("open it from kedi's launcher (apps ▸ {name}) — no restart needed.");
    Ok(())
}

fn remove(dir: &Path, name: &str, purge: bool) -> R<()> {
    let rows = read_rows(dir);
    let row = rows
        .iter()
        .find(|r| r.name == name)
        .ok_or_else(|| format!("no plugin `{name}` to remove (see: kedi plugin list)"))?;

    let removed = delete_from_registry(dir, name)?;
    if !removed {
        return Err(format!("plugin `{name}` was not in plugins.toml"));
    }
    if purge {
        let f = dir.join(&row.wasm);
        match std::fs::remove_file(&f) {
            Ok(()) => println!("purged {}", f.display()),
            Err(e) => eprintln!("note: could not delete {}: {e}", f.display()),
        }
    }
    println!(
        "removed `{name}` from the registry{}",
        if purge { " and disk" } else { "" }
    );
    if !purge {
        println!("its .wasm is still on disk — `--purge` to delete it too");
    }
    Ok(())
}

// ── registry writes (comment-preserving, via toml_edit) ───────────────────────────────────────

/// Add or replace the `[[plugin]]` entry for `name`, preserving the file's comments + layout.
fn upsert_registry(dir: &Path, name: &str, wasm: &str, icon: &str, caps: &[String]) -> R<()> {
    use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Table, value};

    let path = registry_path(dir);
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let mut doc: DocumentMut = existing
        .parse()
        .map_err(|e| format!("{} is not valid TOML: {e}", path.display()))?;

    // ensure a `plugin` array-of-tables exists
    if !doc.contains_key("plugin") {
        doc["plugin"] = Item::ArrayOfTables(ArrayOfTables::new());
    }
    let arr = doc["plugin"]
        .as_array_of_tables_mut()
        .ok_or("plugins.toml: `plugin` is not an array of tables")?;

    // build the new table
    let mut t = Table::new();
    t["name"] = value(name);
    if !icon.is_empty() {
        t["icon"] = value(icon);
    }
    // only write `wasm` when it isn't the default <name>.wasm (keeps the file tidy)
    if wasm != format!("{name}.wasm") {
        t["wasm"] = value(wasm);
    }
    let mut cap_arr = Array::new();
    for c in caps {
        cap_arr.push(c.as_str());
    }
    t["caps"] = value(cap_arr);

    // replace an existing entry in place, else append
    if let Some(existing) = arr
        .iter_mut()
        .find(|e| e.get("name").and_then(|v| v.as_str()) == Some(name))
    {
        *existing = t;
    } else {
        arr.push(t);
    }
    write_registry(&path, &doc)
}

/// Serialize `doc` to the registry path, guaranteeing the explanatory header leads the file. We
/// prepend it at write time (rather than as toml_edit decor) because a document-level prefix is
/// unreliable across edits — it can be dropped when the last table is removed, and the serializer may
/// re-order pure-comment seed text after the first table. This is version-proof and always tidy.
fn write_registry(path: &Path, doc: &toml_edit::DocumentMut) -> R<()> {
    let body = doc.to_string();
    let out = if body.trim_start().starts_with("# kedi plugin registry") {
        body
    } else {
        format!("{DEFAULT_HEADER}{}", body)
    };
    std::fs::write(path, out).map_err(|e| format!("write {}: {e}", path.display()))
}

/// Delete the `[[plugin]]` entry for `name`. Returns whether one was removed. Comment-preserving.
fn delete_from_registry(dir: &Path, name: &str) -> R<bool> {
    use toml_edit::DocumentMut;
    let path = registry_path(dir);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(false);
    };
    let mut doc: DocumentMut = text
        .parse()
        .map_err(|e| format!("{} is not valid TOML: {e}", path.display()))?;
    let Some(arr) = doc
        .get_mut("plugin")
        .and_then(|i| i.as_array_of_tables_mut())
    else {
        return Ok(false);
    };
    let before = arr.len();
    arr.retain(|e| e.get("name").and_then(|v| v.as_str()) != Some(name));
    let removed = arr.len() < before;
    if removed {
        write_registry(&path, &doc)?;
    }
    Ok(removed)
}

const DEFAULT_HEADER: &str = "\
# kedi plugin registry — managed by `kedi plugin` (add/remove edits this file in place).
# name = launcher label · wasm = component file (default <name>.wasm) · icon = launcher glyph
# caps = the capability kinds kedi grants the plugin (its only doors to the world).
";

#[cfg(test)]
mod tests {
    use super::*;

    // A throwaway plugin dir per test, unique by name — no shared global state (the manager functions
    // take the dir explicitly), so these run in parallel with everything else, no env, no lock.
    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kedi-pm-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    // install → read → remove: the registry round-trips, the .wasm lands under <name>.wasm, and the
    // header comment survives both the install and the later removal.
    #[test]
    fn install_list_remove_roundtrip() {
        let dir = scratch("rt");
        let src = dir.join("src-thing.wasm");
        std::fs::write(&src, b"\0asm fake").unwrap();

        install(
            &dir,
            &[
                src.to_string_lossy().into_owned(),
                "--name".into(),
                "thing".into(),
                "--icon".into(),
                "▤".into(),
                "--caps".into(),
                "dstask,ai".into(),
            ],
        )
        .unwrap();

        let reg = std::fs::read_to_string(dir.join("plugins.toml")).unwrap();
        assert!(reg.contains("name = \"thing\""), "registered: {reg}");
        assert!(
            reg.contains("\"dstask\"") && reg.contains("\"ai\""),
            "caps written: {reg}"
        );
        assert!(
            dir.join("thing.wasm").is_file(),
            "wasm copied to canonical name"
        );
        assert!(
            reg.contains("# kedi plugin registry"),
            "header preserved: {reg}"
        );

        let rows = read_rows(&dir);
        let t = rows
            .iter()
            .find(|r| r.name == "thing")
            .expect("in registry");
        assert_eq!(t.caps, vec!["dstask", "ai"]);
        assert!(t.present);

        // remove drops the entry (keeps the .wasm) and the header survives even at zero plugins
        delete_from_registry(&dir, "thing").unwrap();
        let reg2 = std::fs::read_to_string(dir.join("plugins.toml")).unwrap();
        assert!(!reg2.contains("name = \"thing\""), "entry removed: {reg2}");
        assert!(
            reg2.contains("# kedi plugin registry"),
            "header still there after remove: {reg2}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // installing the same name twice without --force is refused (no silent overwrite).
    #[test]
    fn install_refuses_duplicate_without_force() {
        let dir = scratch("dup");
        let src = dir.join("p.wasm");
        std::fs::write(&src, b"x").unwrap();
        let a = [
            src.to_string_lossy().into_owned(),
            "--name".into(),
            "dup".into(),
        ];
        install(&dir, &a).unwrap();
        let err = install(&dir, &a).unwrap_err();
        assert!(
            err.contains("already installed"),
            "dup should be refused: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
