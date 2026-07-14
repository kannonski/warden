fn main() {
    // include_dir!("ui") embeds at compile time but doesn't register the files with cargo, so ui/
    // edits wouldn't trigger a rebuild (→ a stale embedded default). Watch the dir explicitly.
    println!("cargo:rerun-if-changed=ui");
    tauri_build::build()
}
