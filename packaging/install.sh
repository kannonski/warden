#!/usr/bin/env sh
# kedi installer — puts the binary on your PATH and registers a desktop icon that launches it into
# your browser. No root, no daemon: `kedi --open` self-detaches a loopback-only background server
# and opens the tab; quit it explicitly from the ⏻ button in the UI (or `curl -X POST
# http://localhost:8788/shutdown`).
#
#   ./packaging/install.sh            # install from a local ./kedi (or the release build)
#   KEDI_BIN=/path/to/kedi  ./packaging/install.sh
#
# Linux installs the .desktop entry + icon; macOS just installs the binary (use `kedi --open`).
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
prefix="${XDG_DATA_HOME:-$HOME/.local/share}"
bindir="$HOME/.local/bin"

# 1. locate the binary: $KEDI_BIN, then a sibling ./kedi, then the cargo release build.
bin="${KEDI_BIN:-}"
if [ -z "$bin" ]; then
  for c in "$here/kedi" "$here/../kedi" "$here/../target/release/kedi"; do
    if [ -x "$c" ]; then bin="$c"; break; fi
  done
fi
if [ -z "$bin" ] || [ ! -x "$bin" ]; then
  echo "kedi: no binary found. Build it (cargo build -p kedi --release) or set KEDI_BIN=..." >&2
  exit 1
fi

# 2. install the binary.
mkdir -p "$bindir"
install -m 0755 "$bin" "$bindir/kedi"
echo "kedi: installed $bindir/kedi"
case ":$PATH:" in
  *":$bindir:"*) ;;
  *) echo "kedi: note — $bindir is not on your PATH; add it to use 'kedi' directly." >&2 ;;
esac

# 3. Linux desktop integration (icon + launcher entry). Skipped elsewhere.
if [ "$(uname -s)" = "Linux" ]; then
  appdir="$prefix/applications"
  icondir="$prefix/icons/hicolor/scalable/apps"
  mkdir -p "$appdir" "$icondir"
  install -m 0644 "$here/kedi.svg" "$icondir/kedi.svg"
  install -m 0644 "$here/kedi.desktop" "$appdir/kedi.desktop"
  command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$appdir" 2>/dev/null || true
  command -v gtk-update-icon-cache   >/dev/null 2>&1 && gtk-update-icon-cache -f "$prefix/icons/hicolor" 2>/dev/null || true
  echo "kedi: installed desktop entry + icon — look for 'kedi' in your launcher."
fi

echo "kedi: done. Launch from the icon, or run:  kedi --open"
