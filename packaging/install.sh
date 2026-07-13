#!/usr/bin/env sh
# kedi installer — puts the binary on your PATH and registers a desktop icon that launches it into
# your browser. No root, no daemon: `kedi --open` self-detaches a loopback-only background server
# and opens the tab; quit it explicitly from the ⏻ button in the UI (or `curl -X POST
# http://localhost:8788/shutdown`).
#
#   ./packaging/install.sh            # install from a local ./kedi (or the release build)
#   KEDI_BIN=/path/to/kedi  ./packaging/install.sh
#
# Linux installs the .desktop entry + icon; macOS builds a double-clickable ~/Applications/kedi.app.
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
  # Rewrite Exec to the absolute installed path: GNOME (and most launchers) start .desktop entries
  # with a minimal PATH that omits ~/.local/bin, so a bare `Exec=kedi` would not resolve from the GUI.
  sed "s|^Exec=kedi |Exec=$bindir/kedi |" "$here/kedi.desktop" > "$appdir/kedi.desktop"
  chmod 0644 "$appdir/kedi.desktop"
  command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$appdir" 2>/dev/null || true
  command -v gtk-update-icon-cache   >/dev/null 2>&1 && gtk-update-icon-cache -f "$prefix/icons/hicolor" 2>/dev/null || true
  echo "kedi: installed desktop entry + icon — look for 'kedi' in your launcher."

# 3b. macOS app bundle: a double-clickable ~/Applications/kedi.app (Spotlight/Launchpad/Dock).
elif [ "$(uname -s)" = "Darwin" ]; then
  app="$HOME/Applications/kedi.app"
  ver=$(sed -n 's/^version = "\(.*\)"/\1/p' "$here/../Cargo.toml" | head -1)
  ver="${ver:-0.1.0}"
  rm -rf "$app"
  mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"

  # Self-contained: embed the binary so Finder launches work regardless of PATH. Info.plist can't
  # pass args, so CFBundleExecutable is a wrapper that runs the embedded binary with `--open`.
  install -m 0755 "$bin" "$app/Contents/MacOS/kedi-bin"
  cat > "$app/Contents/MacOS/kedi" <<'SH'
#!/bin/sh
# kedi.app launcher — opens the governed web terminal in your browser.
exec "$(dirname "$0")/kedi-bin" --open
SH
  chmod 0755 "$app/Contents/MacOS/kedi"

  # Icon: render the SVG to a multi-resolution .icns when the tools are present; skip gracefully
  # (generic app icon) otherwise — the app still launches.
  if command -v rsvg-convert >/dev/null 2>&1 && command -v iconutil >/dev/null 2>&1; then
    iconset=$(mktemp -d)/kedi.iconset
    mkdir -p "$iconset"
    for pair in 16:16x16 32:16x16@2x 32:32x32 64:32x32@2x 128:128x128 256:128x128@2x \
                256:256x256 512:256x256@2x 512:512x512 1024:512x512@2x; do
      px=${pair%%:*}; nm=${pair#*:}
      rsvg-convert -w "$px" -h "$px" "$here/kedi.svg" -o "$iconset/icon_$nm.png"
    done
    iconutil -c icns "$iconset" -o "$app/Contents/Resources/kedi.icns"
    rm -rf "$(dirname "$iconset")"
    icon_key='  <key>CFBundleIconFile</key><string>kedi</string>'
  else
    echo "kedi: note — rsvg-convert/iconutil not found; app installed without a custom icon." >&2
    icon_key=''
  fi

  cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>kedi</string>
  <key>CFBundleDisplayName</key><string>kedi</string>
  <key>CFBundleIdentifier</key><string>com.unblu.kedi</string>
  <key>CFBundleVersion</key><string>$ver</string>
  <key>CFBundleShortVersionString</key><string>$ver</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleExecutable</key><string>kedi</string>
$icon_key
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>LSUIElement</key><true/>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

  # Refresh LaunchServices so the icon/name show up immediately.
  lsr=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
  [ -x "$lsr" ] && "$lsr" -f "$app" 2>/dev/null || true
  echo "kedi: installed $app — find 'kedi' in Spotlight/Launchpad, or drag it to your Dock."

  # On-demand LaunchAgent (skip with KEDI_NO_AGENT=1). launchd holds the http port (8788) and starts
  # kedi only when something connects — so opening the installed PWA "launches" the server, and kedi's
  # 90s idle-exit stops it again. Nothing runs while unused. kedi picks up the socket via
  # launch_activate_socket("KediHTTP"); it still binds the WT/QUIC port (4433) itself.
  if [ "${KEDI_NO_AGENT:-0}" != "1" ]; then
    label="com.unblu.kedi"
    agentdir="$HOME/Library/LaunchAgents"
    plist="$agentdir/$label.plist"
    mkdir -p "$agentdir"
    # A launchd agent gets a minimal environment, but kedi spawns your $SHELL for each session. Bake in
    # the shell + PATH from the installing environment so sessions behave like a normal terminal.
    user_shell="${SHELL:-/bin/zsh}"
    user_path="${PATH:-/usr/bin:/bin:/usr/sbin:/sbin}"
    cat > "$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$label</string>
  <key>ProgramArguments</key>
  <array>
    <string>$bindir/kedi</string>
  </array>
  <key>Sockets</key>
  <dict>
    <key>KediHTTP</key>
    <array>
      <dict>
        <key>SockNodeName</key><string>127.0.0.1</string>
        <key>SockServiceName</key><string>8788</string>
        <key>SockType</key><string>stream</string>
        <key>SockFamily</key><string>IPv4</string>
      </dict>
      <dict>
        <key>SockNodeName</key><string>::1</string>
        <key>SockServiceName</key><string>8788</string>
        <key>SockType</key><string>stream</string>
        <key>SockFamily</key><string>IPv6</string>
      </dict>
    </array>
  </dict>
  <key>EnvironmentVariables</key>
  <dict>
    <key>SHELL</key><string>$user_shell</string>
    <key>PATH</key><string>$user_path</string>
    <key>HOME</key><string>$HOME</string>
  </dict>
  <key>ProcessType</key><string>Interactive</string>
</dict>
</plist>
PLIST
    # Reload idempotently: bootout an old instance (ignore "not loaded"), then bootstrap the new one.
    dom="gui/$(id -u)"
    launchctl bootout "$dom/$label" 2>/dev/null || true
    if launchctl bootstrap "$dom" "$plist" 2>/dev/null; then
      launchctl enable "$dom/$label" 2>/dev/null || true
      echo "kedi: on-demand service registered — opening kedi (icon or http://localhost:8788) starts it automatically."
    else
      echo "kedi: note — could not load the LaunchAgent; the app still works, just start it via the icon." >&2
    fi
    echo "kedi: (to remove the service:  launchctl bootout $dom/$label; rm \"$plist\")"
  fi
fi

echo "kedi: done. Launch from the icon, or run:  kedi --open"
