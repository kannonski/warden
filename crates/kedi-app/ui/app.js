// kedi-app frontend — xterm.js pane over Tauri IPC + a live plugin launcher. Hot-swappable: edit on
// disk and the window reloads. Sessions run in the in-process warden; output streams over a Channel.
const { invoke, Channel } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const term = new Terminal({
  fontSize: 14,
  cursorBlink: true,
  fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
  theme: { background: '#1e1e2e', foreground: '#cdd6f4', cursor: '#cba6f7' },
});
const fit = new FitAddon.FitAddon();
term.loadAddon(fit);
term.open(document.getElementById('term'));
fit.fit();

// The active pane id. Switching pane (shell ↔ plugin) closes the old one and bumps the id.
let paneId = 1;

function openPane(app) {
  const onOutput = new Channel();
  onOutput.onmessage = (bytes) => term.write(new Uint8Array(bytes));
  term.reset();
  invoke('open_pane', { paneId, onOutput, app: app || null })
    .then(() => invoke('pane_resize', { paneId, cols: term.cols, rows: term.rows }))
    .catch((e) => term.write(`\r\n\x1b[1;31m[kedi] open_pane failed: ${e}\x1b[0m\r\n`));
}

function switchPane(app) {
  invoke('pane_close', { paneId }).catch(() => {});
  paneId += 1;
  openPane(app);
  term.focus();
}

// Input + resize → the active pane (handlers read `paneId` live, so they follow pane switches).
term.onData((data) => invoke('pane_input', { paneId, data }));
term.onResize(({ cols, rows }) => invoke('pane_resize', { paneId, cols, rows }));
window.addEventListener('resize', () => fit.fit());

// Plugin launcher bar — a shell button plus one button per installed WASM plugin. Refreshes live when
// the plugins dir changes (drop a .wasm / edit plugins.toml → `plugins-changed`).
async function refreshBar() {
  const bar = document.getElementById('bar');
  bar.replaceChildren();
  const label = document.createElement('span');
  label.className = 'lbl';
  label.textContent = 'kedi';
  bar.appendChild(label);

  const shell = document.createElement('button');
  shell.textContent = '🖥 shell';
  shell.onclick = () => switchPane(null);
  bar.appendChild(shell);

  try {
    const plugins = JSON.parse(await invoke('plugins_json'));
    for (const p of plugins) {
      const b = document.createElement('button');
      b.textContent = `${p.icon || '▤'} ${p.name}`;
      b.onclick = () => switchPane(p.name);
      bar.appendChild(b);
    }
  } catch (_) { /* no plugins / bad registry → just the shell button */ }
}

// Boot: shell pane + the plugin bar, then live-refresh the bar on hot-reload.
openPane(null);
refreshBar();
listen('plugins-changed', refreshBar);
term.focus();
