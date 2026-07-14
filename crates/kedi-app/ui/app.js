// kedi-app frontend — multi-pane governed terminal over Tauri IPC. Hot-swappable: edit on disk and the
// window reloads. Each pane is its own warden session (shell or WASM plugin), its own xterm + Channel.
const { invoke, Channel } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const THEME = { background: '#1e1e2e', foreground: '#cdd6f4', cursor: '#cba6f7' };

// base64 (from Rust) → bytes for term.write (pty output is binary, not always valid UTF-8).
function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function esc(s) {
  return String(s).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
}

// ── pane manager ──────────────────────────────────────────────────────────────────────────────
const panes = new Map(); // id → { el, term, fit, label }
let nextId = 1;
let activeId = null;

function makeTerm() {
  const term = new Terminal({
    fontSize: 14,
    cursorBlink: true,
    // Nerd Font first so prompt glyphs (powerlevel10k / starship icons) render instead of tofu.
    fontFamily: '"FiraCode Nerd Font Mono", "FiraCode Nerd Font", "MesloLGS NF", ui-monospace, Menlo, monospace',
    theme: THEME,
  });
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  return { term, fit };
}

function createPane(app, label) {
  const id = nextId++;
  const el = document.createElement('div');
  el.className = 'pane';
  document.getElementById('panes').appendChild(el);
  const { term, fit } = makeTerm();
  panes.set(id, { el, term, fit, label: label || 'shell' });

  activate(id); // show it before open() so xterm gets real dimensions
  term.open(el);
  fit.fit();

  const onOutput = new Channel();
  onOutput.onmessage = (b64) => term.write(b64ToBytes(b64));
  invoke('open_pane', { paneId: id, onOutput, app: app || null })
    .then(() => invoke('pane_resize', { paneId: id, cols: term.cols, rows: term.rows }))
    .catch((e) => term.write(`\r\n\x1b[1;31m[kedi] open_pane failed: ${e}\x1b[0m\r\n`));

  term.onData((data) => invoke('pane_input', { paneId: id, data }));
  term.onResize(({ cols, rows }) => invoke('pane_resize', { paneId: id, cols, rows }));
  renderTabs();
  return id;
}

function activate(id) {
  activeId = id;
  for (const [pid, p] of panes) p.el.classList.toggle('active', pid === id);
  const p = panes.get(id);
  if (p) {
    p.fit.fit();
    p.term.focus();
    invoke('pane_resize', { paneId: id, cols: p.term.cols, rows: p.term.rows }).catch(() => {});
  }
  renderTabs();
}

function closePane(id) {
  const p = panes.get(id);
  if (!p) return;
  invoke('pane_close', { paneId: id }).catch(() => {});
  p.term.dispose();
  p.el.remove();
  panes.delete(id);
  if (activeId === id) {
    const first = panes.keys().next();
    if (!first.done) activate(first.value);
    else createPane(null, 'shell'); // never leave zero panes
  } else {
    renderTabs();
  }
}

function renderTabs() {
  const tabs = document.getElementById('tabs');
  tabs.replaceChildren();
  for (const [id, p] of panes) {
    const tab = document.createElement('span');
    tab.className = 'tab' + (id === activeId ? ' active' : '');
    const name = document.createElement('span');
    name.textContent = p.label;
    name.onclick = () => activate(id);
    const x = document.createElement('span');
    x.className = 'x';
    x.textContent = '✕';
    x.onclick = (e) => { e.stopPropagation(); closePane(id); };
    tab.append(name, x);
    tabs.appendChild(tab);
  }
}

// ── plugin launcher ───────────────────────────────────────────────────────────────────────────
async function refreshPlugins() {
  const bar = document.getElementById('plugins');
  bar.replaceChildren();
  try {
    const plugins = JSON.parse(await invoke('plugins_json'));
    for (const pl of plugins) {
      const b = document.createElement('button');
      const face = `${pl.icon || '▤'} ${pl.name}`;
      b.textContent = face;
      b.title = `Launch plugin: ${pl.name}`;
      b.onclick = () => createPane(pl.name, face);
      bar.appendChild(b);
    }
  } catch (_) { /* no/invalid registry → no plugin buttons */ }
}

// ── recording toggle ──────────────────────────────────────────────────────────────────────────
async function initRec() {
  const btn = document.getElementById('rec-toggle');
  const on = await invoke('get_recording').catch(() => false);
  btn.classList.toggle('on', !!on);
  btn.onclick = async () => {
    const want = !btn.classList.contains('on');
    const now = await invoke('set_recording', { on: want }).catch(() => null);
    if (now !== null) btn.classList.toggle('on', !!now);
  };
}

// ── audit panel (sessions + verified record) ───────────────────────────────────────────────────
let auditTimer = null;
let recSince = 0;

function toggleAudit() {
  const el = document.getElementById('audit');
  const btn = document.getElementById('audit-toggle');
  const show = el.hidden;
  el.hidden = !show;
  btn.classList.toggle('on', show);
  const p = panes.get(activeId);
  if (p) setTimeout(() => p.fit.fit(), 0); // width changed → refit the terminal
  if (show) {
    pollAudit();
    auditTimer = setInterval(pollAudit, 1200);
  } else if (auditTimer) {
    clearInterval(auditTimer);
    auditTimer = null;
  }
}

async function pollAudit() {
  try {
    const sessions = JSON.parse(await invoke('sessions_json'));
    const box = document.getElementById('sessions');
    box.replaceChildren();
    if (!sessions.length) {
      const d = document.createElement('div');
      d.className = 'muted';
      d.textContent = 'no live sessions';
      box.appendChild(d);
    }
    for (const s of sessions) {
      const row = document.createElement('div');
      row.className = 'sess';
      const kill = document.createElement('button');
      kill.textContent = 'kill';
      kill.onclick = () => invoke('kill_session', { session: s.id, by: 'console' });
      const head = document.createElement('div');
      head.innerHTML = `<span class="id">#${s.id}</span> <span class="who">${esc(s.identity)}</span>`;
      const prev = document.createElement('div');
      prev.className = 'prev';
      prev.textContent = s.preview || s.title || '';
      row.append(kill, head, prev);
      box.appendChild(row);
    }
  } catch (_) { /* ignore poll error */ }

  try {
    const rec = JSON.parse(await invoke('record_json', { since: recSince }));
    if (rec && rec.ok && Array.isArray(rec.events)) {
      const box = document.getElementById('record');
      for (const ev of rec.events) {
        const kind = (ev && typeof ev === 'object') ? Object.keys(ev)[0] : String(ev);
        const r = document.createElement('div');
        r.className = 'rec-row';
        r.innerHTML = `<span class="k">${esc(kind)}</span>`;
        box.appendChild(r);
      }
      recSince = (rec.since || 0) + (rec.count || 0);
      while (box.childElementCount > 200) box.removeChild(box.firstChild);
    }
  } catch (_) { /* ignore poll error */ }
}

// ── boot ────────────────────────────────────────────────────────────────────────────────────────
createPane(null, 'shell');
document.getElementById('new-shell').onclick = () => createPane(null, 'shell');
document.getElementById('audit-toggle').onclick = toggleAudit;
refreshPlugins();
initRec();
listen('plugins-changed', refreshPlugins);
window.addEventListener('resize', () => {
  const p = panes.get(activeId);
  if (p) p.fit.fit();
});
