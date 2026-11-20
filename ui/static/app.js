"use strict";

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const POOL_HASH = "#~keys";
const SETTINGS_HASH = "#~settings";
const IMPORT_HASH = "#~import";
const HOST_HASH = "#~host";
const GUIDE_HASH = "#~hermes-setup";
const VIEW_OF_HASH = { [POOL_HASH]: "pool", [SETTINGS_HASH]: "settings", [IMPORT_HASH]: "import", [HOST_HASH]: "host",
  [GUIDE_HASH]: "guide" };
const PAGES = { pool: "#pool", import: "#import", host: "#host", settings: "#settings", guide: "#guide" };   // view -> section
const state = {
  workspaces: [],
  view: VIEW_OF_HASH[location.hash] || "ws",
  selected: VIEW_OF_HASH[location.hash] ? null : decodeURIComponent(location.hash.slice(1)) || null,
  tab: "claude",
  filesPath: {},          // per-workspace current folder in the Files tab
  frameFor: {},           // tab -> workspace its sandbox iframe is showing
};

// ------------------------------------------------------------------ API

async function api(method, path, body) {
  const opts = { method, headers: { "X-Requested-With": "sbui" } };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(`/api/${path}`, opts);
  if (res.status === 401) { location.reload(); throw new Error("Signed out"); }
  const data = res.headers.get("content-type")?.includes("json") ? await res.json() : { error: await res.text() };
  if (!res.ok || data.ok === false) throw new Error(data.error || data.log || `HTTP ${res.status}`);
  return data;
}

const current = () => state.workspaces.find((w) => w.name === state.selected) || null;
const wsPath = (name, rest = "") => `workspaces/${encodeURIComponent(name)}${rest}`;

// ------------------------------------------------------------------ status

const CONTAINER_TONE = { running: "ok", restarting: "warn", created: "warn", paused: "warn", exited: "bad", dead: "bad" };
const CLAUDE_TONE = { running: "ok", exited: "warn" };
const GATEWAY_TONE = { running: "ok", failed: "bad" };
const AGENT_NAME = { claude: "Claude", hermes: "Hermes" };
const agentName = (w) => AGENT_NAME[w?.agent] || "Claude";

async function refresh() {
  try {
    state.workspaces = await api("GET", "workspaces");
  } catch (e) {
    return;
  }
  if (state.selected && !current()) state.selected = null;
  renderList();
  renderDetail();
}

function renderList() {
  const list = $("#ws-list");
  list.replaceChildren();
  if (!state.workspaces.length) {
    const p = document.createElement("p");
    p.className = "ws-empty";
    p.textContent = "No workspaces yet.";
    list.append(p);
    return;
  }
  for (const w of state.workspaces) {
    const b = document.createElement("button");
    b.className = "ws-item";
    b.type = "button";
    b.setAttribute("aria-current", String(state.view === "ws" && w.name === state.selected));
    b.innerHTML = `<span class="n"></span><span class="dots"><span class="dot" title="container"></span><span class="dot" title="Claude"></span></span><span class="sub"></span>`;
    $(".n", b).textContent = w.name;
    $(".sub", b).textContent = w.dir.replace(/^\/home\/[^/]+/, "~") + (w.kind === "microvm" ? " · microVM" : "")
      + (w.agent === "hermes" ? " · Hermes" : "");
    const [dc, dl] = $$(".dot", b);
    dc.classList.add(CONTAINER_TONE[w.container] || "none");
    dc.title = `${w.kind === "microvm" ? "VM" : "Container"}: ${w.container}`;
    dl.classList.add(CLAUDE_TONE[w.claude] || "none");
    dl.title = `${agentName(w)}: ${w.claude}`;
    b.addEventListener("click", () => select(w.name));
    list.append(b);
  }
}

function setPill(el, label, value, tone) {
  el.className = `pill ${tone || ""}`;
  el.textContent = `${label}: ${value}`;
}

function renderDetail() {
  const page = state.view in PAGES;
  for (const [view, sel] of Object.entries(PAGES)) {
    $(sel).hidden = state.view !== view;
    $(`${sel}-btn`).setAttribute("aria-current", String(state.view === view));
  }
  if (state.view !== "host") disconnectHost();
  const w = page ? null : current();
  $("#empty").hidden = !!w || page;
  $("#detail").hidden = !w;
  if (!w) { disconnectTerm(); return; }

  $("#d-name").textContent = w.name;
  $("#d-dir").textContent = w.dir;
  $$(".d-dir-inline").forEach((el) => (el.textContent = w.dir));
  const vm = w.kind === "microvm";
  const agent = agentName(w);
  $("#detail").classList.toggle("is-vm", vm);
  $("#detail").classList.toggle("is-hermes", w.agent === "hermes");
  $$("#detail .agent-name").forEach((e) => (e.textContent = agent));
  $("#d-port-label").textContent = vm ? "microVM, slot" : "sandbox port";
  $("#d-port").textContent = w.port;
  $("#d-runtime").textContent = vm ? "VM" : "Container";
  setPill($("#d-container"), vm ? "VM" : "container", w.container, CONTAINER_TONE[w.container]);
  // a microVM without the browser container: no sandbox views, no container files
  const views = !vm || w.browser;
  for (const tab of VM_HIDDEN_TABS) $(`.tabs [data-tab="${tab}"]`).hidden = !views;
  if (!views && VM_HIDDEN_TABS.includes(state.tab)) selectTab("claude");
  $("#builds-tab").hidden = !w.builds;
  if (!w.builds && state.tab === "builds") selectTab("claude");
  setPill($("#d-claude"), agent, w.claude, CLAUDE_TONE[w.claude]);
  $("#d-pending").hidden = !w.policyPending;
  // Hermes' gateway (a VM's state comes from GET .../gateway: an ssh round trip)
  const gw = w.gateway === "unknown" ? gatewayState[w.name] : w.gateway;
  $("#d-gateway").hidden = w.agent !== "hermes";
  if (w.agent === "hermes") {
    setPill($("#d-gateway"), "gateway", gw || "…", GATEWAY_TONE[gw]);
    if (w.gateway === "unknown" && !(w.name in gatewayState)) fetchGateway(w);
    $('[data-act="gateway/start"]').disabled = gw === "running";
    $('[data-act="gateway/stop"]').disabled = gw === "stopped";
  }
  renderSetup(w);

  const up = w.container === "running";
  for (const b of $$('[data-act="container/start"]')) b.disabled = up;
  $('[data-act="container/stop"]').disabled = !up && w.container !== "restarting";
  $$('.toolbar [data-act="claude/start"]')[0].disabled = w.claude === "running";
  $('[data-act="claude/restart"]').disabled = w.claude === "stopped";
  $('[data-act="claude/stop"]').disabled = w.claude === "stopped";
  $('#term-overlay [data-act]').disabled = false;

  // Claude tab
  const overlay = $("#term-overlay");
  overlay.hidden = w.claude !== "stopped";
  $("#term-overlay-msg").textContent = up
    ? `${agent} isn't running in this workspace.`
    : vm ? `${agent} isn't running. Start the VM first: ${agent} runs inside it.`
      : `${agent} isn't running. Start the container first so it can use the browser.`;
  if (state.tab === "claude" && w.claude !== "stopped") ensureTerm(w);
  if (w.claude === "stopped" && term.for === w.name) disconnectTerm();

  // Browser tab
  // Sandbox-backed tabs (browser, VS Code, container terminal)
  for (const tab of Object.keys(FRAMES)) {
    $(`[data-panel="${tab}"] .overlay`).hidden = up && views;
    if ((!up || !views) && state.frameFor[tab]) clearFrame(tab);
  }
  if (up && views && FRAMES[state.tab] && state.frameFor[state.tab] !== w.name) loadFrame(state.tab, w);
}

function select(name) {
  if (state.selected !== name || state.view !== "ws") {
    state.view = "ws";
    state.selected = name;
    history.replaceState(null, "", `#${encodeURIComponent(name)}`);
    hideConfirm();
    msg("");
    disconnectTerm();
    Object.keys(FRAMES).forEach(clearFrame);
  }
  renderList();
  renderDetail();
  if (state.tab === "files") loadFiles();
  if (state.tab === "logs") loadLogs();
  if (state.tab === "access") loadAccess();
  if (state.tab === "builds") loadBuilds(true);
}

const PAGE_LOAD = { pool: () => loadPool(), import: () => loadImport(), host: () => loadHost(), settings: () => loadSettings(),
  guide: () => loadGuide() };

function showPage(view) {
  state.view = view;
  history.replaceState(null, "", Object.keys(VIEW_OF_HASH).find((h) => VIEW_OF_HASH[h] === view));
  disconnectTerm();
  Object.keys(FRAMES).forEach(clearFrame);
  renderList();
  renderDetail();
  PAGE_LOAD[view]();
}
for (const view of Object.keys(PAGES)) $(`${PAGES[view]}-btn`).addEventListener("click", () => showPage(view));

// ------------------------------------------------------------------ actions

function msg(text, isErr = false) {
  const el = $("#action-msg");
  el.textContent = text;
  el.classList.toggle("err", isErr);
}

const VM_HIDDEN_TABS = ["browser", "vscode", "shell", "files"];

const ACT_LABEL = {
  "container/start": "Starting container…", "container/stop": "Stopping container…",
  "claude/start": "Starting {}…", "claude/restart": "Restarting {}…", "claude/stop": "Stopping {}…",
  "gateway/start": "Starting the gateway (in a VM, the first start installs Hermes: minutes)…",
  "gateway/stop": "Stopping the gateway…",
};

// microVM workspaces' gateway states, fetched on demand
const gatewayState = {};
async function fetchGateway(w) {
  gatewayState[w.name] = "…";
  try {
    gatewayState[w.name] = (await api("GET", wsPath(w.name, "/gateway"))).state;
  } catch (e) {
    gatewayState[w.name] = "unknown";
  }
  if (current()?.name === w.name) renderDetail();
}

document.addEventListener("click", async (ev) => {
  const btn = ev.target.closest("[data-act]");
  if (!btn) return;
  const w = current();
  if (!w) return;
  const act = btn.dataset.act;
  $$("[data-act]").forEach((b) => (b.disabled = true));
  msg(w.kind === "microvm" && act.startsWith("container/")
    ? (act === "container/start" ? "Starting VM…" : "Stopping VM…") : (ACT_LABEL[act] || "Working…").replace("{}", agentName(w)));
  try {
    await api("POST", wsPath(w.name, `/${act}`));
    msg(act === "gateway/start" ? "Gateway started; its output is in the Logs tab." : "");
    if (act.startsWith("gateway/") || act.startsWith("container/")) delete gatewayState[w.name];
    if (act.startsWith("claude/")) disconnectTerm();
    if (act !== "claude/stop" && act.startsWith("claude/")) selectTab("claude");
  } catch (e) {
    msg(e.message, true);
  }
  await refresh();
});

$("#remove-btn").addEventListener("click", () => {
  const w = current();
  $("#rm-name").textContent = w.name;
  $("#rm-dir").textContent = w.dir;
  $("#rm-what").textContent = w.kind === "microvm"
    ? `VM and its disk (${agentName(w)}'s login there, Docker images, anything outside /project)` : "container and its key";
  $("#remove-confirm").hidden = false;
});
const hideConfirm = () => ($("#remove-confirm").hidden = true);
$("#rm-no").addEventListener("click", hideConfirm);
$("#rm-yes").addEventListener("click", async () => {
  const w = current();
  $("#rm-yes").disabled = true;
  msg(`Removing ${w.name}…`);
  try {
    await api("DELETE", wsPath(w.name));
    hideConfirm();
    msg("");
    disconnectTerm();
    state.selected = null;
    history.replaceState(null, "", location.pathname);
  } catch (e) {
    msg(e.message, true);
  }
  $("#rm-yes").disabled = false;
  await refresh();
});

// new workspace
const newForm = $("#new-form");
$("#new-toggle").addEventListener("click", () => {
  newForm.hidden = false;
  $("#new-toggle").hidden = true;
  newForm.elements.name.focus();
});
newForm.elements.kind.addEventListener("change", () => {
  $("#new-kind-hint").hidden = newForm.elements.kind.value !== "microvm";
});
newForm.elements.agent.addEventListener("change", () => {
  $("#new-agent-hint").hidden = newForm.elements.agent.value !== "hermes";
});
$("#new-cancel").addEventListener("click", () => {
  newForm.hidden = true;
  $("#new-toggle").hidden = false;
  $("#new-msg").textContent = "";
});
newForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const name = newForm.elements.name.value.trim();
  const dir = newForm.elements.dir.value.trim();
  const kind = newForm.elements.kind.value;
  const agent = newForm.elements.agent.value;
  const out = $("#new-msg");
  out.classList.remove("err");
  out.textContent = kind === "microvm"
    ? "Creating workspace and starting its VM (the first start copies the image)…"
    : "Creating workspace and starting its container…";
  $$("button", newForm).forEach((b) => (b.disabled = true));
  try {
    const res = await api("POST", "workspaces", { name, dir: dir || undefined, kind, agent });
    newForm.reset();
    $("#new-kind-hint").hidden = true;
    $("#new-agent-hint").hidden = true;
    newForm.hidden = true;
    $("#new-toggle").hidden = false;
    out.textContent = "";
    await refresh();
    select(res.name);
    msg(res.notes?.length ? res.notes.join(" · ") : agent === "hermes"
      ? `Created ${res.name}. Pick its model provider in the Access tab, then start Hermes.`
      : `Created ${res.name}. Start Claude when you're ready.`);
  } catch (e) {
    out.classList.add("err");
    out.textContent = e.message;
  }
  $$("button", newForm).forEach((b) => (b.disabled = false));
});

// ------------------------------------------------------------------ tabs

function selectTab(tab) {
  state.tab = tab;
  for (const b of $$(".tabs [role=tab]")) b.setAttribute("aria-selected", String(b.dataset.tab === tab));
  for (const p of $$(".panel")) p.hidden = p.dataset.panel !== tab;
  const w = current();
  if (!w) return;
  if (tab === "claude") { if (w.claude !== "stopped") ensureTerm(w); requestAnimationFrame(fitTerm); }
  if (FRAMES[tab] && w.container === "running" && state.frameFor[tab] !== w.name) loadFrame(tab, w);
  if (tab === "files") loadFiles();
  if (tab === "logs") loadLogs();
  if (tab === "access") loadAccess();
  if (tab === "builds") loadBuilds(true);
}
$$(".tabs [role=tab]").forEach((b) => b.addEventListener("click", () => selectTab(b.dataset.tab)));

// ------------------------------------------------------------------ terminal

const term = { xterm: null, fit: null, sock: null, for: null, retry: 0, timer: null };

function initXterm() {
  if (term.xterm) return;
  const css = getComputedStyle(document.documentElement);
  term.xterm = new Terminal({
    cursorBlink: true,
    fontFamily: css.getPropertyValue("--mono"),
    fontSize: 13,
    scrollback: 5000,
    macOptionClickForcesSelection: true,   // tmux takes the mouse (wheel scrollback); Shift-drag elsewhere
    theme: { background: css.getPropertyValue("--term-bg").trim() || "#1b1b19" },
  });
  term.fit = new FitAddon.FitAddon();
  term.xterm.loadAddon(term.fit);
  term.xterm.open($("#term"));
  term.xterm.onData((d) => send({ t: "i", d }));
  new ResizeObserver(() => fitTerm()).observe($("#term"));
}

function send(obj) {
  if (term.sock?.readyState === WebSocket.OPEN) term.sock.send(JSON.stringify(obj));
}

function fitTerm() {
  if (!term.xterm || $('[data-panel="claude"]').hidden) return;
  try { term.fit.fit(); } catch { return; }
  send({ t: "r", c: term.xterm.cols, r: term.xterm.rows });
}

function ensureTerm(w) {
  initXterm();
  if (term.for === w.name && term.sock && term.sock.readyState <= WebSocket.OPEN) return;
  disconnectTerm();
  term.for = w.name;
  term.xterm.reset();
  fitTerm();
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const q = `cols=${term.xterm.cols}&rows=${term.xterm.rows}`;
  const sock = new WebSocket(`${proto}://${location.host}/ws/term/${encodeURIComponent(w.name)}?${q}`);
  sock.binaryType = "arraybuffer";
  sock.onopen = () => { term.retry = 0; fitTerm(); term.xterm.focus(); };
  sock.onmessage = (ev) => term.xterm.write(typeof ev.data === "string" ? ev.data : new Uint8Array(ev.data));
  sock.onclose = () => {
    if (term.sock !== sock) return;
    term.sock = null;
    const cur = current();
    // Reconnect if the session still exists (e.g. network blip), with backoff.
    if (cur && cur.name === term.for && cur.claude !== "stopped" && state.tab === "claude" && term.retry < 5) {
      term.retry += 1;
      term.timer = setTimeout(() => { term.for = null; refresh(); }, 1000 * term.retry);
    }
  };
  term.sock = sock;
}

function disconnectTerm() {
  clearTimeout(term.timer);
  const s = term.sock;
  term.sock = null;
  term.for = null;
  if (s) s.close();
}

// ------------------------------------------------------------------ host shell

// The Host page: a login shell on this host (its own tmux session, which
// outlasts the page and UI restarts). Separate from the Claude terminal.
const host = { xterm: null, fit: null, sock: null, retry: 0, timer: null, info: null };

const HOST_CMDS = {
  update: () => `${host.info?.root || "~/agent-sandboxes"}/bin/update-host`,
  "restart-ui": () => "sudo systemctl restart agent-sandboxes-ui",
  "restart-proxy": () => "sudo systemctl restart agent-sandboxes-proxy",
  status: () => "systemctl --no-pager status agent-sandboxes-ui agent-sandboxes-proxy",
};

function initHostXterm() {
  if (host.xterm) return;
  const css = getComputedStyle(document.documentElement);
  host.xterm = new Terminal({
    cursorBlink: true,
    fontFamily: css.getPropertyValue("--mono"),
    fontSize: 13,
    scrollback: 5000,
    macOptionClickForcesSelection: true,
    theme: { background: css.getPropertyValue("--term-bg").trim() || "#1b1b19" },
  });
  host.fit = new FitAddon.FitAddon();
  host.xterm.loadAddon(host.fit);
  host.xterm.open($("#host-term"));
  host.xterm.onData((d) => hostSend({ t: "i", d }));
  new ResizeObserver(() => fitHost()).observe($("#host-term"));
}

function hostSend(obj) {
  if (host.sock?.readyState === WebSocket.OPEN) { host.sock.send(JSON.stringify(obj)); return true; }
  return false;
}

function fitHost() {
  if (!host.xterm || $("#host").hidden) return;
  try { host.fit.fit(); } catch { return; }
  hostSend({ t: "r", c: host.xterm.cols, r: host.xterm.rows });
}

function hostOverlay(text) {
  $("#host-overlay").hidden = !text;
  $("#host-overlay-msg").textContent = text || "";
}

function connectHost() {
  initHostXterm();
  if (host.sock && host.sock.readyState <= WebSocket.OPEN) return;
  clearTimeout(host.timer);
  hostOverlay("");
  host.xterm.reset();
  fitHost();
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const sock = new WebSocket(`${proto}://${location.host}/ws/host?cols=${host.xterm.cols}&rows=${host.xterm.rows}`);
  sock.binaryType = "arraybuffer";
  sock.onopen = () => { host.retry = 0; fitHost(); host.xterm.focus(); };
  sock.onmessage = (ev) => host.xterm.write(typeof ev.data === "string" ? ev.data : new Uint8Array(ev.data));
  sock.onclose = async () => {
    if (host.sock !== sock) return;      // closed on purpose
    host.sock = null;
    if (state.view !== "host") return;
    // The shell exited, or the UI restarted (an update): reconnect while the
    // session is there, with backoff; the UI may take a few seconds to return.
    let info = null;
    try { info = await api("GET", "host"); } catch { /* UI restarting */ }
    if (state.view !== "host") return;
    if (info) renderHostInfo(info);
    if (info && !info.running) return hostOverlay("The shell ended.");
    if (host.retry >= 10) return hostOverlay("Disconnected from the host shell.");
    host.retry += 1;
    hostOverlay("Reconnecting…");
    host.timer = setTimeout(connectHost, Math.min(1000 * host.retry, 5000));
  };
  host.sock = sock;
}

function disconnectHost() {
  clearTimeout(host.timer);
  const s = host.sock;
  host.sock = null;
  if (s) s.close();
}

function renderHostInfo(info) {
  host.info = info;
  const g = info.git || {};
  $("#host-meta").textContent = `A login shell as ${info.user} in ${info.root}`
    + (g.commit ? ` · ${g.branch} at ${g.commit} (${g.when}): ${g.subject}` : "");
  const pill = (cls, text, title = "") => el("span", { className: `pill ${cls}`, textContent: text, title });
  const pills = [];
  if (g.dirty) pills.push(pill("warn", "local changes", "Tracked files differ from the last commit: a pull may refuse to run"));
  if (info.uiStale) pills.push(pill("warn", "UI runs older code", "ui/server.py or ui/common.py changed since the UI started: Restart UI"));
  if (info.proxyStale) pills.push(pill("warn", "proxy runs older code", "ui/proxyd.py or ui/common.py changed since the proxy started: Restart proxy"));
  if (info.proxyError) pills.push(pill("bad", "proxy not answering", info.proxyError));
  if (!info.sudo) pills.push(pill("bad", "no sudo here", `No systemd --user instance, so the shell runs under the UI's service, which forbids sudo: sudo loginctl enable-linger ${info.user}`));
  if (!pills.length) pills.push(pill("ok", "running the code on disk"));
  $("#host-pills").replaceChildren(...pills);
  $$("[data-host-cmd]").forEach((b) => (b.disabled = !info.enabled));
}

async function loadHost() {
  let info;
  try {
    info = await api("GET", "host");
  } catch (e) {
    return hostOverlay(e.message);
  }
  renderHostInfo(info);
  if (!info.enabled) {
    initHostXterm();
    $("#host-reconnect").hidden = true;
    return hostOverlay("The host shell is turned off on this server (AIO_HOST_SHELL=0).");
  }
  connectHost();
}

$("#host-reconnect").addEventListener("click", () => { host.retry = 0; connectHost(); });
$$("[data-host-cmd]").forEach((b) => b.addEventListener("click", () => {
  const cmd = HOST_CMDS[b.dataset.hostCmd]();
  if (!hostSend({ t: "i", d: `${cmd}\r` })) {
    host.retry = 0;
    connectHost();
    return;
  }
  host.xterm.focus();
}));

// ------------------------------------------------------------------ browser (VNC via proxy)

// Each sandbox needs its own origin. Over an SSH tunnel (UI on localhost) use
// <name>.localhost, which browsers resolve to loopback; when the UI is opened
// by IP or hostname, the server listens on a dedicated port per workspace.
function sandboxOrigin(w, link) {
  if (["localhost", "127.0.0.1"].includes(location.hostname)) {
    const port = location.port ? `:${location.port}` : "";
    return `${location.protocol}//${w.name}.localhost${port}`;
  }
  return `${location.protocol}//${location.hostname}:${link.port}`;
}

// The server hands out a per-workspace capability prefix (/__s/<secret>);
// everything under it is proxied to that workspace's sandbox.
async function sandboxUrl(w, page) {
  const link = await api("GET", wsPath(w.name, "/sandbox-link"));
  return `${sandboxOrigin(w, link)}${link.prefix}${page(link.prefix)}`;
}

const VNC_PATH = (prefix) =>
  `/vnc/index.html?autoconnect=true&resize=scale&reconnect=true&path=${encodeURIComponent(prefix.slice(1) + "/websockify")}`;
const HOME_PATH = () => "/";

// Tabs that embed a page served by the workspace's sandbox container.
const FRAMES = {
  browser: VNC_PATH,
  vscode: () => "/code-server/?folder=/home/gem/workspace",
  shell: () => "/terminal",
};
const frameEl = (tab) => $(`[data-panel="${tab}"] iframe`);

function clearFrame(tab) {
  frameEl(tab).src = "about:blank";
  state.frameFor[tab] = null;
}

async function loadFrame(tab, w) {
  state.frameFor[tab] = w.name;
  try {
    frameEl(tab).src = await sandboxUrl(w, FRAMES[tab]);
  } catch (e) {
    state.frameFor[tab] = null;
    msg(e.message, true);
  }
}

document.addEventListener("click", (ev) => {
  const btn = ev.target.closest("[data-frame-reload], [data-frame-open]");
  const w = current();
  if (!btn || !w) return;
  const tab = btn.closest("[data-panel]").dataset.panel;
  if (btn.hasAttribute("data-frame-reload")) loadFrame(tab, w);
  else openInTab(FRAMES[tab]);
});

async function openInTab(next) {
  const w = current();
  if (!w) return;
  const win = window.open("about:blank", "_blank");   // open synchronously so it isn't popup-blocked
  try {
    const url = await sandboxUrl(w, next);
    if (win) { win.opener = null; win.location = url; } else location.assign(url);
  } catch (e) {
    win?.close();
    msg(e.message, true);
  }
}
$("#open-sandbox").addEventListener("click", () => openInTab(HOME_PATH));

// ------------------------------------------------------------------ files

const fmtSize = (n) => n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : n < 1073741824 ? `${(n / 1048576).toFixed(1)} MB` : `${(n / 1073741824).toFixed(2)} GB`;
const fmtTime = (t) => new Date(t * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
const joinPath = (a, b) => (a.endsWith("/") ? a : a + "/") + b;
const parentPath = (p) => p.replace(/\/[^/]+\/?$/, "") || "/";
const downloadHref = (w, p) => `/api/${wsPath(w.name, "/download")}?path=${encodeURIComponent(p)}`;

function noteRow(text) {
  const tr = document.createElement("tr");
  const td = document.createElement("td");
  td.colSpan = 4;
  td.className = "note";
  td.textContent = text;
  tr.append(td);
  return tr;
}

async function loadFiles(path) {
  const w = current();
  if (!w) return;
  path = path || state.filesPath[w.name] || "/home/gem/workspace";
  $("#f-path").value = path;
  const body = $("#f-body");
  if (w.container !== "running") {
    body.replaceChildren(noteRow("Start the container to browse its files."));
    return;
  }
  body.replaceChildren(noteRow("Loading…"));
  try {
    const res = await api("GET", `${wsPath(w.name, "/files")}?path=${encodeURIComponent(path)}`);
    state.filesPath[w.name] = res.path;
    $("#f-path").value = res.path;
    body.replaceChildren();
    if (!res.entries.length) body.append(noteRow("Empty folder."));
    for (const e of res.entries) {
      const full = joinPath(res.path, e.name);
      const tr = document.createElement("tr");
      const name = document.createElement("td");
      const a = document.createElement("a");
      a.textContent = e.name;
      if (e.type === "dir") {
        a.href = "#";
        a.className = "dir";
        a.addEventListener("click", (ev) => { ev.preventDefault(); loadFiles(full); });
      } else {
        a.href = downloadHref(w, full);
        a.setAttribute("download", "");
      }
      name.append(a);
      const size = document.createElement("td");
      size.className = "num";
      size.textContent = e.type === "dir" ? "—" : fmtSize(e.size);
      const mod = document.createElement("td");
      mod.textContent = fmtTime(e.mtime);
      const act = document.createElement("td");
      const dl = document.createElement("a");
      dl.className = "dl";
      dl.href = downloadHref(w, full);
      dl.setAttribute("download", "");
      dl.textContent = e.type === "dir" ? "Download .tar" : "Download";
      act.append(dl);
      tr.append(name, size, mod, act);
      body.append(tr);
    }
  } catch (e) {
    body.replaceChildren(noteRow(e.message));
  }
}

$("#f-form").addEventListener("submit", (ev) => { ev.preventDefault(); loadFiles($("#f-path").value.trim()); });
$("#f-up").addEventListener("click", () => loadFiles(parentPath($("#f-path").value)));
$$("[data-jump]").forEach((b) => b.addEventListener("click", () => loadFiles(b.dataset.jump)));
$("#f-zip").addEventListener("click", () => {
  const w = current();
  const p = $("#f-path").value.trim();
  if (!w || !p || p === "/") return;
  const a = document.createElement("a");
  a.href = downloadHref(w, p);
  a.setAttribute("download", "");
  a.click();
});

// Uploads: one request per file, streamed into the container (PUT
// .../upload?path=<folder>&name=<file or relative path>). XHR, not fetch,
// for upload progress.
const upload = { xhr: null, cancelled: false };

function putFile(w, folder, rel, file, overwrite, onProgress) {
  return new Promise((resolve, reject) => {
    const q = `path=${encodeURIComponent(folder)}&name=${encodeURIComponent(rel)}${overwrite ? "&overwrite=1" : ""}`;
    const xhr = new XMLHttpRequest();
    upload.xhr = xhr;
    xhr.open("PUT", `/api/${wsPath(w.name, "/upload")}?${q}`);
    xhr.setRequestHeader("X-Requested-With", "sbui");
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.upload.onprogress = (ev) => onProgress(ev.loaded);
    xhr.onload = () => {
      if (xhr.status === 401) { location.reload(); return reject(new Error("Signed out")); }
      let data = {};
      try { data = JSON.parse(xhr.responseText); } catch { data = { error: xhr.responseText || `HTTP ${xhr.status}` }; }
      if (xhr.status >= 200 && xhr.status < 300) resolve(data);
      else reject(Object.assign(new Error(data.error || `HTTP ${xhr.status}`), { exists: !!data.exists }));
    };
    xhr.onerror = () => reject(new Error("Upload failed (connection lost)"));
    xhr.onabort = () => reject(Object.assign(new Error("Cancelled"), { cancelled: true }));
    xhr.send(file);
  });
}

// items: [{ file, rel }] (rel: the name, or a path inside an uploaded folder)
async function uploadFiles(items) {
  const w = current();
  if (!w || !items.length) return;
  if (w.container !== "running") return alert("Start the container first.");
  const folder = state.filesPath[w.name] || $("#f-path").value.trim();
  // Ask about names already in this folder before sending anything
  const res = await api("GET", `${wsPath(w.name, "/files")}?path=${encodeURIComponent(folder)}`).catch(() => ({ entries: [] }));
  const here = new Set(res.entries.map((e) => e.name));
  const clash = [...new Set(items.map((i) => i.rel.split("/")[0]).filter((n) => here.has(n)))];
  let overwrite = false;
  if (clash.length) {
    const list = clash.slice(0, 8).join(", ") + (clash.length > 8 ? ` and ${clash.length - 8} more` : "");
    if (!confirm(`Already in ${folder}: ${list}.\n\nReplace ${clash.length === 1 ? "it" : "them"}?`)) return;
    overwrite = true;
  }
  const total = items.reduce((n, i) => n + i.file.size, 0);
  let done = 0, sent = 0;
  const failed = [];
  upload.cancelled = false;
  $("#f-progress").hidden = false;
  const bar = $("#f-progress-bar");
  for (const [n, { file, rel }] of items.entries()) {
    if (upload.cancelled) break;
    const show = (loaded) => {
      $("#f-progress-text").textContent = `Uploading ${n + 1} of ${items.length}: ${rel} (${fmtSize(sent + loaded)} of ${fmtSize(total)})`;
      bar.value = total ? (sent + loaded) / total : (n + 1) / items.length;
    };
    show(0);
    try {
      await putFile(w, folder, rel, file, overwrite, show);
      done += 1;
    } catch (e) {
      if (e.cancelled) break;
      failed.push(`${rel}: ${e.message}`);
    }
    sent += file.size;
  }
  upload.xhr = null;
  $("#f-progress").hidden = true;
  msg(failed.length
    ? `Uploaded ${done} of ${items.length}. Failed: ${failed.slice(0, 3).join("; ")}${failed.length > 3 ? "…" : ""}`
    : upload.cancelled ? `Cancelled after ${done} of ${items.length}.` : `Uploaded ${done} file${done === 1 ? "" : "s"} to ${folder}.`,
  failed.length > 0);
  if (state.tab === "files" && current()?.name === w.name) loadFiles(folder);
}

$("#f-upload").addEventListener("click", () => $("#f-pick").click());
$("#f-upload-dir").addEventListener("click", () => $("#f-pick-dir").click());
$("#f-pick").addEventListener("change", (ev) => {
  uploadFiles([...ev.target.files].map((file) => ({ file, rel: file.name })));
  ev.target.value = "";
});
$("#f-pick-dir").addEventListener("change", (ev) => {
  uploadFiles([...ev.target.files].map((file) => ({ file, rel: file.webkitRelativePath || file.name })));
  ev.target.value = "";
});
$("#f-cancel").addEventListener("click", () => {
  upload.cancelled = true;
  upload.xhr?.abort();
});

// Drag and drop: files, and folders (walked with the entries API)
async function droppedItems(dt) {
  const entries = [...dt.items].map((i) => i.webkitGetAsEntry?.()).filter(Boolean);
  if (!entries.length) return [...dt.files].map((file) => ({ file, rel: file.name }));
  const out = [];
  const walk = async (entry, prefix) => {
    if (entry.isFile) {
      out.push({ file: await new Promise((ok, bad) => entry.file(ok, bad)), rel: prefix + entry.name });
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      for (;;) {                          // readEntries returns them in batches
        const batch = await new Promise((ok, bad) => reader.readEntries(ok, bad));
        if (!batch.length) break;
        for (const e of batch) await walk(e, `${prefix}${entry.name}/`);
      }
    }
  };
  for (const e of entries) await walk(e, "");
  return out;
}
const drop = $("#f-drop");
drop.addEventListener("dragover", (ev) => {
  if (![...ev.dataTransfer.types].includes("Files")) return;
  ev.preventDefault();
  drop.classList.add("dropping");
});
drop.addEventListener("dragleave", (ev) => { if (!drop.contains(ev.relatedTarget)) drop.classList.remove("dropping"); });
drop.addEventListener("drop", async (ev) => {
  if (![...ev.dataTransfer.types].includes("Files")) return;
  ev.preventDefault();
  drop.classList.remove("dropping");
  try {
    uploadFiles(await droppedItems(ev.dataTransfer));
  } catch (e) {
    msg(`Couldn't read the dropped files: ${e.message}`, true);
  }
});

// ------------------------------------------------------------------ logs

async function loadLogs() {
  const w = current();
  if (!w) return;
  $("#logs").textContent = "Loading…";
  try {
    const { log } = await api("GET", wsPath(w.name, "/logs"));
    let text = log || "(no output)";
    if (w.agent === "hermes") {
      try {
        const g = await api("GET", wsPath(w.name, "/gateway"));
        gatewayState[w.name] = g.state;
        text += `\n\n──── Hermes gateway (${g.state}) ────\n${g.log || "(no output)"}`;
      } catch (e) { text += `\n\n──── Hermes gateway ────\n${e.message}`; }
    }
    const el = $("#logs");
    el.textContent = text;
    el.scrollTop = el.scrollHeight;
  } catch (e) {
    $("#logs").textContent = e.message;
  }
}
$("#logs-refresh").addEventListener("click", loadLogs);

// ------------------------------------------------------------------ Apple builds (per workspace)

const BUILD_TONE = { passed: "ok", running: "warn", queued: "warn", failed: "bad", error: "bad", timeout: "bad",
  stale: "warn" };
const ACTIVE = ["queued", "running", "stale"];
const bstate = { for: null, sel: null, offset: 0, timer: null, jobs: [] };
const dur = (s) => (s == null ? "" : s < 90 ? `${s} s` : `${Math.round(s / 60)} min`);
function bMsg(text, isErr = false) { const e = $("#b-msg"); e.textContent = text; e.classList.toggle("err", isErr); }

async function loadBuilds(fresh = false) {
  clearTimeout(bstate.timer);
  const w = current();
  if (!w || state.view !== "ws" || state.tab !== "builds") return;
  if (bstate.for !== w.name) {
    Object.assign(bstate, { for: w.name, sel: null, offset: 0, jobs: [] });
    $("#b-detail").hidden = true;
    bMsg("");
  }
  let r;
  try { r = await api("GET", wsPath(w.name, "/builds")); }
  catch (e) { $("#b-status").textContent = e.message; bstate.timer = setTimeout(loadBuilds, 10000); return; }
  const online = r.workers.filter((x) => x.online);
  $("#b-status").textContent = !r.host ? "No build host set up yet: Settings → Apple builds."
    : !r.connected ? `Build host ${r.host}: not connected${r.error ? ` (${r.error})` : ""}`
      : `Build host ${r.host} · Mac workers: ${r.workers.map((x) => `${x.name} (${x.online ? "online" : "offline"})`).join(", ") || "none yet"}`
        + (online.length ? "" : " · jobs wait in the queue until a worker is online");
  bstate.jobs = r.jobs;
  const head = el("tr", {}, ...["Build", "Action", "Scheme", "Commit", "State", "Time", "Worker"].map((h) => el("th", { textContent: h })));
  const rows = r.jobs.map((j) => {
    const pill = el("span", { className: `pill ${BUILD_TONE[j.state] || ""}`, textContent: j.state });
    const tr = el("tr", { className: j.id === bstate.sel ? "sel" : "" },
      el("td", { className: "mono", textContent: j.id }), el("td", { textContent: j.spec?.action || "" }),
      el("td", { textContent: j.spec?.scheme || "" }), el("td", { className: "mono", textContent: (j.commit || "").slice(0, 10) }),
      el("td", {}, pill), el("td", { textContent: dur(j.summary?.seconds) }), el("td", { textContent: j.worker || "" }));
    tr.dataset.id = j.id;
    tr.addEventListener("click", () => openBuild(j.id));
    return tr;
  });
  if (!rows.length) rows.push(el("tr", {}, el("td", { colSpan: 7, className: "note muted",
    textContent: "No builds yet. Queue one above, or ask the agent (its aio-builds MCP tools)." })));
  $("#b-jobs").replaceChildren(head, ...rows);
  if (bstate.sel) await showBuild(fresh);
  const busy = r.jobs.some((j) => ACTIVE.includes(j.state));
  bstate.timer = setTimeout(loadBuilds, busy ? 3000 : 15000);
}

function openBuild(id) {
  Object.assign(bstate, { sel: id, offset: 0 });
  $("#b-log").textContent = "";
  $("#b-shots").replaceChildren();
  $("#b-arts").replaceChildren();
  $("#b-detail").hidden = false;
  $$("#b-jobs tr[data-id]").forEach((tr) => tr.classList.toggle("sel", tr.dataset.id === id));
  showBuild(true);
}

async function showBuild(full) {
  const w = current();
  const j = bstate.jobs.find((x) => x.id === bstate.sel);
  if (!w) return;
  if (!j) {     // just queued: the build host's next snapshot brings it
    $("#b-d-title").textContent = `${bstate.sel} · queued`;
    $("#b-d-meta").textContent = "Waiting for the build host…";
    $("#b-cancel").hidden = $("#b-abandon").hidden = true;
    return;
  }
  const base = `/api/${wsPath(w.name, `/builds/${j.id}`)}`;
  $("#b-d-title").textContent = `${j.spec?.action} ${j.spec?.scheme} · ${j.state}`;
  const s = j.summary || {};
  $("#b-d-meta").textContent = [`commit ${j.commit?.slice(0, 12)}`, j.spec?.project, j.spec?.destination,
    j.spec?.configuration, `queued ${j.spec?.submitted || ""} by ${j.spec?.by === "agent" ? "the agent" : "you"}`,
    j.worker && `worker ${j.worker}`, s.xcode, s.seconds != null && dur(s.seconds), s.error && `error: ${s.error}`]
    .filter(Boolean).join(" · ");
  $("#b-cancel").hidden = !["queued", "running"].includes(j.state);
  $("#b-abandon").hidden = j.state !== "stale";
  // the log, from where we got to
  if (full || ACTIVE.includes(j.state) || j.log_size > bstate.offset) {
    try {
      const res = await fetch(`${base}/log?offset=${bstate.offset}`, { headers: { "X-Requested-With": "sbui" } });
      const t = await res.text();
      if (res.ok && t) {
        const pre = $("#b-log");
        const atEnd = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 20;
        pre.textContent += t;
        bstate.offset += new TextEncoder().encode(t).length;
        if (atEnd) pre.scrollTop = pre.scrollHeight;
      }
    } catch { /* next time */ }
  }
  if (!j.summary || !full) return;
  $("#b-shots").replaceChildren(...(s.files || []).filter((f) => /^screenshots\/.*\.png$/.test(f)).map((f) =>
    el("img", { src: `${base}/file?path=${encodeURIComponent(f)}`, alt: f })));
  const arts = j.artifacts || [];
  $("#b-arts").replaceChildren(...(arts.length ? [el("span", { className: "muted", textContent: "Artifacts: " })] : []),
    ...arts.map((a) => el("a", { className: "btn", href: `${base}/artifact?name=${encodeURIComponent(a)}`, textContent: `⬇ ${a}` })));
}

async function buildAction(what) {
  const w = current();
  if (!w || !bstate.sel) return;
  if (what === "abandon" && !confirm("Mark this build abandoned? Do it when its worker is gone for good.")) return;
  try { await api("POST", wsPath(w.name, `/builds/${bstate.sel}/${what}`)); bMsg(what === "cancel" ? "Cancel requested." : "Marked abandoned."); }
  catch (e) { bMsg(e.message, true); }
  loadBuilds();
}
$("#b-cancel").addEventListener("click", () => buildAction("cancel"));
$("#b-abandon").addEventListener("click", () => buildAction("abandon"));
$("#b-close").addEventListener("click", () => { bstate.sel = null; $("#b-detail").hidden = true; loadBuilds(); });
$("#b-refresh").addEventListener("click", () => loadBuilds(true));
$("#b-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const w = current();
  const f = ev.currentTarget.elements;
  const body = Object.fromEntries(["action", "scheme", "project", "destination", "configuration", "ref"].map((k) => [k, f[k].value.trim()]));
  bMsg("Sending the commit to the build host…");
  try {
    const j = await api("POST", wsPath(w.name, "/builds"), body);
    bMsg(`Queued ${j.id} (${j.commit.slice(0, 10)}).`);
    await loadBuilds();
    openBuild(j.id);
  } catch (e) { bMsg(e.message, true); }
});

// ------------------------------------------------------------------ Apple builds (Settings: build host, workers)

function bhMsg(text, isErr = false) { const e = $("#bh-msg"); e.textContent = text; e.classList.toggle("err", isErr); }

async function loadBuildHost() {
  let r;
  try { r = await api("GET", "builds"); } catch (e) { return bhMsg(e.message, true); }
  const f = $("#bh-form").elements;
  if (document.activeElement?.form !== $("#bh-form")) { f.host.value = r.host; f.port.value = r.port; }
  $("#bh-key").textContent = r.publicKey;
  $("#bh-cmd-host").textContent = `tar xzf aio-buildhost.tar.gz && aio-buildhost/bin/install-buildhost --ui-key '${r.publicKey}'`;
  // The Mac reaches the build host from outside: a loopback address means this machine
  const [user, at] = r.host.includes("@") ? r.host.split("@") : ["aiogit", r.host];
  const host = !at || /^(127\.|localhost$|::1$)/.test(at) ? location.hostname : at;
  $("#bh-cmd-mac").textContent = `tar xzf aio-build-worker.tar.gz && aio-build-worker/buildhost/install-worker --host ${user}@${host}`
    + (Number(r.port) && Number(r.port) !== 22 ? ` --port ${r.port}` : "");
  if (!r.host || !r.workers.length) $("#bh-setup").open = true;
  setPill($("#bh-state"), "build host", !r.host ? "not set up" : r.connected ? "connected" : "not connected",
    !r.host ? "" : r.connected ? "ok" : "bad");
  if (r.error) bhMsg(r.error, true);
  let keys = [];
  if (r.connected) { try { keys = (await api("GET", "builds/worker-keys")).workers; } catch { /* shown above */ } }
  const names = [...new Set([...keys.map((k) => k.name), ...r.workers.map((x) => x.name)])];
  const rows = names.map((n) => {
    const hb = r.workers.find((x) => x.name === n) || {};
    const del = el("button", { className: "btn ghost danger", type: "button", textContent: "Remove" });
    del.addEventListener("click", async () => {
      if (!confirm(`Remove worker ${n}? Its key stops working on the build host.`)) return;
      try { await api("DELETE", `builds/workers/${encodeURIComponent(n)}`); bhMsg(`Removed ${n}.`); } catch (e) { bhMsg(e.message, true); }
      loadBuildHost();
    });
    const facts = [hb.online ? "online" : hb.seen ? `offline, last seen ${when(hb.seen)}` : "never connected",
      hb.macos && `macOS ${hb.macos}`, hb.tart, hb.max_vms && `up to ${hb.max_vms} VM(s)`,
      hb.running?.length && `running ${hb.running.length}`, hb.image].filter(Boolean).join(" · ");
    return el("div", { className: "keyrow" },
      el("div", {}, el("strong", { textContent: n }), el("div", { className: "muted", textContent: facts })), del);
  });
  if (!rows.length) rows.push(el("p", { className: "muted", textContent: r.connected ? "No workers yet: add one below." : "Connect to the build host to see its workers." }));
  $("#bh-workers").replaceChildren(...rows);
}
$("#bh-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.currentTarget.elements;
  try { await api("PUT", "builds/config", { host: f.host.value.trim(), port: Number(f.port.value || 22) }); bhMsg("Saved; connecting…"); }
  catch (e) { return bhMsg(e.message, true); }
  setTimeout(loadBuildHost, 2500);
});
$("#bh-test").addEventListener("click", async () => {
  bhMsg("Testing…");
  try { const r = await api("POST", "builds/test"); bhMsg(`Connected: aio-buildd ${r.version}.`); }
  catch (e) { bhMsg(e.message, true); }
  loadBuildHost();
});
$("#bh-add").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.currentTarget.elements;
  try {
    await api("POST", "builds/workers", { name: f.name.value.trim(), key: f.key.value.trim() });
    bhMsg(`Added ${f.name.value.trim()}. Start the worker on the Mac.`);
    f.name.value = ""; f.key.value = "";
  } catch (e) { bhMsg(e.message, true); }
  loadBuildHost();
});
for (const b of document.querySelectorAll(".bh-cmd [data-copy]")) {
  b.addEventListener("click", async () => {
    const code = b.previousElementSibling;
    try { await navigator.clipboard.writeText(code.textContent); bhMsg("Copied."); }
    catch { getSelection().selectAllChildren(code); bhMsg("Selected: copy it with Ctrl+C / ⌘C."); }
  });
}
$("#bh-copy").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($("#bh-key").textContent); bhMsg("Copied."); }
  catch { getSelection().selectAllChildren($("#bh-key")); bhMsg("Selected: copy it with Ctrl+C / ⌘C."); }
});

// ------------------------------------------------------------------ access (per-workspace policy)

function el(tag, props = {}, ...kids) {
  const n = Object.assign(document.createElement(tag), props);
  n.append(...kids);
  return n;
}

function checkItem(name, value, checked, title, sub) {
  const input = el("input", { type: "checkbox", name, value, checked });
  return el("label", { className: "check" }, input,
    el("span", {}, el("strong", { textContent: title }), " ", el("span", { className: "muted", textContent: sub })));
}

const lines = (text) => text.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

let poolTokenIds = [];
async function loadAccess() {
  const w = current();
  if (!w) return;
  const form = $("#access-form");
  $("#acc-msg").textContent = "";
  $("#acc-msg").classList.remove("err");
  $("#acc-port").textContent = `(127.0.0.1:${w.port})`;
  try {
    const [{ policy }, pool] = await Promise.all([api("GET", wsPath(w.name, "/policy")), api("GET", "pool")]);
    if (current()?.name !== w.name) return;
    const ssh = $("#acc-ssh");
    ssh.replaceChildren(...pool.ssh.map((k) =>
      checkItem("ssh", k.id, policy.ssh_keys.includes(k.id), k.id, `${k.type} ${k.fingerprint}`)));
    if (!pool.ssh.length) ssh.append(el("p", { className: "muted", textContent: "No SSH keys in the pool yet — add one under Keys & tokens." }));
    poolTokenIds = pool.tokens.map((t) => t.id);
    const tok = $("#acc-tokens");
    tok.replaceChildren(...pool.tokens.map((t) =>
      checkItem("token", t.id, policy.tokens.includes(t.id), t.id, `${t.label} → $${t.env_var}`)));
    if (!pool.tokens.length) tok.append(el("p", { className: "muted", textContent: "No API tokens in the pool yet — add one under Keys & tokens." }));
    $("#acc-net").replaceChildren(...Object.entries(pool.netModes).map(([mode, desc]) =>
      el("label", { className: "check" }, el("input", { type: "radio", name: "mode", value: mode, checked: policy.network.mode === mode }),
        el("span", {}, el("strong", { textContent: mode }), " ", el("span", { className: "muted", textContent: desc })))));
    form.elements.allow.value = policy.network.allow.join("\n");
    form.elements.deny.value = policy.network.deny.join("\n");
    form.elements.listen.value = (policy.network.listen || []).join(", ");
    form.elements.memory.value = policy.limits.memory;
    form.elements.pids.value = policy.limits.pids || "";
    form.elements.cpus.value = policy.limits.cpus || "";
    form.elements.cpus.placeholder = w.kind === "microvm" ? "default: 2" : "0 = no limit";
    form.elements.disk.value = policy.limits.disk || "";
    form.elements.browser_memory.value = policy.limits.browser_memory || "";
    form.elements.browser_cpus.value = policy.limits.browser_cpus || "";
    form.elements.claude_md.checked = policy.claude_md;
    const llm = $("#acc-hermes-llm");
    const llmTokens = pool.tokens.filter((t) => LLM_SERVICES.includes(t.service));
    llm.replaceChildren(
      ...llmTokens.map((t) => el("option", { value: t.id, textContent: `${t.id} (${t.label})` })),
      el("option", { value: NEW_LLM, textContent: "Add an API key…" }),
      el("option", { value: "", textContent: "A server that needs no key" }));
    // Nothing set yet: offer the first pool key, or adding one
    llm.value = policy.hermes?.llm || (policy.hermes?.base_url ? "" : llmTokens[0]?.id || NEW_LLM);
    form.elements.hermes_model.value = policy.hermes?.model || "";
    form.elements.hermes_base_url.value = policy.hermes?.base_url || "";
    for (const p of ["telegram", "discord", "slack"]) form.elements[`users_${p}`].value = policy.hermes?.allowed_users?.[p] || "";
    for (const n of ["hermes_new_id", "hermes_new_url", "hermes_new_key"]) form.elements[n].value = "";
    hermesLlmChanged();
    form.elements.vm_browser.checked = !!policy.vm_browser;
    form.elements.builds.checked = !!policy.builds;
    form.elements.container.value = policy.network.container;
    $("#acc-restart").hidden = w.claude === "stopped";
    loadWsSshAccess(w);
  } catch (e) {
    $("#acc-msg").textContent = e.message;
    $("#acc-msg").classList.add("err");
  }
}

async function saveAccess(restart) {
  const w = current();
  const form = $("#access-form");
  const out = $("#acc-msg");
  out.classList.remove("err");
  let llm = w.agent === "hermes" ? form.elements.hermes_llm.value : "";
  if (llm === NEW_LLM) {
    // Add the key to the pool first; the policy below then ticks and uses it
    const service = form.elements.hermes_new_service.value;
    const url = form.elements.hermes_new_url.value.trim();
    const id = form.elements.hermes_new_id.value.trim() || defaultLlmId(service, url);
    const key = form.elements.hermes_new_key.value.trim();
    if (!key) {
      out.textContent = service === "custom"
        ? "Hermes model: paste the server's API key, or pick “A server that needs no key”."
        : "Hermes model: paste the API key.";
      out.classList.add("err");
      return;
    }
    out.textContent = "Adding the key to the pool…";
    try {
      await api("POST", "pool/tokens", { id, service, secret: key,
        custom: service === "custom" ? { upstream: url, header: "Authorization", format: "Bearer {}",
          env_var: `${id.toUpperCase().replace(/-/g, "_").replace(/^(\d)/, "LLM_$1")}_API_KEY` } : undefined });
    } catch (e) {
      out.textContent = `Hermes model: ${e.message}`;
      out.classList.add("err");
      return;
    }
    llm = id;
    // It's in the pool now: a retry (if the policy below fails) picks it, not adds it again
    poolTokenIds.push(id);
    const sel = form.elements.hermes_llm;
    sel.insertBefore(el("option", { value: id, textContent: id }), sel.querySelector(`option[value="${NEW_LLM}"]`));
    sel.value = id;
    hermesLlmChanged();
  }
  const tokens = $$('input[name="token"]:checked', form).map((i) => i.value);
  if (llm && !tokens.includes(llm)) tokens.push(llm);     // the provider's key comes with it
  const body = {
    ssh_keys: $$('input[name="ssh"]:checked', form).map((i) => i.value),
    tokens,
    network: { mode: form.elements.mode?.value || "claude-code", allow: lines(form.elements.allow.value), deny: lines(form.elements.deny.value),
      container: form.elements.container.value || "open", listen: lines(form.elements.listen.value) },
    limits: { memory: form.elements.memory.value.trim(), pids: Number(form.elements.pids.value || 0),
      cpus: Number(form.elements.cpus.value || 0), disk: form.elements.disk.value.trim(),
      browser_memory: form.elements.browser_memory.value.trim(), browser_cpus: Number(form.elements.browser_cpus.value || 0) },
    claude_md: form.elements.claude_md.checked,
    vm_browser: form.elements.vm_browser.checked,
    builds: form.elements.builds.checked,
    hermes: { llm, model: form.elements.hermes_model.value.trim(),
      base_url: form.elements.hermes_base_url.value.trim(),
      allowed_users: Object.fromEntries(["telegram", "discord", "slack"].map((p) =>
        [p, lines(form.elements[`users_${p}`].value).join(",")])) },
  };
  out.textContent = "Saving…";
  try {
    const res = await api("PUT", wsPath(w.name, "/policy"), body);
    if (restart) {
      out.textContent = `Saved.${res.notes?.length ? ` ${res.notes.join(" ")}` : ""} Restarting ${agentName(w)}…`;
      await api("POST", wsPath(w.name, "/claude/restart"));
      disconnectTerm();
      out.textContent = `Saved and ${agentName(w)} restarted with the new policy.`
        + (w.gateway === "running" ? " Restart the gateway too (Stop, Start) for it." : "");
    } else {
      out.textContent = (res.pending
        ? `Saved. SSH key changes are live; restart ${agentName(w)} for the rest.`
        : w.claude === "stopped" ? `Saved. Applies when ${agentName(w)} starts.` : "Saved and applied.")
        + (res.notes?.length ? ` ${res.notes.join(" ")}` : "");
    }
  } catch (e) {
    out.textContent = e.message;
    out.classList.add("err");
  }
  await refresh();
}
$("#access-form").addEventListener("submit", (ev) => { ev.preventDefault(); saveAccess(false); });
// Pool token services Hermes can use as its model provider
const LLM_SERVICES = ["openrouter", "openai", "custom"];
const NEW_LLM = "+new";
function hermesLlmChanged() {
  const v = $("#acc-hermes-llm").value;
  $("#acc-hermes-url").hidden = v !== "";
  $("#acc-hermes-new").hidden = v !== NEW_LLM;
  $("#acc-hermes-new-url").hidden = $("#acc-hermes-new-service").value !== "custom";
}
// A free pool name for a new provider key: openrouter, openai, llm-<host>
function defaultLlmId(service, url) {
  let host = "";
  try { host = new URL(url).hostname; } catch { /* the server says what's wrong with the URL */ }
  const clean = (s) => s.toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 36);
  const base = clean(service === "custom" ? `llm-${host || "server"}` : service) || "llm";
  const taken = new Set(poolTokenIds);
  let id = base;
  for (let i = 2; taken.has(id); i++) id = `${base}-${i}`;
  return id;
}
$("#acc-hermes-llm").addEventListener("change", hermesLlmChanged);
$("#acc-hermes-new-service").addEventListener("change", hermesLlmChanged);
$("#acc-restart").addEventListener("click", () => saveAccess(true));

// ------------------------------------------------------------------ keys & tokens pool

let poolData = null;

function poolMsg(text, isErr = false) {
  $("#pool-msg").textContent = text;
  $("#pool-msg").classList.toggle("err", isErr);
}

function renderMatrix(table, kind, items, describe) {
  const wss = poolData.workspaces;
  const head = el("tr", {}, el("th", { textContent: kind === "ssh" ? "Key" : "Token" }),
    ...wss.map((n) => el("th", { className: "ws-col", textContent: n, title: n })), el("th"));
  const rows = items.map((it) => {
    const tds = wss.map((n) => {
      const cb = el("input", { type: "checkbox", checked: it.workspaces.includes(n), title: `${it.id} → ${n}` });
      cb.addEventListener("change", async () => {
        const want = wss.filter((x, i) => $$("input[type=checkbox]", cb.closest("tr"))[i].checked);
        cb.disabled = true;
        try {
          await api("PUT", `pool/${kind}/${encodeURIComponent(it.id)}/workspaces`, { workspaces: want });
          poolMsg(kind === "ssh" ? `${it.id}: applied to running sessions.` : `${it.id}: restart the agent in ${n} to apply.`);
        } catch (e) {
          cb.checked = !cb.checked;
          poolMsg(e.message, true);
        }
        cb.disabled = false;
        refresh();
      });
      return el("td", { className: "ws-col" }, cb);
    });
    const actions = el("td", { className: "acts" });
    if (kind === "ssh") {
      const copy = el("button", { className: "btn ghost", type: "button", textContent: "Copy public key" });
      copy.addEventListener("click", async () => {
        try { await navigator.clipboard.writeText(it.public); poolMsg(`Copied ${it.id}.pub — add it as a deploy key or to your account.`); }
        catch { window.prompt("Public key:", it.public); }
      });
      actions.append(copy);
    }
    const del = el("button", { className: "btn ghost danger", type: "button", textContent: "Delete" });
    del.addEventListener("click", async () => {
      if (!confirm(`Delete ${it.id}? It is removed from ${it.workspaces.length || "no"} workspace(s) and from disk.`)) return;
      try { await api("DELETE", `pool/${kind}/${encodeURIComponent(it.id)}`); poolMsg(`Deleted ${it.id}.`); }
      catch (e) { poolMsg(e.message, true); }
      loadPool();
      refresh();
    });
    actions.append(del);
    return el("tr", {}, el("td", { className: "item" }, el("strong", { textContent: it.id }), el("div", { className: "muted", textContent: describe(it) })), ...tds, actions);
  });
  if (!items.length) rows.push(el("tr", {}, el("td", { className: "muted note", colSpan: wss.length + 2, textContent: "None yet." })));
  table.replaceChildren(el("thead", {}, head), el("tbody", {}, ...rows));
}

async function loadPool() {
  try {
    poolData = await api("GET", "pool");
  } catch (e) {
    return poolMsg(e.message, true);
  }
  loadGoogle();
  renderMatrix($("#m-ssh"), "ssh", poolData.ssh, (k) => `${k.type} ${k.fingerprint} · ${k.comment}`);
  renderMatrix($("#m-tokens"), "tokens", poolData.tokens, (t) => t.service === "google"
    ? `${t.label} → $${baseUrlVar(t.id)} · ${t.detail}`
    : `${t.label} (${t.upstream}) → $${t.env_var}` + (t.upstream.startsWith("http://") ? ` · call it via $${baseUrlVar(t.id)}` : ""));
  const sel = $("#tok-service");
  if (!sel.options.length) {
    for (const [k, v] of Object.entries(poolData.services)) sel.append(el("option", { value: k, textContent: `${v.label} → $${v.env_var}` }));
    sel.append(el("option", { value: "custom", textContent: "Custom HTTP(S) API…" }));
    sel.append(el("option", { value: "google", textContent: "Google (Gmail, Calendar): a grant on a connected account…" }));
  }
}

// ---- Google grants in the token form

let googleData = null;

async function showGoogleFields(on) {
  $("#tok-google").hidden = !on;
  $("#tok-secret").hidden = on;
  $("#add-tokens").elements.secret.required = !on;
  if (!on) return;
  try {
    googleData = await api("GET", "google");
  } catch (e) {
    $("#tok-g-detail").textContent = e.message;
    return;
  }
  const acc = $("#tok-g-account");
  acc.replaceChildren(...googleData.accounts.map((a) => el("option", { value: a.id, textContent: `${a.email} (${a.scopes.join(", ")})` })));
  if (!googleData.accounts.length) acc.append(el("option", { value: "", textContent: "None yet: connect one in Google accounts below" }));
  const pre = $("#tok-g-preset");
  if (!pre.options.length) {
    for (const [k, v] of Object.entries(googleData.presets)) pre.append(el("option", { value: k, textContent: v.label }));
  }
  googlePresetChanged();
}

async function googlePresetChanged() {
  const p = googleData?.presets[$("#tok-g-preset").value];
  if (!p) return;
  $("#tok-g-detail").textContent = `${p.detail} Needs the account connected with ${p.scope}.`;
  $("#tok-g-label-wrap").hidden = !p.needsLabel;
  const aid = $("#tok-g-account").value;
  if (!p.needsLabel || !aid) return;
  const sel = $("#tok-g-label");
  sel.replaceChildren(el("option", { value: "", textContent: "Loading labels…" }));
  try {
    const { labels } = await api("GET", `google/accounts/${encodeURIComponent(aid)}/labels`);
    sel.replaceChildren(...labels.sort((a, b) => a.name.localeCompare(b.name))
      .map((l) => el("option", { value: l.id, textContent: l.name === l.id ? l.name : `${l.name} (${l.id})` })));
  } catch (e) {
    sel.replaceChildren(el("option", { value: "", textContent: e.message }));
  }
}
$("#tok-g-preset").addEventListener("change", googlePresetChanged);
$("#tok-g-account").addEventListener("change", googlePresetChanged);

$$("[data-add]").forEach((b) => b.addEventListener("click", () => {
  const f = $(`#add-${b.dataset.add}`);
  f.hidden = false;
  f.elements.id.focus();
}));
$$(".add-form [data-cancel]").forEach((b) => b.addEventListener("click", () => {
  const f = b.closest("form");
  f.reset();
  f.hidden = true;
  $(".form-msg", f).textContent = "";
}));
$("#add-ssh").addEventListener("change", (ev) => {
  if (ev.target.name === "how") ev.currentTarget.elements.private_key.hidden = ev.target.value !== "import";
});
// nono's route for a pool token; http:// APIs can only be reached through it
const baseUrlVar = (id) => `POOL_${id.replace(/-/g, "_").toUpperCase()}_BASE_URL`;

$("#tok-service").addEventListener("change", (ev) => {
  $("#tok-custom").hidden = ev.target.value !== "custom";
  showGoogleFields(ev.target.value === "google");
});

async function submitAdd(form, path, body) {
  const out = $(".form-msg", form);
  out.classList.remove("err");
  out.textContent = "Adding…";
  try {
    const res = await api("POST", path, body);
    form.reset();
    form.hidden = true;
    out.textContent = "";
    $("#tok-custom").hidden = true;
    if (form.id === "add-tokens") showGoogleFields(false);
    form.elements.private_key && (form.elements.private_key.hidden = true);
    poolMsg(res.public ? `Added ${res.id}. Public key: ${res.public}` : `Added ${res.id}.`);
    loadPool();
  } catch (e) {
    out.textContent = e.message;
    out.classList.add("err");
  }
}
$("#add-ssh").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const f = ev.currentTarget.elements;
  const generate = f.how.value === "generate";
  submitAdd(ev.currentTarget, "pool/ssh", { id: f.id.value.trim(), comment: f.comment.value.trim() || undefined,
    generate, private_key: generate ? undefined : f.private_key.value });
});
$("#add-tokens").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const f = ev.currentTarget.elements;
  const service = f.service.value;
  const label = $("#tok-g-label");
  submitAdd(ev.currentTarget, "pool/tokens", { id: f.id.value.trim(), service, secret: f.secret.value,
    custom: service === "custom" ? { upstream: f.upstream.value.trim(), header: f.header.value.trim(),
      format: f.format.value.trim(), env_var: f.env_var.value.trim() } : undefined,
    google: service === "google" ? { account: f.g_account.value, preset: f.g_preset.value,
      label: label.value, label_name: label.selectedOptions[0]?.textContent || "" } : undefined });
});

// ------------------------------------------------------------------ SSH access keys (shared widget)

const sshHost = () => location.hostname;

function renderKeyList(box, scope, keys, onChange) {
  const rows = keys.map((k) => {
    const del = el("button", { className: "btn ghost danger", type: "button", textContent: "Remove" });
    del.addEventListener("click", async () => {
      if (!confirm(`Remove ${k.comment || k.fingerprint}? It stops working immediately.`)) return;
      try { await api("DELETE", `access/${k.id}`); } catch (e) { alert(e.message); }
      onChange();
    });
    return el("div", { className: "keyrow" },
      el("div", {}, el("strong", { textContent: k.comment || "(no comment)" }),
        el("div", { className: "muted mono", textContent: `${k.type} ${k.fingerprint}` })), del);
  });
  if (!keys.length) rows.push(el("p", { className: "muted", textContent: "No keys yet." }));
  const ta = el("textarea", { rows: 2, spellcheck: false, placeholder: "ssh-ed25519 AAAA… you@laptop  (contents of the .pub file)" });
  const add = el("button", { className: "btn", type: "button", textContent: "Add key" });
  const out = el("p", { className: "form-msg", role: "status" });
  add.addEventListener("click", async () => {
    out.classList.remove("err");
    try {
      const r = await api("POST", "access", { scope, key: ta.value });
      ta.value = "";
      out.textContent = `Added ${r.fingerprint}.`;
      onChange();
    } catch (e) {
      out.textContent = e.message;
      out.classList.add("err");
    }
  });
  box.replaceChildren(...rows, el("div", { className: "keyadd" }, ta, add), out);
}

async function loadWsSshAccess(w) {
  try {
    const acc = await api("GET", "access");
    if (current()?.name !== w.name) return;
    renderKeyList($("#acc-ssh-access"), w.name, acc.workspaces[w.name] || [], () => loadWsSshAccess(w));
    const t = `${acc.user}@${sshHost()}`, k = "-i ~/.ssh/<this key>";
    $("#acc-ssh-snippet").textContent =
      `ssh -t ${k} ${t}               # Claude session (C-b d detaches)\n` +
      `ssh -t ${k} ${t} shell         # shell in the sandbox\n` +
      `ssh ${k} ${t} 'git status'     # any command, in the sandbox\n` +
      `rsync -a -e "ssh ${k}" ./src/ ${t}:src/    # files (scp / sftp work too)`;
  } catch (e) {
    $("#acc-ssh-access").replaceChildren(el("p", { className: "form-msg err", textContent: e.message }));
  }
}

// ------------------------------------------------------------------ import

function fmtBytes(n) {
  if (n == null) return "";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i && n < 10 ? 1 : 0)} ${u[i]}`;
}

function importMsg(text, isErr = false) {
  $("#import-msg").textContent = text;
  $("#import-msg").classList.toggle("err", isErr);
}

function renderDrop(d) {
  const chips = [];
  if (d.history) chips.push(`${d.history.sessions} Claude session${d.history.sessions === 1 ? "" : "s"} from ${d.history.sourceHost}:${d.history.sourcePath}`);
  else if (!d.incomplete) chips.push("no Claude history");
  if (d.git) chips.push("git");
  if (d.claudeDir) chips.push(".claude/");
  if (d.claudeMd) chips.push("CLAUDE.md");
  if (d.size != null) chips.push(fmtBytes(d.size));
  const name = el("input", { value: d.suggested, required: true, pattern: "[a-z0-9][a-z0-9\\-]{0,29}", autocomplete: "off" });
  const dir = el("input", { placeholder: `~/projects/${d.suggested}`, autocomplete: "off" });
  name.addEventListener("input", () => (dir.placeholder = `~/projects/${name.value || "<name>"}`));
  const go = el("button", { className: "btn primary", type: "submit", textContent: "Import", disabled: d.incomplete });
  const del = el("button", { className: "btn ghost danger", type: "button", textContent: "Delete upload" });
  const out = el("p", { className: "form-msg", role: "status" });
  const form = el("form", { className: "drop" },
    el("div", { className: "drop-head" }, el("strong", { textContent: d.drop }),
      el("span", { className: "muted", textContent: ` · uploaded ${new Date(d.modified * 1000).toLocaleString()}` })),
    el("div", { className: "chips" }, ...chips.map((c) => el("span", { className: "chip", textContent: c })),
      ...(d.incomplete ? [el("span", { className: "pill warn", textContent: "upload incomplete — no manifest yet" })] : [])),
    el("div", { className: "row" },
      el("label", {}, "Workspace name", name), el("label", {}, el("span", {}, "Folder ", el("span", { className: "muted", textContent: "(optional)" })), dir),
      go, del),
    out);
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    go.disabled = del.disabled = true;
    out.classList.remove("err");
    out.textContent = "Importing… (moving files, starting the sandbox)";
    try {
      const r = await api("POST", `inbox/${encodeURIComponent(d.drop)}/import`, { name: name.value.trim(), dir: dir.value.trim() || undefined });
      const h = r.history;
      importMsg(`Imported ${d.drop} as ${r.name} (${r.dir})` +
        (h ? `, with ${h.sessions} Claude session${h.sessions === 1 ? "" : "s"}${h.prompts ? ` and ${h.prompts} prompts` : ""}` : "") +
        (r.notes.length ? `. ${r.notes.join(". ")}` : "") + ". Use /resume in its Claude tab to pick a conversation up.");
      await refresh();
      loadImport();
    } catch (e) {
      out.textContent = e.message;
      out.classList.add("err");
      go.disabled = del.disabled = false;
    }
  });
  del.addEventListener("click", async () => {
    if (!confirm(`Delete the upload ${d.drop} from the inbox? Its files are removed.`)) return;
    try { await api("DELETE", `inbox/${encodeURIComponent(d.drop)}`); importMsg(`Deleted ${d.drop}.`); }
    catch (e) { importMsg(e.message, true); }
    loadImport();
  });
  return form;
}

async function loadImport() {
  try {
    const [inbox, acc] = await Promise.all([api("GET", "inbox"), api("GET", "access")]);
    const list = $("#inbox-list");
    list.replaceChildren(...inbox.drops.map(renderDrop));
    if (!inbox.drops.length) list.append(el("p", { className: "muted", textContent: "Nothing in the inbox. Send a project with the steps below." }));
    renderKeyList($("#upload-keys"), "upload", acc.upload, loadImport);
    $("#import-snippet").textContent =
      `python3 export-claude-project . --to ${acc.user}@${sshHost()} -i ~/.ssh/sandboxes-upload`;
  } catch (e) {
    importMsg(e.message, true);
  }
}
$("#inbox-refresh").addEventListener("click", () => { importMsg(""); loadImport(); });

// ------------------------------------------------------------------ settings (monitoring)

const MON_SERVICES = { alloy: "Alloy", prometheus: "Prometheus", loki: "Loki", grafana: "Grafana" };

function monMsg(text, isErr = false) {
  $("#mon-msg").textContent = text;
  $("#mon-msg").classList.toggle("err", isErr);
}

function showMonLog(log) {
  $("#mon-log-wrap").hidden = !log;
  $("#mon-log").textContent = log || "";
}

function syncStackFields() {
  const stack = $("#mon-form").elements.MON_STACK.value;
  $$("[data-when-stack]").forEach((n) => (n.hidden = n.dataset.whenStack !== stack));
}

function renderMonStatus(st) {
  const box = $("#mon-status");
  box.replaceChildren();
  if (!st.configured) {
    box.append(el("span", { className: "pill", textContent: "Not set up — Save & apply starts it" }));
  } else {
    const local = st.settings.MON_STACK !== "0";
    const want = local ? Object.keys(MON_SERVICES) : ["alloy"];
    for (const svc of want) {
      const s = st.services.find((x) => x.name === svc);
      const state_ = s ? s.state : "absent";
      box.append(el("span", { className: `pill ${state_ === "running" ? "ok" : "bad"}`,
        title: s ? s.detail : "not created", textContent: `${MON_SERVICES[svc]} ${state_}` }));
    }
    const age = st.exporterAge;
    const fresh = age !== null && age < 90;
    box.append(el("span", { className: `pill ${fresh ? "ok" : "bad"}`,
      textContent: `exporter ${age === null ? "not running" : `updated ${age}s ago`}` }));
    box.append(el("span", { className: `pill ${st.telemetry ? "ok" : ""}`, textContent: `telemetry ${st.telemetry ? "on" : "off"}` }));
  }
  const url = st.settings.MONITORING_URL;
  const open = $("#mon-open");
  open.hidden = !url;
  if (url) open.href = url;
}

function fillMonForm(st) {
  const f = $("#mon-form").elements;
  for (const [k, v] of Object.entries(st.settings)) {
    if (k === "CLAUDE_TELEMETRY") f[k].checked = v !== "0";
    else if (k === "MON_STACK") f[k].value = v === "0" ? "0" : "1";
    else if (f[k]) f[k].value = v;
  }
  syncStackFields();
}

// ------------------------------------------------------------------ sign-in (Settings)

const b64u = {
  enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
  dec: (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4)), (c) => c.charCodeAt(0)),
};
const METHOD_LABEL = { password: "your password", passkey: "a passkey", token: "the login token" };
const when = (t) => (t ? new Date(t * 1000).toLocaleString() : "never");

function authMsg(sel, text, isErr = false) {
  $(sel).textContent = text;
  $(sel).classList.toggle("err", isErr);
}

async function loadAuth() {
  let a;
  try {
    a = await api("GET", "auth");
  } catch (e) {
    return authMsg("#auth-msg", e.message, true);
  }
  $("#auth-summary").textContent = `Signed in as ${a.user} with ${METHOD_LABEL[a.method] || a.method} since ${when(a.since)}. `
    + `${a.sessions} signed-in session${a.sessions === 1 ? "" : "s"} in all. `
    + (a.tokenLogin ? "The login token link also works (turn it off with AIO_TOKEN_LOGIN=0)." : "Token sign-in is off.");
  $("#auth-rp").textContent = a.rpId || "a hostname";
  $("#pk-pw").hidden = a.fresh;
  const rows = a.passkeys.map((p) => {
    const ren = el("button", { className: "btn ghost", type: "button", textContent: "Rename" });
    ren.addEventListener("click", async () => {
      const name = prompt("Passkey name", p.name);
      if (!name) return;
      try { await api("PATCH", `auth/passkeys/${encodeURIComponent(p.id)}`, { name }); } catch (e) { alert(e.message); }
      loadAuth();
    });
    const del = el("button", { className: "btn ghost danger", type: "button", textContent: "Remove" });
    del.addEventListener("click", async () => {
      if (!confirm(`Remove the passkey "${p.name}"? It stops working here at once (delete it from the device too).`)) return;
      try { await api("DELETE", `auth/passkeys/${encodeURIComponent(p.id)}`); } catch (e) { alert(e.message); }
      loadAuth();
    });
    const other = p.rp_id !== a.rpId ? ` · for ${p.rp_id}` : "";
    return el("div", { className: "keyrow" },
      el("div", {}, el("strong", { textContent: p.name }),
        el("div", { className: "muted", textContent: `Added ${when(p.created)} · last used ${when(p.last_used)}${other}` })),
      el("div", { className: "row" }, ren, del));
  });
  if (!rows.length) rows.push(el("p", { className: "muted", textContent: "No passkeys yet." }));
  $("#auth-passkeys").replaceChildren(...rows);
  const form = $("#pk-form");
  form.querySelector("button").disabled = !a.rpId || !window.PublicKeyCredential;
  if (a.rpError) authMsg("#pk-msg", a.rpError, true);
  else if (!window.PublicKeyCredential) authMsg("#pk-msg", "This browser can't create passkeys (or the page isn't on HTTPS).", true);
}

// The options call needs a recent password check: on 403 needPassword, ask for it
async function passkeyOptions(password) {
  const res = await fetch("/api/auth/passkeys/options", {
    method: "POST",
    headers: { "X-Requested-With": "sbui", "Content-Type": "application/json" },
    body: JSON.stringify(password ? { password } : {}),
  });
  if (res.status === 401) { location.reload(); throw new Error("Signed out"); }
  const data = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
  if (!res.ok) throw Object.assign(new Error(data.error || `HTTP ${res.status}`), { needPassword: !!data.needPassword });
  return data;
}

$("#pk-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const form = ev.target;
  const btn = form.querySelector("button");
  btn.disabled = true;
  authMsg("#pk-msg", "Follow your browser's prompt…");
  try {
    const opts = await passkeyOptions(form.elements.password.value);
    form.elements.password.value = "";
    $("#pk-pw").hidden = true;
    const pk = opts.publicKey;
    const cred = await navigator.credentials.create({ publicKey: {
      ...pk,
      challenge: b64u.dec(pk.challenge),
      user: { ...pk.user, id: b64u.dec(pk.user.id) },
      excludeCredentials: pk.excludeCredentials.map((c) => ({ ...c, id: b64u.dec(c.id) })),
    } });
    const r = cred.response;
    const res = await api("POST", "auth/passkeys", {
      challengeId: opts.challengeId,
      name: form.elements.name.value,
      credential: { id: cred.id, response: {
        clientDataJSON: b64u.enc(r.clientDataJSON),
        attestationObject: b64u.enc(r.attestationObject),
        transports: r.getTransports?.() || [],
      } },
    });
    form.elements.name.value = "";
    authMsg("#pk-msg", `Added "${res.passkey.name}". Sign in with it from the sign-in page on ${res.passkey.rp_id}.`);
  } catch (e) {
    if (e.needPassword) {
      $("#pk-pw").hidden = false;
      form.elements.password.focus();
    }
    const cancelled = e.name === "NotAllowedError" || e.name === "AbortError";
    const exists = e.name === "InvalidStateError";
    authMsg("#pk-msg", cancelled ? "Cancelled." : exists ? "This device already has a passkey here." : e.message, !cancelled);
  }
  btn.disabled = false;
  loadAuth();
});

$("#auth-logout").addEventListener("click", async () => {
  try { await api("POST", "auth/logout"); } catch { /* signed out anyway */ }
  location.reload();
});
$("#auth-logout-others").addEventListener("click", async () => {
  try {
    const r = await api("POST", "auth/logout-others");
    authMsg("#auth-msg", `Signed out ${r.ended} other session${r.ended === 1 ? "" : "s"}.`);
  } catch (e) { authMsg("#auth-msg", e.message, true); }
  loadAuth();
});

// ---- Keys & tokens: Google accounts (OAuth client, connected accounts)

function gMsg(text, isErr = false) {
  $("#g-msg").textContent = text;
  $("#g-msg").classList.toggle("err", isErr);
}

let googleState = null;      // the last GET google
async function loadGoogle() {
  let g;
  try { g = await api("GET", "google"); } catch (e) { return gMsg(e.message, true); }
  googleState = g;
  const kind = { web: "Web application", desktop: "Desktop app" }[g.clientType];
  $("#g-client-state").textContent = g.client ? `${kind} client ${g.clientId}` : "none yet: set one up first";
  $("#g-setup").open = !g.client;
  const cf = $("#g-client-form").elements;
  cf.client_id.value = g.clientId || "";
  if (!g.client) cf.type.value = g.callbackProblem ? "desktop" : "web";
  $("#g-callback").textContent = g.callback;
  $("#g-callback-problem").textContent = g.callbackProblem;
  $("#g-step-web").hidden = !!g.callbackProblem;
  $("#g-step-desktop").hidden = !g.callbackProblem;
  $("#g-redirect").textContent = g.redirect;

  // Connect: straight back here with a Web client (when Google allows this
  // page's name), else the paste-back way (a Desktop client)
  $("#g-connect-form").hidden = !g.client;
  const redirect = g.clientType === "web" && !g.callbackProblem;
  $("#g-signin").textContent = redirect ? "Sign in with Google" : "Open Google consent ↗";
  const hint = $("#g-connect-hint");
  hint.textContent = g.clientType === "web" && g.callbackProblem
    ? `${g.callbackProblem} A Web application client can only send you back to a page Google accepts; for this address, set up a Desktop app client instead.`
    : redirect && g.callbackListed === false
      ? `Your client's JSON doesn't list ${g.callback} as an authorized redirect URI: add it in Google Cloud Console (then save the client again), or Google will refuse the sign-in.`
      : "";
  hint.hidden = !hint.textContent;
  $("#g-signin").disabled = g.clientType === "web" && !!g.callbackProblem;

  const rows = g.accounts.map((a) => {
    const del = el("button", { className: "btn ghost danger", type: "button", textContent: "Disconnect" });
    del.addEventListener("click", async () => {
      if (!confirm(`Disconnect ${a.email}? Google revokes this app's access, and its grants are removed from every workspace.`)) return;
      try { await api("DELETE", `google/accounts/${encodeURIComponent(a.id)}`); gMsg(`Disconnected ${a.email}.`); }
      catch (e) { gMsg(e.message, true); }
      loadGoogle();
    });
    return el("div", { className: "keyrow" },
      el("div", {}, el("strong", { textContent: a.email || a.id }),
        el("div", { className: "muted mono", textContent: `${a.id} · ${a.scopes.join(", ") || "no API scopes"}` })), del);
  });
  if (!rows.length) rows.push(el("p", { className: "muted", textContent: "No Google accounts connected." }));
  $("#g-accounts").replaceChildren(...rows);
  const box = $("#g-scopes");
  if (!box.children.length) {
    box.append(...g.scopes.map((sc) => el("label", { className: "check" },
      el("input", { type: "checkbox", name: "scope", value: sc, checked: sc === "gmail.readonly" }),
      el("span", { textContent: sc }))));
  }
}

let googleConnectState = "";
$("#g-client-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.currentTarget.elements;
  try {
    const r = await api("PUT", "google/client", { json: f.json.value.trim() || undefined, client_id: f.client_id.value.trim(),
      client_secret: f.client_secret.value.trim(), type: f.type.value });
    f.client_secret.value = "";
    f.json.value = "";
    gMsg(`OAuth client saved (${r.type === "web" ? "Web application" : "Desktop app"}). Now connect an account.`);
  } catch (e) { gMsg(e.message, true); }
  loadGoogle();
});
$("#g-copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("#g-callback").textContent);
    gMsg("Copied the redirect URI.");
  } catch {
    getSelection().selectAllChildren($("#g-callback"));     // no clipboard over plain HTTP: select it
    gMsg("Selected: copy it with Ctrl+C / ⌘C.");
  }
});
async function googleConnect(redirect) {
  const scopes = $$('#g-scopes input:checked').map((i) => i.value);
  try {
    const r = await api("POST", "google/connect", { scopes, redirect });
    if (redirect) {
      gMsg("Taking you to Google…");
      location.assign(r.url);        // Google sends you back to this page
      return;
    }
    googleConnectState = r.state;
    window.open(r.url, "_blank", "noopener");
    $("#g-finish").hidden = false;
    gMsg("Allow access in the Google tab, then paste the address it ends on below.");
  } catch (e) { gMsg(e.message, true); }
}
$("#g-connect-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  googleConnect(googleState?.clientType === "web" && !googleState.callbackProblem);
});
$("#g-finish-btn").addEventListener("click", async () => {
  const f = $("#g-connect-form").elements;
  try {
    const r = await api("POST", "google/finish", { url: f.url.value.trim() });
    f.url.value = "";
    $("#g-finish").hidden = true;
    gMsg(`Connected ${r.email} (${r.scopes.join(", ") || "no API scopes granted"}). Create grants for it with + Add token (service Google).`);
    if (!$("#tok-google").hidden) showGoogleFields(true);
  } catch (e) { gMsg(e.message, true); }
  loadGoogle();
});
// Back from Google's sign-in (GET /oauth/google/callback sends you here)
function googleReturn() {
  const q = new URLSearchParams(location.search);
  if (!q.has("google") && !q.has("google_error")) return;
  if (q.has("google")) gMsg(`Connected ${q.get("google")}. Create grants for it with + Add token (service Google).`);
  else gMsg(q.get("google_error"), true);
  history.replaceState(null, "", location.pathname + location.hash);
  $("#google-card").scrollIntoView({ block: "center" });
}

async function loadSettings() {
  loadAuth();
  loadBuildHost();
  try {
    const st = await api("GET", "settings/monitoring");
    loadClaudeMd();
    loadBackup(true);
    renderMonStatus(st);
    fillMonForm(st);
    $("#ca-card").hidden = !st.caFingerprint;
    $("#ca-fp").textContent = st.caFingerprint || "";
  } catch (e) {
    monMsg(e.message, true);
  }
}

// sandbox notes appended to workspaces' CLAUDE.md
function showClaudeMd(res, msg) {
  $("#md-text").value = res.text;
  $("#md-state").textContent = res.custom ? "edited" : "default";
  $("#md-reset").disabled = !res.custom;
  $("#md-enabled").textContent = res.enabled.length
    ? `In the CLAUDE.md of: ${res.enabled.join(", ")}.` : "No workspace has Notes for Claude ticked yet.";
  $("#md-msg").textContent = res.errors?.length ? `${msg} Not updated: ${res.errors.join("; ")}` : msg;
  $("#md-msg").classList.toggle("err", !!res.errors?.length);
}

async function loadClaudeMd() {
  try { showClaudeMd(await api("GET", "settings/claude-md"), ""); } catch (e) { $("#md-msg").textContent = e.message; }
}

async function saveClaudeMd(reset) {
  if (reset && !confirm("Replace your edited notes with the default?")) return;
  $("#md-msg").classList.remove("err");
  $("#md-msg").textContent = "Saving…";
  try {
    const res = reset ? await api("DELETE", "settings/claude-md")
      : await api("PUT", "settings/claude-md", { text: $("#md-text").value });
    showClaudeMd(res, res.enabled.length ? "Saved; those workspaces' CLAUDE.md updated." : "Saved.");
  } catch (e) {
    $("#md-msg").textContent = e.message;
    $("#md-msg").classList.add("err");
  }
}
$("#md-form").addEventListener("submit", (ev) => { ev.preventDefault(); saveClaudeMd(false); });
$("#md-reset").addEventListener("click", () => saveClaudeMd(true));

function monValues() {
  const f = $("#mon-form").elements;
  const out = {};
  for (const n of ["MONITORING_URL", "PROM_WRITE_URL", "LOKI_URL", "GRAFANA_BIND", "GRAFANA_PORT",
    "GRAFANA_DOMAIN", "PROM_RETENTION", "PROM_RETENTION_SIZE", "LOKI_RETENTION"]) out[n] = f[n].value.trim();
  out.MON_STACK = f.MON_STACK.value;
  out.CLAUDE_TELEMETRY = f.CLAUDE_TELEMETRY.checked ? "1" : "0";
  return out;
}

async function monAction(kind) {
  const buttons = $$("#mon-form .sticky-save .btn");
  buttons.forEach((b) => (b.disabled = true));
  showMonLog("");
  try {
    if (kind !== "stop") {
      monMsg("Saving…");
      renderMonStatus(await api("PUT", "settings/monitoring", monValues()));
    }
    if (kind === "save") {
      monMsg("Saved. Apply to restart monitoring with these settings; telemetry changes apply when Claude restarts.");
    } else {
      monMsg(kind === "apply" ? "Applying… (pulling images can take a few minutes)" : "Stopping…");
      const res = await api("POST", `settings/monitoring/${kind}`);
      renderMonStatus(res);
      showMonLog(res.log);
      monMsg(kind === "apply" ? "Applied." : "Monitoring stopped. Data is kept.");
    }
  } catch (e) {
    monMsg(e.message.split("\n").slice(-3).join(" "), true);
    showMonLog(e.message);
  }
  buttons.forEach((b) => (b.disabled = false));
  refresh();
}

$("#mon-form").addEventListener("submit", (ev) => { ev.preventDefault(); monAction("save"); });
$("#mon-apply").addEventListener("click", () => monAction("apply"));
$("#mon-stop").addEventListener("click", () => {
  if (confirm("Stop monitoring? Collection stops; stored metrics and logs are kept.")) monAction("stop");
});
$("#mon-form").addEventListener("change", (ev) => { if (ev.target.name === "MON_STACK") syncStackFields(); });
$("#mon-pw").addEventListener("click", async () => {
  const out = $("#mon-pw-val");
  try {
    out.textContent = (await api("GET", "settings/monitoring/password")).password;
    out.hidden = false;
    $("#mon-pw").hidden = true;
  } catch (e) {
    monMsg(e.message, true);
  }
});

// ------------------------------------------------------------------ settings (backup)

let bkPoll = null;

function bkMsg(text, isErr = false) {
  $("#bk-msg").textContent = text;
  $("#bk-msg").classList.toggle("err", isErr);
}

function syncSchedFields() {
  const v = $("#bk-form").elements.schedule.value;
  $$("[data-when-sched]").forEach((n) => (n.hidden = !n.dataset.whenSched.split(" ").includes(v)));
}

function renderBackupStatus(st) {
  const box = $("#bk-status");
  box.replaceChildren();
  if (!st.smbclient) box.append(el("span", { className: "pill bad", textContent: "smbclient not installed — sudo apt install smbclient" }));
  if (st.running) box.append(el("span", { className: "pill warn", textContent: `backing up: ${st.running}…` }));
  const last = st.runs[0];
  if (last) {
    box.append(el("span", { className: `pill ${last.ok ? "ok" : "bad"}`, title: last.error || "",
      textContent: `last backup ${last.ok ? "ok" : "failed"} ${fmtTime(last.finished)}` }));
  }
  box.append(el("span", { className: `pill ${st.next ? "ok" : ""}`,
    textContent: st.next ? `next ${fmtTime(st.next)}` : "not scheduled" }));
  $("#bk-run").disabled = !!st.running;

  const runs = $("#bk-runs");
  runs.replaceChildren();
  if (!st.runs.length) {
    runs.append(el("tr", {}, el("td", { className: "note muted", textContent: "No backups yet." })));
  } else {
    runs.append(el("tr", {}, ...["Started", "", "Size", "Result"].map((t) => el("th", { textContent: t }))));
    for (const r of st.runs) {
      const notes = [r.ok ? `uploaded ${r.file}` : r.error];
      if (r.pruned?.length) notes.push(`pruned ${r.pruned.length}`);
      if (r.warnings?.length) notes.push(`${r.warnings.length} warning${r.warnings.length === 1 ? "" : "s"}`);
      runs.append(el("tr", { title: (r.warnings || []).join("\n") },
        el("td", { textContent: fmtTime(r.started) }),
        el("td", { className: "muted", textContent: r.trigger }),
        el("td", { className: "num", textContent: fmtBytes(r.size) }),
        el("td", {}, el("span", { className: `pill ${r.ok ? "ok" : "bad"}`, textContent: r.ok ? "ok" : "failed" }),
          " ", el("span", { className: "muted", textContent: notes.join(" · ") }))));
    }
  }
  clearInterval(bkPoll);
  bkPoll = st.running ? setInterval(async () => {
    if (state.view !== "settings") return clearInterval(bkPoll);
    try {
      const s2 = await api("GET", "settings/backup");
      renderBackupStatus(s2);
      if (!s2.running) {
        const r = s2.runs[0];
        if (r) bkMsg(r.ok ? `Backed up ${fmtBytes(r.size)} as ${r.file}.` : `Backup failed: ${r.error}`, !r.ok);
        loadRemote();
      }
    } catch (e) { /* keep polling */ }
  }, 2000) : null;
}

function fillBackupForm(st) {
  const f = $("#bk-form").elements, c = st.config;
  for (const k of ["server", "share", "dir", "domain", "username", "time", "keep_days"]) f[k].value = c[k];
  f.password.value = "";
  f.password.placeholder = c.password_set ? "saved — type to change" : "";
  $("#bk-forget").hidden = !c.password_set;
  for (const k of ["projects", "config", "claude"]) f[`inc-${k}`].checked = c.include[k];
  f.skip_rebuildable.checked = c.skip_rebuildable;
  f.schedule.value = c.schedule;
  f.weekday.value = String(c.weekday);
  const src = st.sources;
  const tilde = (ps) => ps.map((p) => p.replace(st.home, "~")).join(", ");
  $("#bk-src-projects").textContent = src.projects.length ? `(${src.projects.length}: ${tilde(src.projects)})` : "(none yet)";
  $("#bk-src-config").textContent = `(${tilde(src.config)})`;
  $("#bk-src-claude").textContent = `(${tilde(src.claude)})`;
  $("#bk-tz").textContent = ` (${st.tz})`;
  syncSchedFields();
}

async function loadBackup(fill) {
  try {
    const st = await api("GET", "settings/backup");
    if (fill) fillBackupForm(st);
    renderBackupStatus(st);
    if (st.config.server) loadRemote();
    else $("#bk-files").replaceChildren(el("tr", {}, el("td", { className: "note muted", textContent: "Set up the NAS above first." })));
  } catch (e) {
    bkMsg(e.message, true);
  }
}

function renderRemote(r) {
  $("#bk-free").textContent = r.free == null ? "" : `${fmtBytes(r.free)} free of ${fmtBytes(r.total)} on the share.`;
  const t = $("#bk-files");
  t.replaceChildren();
  if (!r.files.length) {
    t.append(el("tr", {}, el("td", { className: "note muted", textContent: "No backups in this folder yet." })));
    return;
  }
  t.append(el("tr", {}, ...["Backup", "Host", "Taken", "Size", ""].map((x) => el("th", { textContent: x }))));
  for (const f of r.files) {
    const del = el("button", { className: "btn ghost danger", type: "button", textContent: "Delete" });
    del.addEventListener("click", async () => {
      if (!confirm(`Delete ${f.name} from the NAS? This can't be undone.`)) return;
      try { renderRemote(await api("DELETE", `settings/backup/remote/${encodeURIComponent(f.name)}`)); bkMsg(`Deleted ${f.name}.`); }
      catch (e) { bkMsg(e.message, true); }
    });
    t.append(el("tr", {},
      el("td", { className: "item" }, el("span", { className: "mono", textContent: f.name }),
        ...(f.partial ? [" ", el("span", { className: "pill warn", textContent: "incomplete" })] : [])),
      el("td", { className: f.mine ? "" : "muted", textContent: f.host }),
      el("td", { textContent: fmtTime(f.at) }),
      el("td", { className: "num", textContent: fmtBytes(f.size) }),
      el("td", { className: "acts" }, del)));
  }
}

async function loadRemote() {
  $("#bk-free").textContent = "Listing the NAS folder…";
  try { renderRemote(await api("GET", "settings/backup/remote")); }
  catch (e) {
    $("#bk-free").textContent = "";
    $("#bk-files").replaceChildren(el("tr", {}, el("td", { className: "note err", textContent: e.message })));
  }
}

function backupValues() {
  const f = $("#bk-form").elements;
  const out = { include: {} };
  for (const k of ["server", "share", "dir", "domain", "username", "time", "schedule"]) out[k] = f[k].value.trim();
  if (f.password.value) out.password = f.password.value;
  for (const k of ["projects", "config", "claude"]) out.include[k] = f[`inc-${k}`].checked;
  out.skip_rebuildable = f.skip_rebuildable.checked;
  out.weekday = Number(f.weekday.value);
  out.keep_days = Number(f.keep_days.value);
  return out;
}

async function saveBackup(extra = {}) {
  const st = await api("PUT", "settings/backup", { ...backupValues(), ...extra });
  fillBackupForm(st);
  renderBackupStatus(st);
  return st;
}

async function backupAction(kind) {
  const buttons = $$("#bk-form .sticky-save .btn");
  buttons.forEach((b) => (b.disabled = true));
  bkMsg("Saving…");
  try {
    await saveBackup();
    if (kind === "save") bkMsg("Saved.");
    if (kind === "test") {
      bkMsg("Connecting to the NAS…");
      const r = await api("POST", "settings/backup/test");
      bkMsg(`Connected; the folder is ready${r.free == null ? "" : ` (${fmtBytes(r.free)} free)`}.`);
      renderRemote(r);
    }
    if (kind === "run") {
      renderBackupStatus(await api("POST", "settings/backup/run"));
      bkMsg("Backing up… you can leave this page; it carries on.");
    }
  } catch (e) {
    bkMsg(e.message, true);
  }
  buttons.forEach((b) => (b.disabled = false));
  loadBackup(false);
}

$("#bk-form").addEventListener("submit", (ev) => { ev.preventDefault(); backupAction("save"); });
$("#bk-test").addEventListener("click", () => backupAction("test"));
$("#bk-run").addEventListener("click", () => backupAction("run"));
$("#bk-form").addEventListener("change", (ev) => { if (ev.target.name === "schedule") syncSchedFields(); });
$("#bk-list").addEventListener("click", loadRemote);
$("#bk-forget").addEventListener("click", async () => {
  if (!confirm("Forget the saved NAS password?")) return;
  try { await saveBackup({ forget_password: true }); bkMsg("Password forgotten."); } catch (e) { bkMsg(e.message, true); }
});
$("#bk-prune").addEventListener("click", async () => {
  try {
    const r = await api("POST", "settings/backup/prune");
    renderRemote(r);
    bkMsg(r.pruned.length ? `Deleted ${r.pruned.length}: ${r.pruned.join(", ")}.` : "Nothing old enough to prune.");
  } catch (e) { bkMsg(e.message, true); }
});

// ------------------------------------------------------------------ guided Hermes setup

const GUIDE_STEPS = ["where", "model", "chat", "google", "network", "review"];
const CHAT_SERVICES = { telegram: ["telegram"], discord: ["discord"], slack: ["slack-bot", "slack-app"] };
const SERVICE_NAME = { openrouter: "OpenRouter", openai: "OpenAI", custom: "server", telegram: "Telegram bot",
  discord: "Discord bot", "slack-bot": "Slack bot", "slack-app": "Slack app" };
const MODEL_HINT = {
  pool: ["", "The model name that provider serves."],
  openrouter: ["e.g. anthropic/claude-sonnet-4.5", "OpenRouter's model ID, provider/model, as listed on openrouter.ai/models."],
  openai: ["e.g. gpt-4.1", "An OpenAI model name."],
  custom: ["e.g. qwen3-32b", "A model your server serves (its /v1/models list)."],
  keyless: ["e.g. llama3.1:8b", "A model your server serves (for Ollama, as `ollama list` shows it)."],
};
// guide.run: what the Create step has done so far, so a retry carries on from there
const guide = { step: 0, status: null, pool: null, run: null };
const gf = $("#guide-form");
const gEl = gf.elements;

function guideMsg(text, isErr = false) {
  $("#guide-msg").textContent = text;
  $("#guide-msg").classList.toggle("err", isErr);
}

// A pool token id that isn't taken: <workspace>-<what>
function freeTokenId(base, taken) {
  base = base.toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 36) || "token";
  let id = base;
  for (let i = 2; taken.has(id); i++) id = `${base}-${i}`;
  taken.add(id);
  return id;
}
const envFromId = (id) => `${id.toUpperCase().replace(/-/g, "_").replace(/^(\d)/, "LLM_$1")}_API_KEY`;

async function loadGuide() {
  if (guide.run?.done) resetGuide();
  showGuideStep(guide.step);
  try {
    [guide.status, guide.pool] = await Promise.all([api("GET", "setup/hermes"), api("GET", "pool")]);
  } catch (e) {
    guideMsg(/not found/i.test(e.message)
      ? "The web UI service is running older code than these pages: restart it (Host page, or sudo systemctl restart agent-sandboxes-ui), then reload."
      : `Couldn't load this host's status: ${e.message}`, true);
    $("#guide-next").disabled = true;
    return;
  }
  const st = guide.status;
  for (const kind of ["sandbox", "microvm"]) {
    const problems = st[kind];
    const box = $(`[data-ready="${kind}"]`);
    const radio = $(`#guide-kinds input[value="${kind}"]`);
    radio.disabled = problems.length > 0;
    box.className = `guide-ready ${problems.length ? "warn" : "ok"}`;
    box.replaceChildren(problems.length ? `Not ready: ${problems.join("; ")}.` : "Ready on this host.");
    if (problems.length && kind === "sandbox") {
      const b = el("button", { type: "button", className: "linkish", textContent: "Open the Host page to run it" });
      b.addEventListener("click", () => showPage("host"));
      box.append(" ", b);
    }
  }
  if (!gf.querySelector('input[name="kind"]:checked:not(:disabled)')) {
    const first = gf.querySelector('input[name="kind"]:not(:disabled)');
    if (first) first.checked = true;
  }
  guideDirPlaceholder();

  // Model: keys already in the pool
  const llms = guide.pool.tokens.filter((t) => LLM_SERVICES.includes(t.service));
  const sel = $("#guide-llm-pool");
  const was = sel.value;
  sel.replaceChildren(...llms.map((t) => el("option", { value: t.id, textContent: `${t.id} (${t.label})` })));
  if (was) sel.value = was;
  $("#guide-llm-pool-wrap").hidden = !llms.length;
  if (!gf.querySelector('input[name="llm_kind"]:checked'))
    gf.querySelector(`input[name="llm_kind"][value="${llms.length ? "pool" : "openrouter"}"]`).checked = true;

  // Chat: an existing token of that kind, or a new one
  for (const span of $$(".guide-tok", gf)) {
    const service = span.dataset.service;
    const have = guide.pool.tokens.filter((t) => t.service === service);
    const prev = gEl[`tok_${service}`]?.value;
    const typed = gEl[`tok_${service}_new`]?.value || "";
    const pick = el("select", { name: `tok_${service}` },
      ...have.map((t) => el("option", { value: t.id, textContent: `${t.id} (in the pool)` })),
      el("option", { value: "", textContent: "A new token…" }));
    pick.hidden = !have.length;
    pick.value = prev ?? (have[0]?.id || "");
    const input = el("input", { name: `tok_${service}_new`, type: "password", spellcheck: false, value: typed,
      placeholder: service === "slack-bot" ? "xoxb-…" : service === "slack-app" ? "xapp-…" : "" });
    const sync = () => (input.hidden = !!pick.value);
    pick.addEventListener("change", sync);
    sync();
    span.replaceChildren(pick, input);
  }

  // Google grants already made
  const box = $("#guide-google");
  const grants = guide.pool.tokens.filter((t) => t.service === "google");
  const ticked = new Set($$('input[name="google"]:checked', gf).map((i) => i.value));
  box.replaceChildren(...grants.map((t) => checkItem("google", t.id, ticked.has(t.id), t.id, t.detail || t.label)));
  if (!grants.length) {
    const g = st.google;
    const p = el("p", { className: "hint" }, !g.client
      ? "No Google OAuth client yet: add yours under Keys & tokens → Google accounts, connect an account, then make a grant there (+ Add token, service Google). "
      : !g.accounts ? "No Google account connected yet: connect one under Keys & tokens → Google accounts, then make a grant there (+ Add token, service Google). "
        : "No grants yet: make one under Keys & tokens (Add token → Google grant). ");
    const toPool = el("button", { type: "button", className: "btn", textContent: "Keys & tokens" });
    toPool.addEventListener("click", () => showPage("pool"));
    box.append(p, el("div", { className: "row" }, toPool),
      el("p", { className: "hint", textContent: "Your answers here are kept while you do that; come back with the guided setup button. Or skip this: grants can be added in the Access tab later." }));
  }
  guideModelChanged();
  guideChatChanged();
  showGuideStep(guide.step);
}

function guideDirPlaceholder() {
  const name = gEl.name.value.trim() || "<name>";
  $("#guide-dir").placeholder = `${guide.status?.projects || "~/projects"}/${name}`.replace(/^\/home\/[^/]+/, "~");
}
gEl.name.addEventListener("input", guideDirPlaceholder);

function guideModelChanged() {
  const kind = gEl.llm_kind.value;
  for (const lab of $$("[data-llm]", gf)) lab.hidden = !lab.dataset.llm.split(" ").includes(kind);
  const [ph, hint] = MODEL_HINT[kind] || ["", ""];
  $("#guide-model").placeholder = ph;
  $("#guide-model-hint").textContent = hint;
}
$$('input[name="llm_kind"]', gf).forEach((r) => r.addEventListener("change", guideModelChanged));
$("#guide-llm-pool").addEventListener("change", () => (gEl.llm_kind.value = "pool"));

const chatPicked = () => Object.keys(CHAT_SERVICES).filter((p) => gEl[`chat_${p}`].checked);
function guideChatChanged() {
  for (const box of $$(".guide-chat", gf)) $(".guide-chat-body", box).hidden = !gEl[`chat_${box.dataset.platform}`].checked;
  $("#guide-gw-wrap").hidden = !chatPicked().length;
}
$$('.guide-chat input[type="checkbox"]', gf).forEach((c) => c.addEventListener("change", guideChatChanged));

function showGuideStep(i) {
  guide.step = i;
  const step = GUIDE_STEPS[i];
  for (const sec of $$(".guide-step", gf)) sec.hidden = sec.dataset.step !== step;
  $("#guide-steps").replaceChildren(...GUIDE_STEPS.map((s, j) => {
    const title = $(`.guide-step[data-step="${s}"]`).dataset.title;
    const b = el("button", { type: "button", textContent: `${j + 1}. ${title}`, disabled: j > i || !!guide.run?.done });
    b.addEventListener("click", () => { guideMsg(""); showGuideStep(j); });
    return el("li", { className: j < i ? "done" : j === i ? "current" : "" }, b);
  }));
  const running = !!guide.run?.busy;
  $("#guide-back").hidden = i === 0 || !!guide.run?.done;
  $("#guide-back").disabled = running;
  $("#guide-next").hidden = !!guide.run?.done;
  $("#guide-next").disabled = running;
  $("#guide-next").textContent = step !== "review" ? "Next" : guide.run?.failed ? "Try again" : "Create";
  $("#guide-open").hidden = !guide.run?.done;
  if (step === "network") guidePrefillAllow();
  if (step === "review") guideSummary();
}

// The keyless server (and an https:// one with a key) must be on the allowlist;
// an http:// one with a key goes through the bridge instead
function guidePrefillAllow() {
  const kind = gEl.llm_kind.value;
  const url = gEl.llm_url.value.trim();
  if (!(kind === "keyless" || (kind === "custom" && url.startsWith("https://")))) return;
  let entry;
  try {
    const u = new URL(url);
    entry = u.port ? `${u.hostname}:${u.port}` : u.hostname;
  } catch { return; }
  const have = lines(gEl.allow.value);
  if (!have.includes(entry)) gEl.allow.value = [...have, entry].join("\n");
}

function guideValidate(step) {
  const v = (n) => gEl[n].value.trim();
  if (step === "where") {
    const name = v("name");
    if (!/^[a-z0-9][a-z0-9-]{0,29}$/.test(name)) return "Name: lowercase letters, digits and dashes (up to 30).";
    if (state.workspaces.some((w) => w.name === name) && guide.run?.name !== name) return `There's already a workspace called ${name}.`;
    if (!gf.querySelector('input[name="kind"]:checked:not(:disabled)'))
      return "Neither kind can run on this host yet: see what's missing above.";
  }
  if (step === "model") {
    const kind = gEl.llm_kind.value;
    if (kind === "pool" && !v("llm_pool")) return "Pick a key from the pool.";
    if (["custom", "keyless"].includes(kind)) {
      try {
        if (!/^https?:$/.test(new URL(v("llm_url")).protocol)) throw new Error();
      } catch { return "Server URL: http:// or https://, e.g. http://192.168.1.20:11434/v1"; }
    }
    if (["openrouter", "openai", "custom"].includes(kind) && !v("llm_key")) return "Paste the API key.";
    if (!v("model")) return "Model: the model name to use (see the hint below it).";
  }
  if (step === "chat") {
    for (const p of chatPicked()) {
      for (const service of CHAT_SERVICES[p]) {
        if (!gEl[`tok_${service}`].value && !gEl[`tok_${service}_new`].value.trim())
          return `${SERVICE_NAME[service]}: paste its token.`;
      }
      if (!lines(v(`users_${p}`)).length)
        return `${p[0].toUpperCase() + p.slice(1)}: list at least one user ID. Hermes refuses everyone not listed.`;
    }
  }
  return "";
}

function guideSummary() {
  const v = (n) => gEl[n].value.trim();
  const kind = gEl.kind.value;
  const llm = gEl.llm_kind.value;
  const provider = llm === "pool" ? `${v("llm_pool")} (from the pool)` : llm === "keyless" ? `${v("llm_url")} (no key)`
    : llm === "custom" ? `${v("llm_url")}, with its key` : SERVICE_NAME[llm];
  const chats = chatPicked();
  const google = $$('input[name="google"]:checked', gf).map((i) => i.value);
  const allow = lines(v("allow"));
  const item = (k, val) => el("li", {}, el("strong", { textContent: `${k}: ` }), val);
  $("#guide-summary").replaceChildren(
    item("Workspace", `${v("name")}, ${kind === "microvm" ? "microVM" : "sandbox"}, folder ${v("dir") || $("#guide-dir").placeholder}`),
    item("Model", `${v("model")} via ${provider}`),
    item("Chat", chats.length ? chats.map((p) => `${p} (users ${lines(v(`users_${p}`)).join(", ")})`).join("; ") : "none (terminal only)"),
    item("Google", google.length ? google.join(", ") : "none"),
    item("Network", `LLM provider APIs${chats.length ? ", the chat platforms" : ""}${allow.length ? `, ${allow.join(", ")}` : ""}`));
  guideChatChanged();
}

gf.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const step = GUIDE_STEPS[guide.step];
  const problem = guideValidate(step);
  if (problem) { guideMsg(problem, true); return; }
  guideMsg("");
  if (step !== "review") { showGuideStep(guide.step + 1); return; }
  await guideCreate();
});
$("#guide-back").addEventListener("click", () => { guideMsg(""); showGuideStep(Math.max(0, guide.step - 1)); });
$("#guide-open").addEventListener("click", () => {
  const name = guide.run.name;
  resetGuide();
  select(name);
  selectTab("claude");
});
$("#empty-guide").addEventListener("click", () => showPage("guide"));

function resetGuide() {
  gf.reset();
  guide.run = null;
  guide.step = 0;
  $("#guide-progress").replaceChildren();
  guideMsg("");
}

async function guideCreate() {
  const v = (n) => gEl[n].value.trim();
  const name = v("name");
  if (guide.run && guide.run.name !== name) guide.run = null;      // renamed after a failed try: start over
  const run = guide.run ||= { name, tokens: {}, done: false };
  run.busy = true;
  run.failed = false;
  const kind = gEl.kind.value;
  const llmKind = gEl.llm_kind.value;
  const chats = chatPicked();
  const taken = new Set([...guide.pool.tokens.map((t) => t.id), ...Object.values(run.tokens)]);

  // New keys and tokens for the pool: [what, service, secret, extra]
  const newTokens = [];
  if (["openrouter", "openai", "custom"].includes(llmKind)) newTokens.push(["llm", llmKind, v("llm_key")]);
  for (const p of chats) {
    for (const service of CHAT_SERVICES[p]) {
      if (!gEl[`tok_${service}`].value) newTokens.push([service, service, v(`tok_${service}_new`)]);
    }
  }
  const tasks = [[`Create the workspace and start its ${kind === "microvm" ? "VM (the first start copies its image: minutes)" : "container"}`,
    async () => { if (!run.ws) { await api("POST", "workspaces", { name, dir: v("dir") || undefined, kind, agent: "hermes" }); run.ws = true; } }]];
  for (const [what, service, secret] of newTokens) {
    tasks.push([`Add the ${SERVICE_NAME[service]} ${what === "llm" ? "key" : "token"} to the pool`, async () => {
      if (run.tokens[what]) return;
      const id = freeTokenId(`${name}-${what === "llm" ? (service === "custom" ? "llm" : service) : service}`, taken);
      await api("POST", "pool/tokens", { id, service, secret,
        custom: service === "custom" ? { upstream: v("llm_url"), header: "Authorization", format: "Bearer {}", env_var: envFromId(id) } : undefined });
      run.tokens[what] = id;
    }]);
  }
  tasks.push(["Give it the model, chat and Google access, and the network allowlist", async () => {
    const { policy: pol } = await api("GET", wsPath(name, "/policy"));
    const llm = llmKind === "pool" ? v("llm_pool") : llmKind === "keyless" ? "" : run.tokens.llm;
    const tokens = new Set(pol.tokens);
    if (llm) tokens.add(llm);
    for (const p of chats) for (const service of CHAT_SERVICES[p]) tokens.add(gEl[`tok_${service}`].value || run.tokens[service]);
    for (const i of $$('input[name="google"]:checked', gf)) tokens.add(i.value);
    pol.tokens = [...tokens];
    pol.hermes = { llm, base_url: llmKind === "keyless" ? v("llm_url") : "", model: v("model"),
      allowed_users: Object.fromEntries(Object.keys(CHAT_SERVICES).map((p) => [p, chats.includes(p) ? lines(v(`users_${p}`)).join(",") : ""])) };
    pol.network.allow = [...new Set([...pol.network.allow, ...lines(v("allow"))])];
    await api("PUT", wsPath(name, "/policy"), pol);
  }]);
  if (gEl.start.checked) {
    tasks.push([kind === "microvm" ? "Start Hermes (in a new VM it installs first: a few minutes)" : "Start Hermes",
      async () => { if (!run.started) { await api("POST", wsPath(name, "/claude/start")); run.started = true; } }]);
  }
  if (chats.length && gEl.gateway.checked) {
    tasks.push(["Start the chat gateway",
      async () => { if (!run.gateway) { await api("POST", wsPath(name, "/gateway/start")); run.gateway = true; } }]);
  }

  const items = tasks.map(([label]) => el("li", { textContent: label }));
  $("#guide-progress").replaceChildren(...items);
  showGuideStep(guide.step);
  guideMsg("Working…");
  for (const [i, [, fn]] of tasks.entries()) {
    items[i].className = "busy";
    try {
      await fn();
      items[i].className = "ok";
    } catch (e) {
      items[i].className = "bad";
      items[i].append(el("div", { className: "muted", textContent: e.message }));
      run.busy = false;
      run.failed = true;
      guideMsg("That step failed: fix it (Back changes your answers), then Try again; done steps aren't repeated.", true);
      showGuideStep(guide.step);
      await refresh();
      return;
    }
  }
  run.busy = false;
  run.done = true;
  showGuideStep(guide.step);
  guideMsg(`${name} is set up.${chats.length ? " Message your bot to try it." : ""}`);
  await refresh();
}

// ------------------------------------------------------------------ a Hermes workspace's setup checklist

const setupHidden = (name) => { try { return localStorage.getItem(`setup-hidden:${name}`) === "1"; } catch { return false; } };

function renderSetup(w) {
  const box = $("#d-setup");
  const s = w.setup;
  if (w.agent !== "hermes" || !s || setupHidden(w.name)) { box.hidden = true; return; }
  const gw = w.gateway === "unknown" ? gatewayState[w.name] : w.gateway;
  const access = () => selectTab("access");
  // [done, text, action label, action]
  const items = [
    [s.model && !!s.modelName, s.model && s.modelName ? `Model: ${s.modelName}` : "Choose its model provider and model", "Access tab", access],
    [w.claude === "running", "Start Hermes", "Start", "claude/start"],
    ...s.chat.map((p) => {
      const name = p[0].toUpperCase() + p.slice(1);
      return s.allowed.includes(p) ? [true, `${name}: allowed users set`]
        : [false, `${name}: list who may talk to the bot (Hermes refuses everyone until you do)`, "Access tab", access];
    }),
  ];
  if (s.chat.length) items.push([gw === "running", `Start the chat gateway (${s.chat.join(", ")})`, "Start", "gateway/start"]);
  if (items.every(([done]) => done)) { box.hidden = true; return; }
  box.hidden = false;
  const hide = el("button", { type: "button", className: "btn ghost", textContent: "Hide" });
  hide.addEventListener("click", () => {
    try { localStorage.setItem(`setup-hidden:${w.name}`, "1"); } catch { /* shown again next time */ }
    box.hidden = true;
  });
  box.replaceChildren(
    el("div", { className: "setup-head" }, el("strong", { textContent: "Finish setting up Hermes" }), hide),
    el("ul", {}, ...items.map(([done, text, label, action]) => {
      const li = el("li", { className: done ? "ok" : "" }, el("span", { textContent: text }));
      if (!done) {
        const b = el("button", { type: "button", className: "btn", textContent: label });
        if (typeof action === "string") b.dataset.act = action;
        else b.addEventListener("click", action);
        li.append(b);
      }
      return li;
    })));
}

// ------------------------------------------------------------------ boot (keep last: it uses everything above)

window.addEventListener("hashchange", () => {
  const view = VIEW_OF_HASH[location.hash];
  if (view) return state.view !== view && showPage(view);
  const name = decodeURIComponent(location.hash.slice(1));
  if (name && (name !== state.selected || state.view !== "ws")) select(name);
});

if (state.view in PAGE_LOAD) PAGE_LOAD[state.view]();
googleReturn();
refresh();
setInterval(refresh, 4000);
document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
