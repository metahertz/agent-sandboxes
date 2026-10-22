"use strict";

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const state = {
  workspaces: [],
  selected: decodeURIComponent(location.hash.slice(1)) || null,
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
    b.setAttribute("aria-current", String(w.name === state.selected));
    b.innerHTML = `<span class="n"></span><span class="dots"><span class="dot" title="container"></span><span class="dot" title="Claude"></span></span><span class="sub"></span>`;
    $(".n", b).textContent = w.name;
    $(".sub", b).textContent = w.dir.replace(/^\/home\/[^/]+/, "~");
    const [dc, dl] = $$(".dot", b);
    dc.classList.add(CONTAINER_TONE[w.container] || "none");
    dc.title = `Container: ${w.container}`;
    dl.classList.add(CLAUDE_TONE[w.claude] || "none");
    dl.title = `Claude: ${w.claude}`;
    b.addEventListener("click", () => select(w.name));
    list.append(b);
  }
}

function setPill(el, label, value, tone) {
  el.className = `pill ${tone || ""}`;
  el.textContent = `${label}: ${value}`;
}

function renderDetail() {
  const w = current();
  $("#empty").hidden = !!w;
  $("#detail").hidden = !w;
  if (!w) { disconnectTerm(); return; }

  $("#d-name").textContent = w.name;
  $("#d-dir").textContent = w.dir;
  $$(".d-dir-inline").forEach((el) => (el.textContent = w.dir));
  $("#d-port").textContent = w.port;
  setPill($("#d-container"), "container", w.container, CONTAINER_TONE[w.container]);
  setPill($("#d-claude"), "Claude", w.claude, CLAUDE_TONE[w.claude]);

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
    ? "Claude isn't running in this workspace."
    : "Claude isn't running. Start the container first so it can use the browser.";
  if (state.tab === "claude" && w.claude !== "stopped") ensureTerm(w);
  if (w.claude === "stopped" && term.for === w.name) disconnectTerm();

  // Browser tab
  // Sandbox-backed tabs (browser, VS Code, container terminal)
  for (const tab of Object.keys(FRAMES)) {
    $(`[data-panel="${tab}"] .overlay`).hidden = up;
    if (!up && state.frameFor[tab]) clearFrame(tab);
  }
  if (up && FRAMES[state.tab] && state.frameFor[state.tab] !== w.name) loadFrame(state.tab, w);
}

function select(name) {
  if (state.selected !== name) {
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
}

// ------------------------------------------------------------------ actions

function msg(text, isErr = false) {
  const el = $("#action-msg");
  el.textContent = text;
  el.classList.toggle("err", isErr);
}

const ACT_LABEL = {
  "container/start": "Starting container…", "container/stop": "Stopping container…",
  "claude/start": "Starting Claude…", "claude/restart": "Restarting Claude…", "claude/stop": "Stopping Claude…",
};

document.addEventListener("click", async (ev) => {
  const btn = ev.target.closest("[data-act]");
  if (!btn) return;
  const w = current();
  if (!w) return;
  const act = btn.dataset.act;
  $$("[data-act]").forEach((b) => (b.disabled = true));
  msg(ACT_LABEL[act] || "Working…");
  try {
    await api("POST", wsPath(w.name, `/${act}`));
    msg("");
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
$("#new-cancel").addEventListener("click", () => {
  newForm.hidden = true;
  $("#new-toggle").hidden = false;
  $("#new-msg").textContent = "";
});
newForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const name = newForm.elements.name.value.trim();
  const dir = newForm.elements.dir.value.trim();
  const out = $("#new-msg");
  out.classList.remove("err");
  out.textContent = "Creating workspace and starting its container…";
  $$("button", newForm).forEach((b) => (b.disabled = true));
  try {
    const res = await api("POST", "workspaces", { name, dir: dir || undefined });
    newForm.reset();
    newForm.hidden = true;
    $("#new-toggle").hidden = false;
    out.textContent = "";
    await refresh();
    select(res.name);
    msg(res.notes?.length ? res.notes.join(" · ") : `Created ${res.name}. Start Claude when you're ready.`);
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

// ------------------------------------------------------------------ logs

async function loadLogs() {
  const w = current();
  if (!w) return;
  $("#logs").textContent = "Loading…";
  try {
    const { log } = await api("GET", wsPath(w.name, "/logs"));
    const el = $("#logs");
    el.textContent = log || "(no output)";
    el.scrollTop = el.scrollHeight;
  } catch (e) {
    $("#logs").textContent = e.message;
  }
}
$("#logs-refresh").addEventListener("click", loadLogs);

// ------------------------------------------------------------------ boot

window.addEventListener("hashchange", () => {
  const name = decodeURIComponent(location.hash.slice(1));
  if (name && name !== state.selected) select(name);
});

refresh();
setInterval(refresh, 4000);
document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
