"use strict";

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const POOL_HASH = "#~keys";
const SETTINGS_HASH = "#~settings";
const IMPORT_HASH = "#~import";
const VIEW_OF_HASH = { [POOL_HASH]: "pool", [SETTINGS_HASH]: "settings", [IMPORT_HASH]: "import" };
const PAGES = { pool: "#pool", import: "#import", settings: "#settings" };   // view -> section
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
  const page = state.view in PAGES;
  for (const [view, sel] of Object.entries(PAGES)) {
    $(sel).hidden = state.view !== view;
    $(`${sel}-btn`).setAttribute("aria-current", String(state.view === view));
  }
  const w = page ? null : current();
  $("#empty").hidden = !!w || page;
  $("#detail").hidden = !w;
  if (!w) { disconnectTerm(); return; }

  $("#d-name").textContent = w.name;
  $("#d-dir").textContent = w.dir;
  $$(".d-dir-inline").forEach((el) => (el.textContent = w.dir));
  $("#d-port").textContent = w.port;
  setPill($("#d-container"), "container", w.container, CONTAINER_TONE[w.container]);
  setPill($("#d-claude"), "Claude", w.claude, CLAUDE_TONE[w.claude]);
  $("#d-pending").hidden = !w.policyPending;

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
}

const PAGE_LOAD = { pool: () => loadPool(), import: () => loadImport(), settings: () => loadSettings() };

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
  if (tab === "access") loadAccess();
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
    const tok = $("#acc-tokens");
    tok.replaceChildren(...pool.tokens.map((t) =>
      checkItem("token", t.id, policy.tokens.includes(t.id), t.id, `${t.label} → $${t.env_var}`)));
    if (!pool.tokens.length) tok.append(el("p", { className: "muted", textContent: "No API tokens in the pool yet — add one under Keys & tokens." }));
    $("#acc-net").replaceChildren(...Object.entries(pool.netModes).map(([mode, desc]) =>
      el("label", { className: "check" }, el("input", { type: "radio", name: "mode", value: mode, checked: policy.network.mode === mode }),
        el("span", {}, el("strong", { textContent: mode }), " ", el("span", { className: "muted", textContent: desc })))));
    form.elements.allow.value = policy.network.allow.join("\n");
    form.elements.deny.value = policy.network.deny.join("\n");
    form.elements.memory.value = policy.limits.memory;
    form.elements.pids.value = policy.limits.pids || "";
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
  const body = {
    ssh_keys: $$('input[name="ssh"]:checked', form).map((i) => i.value),
    tokens: $$('input[name="token"]:checked', form).map((i) => i.value),
    network: { mode: form.elements.mode?.value || "claude-code", allow: lines(form.elements.allow.value), deny: lines(form.elements.deny.value) },
    limits: { memory: form.elements.memory.value.trim(), pids: Number(form.elements.pids.value || 0) },
  };
  out.textContent = "Saving…";
  try {
    const res = await api("PUT", wsPath(w.name, "/policy"), body);
    if (restart) {
      out.textContent = "Saved. Restarting Claude…";
      await api("POST", wsPath(w.name, "/claude/restart"));
      disconnectTerm();
      out.textContent = "Saved and Claude restarted with the new policy.";
    } else {
      out.textContent = res.pending
        ? "Saved. SSH key changes are live; restart Claude for the rest."
        : w.claude === "stopped" ? "Saved. Applies when Claude starts." : "Saved and applied.";
    }
  } catch (e) {
    out.textContent = e.message;
    out.classList.add("err");
  }
  await refresh();
}
$("#access-form").addEventListener("submit", (ev) => { ev.preventDefault(); saveAccess(false); });
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
          poolMsg(kind === "ssh" ? `${it.id}: applied to running sessions.` : `${it.id}: restart Claude in ${n} to apply.`);
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
  renderMatrix($("#m-ssh"), "ssh", poolData.ssh, (k) => `${k.type} ${k.fingerprint} · ${k.comment}`);
  renderMatrix($("#m-tokens"), "tokens", poolData.tokens, (t) => `${t.label} (${t.upstream}) → $${t.env_var}`
    + (t.upstream.startsWith("http://") ? ` · call it via $${baseUrlVar(t.id)}` : ""));
  const sel = $("#tok-service");
  if (!sel.options.length) {
    for (const [k, v] of Object.entries(poolData.services)) sel.append(el("option", { value: k, textContent: `${v.label} → $${v.env_var}` }));
    sel.append(el("option", { value: "custom", textContent: "Custom HTTP(S) API…" }));
  }
}

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

$("#tok-service").addEventListener("change", (ev) => ($("#tok-custom").hidden = ev.target.value !== "custom"));

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
  submitAdd(ev.currentTarget, "pool/tokens", { id: f.id.value.trim(), service, secret: f.secret.value,
    custom: service === "custom" ? { upstream: f.upstream.value.trim(), header: f.header.value.trim(),
      format: f.format.value.trim(), env_var: f.env_var.value.trim() } : undefined });
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

async function loadSettings() {
  try {
    const st = await api("GET", "settings/monitoring");
    renderMonStatus(st);
    fillMonForm(st);
    $("#ca-card").hidden = !st.caFingerprint;
    $("#ca-fp").textContent = st.caFingerprint || "";
  } catch (e) {
    monMsg(e.message, true);
  }
}

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

// ------------------------------------------------------------------ boot

window.addEventListener("hashchange", () => {
  const view = VIEW_OF_HASH[location.hash];
  if (view) return state.view !== view && showPage(view);
  const name = decodeURIComponent(location.hash.slice(1));
  if (name && (name !== state.selected || state.view !== "ws")) select(name);
});

if (state.view in PAGE_LOAD) PAGE_LOAD[state.view]();
refresh();
setInterval(refresh, 4000);
document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
