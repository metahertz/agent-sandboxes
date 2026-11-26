"use strict";

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const POOL_HASH = "#~keys";
const SETTINGS_HASH = "#~settings";
const IMPORT_HASH = "#~import";
const HOST_HASH = "#~host";
const WORKERS_HASH = "#~workers";
const VIEW_OF_HASH = { [POOL_HASH]: "pool", [SETTINGS_HASH]: "settings", [IMPORT_HASH]: "import", [HOST_HASH]: "host", [WORKERS_HASH]: "workers" };
const PAGES = { pool: "#pool", import: "#import", host: "#host", workers: "#workers", settings: "#settings" };   // view -> section
const state = {
  workspaces: [],
  view: VIEW_OF_HASH[location.hash] || "ws",
  selected: VIEW_OF_HASH[location.hash] ? null : decodeURIComponent(location.hash.slice(1)) || null,
  tab: "claude",
  filesPath: {},          // per-workspace current folder in the Files tab
  frameFor: {},           // tab -> workspace its sandbox iframe is showing
};
const shareSeen = { guests: "" };   // the Share tab reloads when its workspace's guests change

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
  noteSeen();
  renderList();
  renderDetail();
}

// ------------------------------------------------------------------ sidebar: activity, filter, sort, groups

// Per-browser preferences (localStorage can be blocked: then they last until reload).
const prefs = {
  read(k, dflt) {
    try { const v = JSON.parse(localStorage.getItem(`aio-${k}`)); return v ?? dflt; } catch { return dflt; }
  },
  write(k, v) {
    try { localStorage.setItem(`aio-${k}`, JSON.stringify(v)); } catch { /* private mode */ }
  },
};
const side = {
  filter: "",
  sort: prefs.read("sort", "name") === "activity" ? "activity" : "name",
  compact: prefs.read("compact", false) === true,
  pinned: new Set(prefs.read("pinned", [])),
  collapsed: new Set(prefs.read("collapsed", [])),
  // workspace -> the newest tmux activity / bell time you've seen (the host's clock, so no skew)
  seen: prefs.read("seen", {}),
};
const WORKING_SECS = 8;     // output this recent: Claude is working (it redraws while it does)
const lastTime = (w) => Math.max(w.term?.activity || 0, w.term?.bell || 0);
const viewing = (name) => state.view === "ws" && state.selected === name && !document.hidden;

// What the sidebar shows for a workspace's Claude terminal:
//   waiting: it rang the bell (finished, or needs you) since you last looked
//   working: printing right now;  unread: printed since you last looked
function termState(w) {
  const t = w.term;
  if (!t || w.claude !== "running") return "";
  const busy = t.idle !== null && t.idle < WORKING_SECS && t.activity > t.bell + 3;
  if (busy) return "working";
  if (viewing(w.name)) return "";
  const seen = side.seen[w.name] || 0;
  if (t.bell > seen) return "waiting";
  if (t.activity > seen) return "unread";
  return "";
}

function noteSeen() {
  let changed = false;
  for (const w of state.workspaces) {
    if (!w.term) continue;
    // first sight, or looking at it now: everything so far counts as seen
    if (side.seen[w.name] === undefined || viewing(w.name)) {
      if (side.seen[w.name] !== lastTime(w)) { side.seen[w.name] = lastTime(w); changed = true; }
    }
  }
  const names = new Set(state.workspaces.map((w) => w.name));
  for (const n of Object.keys(side.seen)) if (!names.has(n)) { delete side.seen[n]; changed = true; }
  if (changed) prefs.write("seen", side.seen);
}

function matches(w, words) {
  return words.every((q) => q.startsWith("#")
    ? (w.tags || []).some((t) => t.startsWith(q.slice(1)))
    : w.name.includes(q) || (w.dir || "").toLowerCase().includes(q) || (w.tags || []).includes(q));
}

function wsRow(w, act) {
  const b = el("button", { className: `ws-item${side.compact ? " compact" : ""}${act ? ` ${act}` : ""}`, type: "button" });
  b.setAttribute("aria-current", String(state.view === "ws" && w.name === state.selected));
  const ACT_TITLE = { working: "Claude is working", waiting: "Claude finished or needs you", unread: "New output since you looked" };
  const mark = el("span", { className: `act ${act}`, title: ACT_TITLE[act] || "" });
  mark.hidden = !act;
  b.append(el("span", { className: "n" }, mark, el("span", { className: "label", textContent: w.name })));
  if ((w.guests || []).length) {
    b.querySelector(".n").append(el("span", { className: "guests", textContent: `👥${w.guests.length}`,
      title: `Guests in the terminal: ${w.guests.join(", ")}` }));
  }
  const dots = el("span", { className: "dots" });
  const dc = el("span", { className: `dot ${CONTAINER_TONE[w.container] || "none"}`,
    title: `${w.kind === "microvm" ? "VM" : "Container"}: ${w.container}` });
  const dl = el("span", { className: `dot ${CLAUDE_TONE[w.claude] || "none"}`, title: `Claude: ${w.claude}` });
  dots.append(dc, dl);
  b.append(dots);
  const sub = w.dir.replace(/^\/home\/[^/]+/, "~") + (w.kind === "microvm" ? " · microVM" : "")
    + ((w.tags || []).length ? ` · ${w.tags.map((t) => `#${t}`).join(" ")}` : "");
  b.append(el("span", { className: "sub", textContent: sub }));
  if (side.compact) b.title = sub;
  b.addEventListener("click", () => select(w.name));
  return b;
}

function renderList() {
  const list = $("#ws-list");
  const all = state.workspaces;
  const acts = new Map(all.map((w) => [w.name, termState(w)]));
  const waiting = all.filter((w) => acts.get(w.name) === "waiting").length;
  document.title = `${waiting ? `(${waiting}) ` : ""}Agent Sandboxes`;
  if (!all.length) {
    list.replaceChildren(el("p", { className: "ws-empty", textContent: "No workspaces yet." }));
    return;
  }
  const words = side.filter.toLowerCase().split(/\s+/).filter(Boolean);
  const shown = all.filter((w) => matches(w, words));
  shown.sort(side.sort === "activity"
    ? (a, b) => lastTime(b) - lastTime(a) || a.name.localeCompare(b.name)
    : (a, b) => a.name.localeCompare(b.name));
  // groups: Pinned, then each first tag (A–Z), then the rest; no headings while nothing is grouped
  const groups = new Map();
  const add = (key, w) => (groups.get(key) || groups.set(key, []).get(key)).push(w);
  for (const w of shown) add(side.pinned.has(w.name) ? "\u0000pinned" : (w.tags || [])[0] || "￿other", w);
  const keys = [...groups.keys()].sort();
  const flat = keys.length === 1 && keys[0] === "￿other";
  const out = [];
  for (const key of keys) {
    const items = groups.get(key);
    if (!flat) {
      const label = key === "\u0000pinned" ? "Pinned" : key === "￿other" ? "Other" : `#${key}`;
      const open = words.length > 0 || !side.collapsed.has(key);
      const head = el("button", { className: "ws-group", type: "button" },
        el("span", { className: "caret", textContent: "▾" }), el("span", { textContent: label }),
        el("span", { className: "count", textContent: `${items.length}` }));
      head.setAttribute("aria-expanded", String(open));
      const wait = items.filter((w) => acts.get(w.name) === "waiting").length;
      if (!open && wait) head.append(el("span", { className: "waiting-count", textContent: `${wait} waiting` }));
      head.addEventListener("click", () => {
        if (side.collapsed.has(key)) side.collapsed.delete(key); else side.collapsed.add(key);
        prefs.write("collapsed", [...side.collapsed]);
        renderList();
      });
      out.push(head);
      if (!open) continue;
    }
    for (const w of items) out.push(wsRow(w, acts.get(w.name)));
  }
  if (!shown.length) out.push(el("p", { className: "ws-empty", textContent: "No workspace matches." }));
  list.replaceChildren(...out);
}

$("#ws-filter").addEventListener("input", (ev) => { side.filter = ev.target.value; renderList(); });
$("#ws-filter").addEventListener("keydown", (ev) => {
  if (ev.key === "Escape") { ev.target.value = ""; side.filter = ""; renderList(); ev.target.blur(); }
  if (ev.key === "Enter") {         // open the first match
    const first = $("#ws-list .ws-item");
    if (first) first.click();
  }
});
$("#ws-sort").value = side.sort;
$("#ws-sort").addEventListener("change", (ev) => { side.sort = ev.target.value; prefs.write("sort", side.sort); renderList(); });
$("#ws-compact").setAttribute("aria-pressed", String(side.compact));
$("#ws-compact").addEventListener("click", (ev) => {
  side.compact = !side.compact;
  prefs.write("compact", side.compact);
  ev.currentTarget.setAttribute("aria-pressed", String(side.compact));
  renderList();
});
// "/" focuses the filter, unless you're typing somewhere (the terminals included)
document.addEventListener("keydown", (ev) => {
  if (ev.key !== "/" || ev.ctrlKey || ev.metaKey || ev.altKey) return;
  const a = document.activeElement;
  if (a && (a.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(a.tagName) || a.closest?.(".xterm"))) return;
  ev.preventDefault();
  $("#ws-filter").focus();
});
document.addEventListener("visibilitychange", () => { if (!document.hidden) { noteSeen(); renderList(); } });

// ---- the workspace header: pin (this browser) and tags (saved with the workspace)

$("#d-pin").addEventListener("click", () => {
  const w = current();
  if (!w) return;
  if (side.pinned.has(w.name)) side.pinned.delete(w.name); else side.pinned.add(w.name);
  prefs.write("pinned", [...side.pinned]);
  renderPin(w);
  renderList();
});

function renderPin(w) {
  const on = side.pinned.has(w.name);
  $("#d-pin").textContent = on ? "★" : "☆";
  $("#d-pin").setAttribute("aria-pressed", String(on));
}

let tagsEditing = null;     // the workspace whose tags are being edited
function renderTags(w) {
  const box = $("#d-tags");
  if (tagsEditing === w.name) return;
  tagsEditing = null;
  const tags = w.tags || [];
  const edit = el("button", { className: "btn ghost", type: "button", textContent: tags.length ? "Edit tags" : "+ Tag",
    title: "Tags group the sidebar (by the first one) and match #tag in its filter" });
  edit.addEventListener("click", () => editTags(w));
  box.replaceChildren(...tags.map((t) => el("span", { className: "tag", textContent: `#${t}` })), edit);
}

function editTags(w) {
  tagsEditing = w.name;
  const known = [...new Set(state.workspaces.flatMap((x) => x.tags || []))].sort();
  const input = el("input", { value: (w.tags || []).join(", "), placeholder: "client-a, ios, experiments",
    title: `Comma or space separated; the first one is the sidebar group.${known.length ? ` In use: ${known.join(", ")}` : ""}`,
    autocomplete: "off", spellcheck: false });
  input.setAttribute("list", "tag-suggestions");
  const dl = el("datalist", { id: "tag-suggestions" }, ...known.map((t) => el("option", { value: t })));
  const save = el("button", { className: "btn", type: "button", textContent: "Save" });
  const cancel = el("button", { className: "btn ghost", type: "button", textContent: "Cancel" });
  const done = () => { tagsEditing = null; const cur = current(); if (cur) renderTags(cur); };
  const submit = async () => {
    const tags = input.value.split(/[\s,]+/).map((t) => t.replace(/^#/, "").toLowerCase()).filter(Boolean);
    try {
      const r = await api("PUT", wsPath(w.name, "/tags"), { tags });
      const x = state.workspaces.find((y) => y.name === w.name);
      if (x) x.tags = r.tags;
      done();
      renderList();
    } catch (e) {
      msg(e.message, true);
      input.focus();
    }
  };
  save.addEventListener("click", submit);
  cancel.addEventListener("click", done);
  input.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") { ev.preventDefault(); submit(); }
    if (ev.key === "Escape") done();
  });
  $("#d-tags").replaceChildren(input, dl, save, cancel);
  input.focus();
}

// ---- theme: Auto (the system's), Light or Dark, per browser; theme.js applies it before first paint

function setTheme(t) {
  try { if (t) localStorage.setItem("aio-theme", t); else localStorage.removeItem("aio-theme"); } catch { /* this page only */ }
  if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme;
  $$("[data-theme-set]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.themeSet === t)));
}
$$("[data-theme-set]").forEach((b) => b.addEventListener("click", () => setTheme(b.dataset.themeSet)));
setTheme(document.documentElement.dataset.theme || "");

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
  renderPin(w);
  renderTags(w);
  $("#d-dir").textContent = w.dir;
  $$(".d-dir-inline").forEach((el) => (el.textContent = w.dir));
  const vm = w.kind === "microvm";
  $("#detail").classList.toggle("is-vm", vm);
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
  setPill($("#d-claude"), "Claude", w.claude, CLAUDE_TONE[w.claude]);
  $("#d-pending").hidden = !w.policyPending;
  const guests = w.guests || [];
  $("#d-guests").hidden = !guests.length;
  $("#d-guests").textContent = guests.length === 1 ? `guest: ${guests[0]}` : `${guests.length} guests`;
  $("#d-guests").title = guests.length ? `In the terminal now: ${guests.join(", ")}` : "";
  if (state.tab === "share" && guests.join() !== shareSeen.guests) loadShares();

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
    : vm ? "Claude isn't running. Start the VM first: Claude runs inside it."
      : "Claude isn't running. Start the container first so it can use the browser.";
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

const PAGE_LOAD = { pool: () => loadPool(), import: () => loadImport(), host: () => loadHost(), workers: () => loadBuildHost(), settings: () => loadSettings() };

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
  "claude/start": "Starting Claude…", "claude/restart": "Restarting Claude…", "claude/stop": "Stopping Claude…",
};

document.addEventListener("click", async (ev) => {
  const btn = ev.target.closest("[data-act]");
  if (!btn) return;
  const w = current();
  if (!w) return;
  const act = btn.dataset.act;
  $$("[data-act]").forEach((b) => (b.disabled = true));
  msg(w.kind === "microvm" && act.startsWith("container/")
    ? (act === "container/start" ? "Starting VM…" : "Stopping VM…") : ACT_LABEL[act] || "Working…");
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
  $("#rm-what").textContent = w.kind === "microvm"
    ? "VM and its disk (Claude's login there, Docker images, anything outside /project)" : "container and its key";
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
  const out = $("#new-msg");
  out.classList.remove("err");
  out.textContent = kind === "microvm"
    ? "Creating workspace and starting its VM (the first start copies the image)…"
    : "Creating workspace and starting its container…";
  $$("button", newForm).forEach((b) => (b.disabled = true));
  try {
    const res = await api("POST", "workspaces", { name, dir: dir || undefined, kind });
    newForm.reset();
    $("#new-kind-hint").hidden = true;
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
  if (tab === "share") loadShares();
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
    const el = $("#logs");
    el.textContent = log || "(no output)";
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
  bstate.signing = r.signing || [];
  $("#b-status").textContent = !r.host ? "No build host set up yet: Build workers → Apple builds."
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
  const exp = $("#b-export");
  const canExport = j.spec?.action === "archive" && j.state === "passed" && (j.artifacts || []).includes("build.xcarchive.zip");
  if (exp.dataset.job !== j.id) {
    exp.dataset.job = j.id;
    exp.hidden = !canExport;
    if (canExport) {
      const idents = bstate.signing || [];
      exp.elements.identity.replaceChildren(...idents.map((s) => el("option", { value: s.id, textContent: `${s.id} (${s.name})` })));
      if (!idents.length) exp.elements.identity.append(el("option", { value: "", textContent: "none assigned (Access tab)" }));
    }
  }
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
  const files = s.files || [];
  const shots = files.filter((f) => /^screenshots\/[^/]+\.png$/.test(f));
  $("#b-shots").replaceChildren(...shots.map((f) => {
    const name = f.slice("screenshots/".length), thumb = `screenshots/thumbs/${name}`;
    const src = (p) => `${base}/file?path=${encodeURIComponent(p)}`;
    return el("a", { href: src(f), target: "_blank", rel: "noopener", title: name },
      el("img", { src: src(files.includes(thumb) ? thumb : f), alt: name, loading: "lazy" }),
      el("span", { className: "muted", textContent: name }));
  }));
  $("#b-save").hidden = !shots.length;
  $("#b-save-btn").onclick = async () => {
    const btn = $("#b-save-btn");
    btn.disabled = true;
    try {
      const r = await api("POST", wsPath(w.name, `/builds/${j.id}/screenshots`), { folder: $("#b-save input").value.trim() });
      bMsg(`Saved ${r.paths.length} screenshot(s) into the project: ${r.paths.length > 3 ? r.paths.slice(0, 3).join(", ") + ", …" : r.paths.join(", ")}`);
    } catch (e) { bMsg(e.message, true); }
    btn.disabled = false;
  };
  const arts = j.artifacts || [];
  $("#b-arts").replaceChildren(...(arts.length ? [el("span", { className: "muted", textContent: "Artifacts: " })] : []),
    ...arts.flatMap((a) => {
      const copy = el("button", { className: "btn", type: "button", textContent: "Copy into workspace",
        title: `To .aio-builds/${j.id}/${a} in the project folder` });
      copy.addEventListener("click", async () => {
        copy.disabled = true;
        try { const r = await api("POST", wsPath(w.name, `/builds/${j.id}/fetch?name=${encodeURIComponent(a)}`)); bMsg(`Copied to ${r.path} in the project folder.`); }
        catch (e) { bMsg(e.message, true); }
        copy.disabled = false;
      });
      return [el("a", { className: "btn", href: `${base}/artifact?name=${encodeURIComponent(a)}`, textContent: `⬇ ${a}` }), copy];
    }));
}

$("#b-export").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const w = current(), f = ev.currentTarget.elements;
  try {
    const r = await api("POST", wsPath(w.name, "/builds/export"), { from: bstate.sel, identity: f.identity.value,
      method: f.method.value, upload: f.upload.checked });
    bMsg(`Queued export ${r.id}, sealed for ${r.workers.join(", ")}.`);
    openBuild(r.id);
  } catch (e) { bMsg(e.message, true); }
  loadBuilds();
});

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
function bActionChanged() {
  const a = $("#b-form").elements.action.value;
  $("#b-shot-opts").hidden = !["run", "screenshots"].includes(a);
  $$("#b-shot-opts [data-for]").forEach((x) => { x.hidden = x.dataset.for !== a; });
}
$("#b-form").elements.action.addEventListener("change", bActionChanged);

$("#b-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const w = current();
  const f = ev.currentTarget.elements;
  const body = Object.fromEntries(["action", "scheme", "project", "destination", "configuration", "ref"].map((k) => [k, f[k].value.trim()]));
  if (["run", "screenshots"].includes(body.action)) {
    Object.assign(body, { devices: f.devices.value, locales: f.locales.value, appearance: f.appearance.value,
      status_bar: f.status_bar.checked, grant_permissions: f.grant_permissions.checked });
    if (body.action === "run" && f.shots.value.trim()) body.shots = f.shots.value;
    if (body.action === "screenshots") body.only_testing = f.only_testing.value;
  }
  bMsg("Sending the commit to the build host…");
  try {
    const j = await api("POST", wsPath(w.name, "/builds"), body);
    bMsg(`Queued ${j.id} (${j.commit.slice(0, 10)}).`);
    await loadBuilds();
    openBuild(j.id);
  } catch (e) { bMsg(e.message, true); }
});

// ------------------------------------------------------------------ Apple builds (Build workers page: build host, Mac workers)

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
    const sig = $("#acc-signing");
    sig.replaceChildren(...(pool.signing || []).map((s) =>
      checkItem("signing", s.id, (policy.signing || []).includes(s.id), s.id,
        `${s.name} · ${s.profiles.map((p) => `${p.bundle_id} (${p.type})`).join(", ") || "no profiles"}`)));
    if (!(pool.signing || []).length) sig.append(el("p", { className: "muted", textContent: "No signing identities yet — add one under Keys & tokens." }));
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
  const body = {
    ssh_keys: $$('input[name="ssh"]:checked', form).map((i) => i.value),
    tokens: $$('input[name="token"]:checked', form).map((i) => i.value),
    signing: $$('input[name="signing"]:checked', form).map((i) => i.value),
    network: { mode: form.elements.mode?.value || "claude-code", allow: lines(form.elements.allow.value), deny: lines(form.elements.deny.value),
      container: form.elements.container.value || "open", listen: lines(form.elements.listen.value) },
    limits: { memory: form.elements.memory.value.trim(), pids: Number(form.elements.pids.value || 0),
      cpus: Number(form.elements.cpus.value || 0), disk: form.elements.disk.value.trim(),
      browser_memory: form.elements.browser_memory.value.trim(), browser_cpus: Number(form.elements.browser_cpus.value || 0) },
    claude_md: form.elements.claude_md.checked,
    vm_browser: form.elements.vm_browser.checked,
    builds: form.elements.builds.checked,
  };
  out.textContent = "Saving…";
  try {
    const res = await api("PUT", wsPath(w.name, "/policy"), body);
    if (restart) {
      out.textContent = `Saved.${res.notes?.length ? ` ${res.notes.join(" ")}` : ""} Restarting Claude…`;
      await api("POST", wsPath(w.name, "/claude/restart"));
      disconnectTerm();
      out.textContent = "Saved and Claude restarted with the new policy.";
    } else {
      out.textContent = (res.pending
        ? "Saved. SSH key changes are live; restart Claude for the rest."
        : w.claude === "stopped" ? "Saved. Applies when Claude starts." : "Saved and applied.")
        + (res.notes?.length ? ` ${res.notes.join(" ")}` : "");
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
  const head = el("tr", {}, el("th", { textContent: { ssh: "Key", tokens: "Token", signing: "Identity" }[kind] }),
    ...wss.map((n) => el("th", { className: "ws-col", textContent: n, title: n })), el("th"));
  const rows = items.map((it) => {
    const tds = wss.map((n) => {
      const cb = el("input", { type: "checkbox", checked: it.workspaces.includes(n), title: `${it.id} → ${n}` });
      cb.addEventListener("change", async () => {
        const want = wss.filter((x, i) => $$("input[type=checkbox]", cb.closest("tr"))[i].checked);
        cb.disabled = true;
        try {
          await api("PUT", `pool/${kind}/${encodeURIComponent(it.id)}/workspaces`, { workspaces: want });
          poolMsg(kind === "tokens" ? `${it.id}: restart Claude in ${n} to apply.` : `${it.id}: applied.`);
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
    if (kind === "signing") {
      const pick = el("input", { type: "file", accept: ".mobileprovision,.provisionprofile", hidden: true, multiple: true });
      const add = el("button", { className: "btn ghost", type: "button", textContent: "+ Profile" });
      add.addEventListener("click", () => pick.click());
      pick.addEventListener("change", async () => {
        try {
          for (const f of pick.files) await api("POST", `pool/signing/${encodeURIComponent(it.id)}/profiles`, { profile: await fileB64(f) });
          poolMsg(`${it.id}: profile added.`);
        } catch (e) { poolMsg(e.message, true); }
        loadPool();
      });
      actions.append(add, pick);
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
    const item = el("td", { className: "item" }, el("strong", { textContent: it.id }), el("div", { className: "muted", textContent: describe(it) }));
    if (kind === "signing") item.append(signingProfiles(it));
    return el("tr", {}, item, ...tds, actions);
  });
  if (!items.length) rows.push(el("tr", {}, el("td", { className: "muted note", colSpan: wss.length + 2, textContent: "None yet." })));
  table.replaceChildren(el("thead", {}, head), el("tbody", {}, ...rows));
}

const fileB64 = async (file) => {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
};
const day = (iso) => (iso || "").slice(0, 10);

function signingProfiles(it) {
  const list = el("ul", { className: "sign-profiles" });
  for (const p of it.profiles) {
    const gone = new Date(p.expires) < new Date();
    const del = el("button", { className: "btn ghost danger small", type: "button", textContent: "×", title: `Remove ${p.name}` });
    del.addEventListener("click", async () => {
      if (!confirm(`Remove the profile ${p.name}?`)) return;
      try { await api("DELETE", `pool/signing/${encodeURIComponent(it.id)}/profiles/${p.uuid}`); } catch (e) { poolMsg(e.message, true); }
      loadPool();
    });
    list.append(el("li", { className: gone ? "bad" : "" }, `${p.name} · ${p.bundle_id} · ${p.type}${p.devices ? ` (${p.devices} devices)` : ""} · `,
      el("span", { textContent: gone ? `expired ${day(p.expires)}` : `until ${day(p.expires)}` }), " ", del));
  }
  if (!it.profiles.length) list.append(el("li", { className: "muted", textContent: "No provisioning profiles yet: add one (+ Profile)." }));
  return list;
}

async function loadPool() {
  try {
    poolData = await api("GET", "pool");
  } catch (e) {
    return poolMsg(e.message, true);
  }
  renderMatrix($("#m-ssh"), "ssh", poolData.ssh, (k) => `${k.type} ${k.fingerprint} · ${k.comment}`);
  renderMatrix($("#m-signing"), "signing", poolData.signing || [], (s) =>
    `${s.name} · team ${s.team} · ${new Date(s.expires) < new Date() ? "EXPIRED " : "until "}${day(s.expires)}`);
  renderMatrix($("#m-tokens"), "tokens", poolData.tokens, (t) => t.service === "plain" ? `${t.label} → $${t.env_var} · ${t.sent_as}`
    : `${t.label} (${t.upstream}) → $${t.env_var}${t.sent_as ? ` · ${t.sent_as}` : ""}`
    + (t.upstream.startsWith("http://") ? ` · call it via $${baseUrlVar(t.id)}` : ""));
  const sel = $("#tok-service");
  if (!sel.options.length) {
    for (const [k, v] of Object.entries(poolData.services)) sel.append(el("option", { value: k, textContent: `${v.label} → $${v.env_var}` }));
    sel.append(el("option", { value: "custom", textContent: "Custom API, client ID or other value…" }));
    sel.append(el("option", { value: "plain", textContent: "Plain value, visible to the agent (env var)…" }));
    for (const [k, v] of Object.entries(poolData.ascPresets || {})) $("#tok-asc-preset").append(el("option", { value: k, textContent: v }));
    $("#tok-asc-preset").value = "testflight";
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
  tokServiceChanged();
}));
$("#add-ssh").addEventListener("change", (ev) => {
  if (ev.target.name === "how") ev.currentTarget.elements.private_key.hidden = ev.target.value !== "import";
});
// nono's route for a pool token; http:// APIs can only be reached through it
const baseUrlVar = (id) => `POOL_${id.replace(/-/g, "_").toUpperCase()}_BASE_URL`;

function tokServiceChanged() {
  const v = $("#tok-service").value, asc = v === "appstoreconnect";
  $("#tok-custom").hidden = v !== "custom";
  $("#tok-plain").hidden = v !== "plain";
  $("#tok-asc").hidden = !asc;
  $("#tok-secret").hidden = asc;
  $("#add-tokens").elements.secret.required = !asc;
  tokModeChanged();
}
function tokModeChanged() {
  const mode = $("#tok-mode").value;
  $$("#tok-custom [data-mode]").forEach((x) => { x.hidden = x.dataset.mode !== mode; });
  const basic = $("#tok-service").value === "custom" && mode === "basic_auth";
  const plain = $("#tok-service").value === "plain";
  $("#tok-secret-label").textContent = basic ? "Value (username:password)" : plain ? "Value" : "Token";
  $("#add-tokens").elements.secret.type = plain ? "text" : "password";
  $("#add-tokens").elements.secret.placeholder = basic ? "client_id:client_secret" : "";
}
$("#tok-mode").addEventListener("change", tokModeChanged);
$("#tok-service").addEventListener("change", tokServiceChanged);
$("#add-tokens").elements.asc_file.addEventListener("change", async (ev) => {
  const file = ev.target.files[0];
  if (file) $("#add-tokens").elements.asc_p8.value = await file.text();
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
    tokServiceChanged();
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
$("#add-signing").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const form = ev.currentTarget, f = form.elements;
  try {
    submitAdd(form, "pool/signing", { id: f.id.value.trim(), password: f.password.value,
      p12: await fileB64(f.p12.files[0]), profiles: await Promise.all([...f.profiles.files].map(fileB64)) });
  } catch (e) { $(".form-msg", form).textContent = e.message; }
});
$("#add-tokens").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const f = ev.currentTarget.elements;
  const service = f.service.value;
  const asc = service === "appstoreconnect";
  submitAdd(ev.currentTarget, "pool/tokens", { id: f.id.value.trim(), service, secret: asc ? f.asc_p8.value : f.secret.value,
    plain: service === "plain" ? { env_var: f.plain_env.value.trim(), note: f.plain_note.value.trim() } : undefined,
    asc: asc ? { key_id: f.asc_key_id.value.trim(), issuer_id: f.asc_issuer_id.value.trim(), preset: f.asc_preset.value } : undefined,
    custom: service === "custom" ? { upstream: f.upstream.value.trim(), env_var: f.env_var.value.trim(), mode: f.mode.value,
      header: f.header.value.trim(), format: f.format.value.trim(), param: f.param.value.trim(), path: f.path.value.trim() } : undefined });
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

async function loadSettings() {
  loadAuth();
  try {
    const st = await api("GET", "settings/monitoring");
    loadClaudeMd();
    loadBackup(true);
    loadSharing();
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

// ------------------------------------------------------------------ sharing

const fmtLeft = (t) => {
  const s = t - Date.now() / 1000;
  return s <= 0 ? "ended" : s > 86400 ? `${Math.floor(s / 86400)} d left` : s > 3600 ? `${Math.floor(s / 3600)} h left` : `${Math.ceil(s / 60)} min left`;
};

function shMsg(text, bad = false) {
  $("#sh-msg").textContent = text;
  $("#sh-msg").classList.toggle("err", bad);
}

function showLink(r) {
  $("#sh-link").hidden = false;
  $("#sh-link-who").textContent = r.share.label;
  $("#sh-link-url").value = r.link;
  $("#sh-link-url").select();
}

async function loadShares() {
  const w = current();
  if (!w) return;
  shareSeen.guests = (w.guests || []).join();
  try {
    const r = await api("GET", wsPath(w.name, "/shares"));
    if (current()?.name !== w.name) return;
    $("#sh-off").hidden = r.enabled;
    $("#sh-form button[type=submit]").disabled = !r.enabled;
    $("#sh-desktop-wrap").hidden = !r.desktop;
    $("#sh-list").replaceChildren(...r.shares.map((x) => {
      const scope = [x.terminal === "drive" ? "types" : "watches", x.files !== "none" ? `files: ${x.files}` : "", x.desktop ? "desktop" : ""].filter(Boolean).join(" · ");
      const status = x.revoked ? "revoked" : x.active ? fmtLeft(x.expires) : "expired";
      const info = el("div", {}, el("strong", { textContent: x.label }), " ",
        el("span", { className: "muted", textContent: `${scope} · ${status}${x.connected ? ` · connected now (${x.connected})` : ""}` }));
      const row = el("div", { className: `keyrow${x.active ? "" : " ended"}` }, info);
      if (x.active) {
        const btns = el("div", { className: "row" });
        const again = el("button", { className: "btn", type: "button", textContent: "New link" });
        again.title = "Replace the link (the old one stops working, and the guest is disconnected)";
        again.addEventListener("click", async () => {
          try { showLink(await api("POST", `shares/${x.id}/link`)); loadShares(); } catch (e) { shMsg(e.message, true); }
        });
        const rev = el("button", { className: "btn danger ghost", type: "button", textContent: "Revoke" });
        rev.addEventListener("click", async () => {
          try { await api("DELETE", `shares/${x.id}`); shMsg(`Revoked ${x.label}'s link.`); loadShares(); refresh(); } catch (e) { shMsg(e.message, true); }
        });
        btns.append(again, rev);
        row.append(btns);
      }
      return row;
    }));
    if (!r.shares.length) $("#sh-list").append(el("p", { className: "muted", textContent: "No links yet." }));
  } catch (e) { shMsg(e.message, true); }
}

function shFormChanged() {
  const f = $("#sh-form");
  const drive = f.terminal.value === "drive";
  f.desktop.disabled = !drive;
  if (!drive) f.desktop.checked = false;
  $("#sh-drive-warn").hidden = !drive;
}
$("#sh-form").terminal.addEventListener("change", shFormChanged);

$("#sh-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const w = current();
  const f = ev.target;
  if (!w) return;
  try {
    const r = await api("POST", wsPath(w.name, "/shares"), { label: f.label.value.trim(), terminal: f.terminal.value,
      files: f.files.value, desktop: f.desktop.checked, expires: f.expires.value });
    showLink(r);
    shMsg("");
    f.label.value = "";
    loadShares();
  } catch (e) { shMsg(e.message, true); }
});

$("#sh-copy").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($("#sh-link-url").value); shMsg("Link copied."); }
  catch { $("#sh-link-url").select(); shMsg("Select the link and copy it."); }
});

let srPending = null;      // the form waiting for its host key to be confirmed
let srTimer = 0;

function srMsg(text, bad = false) {
  $("#sr-msg").textContent = text;
  $("#sr-msg").classList.toggle("err", bad);
}

async function loadSharing(fill = true) {
  clearTimeout(srTimer);
  try {
    const r = await api("GET", "settings/sharing");
    const f = $("#sr-form"), set = r.settings, t = r.tunnel;
    if (fill && !srPending) {
      f.shareHost.value = set.shareHost; f.desktopHost.value = set.desktopHost;
      f.vps.value = set.vps; f.sshPort.value = set.sshPort; f.cloudflare.checked = set.cloudflare;
    }
    const st = $("#sr-state");
    st.textContent = !r.enabled ? "not set up" : !r.listening ? "listener down" : !set.tunnel ? "tunnel stopped" : `tunnel ${t.state}`;
    st.className = `pill ${!r.enabled ? "" : r.listening && t.state === "up" ? "ok" : t.state === "connecting" ? "" : "warn"}`;
    const parts = [];
    if (r.enabled) parts.push(`Guests open ${r.origin}${r.desktop ? ` (browser desktop: ${r.desktop})` : ""}. ${r.active} active link(s).`);
    if (r.hostKey.fingerprint) parts.push(`VPS host key ${r.hostKey.fingerprint} (pinned).`);
    if (set.tunnel && t.state === "down") parts.push(`Tunnel down, retrying: ${t.error}`);
    if (t.state === "up") parts.push(`Tunnel up since ${new Date(t.since * 1000).toLocaleTimeString()}.`);
    $("#sr-summary").textContent = parts.join(" ");
    $("#sr-steps").hidden = r.enabled && t.state === "up";
    $("#sr-script-wrap").hidden = !r.vpsScript;
    $("#sr-script").textContent = r.vpsScript || "";
    if (r.vpsScript && t.state !== "up") $("#sr-script-wrap").open = true;
    $("#sr-check").disabled = !r.enabled;
    $("#sr-tunnel").hidden = $("#sr-repin").hidden = $("#sr-off").hidden = !r.enabled;
    $("#sr-tunnel").textContent = set.tunnel ? "Stop tunnel" : "Start tunnel";
    $("#sr-tunnel").dataset.on = set.tunnel ? "" : "1";
    $("#sr-save").textContent = r.enabled ? "Save" : "Save & set up";
    if (!$("#settings").hidden && t.state === "connecting") srTimer = setTimeout(() => loadSharing(false), 4000);
  } catch (e) { srMsg(e.message, true); }
}

async function srSave(extra = {}) {
  const f = $("#sr-form");
  const body = { shareHost: f.shareHost.value.trim(), desktopHost: f.desktopHost.value.trim(),
                 vps: f.vps.value.trim(), sshPort: Number(f.sshPort.value),
                 cloudflare: f.cloudflare.checked, ...extra };
  srMsg(extra.fingerprint ? "Saving…" : "Fetching the VPS's host key…");
  $("#sr-save").disabled = true;
  try {
    const res = await fetch("/api/settings/sharing", { method: "PUT", body: JSON.stringify(body),
      headers: { "Content-Type": "application/json", "X-Requested-With": "sbui" } });
    const data = await res.json();
    if (res.ok && data.confirm) {
      srPending = body;
      $("#sr-confirm-host").textContent = data.confirm.host;
      $("#sr-confirm-fp").textContent = data.confirm.fingerprint;
      $("#sr-confirm").hidden = false;
      $("#sr-confirm-yes").dataset.fp = data.confirm.fingerprint;
      srMsg("Confirm the VPS's host key to save.");
      return;
    }
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    srPending = null;
    $("#sr-confirm").hidden = true;
    srMsg("Saved. Run the VPS setup script on the VPS if you haven't (or the names changed), then check from the internet.");
    loadSharing();
  } catch (e) { srMsg(e.message, true); }
  finally { $("#sr-save").disabled = false; }
}

$("#sr-form").addEventListener("submit", (ev) => { ev.preventDefault(); srSave(); });
$("#sr-repin").addEventListener("click", () => srSave({ repin: true }));
$("#sr-confirm-yes").addEventListener("click", () => {
  const { repin, ...form } = srPending || {};
  if (srPending) srSave({ ...form, repin, fingerprint: $("#sr-confirm-yes").dataset.fp });
});
$("#sr-confirm-no").addEventListener("click", () => {
  srPending = null;
  $("#sr-confirm").hidden = true;
  srMsg("Not saved: the host key wasn't confirmed.");
});
$("#sr-tunnel").addEventListener("click", async () => {
  try {
    await api("POST", "settings/sharing/tunnel", { on: !!$("#sr-tunnel").dataset.on });
    srMsg("");
    loadSharing(false);
  } catch (e) { srMsg(e.message, true); }
});
$("#sr-off").addEventListener("click", async () => {
  if (!confirm("Turn off sharing? The tunnel stops and the relay settings are removed here. Share links stay, but nobody can reach them until it's set up again. (The VPS is left as it is.)")) return;
  try { await api("DELETE", "settings/sharing"); srMsg("Sharing is off."); loadSharing(); }
  catch (e) { srMsg(e.message, true); }
});
$("#sr-copy").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($("#sr-script").textContent); srMsg("Script copied."); }
  catch { srMsg("Select the script and copy it."); }
});
$("#sr-check").addEventListener("click", async () => {
  srMsg("Checking…");
  try {
    const r = await api("POST", "settings/sharing/check");
    srMsg(r.ok ? `Works: ${r.url} reached this host through the relay.` : r.error, !r.ok);
  } catch (e) { srMsg(e.message, true); }
});
