"use strict";
// A guest's view of one shared workspace: its Claude terminal (watch or
// drive), its project files and its browser desktop, as the share allows.

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];
const g = { me: null, xterm: null, fit: null, sock: null, retry: 0, path: "" };

function ended() {
  $$("[data-panel]").forEach((p) => { p.hidden = true; });
  $(".tabs").hidden = true;
  $("#g-ended").hidden = false;
  if (g.sock) { const s = g.sock; g.sock = null; s.close(); }
}

async function api(method, path, body, extra = {}) {
  const res = await fetch(`/api/${path}`, { method, headers: { "X-Requested-With": "sbui", ...extra.headers }, body });
  if (res.status === 401) { ended(); throw new Error("This share has ended"); }
  const data = res.headers.get("content-type")?.includes("json") ? await res.json() : { error: await res.text() };
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function left() {
  const s = g.me.expires - Date.now() / 1000;
  if (s <= 0) return ended();
  $("#g-left").textContent = s > 86400 ? `${Math.floor(s / 86400)} d left` : s > 3600 ? `${Math.floor(s / 3600)} h ${Math.floor(s % 3600 / 60)} min left` : `${Math.ceil(s / 60)} min left`;
}

function selectTab(tab) {
  $$(".tabs [role=tab]").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === tab)));
  $$("[data-panel]").forEach((p) => { p.hidden = p.dataset.panel !== tab; });
  if (tab === "term") fitTerm();
  if (tab === "files" && !g.path) loadFiles(g.me.root);
}
$$(".tabs [role=tab]").forEach((b) => b.addEventListener("click", () => selectTab(b.dataset.tab)));

// ---- terminal

function send(obj) {
  if (g.sock?.readyState === WebSocket.OPEN) g.sock.send(JSON.stringify(obj));
}

function fitTerm() {
  if (!g.xterm || $('[data-panel="term"]').hidden) return;
  try { g.fit.fit(); } catch { return; }
  send({ t: "r", c: g.xterm.cols, r: g.xterm.rows });
}

function connect() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const sock = new WebSocket(`${proto}://${location.host}/ws/term?cols=${g.xterm.cols}&rows=${g.xterm.rows}`);
  sock.binaryType = "arraybuffer";
  sock.onopen = () => { g.retry = 0; fitTerm(); g.xterm.focus(); };
  sock.onmessage = (ev) => g.xterm.write(typeof ev.data === "string" ? ev.data : new Uint8Array(ev.data));
  sock.onclose = async () => {
    if (g.sock !== sock) return;
    g.sock = null;
    try { await api("GET", "me"); } catch { return; }     // ended: api() shows it
    if (g.retry < 6) {
      g.retry += 1;
      g.xterm.write(`\r\n\x1b[33m(disconnected; reconnecting in ${g.retry} s)\x1b[0m\r\n`);
      setTimeout(() => { if (!g.sock) { g.xterm.reset(); connect(); } }, 1000 * g.retry);
    }
  };
  g.sock = sock;
}

function initTerm() {
  const css = getComputedStyle(document.documentElement);
  g.xterm = new Terminal({
    cursorBlink: g.me.terminal === "drive",
    disableStdin: g.me.terminal !== "drive",
    fontFamily: css.getPropertyValue("--mono"),
    fontSize: 13,
    scrollback: 5000,
    macOptionClickForcesSelection: true,
    theme: { background: css.getPropertyValue("--term-bg").trim() || "#1b1b19" },
  });
  g.fit = new FitAddon.FitAddon();
  g.xterm.loadAddon(g.fit);
  g.xterm.open($("#term"));
  if (g.me.terminal === "drive") g.xterm.onData((d) => send({ t: "i", d }));
  new ResizeObserver(() => fitTerm()).observe($("#term"));
  fitTerm();
  connect();
}

// ---- files

const fmtSize = (n) => n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : n < 1073741824 ? `${(n / 1048576).toFixed(1)} MB` : `${(n / 1073741824).toFixed(2)} GB`;
const joinPath = (a, b) => (a.endsWith("/") ? a : a + "/") + b;
const parentPath = (p) => p.replace(/\/[^/]+\/?$/, "") || "/";

function fMsg(text, bad = false) {
  $("#f-msg").textContent = text;
  $("#f-msg").className = bad ? "msg bad" : "msg";
}

async function loadFiles(path) {
  try {
    const res = await api("GET", `files?path=${encodeURIComponent(path)}`);
    g.path = res.path;
    $("#f-path").value = res.path;
    fMsg("");
    $("#f-list").replaceChildren(...res.entries.map((e) => {
      const tr = document.createElement("tr");
      const name = document.createElement("td");
      const a = document.createElement("a");
      const full = joinPath(res.path, e.name);
      a.textContent = e.type === "dir" ? `${e.name}/` : e.name;
      if (e.type === "dir") {
        a.href = "#";
        a.addEventListener("click", (ev) => { ev.preventDefault(); loadFiles(full); });
      } else {
        a.href = `/api/download?path=${encodeURIComponent(full)}`;
        a.download = e.name;
      }
      name.append(a);
      const size = document.createElement("td");
      size.className = "num";
      size.textContent = e.type === "dir" ? "" : fmtSize(e.size);
      tr.append(name, size);
      return tr;
    }));
  } catch (e) { fMsg(e.message, true); }
}

$("#f-form").addEventListener("submit", (ev) => { ev.preventDefault(); loadFiles($("#f-path").value.trim()); });
$("#f-up").addEventListener("click", () => {
  const p = parentPath(g.path || g.me.root);
  loadFiles(p.length < g.me.root.length ? g.me.root : p);
});
$("#f-file").addEventListener("change", async (ev) => {
  for (const file of ev.target.files) {
    fMsg(`Uploading ${file.name}…`);
    const q = `path=${encodeURIComponent(g.path)}&name=${encodeURIComponent(file.name)}`;
    try {
      await api("PUT", `upload?${q}`, file);
    } catch (e) {
      if (!/already exists/.test(e.message) || !confirm(`${file.name} already exists. Replace it?`)) { fMsg(e.message, true); continue; }
      try { await api("PUT", `upload?${q}&overwrite=1`, file); } catch (e2) { fMsg(e2.message, true); continue; }
    }
  }
  ev.target.value = "";
  loadFiles(g.path);
});

// ---- start

(async () => {
  try {
    g.me = await api("GET", "me");
  } catch { return; }
  $("#g-ws").textContent = g.me.workspace;
  document.title = `${g.me.workspace} (shared)`;
  const mode = $("#g-mode");
  mode.textContent = g.me.terminal === "drive" ? "you can type" : "watching";
  mode.classList.toggle("drive", g.me.terminal === "drive");
  mode.title = g.me.terminal === "drive" ? `Shared with ${g.me.label}: what you type goes to Claude` : `Shared with ${g.me.label}: view only`;
  $('[data-tab="files"]').hidden = g.me.files === "none";
  $("#f-upload").hidden = g.me.files !== "upload";
  if (g.me.desktop) { $("#g-desktop").href = g.me.desktop; $("#g-desktop").hidden = false; }
  left();
  setInterval(left, 30000);
  initTerm();
})();
