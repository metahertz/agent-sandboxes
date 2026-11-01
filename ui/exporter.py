#!/usr/bin/env python3
"""Agent Sandboxes metrics / log exporter (user service, see systemd/).

Every INTERVAL seconds it
  - writes per-workspace Prometheus metrics (container, Claude session,
    policy, and the Claude scope's cgroup usage) to
    monitoring/data/exporter/workspaces.prom, which Alloy's node exporter
    picks up as a textfile collector;
  - tails nono's audit trail (~/.local/state/nono/audit/<session>/
    audit-events.ndjson: sessions and every network allow / deny), tags each
    event with its workspace and appends it to nono-audit.ndjson in the same
    directory, which Alloy ships to Loki. Event counts are exported too;
  - reports whether the UI and proxy services are up, and the proxy
    service's own state (from its control socket).

Stdlib only; reuses the UI server's workspace / policy code.
"""

import asyncio
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import server  # noqa: E402

OUT = server.ROOT / "monitoring" / "data" / "exporter"
PROM = OUT / "workspaces.prom"
AUDIT_LOG = OUT / "nono-audit.ndjson"
OFFSETS = OUT / "offsets.json"
from common import NONO_LOGS  # noqa: E402
NONO_STATE = Path.home() / ".local" / "state" / "nono"
CGROUP_APP = Path(f"/sys/fs/cgroup/user.slice/user-{os.getuid()}.slice/"
                  f"user@{os.getuid()}.service/app.slice")
SCOPE_RE = re.compile(r"^claude-(.+)-\d+\.scope$")
INTERVAL = float(os.environ.get("AIO_EXPORTER_INTERVAL", "15"))
DU_EVERY = 300                       # seconds between workspace disk-usage scans
MAX_LOG = 20 * 1024 * 1024           # rotate nono-audit.ndjson (one old copy kept)
# "<ts>  INFO proxy request allowed mode=external host=\"…\" port=443 …", and claude-in's markers
LOG_LINE = re.compile(r"^(\d{4}-\d\d-\d\dT\S+Z)\s+(TRACE|DEBUG|INFO|WARN|ERROR|AIO)\s+(.*)$")
# nono 0.80 writes key="value" fields after the message, 0.81 key=value in it (reason may
# have spaces): a value runs to the next of these keys
LOG_KEY = re.compile(r"\s(mode|host|port|method|decision|reason|denial_category|target|path|status|"
                     r"endpoint_policy_action|endpoint_policy_rule|route_id|credential|action)=")
LOG_EVENTS = {"proxy request allowed": "allow", "proxy request denied": "deny",
              "l7 proxy response": "allow", "l7 endpoint policy decision": None}   # None: its decision=


def parse_ts(s: str) -> float | None:
    """RFC 3339 with up to nanoseconds, as nono writes it."""
    m = re.match(r"^(\S+?T\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:\d\d)$", s)
    if not m:
        return None
    frac = (m[2] or ".0")[:7]
    try:
        return datetime.fromisoformat(m[1] + frac + ("+00:00" if m[3] == "Z" else m[3])).timestamp()
    except ValueError:
        return None


def unquote(v: str) -> str:
    if v.startswith('"'):
        try:
            return json.loads(v)
        except ValueError:
            return v.strip('"')
    return v


def esc(v) -> str:
    return str(v).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


class Metrics:
    def __init__(self):
        self.lines: list[str] = []
        self.seen: set[str] = set()

    def add(self, name: str, kind: str, help_: str, value, **labels):
        if name not in self.seen:
            self.seen.add(name)
            self.lines += [f"# HELP {name} {help_}", f"# TYPE {name} {kind}"]
        lab = ",".join(f'{k}="{esc(v)}"' for k, v in labels.items())
        self.lines.append(f"{name}{{{lab}}} {value}" if lab else f"{name} {value}")

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


def read_int(p: Path, default=0) -> int:
    try:
        v = p.read_text().split()[0]
        return 0 if v == "max" else int(v)
    except (OSError, ValueError, IndexError):
        return default


def kv_file(p: Path) -> dict[str, int]:
    out = {}
    try:
        for line in p.read_text().splitlines():
            k, _, v = line.partition(" ")
            out[k] = int(v)
    except (OSError, ValueError):
        pass
    return out


def claude_scopes() -> dict[str, dict[str, int]]:
    """Sum the cgroup usage of each workspace's claude-<ws>-<pid>.scope(s)."""
    usage: dict[str, dict[str, int]] = {}
    try:
        scopes = list(CGROUP_APP.iterdir())
    except OSError:
        return usage
    for d in scopes:
        m = SCOPE_RE.match(d.name)
        if not m:
            continue
        u = usage.setdefault(m.group(1), {"scopes": 0, "mem": 0, "peak": 0, "cpu_us": 0,
                                          "pids": 0, "oom": 0})
        u["scopes"] += 1
        u["mem"] += read_int(d / "memory.current")
        u["peak"] += read_int(d / "memory.peak")
        u["cpu_us"] += kv_file(d / "cpu.stat").get("usage_usec", 0)
        u["pids"] += read_int(d / "pids.current")
        u["oom"] += kv_file(d / "memory.events").get("oom_kill", 0)
    return usage


class Audit:
    """Incremental reader of nono's per-session audit event logs."""

    def __init__(self):
        try:
            st = json.loads(OFFSETS.read_text())
        except (OSError, ValueError):
            st = {}
        self.offsets: dict[str, int] = st.get("offsets", {})
        self.ws_of: dict[str, str] = st.get("ws_of", {})
        # counters persist so restarts don't look like resets to Prometheus
        self.net: dict[str, int] = st.get("net", {})          # "ws\tdecision\tcategory"
        self.sessions: dict[str, int] = st.get("sessions", {})  # ws
        self.overflow: dict[str, int] = st.get("overflow", {})  # ws: events past nono's buffer
        # nono's own log (bin/claude-in): offsets per file, and when claude-in
        # started sessions that log every proxy event there (recent ones)
        self.log_offsets: dict[str, int] = st.get("log_offsets", {})
        self.log_starts: dict[str, list[float]] = st.get("log_starts", {})
        self.sess: dict[str, list] = st.get("sess", {})         # sid: [started epoch, command]

    def save(self):
        server.private_write(OFFSETS, json.dumps(
            {"offsets": self.offsets, "ws_of": self.ws_of, "net": self.net,
             "sessions": self.sessions, "overflow": self.overflow, "log_offsets": self.log_offsets,
             "log_starts": self.log_starts, "sess": self.sess}))

    def workspace(self, sid: str, wss: list[dict[str, str]]) -> str:
        if sid in self.ws_of:
            return self.ws_of[sid]
        name = "-"
        try:
            info = json.loads((NONO_STATE / "sessions" / f"{sid}.json").read_text())
        except (OSError, ValueError):
            info = {}
        prof = Path(str(info.get("profile") or ""))
        if prof.parent == server.WS_ROOT and prof.name.endswith(".profile.json"):
            name = prof.name[:-len(".profile.json")]
        else:   # e.g. started with a stock profile: match the working directory
            wd = os.path.realpath(str(info.get("workdir") or "/nonexistent"))
            for ws in wss:
                d = os.path.realpath(ws.get("WS_DIR", "/nonexistent"))
                if wd == d or wd.startswith(d + "/"):
                    name = ws["WS_NAME"]
        if info:            # the session file can disappear later; remember the answer
            self.ws_of[sid] = name
        return name

    def poll(self, wss: list[dict[str, str]]) -> int:
        root = NONO_STATE / "audit"
        try:
            dirs = {d.name: d / "audit-events.ndjson" for d in root.iterdir() if d.is_dir()}
        except OSError:
            return 0
        for gone in set(self.offsets) - set(dirs):
            self.offsets.pop(gone, None)
            self.ws_of.pop(gone, None)
            self.sess.pop(gone, None)
        out = self.poll_logs()
        for sid, f in dirs.items():
            off = self.offsets.get(sid, 0)
            try:
                size = f.stat().st_size
                if size <= off:
                    continue
                with f.open("rb") as fh:
                    fh.seek(off)
                    chunk = fh.read(size - off)
            except OSError:
                continue
            end = chunk.rfind(b"\n") + 1      # only whole lines; the rest next time
            if not end:
                continue
            self.offsets[sid] = off + end
            ws = self.workspace(sid, wss)
            for raw in chunk[:end].splitlines():
                try:
                    rec = self.record(sid, ws, json.loads(raw)["event"])
                except (ValueError, KeyError, TypeError):
                    continue
                if rec:
                    out.append(rec)
        if out:
            # Loki rejects a stream's entries arriving far out of order (backfill)
            out = [json.dumps(r, separators=(",", ":")) for r in sorted(out, key=lambda r: r["ts"] or "")]
            try:
                if AUDIT_LOG.stat().st_size > MAX_LOG:
                    AUDIT_LOG.replace(AUDIT_LOG.with_suffix(".ndjson.1"))
            except OSError:
                pass
            fd = os.open(AUDIT_LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a") as fh:
                fh.write("\n".join(out) + "\n")
        self.save()
        return len(out)

    def poll_logs(self) -> list[dict]:
        """New lines of nono's per-workspace logs, as records like record()'s."""
        out = []
        try:
            files = {f.stem: f for f in NONO_LOGS.glob("*.log")}
        except OSError:
            return out
        for stem, f in files.items():
            ws, _, kind = stem.partition(".")      # <ws>.log: Claude; <ws>.container.log: its container
            off = self.log_offsets.get(stem, 0)
            try:
                size = f.stat().st_size
                if size < off:          # truncated (rotated below)
                    off = 0
                if size == off:
                    continue
                with f.open("rb") as fh:
                    fh.seek(off)
                    chunk = fh.read(size - off)
            except OSError:
                continue
            end = chunk.rfind(b"\n") + 1
            if not end:
                continue
            self.log_offsets[stem] = off + end
            for raw in chunk[:end].decode("utf-8", "replace").splitlines():
                if rec := self.log_record(ws, raw, kind):
                    out.append(rec)
            # nono keeps the file open in append mode, so it carries on at 0
            if off + end == size > MAX_LOG:
                try:
                    if f.stat().st_size == size:
                        os.truncate(f, 0)
                        self.log_offsets[stem] = 0
                except OSError:
                    pass
        return out

    def log_record(self, ws: str, line: str, kind: str = "") -> dict | None:
        m = LOG_LINE.match(line)
        if not m:
            return None
        ts, level, text = m.groups()
        if level == "AIO" and not kind:
            if text.startswith("session-start") and "events=log" in text and (t := parse_ts(ts)):
                self.log_starts[ws] = (self.log_starts.get(ws, []) + [t])[-50:]
            return None
        keys = list(LOG_KEY.finditer(text))
        msg = text[:keys[0].start()].strip() if keys else text.strip()
        f = {k.group(1): unquote(text[k.end():nxt.start() if nxt else len(text)].strip())
             for k, nxt in zip(keys, keys[1:] + [None])}
        rec = {"workspace": ws, "session": "log", "ts": ts, "via": "log"}
        if kind:
            rec["proxy"] = kind
        if level == "INFO" and msg in LOG_EVENTS:
            decision = LOG_EVENTS[msg] or str(f.get("decision", "")).lower()
            if msg == "l7 endpoint policy decision" and decision == "allow":
                return None     # its "l7 proxy response" line follows, with the status
            rec.update(type="network", decision=decision, target=f.get("host") or f.get("target"))
            for k in ("mode", "port", "method", "path", "status", "reason"):
                if f.get(k) not in (None, ""):
                    rec[k] = int(f[k]) if k in ("port", "status") and str(f[k]).isdigit() else f[k]
            cat = f.get("denial_category") or (
                "host_denied" if "not in the allowlist" in str(f.get("reason", "")) else "")   # 0.80
            if cat:
                rec["denial_category"] = cat
            key = f"{ws}\t{decision}\t{cat}"
            self.net[key] = self.net.get(key, 0) + 1
            return rec
        if "audit buffer full" in msg:
            self.overflow[ws] = self.overflow.get(ws, 0) + 1
            return None
        if level in ("WARN", "ERROR"):
            rec.update(type="nono_log", level=level.lower(), message=text[:1000])
            return rec
        return None

    def covered(self, sid: str, ws: str) -> bool:
        """Whether this session's proxy events already came from nono's log."""
        started, _ = self.sess.get(sid, (None, ""))
        # claude-in writes the marker just before nono starts the session
        return started is not None and any(started - 60 <= t <= started for t in self.log_starts.get(ws, []))

    def record(self, sid: str, ws: str, ev: dict) -> dict | None:
        t = ev.get("type")
        rec = {"workspace": ws, "session": sid, "type": t}
        if t == "network":
            n = ev.get("event") or {}
            if n.get("mode") != "connect" and self.covered(sid, ws):
                return None     # nono's proxy; "connect" ones are syscall denials, not in the log
            ms = n.get("timestamp_unix_ms") or time.time() * 1000
            rec["ts"] = datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat()
            for k in ("decision", "denial_category", "target", "port", "method", "path",
                      "status", "reason", "mode"):
                if n.get(k) is not None:
                    rec[k] = n[k]
            key = f"{ws}\t{n.get('decision', '?')}\t{n.get('denial_category') or ''}"
            self.net[key] = self.net.get(key, 0) + 1
        elif t == "session_started":
            rec["ts"] = ev.get("started")
            rec["command"] = " ".join(ev.get("command") or [])[:500]
            self.sess[sid] = [parse_ts(rec["ts"] or ""), (ev.get("command") or [""])[0]]
            self.sessions[ws] = self.sessions.get(ws, 0) + 1
        elif t == "session_ended":
            rec["ts"] = ev.get("ended")
            rec["exit_code"] = ev.get("exit_code")
        else:
            return None
        return rec


async def disk_usage(wss: list[dict[str, str]]) -> dict[str, int]:
    sizes = {}
    for ws in wss:
        rc, out, _ = await server.run("du", "-sxB1", ws.get("WS_DIR", "/nonexistent"), timeout=60)
        if rc == 0 and out.split():
            sizes[ws["WS_NAME"]] = int(out.split()[0])
    return sizes


BACKUP_GRACE = 2 * 3600            # a scheduled backup this late counts as overdue


def backup_metrics(m: Metrics):
    """From the backup settings and run history the UI server keeps in secrets/."""
    cfg, st = server.load_backup_conf(), server.load_backup_status()
    runs = st.get("runs", [])
    good = [r for r in runs if r.get("ok")]
    nxt = server.next_backup(cfg, st)
    if not server.backup_configured(cfg):
        state = 0
    elif runs and not runs[-1].get("ok"):
        state = 3
    elif nxt is not None and time.time() > nxt + BACKUP_GRACE:
        state = 2                    # the slot passed and nothing ran (UI down, or stuck)
    elif cfg["schedule"] == "off":
        state = 4
    else:
        state = 1
    m.add("aio_backup_state", "gauge",
          "Backup health: 0 not set up, 1 ok, 2 overdue, 3 last run failed, 4 manual only.", state)
    m.add("aio_backup_schedule_info", "gauge", "Backup schedule (always 1) as labels.", 1,
          schedule=cfg["schedule"], time=cfg["time"], weekday=cfg["weekday"],
          projects=int(cfg["include"]["projects"]), config=int(cfg["include"]["config"]),
          claude=int(cfg["include"]["claude"]))
    m.add("aio_backup_keep_days", "gauge", "Days backups are kept on the NAS (0 = all).", cfg["keep_days"])
    if nxt is not None:
        m.add("aio_backup_next_run_timestamp_seconds", "gauge", "When the next scheduled backup is due.",
              int(nxt))
    if runs:
        r = runs[-1]
        m.add("aio_backup_last_run_timestamp_seconds", "gauge", "When the last backup finished.",
              int(r["finished"]))
        m.add("aio_backup_last_run_ok", "gauge", "Whether the last backup succeeded.", int(bool(r.get("ok"))))
        m.add("aio_backup_last_run_duration_seconds", "gauge", "How long the last backup took.",
              round(r["finished"] - r["started"], 1))
        m.add("aio_backup_last_run_warnings", "gauge", "Files the last backup couldn't read in full.",
              len(r.get("warnings", [])))
    if good:
        m.add("aio_backup_last_success_timestamp_seconds", "gauge", "When the last good backup finished.",
              int(good[-1]["finished"]))
        m.add("aio_backup_last_success_bytes", "gauge", "Size of the last good backup's tarball.",
              good[-1].get("size", 0))
    nas = st.get("remote")
    if nas:
        m.add("aio_backup_nas_backups", "gauge", "This host's backups on the NAS, at the last listing.",
              nas["count"])
        m.add("aio_backup_nas_bytes", "gauge", "Space this host's backups use on the NAS.", nas["bytes"])
        if nas.get("free") is not None:
            m.add("aio_backup_nas_free_bytes", "gauge", "Free space on the NAS share.", nas["free"])
            m.add("aio_backup_nas_size_bytes", "gauge", "Size of the NAS share.", nas["total"])
        m.add("aio_backup_nas_listed_timestamp_seconds", "gauge", "When the NAS folder was last listed.",
              int(nas["at"]))


SERVICES = {"ui": "agent-sandboxes-ui.service", "proxy": "agent-sandboxes-proxy.service"}


async def service_metrics(m: Metrics):
    """The two system units, and what the proxy service reports on its control socket."""
    _, out, _ = await server.run("systemctl", "is-active", *SERVICES.values())
    states = out.split()
    for (svc, unit), state in zip(SERVICES.items(), states):
        m.add("aio_service_up", "gauge", "Whether the system unit is active.", int(state == "active"),
              service=svc, unit=unit, state=state)
    st = await server.proxyd({"op": "status"}, timeout=5)
    m.add("aio_proxy_responding", "gauge", "The proxy service answered on its control socket.",
          int("error" not in st))
    if "error" in st:
        return
    m.add("aio_proxy_code_current", "gauge",
          "The proxy service runs the code on disk (0: restart agent-sandboxes-proxy to update it).",
          int(st.get("version") == server.proxyd_source_version()))
    m.add("aio_proxy_start_timestamp_seconds", "gauge", "When the proxy service started.", int(st["started"]))
    m.add("aio_proxy_bridge_up", "gauge", "The HTTP API bridge is listening.", int(bool(st.get("bridge"))))
    m.add("aio_proxy_problems", "gauge", "Proxies that can't run (see the proxy service's journal).",
          len(st.get("problems", [])))
    for n, v in sorted(st.get("port_filter_denied", {}).items()):
        m.add("aio_port_filter_denied_total", "counter",
              "Connections the port filter refused (host allowed by nono, port not listed).", v, workspace=n)
    running = st.get("container_proxies", {})
    for n in st.get("port_filters", []):
        m.add("aio_proxy_port_filter_up", "gauge", "The workspace's port filter is listening.", 1, workspace=n)
    for n, state in sorted(running.items()):
        m.add("aio_proxy_container_proxy_up", "gauge",
              "The container's nono proxy is running (Container network: Same as Claude).",
              int(state == "running"), workspace=n)


async def collect(audit: Audit, du: dict[str, int]) -> str:
    m = Metrics()
    t0 = time.monotonic()
    wss = server.all_ws()
    status = {s["name"]: s for s in await server.status_all()}
    audit.poll(wss)
    scopes = claude_scopes()
    for ws in wss:
        n = ws["WS_NAME"]
        s = status.get(n, {})
        pol = server.load_policy(n)
        lim = pol["limits"]
        m.add("aio_workspace_info", "gauge", "Workspace (always 1) with its settings as labels.", 1,
              workspace=n, dir=ws.get("WS_DIR", ""), port=ws.get("WS_PORT", ""),
              network=pol["network"]["mode"])
        m.add("aio_workspace_container_up", "gauge", "AIO Sandbox container is running.",
              int(s.get("container") == "running"), workspace=n)
        m.add("aio_workspace_container_healthy", "gauge", "AIO Sandbox container reports healthy.",
              int("(healthy)" in s.get("containerDetail", "")), workspace=n)
        m.add("aio_workspace_claude_running", "gauge", "Claude's tmux session is alive.",
              int(s.get("claude") == "running"), workspace=n)
        m.add("aio_workspace_policy_pending", "gauge",
              "Saved policy differs from the one the running Claude started with.",
              int(bool(s.get("policyPending"))), workspace=n)
        m.add("aio_workspace_ssh_keys", "gauge", "SSH keys assigned from the pool.",
              len(pol["ssh_keys"]), workspace=n)
        m.add("aio_workspace_tokens", "gauge", "API tokens assigned from the pool.",
              len(pol["tokens"]), workspace=n)
        mem = lim.get("memory") or ""
        m.add("aio_workspace_memory_limit_bytes", "gauge", "Claude memory limit (0 = none).",
              int(mem[:-1]) * (1 << (30 if mem.endswith("G") else 20)) if mem else 0, workspace=n)
        m.add("aio_workspace_pids_limit", "gauge", "Claude process limit (0 = none).",
              int(lim.get("pids") or 0), workspace=n)
        if n in du:
            m.add("aio_workspace_dir_bytes", "gauge", "Disk used by the project folder.",
                  du[n], workspace=n)
        u = scopes.get(n)
        if u:
            m.add("aio_claude_scopes", "gauge", "Running Claude scopes (sessions).", u["scopes"],
                  workspace=n)
            m.add("aio_claude_memory_bytes", "gauge", "Memory used by Claude and its children.",
                  u["mem"], workspace=n)
            m.add("aio_claude_memory_peak_bytes", "gauge", "Peak memory of the Claude scope(s).",
                  u["peak"], workspace=n)
            m.add("aio_claude_cpu_seconds_total", "counter", "CPU time of Claude and its children.",
                  u["cpu_us"] / 1e6, workspace=n)
            m.add("aio_claude_pids", "gauge", "Processes in the Claude scope(s).", u["pids"],
                  workspace=n)
            m.add("aio_claude_oom_kills_total", "counter", "OOM kills in the Claude scope(s).",
                  u["oom"], workspace=n)
    for key, v in sorted(audit.net.items()):
        ws, decision, cat = key.split("\t")
        m.add("aio_nono_network_events_total", "counter",
              "Network connections nono allowed or denied.", v,
              workspace=ws, decision=decision, category=cat)
    for ws, v in sorted(audit.sessions.items()):
        m.add("aio_nono_sessions_total", "counter", "nono sandbox sessions started.", v,
              workspace=ws)
    for ws, v in sorted(audit.overflow.items()):
        m.add("aio_nono_audit_overflow_total", "counter",
              "Proxy events past nono's 4096-event session buffer (still shipped from nono's log).",
              v, workspace=ws)
    backup_metrics(m)
    await service_metrics(m)
    m.add("aio_exporter_scrape_duration_seconds", "gauge", "Time taken to collect.",
          round(time.monotonic() - t0, 3))
    m.add("aio_exporter_last_run_timestamp_seconds", "gauge", "When metrics were last written.",
          int(time.time()))
    return m.text()


async def main():
    OUT.mkdir(mode=0o700, parents=True, exist_ok=True)
    audit = Audit()
    du: dict[str, int] = {}
    du_at = 0.0
    while True:
        try:
            if time.monotonic() - du_at > DU_EVERY:
                du_at = time.monotonic()
                du = await disk_usage(server.all_ws())
            text = await collect(audit, du)
            tmp = PROM.with_suffix(".tmp")
            tmp.write_text(text)
            tmp.replace(PROM)
        except Exception as e:   # keep running; the stale timestamp shows up in Grafana
            print(f"collect failed: {e!r}", flush=True)
        if "--once" in sys.argv:
            return
        await asyncio.sleep(INTERVAL)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
