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
    directory, which Alloy ships to Loki. Event counts are exported too.

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
NONO_STATE = Path.home() / ".local" / "state" / "nono"
CGROUP_APP = Path(f"/sys/fs/cgroup/user.slice/user-{os.getuid()}.slice/"
                  f"user@{os.getuid()}.service/app.slice")
SCOPE_RE = re.compile(r"^claude-(.+)-\d+\.scope$")
INTERVAL = float(os.environ.get("AIO_EXPORTER_INTERVAL", "15"))
DU_EVERY = 300                       # seconds between workspace disk-usage scans
MAX_LOG = 20 * 1024 * 1024           # rotate nono-audit.ndjson (one old copy kept)


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

    def save(self):
        server.private_write(OFFSETS, json.dumps(
            {"offsets": self.offsets, "ws_of": self.ws_of, "net": self.net,
             "sessions": self.sessions}))

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
        out = []
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

    def record(self, sid: str, ws: str, ev: dict) -> dict | None:
        t = ev.get("type")
        rec = {"workspace": ws, "session": sid, "type": t}
        if t == "network":
            n = ev.get("event") or {}
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
