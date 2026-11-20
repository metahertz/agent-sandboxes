"""Apple builds: the web UI's side of the build host (buildhost/aio-buildd).

A workspace with "Apple builds" ticked gets an MCP server, aio-builds, that
the agent reaches like an API token route: nono's proxy adds the workspace's
key (X-AIO-Build) on the way to the proxy service's bridge (/~build), which
looks the key up and passes the request here, on a Unix socket only the
proxy service can reach, naming the workspace. The agent never holds a git
credential or a connection to the build host:

  submit   copy the commit out of the workspace's repo into a clean mirror
           here (secrets/builds/mirrors/<ws>.git; git's upload-pack, which is
           safe on an untrusted repo, and never the repo's hooks or config),
           tag it build/<id> with the job as the tag message, and push the tag
           to the build host over ssh with the UI's key
  watch    one long-running `ssh … watch`: the build host's state, kept here
           for the UI and the MCP tools
  …        log, result, file, cancel, abandon: one ssh command each (a shared
           ssh connection, ControlMaster)

The build host's key and address: secrets/builds/ (bin/install-buildhost
sets them up for a build host on this machine).
"""

import asyncio
import base64
import hmac
import json
import os
import re
import secrets
import shlex
import shutil
import time
from pathlib import Path

from common import RUNTIME, SECRETS

BUILDS_DIR = SECRETS / "builds"
CONFIG_FILE = BUILDS_DIR / "config.json"
UI_KEY = BUILDS_DIR / "ui_ed25519"
KNOWN_HOSTS = BUILDS_DIR / "known_hosts"
MCP_KEYS = BUILDS_DIR / "mcp"               # one per workspace with builds on: what nono injects
MIRRORS = BUILDS_DIR / "mirrors"
MCP_SOCK = RUNTIME / "builds-mcp.sock"      # the proxy service's bridge connects here
ROUTE = "aio_build"                          # nono route: $AIO_BUILD_BASE_URL, $AIO_BUILD_KEY
MCP_NAME = "aio-builds"

ID_RE = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{6}$")
WS_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,29}$")
REF_RE = re.compile(r"^(HEAD|[A-Za-z0-9][A-Za-z0-9._/-]{0,100})$")
HOST_RE = re.compile(r"^([a-z_][a-z0-9_-]{0,31}@)?([A-Za-z0-9][A-Za-z0-9.-]{0,252}|\[[0-9A-Fa-f:.]+\])$")
WORKER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,29}$")
# The job spec; the build host and the worker check the same rules
SPEC_RULES = {
    "action": re.compile(r"^(build|test|run|archive)$"),
    "scheme": re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.+-]{0,99}$"),
    "project": re.compile(r"^$|^(?![/-])(?!.*(^|/)\.\.(/|$))[A-Za-z0-9 _.+/-]{1,200}$"),
    "destination": re.compile(r"^$|^[A-Za-z0-9 _.,=:()+/-]{1,200}$"),
    "configuration": re.compile(r"^$|^[A-Za-z0-9_-]{1,40}$"),
}
FINAL = {"passed", "failed", "error", "cancelled", "timeout", "abandoned"}


class BuildError(Exception):
    pass


# ---------------------------------------------------------------- config
def config() -> dict:
    try:
        c = json.loads(CONFIG_FILE.read_text())
    except (OSError, ValueError):
        c = {}
    return {"host": c.get("host", ""), "port": int(c.get("port", 22) or 22)}


def save_config(host: str, port: int):
    host, port = host.strip(), int(port)
    if host and not HOST_RE.match(host):
        raise BuildError("Build host: user@host, e.g. aiogit@127.0.0.1")
    if not 1 <= port <= 65535:
        raise BuildError("Port: 1-65535")
    old = config()
    BUILDS_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = CONFIG_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps({"host": host, "port": port}) + "\n")
    tmp.chmod(0o600)
    tmp.replace(CONFIG_FILE)
    if (old["host"], old["port"]) != (host, port):
        KNOWN_HOSTS.unlink(missing_ok=True)         # a new host: trust its key on first contact


async def ensure_key() -> str:
    BUILDS_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not UI_KEY.is_file():
        p = await asyncio.create_subprocess_exec(
            "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "agent-sandboxes-ui", "-f", str(UI_KEY),
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await p.wait()
    try:
        return UI_KEY.with_suffix(".pub").read_text().strip()
    except OSError:
        return ""


def ssh_base() -> list[str]:
    c = config()
    return ["ssh", "-F", "/dev/null", "-i", str(UI_KEY), "-o", "IdentitiesOnly=yes",
            "-o", f"UserKnownHostsFile={KNOWN_HOSTS}", "-o", "StrictHostKeyChecking=accept-new",
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=20",
            "-o", "ControlMaster=auto", "-o", f"ControlPath={RUNTIME}/builds-ssh-%C",
            "-o", "ControlPersist=300", "-p", str(c["port"])]


def repo_url(ws: str) -> str:
    c = config()
    user, _, host = c["host"].rpartition("@")
    return f"ssh://{user + '@' if user else ''}{host}:{c['port']}/{ws}.git"


async def call(*cmd: str, input: bytes | None = None, timeout: float = 30) -> bytes:
    if not config()["host"]:
        raise BuildError("No build host set up (Settings → Apple builds)")
    p = await asyncio.create_subprocess_exec(
        *ssh_base(), config()["host"], " ".join(shlex.quote(c) for c in cmd),
        stdin=asyncio.subprocess.PIPE if input is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        out, err = await asyncio.wait_for(p.communicate(input), timeout)
    except asyncio.TimeoutError:
        p.kill()
        raise BuildError(f"the build host didn't answer ({cmd[0]})")
    if p.returncode != 0:
        msg = err.decode(errors="replace").strip().splitlines()
        raise BuildError((msg[-1] if msg else f"ssh exited {p.returncode}").removeprefix("aio-buildd: "))
    return out


async def call_json(*cmd: str, input: bytes | None = None) -> dict:
    try:
        return json.loads(await call(*cmd, input=input))
    except ValueError:
        raise BuildError(f"the build host sent something that isn't JSON ({cmd[0]})")


# ---------------------------------------------------------------- monitor
class Monitor:
    """The build host's state, from one `ssh … watch` (it sends a snapshot on
    every change). Restarted when the config changes."""

    def __init__(self):
        self.state: dict = {}
        self.connected = False
        self.error = ""
        self.since = 0.0
        self.task: asyncio.Task | None = None
        self.changed = asyncio.Event()

    def start(self):
        if self.task:
            self.task.cancel()
        self.state, self.connected, self.error = {}, False, ""
        self.task = asyncio.create_task(self.run())

    async def run(self):
        delay = 2
        while True:
            if not config()["host"]:
                self.error = ""
                await asyncio.sleep(10)
                continue
            proc = None
            try:
                await ensure_key()
                proc = await asyncio.create_subprocess_exec(
                    *ssh_base(), config()["host"], "watch", stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, limit=16 << 20)
                while True:
                    line = await asyncio.wait_for(proc.stdout.readline(), 60)
                    if not line:
                        break
                    try:
                        msg = json.loads(line)
                    except ValueError:
                        continue
                    if msg.get("type") == "status":
                        self.state, self.connected, self.error, delay = msg, True, "", 2
                        self.since = time.time()
                        self.changed.set()
                        self.changed = asyncio.Event()
                err = (await proc.stderr.read()).decode(errors="replace").strip().splitlines()
                self.error = (err[-1] if err else "the build host closed the connection").removeprefix("aio-buildd: ")
            except asyncio.CancelledError:
                if proc and proc.returncode is None:
                    proc.kill()
                raise
            except (OSError, asyncio.TimeoutError, ValueError) as e:
                self.error = f"no answer from the build host ({e.__class__.__name__})"
            finally:
                if proc and proc.returncode is None:
                    proc.kill()
                    await proc.wait()
            self.connected = False
            await asyncio.sleep(delay)
            delay = min(delay * 2, 60)

    def jobs(self, ws: str) -> list[dict]:
        return list(self.state.get("repos", {}).get(ws, []))

    def job(self, ws: str, jid: str) -> dict | None:
        return next((j for j in self.jobs(ws) if j["id"] == jid), None)

    def workers(self) -> list[dict]:
        return list(self.state.get("workers", []))


monitor = Monitor()


def overview() -> dict:
    c = config()
    return {"host": c["host"], "port": c["port"], "connected": monitor.connected, "error": monitor.error,
            "workers": monitor.workers(), "version": monitor.state.get("version", ""),
            "repos": {k: len(v) for k, v in monitor.state.get("repos", {}).items()}}


async def wait_for_change(ws: str, jid: str, until: float):
    """Until the job is finished, or the time is up."""
    while time.time() < until:
        j = monitor.job(ws, jid)
        if j and j.get("state") in FINAL:
            return
        try:
            await asyncio.wait_for(monitor.changed.wait(), max(0.1, min(5, until - time.time())))
        except asyncio.TimeoutError:
            pass


# ---------------------------------------------------------------- submit
def mcp_key_path(ws: str) -> Path:
    return MCP_KEYS / f"{ws}.key"


def ensure_mcp_key(ws: str) -> Path:
    p = mcp_key_path(ws)
    if not p.is_file():
        MCP_KEYS.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("aiob_" + secrets.token_urlsafe(32))
    return p


def workspace_for_key(key: str) -> str:
    """The proxy service's lookup (constant time per key)."""
    found = ""
    for p in MCP_KEYS.glob("*.key"):
        try:
            if hmac.compare_digest(p.read_text().strip().encode(), key.strip().encode()) and key:
                found = p.stem
        except OSError:
            pass
    return found


def git_env(home: Path) -> dict:
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home), "LANG": "C.UTF-8",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
            "GIT_SSH_COMMAND": " ".join(shlex.quote(x) for x in ssh_base())}


async def git(*args: str, env: dict, input: bytes | None = None, timeout: float = 300) -> str:
    p = await asyncio.create_subprocess_exec(
        "git", *args, env=env, stdin=asyncio.subprocess.PIPE if input is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        out, err = await asyncio.wait_for(p.communicate(input), timeout)
    except asyncio.TimeoutError:
        p.kill()
        raise BuildError(f"git {args[0]} took too long")
    if p.returncode != 0:
        verb = next((a for i, a in enumerate(args) if not a.startswith("-")
                     and (i == 0 or args[i - 1] not in ("--git-dir", "-c"))), "")
        raise BuildError(f"git {verb}: {err.decode(errors='replace').strip()[-400:]}")
    return out.decode().strip()


def source_git_dir(ws_dir: str, sub: str) -> Path:
    """The workspace's repo, which the agent controls: a plain .git folder
    inside the project folder, not one that borrows objects from elsewhere
    (what's sent is only what that repo holds)."""
    root = Path(ws_dir).resolve()
    top = (root / sub).resolve() if sub else root
    if not top.is_relative_to(root):
        raise BuildError("repo: a folder inside the project")
    g = top / ".git"
    if g.is_symlink() or not g.is_dir():
        raise BuildError(f"No git repository at {top} (a .git folder; worktrees and submodule checkouts aren't "
                         "supported): git init and commit first")
    for f in ("commondir", "objects/info/alternates"):
        if (g / f).exists():
            raise BuildError(f"{g}/{f} exists: a repository that borrows objects from elsewhere can't be sent")
    if not g.resolve().is_relative_to(root):
        raise BuildError("the repository is outside the project folder")
    for d in ("objects", "refs"):
        if (g / d).is_symlink():
            raise BuildError(f"{g}/{d} is a symlink: not sending objects from elsewhere")
    for top_dir, dirs, files in os.walk(g / "objects"):
        if any(os.path.islink(os.path.join(top_dir, x)) for x in dirs + files):
            raise BuildError(f"{g}/objects holds symlinks: not sending objects from elsewhere")
    return g


def clean_spec(params: dict) -> dict:
    spec = {"v": 1}
    for k, rx in SPEC_RULES.items():
        v = params.get(k, "")
        v = "" if v is None else str(v).strip()
        if not rx.match(v):
            raise BuildError(f"{k}: {'required' if not v else 'not allowed: ' + v[:60]}")
        spec[k] = v
    if spec["action"] in ("test", "run") and not spec["destination"].startswith("platform="):
        raise BuildError(f"{spec['action']} needs a destination, e.g. platform=iOS Simulator,name=iPhone 16")
    t = params.get("timeout_min", 60)
    try:
        t = int(t)
    except (TypeError, ValueError):
        raise BuildError("timeout_min: a number of minutes")
    if not 1 <= t <= 240:
        raise BuildError("timeout_min: 1-240")
    spec["timeout_min"] = t
    return spec


async def submit(ws: str, ws_dir: str, params: dict, by: str) -> dict:
    if not WS_RE.match(ws):
        raise BuildError("bad workspace")
    if not config()["host"]:
        raise BuildError("No build host is set up (Settings → Apple builds)")
    spec = clean_spec(params)
    ref = str(params.get("ref") or "HEAD").strip()
    sub = str(params.get("repo") or "").strip().strip("/")
    if not REF_RE.match(ref) or ".." in ref:
        raise BuildError("ref: a branch or tag name, or HEAD")
    if sub and not SPEC_RULES["project"].match(sub):
        raise BuildError("repo: a folder inside the project")
    src = source_git_dir(ws_dir, sub)
    await ensure_key()
    mirror = MIRRORS / f"{ws}.git"
    env = git_env(MIRRORS)
    if not (mirror / "HEAD").is_file():
        MIRRORS.mkdir(mode=0o700, parents=True, exist_ok=True)
        await git("init", "-q", "--bare", str(mirror), env=env)
    g = ("--git-dir", str(mirror), "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=always")
    jid = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + secrets.token_hex(3)
    tmp_ref = f"refs/src/{jid}"
    await git(*g, "fetch", "-q", "--no-tags", "--no-write-fetch-head", f"file://{src}",
              f"+{ref}:{tmp_ref}", env=env, timeout=600)
    try:
        commit = await git(*g, "rev-parse", "--verify", f"{tmp_ref}^{{commit}}", env=env)
        spec.update(workspace=ws, commit=commit, by=by,
                    submitted=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        msg = json.dumps(spec, indent=1, sort_keys=True) + "\n"
        await git(*g, "-c", "user.name=agent-sandboxes", "-c", "user.email=builds@agent-sandboxes.invalid",
                  "tag", "-a", "-F", "-", f"build/{jid}", commit, env=env, input=msg.encode())
        await git(*g, "push", "-q", repo_url(ws), f"refs/tags/build/{jid}", env=env, timeout=900)
    finally:
        try:
            await git(*g, "update-ref", "-d", tmp_ref, env=env)
        except BuildError:
            pass
    return {"workspace": ws, "id": jid, "commit": commit, "spec": spec, "state": "queued"}


# ---------------------------------------------------------------- job ops
def check_job(ws: str, jid: str):
    if not WS_RE.match(ws) or not ID_RE.match(jid):
        raise BuildError("No such build")


async def job(ws: str, jid: str) -> dict:
    check_job(ws, jid)
    return await call_json("result", ws, jid)


async def job_log(ws: str, jid: str, offset: int = 0) -> bytes:
    check_job(ws, jid)
    return await call("log", ws, jid, str(max(0, int(offset))), timeout=60)


async def job_file(ws: str, jid: str, path: str) -> bytes:
    check_job(ws, jid)
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,200}$", path) or ".." in path:
        raise BuildError("bad path")
    return await call("file", ws, jid, path, timeout=60)


async def artifact_stream(ws: str, jid: str, name: str):
    """(process, stdout) streaming the artifact; the caller reads and waits."""
    check_job(ws, jid)
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$", name):
        raise BuildError("bad artifact name")
    return await asyncio.create_subprocess_exec(
        *ssh_base(), config()["host"], f"artifact-get {ws} {jid} {name}",
        stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)


async def cancel(ws: str, jid: str, abandon: bool = False):
    check_job(ws, jid)
    await call_json("abandon" if abandon else "cancel", ws, jid)


async def add_worker(name: str, key: str):
    if not WORKER_RE.match(name):
        raise BuildError("Worker name: lowercase letters, digits and -")
    await call_json("add-worker", name, input=key.strip().encode())


async def remove_worker(name: str):
    if not WORKER_RE.match(name):
        raise BuildError("bad worker name")
    await call_json("remove-worker", name)


def remove_workspace(ws: str):
    mcp_key_path(ws).unlink(missing_ok=True)
    shutil.rmtree(MIRRORS / f"{ws}.git", ignore_errors=True)


# ---------------------------------------------------------------- MCP
# Streamable HTTP, JSON responses only (no SSE, no sessions): enough for
# Claude Code and Hermes. The bridge has already checked the workspace's key.

INSTRUCTIONS = (
    "Builds and tests Apple apps (iOS, macOS) with Xcode on a Mac build worker, each job in a fresh macOS "
    "VM that is deleted afterwards. It builds a commit of this workspace's git repository (HEAD by default): "
    "commit your changes first, uncommitted changes aren't sent. Typical loop: apple_build, then "
    "build_status with wait_seconds until it finishes, then build_log / build_result. Builds are unsigned "
    "(no App Store or device signing here).")

TOOLS = [
    {"name": "apple_build",
     "description": "Queue an Xcode job for a commit of this workspace's repo. action: build, test (runs the "
                    "scheme's tests; needs a simulator destination), run (build, install and launch in the "
                    "Simulator, then take a screenshot), archive (an unsigned .xcarchive, zipped, kept as an "
                    "artifact). Returns the job id.",
     "inputSchema": {"type": "object", "required": ["action", "scheme"], "properties": {
         "action": {"type": "string", "enum": ["build", "test", "run", "archive"]},
         "scheme": {"type": "string", "description": "the Xcode scheme"},
         "project": {"type": "string", "description": "path in the repo to the .xcodeproj or .xcworkspace, or "
                                                      "a Swift package's folder; empty: xcodebuild finds it"},
         "destination": {"type": "string", "description": "xcodebuild -destination, e.g. "
                                                          "'platform=iOS Simulator,name=iPhone 16' or "
                                                          "'generic/platform=iOS Simulator'"},
         "configuration": {"type": "string", "description": "Debug or Release (the scheme's default if empty)"},
         "ref": {"type": "string", "description": "branch or tag to build (default HEAD)"},
         "repo": {"type": "string", "description": "the repo's folder within the project, if not the top"},
         "timeout_min": {"type": "integer", "minimum": 1, "maximum": 240, "default": 60}}}},
    {"name": "build_status",
     "description": "One build's state (queued, running, passed, failed, error, cancelled, timeout), or with no id "
                    "the recent builds and whether a Mac worker is online. wait_seconds (up to 100) waits for "
                    "the build to finish first; call it again to keep waiting.",
     "inputSchema": {"type": "object", "properties": {
         "id": {"type": "string"}, "wait_seconds": {"type": "integer", "minimum": 0, "maximum": 100}}}},
    {"name": "build_log",
     "description": "A build's log (xcodebuild's output). By default the last 200 lines; offset (bytes) reads "
                    "from there, e.g. to follow a running build.",
     "inputSchema": {"type": "object", "required": ["id"], "properties": {
         "id": {"type": "string"}, "tail_lines": {"type": "integer", "minimum": 1, "maximum": 3000},
         "offset": {"type": "integer", "minimum": 0}}}},
    {"name": "build_result",
     "description": "A finished build's summary, its test results (action test) and Simulator screenshots "
                    "(action run), as images.",
     "inputSchema": {"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}},
    {"name": "cancel_build",
     "description": "Cancel a queued or running build.",
     "inputSchema": {"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}},
]


def text(s: str, error: bool = False) -> dict:
    return {"content": [{"type": "text", "text": s}], **({"isError": True} if error else {})}


def job_line(j: dict) -> str:
    s = j.get("spec", {})
    extra = ""
    if j.get("summary", {}).get("seconds") is not None:
        extra = f", {j['summary']['seconds']} s"
    if j.get("worker"):
        extra += f", on {j['worker']}"
    return (f"{j['id']}: {j.get('state')} — {s.get('action')} {s.get('scheme')} at {j.get('commit', '')[:10]}"
            f"{extra}")


async def tool_call(ws: str, ws_dir: str, name: str, args: dict) -> dict:
    try:
        if name == "apple_build":
            j = await submit(ws, ws_dir, args, "agent")
            online = [w["name"] for w in monitor.workers() if w.get("online")]
            note = "" if online else " No Mac worker is online right now: it waits in the queue until one is."
            return text(f"Queued build {j['id']} ({j['spec']['action']} {j['spec']['scheme']} at "
                        f"{j['commit'][:10]}).{note} Next: build_status with id and wait_seconds.")
        if name == "build_status":
            jid = str(args.get("id") or "")
            if not jid:
                jobs = monitor.jobs(ws)[:15]
                ws_line = ", ".join(f"{w['name']} ({'online' if w.get('online') else 'offline'})"
                                    for w in monitor.workers()) or "none"
                head = (f"Build host: {'connected' if monitor.connected else 'not connected: ' + monitor.error}. "
                        f"Mac workers: {ws_line}.")
                return text(head + "\n" + ("\n".join(job_line(j) for j in jobs) or "No builds yet."))
            check_job(ws, jid)
            wait = max(0, min(100, int(args.get("wait_seconds") or 0)))
            if wait:
                await wait_for_change(ws, jid, time.time() + wait)
            j = monitor.job(ws, jid) or await job(ws, jid)
            out = job_line(j)
            if j.get("state") in ("queued", "running", "stale"):
                out += f"\nLog so far: {j.get('log_size', 0)} bytes (build_log)."
            if j.get("state") == "stale":
                out += "\nIts worker stopped sending heartbeats; it may be gone."
            if s := j.get("summary"):
                if s.get("error"):
                    out += f"\nError: {s['error']}"
                if s.get("xcode"):
                    out += f"\n{s['xcode']}"
            return text(out)
        if name == "build_log":
            jid = str(args.get("id") or "")
            check_job(ws, jid)
            if args.get("offset") is not None:
                data = (await job_log(ws, jid, int(args["offset"]))).decode(errors="replace")
                return text(data[-200_000:] or "(nothing more yet)")
            j = monitor.job(ws, jid)
            size = (j or {}).get("log_size", 0)
            data = (await job_log(ws, jid, max(0, size - 2_000_000))).decode(errors="replace")
            lines = data.splitlines()[-max(1, min(3000, int(args.get("tail_lines") or 200))):]
            return text("\n".join(lines) or "(no log yet)")
        if name == "build_result":
            jid = str(args.get("id") or "")
            j = await job(ws, jid)
            s = j.get("summary")
            if not s:
                return text(f"{job_line(j)}\nNot finished yet.")
            content = [{"type": "text", "text": job_line(j) + "\n" + json.dumps(
                {k: v for k, v in s.items() if k not in ("files",)}, indent=1)}]
            files = s.get("files", [])
            if "test-summary.json" in files:
                ts = (await job_file(ws, jid, "test-summary.json")).decode(errors="replace")
                content.append({"type": "text", "text": "Test results:\n" + ts[:50_000]})
            for f in [f for f in files if f.startswith("screenshots/") and f.endswith(".png")][:4]:
                data = await job_file(ws, jid, f)
                content.append({"type": "image", "data": base64.b64encode(data).decode(), "mimeType": "image/png"})
            if j.get("artifacts"):
                content.append({"type": "text", "text": "Artifacts (download in the web UI's Builds tab): "
                                + ", ".join(j["artifacts"])})
            return {"content": content}
        if name == "cancel_build":
            jid = str(args.get("id") or "")
            await cancel(ws, jid)
            return text(f"Asked to cancel {jid}.")
        return text(f"No tool {name}", True)
    except (BuildError, ValueError) as e:
        return text(str(e), True)


async def mcp_rpc(ws: str, ws_dir: str, msg: dict) -> dict | None:
    mid, method = msg.get("id"), msg.get("method", "")
    if mid is None:
        return None                       # a notification
    if method == "initialize":
        want = (msg.get("params") or {}).get("protocolVersion", "")
        ver = want if want in ("2025-06-18", "2025-03-26", "2024-11-05") else "2025-06-18"
        result = {"protocolVersion": ver, "capabilities": {"tools": {}},
                  "serverInfo": {"name": MCP_NAME, "version": "1"}, "instructions": INSTRUCTIONS}
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        p = msg.get("params") or {}
        result = await tool_call(ws, ws_dir, str(p.get("name", "")), p.get("arguments") or {})
    else:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"Method not found: {method}"}}
    return {"jsonrpc": "2.0", "id": mid, "result": result}


async def serve_mcp(load_ws, enabled):
    """The Unix socket the proxy service's bridge passes MCP requests to.
    load_ws(name) -> the workspace's env, or None; enabled(name): builds on."""
    MCP_SOCK.unlink(missing_ok=True)

    async def handle(reader, w):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
            lines = head[:-4].decode("latin-1").split("\r\n")
            method, path = (lines[0].split(" ") + ["", ""])[:2]
            h = {k.strip().lower(): v.strip() for k, _, v in (x.partition(":") for x in lines[1:])}
            body = await reader.readexactly(min(int(h.get("content-length", "0") or 0), 4 << 20))
            ws = h.get("x-aio-workspace", "")
            env = load_ws(ws) if WS_RE.match(ws) else None
            if not env or not enabled(ws):
                return reply(w, 403, {"error": "unknown workspace"})
            if path.rstrip("/").split("?")[0] != "/mcp":
                return reply(w, 404, {"error": "the MCP endpoint is /mcp"})
            if method != "POST":
                return reply(w, 405, {"error": "POST JSON-RPC to /mcp"})
            try:
                msg = json.loads(body)
            except ValueError:
                return reply(w, 400, {"jsonrpc": "2.0", "id": None,
                                      "error": {"code": -32700, "message": "Parse error"}})
            if isinstance(msg, list):
                out = [r for r in [await mcp_rpc(ws, env["WS_DIR"], m) for m in msg if isinstance(m, dict)] if r]
            else:
                out = await mcp_rpc(ws, env["WS_DIR"], msg) if isinstance(msg, dict) else None
            if not out:
                return reply(w, 202, None)
            reply(w, 200, out)
        except (OSError, ValueError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
            pass
        finally:
            try:
                await w.drain()
            except OSError:
                pass
            w.close()

    server = await asyncio.start_unix_server(handle, str(MCP_SOCK), limit=64 * 1024)
    MCP_SOCK.chmod(0o600)
    return server


def reply(w, status: int, obj):
    body = b"" if obj is None else json.dumps(obj).encode()
    reason = {200: "OK", 202: "Accepted", 400: "Bad Request", 403: "Forbidden", 404: "Not Found",
              405: "Method Not Allowed"}.get(status, "OK")
    w.write(f"HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n".encode() + body)
