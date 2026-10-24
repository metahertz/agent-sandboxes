#!/usr/bin/env python3
"""Agent Sandboxes web UI.

Manages the lifecycle of nono-sandboxed Claude Code workspaces, each
paired with an AIO Sandbox container: create / start / stop / remove,
a browser terminal onto the workspace's Claude session (tmux), a file
browser with downloads from the container, and the container's VNC /
web UI through an authenticating reverse proxy. Also a pool of SSH keys and
API tokens assigned per workspace, and each workspace's nono policy
(network allowlist, resource limits), rendered to a per-workspace profile.

Stdlib only (this host has no pip). Listens on 127.0.0.1 and the host's
primary IP (override with AIO_UI_BIND=addr[,addr...]).

Routing:
  <host>:443 (AIO_UI_PORT)           -> this UI (token login, cookie)
  <host>:<workspace port + 1000>     -> that workspace's sandbox
  <workspace>.localhost:<UI port>    -> same, for SSH-tunnel access
Sandbox requests carry a per-workspace capability path and get the
sandbox API key injected here, so the key never reaches a browser.
"""

import asyncio
import base64
import ctypes
import fcntl
import hashlib
import hmac
import json
import mimetypes
import os
import posixpath
import pwd
import re
import secrets
import shlex
import shutil
import socket
import ssl
import struct
import sys
import termios
import urllib.parse
from pathlib import Path

ROOT = Path(os.environ.get("AIO_ROOT", Path.home() / "agent-sandboxes"))
WS_ROOT = ROOT / "workspaces"
COMPOSE_FILE = ROOT / "compose.workspace.yaml"
CLAUDE_IN = ROOT / "bin" / "claude-in"
MCP_TEMPLATE = ROOT / "mcp.json.template"
STATIC = ROOT / "ui" / "static"
TOKEN_FILE = ROOT / "ui" / "token"
TLS_DIR = ROOT / "ui" / "tls"
CERT_TOOL = ROOT / "bin" / "sandbox-ui-cert"
TMUX_CONF = ROOT / "ui" / "tmux.conf"
SECRETS = ROOT / "secrets"              # key/token pool; never readable inside nono
SSH_POOL = SECRETS / "ssh"
TOKEN_POOL = SECRETS / "tokens"
STATE_ROOT = ROOT / "state"             # per-workspace ssh_config / known_hosts (Claude-writable)
LIBEXEC = ROOT / "libexec"              # helpers Claude may run (read-only)
RUNTIME = Path(os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}") / "agent-sandboxes"
PROJECTS_BASE = Path(os.environ.get("AIO_PROJECTS", Path.home() / "projects"))
LISTEN_PORT = int(os.environ.get("AIO_UI_PORT", "9000"))
SANDBOX_PORTS = range(8101, 8200)
PROXY_PORT_OFFSET = 1000          # sandbox 8101 is served to browsers on 9101

TMUX = ["tmux", "-L", "agent-sandboxes", "-f", str(TMUX_CONF)]
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,29}$")
ITEM_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")          # pool key / token ids
DOMAIN_RE = re.compile(r"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$")
ENV_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,63}$")
HEADER_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
MEM_RE = re.compile(r"^[1-9][0-9]{0,5}[MG]$")
DIR_RE = re.compile(r"^/[A-Za-z0-9._/-]+$")
UI_HOSTNAMES = {"localhost", "127.0.0.1"}   # extended at startup with bind IPs / hostname
BIND: list[str] = []
TLS_CTX: ssl.SSLContext | None = None        # set at startup unless AIO_UI_TLS=0
SCHEME, WS_SCHEME = "http", "ws"
WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_HEAD = 64 * 1024
MAX_BODY = 1024 * 1024

USER_GID = pwd.getpwuid(os.getuid()).pw_gid
TOKEN = ""
CAP_SALT = secrets.token_hex(16)   # sandbox links stop working when the server restarts
sandbox_listeners: dict[str, list[asyncio.Server]] = {}


# --------------------------------------------------------------- helpers

def session_value(scope: str) -> str:
    return hmac.new(TOKEN.encode(), scope.encode(), hashlib.sha256).hexdigest()


def sandbox_prefix(name: str) -> str:
    """Capability path for one workspace's sandbox. Cookies can't be used:
    <name>.localhost is a different *site* from localhost, so a cookie set
    inside the dashboard's iframe is third-party and browsers drop it."""
    return "/__s/" + session_value(f"sbx:{name}:{CAP_SALT}")[:40]


async def run(*cmd: str, timeout: float = 120) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except TimeoutError:
        proc.kill()
        return 124, "", f"timed out after {timeout:.0f}s"
    return proc.returncode, out.decode(errors="replace"), err.decode(errors="replace")


def read_env(path: Path) -> dict[str, str]:
    env = {}
    for line in path.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


def load_ws(name: str) -> dict[str, str] | None:
    if not NAME_RE.match(name):
        return None
    path = WS_ROOT / f"{name}.env"
    return read_env(path) if path.is_file() else None


def all_ws() -> list[dict[str, str]]:
    return [read_env(p) for p in sorted(WS_ROOT.glob("*.env"))]


def container(name: str) -> str:
    return f"aio-{name}"


def compose(ws: dict[str, str], *args: str) -> list[str]:
    return ["docker", "compose", "-p", container(ws["WS_NAME"]),
            "--env-file", str(WS_ROOT / f"{ws['WS_NAME']}.env"),
            "-f", str(COMPOSE_FILE), *args]


def port_free(port: int) -> bool:
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def dirs_overlap(a: str, b: str) -> bool:
    a, b = a.rstrip("/") + "/", b.rstrip("/") + "/"
    return a.startswith(b) or b.startswith(a)


# --------------------------------------------------------------- HTTP

class Request:
    def __init__(self, head: bytes):
        lines = head.decode("latin-1").split("\r\n")
        self.method, self.target, self.version = lines[0].split(" ", 2)
        self.raw_headers: list[tuple[str, str]] = []
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                self.raw_headers.append((k.strip(), v.strip()))
        self.headers = {k.lower(): v for k, v in self.raw_headers}
        parsed = urllib.parse.urlsplit(self.target)
        self.path = urllib.parse.unquote(parsed.path)
        self.query = dict(urllib.parse.parse_qsl(parsed.query))
        self.host = self.headers.get("host", "").lower()
        self.hostname = self.host.rsplit(":", 1)[0] if ":" in self.host else self.host
        self.body = b""

    def cookies(self) -> dict[str, str]:
        out = {}
        for part in self.headers.get("cookie", "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                out.setdefault(k, v)
        return out


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
def ui_csp(req: Request) -> str:
    return ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            f"connect-src 'self' {WS_SCHEME}://{req.host}; "
            f"frame-src {SCHEME}://*.localhost:* {SCHEME}://{req.hostname}:*; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


def ui_ancestors() -> str:
    return " ".join(f"{SCHEME}://{h}:*" for h in sorted(UI_HOSTNAMES))


async def respond(w: asyncio.StreamWriter, status: int, body: bytes | str = b"",
                  ctype: str = "text/plain; charset=utf-8", headers: dict | None = None):
    if isinstance(body, str):
        body = body.encode()
    reason = {200: "OK", 201: "Created", 303: "See Other", 400: "Bad Request",
              401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 409: "Conflict",
              421: "Misdirected Request", 500: "Internal Server Error",
              502: "Bad Gateway"}.get(status, "")
    hdrs = {"Content-Type": ctype, "Content-Length": str(len(body)),
            "Connection": "close", **SECURITY_HEADERS, **(headers or {})}
    head = f"HTTP/1.1 {status} {reason}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
    w.write(head.encode("latin-1") + b"\r\n" + body)
    await w.drain()


async def send_json(w, obj, status: int = 200):
    await respond(w, status, json.dumps(obj), "application/json")


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 sandbox: str | None = None):
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
        req = Request(head[:-4])
        if sandbox is not None:            # connection arrived on a sandbox port
            if req.hostname in UI_HOSTNAMES and load_ws(sandbox):
                await handle_proxy(req, sandbox, reader, writer)
            else:
                await respond(writer, 421, "Unknown host\n")
        elif req.hostname in UI_HOSTNAMES:
            await handle_ui(req, reader, writer)
        elif (m := re.fullmatch(r"([a-z0-9-]+)\.localhost", req.hostname)) and load_ws(m[1]):
            await handle_proxy(req, m[1], reader, writer)
        else:
            await respond(writer, 421, "Unknown host\n")
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError,
            TimeoutError, ValueError):
        pass
    except Exception as e:  # keep serving; report to the client if we still can
        print(f"error: {e!r}", flush=True)
        try:
            await respond(writer, 500, f"Internal error: {e}\n")
        except Exception:
            pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


# --------------------------------------------------------------- UI

def ui_authed(req: Request) -> bool:
    return hmac.compare_digest(req.cookies().get("asui", ""), session_value("ui"))


def same_origin(req: Request) -> bool:
    """Requests from pages on other origins (incl. sandbox subdomains,
    which are *same-site* with localhost) must never reach the API."""
    sfs = req.headers.get("sec-fetch-site")
    origin = req.headers.get("origin")
    if origin is not None and origin != f"{SCHEME}://{req.host}":
        return False
    if sfs is not None:
        return sfs == "same-origin"
    # Plain HTTP to a non-localhost address gets no Sec-Fetch-* headers, and
    # same-origin GETs carry no Origin. Cross-origin pages can't read GET
    # responses (no CORS), while every state-changing method and WebSocket
    # handshake carries Origin, so require it for those.
    return origin is not None or req.method in ("GET", "HEAD") and \
        req.headers.get("upgrade", "").lower() != "websocket"


async def handle_ui(req: Request, reader, w):
    if req.path == "/ca.crt" and TLS_CTX:     # public cert, for importing on your laptop
        return await respond(w, 200, (TLS_DIR / "ca.crt").read_bytes(), "application/x-x509-ca-cert",
                             {"Content-Disposition": 'attachment; filename="agent-sandboxes-ca.crt"'})
    if req.path == "/login":
        if hmac.compare_digest(req.query.get("token", ""), TOKEN):
            await respond(w, 303, headers={
                "Location": "/",
                "Set-Cookie": f"asui={session_value('ui')}; HttpOnly; SameSite=Strict; Path=/"
                              + ("; Secure" if TLS_CTX else "")})
        else:
            await respond(w, 401, "Bad token.\n")
        return

    if not ui_authed(req):
        await respond(w, 401, (STATIC / "login.html").read_bytes(), "text/html; charset=utf-8",
                      {"Content-Security-Policy": ui_csp(req)})
        return

    if req.path.startswith("/ws/term/"):
        if req.headers.get("upgrade", "").lower() != "websocket" or not same_origin(req):
            await respond(w, 403, "Forbidden\n")
            return
        await terminal(req, req.path.removeprefix("/ws/term/"), reader, w)
        return

    if req.path.startswith("/api/"):
        if not same_origin(req):
            await respond(w, 403, "Cross-origin request refused\n")
            return
        if req.method != "GET" and req.headers.get("x-requested-with") != "sbui":
            await respond(w, 403, "Missing X-Requested-With\n")
            return
        length = int(req.headers.get("content-length", "0") or 0)
        if length > MAX_BODY:
            await respond(w, 400, "Body too large\n")
            return
        if length:
            req.body = await reader.readexactly(length)
        await api(req, w)
        return

    # static files
    rel = "index.html" if req.path in ("/", "/index.html") else req.path.removeprefix("/static/")
    path = (STATIC / rel).resolve()
    if req.method == "GET" and path.is_file() and path.is_relative_to(STATIC.resolve()) \
            and path.name != "login.html":
        ctype = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype.endswith("javascript"):
            ctype += "; charset=utf-8"
        await respond(w, 200, path.read_bytes(), ctype,
                      {"Content-Security-Policy": ui_csp(req), "X-Frame-Options": "DENY"})
    else:
        await respond(w, 404, "Not found\n")


# --------------------------------------------------------------- API

async def api(req: Request, w):
    parts = [p for p in req.path.split("/") if p][1:]   # drop "api"
    m = req.method

    if parts == ["workspaces"] and m == "GET":
        return await send_json(w, await status_all())
    if parts == ["workspaces"] and m == "POST":
        return await create_ws(req, w)

    if parts and parts[0] == "pool":
        return await pool_api(req, parts[1:], w)

    if len(parts) < 2 or parts[0] != "workspaces":
        return await respond(w, 404, "Not found\n")
    ws = load_ws(parts[1])
    if not ws:
        return await send_json(w, {"error": "No such workspace"}, 404)
    name, action = ws["WS_NAME"], parts[2:]

    if action == [] and m == "DELETE":
        await run(*TMUX, "kill-session", "-t", f"cl-{name}")
        rc, out, err = await run(*compose(ws, "down", "--remove-orphans"))
        if rc != 0:
            return await send_json(w, {"error": err or out}, 500)
        (WS_ROOT / f"{name}.env").unlink()
        kill_agent(name)
        for p in (policy_path(name), profile_path(name)):
            p.unlink(missing_ok=True)
        shutil.rmtree(STATE_ROOT / name, ignore_errors=True)
        shutil.rmtree(RUNTIME / name, ignore_errors=True)
        close_sandbox_listener(name)
        await refresh_cert()
        return await send_json(w, {"ok": True, "kept": ws["WS_DIR"]})

    if action == ["container", "start"] and m == "POST":
        rc, out, err = await run(*compose(ws, "up", "-d"), timeout=600)
        return await send_json(w, {"ok": rc == 0, "log": err or out}, 200 if rc == 0 else 500)
    if action == ["container", "stop"] and m == "POST":
        await run(*TMUX, "kill-session", "-t", f"cl-{name}")
        rc, out, err = await run(*compose(ws, "stop"))
        return await send_json(w, {"ok": rc == 0, "log": err or out}, 200 if rc == 0 else 500)

    if action == ["claude", "start"] and m == "POST":
        return await claude_start(ws, w)
    if action == ["claude", "restart"] and m == "POST":
        await run(*TMUX, "kill-session", "-t", f"cl-{name}")
        return await claude_start(ws, w)
    if action == ["claude", "stop"] and m == "POST":
        await run(*TMUX, "kill-session", "-t", f"cl-{name}")
        return await send_json(w, {"ok": True})

    if action == ["policy"] and m in ("GET", "PUT"):
        return await policy_api(ws, req, w)

    if action == ["sandbox-link"] and m == "GET":
        return await send_json(w, {"prefix": sandbox_prefix(name),
                                   "port": int(ws["WS_PORT"]) + PROXY_PORT_OFFSET})

    if action == ["logs"] and m == "GET":
        rc, out, err = await run("docker", "logs", "--tail", "300", container(name))
        return await send_json(w, {"log": out + err})

    if action == ["files"] and m == "GET":
        return await list_files(ws, req, w)
    if action == ["download"] and m == "GET":
        return await download(ws, req, w)

    await respond(w, 404, "Not found\n")


async def status_all() -> list[dict]:
    _, ps, _ = await run("docker", "ps", "-a", "--filter", "name=^aio-",
                         "--format", "{{.Names}}\t{{.State}}\t{{.Status}}")
    states = {}
    for line in ps.splitlines():
        n, state, detail = (line.split("\t") + ["", ""])[:3]
        states[n] = (state, detail)
    _, panes, _ = await run(*TMUX, "list-panes", "-a", "-F", "#{session_name}\t#{pane_dead}")
    claude = {}
    for line in panes.splitlines():
        s, dead = (line.split("\t") + [""])[:2]
        if s.startswith("cl-"):
            claude[s[3:]] = "exited" if dead == "1" else "running"
    out = []
    for ws in all_ws():
        n = ws.get("WS_NAME", "")
        state, detail = states.get(container(n), ("absent", ""))
        pol = load_policy(n)
        out.append({"name": n, "dir": ws.get("WS_DIR"), "port": ws.get("WS_PORT"),
                    "container": state, "containerDetail": detail,
                    "claude": claude.get(n, "stopped"),
                    "sshKeys": len(pol["ssh_keys"]), "tokens": len(pol["tokens"]),
                    "network": pol["network"]["mode"],
                    "policyPending": claude.get(n) == "running" and policy_pending(ws)})
    return out


async def create_ws(req: Request, w):
    try:
        body = json.loads(req.body or b"{}")
    except json.JSONDecodeError:
        return await send_json(w, {"error": "Invalid JSON"}, 400)
    name = str(body.get("name", "")).strip()
    if not NAME_RE.match(name):
        return await send_json(w, {"error": "Name: lowercase letters, digits and dashes, max 30"}, 400)
    if load_ws(name):
        return await send_json(w, {"error": f"Workspace '{name}' already exists"}, 409)

    raw_dir = str(body.get("dir") or PROJECTS_BASE / name).strip()
    raw_dir = os.path.expanduser(raw_dir)
    if not DIR_RE.match(raw_dir):
        return await send_json(w, {"error": "Directory must be an absolute path of [A-Za-z0-9._/-]"}, 400)
    d = os.path.realpath(raw_dir)
    home = str(Path.home())
    if d in ("/", home) or dirs_overlap(d, str(ROOT)) or not d.startswith(home + "/"):
        return await send_json(w, {"error": "Directory must be inside your home, and not your home "
                                            "itself or the agent-sandboxes folder"}, 400)
    others = all_ws()
    for o in others:
        if dirs_overlap(d, os.path.realpath(o["WS_DIR"])):
            return await send_json(w, {"error": f"Overlaps workspace '{o['WS_NAME']}' "
                                                f"({o['WS_DIR']}); nono would expose one to the other"}, 400)

    used = {int(o["WS_PORT"]) for o in others}
    port = next((p for p in SANDBOX_PORTS if p not in used and port_free(p)), None)
    if port is None:
        return await send_json(w, {"error": "No free sandbox port"}, 500)

    created_dir = not os.path.exists(d)
    os.makedirs(d, exist_ok=True)
    notes = []
    mcp = Path(d) / ".mcp.json"
    template = json.loads(MCP_TEMPLATE.read_text())
    if not mcp.exists():
        mcp.write_text(json.dumps(template, indent=2) + "\n")
    else:
        try:
            cfg = json.loads(mcp.read_text())
            servers = cfg.setdefault("mcpServers", {})
            if "aio-sandbox" not in servers:
                servers["aio-sandbox"] = template["mcpServers"]["aio-sandbox"]
                mcp.write_text(json.dumps(cfg, indent=2) + "\n")
                notes.append("Added aio-sandbox to the existing .mcp.json")
        except (json.JSONDecodeError, AttributeError):
            notes.append(".mcp.json exists but isn't valid JSON; add the aio-sandbox server by hand")

    env_path = WS_ROOT / f"{name}.env"
    fd = os.open(env_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(f"WS_NAME={name}\nWS_DIR={d}\nWS_PORT={port}\nWS_KEY={secrets.token_hex(32)}\n")

    # Under `sg docker` new files get group docker; give them the user's own group.
    for p in [env_path, mcp] + ([d] if created_dir else []):
        os.chown(p, -1, USER_GID)

    ws = read_env(env_path)
    rc, out, err = await run(*compose(ws, "up", "-d"), timeout=600)
    if rc != 0:
        notes.append(f"Container failed to start: {(err or out).strip()[-500:]}")
    await refresh_cert()          # adds <name>.localhost to the certificate
    if err := await open_sandbox_listener(ws):
        notes.append(err)
    await send_json(w, {"ok": True, "name": name, "dir": d, "port": port, "notes": notes}, 201)


async def claude_start(ws: dict[str, str], w):
    name = ws["WS_NAME"]
    session = f"cl-{name}"
    rc, out, _ = await run(*TMUX, "list-panes", "-t", session, "-F", "#{pane_dead}")
    if rc == 0 and "0" in out.split():
        return await send_json(w, {"ok": True, "note": "already running"})
    if rc == 0:   # exists but exited: replace it
        await run(*TMUX, "kill-session", "-t", session)
    rc, out, err = await run(*TMUX, "new-session", "-d", "-s", session, "-x", "160", "-y", "45",
                             "-c", ws["WS_DIR"], str(CLAUDE_IN), name)
    return await send_json(w, {"ok": rc == 0, "error": err.strip()}, 200 if rc == 0 else 500)


# --------------------------------------------------------------- policy, key & token pool

NET_MODES = {
    "minimal": "Claude's own APIs only",
    "claude-code": "Claude APIs, package registries, GitHub, GitLab, docs (default)",
    "enterprise": "As above, plus Google Cloud, Azure and AWS Bedrock",
    "open": "Unfiltered internet (raw TCP still blocked when tokens or blocked domains are set)",
}
# Phantom-token routes: the sandbox sees a placeholder in env_var; nono's proxy
# swaps in the real secret only on requests to the upstream. (No "anthropic":
# ANTHROPIC_API_KEY would switch Claude Code itself off your subscription.)
TOKEN_SERVICES = {
    "github": {"label": "GitHub API", "upstream": "https://api.github.com",
               "inject_header": "Authorization", "credential_format": "token {}", "env_var": "GITHUB_TOKEN"},
    "gitlab": {"label": "GitLab API", "upstream": "https://gitlab.com/api",
               "inject_header": "Authorization", "credential_format": "Bearer {}", "env_var": "GITLAB_TOKEN"},
    "openai": {"label": "OpenAI API", "upstream": "https://api.openai.com/v1",
               "inject_header": "Authorization", "credential_format": "Bearer {}", "env_var": "OPENAI_API_KEY"},
    "gemini": {"label": "Gemini API", "upstream": "https://generativelanguage.googleapis.com",
               "inject_header": "x-goog-api-key", "credential_format": "{}", "env_var": "GEMINI_API_KEY"},
}
DEFAULT_POLICY = {"ssh_keys": [], "tokens": [],
                  "network": {"mode": "claude-code", "allow": [], "deny": []},
                  "limits": {"memory": "", "pids": 0}}


def private_write(path: Path, data: str | bytes):
    """Create/replace a 0600 file atomically."""
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data.encode() if isinstance(data, str) else data)
    os.chown(tmp, -1, USER_GID)
    os.replace(tmp, path)


def ensure_dirs():
    for d in (WS_ROOT, SECRETS, SSH_POOL, TOKEN_POOL, STATE_ROOT, RUNTIME):
        d.mkdir(mode=0o700, parents=True, exist_ok=True)


def policy_path(name: str) -> Path:
    return WS_ROOT / f"{name}.policy.json"


def profile_path(name: str) -> Path:
    return WS_ROOT / f"{name}.profile.json"


def agent_sock(name: str) -> Path:
    return RUNTIME / name / "agent.sock"


def load_policy(name: str) -> dict:
    pol = json.loads(json.dumps(DEFAULT_POLICY))
    try:
        saved = json.loads(policy_path(name).read_text())
    except (OSError, json.JSONDecodeError):
        saved = {}
    for k in ("ssh_keys", "tokens"):
        pol[k] = [i for i in saved.get(k, []) if (SSH_POOL if k == "ssh_keys" else TOKEN_POOL).joinpath(
            i if k == "ssh_keys" else f"{i}.json").is_file()]
    pol["network"].update(saved.get("network", {}))
    pol["limits"].update(saved.get("limits", {}))
    return pol


def save_policy(name: str, pol: dict):
    private_write(policy_path(name), json.dumps(pol, indent=2, sort_keys=True) + "\n")


def clean_list(v, pattern: re.Pattern, what: str, limit: int = 100) -> list[str]:
    if not isinstance(v, list) or len(v) > limit:
        raise ValueError(f"{what}: expected a list of at most {limit}")
    out = []
    for x in v:
        x = str(x).strip().lower() if pattern is DOMAIN_RE else str(x).strip()
        if not x:
            continue
        if not pattern.match(x):
            raise ValueError(f"{what}: invalid entry {x!r}")
        if x not in out:
            out.append(x)
    return out


def validate_policy(body: dict) -> dict:
    pol = json.loads(json.dumps(DEFAULT_POLICY))
    pol["ssh_keys"] = clean_list(body.get("ssh_keys", []), ITEM_RE, "SSH keys")
    for k in pol["ssh_keys"]:
        if not (SSH_POOL / k).is_file():
            raise ValueError(f"No SSH key '{k}' in the pool")
    pol["tokens"] = clean_list(body.get("tokens", []), ITEM_RE, "Tokens")
    seen_env = {}
    for t in pol["tokens"]:
        meta = token_meta(t)
        if not meta:
            raise ValueError(f"No token '{t}' in the pool")
        if meta["env_var"] in seen_env:
            raise ValueError(f"Tokens '{seen_env[meta['env_var']]}' and '{t}' both set {meta['env_var']}")
        seen_env[meta["env_var"]] = t
    net = body.get("network", {}) or {}
    if net.get("mode", "claude-code") not in NET_MODES:
        raise ValueError("Unknown network mode")
    pol["network"] = {"mode": net.get("mode", "claude-code"),
                      "allow": clean_list(net.get("allow", []), DOMAIN_RE, "Allowed domains"),
                      "deny": clean_list(net.get("deny", []), DOMAIN_RE, "Blocked domains")}
    lim = body.get("limits", {}) or {}
    mem = str(lim.get("memory", "") or "").strip().upper()
    if mem and not MEM_RE.match(mem):
        raise ValueError("Memory limit: a number with M or G, e.g. 4G")
    try:
        pids = int(lim.get("pids", 0) or 0)
    except (TypeError, ValueError):
        raise ValueError("Max processes: a whole number")
    if not 0 <= pids <= 100000 or 0 < pids < 32:
        raise ValueError("Max processes: 0 (no limit) or 32–100000")
    pol["limits"] = {"memory": mem, "pids": pids}
    return pol


# ---- pool

def token_meta(tid: str) -> dict | None:
    if not ITEM_RE.match(tid):
        return None
    try:
        return json.loads((TOKEN_POOL / f"{tid}.json").read_text())
    except (OSError, json.JSONDecodeError):
        return None


async def ssh_key_info(kid: str) -> dict:
    pub = (SSH_POOL / f"{kid}.pub").read_text().strip()
    _, fp, _ = await run("ssh-keygen", "-l", "-f", str(SSH_POOL / f"{kid}.pub"))
    parts = fp.split()
    return {"id": kid, "public": pub, "fingerprint": parts[1] if len(parts) > 1 else "",
            "type": parts[-1].strip("()") if parts else "", "comment": " ".join(pub.split()[2:])}


async def pool_listing() -> dict:
    policies = {ws["WS_NAME"]: load_policy(ws["WS_NAME"]) for ws in all_ws()}
    keys = []
    for p in sorted(SSH_POOL.glob("*.pub")):
        kid = p.name.removesuffix(".pub")
        if ITEM_RE.match(kid) and (SSH_POOL / kid).is_file():
            info = await ssh_key_info(kid)
            info["workspaces"] = [n for n, pol in policies.items() if kid in pol["ssh_keys"]]
            keys.append(info)
    tokens = []
    for p in sorted(TOKEN_POOL.glob("*.json")):
        tid = p.name.removesuffix(".json")
        if (meta := token_meta(tid)) and (TOKEN_POOL / tid).is_file():
            tokens.append({"id": tid, **{k: meta[k] for k in ("service", "upstream", "env_var", "label")},
                           "workspaces": [n for n, pol in policies.items() if tid in pol["tokens"]]})
    return {"ssh": keys, "tokens": tokens, "workspaces": sorted(policies),
            "services": {k: {"label": v["label"], "env_var": v["env_var"], "upstream": v["upstream"]}
                         for k, v in TOKEN_SERVICES.items()},
            "netModes": NET_MODES}


async def add_ssh_key(body: dict) -> dict:
    kid = str(body.get("id", "")).strip()
    if not ITEM_RE.match(kid):
        raise ValueError("Key name: lowercase letters, digits and dashes, max 40")
    if (SSH_POOL / kid).exists():
        raise ValueError(f"Key '{kid}' already exists")
    comment = str(body.get("comment") or f"agent-sandboxes:{kid}@{socket.gethostname()}").strip()
    if not re.fullmatch(r"[\w.@:+=-][\w .@:+=-]{0,99}", comment):
        raise ValueError("Comment: letters, digits, spaces and . @ : + = - only")
    tmp = SSH_POOL / f".new-{kid}-{secrets.token_hex(4)}"
    try:
        if body.get("generate"):
            rc, _, err = await run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(tmp))
            if rc != 0:
                raise ValueError(f"ssh-keygen failed: {err.strip()}")
        else:
            pem = str(body.get("private_key", "")).replace("\r\n", "\n").strip() + "\n"
            if "PRIVATE KEY-----" not in pem or len(pem) > 20000:
                raise ValueError("Paste an OpenSSH/PEM private key")
            private_write(tmp, pem)
            rc, pub, err = await run("ssh-keygen", "-y", "-P", "", "-f", str(tmp))
            if rc != 0:
                if "passphrase" in err.lower() or "incorrect" in err.lower():
                    raise ValueError("That key is passphrase-protected. Remove it first "
                                     "(ssh-keygen -p -N '' -f <key>) or generate a key here.")
                raise ValueError(f"Not a usable private key: {err.strip()}")
            # Keep the key's own comment if it has one, else use ours.
            fields = pub.split()
            Path(f"{tmp}.pub").write_text(" ".join(fields[:2] + [comment]) + "\n")
        os.chmod(tmp, 0o600)
        for p in (tmp, Path(f"{tmp}.pub")):
            os.chown(p, -1, USER_GID)
        os.replace(f"{tmp}.pub", SSH_POOL / f"{kid}.pub")
        os.replace(tmp, SSH_POOL / kid)
    finally:
        for p in (tmp, Path(f"{tmp}.pub")):
            p.unlink(missing_ok=True)
    return await ssh_key_info(kid)


def add_token(body: dict) -> dict:
    tid = str(body.get("id", "")).strip()
    if not ITEM_RE.match(tid):
        raise ValueError("Token name: lowercase letters, digits and dashes, max 40")
    if (TOKEN_POOL / f"{tid}.json").exists():
        raise ValueError(f"Token '{tid}' already exists")
    secret = str(body.get("secret", "")).strip()
    if not secret or len(secret) > 8192 or any(c in secret for c in "\r\n\0"):
        raise ValueError("Paste the token (single line)")
    service = str(body.get("service", ""))
    if service in TOKEN_SERVICES:
        meta = {"service": service, **TOKEN_SERVICES[service]}
    elif service == "custom":
        c = body.get("custom", {}) or {}
        up = urllib.parse.urlsplit(str(c.get("upstream", "")).strip())
        if up.scheme != "https" or not up.hostname or not DOMAIN_RE.match(up.hostname) \
                or up.query or up.fragment or up.username:
            raise ValueError("Upstream: an https:// URL (host and optional path)")
        header = str(c.get("header") or "Authorization").strip()
        fmt = str(c.get("format") or "Bearer {}").strip()
        env = str(c.get("env_var", "")).strip().upper()
        if not HEADER_RE.match(header):
            raise ValueError("Header: letters, digits and dashes")
        if fmt.count("{}") != 1 or len(fmt) > 100 or any(ch in fmt for ch in "\r\n"):
            raise ValueError("Format must contain {} exactly once, e.g. 'Bearer {}'")
        if not ENV_RE.match(env) or env in ("PATH", "HOME", "SSH_AUTH_SOCK") or env.startswith("NONO_"):
            raise ValueError("Environment variable: e.g. ACME_API_KEY")
        meta = {"service": "custom", "label": up.hostname,
                "upstream": urllib.parse.urlunsplit(("https", up.netloc, up.path.rstrip("/"), "", "")),
                "inject_header": header, "credential_format": fmt, "env_var": env}
    else:
        raise ValueError("Unknown service")
    private_write(TOKEN_POOL / tid, secret)
    private_write(TOKEN_POOL / f"{tid}.json", json.dumps(meta, indent=2) + "\n")
    return {"id": tid, **meta}


async def remove_pool_item(kind: str, iid: str):
    key = "ssh_keys" if kind == "ssh" else "tokens"
    for ws in all_ws():
        pol = load_policy(ws["WS_NAME"])
        if iid in pol[key]:
            pol[key].remove(iid)
            save_policy(ws["WS_NAME"], pol)
    if kind == "ssh":
        # Pull it out of every agent (by public key) before deleting the files.
        for ws in all_ws():
            await sync_agent(ws["WS_NAME"])
        for p in (SSH_POOL / iid, SSH_POOL / f"{iid}.pub"):
            p.unlink(missing_ok=True)
    else:
        for p in (TOKEN_POOL / iid, TOKEN_POOL / f"{iid}.json"):
            p.unlink(missing_ok=True)


async def assign(kind: str, iid: str, workspaces: list[str]):
    key = "ssh_keys" if kind == "ssh" else "tokens"
    wanted = set(clean_list(workspaces, NAME_RE, "Workspaces"))
    known = {ws["WS_NAME"] for ws in all_ws()}
    if wanted - known:
        raise ValueError(f"No such workspace: {', '.join(sorted(wanted - known))}")
    for name in sorted(known):
        pol = load_policy(name)
        has = iid in pol[key]
        if (name in wanted) != has:
            pol[key] = [i for i in pol[key] if i != iid] + ([iid] if name in wanted else [])
            save_policy(name, validate_policy(pol))      # re-checks env-var clashes
            if kind == "ssh":
                await sync_agent(name)


# ---- per-workspace ssh-agent: Claude gets the socket, never the key files

async def ssh_add(name: str, *args: str) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        "ssh-add", *args, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, env={**os.environ, "SSH_AUTH_SOCK": str(agent_sock(name))})
    out, err = await asyncio.wait_for(proc.communicate(), 20)
    return proc.returncode, out.decode(errors="replace"), err.decode(errors="replace")


def kill_agent(name: str):
    pidfile = RUNTIME / name / "agent.pid"
    try:
        pid = int(pidfile.read_text())
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
        if b"ssh-agent" in cmdline and str(agent_sock(name)).encode() in cmdline:
            os.kill(pid, 15)
    except (OSError, ValueError):
        pass
    pidfile.unlink(missing_ok=True)
    agent_sock(name).unlink(missing_ok=True)


async def start_agent(name: str):
    kill_agent(name)
    (RUNTIME / name).mkdir(mode=0o700, parents=True, exist_ok=True)
    rc, out, err = await run("ssh-agent", "-s", "-a", str(agent_sock(name)))
    if rc != 0 or not (m := re.search(r"SSH_AGENT_PID=(\d+)", out)):
        raise RuntimeError(f"ssh-agent failed: {err.strip()}")
    (RUNTIME / name / "agent.pid").write_text(m[1])


async def sync_agent(name: str):
    """Make the workspace agent hold exactly its assigned keys. Takes
    effect immediately, including for a Claude that's already running."""
    want = {}
    for kid in load_policy(name)["ssh_keys"]:
        pub = (SSH_POOL / f"{kid}.pub").read_text().split()
        want[pub[1]] = kid
    for attempt in range(2):
        rc, listed, _ = await ssh_add(name, "-L")
        if rc == 2 or attempt == 1:          # no agent, or it misbehaved (e.g. locked by the agent)
            await start_agent(name)
            listed = ""
        have = {l.split()[1]: l for l in listed.splitlines() if len(l.split()) >= 2}
        for blob, line in have.items():
            if blob not in want:
                tmp = RUNTIME / name / "remove.pub"
                tmp.write_text(line + "\n")
                await ssh_add(name, "-d", str(tmp))
                tmp.unlink(missing_ok=True)
        for blob, kid in want.items():
            if blob not in have:
                await ssh_add(name, "-q", str(SSH_POOL / kid))
        rc, listed, _ = await ssh_add(name, "-L")
        now = {l.split()[1] for l in listed.splitlines() if len(l.split()) >= 2} if rc == 0 else set()
        if now == set(want):
            return
    raise RuntimeError(f"could not load SSH keys into {name}'s agent")


# ---- nono profile per workspace

def render_profile(ws: dict[str, str], pol: dict) -> dict:
    name = ws["WS_NAME"]
    st = STATE_ROOT / name
    net: dict = {"open_port": [int(ws["WS_PORT"])]}
    mode = pol["network"]["mode"]
    net["network_profile"] = None if mode == "open" else mode
    if pol["network"]["allow"]:
        net["allow_domain"] = pol["network"]["allow"]
    if pol["network"]["deny"]:
        net["deny_domain"] = pol["network"]["deny"]
    creds = {}
    for tid in pol["tokens"]:
        meta = token_meta(tid)
        creds["pool_" + tid.replace("-", "_")] = {
            "upstream": meta["upstream"], "credential_key": f"file://{TOKEN_POOL / tid}",
            "inject_header": meta["inject_header"], "credential_format": meta["credential_format"],
            "env_var": meta["env_var"]}
    if creds:
        net["credentials"] = sorted(creds)
        net["custom_credentials"] = creds
    return {
        "meta": {"name": f"ws-{name}", "version": "1.0.0",
                 "description": f"Generated by agent-sandboxes for workspace {name}; edit in the web UI"},
        "extends": "claude-browser",
        # Default-deny pathname Unix sockets: no Docker socket, no tmux server
        # (other workspaces' sessions), no D-Bus / systemd --user.
        "linux": {"af_unix_mediation": "pathname"},
        "filesystem": {"unix_socket": [str(agent_sock(name))],
                       "read": [str(LIBEXEC)], "allow": [str(st)]},
        "network": net,
        "environment": {"set_vars": {"SSH_AUTH_SOCK": str(agent_sock(name)),
                                     "GIT_SSH_COMMAND": f"ssh -F {st / 'ssh_config'}"}},
    }


def profile_text(ws: dict[str, str]) -> str:
    return json.dumps(render_profile(ws, load_policy(ws["WS_NAME"])), indent=2, sort_keys=True) + "\n"


def write_ssh_config(name: str):
    st = STATE_ROOT / name
    st.mkdir(mode=0o700, parents=True, exist_ok=True)
    (st / "known_hosts").touch(mode=0o600)
    (st / "ssh_config").write_text(
        "# Generated by agent-sandboxes. Used via GIT_SSH_COMMAND inside nono.\n"
        "Host *\n"
        f"  IdentityAgent {agent_sock(name)}\n"
        f"  UserKnownHostsFile {st / 'known_hosts'}\n"
        "  StrictHostKeyChecking accept-new\n"
        f"  ProxyCommand {LIBEXEC / 'ssh-proxy-connect'} %h %p\n"
        "  ServerAliveInterval 30\n")


async def prepare(name: str) -> dict:
    """Everything Claude needs before nono starts: agent with its keys,
    ssh config, and the rendered profile (what's now 'applied')."""
    ensure_dirs()
    ws = load_ws(name)
    if not ws:
        raise SystemExit(f"No workspace '{name}'")
    await sync_agent(name)
    write_ssh_config(name)
    private_write(profile_path(name), profile_text(ws))
    return {"profile": str(profile_path(name)), **load_policy(name)["limits"]}


def policy_pending(ws: dict[str, str]) -> bool:
    """True if the saved policy differs from what the running Claude got."""
    try:
        return profile_path(ws["WS_NAME"]).read_text() != profile_text(ws)
    except OSError:
        return True     # started before per-workspace profiles existed


async def policy_api(ws: dict[str, str], req: Request, w):
    name = ws["WS_NAME"]
    if req.method == "PUT":
        try:
            pol = validate_policy(json.loads(req.body or b"{}"))
        except (ValueError, json.JSONDecodeError) as e:
            return await send_json(w, {"error": str(e)}, 400)
        old = load_policy(name)
        save_policy(name, pol)
        if old["ssh_keys"] != pol["ssh_keys"]:
            await sync_agent(name)
    rc, out, _ = await run(*TMUX, "list-panes", "-t", f"cl-{name}", "-F", "#{pane_dead}")
    running = rc == 0 and "0" in out.split()
    return await send_json(w, {"policy": load_policy(name), "pending": running and policy_pending(ws)})


async def pool_api(req: Request, parts: list[str], w):
    m = req.method
    try:
        body = json.loads(req.body or b"{}") if req.body else {}
        if parts == [] and m == "GET":
            return await send_json(w, await pool_listing())
        if parts == ["ssh"] and m == "POST":
            return await send_json(w, await add_ssh_key(body), 201)
        if parts == ["tokens"] and m == "POST":
            return await send_json(w, add_token(body), 201)
        if len(parts) >= 2 and parts[0] in ("ssh", "tokens") and ITEM_RE.match(parts[1]):
            kind, iid = ("ssh" if parts[0] == "ssh" else "token"), parts[1]
            exists = (SSH_POOL / iid).is_file() if kind == "ssh" else token_meta(iid) is not None
            if not exists:
                return await send_json(w, {"error": "Not found"}, 404)
            if parts[2:] == [] and m == "DELETE":
                await remove_pool_item(kind, iid)
                return await send_json(w, {"ok": True})
            if parts[2:] == ["workspaces"] and m == "PUT":
                await assign(kind, iid, body.get("workspaces", []))
                return await send_json(w, {"ok": True})
    except (ValueError, json.JSONDecodeError) as e:
        return await send_json(w, {"error": str(e)}, 400)
    except RuntimeError as e:
        return await send_json(w, {"error": str(e)}, 500)
    await respond(w, 404, "Not found\n")


def clean_container_path(p: str) -> str | None:
    if not p.startswith("/") or "\0" in p or "\n" in p:
        return None
    return posixpath.normpath(p)


async def list_files(ws, req: Request, w):
    path = clean_container_path(req.query.get("path", "/home/gem"))
    if not path:
        return await send_json(w, {"error": "Bad path"}, 400)
    rc, out, err = await run("docker", "exec", "-u", "1000", container(ws["WS_NAME"]),
                             "find", path, "-mindepth", "1", "-maxdepth", "1",
                             "-printf", r"%y\t%s\t%T@\t%f\0", timeout=30)
    if rc != 0 and not out:
        return await send_json(w, {"error": err.strip() or "Listing failed"}, 404)
    entries = []
    for rec in out.split("\0"):
        if rec.count("\t") >= 3:
            kind, size, mtime, fname = rec.split("\t", 3)
            entries.append({"name": fname, "type": {"d": "dir", "f": "file", "l": "link"}.get(kind, kind),
                            "size": int(size), "mtime": float(mtime)})
    entries.sort(key=lambda e: (e["type"] != "dir", e["name"].lower()))
    await send_json(w, {"path": path, "entries": entries})


async def download(ws, req: Request, w):
    path = clean_container_path(req.query.get("path", ""))
    if not path or path == "/":
        return await respond(w, 400, "Bad path\n")
    c = container(ws["WS_NAME"])
    rc, kind, err = await run("docker", "exec", "-u", "1000", c, "stat", "-L", "-c", "%F", path)
    kind = kind.strip()
    base = posixpath.basename(path)
    if kind == "directory":
        cmd = ["docker", "exec", "-u", "1000", c, "tar", "-C", posixpath.dirname(path), "-cf", "-", "--", base]
        fname, ctype = base + ".tar", "application/x-tar"
    elif kind.startswith("regular"):
        cmd = ["docker", "exec", "-u", "1000", c, "cat", "--", path]
        fname, ctype = base, mimetypes.guess_type(base)[0] or "application/octet-stream"
    else:
        return await respond(w, 404, f"Not a file or directory: {err.strip() or kind}\n")

    ascii_name = re.sub(r'[^A-Za-z0-9._-]', "_", fname)
    disp = f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{urllib.parse.quote(fname)}"
    proc = await asyncio.create_subprocess_exec(*cmd, stdin=asyncio.subprocess.DEVNULL,
                                                stdout=asyncio.subprocess.PIPE,
                                                stderr=asyncio.subprocess.DEVNULL)
    head = (f"HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Disposition: {disp}\r\n"
            "Connection: close\r\n" + "".join(f"{k}: {v}\r\n" for k, v in SECURITY_HEADERS.items()))
    w.write(head.encode("utf-8") + b"\r\n")
    try:
        while chunk := await proc.stdout.read(256 * 1024):
            w.write(chunk)
            await w.drain()
    finally:
        if proc.returncode is None:
            proc.kill()
        await proc.wait()


# --------------------------------------------------------------- terminal (WebSocket <-> tmux)

def ws_frame(opcode: int, data: bytes) -> bytes:
    n = len(data)
    if n < 126:
        hdr = struct.pack("!BB", 0x80 | opcode, n)
    elif n < 1 << 16:
        hdr = struct.pack("!BBH", 0x80 | opcode, 126, n)
    else:
        hdr = struct.pack("!BBQ", 0x80 | opcode, 127, n)
    return hdr + data


async def ws_read(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    """Return one complete (reassembled) message as (opcode, payload)."""
    opcode, buf = None, b""
    while True:
        b1, b2 = await reader.readexactly(2)
        op, length = b1 & 0x0F, b2 & 0x7F
        if not b2 & 0x80:
            raise ConnectionError("unmasked client frame")
        if length == 126:
            length = struct.unpack("!H", await reader.readexactly(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", await reader.readexactly(8))[0]
        if length > MAX_BODY:
            raise ConnectionError("frame too large")
        mask = await reader.readexactly(4)
        data = bytes(c ^ mask[i % 4] for i, c in enumerate(await reader.readexactly(length)))
        if op >= 0x8:                      # control frames may interleave
            return op, data
        if op != 0:
            opcode = op
        buf += data
        if b1 & 0x80:
            return opcode or 0x1, buf


async def terminal(req: Request, name: str, reader, w):
    ws = load_ws(name)
    if not ws:
        return await respond(w, 404, "No such workspace\n")
    key = req.headers.get("sec-websocket-key", "")
    accept = base64.b64encode(hashlib.sha1(key.encode() + WS_GUID).digest()).decode()
    w.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
             f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode())
    await w.drain()

    session = f"cl-{name}"
    if (await run(*TMUX, "has-session", "-t", session))[0] != 0:
        w.write(ws_frame(0x2, b"\r\n\x1b[33mNo Claude session running. Use \"Start Claude\".\x1b[0m\r\n"))
        w.write(ws_frame(0x8, struct.pack("!H", 1000)))
        await w.drain()
        return

    cols = max(20, min(500, int(req.query.get("cols", "120") or 120)))
    rows = max(5, min(200, int(req.query.get("rows", "40") or 40)))
    master, slave = os.openpty()
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    env = {**os.environ, "TERM": "xterm-256color"}
    env.pop("TMUX", None)
    # setsid -c: new session with the pty as controlling terminal, so the
    # tmux client gets SIGWINCH when we resize.
    proc = await asyncio.create_subprocess_exec(
        "setsid", "-c", "-w", *TMUX, "attach-session", "-t", session,
        stdin=slave, stdout=slave, stderr=slave, env=env)
    os.close(slave)
    os.set_blocking(master, False)

    loop = asyncio.get_running_loop()
    out_q: asyncio.Queue[bytes | None] = asyncio.Queue()

    def on_pty():
        try:
            data = os.read(master, 65536)
        except BlockingIOError:
            return
        except OSError:
            data = b""
        if not data:
            loop.remove_reader(master)
        out_q.put_nowait(data or None)

    loop.add_reader(master, on_pty)

    async def pump_out():
        while (data := await out_q.get()) is not None:
            w.write(ws_frame(0x2, data))
            await w.drain()
        w.write(ws_frame(0x8, struct.pack("!H", 1000)))
        await w.drain()

    async def pump_in():
        while True:
            op, data = await ws_read(reader)
            if op == 0x8:
                return
            if op == 0x9:
                w.write(ws_frame(0xA, data))
                continue
            if op not in (0x1, 0x2):
                continue
            try:
                msg = json.loads(data)
            except json.JSONDecodeError:
                continue
            if msg.get("t") == "i":
                view = memoryview(str(msg.get("d", "")).encode())
                while view:
                    try:
                        view = view[os.write(master, view):]
                    except BlockingIOError:
                        await asyncio.sleep(0.01)
            elif msg.get("t") == "r":
                c = max(20, min(500, int(msg.get("c", cols))))
                r = max(5, min(200, int(msg.get("r", rows))))
                fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", r, c, 0, 0))

    tasks = [asyncio.create_task(pump_out()), asyncio.create_task(pump_in())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()
        loop.remove_reader(master)
        if proc.returncode is None:
            proc.terminate()       # detaches the tmux client; Claude keeps running
        try:
            await asyncio.wait_for(proc.wait(), 5)
        except TimeoutError:
            proc.kill()
        os.close(master)


# --------------------------------------------------------------- sandbox proxy

PROXY_LOGIN_PAGE = b"""<!doctype html><meta charset=utf-8><title>Sandbox</title>
<p style="font:15px system-ui;margin:3rem">Open this sandbox from the Agent Sandboxes dashboard.</p>"""


async def handle_proxy(req: Request, name: str, reader, w):
    ws = load_ws(name)
    prefix = sandbox_prefix(name)
    raw_path = req.target.split("?", 1)[0]
    if not (raw_path == prefix or raw_path.startswith(prefix + "/")) \
            or not hmac.compare_digest(raw_path[:len(prefix)], prefix):
        return await respond(w, 401, PROXY_LOGIN_PAGE, "text/html; charset=utf-8")
    # Pages in the sandbox are agent-controlled; never let another origin
    # (e.g. a different workspace's sandbox) drive this one.
    origin = req.headers.get("origin")
    if origin is not None and origin != f"{SCHEME}://{req.host}":
        return await respond(w, 403, "Cross-origin request refused\n")

    target = req.target[len(prefix):] or "/"
    if not target.startswith("/"):
        target = "/" + target
    upgrade = "upgrade" in req.headers.get("connection", "").lower()
    drop = {"x-aio-api-key", "authorization", "connection", "keep-alive",
            "proxy-connection", "proxy-authorization", "cookie"}
    headers = [(k, v) for k, v in req.raw_headers if k.lower() not in drop]
    # Cookies aren't port-scoped: on <ip>:91xx the browser also sends the UI's
    # session cookie. Never hand that to an (agent-controlled) container.
    cookies = "; ".join(f"{k}={v}" for k, v in req.cookies().items() if k != "asui")
    if cookies:
        headers.append(("Cookie", cookies))
    headers.append(("X-AIO-API-Key", ws["WS_KEY"]))
    headers.append(("Connection", "Upgrade" if upgrade else "close"))
    head = f"{req.method} {target} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers)

    port = int(ws["WS_PORT"])
    try:
        up_r, up_w = await asyncio.open_connection("127.0.0.1", port)
    except OSError:
        return await respond(w, 502, "Sandbox container isn't running.\n")
    up_w.write(head.encode("latin-1") + b"\r\n")
    await up_w.drain()

    async def client_to_upstream():
        while data := await reader.read(65536):
            up_w.write(data)
            await up_w.drain()
        if up_w.can_write_eof():
            up_w.write_eof()

    c2u = asyncio.create_task(client_to_upstream())
    try:
        resp_head = await up_r.readuntil(b"\r\n\r\n")
        lines = resp_head[:-4].decode("latin-1").split("\r\n")
        out = [lines[0]]
        for line in lines[1:]:
            k = line.split(":", 1)[0].strip().lower()
            if k in ("x-frame-options", "content-security-policy", "referrer-policy"):
                continue      # replaced below; the dashboard must be able to frame it
            if k == "location":
                loc = line.split(":", 1)[1].strip()
                loc = re.sub(rf"^http://(127\.0\.0\.1|localhost):{port}", "", loc, flags=re.I)
                if loc.startswith("/") and not loc.startswith("//") and not loc.startswith(prefix):
                    loc = prefix + loc
                line = f"Location: {loc}"
            out.append(line)
        out.append(f"Content-Security-Policy: frame-ancestors 'self' {ui_ancestors()}")
        out.append("Referrer-Policy: no-referrer")   # keep the capability path from leaking
        w.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1"))
        await w.drain()
        while data := await up_r.read(65536):
            w.write(data)
            await w.drain()
    finally:
        c2u.cancel()
        up_w.close()


# --------------------------------------------------------------- main

def extra_hostnames() -> set[str]:
    """Additional DNS names for this host, from ui/extra-hostnames (also
    read by bin/sandbox-ui-cert, which puts them in the certificate)."""
    path = ROOT / "ui" / "extra-hostnames"
    if not path.is_file():
        return set()
    names = {line.split("#", 1)[0].strip().lower() for line in path.read_text().splitlines()}
    return {n for n in names if re.fullmatch(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", n)}


def primary_ip() -> str | None:
    """Source address of the default route (no packet is sent)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("192.0.2.1", 9))
            return s.getsockname()[0]
        except OSError:
            return None


async def resolve_bind() -> list[str]:
    if spec := os.environ.get("AIO_UI_BIND"):
        return [a.strip() for a in spec.split(",") if a.strip()]
    for _ in range(60):      # at boot the network may not be up yet
        if ip := primary_ip():
            return ["127.0.0.1", ip]
        await asyncio.sleep(2)
    print("warning: no primary IP found; listening on 127.0.0.1 only", flush=True)
    return ["127.0.0.1"]


async def open_sandbox_listener(ws: dict[str, str]) -> str | None:
    name = ws["WS_NAME"]
    port = int(ws["WS_PORT"]) + PROXY_PORT_OFFSET
    servers = []
    try:
        for addr in BIND:
            servers.append(await asyncio.start_server(
                lambda r, w: handle(r, w, sandbox=name), addr, port, limit=MAX_HEAD,
                ssl=TLS_CTX, ssl_handshake_timeout=15 if TLS_CTX else None))
    except OSError as e:
        for s in servers:
            s.close()
        msg = f"Can't serve sandbox '{name}' on port {port}: {e.strerror}"
        print(msg, flush=True)
        return msg
    sandbox_listeners[name] = servers
    return None


def close_sandbox_listener(name: str):
    for s in sandbox_listeners.pop(name, []):
        s.close()


async def refresh_cert():
    """(Re)issue the server certificate if needed and load it; new TLS
    handshakes pick it up immediately."""
    if not TLS_CTX:
        return
    rc, out, err = await run(str(CERT_TOOL), timeout=60)
    if rc != 0:
        print(f"certificate refresh failed: {err.strip()}", flush=True)
        return
    if out.strip() == "issued":
        TLS_CTX.load_cert_chain(TLS_DIR / "server.crt", TLS_DIR / "server.key")
        print("server certificate (re)issued and loaded", flush=True)


async def renew_daily():
    while True:
        await asyncio.sleep(24 * 3600)
        await refresh_cert()


def drop_ambient_caps():
    """The service may start with CAP_NET_BIND_SERVICE (to bind 443). Once
    the sockets are bound, clear the ambient set so nothing we spawn (tmux,
    Claude and everything it runs, docker) inherits it."""
    PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL = 47, 4
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0:
        print(f"warning: could not clear ambient capabilities (errno {ctypes.get_errno()})", flush=True)


def make_tls_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(TLS_DIR / "server.crt", TLS_DIR / "server.key")
    return ctx


async def main():
    global TOKEN, BIND, TLS_CTX, SCHEME, WS_SCHEME
    TOKEN = TOKEN_FILE.read_text().strip()
    ensure_dirs()
    BIND = await resolve_bind()
    UI_HOSTNAMES.update(BIND)
    UI_HOSTNAMES.update(h.lower() for h in {socket.gethostname(), socket.getfqdn()} if h)
    UI_HOSTNAMES.update(extra_hostnames())
    UI_HOSTNAMES.discard("0.0.0.0")

    if os.environ.get("AIO_UI_TLS", "1") != "0":
        rc, _, err = await run(str(CERT_TOOL), timeout=60)
        if rc != 0:
            raise SystemExit(f"certificate setup failed: {err.strip()}")
        TLS_CTX = make_tls_context()
        SCHEME, WS_SCHEME = "https", "wss"
        fp = (await run("openssl", "x509", "-in", str(TLS_DIR / "ca.crt"), "-noout",
                        "-fingerprint", "-sha256"))[1].strip()
        print(f"TLS on; CA {TLS_DIR / 'ca.crt'} ({fp})", flush=True)

    servers = [await asyncio.start_server(handle, addr, LISTEN_PORT, limit=MAX_HEAD, ssl=TLS_CTX,
                                          ssl_handshake_timeout=15 if TLS_CTX else None)
               for addr in BIND]
    for ws in all_ws():
        await open_sandbox_listener(ws)
    drop_ambient_caps()
    for addr in BIND:
        print(f"Agent Sandboxes UI on {SCHEME}://{addr}:{LISTEN_PORT}/", flush=True)
    await asyncio.gather(renew_daily(), *(s.serve_forever() for s in servers))


def cli_prepare(name: str):
    """bin/claude-in calls this (outside nono) and evals the output."""
    info = asyncio.run(prepare(name))
    print(f"WS_PROFILE={shlex.quote(info['profile'])}")
    print(f"WS_MEMORY={shlex.quote(info['memory'])}")
    print(f"WS_PIDS={int(info['pids'])}")


if __name__ == "__main__":
    if sys.argv[1:2] == ["prepare"] and len(sys.argv) == 3:
        cli_prepare(sys.argv[2])
        sys.exit(0)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
