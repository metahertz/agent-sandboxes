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
import ipaddress
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
import time
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
MONITORING_ENV = ROOT / "monitoring" / ".env"   # present once bin/monitoring has set it up
OTLP_PORT = 4318                        # Alloy's OTLP/HTTP receiver (Claude Code telemetry)
PROJECTS_BASE = Path(os.environ.get("AIO_PROJECTS", Path.home() / "projects"))
LISTEN_PORT = int(os.environ.get("AIO_UI_PORT", "9000"))
SANDBOX_PORTS = range(8101, 8200)
PROXY_PORT_OFFSET = 1000          # sandbox 8101 is served to browsers on 9101
EGRESS_PORT_OFFSET = -1000        # and its port filter (host:port allow entries) is on 7101
# nono only injects tokens into plain-HTTP upstreams on loopback: HTTP API
# tokens go to this bridge (127.0.0.2: loopback, but not in nono's NO_PROXY)
HTTP_BRIDGE = ("127.0.0.2", 7100)

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
CA_FINGERPRINT = ""                          # SHA-256 of ui/tls/ca.crt, when TLS is on
WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_HEAD = 64 * 1024
MAX_BODY = 1024 * 1024

USER_GID = pwd.getpwuid(os.getuid()).pw_gid
TOKEN = ""
CAP_SALT = secrets.token_hex(16)   # sandbox links stop working when the server restarts
sandbox_listeners: dict[str, list[asyncio.Server]] = {}
egress_listeners: dict[str, asyncio.Server] = {}


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

    if req.path == "/download/export-claude-project" and req.method == "GET":
        return await respond(w, 200, EXPORT_TOOL.read_bytes(), "text/x-python; charset=utf-8",
                             {"Content-Disposition": 'attachment; filename="export-claude-project"'})

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

    if parts and parts[0] == "settings":
        return await settings_api(req, parts[1:], w)
    if parts and parts[0] == "access":
        return await access_api(req, parts[1:], w)
    if parts and parts[0] == "inbox":
        return await inbox_api(req, parts[1:], w)

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
        remove_access(lambda scope, _: scope == name)
        for p in (policy_path(name), profile_path(name), aux_profile_path(name)):
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


class WsError(Exception):
    def __init__(self, msg: str, status: int = 400):
        super().__init__(msg)
        self.status = status


def check_new_ws(name: str, raw_dir: str | None) -> str:
    """Validate a new workspace's name and folder; returns the real folder path."""
    if not NAME_RE.match(name):
        raise WsError("Name: lowercase letters, digits and dashes, max 30")
    if name == "upload":          # bin/ws-ssh's inbox target
        raise WsError("'upload' is reserved; choose another name")
    if load_ws(name):
        raise WsError(f"Workspace '{name}' already exists", 409)
    raw_dir = os.path.expanduser(str(raw_dir or PROJECTS_BASE / name).strip())
    if not DIR_RE.match(raw_dir):
        raise WsError("Directory must be an absolute path of [A-Za-z0-9._/-]")
    d = os.path.realpath(raw_dir)
    home = str(Path.home())
    if d in ("/", home) or dirs_overlap(d, str(ROOT)) or not d.startswith(home + "/"):
        raise WsError("Directory must be inside your home, and not your home "
                      "itself or the agent-sandboxes folder")
    for o in all_ws():
        if dirs_overlap(d, os.path.realpath(o["WS_DIR"])):
            raise WsError(f"Overlaps workspace '{o['WS_NAME']}' ({o['WS_DIR']}); "
                          "nono would expose one to the other")
    return d


async def provision_ws(name: str, d: str) -> dict:
    """Create (or adopt) the folder, link it to a new sandbox and start that."""
    used = {int(o["WS_PORT"]) for o in all_ws()}
    port = next((p for p in SANDBOX_PORTS if p not in used and port_free(p)), None)
    if port is None:
        raise WsError("No free sandbox port", 500)

    created_dir = not os.path.exists(d)
    os.makedirs(d, exist_ok=True)
    notes = []
    mcp = Path(d) / ".mcp.json"
    if mcp.is_symlink():          # e.g. from an imported project: never write through it
        mcp.unlink()
        notes.append("Replaced a symlinked .mcp.json")
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
    return {"ok": True, "name": name, "dir": d, "port": port, "notes": notes}


async def create_ws(req: Request, w):
    try:
        body = json.loads(req.body or b"{}")
    except json.JSONDecodeError:
        return await send_json(w, {"error": "Invalid JSON"}, 400)
    try:
        name = str(body.get("name", "")).strip()
        d = check_new_ws(name, body.get("dir"))
        return await send_json(w, await provision_ws(name, d), 201)
    except WsError as e:
        return await send_json(w, {"error": str(e)}, e.status)


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
    INBOX.mkdir(mode=0o700, exist_ok=True)
    for d in (WS_ROOT, SECRETS, SSH_POOL, TOKEN_POOL, STATE_ROOT, RUNTIME):
        d.mkdir(mode=0o700, parents=True, exist_ok=True)


def policy_path(name: str) -> Path:
    return WS_ROOT / f"{name}.policy.json"


def profile_path(name: str) -> Path:
    return WS_ROOT / f"{name}.profile.json"


def aux_profile_path(name: str) -> Path:
    return WS_ROOT / f"{name}.aux-profile.json"


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


def unsafe_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """This host (loopback / 0.0.0.0) or link-local (cloud metadata): never a
    network destination. Loopback is open_port's job."""
    ip = getattr(ip, "ipv4_mapped", None) or ip
    return ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast


def parse_net_entry(x: str, what: str, ports_ok: bool) -> tuple[str, int, int]:
    """'host', '*.host', an IPv4 / IPv6 address, each optionally ':port' or
    ':lo-hi' (IPv6 then in brackets). Returns (host, lo, hi), ports 0 = any."""
    x = x.strip().lower()
    lo = hi = 0
    if "://" in x:
        raise ValueError(f"{what}: just the host, not a URL ({x!r})")
    m = re.match(r"^\[([0-9a-f:.]+)\](?::(.*))?$", x) or (
        re.match(r"^([^:]+):(.*)$", x) if x.count(":") == 1 else None)
    host, port = (m[1], m[2]) if m else (x, None)
    if port is not None:
        if not ports_ok:
            raise ValueError(f"{what}: no ports here, just the host ({x!r})")
        pm = re.match(r"^([0-9]{1,5})(?:-([0-9]{1,5}))?$", port)
        lo, hi = (int(pm[1]), int(pm[2] or pm[1])) if pm else (0, 0)
        if not (pm and 1 <= lo <= hi <= 65535):
            raise ValueError(f"{what}: bad port in {x!r} (a port, or a range like 8000-8100)")
    if "/" in host:
        raise ValueError(f"{what}: {x!r}: nono's proxy can't match address ranges; list each address")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if not DOMAIN_RE.match(host):
            raise ValueError(f"{what}: invalid entry {x!r}") from None
    else:
        if unsafe_ip(ip):
            raise ValueError(f"{what}: {x!r} is this host or link-local; use the workspace's own ports instead")
        host = ip.compressed      # the proxy matches IPv6 in canonical form only
    return host, lo, hi


def format_net_entry(host: str, lo: int, hi: int) -> str:
    if not lo:
        return host
    return f"{f'[{host}]' if ':' in host else host}:{lo}" + (f"-{hi}" if hi != lo else "")


def clean_net_list(v, what: str, ports_ok: bool) -> list[str]:
    out = [format_net_entry(*parse_net_entry(x, what, ports_ok))
           for x in clean_list(v, re.compile(r"^\S+$"), what)]
    return list(dict.fromkeys(out))


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
                      "allow": clean_net_list(net.get("allow", []), "Allowed hosts", ports_ok=True),
                      "deny": clean_net_list(net.get("deny", []), "Blocked hosts", ports_ok=False)}
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
        try:
            if up.scheme not in ("https", "http") or not up.hostname or up.query or up.fragment \
                    or up.username or up.password is not None:
                raise ValueError
            parse_net_entry(up.hostname, "", False)     # a domain or a (non-local) IP address
            up.port
        except ValueError:
            raise ValueError("Upstream: an https:// or http:// URL (host, optional port and path)") from None
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
                "upstream": urllib.parse.urlunsplit((up.scheme, up.netloc.lower(), up.path.rstrip("/"), "", "")),
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
    telemetry = telemetry_enabled()
    net: dict = {"open_port": [int(ws["WS_PORT"])] + ([OTLP_PORT] if telemetry else [])}
    mode = pol["network"]["mode"]
    net["network_profile"] = None if mode == "open" else mode
    allow = [parse_net_entry(x, "", True) for x in pol["network"]["allow"]]
    if allow:
        net["allow_domain"] = list(dict.fromkeys(h for h, _, _ in allow))
        if any(lo for _, lo, _ in allow):
            # nono's proxy matches hosts only; it hands what it allowed to our
            # port filter, which enforces the host:port entries
            net["upstream_proxy"] = f"127.0.0.1:{egress_port(ws)}"
    if pol["network"]["deny"]:
        net["deny_domain"] = pol["network"]["deny"]
    creds = {}
    for tid in pol["tokens"]:
        meta = token_meta(tid)
        creds["pool_" + tid.replace("-", "_")] = {
            "upstream": bridge_upstream(tid, meta["upstream"]), "credential_key": f"file://{TOKEN_POOL / tid}",
            "inject_header": meta["inject_header"], "credential_format": meta["credential_format"],
            "env_var": meta["env_var"]}
    if creds:
        net["credentials"] = sorted(creds)
        net["custom_credentials"] = creds
    env = {"SSH_AUTH_SOCK": str(agent_sock(name)),
           "GIT_SSH_COMMAND": f"ssh -F {st / 'ssh_config'}"}
    if telemetry:
        # Claude Code's own metrics and events (tokens, cost, tool decisions;
        # prompt text stays redacted) to Alloy, labelled with the workspace.
        env.update({"CLAUDE_CODE_ENABLE_TELEMETRY": "1",
                    "OTEL_METRICS_EXPORTER": "otlp", "OTEL_LOGS_EXPORTER": "otlp",
                    "OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
                    "OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE": "cumulative",
                    "OTEL_EXPORTER_OTLP_ENDPOINT": f"http://127.0.0.1:{OTLP_PORT}",
                    "OTEL_RESOURCE_ATTRIBUTES": f"workspace={name}",
                    "OTEL_METRIC_EXPORT_INTERVAL": "30000"})
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
        "environment": {"set_vars": env},
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


async def prepare(name: str, aux: bool = False) -> dict:
    """Everything Claude needs before nono starts: agent with its keys,
    ssh config, and the rendered profile (what's now 'applied'). aux: for a
    shell / SSH command instead, whose profile mustn't count as Claude's."""
    ensure_dirs()
    ws = load_ws(name)
    if not ws:
        raise SystemExit(f"No workspace '{name}'")
    await sync_agent(name)
    write_ssh_config(name)
    target = aux_profile_path(name) if aux else profile_path(name)
    private_write(target, profile_text(ws))
    return {"profile": str(target), **load_policy(name)["limits"]}


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


# ---- SSH access: per-workspace keys and inbox upload keys (~/.ssh/authorized_keys)

AUTH_KEYS = Path.home() / ".ssh" / "authorized_keys"
ACCESS_FILE = SECRETS / "ssh-access.json"
WS_SSH = ROOT / "bin" / "ws-ssh"
AK_BEGIN = "# >>> agent-sandboxes: managed by the web UI (Import page, Access tab); edits inside are replaced >>>"
AK_END = "# <<< agent-sandboxes <<<"
KEY_TYPES = {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
             "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"}


def parse_pubkey(text: str) -> tuple[str, str, str]:
    """One OpenSSH public key line, no options -> (type, base64 blob, comment)."""
    parts = text.strip().split(None, 2)
    if "\n" in text.strip() or len(parts) < 2 or parts[0] not in KEY_TYPES:
        raise ValueError("Paste one public key line (ssh-ed25519 AAAA… comment), e.g. from ~/.ssh/id_ed25519.pub")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except ValueError:
        raise ValueError("That key isn't valid base64") from None
    n = struct.unpack(">I", blob[:4])[0] if len(blob) > 4 else 0
    if blob[4:4 + n].decode(errors="replace") != parts[0]:
        raise ValueError("Key type and key data don't match")
    comment = re.sub(r"[^A-Za-z0-9@._+ -]", "", parts[2] if len(parts) > 2 else "")[:80].strip()
    return parts[0], parts[1], comment


def key_fingerprint(b64: str) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(b64)).digest()).decode().rstrip("=")


def key_id(b64: str) -> str:
    return hashlib.sha256(b64.encode()).hexdigest()[:16]


def load_access() -> dict:
    try:
        acc = json.loads(ACCESS_FILE.read_text())
    except (OSError, ValueError):
        acc = {}
    return {"upload": acc.get("upload", []), "workspaces": acc.get("workspaces", {})}


def access_entries(acc: dict):
    for e in acc["upload"]:
        yield "upload", e
    for ws, keys in acc["workspaces"].items():
        for e in keys:
            yield ws, e


def split_authorized_keys() -> tuple[list[str], list[str]]:
    """(lines outside our block, lines inside it)."""
    try:
        lines = AUTH_KEYS.read_text().splitlines()
    except FileNotFoundError:
        lines = []
    if AK_BEGIN in lines and AK_END in lines[lines.index(AK_BEGIN):]:
        a = lines.index(AK_BEGIN)
        b = lines.index(AK_END, a)
        return lines[:a] + lines[b + 1:], lines[a + 1:b]
    return lines, []


def write_authorized_keys(acc: dict):
    outside, _ = split_authorized_keys()
    while outside and not outside[-1].strip():
        outside.pop()
    block = []
    for scope, e in access_entries(acc):
        opts = f'command="{WS_SSH} {scope}",restrict' + ("" if scope == "upload" else ",pty")
        block.append(f"{opts} {e['type']} {e['key']} {e['comment']}".rstrip())
    text = "\n".join(outside + ([""] if outside and block else []) + ([AK_BEGIN, *block, AK_END] if block else []))
    AUTH_KEYS.parent.mkdir(mode=0o700, exist_ok=True)
    private_write(AUTH_KEYS, text + "\n" if text else "")


def save_access(acc: dict):
    private_write(ACCESS_FILE, json.dumps(acc, indent=2) + "\n")
    write_authorized_keys(acc)


def add_access_key(scope: str, text: str) -> dict:
    if scope != "upload" and not load_ws(scope):
        raise ValueError("No such workspace")
    ktype, b64, comment = parse_pubkey(text)
    acc = load_access()
    for sc, e in access_entries(acc):
        if e["key"] == b64:
            raise ValueError(f"That key is already used for {'uploads' if sc == 'upload' else sc}; "
                             "use a separate key for each")
    outside, _ = split_authorized_keys()
    if any(b64 in line.split() for line in outside):
        raise ValueError("That key already logs in to this account unrestricted (it's in "
                         "~/.ssh/authorized_keys), so a restriction here wouldn't apply. Use a new key.")
    entry = {"type": ktype, "key": b64, "comment": comment, "added": int(time.time())}
    (acc["upload"] if scope == "upload" else acc["workspaces"].setdefault(scope, [])).append(entry)
    save_access(acc)
    return {"id": key_id(b64), "fingerprint": key_fingerprint(b64)}


def remove_access(pred) -> int:
    acc = load_access()
    before = sum(1 for _ in access_entries(acc))
    acc["upload"] = [e for e in acc["upload"] if not pred("upload", e)]
    acc["workspaces"] = {ws: kept for ws, keys in acc["workspaces"].items()
                         if (kept := [e for e in keys if not pred(ws, e)])}
    removed = before - sum(1 for _ in access_entries(acc))
    if removed:
        save_access(acc)
    return removed


def access_listing() -> dict:
    acc = load_access()
    view = lambda e: {"id": key_id(e["key"]), "type": e["type"], "comment": e["comment"],
                      "fingerprint": key_fingerprint(e["key"]), "added": e.get("added")}
    return {"user": pwd.getpwuid(os.getuid()).pw_name,
            "upload": [view(e) for e in acc["upload"]],
            "workspaces": {ws: [view(e) for e in keys] for ws, keys in acc["workspaces"].items()}}


async def access_api(req: Request, parts: list[str], w):
    try:
        if parts == [] and req.method == "GET":
            return await send_json(w, access_listing())
        if parts == [] and req.method == "POST":
            body = json.loads(req.body or b"{}")
            return await send_json(w, add_access_key(str(body.get("scope", "")), str(body.get("key", ""))), 201)
        if len(parts) == 1 and re.fullmatch(r"[0-9a-f]{16}", parts[0]) and req.method == "DELETE":
            if not remove_access(lambda _, e: key_id(e["key"]) == parts[0]):
                return await send_json(w, {"error": "Not found"}, 404)
            return await send_json(w, {"ok": True})
    except (ValueError, json.JSONDecodeError) as e:
        return await send_json(w, {"error": str(e)}, 400)
    await respond(w, 404, "Not found\n")


# ---- import inbox: projects (with their Claude history) from other machines

INBOX = ROOT / "inbox"
IMPORT_DIR = ".claude-import"            # written by bin/export-claude-project
CLAUDE_HOME = Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude")
EXPORT_TOOL = ROOT / "bin" / "export-claude-project"
MUNGED = "/rsyncd-munged/"               # rrsync -munge prefix on uploaded symlinks
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
import_lock = asyncio.Lock()


def claude_project_key(path: str) -> str:
    """Claude Code's folder name for a project under ~/.claude/projects."""
    return re.sub(r"[^A-Za-z0-9]", "-", path)


def real_dir(p: Path) -> bool:
    return p.is_dir() and not p.is_symlink()


def read_manifest(drop: Path) -> dict | None:
    m = drop / IMPORT_DIR / "manifest.json"
    try:
        if m.is_symlink() or not m.is_file() or m.stat().st_size > 1 << 20:
            return None
        man = json.loads(m.read_text())
        return man if isinstance(man, dict) and isinstance(man.get("source_path"), str) else None
    except (OSError, ValueError):
        return None


def suggest_name(drop: str) -> str:
    n = re.sub(r"[^a-z0-9-]+", "-", drop.lower()).strip("-")[:30].strip("-")
    return n if NAME_RE.match(n) else "imported"


async def inbox_listing() -> list[dict]:
    INBOX.mkdir(mode=0o700, exist_ok=True)
    out = []
    for d in sorted(INBOX.iterdir()):
        if d.name.startswith(".") or not real_dir(d):
            continue
        rc, du, _ = await run("du", "-sxB1", str(d), timeout=30)
        man = read_manifest(d)
        has_import = real_dir(d / IMPORT_DIR)
        name = suggest_name(d.name)
        out.append({
            "drop": d.name, "suggested": name,
            "nameTaken": bool(load_ws(name)) or (PROJECTS_BASE / name).exists(),
            "size": int(du.split()[0]) if rc == 0 and du.split() else None,
            "modified": int(d.stat().st_mtime),
            "git": real_dir(d / ".git"), "claudeDir": real_dir(d / ".claude"),
            "claudeMd": (d / "CLAUDE.md").is_file(),
            "incomplete": has_import and man is None,
            "history": None if not man else {
                "sourceHost": str(man.get("source_host", ""))[:100],
                "sourcePath": man["source_path"][:300],
                "sessions": len(man.get("sessions") or []),
                "exportedAt": str(man.get("exported_at", ""))[:40]},
        })
    return out


def copy_regular_files(src: Path, dst: Path, transform=None) -> tuple[int, int]:
    """Copy regular files under src to dst (symlinks and specials skipped, nothing
    overwritten). Returns (copied, skipped)."""
    copied = skipped = 0
    if not real_dir(src):
        return 0, 0
    for root, dirs, files in os.walk(src):
        dirs[:] = [x for x in dirs if not os.path.islink(os.path.join(root, x))]
        for f in files:
            p = Path(root) / f
            if p.is_symlink() or not p.is_file():
                continue
            out = dst / p.relative_to(src)
            if out.exists():
                skipped += 1
                continue
            out.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            data = p.read_bytes()
            private_write(out, transform(p, data) if transform else data)
            copied += 1
    return copied, skipped


def install_history(staging: Path, source: str, target: str) -> dict:
    """Put an export's Claude history where Claude Code looks for the new folder."""
    def rehome(v: str) -> str:
        return target + v[len(source):] if v == source or v.startswith(source + "/") else v

    def fix_jsonl(p: Path, data: bytes) -> bytes:
        if p.suffix != ".jsonl":
            return data
        out = []
        for line in data.decode(errors="replace").splitlines():
            try:
                obj = json.loads(line)
            except ValueError:
                out.append(line)
                continue
            if isinstance(obj, dict) and isinstance(obj.get("cwd"), str):
                obj["cwd"] = rehome(obj["cwd"])
                line = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
            out.append(line)
        return ("\n".join(out) + "\n").encode()

    dest = CLAUDE_HOME / "projects" / claude_project_key(target)
    copied, skipped = copy_regular_files(staging / "projects", dest, fix_jsonl)
    sessions = len([f for f in dest.glob("*.jsonl")]) if dest.is_dir() else 0
    fh = staging / "file-history"
    if real_dir(fh):
        for sd in fh.iterdir():
            if UUID_RE.match(sd.name) and real_dir(sd):
                copy_regular_files(sd, CLAUDE_HOME / "file-history" / sd.name)
    td = staging / "todos"
    if real_dir(td):
        for f in td.iterdir():
            if re.fullmatch(r"[0-9a-f-]{36}[A-Za-z0-9._-]{0,80}\.json", f.name) and f.is_file() and not f.is_symlink() \
                    and not (CLAUDE_HOME / "todos" / f.name).exists():
                (CLAUDE_HOME / "todos").mkdir(mode=0o700, exist_ok=True)
                private_write(CLAUDE_HOME / "todos" / f.name, f.read_bytes())
    prompts = 0
    hist = staging / "history.jsonl"
    if hist.is_file() and not hist.is_symlink():
        lines = []
        for line in hist.read_text(errors="replace").splitlines():
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict) and obj.get("project") == source:
                obj["project"] = target
                lines.append(json.dumps(obj, ensure_ascii=False, separators=(",", ":")))
        if lines:
            fd = os.open(CLAUDE_HOME / "history.jsonl", os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a") as f:     # one write: Claude may be appending too
                f.write("\n".join(lines) + "\n")
            prompts = len(lines)
    return {"files": copied, "skipped": skipped, "sessions": sessions, "prompts": prompts}


def unmunge_symlinks(top: str) -> int:
    fixed = 0
    for root, dirs, files in os.walk(top):
        for n in dirs + files:
            p = os.path.join(root, n)
            if os.path.islink(p) and (t := os.readlink(p)).startswith(MUNGED):
                os.unlink(p)
                os.symlink(t[len(MUNGED):], p)
                fixed += 1
    return fixed


async def import_drop(drop: str, name: str, raw_dir: str | None) -> dict:
    src = INBOX / drop
    if drop.startswith(".") or "/" in drop or not real_dir(src):
        raise WsError("No such upload in the inbox", 404)
    d = check_new_ws(name, raw_dir)
    if os.path.lexists(d):
        raise WsError(f"{d} already exists; choose another folder (imports never merge into one)", 409)
    man = read_manifest(src)
    if real_dir(src / IMPORT_DIR) and man is None:
        raise WsError("This upload looks incomplete (no manifest yet); wait for it to finish", 409)
    if (src / IMPORT_DIR).is_symlink():
        raise WsError(f"{IMPORT_DIR} is a symlink; refusing")

    staging = INBOX / f".importing-{secrets.token_hex(4)}"
    if real_dir(src / IMPORT_DIR):
        (src / IMPORT_DIR).rename(staging)
    Path(d).parent.mkdir(parents=True, exist_ok=True)
    try:
        os.rename(src, d)
    except OSError:
        shutil.move(str(src), d)
    fixed = await asyncio.to_thread(unmunge_symlinks, d)
    result = await provision_ws(name, d)
    if fixed:
        result["notes"].append(f"Restored {fixed} symlink(s) defused during upload")
    if man:
        try:
            result["history"] = await asyncio.to_thread(install_history, staging, man["source_path"].rstrip("/"), d)
        except OSError as e:
            result["notes"].append(f"Claude history not fully imported: {e}")
    if staging.exists():
        shutil.rmtree(staging, ignore_errors=True)
    return result


async def inbox_api(req: Request, parts: list[str], w):
    try:
        if parts == [] and req.method == "GET":
            return await send_json(w, {"drops": await inbox_listing(), "inbox": str(INBOX)})
        if len(parts) == 2 and parts[1] == "import" and req.method == "POST":
            body = json.loads(req.body or b"{}")
            if import_lock.locked():
                return await send_json(w, {"error": "Another import is running"}, 409)
            async with import_lock:
                res = await import_drop(parts[0], str(body.get("name", "")).strip(), body.get("dir") or None)
            return await send_json(w, res, 201)
        if len(parts) == 1 and req.method == "DELETE":
            p = INBOX / parts[0]
            if parts[0].startswith(".") or "/" in parts[0] or not real_dir(p):
                return await send_json(w, {"error": "Not found"}, 404)
            await asyncio.to_thread(shutil.rmtree, p)
            return await send_json(w, {"ok": True})
    except WsError as e:
        return await send_json(w, {"error": str(e)}, e.status)
    except json.JSONDecodeError as e:
        return await send_json(w, {"error": str(e)}, 400)
    await respond(w, 404, "Not found\n")


# ---- settings: monitoring (monitoring/.env, shared with bin/monitoring and compose)

def http_url(v: str) -> bool:
    u = urllib.parse.urlsplit(v)
    return u.scheme in ("http", "https") and bool(u.netloc) and not re.search(r"\s", v)


def grafana_port(v: str) -> bool:
    if not re.fullmatch(r"[1-9][0-9]{0,4}", v):
        return False
    n = int(v)
    taken = (LISTEN_PORT, OTLP_PORT, *SANDBOX_PORTS, *(x + PROXY_PORT_OFFSET for x in SANDBOX_PORTS))
    return 1024 <= n <= 65535 and n not in taken


# key: (default, check, what's wrong when it fails)
MON_FIELDS = {
    "MONITORING_URL": ("", lambda v: v == "" or http_url(v), "Dashboards URL must be http(s)://…"),
    "CLAUDE_TELEMETRY": ("1", lambda v: v in ("0", "1"), "Telemetry is on or off"),
    "MON_STACK": ("1", lambda v: v in ("0", "1"), "Choose where data goes"),
    "PROM_WRITE_URL": ("", lambda v: v == "" or http_url(v), "Prometheus URL must be http(s)://…"),
    "LOKI_URL": ("", lambda v: v == "" or http_url(v), "Loki URL must be http(s)://…"),
    "GRAFANA_BIND": ("127.0.0.1", lambda v: re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", v) is not None,
                     "Grafana address must be an IPv4 address of this host"),
    "GRAFANA_PORT": ("3000", grafana_port, "Grafana port must be 1024-65535 and not one the UI or sandboxes use"),
    "GRAFANA_DOMAIN": ("localhost", lambda v: re.fullmatch(r"[A-Za-z0-9.-]{1,253}", v) is not None,
                       "Grafana hostname: letters, digits, dots and dashes"),
    "PROM_RETENTION": ("30d", lambda v: re.fullmatch(r"[1-9][0-9]{0,3}[hdwy]", v) is not None,
                       "Metrics retention: e.g. 30d"),
    "PROM_RETENTION_SIZE": ("5GB", lambda v: re.fullmatch(r"[1-9][0-9]{0,4}(MB|GB|TB)", v) is not None,
                            "Metrics size cap: e.g. 5GB"),
    "LOKI_RETENTION": ("336h", lambda v: re.fullmatch(r"[1-9][0-9]{0,5}h", v) is not None,
                       "Log retention in hours: e.g. 336h"),
}
MON_TOOL = ROOT / "bin" / "monitoring"
EXPORTER_PROM = ROOT / "monitoring" / "data" / "exporter" / "workspaces.prom"
mon_lock = asyncio.Lock()


def monitoring_settings() -> dict[str, str]:
    env = read_env(MONITORING_ENV) if MONITORING_ENV.is_file() else {}
    return {k: env.get(k, d).strip().strip("'\"") for k, (d, _, _) in MON_FIELDS.items()}


def telemetry_enabled() -> bool:
    return MONITORING_ENV.is_file() and monitoring_settings()["CLAUDE_TELEMETRY"] != "0"


def update_env(path: Path, values: dict[str, str]):
    """Set KEY=value lines in place, keeping comments: replace the active line,
    else uncomment a '#KEY=' example (left alone when the value is blank), else append."""
    lines = path.read_text().splitlines()
    todo = dict(values)
    for commented in (False, True):
        for i, line in enumerate(lines):
            body = line.lstrip("#").strip() if commented and line.startswith("#") else line
            if (line.startswith("#") == commented) and "=" in body:
                key = body.split("=", 1)[0].strip()
                if key in todo and not (commented and todo[key] == ""):   # blank: keep the example
                    lines[i] = f"{key}={todo.pop(key)}"
    lines += [f"{k}={v}" for k, v in todo.items() if v != ""]     # absent already means blank
    private_write(path, "\n".join(lines) + "\n")


def validate_monitoring(body: dict) -> dict[str, str]:
    cur = monitoring_settings()
    out = {}
    for k, (_, check, err) in MON_FIELDS.items():
        v = str(body.get(k, cur[k])).strip()
        if "\n" in v or not check(v):
            raise ValueError(err)
        out[k] = v
    if out["MON_STACK"] == "0" and not (out["PROM_WRITE_URL"] and out["LOKI_URL"]):
        raise ValueError("External monitoring needs both the Prometheus remote-write and Loki URLs")
    return out


async def monitoring_status() -> dict:
    _, ps, _ = await run("docker", "ps", "-a", "--filter", "name=^mon-",
                         "--format", "{{.Names}}\t{{.State}}\t{{.Status}}")
    services = []
    for line in ps.splitlines():
        n, state, detail = (line.split("\t") + ["", ""])[:3]
        services.append({"name": n.removeprefix("mon-"), "state": state, "detail": detail})
    try:
        age = int(time.time() - EXPORTER_PROM.stat().st_mtime)
    except OSError:
        age = None
    return {"configured": MONITORING_ENV.is_file(), "services": services, "exporterAge": age,
            "settings": monitoring_settings(), "telemetry": telemetry_enabled(),
            "caFingerprint": CA_FINGERPRINT}


async def settings_api(req: Request, parts: list[str], w):
    m = req.method
    if parts == ["monitoring"] and m == "GET":
        return await send_json(w, await monitoring_status())
    if parts == ["monitoring"] and m == "PUT":
        try:
            values = validate_monitoring(json.loads(req.body or b"{}"))
        except (ValueError, json.JSONDecodeError) as e:
            return await send_json(w, {"error": str(e)}, 400)
        async with mon_lock:
            if not MONITORING_ENV.is_file():
                rc, out, err = await run(str(MON_TOOL), "init", timeout=60)
                if rc != 0:
                    return await send_json(w, {"error": (err or out).strip()}, 500)
            update_env(MONITORING_ENV, values)
        return await send_json(w, await monitoring_status())
    if parts in (["monitoring", "apply"], ["monitoring", "stop"]) and m == "POST":
        if mon_lock.locked():
            return await send_json(w, {"error": "Monitoring is already being changed"}, 409)
        async with mon_lock:
            rc, out, err = await run(str(MON_TOOL), "up" if parts[1] == "apply" else "down", timeout=900)
        log = (out + err).strip()[-6000:]
        return await send_json(w, {**await monitoring_status(), "ok": rc == 0, "log": log},
                               200 if rc == 0 else 500)
    if parts == ["monitoring", "password"] and m == "GET":
        try:
            return await send_json(w, {"password": (SECRETS / "grafana-admin-password").read_text().strip()})
        except OSError:
            return await send_json(w, {"error": "No local Grafana password yet: apply first"}, 404)
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
    egress_err = await open_egress_filter(ws)
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
    return egress_err


def close_sandbox_listener(name: str):
    for s in sandbox_listeners.pop(name, []):
        s.close()
    if s := egress_listeners.pop(name, None):
        s.close()


# --------------------------------------------------------------- egress port filter
# nono's proxy allowlists hosts but not ports. When a workspace has host:port
# allow entries its profile sets this as nono's upstream_proxy: nono checks
# the host as usual, then sends us "CONNECT host:port" (plain HTTP too), and
# we refuse ports those entries don't list. Only nono's proxy can reach this
# listener: the sandbox may connect to its own open_port and the proxy alone.

def egress_port(ws: dict[str, str]) -> int:
    return int(ws["WS_PORT"]) + EGRESS_PORT_OFFSET


def host_matches(pattern: str, host: str) -> bool:
    return host == pattern or pattern.startswith("*.") and host.endswith(pattern[1:])


def egress_allowed(name: str, host: str, port: int) -> bool:
    """Entries naming this exact host decide, else wildcard ones; one without
    a port allows any (nono already allowed the host itself)."""
    entries = [parse_net_entry(x, "", True) for x in load_policy(name)["network"]["allow"]]
    hits = [e for e in entries if e[0] == host] or [e for e in entries if host_matches(e[0], host)]
    return not hits or any(not lo or lo <= port <= hi for _, lo, hi in hits)


async def egress_connect(host: str, port: int):
    """Like nono, never this host or link-local, also when a name resolves there."""
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addrs = [i for i in infos if not unsafe_ip(ipaddress.ip_address(i[4][0].split("%")[0]))]
    if not addrs:
        raise OSError(f"{host} resolves to this host or link-local only")
    err = None
    for family, _, _, _, sockaddr in addrs:
        try:
            return await asyncio.wait_for(asyncio.open_connection(sockaddr[0], port), 15)
        except (OSError, asyncio.TimeoutError) as e:
            err = e
    raise OSError(str(err))


async def handle_egress(reader, w, name: str):
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
        m = re.match(rb"CONNECT (\S+):([0-9]{1,5}) HTTP/1\.[01]\r\n", head)
        if not m:
            w.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return
        host, port = m[1].decode("latin-1").strip("[]").lower(), int(m[2])
        try:
            host = ipaddress.ip_address(host).compressed
        except ValueError:
            pass
        if not egress_allowed(name, host, port):
            print(f"egress: {name}: denied {host}:{port} (port not allowed)", flush=True)
            w.write(f"HTTP/1.1 403 Forbidden: port {port} is not allowed for {host}\r\n\r\n".encode())
            return
        try:
            up_r, up_w = await egress_connect(host, port)
        except OSError as e:
            w.write(f"HTTP/1.1 502 Bad Gateway: {e}\r\n\r\n".encode("latin-1", "replace"))
            return
        w.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await w.drain()

        async def pump(src, dst):
            try:
                while data := await src.read(65536):
                    dst.write(data)
                    await dst.drain()
                if dst.can_write_eof():
                    dst.write_eof()
            except OSError:
                pass

        try:
            await asyncio.gather(pump(reader, up_w), pump(up_r, w))
        finally:
            up_w.close()
    except (OSError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
        pass
    finally:
        w.close()


# --------------------------------------------------------------- HTTP API bridge
# A token for an http:// API gets the nono route http://127.0.0.2:7100/<id><path>;
# nono adds the token and we relay to the real host. One request per
# connection (Connection: close both ways), so nono's keep-alive can't carry a
# request for one token on to another token's host. Only nono's proxy can
# reach this: it's not one of the sandbox's ports.

def bridge_upstream(tid: str, upstream: str) -> str:
    if not upstream.startswith("http://"):
        return upstream
    host, port = HTTP_BRIDGE
    return f"http://{host}:{port}/{tid}{urllib.parse.urlsplit(upstream).path}"


HOP_HEADERS = {"host", "connection", "keep-alive", "proxy-connection", "expect", "upgrade", "te"}


async def copy_body(reader, writer, headers: dict[str, str]):
    """The request body, by Content-Length or chunked framing (and nothing after it)."""
    if "chunked" in headers.get("transfer-encoding", "").lower():
        while True:
            line = await reader.readuntil(b"\r\n")
            writer.write(line)
            size = int(line.split(b";", 1)[0].strip() or b"0", 16)
            if size == 0:
                while (trailer := await reader.readuntil(b"\r\n")) != b"\r\n":
                    writer.write(trailer)
                writer.write(b"\r\n")
                break
            writer.write(await reader.readexactly(size + 2))
            await writer.drain()
    else:
        left = int(headers.get("content-length") or 0)
        while left > 0:
            data = await reader.read(min(left, 65536))
            if not data:
                raise asyncio.IncompleteReadError(b"", left)
            writer.write(data)
            await writer.drain()
            left -= len(data)
    await writer.drain()


async def handle_bridge(reader, w):
    up_w = None
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
        lines = head[:-4].decode("latin-1").split("\r\n")
        m = re.match(r"^([A-Z]+) /([a-z0-9][a-z0-9-]{0,39})(/[^ ]*)? HTTP/1\.[01]$", lines[0])
        meta = token_meta(m[2]) if m else None
        if not meta or not meta.get("upstream", "").startswith("http://"):
            w.write(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            return
        target = urllib.parse.urlsplit(meta["upstream"])
        headers = {}
        out = [f"{m[1]} {m[3] or '/'} HTTP/1.1", f"Host: {target.netloc}"]
        for line in lines[1:]:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
            if k.strip().lower() not in HOP_HEADERS:
                out.append(line)
        out.append("Connection: close")
        try:
            up_r, up_w = await egress_connect(target.hostname, target.port or 80)
        except OSError as e:
            w.write(f"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\nX-Bridge-Error: {e}\r\n\r\n"
                    .encode("latin-1", "replace"))
            return
        if headers.get("expect", "").lower() == "100-continue":
            w.write(b"HTTP/1.1 100 Continue\r\n\r\n")
        up_w.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1"))
        await copy_body(reader, up_w, headers)
        while True:     # skip interim 1xx responses, then rewrite the final head
            resp = await asyncio.wait_for(up_r.readuntil(b"\r\n\r\n"), 300)
            if not re.match(rb"HTTP/1\.[01] 1\d\d", resp):
                break
        rlines = resp[:-4].decode("latin-1").split("\r\n")
        rheaders = {k.strip().lower(): v.strip() for k, _, v in (x.partition(":") for x in rlines[1:])}
        rlines = [rlines[0]] + [x for x in rlines[1:] if x.partition(":")[0].strip().lower()
                                not in ("connection", "keep-alive")] + ["Connection: close"]
        w.write(("\r\n".join(rlines) + "\r\n\r\n").encode("latin-1"))
        status = int(rlines[0].split()[1])
        if m[1] == "HEAD" or status in (204, 304):
            pass
        elif "content-length" in rheaders or "chunked" in rheaders.get("transfer-encoding", "").lower():
            await copy_body(up_r, w, rheaders)    # even if the server ignores Connection: close
        else:
            while data := await up_r.read(65536):
                w.write(data)
                await w.drain()
        await w.drain()
    except (OSError, ValueError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
        pass
    finally:
        if up_w:
            up_w.close()
        w.close()


async def open_egress_filter(ws: dict[str, str]) -> str | None:
    name, port = ws["WS_NAME"], egress_port(ws)
    try:
        egress_listeners[name] = await asyncio.start_server(
            lambda r, w: handle_egress(r, w, name), "127.0.0.1", port, limit=MAX_HEAD)
    except OSError as e:
        msg = f"Can't run the port filter for '{name}' on 127.0.0.1:{port}: {e.strerror}"
        print(msg, flush=True)
        return msg
    return None


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
    global TOKEN, BIND, TLS_CTX, SCHEME, WS_SCHEME, CA_FINGERPRINT
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
        CA_FINGERPRINT = fp.partition("=")[2]
        print(f"TLS on; CA {TLS_DIR / 'ca.crt'} ({fp})", flush=True)

    servers = [await asyncio.start_server(handle, addr, LISTEN_PORT, limit=MAX_HEAD, ssl=TLS_CTX,
                                          ssl_handshake_timeout=15 if TLS_CTX else None)
               for addr in BIND]
    for ws in all_ws():
        await open_sandbox_listener(ws)
    try:
        servers.append(await asyncio.start_server(handle_bridge, *HTTP_BRIDGE, limit=MAX_HEAD))
    except OSError as e:
        print(f"HTTP API bridge not running on {HTTP_BRIDGE[0]}:{HTTP_BRIDGE[1]}: {e.strerror}", flush=True)
    drop_ambient_caps()
    for addr in BIND:
        print(f"Agent Sandboxes UI on {SCHEME}://{addr}:{LISTEN_PORT}/", flush=True)
    await asyncio.gather(renew_daily(), *(s.serve_forever() for s in servers))


def cli_prepare(name: str, aux: bool = False):
    """bin/claude-in calls this (outside nono) and evals the output."""
    info = asyncio.run(prepare(name, aux))
    print(f"WS_PROFILE={shlex.quote(info['profile'])}")
    print(f"WS_MEMORY={shlex.quote(info['memory'])}")
    print(f"WS_PIDS={int(info['pids'])}")


if __name__ == "__main__":
    if sys.argv[1:2] == ["prepare"] and len(sys.argv) in (3, 4) and sys.argv[3:] in ([], ["--aux"]):
        cli_prepare(sys.argv[2], aux=sys.argv[3:] == ["--aux"])
        sys.exit(0)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
