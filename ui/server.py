#!/usr/bin/env python3
"""Agent Sandboxes web UI.

Manages the lifecycle of nono-sandboxed Claude Code workspaces, each
paired with an AIO Sandbox container: create / start / stop / remove,
a browser terminal onto the workspace's Claude session (tmux), a file
browser with downloads from the container, and the container's VNC /
web UI through an authenticating reverse proxy.

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
import socket
import ssl
import struct
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
PROJECTS_BASE = Path(os.environ.get("AIO_PROJECTS", Path.home() / "projects"))
LISTEN_PORT = int(os.environ.get("AIO_UI_PORT", "9000"))
SANDBOX_PORTS = range(8101, 8200)
PROXY_PORT_OFFSET = 1000          # sandbox 8101 is served to browsers on 9101

TMUX = ["tmux", "-L", "agent-sandboxes", "-f", str(TMUX_CONF)]
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,29}$")
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
        out.append({"name": n, "dir": ws.get("WS_DIR"), "port": ws.get("WS_PORT"),
                    "container": state, "containerDetail": detail,
                    "claude": claude.get(n, "stopped")})
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
    WS_ROOT.mkdir(mode=0o700, exist_ok=True)
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


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
