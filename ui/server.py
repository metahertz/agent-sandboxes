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
import contextlib
import ctypes
import datetime
import fcntl
import grp
import hashlib
import hmac
import io
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
import subprocess
import sys
import tarfile
import termios
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (CONTAINER_PROXY_PORT, CONTAINER_PROXY_SECRETS, DEFAULT_POLICY, DOMAIN_RE,  # noqa: E402
                    EGRESS_PORT_OFFSET, HTTP_BRIDGE, ITEM_RE, MAX_HEAD, MAX_TAGS, NAME_RE, TAG_RE, PROXYD_SOCK, ROOT, RUNTIME,
                    SANDBOX_PORTS, SECRETS, SSH_POOL, TOKEN_POOL, VM_BROWSER_PORT, VM_PROXY_OFFSET,
                    VM_RELAY_PORT, VM_ROOT,
                    WS_ROOT, all_ws, container_ca_paths, container_filtered, container_net,
                    container_password_path, container_profile_path, die_with_parent, egress_port, is_microvm,
                    load_policy, load_ws, parse_net_entry, policy_path, proxyd_source_version, read_env,
                    token_meta, vm_browser, vm_cid)
import auth  # noqa: E402
import builds  # noqa: E402
import applesign  # noqa: E402
import relay  # noqa: E402
import shares  # noqa: E402

COMPOSE_FILE = ROOT / "compose.workspace.yaml"
CLAUDE_IN = ROOT / "bin" / "claude-in"
ASC_TOKEN = ROOT / "bin" / "asc-token"       # nono's proxy runs it for App Store Connect keys
MCP_TEMPLATE = ROOT / "mcp.json.template"
CLAUDE_MD_DEFAULT = ROOT / "ui" / "claude-md-additions.md"   # sandbox notes for workspaces' CLAUDE.md
CLAUDE_MD_CUSTOM = ROOT / "state" / "claude-md-additions.md"  # the Settings page's edited copy
CONTAINER_WORKSPACE = "/home/gem/workspace"                     # the project inside the AIO container
STATIC = ROOT / "ui" / "static"
TOKEN_FILE = ROOT / "ui" / "token"
TLS_DIR = ROOT / "ui" / "tls"
CERT_TOOL = ROOT / "bin" / "sandbox-ui-cert"
TMUX_CONF = ROOT / "ui" / "tmux.conf"
STATE_ROOT = ROOT / "state"             # per-workspace ssh_config / known_hosts (Claude-writable)
LIBEXEC = ROOT / "libexec"              # helpers Claude may run (read-only)
MONITORING_ENV = ROOT / "monitoring" / ".env"   # present once bin/monitoring has set it up
OTLP_PORT = 4318                        # Alloy's OTLP/HTTP receiver (Claude Code telemetry)
PROJECTS_BASE = Path(os.environ.get("AIO_PROJECTS", Path.home() / "projects"))
LISTEN_PORT = int(os.environ.get("AIO_UI_PORT", "9000"))
PROXY_PORT_OFFSET = 1000          # sandbox 8101 is served to browsers on 9101
CONTAINER_CA_MOUNT = "/usr/local/share/ca-certificates/agent-sandboxes-proxy.crt"   # in the container
MICROVM = ROOT / "bin" / "microvm"
VM_BASE = VM_ROOT / "base"                # bin/microvm-image's output; each new VM copies it
VM_DISK_FILES = ("vmlinuz", "initrd.img", "rootfs.img")
VM_DEFAULT_MEMORY = "2G"
VM_BROWSER_HEADROOM_MB = 3072             # with the browser container, the VM's default: this + the container's
BROWSER_MEMORY, BROWSER_CPUS = "2G", 2    # the AIO container's defaults (its /dev/shm is as big as its memory)
VM_VCPUS = 2
VM_DISK_GB, VM_BROWSER_DISK_GB = 16, 48   # sparse; the browser image alone is about 13 GB
VM_BRIDGE = "172.17.0.1"                  # Docker's default bridge in the guest: its relay listens there too
VM_GUEST_CA = "/usr/local/share/ca-certificates/aio-proxy.crt"   # where the guest installs the proxy CA
# Always allowed for microVM workspaces: the guest installs Claude Code itself
VM_EXTRA_HOSTS = ["claude.ai", "downloads.claude.ai"]
# A new microVM workspace's allowlist starts with these (editable): apt in the
# guest (the mirrors bin/microvm-image used) and Docker Hub
VM_DEFAULT_ALLOW = ["registry-1.docker.io", "auth.docker.io", "production.cloudflare.docker.com",
                    "production.cloudfront.docker.com"]
QEMU_DATA = ["/usr/share/qemu", "/usr/share/seabios", "/usr/lib/ipxe", "/usr/lib/x86_64-linux-gnu/qemu"]

TMUX = ["tmux", "-L", "agent-sandboxes", "-f", str(TMUX_CONF)]
# The Host page's shell: its own tmux server, apart from the locked-down one
# Claude's sessions (and workspace SSH keys) attach to. AIO_HOST_SHELL=0 turns it off.
HOST_SHELL = os.environ.get("AIO_HOST_SHELL", "1") != "0"
TMUX_HOST = ["tmux", "-L", "agent-sandboxes-host", "-f", str(ROOT / "ui" / "tmux-host.conf")]
HOST_SESSION = "host"
UI_SOURCES = [Path(__file__).resolve(), Path(__file__).resolve().with_name("common.py")]
ENV_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,63}$")
HEADER_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
# A plain value goes into env files (Docker's, systemd's, /etc/environment)
# as is, so nothing those would read differently: no quotes, $, \ or spaces
PLAIN_VALUE_RE = re.compile(r"^[A-Za-z0-9._~:/@+=,%^*!?&|<>()\[\]{}-]{1,2048}$")
# Variables the sandbox itself relies on; a pool entry mustn't replace them
RESERVED_ENV = ("PATH", "HOME", "USER", "SHELL", "TERM", "LANG", "PWD", "TMPDIR", "SSH_AUTH_SOCK",
                "GIT_SSH_COMMAND", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "PROXY_SERVER",
                "REQUESTS_CA_BUNDLE", "PIP_CERT", "SSL_CERT_FILE", "LD_PRELOAD", "LD_LIBRARY_PATH",
                "RUN_HOOK_INIT", "NODE_EXTRA_CA_CERTS", "NODE_USE_ENV_PROXY", "NODE_OPTIONS")
RESERVED_ENV_PREFIXES = ("NONO_", "POOL_", "AIO_", "OTEL_", "CLAUDE_", "ANTHROPIC_", "LD_")
QUERY_PARAM_RE = re.compile(r"^[A-Za-z0-9_.~\[\]-]{1,64}$")
PATH_PATTERN_RE = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*\{\}[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$")
MEM_RE = re.compile(r"^[1-9][0-9]{0,5}[MG]$")
DISK_RE = re.compile(r"^[1-9][0-9]{0,3}G$")
VM_DISK_MAX_GB = 4096
DIR_RE = re.compile(r"^/[A-Za-z0-9._/-]+$")
UI_HOSTNAMES = {"localhost", "127.0.0.1"}   # extended at startup with bind IPs / hostname
BIND: list[str] = []
TLS_CTX: ssl.SSLContext | None = None        # set at startup unless AIO_UI_TLS=0
SCHEME, WS_SCHEME = "http", "ws"
CA_FINGERPRINT = ""                          # SHA-256 of ui/tls/ca.crt, when TLS is on
WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_BODY = 1024 * 1024
MAX_UPLOAD = int(os.environ.get("AIO_UPLOAD_MAX_GB", "20")) << 30   # one file, in the Files tab

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


# When each Claude pane's screen last changed, for the sidebar. tmux's own
# window_activity also counts redraws: attaching the web terminal resizes the
# window, and Claude repaints. So: a hash of the visible text, counted as a change
# only at the same size as the last look (a resize just takes a new baseline).
TERM_SEEN: dict[str, dict] = {}         # workspace -> {"hash", "size", "changed", "settle"}
_term_poll = {"at": 0.0, "lock": None}


async def term_changes(live: dict[str, tuple[int, str]]) -> dict[str, int]:
    """live: workspace -> (tmux window_activity, "WxH") for running sessions.
    Returns workspace -> when its screen last changed (epoch seconds)."""
    lock = _term_poll["lock"] = _term_poll["lock"] or asyncio.Lock()
    async with lock:
        for n in set(TERM_SEEN) - set(live):
            del TERM_SEEN[n]
        if live and time.time() - _term_poll["at"] >= 2:       # several browsers poll: once per 2 s
            _term_poll["at"] = time.time()
            cmd = list(TMUX)
            for i, n in enumerate(sorted(live)):
                cmd += ([";"] if i else []) + ["display-message", "-p", f"\x1eAIO {n}",
                                               ";", "capture-pane", "-p", "-t", f"=cl-{n}:"]
            rc, out, _ = await run(*cmd, timeout=10)
            screens = {}
            for chunk in out.split("\x1eAIO ")[1:]:
                name, _, text = chunk.partition("\n")
                screens[name] = hashlib.sha256(text.encode()).hexdigest()
            now = int(time.time())
            for n, (act, size) in live.items():
                h, old = screens.get(n), TERM_SEEN.get(n)
                if h is None:
                    continue
                if old is None:                 # first look (or the UI restarted): tmux's time, as a start
                    TERM_SEEN[n] = {"hash": h, "size": size, "changed": act, "settle": 0}
                elif old["size"] != size:       # resized: Claude repaints, nothing new;
                    old.update(hash=h, size=size, settle=1)    # nor on the next look (a late repaint)
                elif old["settle"]:
                    old.update(hash=h, settle=old["settle"] - 1)
                elif old["hash"] != h:
                    old.update(hash=h, changed=now)
        return {n: TERM_SEEN[n]["changed"] for n in live if n in TERM_SEEN}


async def run(*cmd: str, timeout: float = 120, preexec_fn=None) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, preexec_fn=preexec_fn)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except TimeoutError:
        proc.kill()
        return 124, "", f"timed out after {timeout:.0f}s"
    return proc.returncode, out.decode(errors="replace"), err.decode(errors="replace")


def container(name: str) -> str:
    return f"aio-{name}"


def compose(ws: dict[str, str], *args: str) -> list[str]:
    """With the filtered-network override when the policy asks for it (its
    files are rewritten first, so they always match the policy)."""
    files = ["-f", str(COMPOSE_FILE)]
    if write_container_files(ws):
        files += ["-f", str(container_override_path(ws["WS_NAME"]))]
    limits = container_limits_path(ws["WS_NAME"])
    write_if_changed(limits, container_limits_text(load_policy(ws["WS_NAME"])))
    files += ["-f", str(limits)]
    return ["docker", "compose", "-p", container(ws["WS_NAME"]),
            "--env-file", str(WS_ROOT / f"{ws['WS_NAME']}.env"), *files, *args]


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
                 sandbox: str | None = None, share: bool = False):
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
        req = Request(head[:-4])
        if share:                          # the share listener: guest routes only, never the UI
            await handle_share(req, reader, writer)
        elif sandbox is not None:            # connection arrived on a sandbox port
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
    return auth.session(req.cookies().get(auth.COOKIE, "")) is not None


def peer_ip(w) -> str:
    peer = w.get_extra_info("peername")
    return str(peer[0]) if peer else ""


def ui_origin(req: Request) -> str:
    return f"{SCHEME}://{req.host}"


async def signed_in(w, req: Request, method: str, extra: dict | None = None):
    sid = auth.new_session(method, peer_ip(w), req.headers.get("user-agent", ""))
    print(f"sign-in: {auth.USER} with {method} from {peer_ip(w)}", flush=True)
    await respond(w, 200, json.dumps({"ok": True, **(extra or {})}), "application/json",
                  {"Set-Cookie": auth.cookie_header(sid, TLS_CTX is not None)})


async def auth_public(req: Request, reader, w):
    """The sign-in endpoints (before there's a session): password, passkey."""
    if req.method != "POST" or not same_origin(req) or req.headers.get("x-requested-with") != "sbui":
        return await respond(w, 403, "Forbidden\n")
    length = int(req.headers.get("content-length", "0") or 0)
    if length > 64 * 1024:
        return await respond(w, 400, "Body too large\n")
    try:
        body = json.loads(await reader.readexactly(length) if length else b"{}")
        if not isinstance(body, dict):
            raise ValueError
    except ValueError:
        return await send_json(w, {"error": "Bad request"}, 400)
    ip = peer_ip(w)
    if req.path == "/auth/password":
        if auth.limited(ip):
            return await send_json(w, {"error": "Too many failed sign-ins: wait a few minutes"}, 429)
        ok, err = await auth.check_password(str(body.get("username", "")), str(body.get("password", "")), ip)
        if err:
            print(f"sign-in: PAM couldn't check the password: {err}", flush=True)
            return await send_json(w, {"error": f"Password sign-in isn't working on this host: {err}"}, 500)
        if not ok:
            auth.failed(ip)
            print(f"sign-in: wrong username or password from {ip}", flush=True)
            return await send_json(w, {"error": "Wrong username or password"}, 401)
        return await signed_in(w, req, "password")
    if req.path == "/auth/passkey/options":
        try:
            return await send_json(w, auth.login_options(auth.rp_id_for(req.hostname)))
        except ValueError as e:
            return await send_json(w, {"error": str(e)}, 400)
    if req.path == "/auth/passkey/verify":
        if auth.limited(ip):
            return await send_json(w, {"error": "Too many failed sign-ins: wait a few minutes"}, 429)
        try:
            name = await asyncio.to_thread(auth.authenticate, body, ui_origin(req))
        except Exception as e:      # malformed input of any kind: a failed sign-in
            auth.failed(ip)
            print(f"sign-in: passkey refused from {ip}: {e}", flush=True)
            return await send_json(w, {"error": str(e) if isinstance(e, ValueError) else "Bad passkey response"}, 401)
        return await signed_in(w, req, "passkey", {"passkey": name})
    return await respond(w, 404, "Not found\n")


def same_origin(req: Request, scheme: str | None = None) -> bool:
    """Requests from pages on other origins (incl. sandbox subdomains,
    which are *same-site* with localhost) must never reach the API."""
    sfs = req.headers.get("sec-fetch-site")
    origin = req.headers.get("origin")
    if origin is not None and origin != f"{scheme or SCHEME}://{req.host}":
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
    if req.path == "/login" and "token" in req.query:      # break-glass: the token link
        if auth.TOKEN_LOGIN and hmac.compare_digest(req.query.get("token", ""), TOKEN):
            sid = auth.new_session("token", peer_ip(w), req.headers.get("user-agent", ""))
            print(f"sign-in: {auth.USER} with the login token from {peer_ip(w)}", flush=True)
            await respond(w, 303, headers={"Location": "/",
                                           "Set-Cookie": auth.cookie_header(sid, TLS_CTX is not None)})
        else:
            await respond(w, 401, "Bad token, or token sign-in is turned off (AIO_TOKEN_LOGIN=0).\n")
        return
    if req.path.startswith("/auth/"):
        return await auth_public(req, reader, w)
    if req.path == "/static/login.js" and req.method == "GET":
        return await respond(w, 200, (STATIC / "login.js").read_bytes(), "text/javascript; charset=utf-8",
                             {"Content-Security-Policy": ui_csp(req)})

    if not ui_authed(req):
        await respond(w, 401, (STATIC / "login.html").read_bytes(), "text/html; charset=utf-8",
                      {"Content-Security-Policy": ui_csp(req)})
        return

    if req.path == "/ws/host":
        if req.headers.get("upgrade", "").lower() != "websocket" or not same_origin(req):
            await respond(w, 403, "Forbidden\n")
            return
        if not HOST_SHELL:
            await respond(w, 403, "The host shell is turned off (AIO_HOST_SHELL=0)\n")
            return
        await host_terminal(req, reader, w)
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
        if req.method == "PUT" and (m := re.fullmatch(r"/api/workspaces/([^/]+)/upload", req.path)):
            return await upload(m[1], req, reader, w)      # streamed: no MAX_BODY
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
    if parts == ["host"] and m == "GET":
        return await send_json(w, await host_status())
    if parts and parts[0] == "auth":
        return await auth_api(req, parts[1:], w)
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
    if parts and parts[0] == "builds":
        return await builds_api(req, parts[1:], w)
    if parts and parts[0] == "shares":
        return await shares_api(req, parts[1:], w)

    if len(parts) < 2 or parts[0] != "workspaces":
        return await respond(w, 404, "Not found\n")
    ws = load_ws(parts[1])
    if not ws:
        return await send_json(w, {"error": "No such workspace"}, 404)
    name, action = ws["WS_NAME"], parts[2:]

    if action[:1] == ["builds"]:
        return await builds_ws_api(ws, req, action[1:], w)
    if action == ["shares"]:
        return await shares_api(req, [], w, ws)
    if is_microvm(ws) and (resp := await vm_api(ws, action, m, w)) is not None:
        return resp

    if action == [] and m == "DELETE":
        await run(*TMUX, "kill-session", "-t", f"cl-{name}")
        rc, out, err = await run(*compose(ws, "down", "--remove-orphans"))
        if rc != 0:
            return await send_json(w, {"error": err or out}, 500)
        (WS_ROOT / f"{name}.env").unlink()
        kill_agent(name)
        remove_access(lambda scope, _: scope == name)
        shares.revoke_workspace(name)
        builds.remove_workspace(name)
        for p in (policy_path(name), profile_path(name), aux_profile_path(name), container_override_path(name),
                  container_limits_path(name),
                  container_env_path(name), container_profile_path(name), *container_ca_files(name),
                  *(CONTAINER_PROXY_SECRETS / f"{name}{x}" for x in ("", ".ca.crt", ".ca.key"))):
            p.unlink(missing_ok=True)
        # `down` only removes the network of the current mode; the other one may be left over
        await run("docker", "network", "rm", f"{container(name)}_ws", f"{container(name)}_default")
        shutil.rmtree(STATE_ROOT / name, ignore_errors=True)
        shutil.rmtree(RUNTIME / name, ignore_errors=True)
        close_sandbox_listener(name)
        await sync_proxies()
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
    if action == ["tags"] and m == "PUT":
        try:
            tags = clean_tags(json.loads(req.body or b"{}").get("tags"))
        except (ValueError, json.JSONDecodeError) as e:
            return await send_json(w, {"error": str(e)}, 400)
        pol = load_policy(ws["WS_NAME"])
        pol["tags"] = tags
        save_policy(ws["WS_NAME"], pol)
        return await send_json(w, {"tags": tags})

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


async def vm_api(ws: dict[str, str], action: list[str], m: str, w):
    """The workspace API calls that differ for a microVM (None: as for a sandbox)."""
    name = ws["WS_NAME"]
    if action == [] and m == "DELETE":
        await run(*TMUX, "kill-session", "-t", f"cl-{name}")
        rc, out, err = await run(str(MICROVM), "stop", name, timeout=90)
        if rc != 0:
            return await send_json(w, {"error": err or out}, 500)
        (WS_ROOT / f"{name}.env").unlink()
        kill_agent(name)
        remove_access(lambda scope, _: scope == name)
        shares.revoke_workspace(name)
        builds.remove_workspace(name)
        for p in (policy_path(name), profile_path(name), aux_profile_path(name), container_profile_path(name),
                  *(CONTAINER_PROXY_SECRETS / f"{name}{x}" for x in ("", ".ca.crt", ".ca.key"))):
            p.unlink(missing_ok=True)
        shutil.rmtree(vm_dir(name), ignore_errors=True)      # the VM's disk: its Claude login, Docker images
        shutil.rmtree(STATE_ROOT / name, ignore_errors=True)
        shutil.rmtree(RUNTIME / name, ignore_errors=True)
        close_sandbox_listener(name)
        await sync_proxies()
        return await send_json(w, {"ok": True, "kept": ws["WS_DIR"]})
    if action == ["container", "start"] and m == "POST":
        await sync_proxies(name)
        rc, out, err = await run(str(MICROVM), "start", name, timeout=300)
        return await send_json(w, {"ok": rc == 0, "log": err or out}, 200 if rc == 0 else 500)
    if action == ["container", "stop"] and m == "POST":
        await run(*TMUX, "kill-session", "-t", f"cl-{name}")
        rc, out, err = await run(str(MICROVM), "stop", name, timeout=90)
        return await send_json(w, {"ok": rc == 0, "log": err or out}, 200 if rc == 0 else 500)
    if action == ["logs"] and m == "GET":
        try:
            with open(vm_dir(name) / "console.log", "rb") as f:
                f.seek(0, os.SEEK_END)
                f.seek(max(0, f.tell() - 64 * 1024))
                log = f.read().decode(errors="replace")
        except OSError:
            log = "(the VM hasn't started yet)"
        return await send_json(w, {"log": re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", log)})
    if action in (["files"], ["download"], ["sandbox-link"]) and not vm_browser(ws):
        return await send_json(w, {"error": "This microVM has no browser container (Access tab)"}, 404)
    return None


async def status_all() -> list[dict]:
    _, ps, _ = await run("docker", "ps", "-a", "--filter", "name=^aio-",
                         "--format", "{{.Names}}\t{{.State}}\t{{.Status}}")
    states = {}
    for line in ps.splitlines():
        n, state, detail = (line.split("\t") + ["", ""])[:3]
        states[n] = (state, detail)
    # @aio_bell: when the pane last rang the bell (tmux.conf's alert-bell hook),
    # which Claude does when it finishes or needs you (claude-in's hooks)
    _, panes, _ = await run(*TMUX, "list-panes", "-a", "-F",
                            "#{session_name}\t#{pane_dead}\t#{window_activity}\t#{@aio_bell}\t#{pane_title}"
                            "\t#{window_width}x#{window_height}")
    claude, seen, live = {}, {}, {}
    for line in panes.splitlines():
        s, dead, act, bell, title, size = (line.split("\t", 5) + [""] * 5)[:6]
        if s.startswith("cl-"):
            claude[s[3:]] = "exited" if dead == "1" else "running"
            seen[s[3:]] = {"bell": int(bell) if bell.isdigit() else 0, "title": title[:120]}
            if dead != "1":
                live[s[3:]] = (int(act) if act.isdigit() else 0, size)
    changed = await term_changes(live)
    now = int(time.time())
    for n, t in seen.items():
        c = changed.get(n, 0)
        t.update(activity=c, idle=max(0, now - c) if c else None)
    vms = await vm_states()
    guests = shares.connected_by_workspace()
    out = []
    for ws in all_ws():
        n = ws.get("WS_NAME", "")
        vm = is_microvm(ws)
        if vm:
            state, detail = vm_container_state(n, vms.get(n)), vms.get(n, "not started")
        else:
            state, detail = states.get(container(n), ("absent", ""))
        pol = load_policy(n)
        out.append({"name": n, "dir": ws.get("WS_DIR"), "port": ws.get("WS_PORT"),
                    "kind": "microvm" if vm else "sandbox", "browser": not vm or pol["vm_browser"],
                    "container": state, "containerDetail": detail,
                    "claude": claude.get(n, "stopped"),
                    "term": seen.get(n), "tags": pol["tags"], "guests": guests.get(n, []),
                    "sshKeys": len(pol["ssh_keys"]), "tokens": len(pol["tokens"]),
                    "network": pol["network"]["mode"], "builds": pol["builds"],
                    "policyPending": not vm and claude.get(n) == "running" and policy_pending(ws)})
    return out


class WsError(Exception):
    def __init__(self, msg: str, status: int = 400):
        super().__init__(msg)
        self.status = status


def check_new_ws(name: str, raw_dir: str | None, kind: str = "sandbox") -> str:
    """Validate a new workspace's name and folder; returns the real folder path."""
    if kind not in ("sandbox", "microvm"):
        raise WsError("Type: sandbox or microvm")
    if kind == "microvm" and (missing := vm_problems()):
        raise WsError("MicroVM workspaces can't run here yet: " + "; ".join(missing))
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


BUILDS_MCP_ENTRY = {"type": "http", "url": "${AIO_BUILD_BASE_URL}/mcp", "headers": {"X-AIO-Build": "${AIO_BUILD_KEY}"}}


def sync_builds_mcp(d: str, on: bool):
    """The aio-builds server in the project's .mcp.json, while Apple builds are on."""
    mcp = Path(d) / ".mcp.json"
    if mcp.is_symlink():
        return
    try:
        cfg = json.loads(mcp.read_text()) if mcp.exists() else {}
    except (OSError, ValueError):
        return                          # not ours to fix; ensure_mcp_json says so
    servers = cfg.setdefault("mcpServers", {})
    if on and servers.get(builds.MCP_NAME) != BUILDS_MCP_ENTRY:
        servers[builds.MCP_NAME] = BUILDS_MCP_ENTRY
    elif not on and servers.get(builds.MCP_NAME) == BUILDS_MCP_ENTRY:
        del servers[builds.MCP_NAME]
    else:
        return
    mcp.write_text(json.dumps(cfg, indent=2) + "\n")
    os.chown(mcp, -1, USER_GID)


def ensure_mcp_json(d: str) -> list[str]:
    """The project's .mcp.json links Claude to its AIO sandbox (${AIO_PORT} / ${AIO_KEY})."""
    notes = []
    mcp = Path(d) / ".mcp.json"
    if mcp.is_symlink():          # e.g. from an imported project: never write through it
        mcp.unlink()
        notes.append("Replaced a symlinked .mcp.json")
    template = json.loads(MCP_TEMPLATE.read_text())
    if not mcp.exists():
        mcp.write_text(json.dumps(template, indent=2) + "\n")
        os.chown(mcp, -1, USER_GID)
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
    return notes


async def provision_ws(name: str, d: str, kind: str = "sandbox") -> dict:
    """Create (or adopt) the folder, link it to a new sandbox and start that."""
    if kind == "microvm":
        return await provision_vm(name, d)
    used = {int(o["WS_PORT"]) for o in all_ws()}
    port = next((p for p in SANDBOX_PORTS if p not in used and port_free(p)), None)
    if port is None:
        raise WsError("No free sandbox port", 500)

    created_dir = not os.path.exists(d)
    os.makedirs(d, exist_ok=True)
    notes = ensure_mcp_json(d)
    mcp = Path(d) / ".mcp.json"

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
    notes += await sync_proxies(name)
    return {"ok": True, "name": name, "dir": d, "port": port, "notes": notes}


async def provision_vm(name: str, d: str) -> dict:
    """A microVM workspace: the folder (shared into the VM at /project), its
    proxy, and the VM, which copies the image the first time."""
    used = {int(o["WS_PORT"]) for o in all_ws()}
    port = next((p for p in SANDBOX_PORTS if p not in used), None)
    if port is None:
        raise WsError("No free workspace slot", 500)
    created_dir = not os.path.exists(d)
    os.makedirs(d, exist_ok=True)
    env_path = WS_ROOT / f"{name}.env"
    fd = os.open(env_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(f"WS_NAME={name}\nWS_DIR={d}\nWS_PORT={port}\nWS_KEY={secrets.token_hex(32)}\nWS_KIND=microvm\n")
    for p in [env_path] + ([d] if created_dir else []):
        os.chown(p, -1, USER_GID)
    ws = read_env(env_path)
    pol = load_policy(name)
    pol["network"]["allow"] = list(dict.fromkeys(vm_apt_hosts() + VM_DEFAULT_ALLOW))
    save_policy(name, validate_policy(pol))
    notes = await sync_proxies(name)
    await refresh_cert()          # <name>.localhost, for the browser container's views
    if err := await open_sandbox_listener(ws):
        notes.append(err)
    rc, out, err = await run(str(MICROVM), "start", name, timeout=300)
    if rc != 0:
        notes.append(f"The VM didn't start: {(err or out).strip()[-500:]}")
    return {"ok": True, "name": name, "dir": d, "port": port, "notes": notes}


async def create_ws(req: Request, w):
    try:
        body = json.loads(req.body or b"{}")
    except json.JSONDecodeError:
        return await send_json(w, {"error": "Invalid JSON"}, 400)
    try:
        name = str(body.get("name", "")).strip()
        kind = str(body.get("kind") or "sandbox")
        d = check_new_ws(name, body.get("dir"), kind)
        return await send_json(w, await provision_ws(name, d, kind), 201)
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
    # An API key (.p8) never goes in: nono's proxy asks bin/asc-token for a
    # short-lived JWT signed with it (a cmd:// credential). Uploading a build's
    # bytes goes to pre-signed URLs on Apple's storage hosts (allow_hosts).
    "appstoreconnect": {"label": "App Store Connect API", "upstream": "https://api.appstoreconnect.apple.com",
                        "inject_header": "Authorization", "credential_format": "Bearer {}", "env_var": "ASC_TOKEN",
                        "allow_hosts": ["*.blobstore.apple.com"]},
}
# What a pool token's route may carry over to nono's custom_credentials
ROUTE_EXTRAS = ("endpoint_rules", "inject_mode", "query_param_name", "path_pattern", "path_replacement")
# Where nono's proxy puts a custom token: not every credential is an
# Authorization header (client IDs in a query parameter, bot tokens in the
# path, client_id:secret as Basic auth). There's no body substitution.
INJECT_MODES = {"header": "a header", "query_param": "a query parameter", "url_path": "the URL path",
                "basic_auth": "HTTP Basic auth"}
ASC_CACHE_TTL = 15 * 60                       # asc-token's JWTs last 19 minutes
ASC_KEY_ID_RE = re.compile(r"^[A-Z0-9]{8,12}$")
ASC_ISSUER_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
# App Store Connect presets: endpoint_rules (default-deny) for nono's proxy
ASC_PRESETS = {
    "full": {"label": "Full API (whatever the key's role allows)", "rules": None},
    "testflight": {"label": "TestFlight: builds, uploads, beta groups and testers", "rules": [
        *(("GET", p) for p in (
            "/v1/apps", "/v1/apps/*", "/v1/apps/*/builds", "/v1/apps/*/buildUploads", "/v1/apps/*/betaGroups",
            "/v1/apps/*/preReleaseVersions", "/v1/builds", "/v1/builds/*", "/v1/builds/*/betaGroups",
            "/v1/builds/*/buildBetaDetail", "/v1/builds/*/betaBuildLocalizations", "/v1/buildUploads/*",
            "/v1/buildUploads/*/buildUploadFiles", "/v1/buildUploadFiles/*", "/v1/betaGroups", "/v1/betaGroups/*",
            "/v1/betaGroups/*/builds", "/v1/betaGroups/*/betaTesters", "/v1/betaTesters", "/v1/betaTesters/*",
            "/v1/buildBetaDetails/*", "/v1/betaBuildLocalizations", "/v1/betaBuildLocalizations/*",
            "/v1/preReleaseVersions", "/v1/preReleaseVersions/*")),
        *(("POST", p) for p in (
            "/v1/buildUploads", "/v1/buildUploadFiles", "/v1/betaGroups", "/v1/betaTesters",
            "/v1/betaGroups/*/relationships/builds", "/v1/betaGroups/*/relationships/betaTesters",
            "/v1/builds/*/relationships/betaGroups", "/v1/betaBuildLocalizations",
            "/v1/betaAppReviewSubmissions", "/v1/buildBetaNotifications")),
        *(("PATCH", p) for p in (
            "/v1/buildUploads/*", "/v1/buildUploadFiles/*", "/v1/builds/*", "/v1/buildBetaDetails/*",
            "/v1/betaBuildLocalizations/*", "/v1/betaGroups/*")),
        ("DELETE", "/v1/betaGroups/*/relationships/betaTesters")]},
}


def check_asc_key(pem: str) -> str:
    """The .p8: an EC P-256 private key openssl can sign with."""
    pem = pem.strip().replace("\r\n", "\n") + "\n"
    if not pem.startswith("-----BEGIN PRIVATE KEY-----") or len(pem) > 4096:
        raise ValueError("The .p8 file's contents: -----BEGIN PRIVATE KEY----- …")
    p = subprocess.run(["openssl", "pkey", "-noout", "-text"], input=pem.encode(), capture_output=True, timeout=15)
    if p.returncode != 0 or b"prime256v1" not in p.stdout and b"P-256" not in p.stdout:
        raise ValueError("That isn't an App Store Connect key (.p8: an EC P-256 private key)")
    return pem


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


def profile_path(name: str) -> Path:
    return WS_ROOT / f"{name}.profile.json"


def aux_profile_path(name: str) -> Path:
    return WS_ROOT / f"{name}.aux-profile.json"


def agent_sock(name: str) -> Path:
    return RUNTIME / name / "agent.sock"


def save_policy(name: str, pol: dict):
    private_write(policy_path(name), json.dumps(pol, indent=2, sort_keys=True) + "\n")


def clean_tags(v) -> list[str]:
    """A workspace's tags: lowercase words, the first one its sidebar group."""
    if not isinstance(v, list) or len(v) > MAX_TAGS:
        raise ValueError(f"Tags: at most {MAX_TAGS}")
    out = []
    for t in v:
        t = str(t).strip().lower().lstrip("#")
        if not TAG_RE.match(t):
            raise ValueError(f"Tag {t!r}: letters, digits and dashes, up to 24")
        if t not in out:
            out.append(t)
    return out


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


def format_net_entry(host: str, lo: int, hi: int) -> str:
    if not lo:
        return host
    return f"{f'[{host}]' if ':' in host else host}:{lo}" + (f"-{hi}" if hi != lo else "")


def clean_net_list(v, what: str, ports_ok: bool) -> list[str]:
    out = [format_net_entry(*parse_net_entry(x, what, ports_ok))
           for x in clean_list(v, re.compile(r"^\S+$"), what)]
    return list(dict.fromkeys(out))


def reserved_ports() -> list[tuple[int, int, str]]:
    """Ports this app listens on, which a workspace mustn't take over: nono lets
    a listen_port bind every address, so it could stand in for them."""
    lo, hi = SANDBOX_PORTS.start, SANDBOX_PORTS.stop - 1
    return [(lo, hi, "the sandbox ports"),
            (lo + PROXY_PORT_OFFSET, hi + PROXY_PORT_OFFSET, "the UI's sandbox views"),
            (lo + EGRESS_PORT_OFFSET, hi + EGRESS_PORT_OFFSET, "the port filters"),
            (lo + VM_PROXY_OFFSET, hi + VM_PROXY_OFFSET, "the microVMs' proxies"),
            (HTTP_BRIDGE[1], HTTP_BRIDGE[1], "the API bridge"),
            (CONTAINER_PROXY_PORT, CONTAINER_PROXY_PORT, "the container proxies"),
            (OTLP_PORT, OTLP_PORT, "Alloy's telemetry receiver")]


def port_range(x: str) -> tuple[int, int]:
    lo, _, hi = x.partition("-")
    return int(lo), int(hi or lo)


def clean_listen(v) -> list[str]:
    """Ports the workspace's own servers may listen on: '8000' or '8000-8010'."""
    out, total = [], 0
    for x in clean_list(v, re.compile(r"^[0-9]{1,5}(-[0-9]{1,5})?$"), "Listen ports", limit=20):
        lo, hi = port_range(x)
        if not 1024 <= lo <= hi <= 65535:
            raise ValueError(f"Listen ports: {x!r} isn't a port 1024–65535 or a range low-high of them")
        for a, b, what in reserved_ports():
            if lo <= b and a <= hi:
                raise ValueError(f"Listen ports: {x} overlaps {a if a == b else f'{a}–{b}'}, {what}")
        total += hi - lo + 1
        out.append(f"{lo}" if lo == hi else f"{lo}-{hi}")
    if total > 100:
        raise ValueError("Listen ports: at most 100 in all")
    return out


def listen_ports(pol: dict) -> list[int]:
    return sorted({p for x in pol["network"].get("listen", []) for p in range(port_range(x)[0], port_range(x)[1] + 1)})


def mem_mb(mem: str) -> int:
    return int(mem[:-1]) * (1024 if mem.endswith("G") else 1)


def host_memory_mb() -> int:
    try:
        m = re.search(r"^MemTotal:\s+(\d+) kB", Path("/proc/meminfo").read_text(), re.M)
        return int(m[1]) // 1024 if m else 1 << 30
    except OSError:
        return 1 << 30


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
    if net.get("container", "open") not in ("open", "filtered"):
        raise ValueError("Container network: open or filtered")
    pol["network"] = {"mode": net.get("mode", "claude-code"), "container": net.get("container", "open"),
                      "allow": clean_net_list(net.get("allow", []), "Allowed hosts", ports_ok=True),
                      "deny": clean_net_list(net.get("deny", []), "Blocked hosts", ports_ok=False),
                      "listen": clean_listen(net.get("listen", []))}
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
    if mem and mem_mb(mem) > (host := host_memory_mb()):
        raise ValueError(f"Memory: this host has {host // 1024}G")
    ncpu = os.cpu_count() or 1
    try:
        cpus = int(lim.get("cpus", 0) or 0)
    except (TypeError, ValueError):
        raise ValueError("CPUs: a whole number")
    if not 0 <= cpus <= ncpu:
        raise ValueError(f"CPUs: 0 (default) to {ncpu}, this host's count")
    disk = str(lim.get("disk", "") or "").strip().upper()
    if disk and not disk.endswith("G"):
        disk += "G"
    if disk and (not DISK_RE.match(disk) or not VM_DISK_GB <= int(disk[:-1]) <= VM_DISK_MAX_GB):
        raise ValueError(f"Disk: {VM_DISK_GB}G to {VM_DISK_MAX_GB}G, e.g. 64G")
    bmem = str(lim.get("browser_memory", "") or "").strip().upper()
    if bmem and (not MEM_RE.match(bmem) or mem_mb(bmem) < 1024):
        raise ValueError("Browser container memory: at least 1G, with M or G, e.g. 4G")
    if bmem and mem_mb(bmem) > host_memory_mb():
        raise ValueError(f"Browser container memory: this host has {host_memory_mb() // 1024}G")
    try:
        bcpus = int(lim.get("browser_cpus", 0) or 0)
    except (TypeError, ValueError):
        raise ValueError("Browser container CPUs: a whole number")
    if not 0 <= bcpus <= ncpu:
        raise ValueError(f"Browser container CPUs: 0 (default) to {ncpu}, this host's count")
    pol["limits"] = {"memory": mem, "pids": pids, "cpus": cpus, "disk": disk,
                     "browser_memory": bmem, "browser_cpus": bcpus}
    pol["claude_md"] = body.get("claude_md") is True
    pol["vm_browser"] = body.get("vm_browser") is True
    pol["builds"] = body.get("builds") is True
    pol["signing"] = clean_list(body.get("signing", []), ITEM_RE, "Signing identities")
    for i in pol["signing"]:
        if not applesign.meta(i):
            raise ValueError(f"No signing identity '{i}'")
    return pol


# ---- pool


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
                           "sent_as": sent_as(meta),
                           "workspaces": [n for n, pol in policies.items() if tid in pol["tokens"]]})
    signing = [{**{k: v for k, v in m.items() if k != "profiles"},
                "profiles": [{k: v for k, v in x.items() if k not in ("entitlements", "certs")} for x in m["profiles"]],
                "workspaces": [n for n, pol in policies.items() if m["id"] in pol["signing"]]}
               for m in applesign.identities()]
    return {"ssh": keys, "tokens": tokens, "signing": signing, "workspaces": sorted(policies),
            "services": {k: {"label": v["label"], "env_var": v["env_var"], "upstream": v["upstream"]}
                         for k, v in TOKEN_SERVICES.items()},
            "ascPresets": {k: v["label"] for k, v in ASC_PRESETS.items()},
            "netModes": NET_MODES}


def sent_as(meta: dict) -> str:
    if meta["service"] == "plain":
        return "plain value, visible to the agent"
    mode = meta.get("inject_mode", "header")
    if mode == "query_param":
        return f"?{meta['query_param_name']}="
    if mode == "url_path":
        return f"path {meta['path_pattern']}"
    if mode == "basic_auth":
        return "Basic auth"
    return f"{meta['inject_header']}: {meta['credential_format']}"


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
    service = str(body.get("service", ""))
    if service == "appstoreconnect":
        a = body.get("asc", {}) or {}
        key_id, issuer = str(a.get("key_id", "")).strip(), str(a.get("issuer_id", "")).strip().lower()
        preset = str(a.get("preset") or "testflight")
        if not ASC_KEY_ID_RE.match(key_id):
            raise ValueError("Key ID: the 10 letters and digits in the key's name (AuthKey_<ID>.p8)")
        if not ASC_ISSUER_RE.match(issuer):
            raise ValueError("Issuer ID: the UUID above the keys list (Users and Access → Integrations)")
        if preset not in ASC_PRESETS:
            raise ValueError("Unknown access preset")
        secret = check_asc_key(secret)
        meta = {"service": service, **TOKEN_SERVICES[service], "key_id": key_id, "issuer_id": issuer,
                "preset": preset}
        meta["label"] = f"App Store Connect, {ASC_PRESETS[preset]['label'].split(':')[0]} (key {key_id})"
        if rules := ASC_PRESETS[preset]["rules"]:
            meta["endpoint_rules"] = [{"method": m, "path": p} for m, p in rules]
        private_write(TOKEN_POOL / tid, secret)
        private_write(TOKEN_POOL / f"{tid}.json", json.dumps(meta, indent=2) + "\n")
        return {"id": tid, **meta}
    if not secret or len(secret) > 8192 or any(c in secret for c in "\r\n\0"):
        raise ValueError("Paste the token (single line)")
    c = body.get("custom", {}) or {}
    if service == "plain":
        # Not secret from the agent: set as the real value (a client ID, an
        # account or project ID, a public key), but kept, listed and assigned here
        pl = body.get("plain", {}) or {}
        env = check_env_name(pl.get("env_var", ""))
        note = " ".join(str(pl.get("note", "")).split())[:80]
        if not PLAIN_VALUE_RE.match(secret):
            raise ValueError("Value: up to 2048 characters, no spaces, quotes, $ or \\")
        meta = {"service": "plain", "label": note or "Plain value", "upstream": "", "env_var": env}
        private_write(TOKEN_POOL / tid, secret)
        private_write(TOKEN_POOL / f"{tid}.json", json.dumps(meta, indent=2) + "\n")
        return {"id": tid, **meta}
    if service in TOKEN_SERVICES:
        meta = {"service": service, **TOKEN_SERVICES[service]}
    elif service == "custom":
        up = urllib.parse.urlsplit(str(c.get("upstream", "")).strip())
        try:
            if up.scheme not in ("https", "http") or not up.hostname or up.query or up.fragment \
                    or up.username or up.password is not None:
                raise ValueError
            parse_net_entry(up.hostname, "", False)     # a domain or a (non-local) IP address
            up.port
        except ValueError:
            raise ValueError("Upstream: an https:// or http:// URL (host, optional port and path)") from None
        env = check_env_name(c.get("env_var", ""))
        meta = {"service": "custom", "label": up.hostname,
                "upstream": urllib.parse.urlunsplit((up.scheme, up.netloc.lower(), up.path.rstrip("/"), "", "")),
                "env_var": env, **custom_injection(c, secret)}
    else:
        raise ValueError("Unknown service")
    private_write(TOKEN_POOL / tid, secret)
    private_write(TOKEN_POOL / f"{tid}.json", json.dumps(meta, indent=2) + "\n")
    return {"id": tid, **meta}


def check_env_name(v) -> str:
    env = str(v).strip().upper()
    if not ENV_RE.match(env):
        raise ValueError("Environment variable: capitals, digits and _, e.g. ACME_CLIENT_ID")
    if env in RESERVED_ENV or env.startswith(RESERVED_ENV_PREFIXES):
        raise ValueError(f"Environment variable: {env} is one the sandbox sets itself; pick another name")
    return env


def plain_value(tid: str) -> str | None:
    """A plain pool value, read for the env it's set in (None if it's gone or not plain)."""
    meta = token_meta(tid)
    if not meta or meta.get("service") != "plain":
        return None
    try:
        v = (TOKEN_POOL / tid).read_text().strip()
    except OSError:
        return None
    return v if PLAIN_VALUE_RE.match(v) else None


def custom_injection(c: dict, secret: str) -> dict:
    """Where nono's proxy swaps the placeholder for the real value."""
    mode = str(c.get("mode") or "header")
    if mode not in INJECT_MODES:
        raise ValueError("Sent as: a header, a query parameter, the URL path or Basic auth")
    if mode == "header":
        header = str(c.get("header") or "Authorization").strip()
        fmt = str(c.get("format") or "Bearer {}").strip()
        if not HEADER_RE.match(header) or header.lower() in ("host", "content-length", "transfer-encoding",
                                                             "connection", "proxy-authorization"):
            raise ValueError("Header: letters, digits and dashes (not Host, Connection, …)")
        if fmt.count("{}") != 1 or len(fmt) > 100 or any(ch in fmt for ch in "\r\n"):
            raise ValueError("Format must contain {} exactly once, e.g. 'Bearer {}', or just {}")
        return {"inject_header": header, "credential_format": fmt}
    out = {"inject_mode": mode, "inject_header": "Authorization", "credential_format": "{}"}
    if mode == "query_param":
        name = str(c.get("param") or "").strip()
        if not QUERY_PARAM_RE.match(name):
            raise ValueError("Query parameter: its name, e.g. client_id or key")
        out["query_param_name"] = name
    elif mode == "url_path":
        pat = str(c.get("path") or "").strip()
        if pat.count("{}") != 1 or len(pat) > 100 or not PATH_PATTERN_RE.match(pat):
            raise ValueError("Path pattern: starts with / and has {} once where the value goes, e.g. /bot{}/")
        out.update(path_pattern=pat, path_replacement=pat)
    elif ":" not in secret:
        raise ValueError("Basic auth: the value is username:password (e.g. client_id:client_secret)")
    return out


POLICY_KEY = {"ssh": "ssh_keys", "token": "tokens", "signing": "signing"}


async def remove_pool_item(kind: str, iid: str):
    key = POLICY_KEY[kind]
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
    elif kind == "signing":
        applesign.remove_identity(iid)
    else:
        for p in (TOKEN_POOL / iid, TOKEN_POOL / f"{iid}.json"):
            p.unlink(missing_ok=True)


async def assign(kind: str, iid: str, workspaces: list[str]):
    key = POLICY_KEY[kind]
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
    if is_microvm(ws) and mode != "open":
        allow += [(h, 0, 0) for h in VM_EXTRA_HOSTS]
    if mode != "open":
        # Hosts a token's service needs without its credential (App Store
        # Connect's pre-signed upload URLs)
        allow += [(h, 0, 0) for tid in pol["tokens"] if (meta := token_meta(tid))
                  for h in meta.get("allow_hosts", [])]
    if allow:
        net["allow_domain"] = list(dict.fromkeys(h for h, _, _ in allow))
        if any(lo for _, lo, _ in allow):
            # nono's proxy matches hosts only; it hands what it allowed to our
            # port filter, which enforces the host:port entries
            net["upstream_proxy"] = f"127.0.0.1:{egress_port(ws)}"
    if pol["network"]["deny"]:
        net["deny_domain"] = pol["network"]["deny"]
    if ports := listen_ports(pol):
        # its own servers (on any address: nono can't limit that), and connecting to them
        net["listen_port"] = ports
        net["open_port"] += ports
    creds, capture, plain = {}, {}, {}
    for tid in pol["tokens"]:
        meta = token_meta(tid)
        if meta["service"] == "plain":
            if (v := plain_value(tid)) is not None:
                plain[meta["env_var"]] = v
            continue
        route = "pool_" + tid.replace("-", "_")
        creds[route] = {
            "upstream": bridge_upstream(tid, meta["upstream"]), "credential_key": f"file://{TOKEN_POOL / tid}",
            "inject_header": meta["inject_header"], "credential_format": meta["credential_format"],
            "env_var": meta["env_var"]}
        creds[route].update({k: meta[k] for k in ROUTE_EXTRAS if meta.get(k)})
        if meta["service"] == "appstoreconnect":
            # A JWT signed with the key, made by nono outside the sandbox
            creds[route]["credential_key"] = f"cmd://{route}"
            capture[route] = {"command": ["/usr/bin/python3", "-I", str(ASC_TOKEN), tid],
                              "timeout_secs": 20, "cache_ttl_secs": ASC_CACHE_TTL}
    if pol["builds"]:
        # The aio-builds MCP server: the bridge (/~build) knows the workspace by this key
        creds[builds.ROUTE] = {"upstream": f"http://{HTTP_BRIDGE[0]}:{HTTP_BRIDGE[1]}/~build",
                               "credential_key": f"file://{builds.ensure_mcp_key(name)}",
                               "inject_header": "X-AIO-Build", "credential_format": "{}",
                               "env_var": "AIO_BUILD_KEY"}
    if creds:
        net["credentials"] = sorted(creds)
        net["custom_credentials"] = creds
    env = {**plain, "SSH_AUTH_SOCK": str(agent_sock(name)),
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
    prof = {
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
    if capture:
        prof["credential_capture"] = capture
    return prof


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
    if not aux:
        sync_builds_mcp(ws["WS_DIR"], load_policy(name)["builds"])
    prompt = ""
    if not aux:
        try:
            sync_claude_md(ws)
        except (OSError, ValueError) as e:
            print(f"CLAUDE.md not updated: {e}", file=sys.stderr)
        prompt = session_prompt(ws, load_policy(name))
    return {"profile": str(target), "prompt": prompt, **load_policy(name)["limits"]}


# ---- sandbox notes for Claude: CLAUDE.md block (opt-in per workspace) and,
# always when it has tokens, an --append-system-prompt naming their base URLs

MD_BEGIN = "<!-- agent-sandboxes:begin (managed: edit under Settings in the web UI; changes here are replaced) -->"
MD_END = "<!-- agent-sandboxes:end -->"
MD_TAG = "This is running agent-sandboxes from github.com/metahertz/agent-sandboxes"   # always first in the block


def claude_md_template() -> tuple[str, bool]:
    try:
        return CLAUDE_MD_CUSTOM.read_text(), True
    except OSError:
        return CLAUDE_MD_DEFAULT.read_text(), False


def base_url_var(tid: str) -> str:
    """The variable nono sets for the token's route (service pool_<id>)."""
    return f"POOL_{tid.replace('-', '_').upper()}_BASE_URL"


def token_lines(pol: dict) -> str:
    out = []
    for tid in pol["tokens"]:
        if not (meta := token_meta(tid)):
            continue
        env, var = meta["env_var"], base_url_var(tid)
        if meta["service"] == "plain":
            out.append(f"- `${env}` ({tid}{', ' + meta['label'] if meta['label'] != 'Plain value' else ''}): "
                       "a plain value, the real thing rather than a placeholder, so it works anywhere (request "
                       "bodies, config files, URLs). Prefer reading it from the variable to hard-coding it.")
            continue
        if meta["service"] == "appstoreconnect":
            scope = ("Only these calls are let through: TestFlight builds, build uploads, beta groups, testers "
                     "and beta localizations; anything else gets 403." if meta.get("endpoint_rules")
                     else "Whatever the key's role allows.")
            out.append(f"- App Store Connect API ({tid}): call `{meta['upstream']}` (or `${var}`) plus the path, "
                       f"with the header `Authorization: Bearer ${env}`. `${env}` is a placeholder: the proxy "
                       "swaps in a fresh signed JWT, so don't make your own and never ask for the .p8 key. "
                       f"{scope} Uploading a build's bytes goes to the pre-signed URLs the API returns "
                       "(*.blobstore.apple.com, allowed), without the Authorization header.")
            continue
        if meta["upstream"].startswith("http://"):
            how = (f"call **`${var}`** plus the path, never `{meta['upstream']}` itself "
                   "(plain HTTP: the real value is only added on that route)")
        else:
            how = f"call `{meta['upstream']}` or `${var}`, plus the path"
        out.append(f"- `${env}` ({tid}) for {meta['upstream']}: {how}, {placement(meta)}.")
    return "\n".join(out) or "- No API tokens are assigned to this workspace."


def placement(meta: dict) -> str:
    """Where the agent puts a token's placeholder for the proxy to swap it."""
    env = "$" + meta["env_var"]
    mode = meta.get("inject_mode", "header")
    if mode == "query_param":
        return (f"with the query parameter `{meta['query_param_name']}={env}` (the proxy swaps the placeholder "
                "there only: not in a request body, a file or a browser address)")
    if mode == "url_path":
        return f"with `{meta['path_pattern'].replace('{}', env)}` in the path"
    if mode == "basic_auth":
        return f"with HTTP Basic auth, any username and the password `{env}` (e.g. `curl -u x:{env}`)"
    return f"with the header `{meta['inject_header']}: {meta['credential_format'].replace('{}', env)}`"


def builds_lines(pol: dict) -> str:
    if not pol["builds"]:
        return ""
    return ("\n- Apple builds: the aio-builds MCP server (apple_build, build_status, build_log, build_result, "
            "cancel_build) builds, tests or runs this repo's Xcode project on a Mac build worker, in a fresh "
            "macOS VM per job. It builds a commit (HEAD by default): commit first, uncommitted changes aren't "
            "sent. You can't reach the Mac or its git host any other way. get_artifact copies a build's "
            "artifact into .aio-builds/ in the project." + signing_lines(pol))


def signing_lines(pol: dict) -> str:
    ids = [m for i in pol["signing"] if (m := applesign.meta(i))]
    if not ids:
        return ""
    return ("\n- Apple signing: these identities (certificate + private key + provisioning profiles) are on the "
            "host; you never get the key files, only signing done for you. export_build signs an archive build "
            "on the Mac with Xcode (and can upload it to TestFlight); sign_ipa re-signs an .ipa or .app on the "
            "host with rcodesign. "
            + " ".join(applesign.summary(m) for m in ids))


def network_summary(pol: dict) -> str:
    net = pol["network"]
    if net["mode"] == "open":
        text = "the whole internet"
    else:
        text = NET_MODES[net["mode"]].removesuffix(" (default)")
        if net["allow"]:
            text += ", plus " + ", ".join(f"`{x}`" for x in net["allow"])
    if net["deny"]:
        text += "; blocked: " + ", ".join(f"`{x}`" for x in net["deny"])
    if net.get("listen"):
        text += ("; your servers may listen on port(s) " + ", ".join(f"`{x}`" for x in net["listen"])
                 + " (and you can connect to them on localhost)")
    return text


def container_network_lines(pol: dict) -> str:
    if pol["network"]["container"] == "filtered":
        return ("- **Same network rules as you:** it goes out only through its own nono proxy, with this\n"
                "  workspace's allowlist; DNS and raw TCP don't work there. The same token variables are\n"
                "  set, and its `$POOL_<NAME>_BASE_URL` values point at that proxy (HTTPS token APIs also\n"
                "  work at their real URL there). No SSH keys there.")
    return ("- **No SSH keys or API tokens there.** Don't copy secrets or token placeholders into it.\n"
            "- **Its network is not covered by this workspace's allowlist.** Don't use it to reach\n"
            "  hosts the allowlist blocks.")


def render_claude_md(ws: dict[str, str], pol: dict) -> str:
    values = {"workspace": ws["WS_NAME"], "project_dir": ws["WS_DIR"], "container_dir": CONTAINER_WORKSPACE,
              "network": network_summary(pol), "tokens": token_lines(pol) + builds_lines(pol),
              "container_network": container_network_lines(pol)}
    return re.sub(r"\{\{(\w+)\}\}", lambda m: values.get(m[1], m[0]), claude_md_template()[0])


def session_prompt(ws: dict[str, str], pol: dict) -> str:
    if is_microvm(ws):
        vm = (f"This session runs in the agent-sandboxes microVM workspace {ws['WS_NAME']}: a VM of its own, "
              "where you have sudo (root) and Docker. /project is the host's project folder, shared in; the "
              "rest of the VM's disk stays in the VM. The VM has no network interface: everything goes "
              f"through the proxy on 127.0.0.1:{VM_RELAY_PORT} (HTTP(S)_PROXY are set, also for apt, Docker "
              "and git over ssh), which allows only the workspace's allowlist and logs each connection. "
              "Programs that ignore the proxy variables can't connect.")
        if not pol["tokens"]:
            return vm + builds_lines(pol)
        return vm + (" API token variables hold placeholders (except plain values, marked below); the proxy "
                     "swaps in the real token only on "
                     "requests that carry the placeholder. Never ask the user for a real token.\n"
                     + token_lines(pol) + builds_lines(pol))
    if not pol["tokens"]:
        return (f"This session runs in the agent-sandboxes workspace {ws['WS_NAME']}, inside a nono sandbox."
                + builds_lines(pol)) if pol["builds"] else ""
    return (f"This session runs in the agent-sandboxes workspace {ws['WS_NAME']}, inside a nono sandbox. "
            "API token variables hold placeholders (except plain values, marked below); nono's proxy swaps in "
            "the real token only on requests "
            "that carry the placeholder, and for plain-HTTP APIs only via the base URL variable. "
            "Never ask the user for a real token.\n" + token_lines(pol) + builds_lines(pol))


def sync_claude_md(ws: dict[str, str]):
    """Add, refresh or remove the managed block at the end of the project's CLAUDE.md."""
    path = Path(ws["WS_DIR"]) / "CLAUDE.md"
    if path.is_symlink():
        raise ValueError(f"{path} is a symlink; not writing through it")
    try:
        old = path.read_text()
    except FileNotFoundError:
        old = None
    rest = re.sub(rf"\n*{re.escape(MD_BEGIN)}.*?{re.escape(MD_END)}\n?", "\n", old or "", flags=re.S).rstrip()
    pol = load_policy(ws["WS_NAME"])
    if pol["claude_md"] and not is_microvm(ws):      # the notes describe nono; a VM's prompt says what it is
        block = f"{MD_BEGIN}\n{MD_TAG}\n\n{render_claude_md(ws, pol).strip()}\n{MD_END}\n"
        new = f"{rest}\n\n{block}" if rest else block
    else:
        new = f"{rest}\n" if rest else ""
    if new == (old or ""):
        return
    if not new and old is not None and MD_BEGIN in old:
        path.unlink()      # only our block was in it
    elif new:
        path.write_text(new)


async def claude_md_api(req: Request, w):
    if req.method == "PUT":
        try:
            text = str(json.loads(req.body or b"{}").get("text", ""))
        except json.JSONDecodeError:
            return await send_json(w, {"error": "Bad JSON"}, 400)
        if len(text) > 32768 or "\0" in text:
            return await send_json(w, {"error": "At most 32 KB of text"}, 400)
        if MD_BEGIN in text or MD_END in text:
            return await send_json(w, {"error": "The text can't contain the agent-sandboxes markers"}, 400)
        CLAUDE_MD_CUSTOM.parent.mkdir(exist_ok=True)
        CLAUDE_MD_CUSTOM.write_text(text.replace("\r\n", "\n").rstrip() + "\n")
    elif req.method == "DELETE":
        CLAUDE_MD_CUSTOM.unlink(missing_ok=True)
    elif req.method != "GET":
        return await respond(w, 405, "Method not allowed\n")
    enabled, errors = [], []
    for ws in all_ws():
        if load_policy(ws["WS_NAME"])["claude_md"]:
            enabled.append(ws["WS_NAME"])
            if req.method != "GET":
                try:
                    sync_claude_md(ws)
                except (OSError, ValueError) as e:
                    errors.append(f"{ws['WS_NAME']}: {e}")
    text, custom = claude_md_template()
    return await send_json(w, {"text": text, "custom": custom, "default": CLAUDE_MD_DEFAULT.read_text(),
                               "enabled": enabled, "errors": errors})


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
            mine = set(listen_ports(pol))
            for o in all_ws():
                if o["WS_NAME"] != name and (both := mine & set(listen_ports(load_policy(o["WS_NAME"])))):
                    raise ValueError(f"Listen ports: {min(both)} is already used by workspace '{o['WS_NAME']}'")
            if is_microvm(ws) and pol["vm_browser"]:
                lim = pol["limits"]
                if lim["memory"] and mem_mb(lim["memory"]) < browser_memory_mb(pol) + 1024:
                    raise ValueError(f"Memory: the VM needs at least {browser_memory_mb(pol) // 1024 + 1}G "
                                     "with the browser container (its memory plus 1G)")
                if lim["browser_cpus"] > vm_vcpus(pol):
                    raise ValueError(f"Browser container CPUs: at most the VM's {vm_vcpus(pol)} vCPUs")
            if is_microvm(ws) and pol["limits"]["disk"]:
                img = vm_dir(name) / "rootfs.img"
                have = img.stat().st_size >> 30 if img.is_file() else 0
                if vm_disk_gb(pol) < have:
                    raise ValueError(f"Disk: the VM's disk is already {have}G, and disks only grow")
        except (ValueError, json.JSONDecodeError) as e:
            return await send_json(w, {"error": str(e)}, 400)
        old = load_policy(name)
        pol["tags"] = old["tags"]           # edited on their own (PUT …/tags)
        save_policy(name, pol)
        if old["ssh_keys"] != pol["ssh_keys"]:
            await sync_agent(name)
        try:
            sync_claude_md(ws)
        except (OSError, ValueError) as e:
            return await send_json(w, {"error": f"Saved, but CLAUDE.md: {e}"}, 500)
        if is_microvm(ws):
            notes = await apply_vm_policy(ws, old, pol)
        else:
            notes = await apply_container_network(ws, old)
            notes += await apply_container_limits(ws, old, pol, notes)
    else:
        notes = []
    rc, out, _ = await run(*TMUX, "list-panes", "-t", f"cl-{name}", "-F", "#{pane_dead}")
    running = rc == 0 and "0" in out.split()
    return await send_json(w, {"policy": load_policy(name), "pending": running and policy_pending(ws),
                               "notes": notes})


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
        if parts == ["signing"] and m == "POST":
            try:
                p12 = base64.b64decode(str(body.get("p12", "")), validate=True)
                profiles = [base64.b64decode(str(x), validate=True) for x in body.get("profiles", []) or []][:20]
            except ValueError:
                raise ValueError("Bad file upload") from None
            if not ITEM_RE.match(str(body.get("id", ""))) or token_meta(str(body.get("id"))):
                raise ValueError("Name: lowercase letters, digits and dashes, max 40, not a token's name")
            return await send_json(w, await asyncio.to_thread(
                applesign.add_identity, str(body.get("id")), p12, str(body.get("password", "")), profiles), 201)
        if len(parts) >= 3 and parts[0] == "signing" and parts[2] == "profiles" and applesign.meta(parts[1]):
            if parts[3:] == [] and m == "POST":
                try:
                    raw = base64.b64decode(str(body.get("profile", "")), validate=True)
                except ValueError:
                    raise ValueError("Bad file upload") from None
                return await send_json(w, applesign.add_profile(parts[1], raw), 201)
            if len(parts) == 4 and m == "DELETE":
                return await send_json(w, applesign.remove_profile(parts[1], parts[3]))
        if len(parts) >= 2 and parts[0] in ("ssh", "tokens", "signing") and ITEM_RE.match(parts[1]):
            kind, iid = {"ssh": "ssh", "tokens": "token", "signing": "signing"}[parts[0]], parts[1]
            exists = ((SSH_POOL / iid).is_file() if kind == "ssh" else token_meta(iid) is not None if kind == "token"
                      else applesign.meta(iid) is not None)
            if not exists:
                return await send_json(w, {"error": "Not found"}, 404)
            if parts[2:] == [] and m == "DELETE":
                await remove_pool_item(kind, iid)
                return await send_json(w, {"ok": True})
            if parts[2:] == ["workspaces"] and m == "PUT":
                await assign(kind, iid, body.get("workspaces", []))
                return await send_json(w, {"ok": True})
    except (ValueError, json.JSONDecodeError, applesign.SignError) as e:
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


# --------------------------------------------------------------- Apple builds
# The build host (buildhost/aio-buildd, over ssh) and its Mac workers; the
# per-workspace builds, also the agent's through the aio-builds MCP server
# (ui/builds.py)

# Downloads for setting up the other machines: (top folder, files kept at
# their repo paths, so the installers find their neighbours)
BUILD_BUNDLES = {
    "worker": ("aio-build-worker", ["buildhost/install-worker", "buildhost/aio-build-worker"]),
    "buildhost": ("aio-buildhost", ["bin/install-buildhost", "buildhost/aio-buildd"]),
}


def build_bundle(top: str, files: list[str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for f in files:
            data = (ROOT / f).read_bytes()
            info = tarfile.TarInfo(f"{top}/{f}")
            info.size, info.mode, info.mtime = len(data), 0o755, int(time.time())
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


async def builds_api(req: Request, parts: list[str], w):
    m = req.method
    try:
        if parts == [] and m == "GET":
            return await send_json(w, {**builds.overview(), "publicKey": await builds.ensure_key(),
                                       "workspaces": [x["WS_NAME"] for x in all_ws()
                                                      if load_policy(x["WS_NAME"])["builds"]]})
        if parts == ["config"] and m == "PUT":
            body = json.loads(req.body or b"{}")
            builds.save_config(str(body.get("host", "")), int(body.get("port", 22) or 22))
            builds.monitor.start()
            return await send_json(w, {"ok": True})
        if parts == ["test"] and m == "POST":
            await builds.ensure_key()
            got = await builds.call_json("version")
            return await send_json(w, {"ok": True, **got})
        if len(parts) == 2 and parts[0] == "download" and parts[1] in BUILD_BUNDLES and m == "GET":
            top, files = BUILD_BUNDLES[parts[1]]
            return await respond(w, 200, build_bundle(top, files), "application/gzip",
                                 {"Content-Disposition": f'attachment; filename="{top}.tar.gz"'})
        if parts == ["worker-keys"] and m == "GET":
            return await send_json(w, await builds.call_json("worker-keys"))
        if parts == ["workers"] and m == "POST":
            body = json.loads(req.body or b"{}")
            await builds.add_worker(str(body.get("name", "")).strip(), str(body.get("key", "")))
            return await send_json(w, {"ok": True})
        if len(parts) == 2 and parts[0] == "workers" and m == "DELETE":
            await builds.remove_worker(parts[1])
            return await send_json(w, {"ok": True})
    except (builds.BuildError, ValueError, TypeError) as e:
        return await send_json(w, {"error": str(e)}, 400)
    return await respond(w, 404, "Not found\n")


async def builds_ws_api(ws: dict[str, str], req: Request, parts: list[str], w):
    name, m = ws["WS_NAME"], req.method
    try:
        if parts == [] and m == "GET":
            pol = load_policy(name)
            return await send_json(w, {"enabled": pol["builds"], "jobs": builds.monitor.jobs(name),
                                       "signing": [{"id": im["id"], "name": im["name"]} for i in pol["signing"]
                                                   if (im := applesign.meta(i))],
                                       **builds.overview()})
        if parts == [] and m == "POST":
            if not load_policy(name)["builds"]:
                raise builds.BuildError("Turn on Apple builds for this workspace first (Access tab)")
            job = await builds.submit(name, ws["WS_DIR"], json.loads(req.body or b"{}"), "ui")
            return await send_json(w, job)
        if parts == ["export"] and m == "POST":
            pol = load_policy(name)
            if not pol["builds"]:
                raise builds.BuildError("Turn on Apple builds for this workspace first (Access tab)")
            job = await builds.submit_export(name, json.loads(req.body or b"{}"), pol,
                                             lambda: builds.asc_key_for(name), "ui")
            return await send_json(w, job)
        if len(parts) == 1 and m == "GET":
            return await send_json(w, await builds.job(name, parts[0]))
        if len(parts) == 2 and parts[1] == "log" and m == "GET":
            data = await builds.job_log(name, parts[0], int(req.query.get("offset", "0") or 0))
            return await respond(w, 200, data, "text/plain; charset=utf-8")
        if len(parts) == 2 and parts[1] == "file" and m == "GET":
            path = req.query.get("path", "")
            data = await builds.job_file(name, parts[0], path)
            ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
            return await respond(w, 200, data, ctype if ctype in ("image/png", "application/json") else "text/plain")
        if len(parts) == 2 and parts[1] in ("cancel", "abandon") and m == "POST":
            await builds.cancel(name, parts[0], abandon=parts[1] == "abandon")
            return await send_json(w, {"ok": True})
        if len(parts) == 2 and parts[1] == "screenshots" and m == "POST":
            body = json.loads(req.body or b"{}")
            paths = await builds.save_screenshots(name, ws["WS_DIR"], parts[0],
                                                  str(body.get("folder") or "docs/screenshots"), body.get("files"))
            return await send_json(w, {"ok": True, "paths": paths})
        if len(parts) == 2 and parts[1] == "fetch" and m == "POST":
            rel = await builds.fetch_artifact(name, ws["WS_DIR"], parts[0], req.query.get("name", ""))
            return await send_json(w, {"ok": True, "path": rel})
        if len(parts) == 2 and parts[1] == "artifact" and m == "GET":
            art = req.query.get("name", "")
            proc = await builds.artifact_stream(name, parts[0], art)
            first = await proc.stdout.read(65536)
            if not first:
                err = (await proc.stderr.read()).decode(errors="replace").strip()
                await proc.wait()
                raise builds.BuildError(err.removeprefix("aio-buildd: ") or "empty artifact")
            w.write(("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                     f'Content-Disposition: attachment; filename="{name}-{parts[0]}-{art}"\r\n'
                     "Connection: close\r\n\r\n").encode())
            w.write(first)
            while chunk := await proc.stdout.read(1 << 20):
                w.write(chunk)
                await w.drain()
            await proc.wait()
            return
    except (builds.BuildError, ValueError) as e:
        return await send_json(w, {"error": str(e)}, 400)
    return await respond(w, 404, "Not found\n")


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
    if parts == ["claude-md"]:
        return await claude_md_api(req, w)
    if parts[:1] == ["sharing"]:
        return await sharing_api(req, parts[1:], w)
    if parts[:1] == ["backup"]:
        return await backup_api(req, parts[1:], w)
    if parts == ["monitoring", "password"] and m == "GET":
        try:
            return await send_json(w, {"password": (SECRETS / "grafana-admin-password").read_text().strip()})
        except OSError:
            return await send_json(w, {"error": "No local Grafana password yet: apply first"}, 404)
    await respond(w, 404, "Not found\n")


# ---- settings: backup (tarballs to an SMB share via smbclient: no mount, so no root needed)

BACKUP_CONF = SECRETS / "backup.json"              # NAS details, password included (0600)
BACKUP_STATUS = SECRETS / "backup-status.json"     # recent runs, for the Settings page
BACKUP_STAGING = SECRETS / "backup-staging"        # the tarball while it's built and uploaded
BACKUP_RE = re.compile(r"^agent-sandboxes-([a-z0-9-]{1,63})-(\d{8}T\d{6}Z)\.tar\.(zst|gz)(\.part)?$")
REBUILDABLE = ["node_modules", ".venv", "__pycache__"]
BACKUP_DEFAULT = {"server": "", "share": "", "dir": "agent-sandboxes", "username": "", "password": "",
                  "domain": "", "include": {"projects": True, "config": True, "claude": True},
                  "skip_rebuildable": True, "schedule": "off", "time": "03:00", "weekday": 6,
                  "keep_days": 14, "schedule_since": 0}
SMB_ERRORS = {   # smbclient's NT_STATUS codes, said plainly
    "NT_STATUS_LOGON_FAILURE": "The NAS rejected the username or password",
    "NT_STATUS_ACCESS_DENIED": "The NAS denied access (check the user's rights on the share and folder)",
    "NT_STATUS_BAD_NETWORK_NAME": "The NAS has no share by that name",
    "NT_STATUS_OBJECT_NAME_NOT_FOUND": "That folder doesn't exist on the share",
    "NT_STATUS_OBJECT_PATH_NOT_FOUND": "That folder doesn't exist on the share",
    "NT_STATUS_CONNECTION_REFUSED": "The NAS refused the connection (is SMB enabled on it?)",
    "NT_STATUS_IO_TIMEOUT": "Couldn't reach the NAS (timed out)",
    "NT_STATUS_HOST_UNREACHABLE": "Couldn't reach the NAS (host unreachable)",
    "NT_STATUS_UNSUCCESSFUL": "Couldn't reach the NAS (name not found or no route)",
    "NT_STATUS_DISK_FULL": "The share is full",
}
backup_task: asyncio.Task | None = None
backup_phase = ""


class BackupError(Exception):
    pass


def host_tag() -> str:
    return re.sub(r"[^a-z0-9-]+", "-", socket.gethostname().lower()).strip("-")[:63] or "host"


def load_backup_conf() -> dict:
    try:
        saved = json.loads(BACKUP_CONF.read_text())
    except (OSError, ValueError):
        saved = {}
    cfg = {**BACKUP_DEFAULT, **{k: v for k, v in saved.items() if k in BACKUP_DEFAULT}}
    cfg["include"] = {**BACKUP_DEFAULT["include"], **cfg["include"]}
    return cfg


def load_backup_status() -> dict:
    try:
        return json.loads(BACKUP_STATUS.read_text())
    except (OSError, ValueError):
        return {"runs": [], "last_attempt": 0}


def save_backup_status(st: dict):
    st["runs"] = st["runs"][-20:]
    private_write(BACKUP_STATUS, json.dumps(st, indent=2))


def backup_configured(cfg: dict) -> bool:
    return bool(cfg["server"] and cfg["share"] and cfg["username"])


def validate_backup(body: dict, cur: dict) -> dict:
    cfg = dict(cur)
    for k in ("server", "share", "dir", "username", "domain", "time", "schedule"):
        if k in body:
            cfg[k] = str(body[k]).strip()
    cfg["dir"] = cfg["dir"].strip("/")
    if not re.fullmatch(r"([A-Za-z0-9.-]{1,253}(:[1-9][0-9]{0,4})?)?", cfg["server"]):
        raise ValueError("Server: a hostname or IP address, optionally with :port")
    if not re.fullmatch(r"([A-Za-z0-9 ._$-]{1,80})?", cfg["share"]):
        raise ValueError("Share: just the share's name (letters, digits, spaces, . _ - $)")
    if cfg["dir"] and any(seg in (".", "..") or not re.fullmatch(r"[A-Za-z0-9 ._()-]{1,100}", seg)
                          for seg in cfg["dir"].split("/")):
        raise ValueError("Folder: a path on the share like backups/agent-sandboxes (letters, digits, spaces, . _ - ( ))")
    if not re.fullmatch(r"[A-Za-z0-9._@+-]{0,104}", cfg["username"]):
        raise ValueError("Username: letters, digits and . _ @ + - (put the domain in its own field)")
    if not re.fullmatch(r"[A-Za-z0-9.-]{0,64}", cfg["domain"]):
        raise ValueError("Domain / workgroup: letters, digits, dots and dashes")
    if body.get("forget_password"):
        cfg["password"] = ""
    elif isinstance(body.get("password"), str) and body["password"]:
        if re.search(r"[\r\n\0]", body["password"]) or len(body["password"]) > 256:
            raise ValueError("Password can't contain line breaks")
        cfg["password"] = body["password"]
    if cfg["server"] and not (cfg["share"] and cfg["username"]):
        raise ValueError("A NAS needs a share and a username")
    inc = body.get("include", {})
    cfg["include"] = {k: bool(inc.get(k, v)) for k, v in cur["include"].items()}
    cfg["skip_rebuildable"] = bool(body.get("skip_rebuildable", cur["skip_rebuildable"]))
    if cfg["schedule"] not in ("off", "daily", "weekly"):
        raise ValueError("Schedule: off, daily or weekly")
    if not re.fullmatch(r"([01][0-9]|2[0-3]):[0-5][0-9]", cfg["time"]):
        raise ValueError("Time: HH:MM")
    try:
        cfg["weekday"] = int(body.get("weekday", cur["weekday"]))
        cfg["keep_days"] = int(body.get("keep_days", cur["keep_days"]))
    except (TypeError, ValueError):
        raise ValueError("Day and days to keep must be numbers") from None
    if not 0 <= cfg["weekday"] <= 6 or not 0 <= cfg["keep_days"] <= 3650:
        raise ValueError("Keep backups for 0-3650 days (0 keeps them all)")
    if cfg["schedule"] != "off" and not backup_configured(cfg):
        raise ValueError("Set up the NAS before scheduling backups")
    if any(cfg[k] != cur[k] for k in ("schedule", "time", "weekday")):
        cfg["schedule_since"] = time.time()   # the first run is the next slot from now, not a missed one
    return cfg


def next_backup(cfg: dict, st: dict) -> float | None:
    """The first schedule slot after the last run (or after the schedule was
    set): a slot missed while the server was down runs as soon as it's back."""
    if cfg["schedule"] == "off" or not backup_configured(cfg):
        return None
    base = datetime.datetime.fromtimestamp(max(st.get("last_attempt", 0), cfg["schedule_since"]))
    h, m = map(int, cfg["time"].split(":"))
    t = base.replace(hour=h, minute=m, second=0, microsecond=0)
    if t <= base:
        t += datetime.timedelta(days=1)
    while cfg["schedule"] == "weekly" and t.weekday() != cfg["weekday"]:
        t += datetime.timedelta(days=1)
    return t.timestamp()


def smbclient_path() -> str | None:
    return os.environ.get("AIO_SMBCLIENT") or shutil.which("smbclient")


def smb_error(text: str) -> str:
    for code, plain in SMB_ERRORS.items():
        if code in text:
            return f"{plain} ({code})"
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return next((ln for ln in lines if "NT_STATUS" in ln), lines[-1] if lines else "smbclient failed")


async def smb(cfg: dict, command: str, cd: bool = True, timeout: float = 120) -> str:
    """One smbclient command (it ignores errors in a ;-separated list and still
    exits 0, so never chain ones that matter). The password goes in a 0600
    auth file, not on the command line."""
    exe = smbclient_path()
    if not exe:
        raise BackupError("smbclient isn't installed on this host: sudo apt install smbclient")
    auth = RUNTIME / f"smb-auth-{secrets.token_hex(6)}"
    private_write(auth, f"username = {cfg['username']}\npassword = {cfg['password']}\n"
                        + (f"domain = {cfg['domain']}\n" if cfg["domain"] else ""))
    host, _, port = cfg["server"].partition(":")
    args = [exe, f"//{host}/{cfg['share']}", "-A", str(auth), "-c", command]
    if port:
        args += ["-p", port]
    if cd and cfg["dir"]:
        args += ["-D", cfg["dir"].replace("/", "\\")]
    try:
        rc, out, err = await run(*args, timeout=timeout, preexec_fn=die_with_parent)
    finally:
        auth.unlink(missing_ok=True)
    if rc != 0:
        raise BackupError(smb_error(out + err))
    return out


async def smb_ensure_dir(cfg: dict) -> str:
    """Create the folder (and its parents) if needed; returns its listing."""
    if cfg["dir"]:
        segs = cfg["dir"].split("/")
        mk = "; ".join('mkdir "{}"'.format("\\".join(segs[:i])) for i in range(1, len(segs) + 1))
        await smb(cfg, mk, cd=False)     # "already exists" errors are fine; the ls below checks
    return await smb(cfg, "ls")


def parse_listing(out: str) -> dict:
    files = []
    for line in out.splitlines():
        m = re.match(r"^  (.+?)\s+([A-Z]*)\s+(\d+)\s+\w{3} \w{3} [ \d]\d \d\d:\d\d:\d\d \d{4}$", line)
        if not m or "D" in m.group(2):
            continue
        b = BACKUP_RE.match(m.group(1))
        if b:
            at = datetime.datetime.strptime(b.group(2), "%Y%m%dT%H%M%SZ").replace(tzinfo=datetime.timezone.utc)
            files.append({"name": m.group(1), "host": b.group(1), "at": at.timestamp(),
                          "size": int(m.group(3)), "partial": bool(b.group(4)), "mine": b.group(1) == host_tag()})
    files.sort(key=lambda f: f["at"], reverse=True)
    free = re.search(r"(\d+) blocks of size (\d+)\. (\d+) blocks available", out)
    return {"files": files, "free": int(free.group(3)) * int(free.group(2)) if free else None,
            "total": int(free.group(1)) * int(free.group(2)) if free else None}


async def prune_backups(cfg: dict) -> list[str]:
    """Delete this host's backups older than keep_days (never its newest
    complete one), and uploads that never finished."""
    listing = parse_listing(await smb(cfg, "ls"))
    mine = [f for f in listing["files"] if f["mine"]]
    complete = [f for f in mine if not f["partial"]]
    doomed = [f for f in mine if f["partial"] and f["at"] < time.time() - 86400]
    if cfg["keep_days"]:
        cutoff = time.time() - cfg["keep_days"] * 86400
        doomed += [f for f in complete[1:] if f["at"] < cutoff]
    gone = []
    for f in doomed:
        await smb(cfg, f'del "{f["name"]}"')
        gone.append(f["name"])
    return gone


def remember_listing(listing: dict):
    """Keep the NAS totals for the metrics exporter (it doesn't talk to the NAS)."""
    mine = [f for f in listing["files"] if f["mine"] and not f["partial"]]
    st = load_backup_status()
    st["remote"] = {"count": len(mine), "bytes": sum(f["size"] for f in mine),
                    "free": listing["free"], "total": listing["total"], "at": time.time()}
    save_backup_status(st)


def backup_sources(cfg: dict) -> dict[str, list[str]]:
    inc, home = cfg["include"], Path.home()
    src = {"projects": [ws["WS_DIR"] for ws in all_ws()] if inc["projects"] else [],
           "config": [str(p) for p in (WS_ROOT, STATE_ROOT, SECRETS, TOKEN_FILE, TLS_DIR,
                                       ROOT / "ui" / "extra-hostnames", auth.PASSKEYS_FILE,
                                       MONITORING_ENV)] if inc["config"] else [],
           "claude": [str(CLAUDE_HOME), str(home / ".claude.json")] if inc["claude"] else []}
    return {k: [p for p in v if os.path.lexists(p)] for k, v in src.items()}


async def make_tarball(cfg: dict, name: str) -> tuple[Path, list[str]]:
    src = backup_sources(cfg)
    paths = list(dict.fromkeys(p for v in src.values() for p in v))
    if not paths:
        raise BackupError("Nothing to back up: tick at least one of the What to back up options")
    if BACKUP_STAGING.exists():
        shutil.rmtree(BACKUP_STAGING)    # leftovers of a run the server didn't finish
    BACKUP_STAGING.mkdir(mode=0o700)
    meta = BACKUP_STAGING / "meta"
    meta.mkdir()
    (meta / "BACKUP-MANIFEST.json").write_text(json.dumps({
        "format": 1, "tool": "agent-sandboxes", "host": socket.gethostname(),
        "created": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "sources": src, "workspaces": {ws["WS_NAME"]: ws["WS_DIR"] for ws in all_ws()},
        "restore": "Paths are stored relative to /. Look first with tar -tf, then extract "
                   "into a scratch folder (tar -xf FILE -C DIR) or in place (-C /).",
    }, indent=2) + "\n")
    out = BACKUP_STAGING / name
    excludes = [str(p).lstrip("/") for p in (BACKUP_STAGING, BACKUP_CONF)]
    if cfg["skip_rebuildable"]:
        excludes += REBUILDABLE
    cmd = ["tar", "--create", "--file", str(out), "--zstd" if name.endswith(".zst") else "--gzip",
           "--ignore-failed-read", "--warning=no-file-changed", "--warning=no-file-removed",
           *(f"--exclude={x}" for x in excludes),
           "-C", str(meta), "BACKUP-MANIFEST.json", "-C", "/", *(p.lstrip("/") for p in paths)]
    if shutil.which("ionice"):
        cmd = ["ionice", "-c", "3", *cmd]
    rc, _, err = await run("nice", "-n", "10", *cmd, timeout=6 * 3600, preexec_fn=die_with_parent)
    warnings = [ln for ln in err.splitlines() if ln.strip()]
    if rc > 1 or not out.is_file():           # 1: a file changed while it was read
        raise BackupError("tar failed: " + "; ".join(warnings[-3:]) if warnings else f"tar exited {rc}")
    return out, warnings[:20]


async def run_backup(trigger: str):
    global backup_phase
    cfg, st = load_backup_conf(), load_backup_status()
    st["last_attempt"] = time.time()
    save_backup_status(st)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    name = f"agent-sandboxes-{host_tag()}-{stamp}.tar." + ("zst" if shutil.which("zstd") else "gz")
    rec = {"started": st["last_attempt"], "trigger": trigger, "file": name, "ok": False}
    try:
        if not backup_configured(cfg):
            raise BackupError("No NAS set up")
        backup_phase = "checking the NAS"
        await smb_ensure_dir(cfg)
        backup_phase = "archiving"
        tarball, rec["warnings"] = await make_tarball(cfg, name)
        rec["size"] = tarball.stat().st_size
        backup_phase = "uploading"
        try:
            await smb(cfg, f'put "{tarball}" "{name}.part"', timeout=12 * 3600)
            await smb(cfg, f'rename "{name}.part" "{name}"')
        except BackupError:
            with contextlib.suppress(BackupError):
                await smb(cfg, f'del "{name}.part"')
            raise
        rec["ok"] = True
        backup_phase = "pruning old backups"
        try:
            rec["pruned"] = await prune_backups(cfg)
            remember_listing(parse_listing(await smb(cfg, "ls")))
        except BackupError as e:
            rec["warnings"] = rec.get("warnings", []) + [f"Pruning failed: {e}"]
    except BackupError as e:
        rec["error"] = str(e)
    except Exception as e:      # keep the scheduler alive; show it on the page
        rec["error"] = f"{type(e).__name__}: {e}"
    finally:
        shutil.rmtree(BACKUP_STAGING, ignore_errors=True)
        backup_phase = ""
        rec["finished"] = time.time()
        st = load_backup_status()
        st["runs"].append(rec)
        save_backup_status(st)
        # logfmt, for the Backup panel in Grafana (the journal goes to Loki)
        print(f'backup trigger={trigger} result={"ok" if rec["ok"] else "failed"} file={name} '
              f'bytes={rec.get("size", 0)} seconds={rec["finished"] - rec["started"]:.0f} '
              f'warnings={len(rec.get("warnings", []))} pruned={len(rec.get("pruned", []))}'
              + ("" if rec["ok"] else " error=" + json.dumps(rec["error"])), flush=True)


def start_backup(trigger: str) -> bool:
    global backup_task
    if backup_task and not backup_task.done():
        return False
    backup_task = asyncio.create_task(run_backup(trigger))
    return True


async def backup_scheduler():
    await asyncio.sleep(60)          # let the UI and sandboxes come up first
    while True:
        due = next_backup(load_backup_conf(), load_backup_status())
        if due is not None and time.time() >= due:
            start_backup("schedule")
        await asyncio.sleep(30)


def backup_state() -> dict:
    cfg, st = load_backup_conf(), load_backup_status()
    public = {k: v for k, v in cfg.items() if k not in ("password", "schedule_since")}
    return {"config": {**public, "password_set": bool(cfg["password"])},
            "smbclient": bool(smbclient_path()), "running": backup_phase or None,
            "runs": st["runs"][-10:][::-1], "next": next_backup(cfg, st), "host": host_tag(),
            "tz": time.strftime("%Z, UTC%z"), "home": str(Path.home()),
            "sources": backup_sources({**cfg, "include": {k: True for k in cfg["include"]}})}


async def backup_api(req: Request, parts: list[str], w):
    m = req.method
    try:
        if parts == [] and m == "GET":
            return await send_json(w, backup_state())
        if parts == [] and m == "PUT":
            try:
                cfg = validate_backup(json.loads(req.body or b"{}"), load_backup_conf())
            except (ValueError, json.JSONDecodeError) as e:
                return await send_json(w, {"error": str(e)}, 400)
            private_write(BACKUP_CONF, json.dumps(cfg, indent=2))
            return await send_json(w, backup_state())
        cfg = load_backup_conf()
        if parts and not backup_configured(cfg):
            return await send_json(w, {"error": "Set up and save the NAS first"}, 400)
        if parts == ["test"] and m == "POST":
            listing = parse_listing(await smb_ensure_dir(cfg))
            remember_listing(listing)
            return await send_json(w, {"ok": True, **listing})
        if parts == ["run"] and m == "POST":
            if not start_backup("manual"):
                return await send_json(w, {"error": "A backup is already running"}, 409)
            await asyncio.sleep(0.2)
            return await send_json(w, backup_state())
        if parts == ["remote"] and m == "GET":
            listing = parse_listing(await smb(cfg, "ls"))
            remember_listing(listing)
            return await send_json(w, listing)
        if len(parts) == 2 and parts[0] == "remote" and m == "DELETE":
            if not BACKUP_RE.match(parts[1]):
                return await send_json(w, {"error": "Not a backup file"}, 400)
            await smb(cfg, f'del "{parts[1]}"')
            listing = parse_listing(await smb(cfg, "ls"))
            remember_listing(listing)
            return await send_json(w, listing)
        if parts == ["prune"] and m == "POST":
            if backup_phase:
                return await send_json(w, {"error": "A backup is running; it prunes when it's done"}, 409)
            gone = await prune_backups(cfg)
            listing = parse_listing(await smb(cfg, "ls"))
            remember_listing(listing)
            return await send_json(w, {"pruned": gone, **listing})
    except BackupError as e:
        return await send_json(w, {"error": str(e)}, 502)
    await respond(w, 404, "Not found\n")


def clean_container_path(p: str) -> str | None:
    if not p.startswith("/") or "\0" in p or "\n" in p:
        return None
    return posixpath.normpath(p)


def sandbox_exec(ws: dict[str, str], *args: str, stdin: bool = False) -> list[str]:
    """A command in the workspace's AIO container (as gem): on the host, or in its microVM."""
    cmd = ["docker", "exec", *(["-i"] if stdin else []), "-u", "1000"]
    if is_microvm(ws):
        return [str(MICROVM), "ssh", ws["WS_NAME"], "--", shlex.join(cmd + ["aio-browser", *args])]
    return cmd + [container(ws["WS_NAME"]), *args]


async def list_files(ws, req: Request, w):
    path = clean_container_path(req.query.get("path", "/home/gem"))
    if not path:
        return await send_json(w, {"error": "Bad path"}, 400)
    rc, out, err = await run(*sandbox_exec(ws, "find", path, "-mindepth", "1", "-maxdepth", "1",
                                           "-printf", r"%y\t%s\t%T@\t%f\0"), timeout=30)
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
    rc, kind, err = await run(*sandbox_exec(ws, "stat", "-L", "-c", "%F", path))
    kind = kind.strip()
    base = posixpath.basename(path)
    if kind == "directory":
        cmd = sandbox_exec(ws, "tar", "-C", posixpath.dirname(path), "-cf", "-", "--", base)
        fname, ctype = base + ".tar", "application/x-tar"
    elif kind.startswith("regular"):
        cmd = sandbox_exec(ws, "cat", "--", path)
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


# Into the container as gem: the body goes to a hidden temp file next to the
# target, renamed into place only once it has every byte (an upload cut off
# ends the stream early too, so the size is what tells), so a broken upload
# leaves no half file. A file that's there already is only replaced with
# overwrite=1; folders on the way (an uploaded folder's subfolders) are created.
UPLOAD_SH = r"""set -eu
dir=$1 rel=$2 tmp=$3 overwrite=$4 size=$5
dest="$dir/$rel"
parent=$(dirname -- "$dest")
[ -d "$dir" ] || { echo "No such folder: $dir" >&2; exit 2; }
if [ -e "$dest" ] || [ -L "$dest" ]; then
  [ -d "$dest" ] && { echo "A folder has that name" >&2; exit 3; }
  [ "$overwrite" = 1 ] || { echo "exists" >&2; exit 17; }
fi
mkdir -p -- "$parent" 2>/dev/null || { echo "Can't create the folder ${parent#$dir/}" >&2; exit 2; }
[ -w "$parent" ] || { echo "No permission to write in $parent" >&2; exit 2; }
part="$parent/$tmp"
trap 'rm -f -- "$part"' EXIT
cat > "$part"
got=$(wc -c < "$part")
[ "$got" -eq "$size" ] || { echo "Upload incomplete ($got of $size bytes)" >&2; exit 4; }
mv -f -- "$part" "$dest"
trap - EXIT
"""


def clean_upload_name(rel: str) -> str | None:
    """A file name, or a relative path (a folder upload): no '..', no empty parts."""
    parts = rel.split("/")
    if not rel or len(rel) > 1024 or "\0" in rel or "\n" in rel or len(parts) > 32:
        return None
    if any(p in ("", ".", "..") or len(p.encode()) > 255 for p in parts):
        return None
    return rel


async def upload(name: str, req: Request, reader, w):
    ws = load_ws(name)
    if not ws:
        return await send_json(w, {"error": "No such workspace"}, 404)
    if is_microvm(ws) and not vm_browser(ws):
        return await send_json(w, {"error": "This microVM has no browser container (Access tab)"}, 404)
    folder = clean_container_path(req.query.get("path", ""))
    rel = clean_upload_name(req.query.get("name", ""))
    if not folder or not rel:
        return await send_json(w, {"error": "Bad folder or file name"}, 400)
    if "chunked" in req.headers.get("transfer-encoding", "").lower():
        return await send_json(w, {"error": "Uploads need a Content-Length"}, 411)
    try:
        length = int(req.headers.get("content-length", ""))
    except ValueError:
        return await send_json(w, {"error": "Uploads need a Content-Length"}, 411)
    if not 0 <= length <= MAX_UPLOAD:
        return await send_json(w, {"error": f"Files up to {MAX_UPLOAD >> 30} GB (AIO_UPLOAD_MAX_GB)"}, 413)
    tmp = f".{posixpath.basename(rel)[:200]}.aio-upload-{secrets.token_hex(4)}"
    overwrite = "1" if req.query.get("overwrite") == "1" else "0"
    proc = await asyncio.create_subprocess_exec(
        *sandbox_exec(ws, "sh", "-c", UPLOAD_SH, "sh", folder, rel, tmp, overwrite, str(length), stdin=True),
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
    left, broken = length, False
    try:
        while left:
            chunk = await reader.read(min(left, 256 * 1024))
            if not chunk:
                raise ConnectionError("upload cut short")
            left -= len(chunk)
            if broken:
                continue            # the command failed: drain the body, then report
            try:
                proc.stdin.write(chunk)
                await proc.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                broken = True
        proc.stdin.close()
        err = (await proc.stderr.read()).decode(errors="replace").strip()
        rc = await proc.wait()
    except BaseException:
        if proc.returncode is None:
            proc.kill()             # its trap can't run: remove the temp file ourselves
            await proc.wait()
        await run(*sandbox_exec(ws, "sh", "-c", 'rm -f -- "$(dirname -- "$1/$2")/$3"', "sh", folder, rel, tmp))
        raise
    if rc == 17:
        return await send_json(w, {"error": f"{rel} already exists", "exists": True}, 409)
    if rc != 0:
        return await send_json(w, {"error": err.splitlines()[-1] if err else f"Upload failed ({rc})"}, 500)
    return await send_json(w, {"ok": True, "path": posixpath.join(folder, rel), "size": length})


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
    ws_accept(req, w)
    await w.drain()

    session = f"cl-{name}"
    if (await run(*TMUX, "has-session", "-t", session))[0] != 0:
        w.write(ws_frame(0x2, b"\r\n\x1b[33mNo Claude session running. Use \"Start Claude\".\x1b[0m\r\n"))
        w.write(ws_frame(0x8, struct.pack("!H", 1000)))
        await w.drain()
        return

    await attach_pty(req, reader, w, [*TMUX, "attach-session", "-t", session])


def ws_accept(req: Request, w):
    key = req.headers.get("sec-websocket-key", "")
    accept = base64.b64encode(hashlib.sha1(key.encode() + WS_GUID).digest()).decode()
    w.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
             f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode())


def term_size(req: Request) -> tuple[int, int]:
    def num(k, default, lo, hi):
        try:
            return max(lo, min(hi, int(req.query.get(k, default) or default)))
        except ValueError:
            return default
    return num("cols", 120, 20, 500), num("rows", 40, 5, 200)


async def attach_pty(req: Request, reader, w, argv: list[str], readonly: bool = False):
    """Run a tmux client (argv) on a pty and relay it over the WebSocket.
    readonly: drop the browser's keystrokes too (the tmux client is -r)."""
    cols, rows = term_size(req)
    master, slave = os.openpty()
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    env = {**os.environ, "TERM": "xterm-256color"}
    env.pop("TMUX", None)
    # setsid -c: new session with the pty as controlling terminal, so the
    # tmux client gets SIGWINCH when we resize.
    proc = await asyncio.create_subprocess_exec(
        "setsid", "-c", "-w", *argv,
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
            if msg.get("t") == "i" and not readonly:
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


# --------------------------------------------------------------- sign-in settings

async def auth_api(req: Request, parts: list[str], w):
    """Signed in: this session, the passkeys, signing out."""
    m, sid = req.method, req.cookies().get(auth.COOKIE, "")
    sess = auth.session(sid) or {}
    body = json.loads(req.body or b"{}") if m in ("POST", "PATCH") else {}
    secure = TLS_CTX is not None
    if parts == [] and m == "GET":
        try:
            rp_id, rp_err = auth.rp_id_for(req.hostname), ""
        except ValueError as e:
            rp_id, rp_err = "", str(e)
        return await send_json(w, {
            "user": auth.USER, "method": sess.get("method"), "since": sess.get("created"),
            "fresh": auth.now() - sess.get("pw_at", 0) < auth.FRESH, "sessions": auth.session_count(),
            "passkeys": auth.public_passkeys(), "rpId": rp_id, "rpError": rp_err,
            "tokenLogin": auth.TOKEN_LOGIN})
    if parts == ["logout"] and m == "POST":
        auth.end_session(sid)
        return await respond(w, 200, '{"ok": true}', "application/json",
                             {"Set-Cookie": auth.clear_cookie_header(secure)})
    if parts == ["logout-others"] and m == "POST":
        return await send_json(w, {"ended": auth.end_other_sessions(sid)})
    if parts == ["passkeys", "options"] and m == "POST":
        # Adding a passkey needs the password, checked within the last few minutes
        if auth.now() - sess.get("pw_at", 0) >= auth.FRESH:
            ip = peer_ip(w)
            if not body.get("password"):
                return await send_json(w, {"error": "Enter your password to add a passkey", "needPassword": True}, 403)
            if auth.limited(ip):
                return await send_json(w, {"error": "Too many failed attempts: wait a few minutes"}, 429)
            ok, err = await auth.check_password(auth.USER, str(body["password"]), ip)
            if err:
                return await send_json(w, {"error": f"PAM couldn't check the password: {err}"}, 500)
            if not ok:
                auth.failed(ip)
                return await send_json(w, {"error": "Wrong password", "needPassword": True}, 403)
            auth.mark_password(sid)
        try:
            return await send_json(w, auth.registration_options(auth.rp_id_for(req.hostname), auth._key(sid)))
        except ValueError as e:
            return await send_json(w, {"error": str(e)}, 400)
    if parts == ["passkeys"] and m == "POST":
        try:
            p = await asyncio.to_thread(auth.register, body, ui_origin(req), auth._key(sid))
        except Exception as e:
            return await send_json(w, {"error": str(e) if isinstance(e, ValueError) else "Bad passkey response"}, 400)
        print(f"passkey added: {p['name']} ({p['rp_id']})", flush=True)
        return await send_json(w, {"passkey": p}, 201)
    if len(parts) == 2 and parts[0] == "passkeys" and m == "DELETE":
        if not auth.remove_passkey(parts[1]):
            return await send_json(w, {"error": "No such passkey"}, 404)
        print(f"passkey removed: {parts[1][:16]}…", flush=True)
        return await send_json(w, {"ok": True})
    if len(parts) == 2 and parts[0] == "passkeys" and m == "PATCH":
        if not auth.rename_passkey(parts[1], body.get("name", "")):
            return await send_json(w, {"error": "No such passkey"}, 404)
        return await send_json(w, {"ok": True})
    return await respond(w, 404, "Not found\n")


# --------------------------------------------------------------- host shell
# The Host page: a login shell on this host, as this user, in ~/agent-sandboxes.
# The UI's service runs with NoNewPrivileges (so its children can't sudo); the
# shell is started by the user's systemd instance instead, outside the
# service, so sudo works there. It lives in tmux and outlasts UI restarts.

def source_version(paths: list[Path]) -> str:
    h = hashlib.sha256()
    for p in paths:
        h.update(p.read_bytes())
    return h.hexdigest()[:12]


UI_VERSION = source_version(UI_SOURCES)      # the code this process loaded


async def user_manager() -> bool:
    return (await run("systemctl", "--user", "show-environment"))[0] == 0


async def host_session_alive() -> bool:
    return (await run(*TMUX_HOST, "has-session", "-t", f"={HOST_SESSION}"))[0] == 0


async def ensure_host_session(cols: int, rows: int) -> str | None:
    """Start the host shell's tmux session unless it's running. Returns an error."""
    if await host_session_alive():
        return None
    shell = pwd.getpwuid(os.getuid()).pw_shell or "/bin/bash"
    if await user_manager():
        argv = ["systemd-run", "--user", "--pty", "--quiet", "--collect", "--same-dir",
                f"--unit=aio-host-shell-{secrets.token_hex(3)}", "--setenv=TERM=tmux-256color",
                f"--setenv=AIO_ROOT={ROOT}", shell, "-l"]
    else:      # a child of this service: no sudo (NoNewPrivileges)
        note = ("No systemd --user instance (sudo loginctl enable-linger $USER): this shell runs under the "
                "web UI's service, where sudo doesn't work.")
        argv = ["sh", "-c", f"printf '\\033[33m%s\\033[0m\\n' {shlex.quote(note)}; exec {shlex.quote(shell)} -l"]
    rc, out, err = await run(*TMUX_HOST, "new-session", "-d", "-s", HOST_SESSION, "-x", str(cols), "-y", str(rows),
                             "-c", str(ROOT), *argv)
    return None if rc == 0 else (err or out).strip() or "tmux failed"


async def host_terminal(req: Request, reader, w):
    ws_accept(req, w)
    await w.drain()
    cols, rows = term_size(req)
    if err := await ensure_host_session(cols, rows):
        w.write(ws_frame(0x2, f"\r\n\x1b[31mCouldn't start the host shell: {err}\x1b[0m\r\n".encode()))
        w.write(ws_frame(0x8, struct.pack("!H", 1000)))
        await w.drain()
        return
    await attach_pty(req, reader, w, [*TMUX_HOST, "attach-session", "-t", f"={HOST_SESSION}"])


async def host_status() -> dict:
    git = {}
    rc, out, _ = await run("git", "-C", str(ROOT), "log", "-1", "--format=%h%x09%s%x09%cr")
    if rc == 0 and out.strip():
        git["commit"], git["subject"], git["when"] = (out.strip().split("\t") + ["", ""])[:3]
        git["branch"] = (await run("git", "-C", str(ROOT), "rev-parse", "--abbrev-ref", "HEAD"))[1].strip()
        git["dirty"] = bool((await run("git", "-C", str(ROOT), "status", "--porcelain", "-uno"))[1].strip())
    proxy = await proxyd({"op": "status"}, timeout=5)
    return {"enabled": HOST_SHELL, "user": pwd.getpwuid(os.getuid()).pw_name, "root": str(ROOT),
            "sudo": await user_manager(), "running": HOST_SHELL and await host_session_alive(), "git": git,
            "uiStale": source_version(UI_SOURCES) != UI_VERSION,
            "proxyStale": "version" in proxy and proxy["version"] != proxyd_source_version(),
            "proxyError": proxy.get("error", "")}


# --------------------------------------------------------------- sandbox proxy

PROXY_LOGIN_PAGE = b"""<!doctype html><meta charset=utf-8><title>Sandbox</title>
<p style="font:15px system-ui;margin:3rem">Open this sandbox from the Agent Sandboxes dashboard.</p>"""
SANDBOX_DOWN_VM = b"""The browser container in this workspace's VM isn't answering.
- Just ticked Browser container in the Access tab? Stop and Start the VM.
- After a start, the first one copies the image into the VM (about 13 GB): give it a few minutes.
- Otherwise check the VM's log (Logs tab), or in the VM: docker ps -a; systemctl status aio-browser
"""


async def handle_proxy(req: Request, name: str, reader, w, prefix: str | None = None,
                       scheme: str | None = None):
    """prefix / scheme: a guest's desktop (the share listener), else the UI's own."""
    ws = load_ws(name)
    guest = prefix is not None
    prefix = prefix or sandbox_prefix(name)
    raw_path = req.target.split("?", 1)[0]
    if not (raw_path == prefix or raw_path.startswith(prefix + "/")) \
            or not hmac.compare_digest(raw_path[:len(prefix)], prefix):
        return await respond(w, 401, PROXY_LOGIN_PAGE, "text/html; charset=utf-8")
    # Pages in the sandbox are agent-controlled; never let another origin
    # (e.g. a different workspace's sandbox) drive this one.
    origin = req.headers.get("origin")
    if origin is not None and origin != f"{scheme or SCHEME}://{req.host}":
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
    cookies = "; ".join(f"{k}={v}" for k, v in req.cookies().items() if k not in ("asui", shares.COOKIE))
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
        try:
            resp_head = await up_r.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, ConnectionError):
            # Closed before answering. For a microVM the proxy service's forwarder
            # takes the connection and drops it when nothing in the VM answers;
            # without a response the browser shows a TLS error instead.
            return await respond(w, 502, SANDBOX_DOWN_VM if is_microvm(ws) else
                                 b"The sandbox container closed the connection.\n", "text/plain; charset=utf-8")
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
        out.append("Content-Security-Policy: frame-ancestors " + ("'none'" if guest else f"'self' {ui_ancestors()}"))
        out.append("Referrer-Policy: no-referrer")   # keep the capability path from leaking
        w.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1"))
        await w.drain()
        while data := await up_r.read(65536):
            w.write(data)
            await w.drain()
    finally:
        c2u.cancel()
        up_w.close()


# --------------------------------------------------------------- sharing (guests, on the share listener)
#
# The share listener (127.0.0.1:SHARE_PORT, plain HTTP: Caddy on the VPS holds
# TLS) serves guests only: their page, their workspace's terminal, its project
# files and the sandbox's browser desktop, as their share allows. Nothing of
# the UI itself (API, settings, other workspaces, the host shell) is routed here.

SHARE_STATIC = {"/static/guest.js", "/static/guest.css", "/static/theme.js", "/static/vendor/xterm.js",
                "/static/vendor/xterm.css", "/static/vendor/addon-fit.js"}
share_servers: list[asyncio.Server] = []
sharing_lock = asyncio.Lock()


def share_client_ip(req: Request, w) -> str:
    """The guest's address: Caddy's X-Forwarded-For when it came through the tunnel."""
    peer = peer_ip(w)
    fwd = req.headers.get("x-forwarded-for", "").split(",")[-1].strip()
    return fwd if peer in ("127.0.0.1", "::1") and re.fullmatch(r"[0-9a-fA-F.:]{2,45}", fwd) else peer


def share_csp(cfg: dict) -> str:
    ws_origin = cfg["origin"].replace("https://", "wss://", 1).replace("http://", "ws://", 1)
    return ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            f"connect-src 'self' {ws_origin}; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


def share_desktop_url(cfg: dict, s: dict, ws: dict | None) -> str:
    if not (s["desktop"] and cfg["desktop_host"] and ws) or (is_microvm(ws) and not vm_browser(ws)):
        return ""
    prefix = shares.desktop_prefix(s)
    return (f"{cfg['desktop_origin']}{prefix}/vnc/index.html?autoconnect=true&resize=scale&reconnect=true&path="
            + urllib.parse.quote(prefix[1:] + "/websockify", safe=""))


SHARE_ENDED = b"""<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width">
<title>Share ended</title><body style="font:15px system-ui;max-width:34em;margin:4em auto;padding:0 16px">
<h1 style="font-size:20px">This link doesn't work</h1>
<p>It has expired, been revoked or replaced by a new one. Ask whoever shared it for a new link.</p>"""


async def handle_share(req: Request, reader, w):
    cfg = shares.config()
    if not cfg["enabled"]:
        return await respond(w, 421, "Sharing is off\n")
    if req.path == "/__relay/ping" and req.method == "GET" and req.hostname in (cfg["host"], cfg["desktop_host"]):
        n = req.query.get("n", "")                  # Settings' end-to-end check, of both names
        return await respond(w, 200, f"aio-share {n}\n" if re.fullmatch(r"[a-f0-9]{1,64}", n) else "aio-share\n")
    if cfg["desktop_host"] and req.hostname == cfg["desktop_host"]:
        return await share_desktop(req, cfg, reader, w)
    if req.hostname != cfg["host"]:
        return await respond(w, 421, "Unknown host\n")
    path, m = req.path, req.method
    if path.startswith("/s/") and m == "GET":
        ip = share_client_ip(req, w)
        if shares.limited(ip):
            return await respond(w, 429, "Too many bad links from your address: wait a few minutes\n")
        s = shares.by_token(path[3:])
        if not s or not load_ws(s["workspace"]):
            shares.bad_link(ip)
            shares.log(f"bad or ended link from {ip}")
            return await respond(w, 404, SHARE_ENDED, "text/html; charset=utf-8")
        cookie = shares.new_guest(s, ip)
        return await respond(w, 303, headers={
            "Location": "/", "Set-Cookie": shares.cookie_header(cookie, cfg["scheme"] == "https",
                                                                 s["expires"] - shares.now())})
    if m == "GET" and (path in ("/", "/index.html") or path in SHARE_STATIC):
        rel = "guest.html" if path in ("/", "/index.html") else path.removeprefix("/static/")
        f = STATIC / rel
        ctype = mimetypes.guess_type(f.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype.endswith("javascript"):
            ctype += "; charset=utf-8"
        return await respond(w, 200, f.read_bytes(), ctype,
                             {"Content-Security-Policy": share_csp(cfg), "X-Frame-Options": "DENY"})

    s = shares.guest(req.cookies().get(shares.COOKIE, ""))
    if not s:
        if path.startswith("/api/"):
            return await send_json(w, {"error": "This share has ended", "ended": True}, 401)
        return await respond(w, 401, SHARE_ENDED, "text/html; charset=utf-8")
    if path == "/ws/term":
        if req.headers.get("upgrade", "").lower() != "websocket" or not same_origin(req, cfg["scheme"]):
            return await respond(w, 403, "Forbidden\n")
        return await share_terminal(req, s, reader, w)
    if path.startswith("/api/"):
        if not same_origin(req, cfg["scheme"]):
            return await respond(w, 403, "Cross-origin request refused\n")
        if m != "GET" and req.headers.get("x-requested-with") != "sbui":
            return await respond(w, 403, "Missing X-Requested-With\n")
        return await share_api(req, s, cfg, reader, w)
    await respond(w, 404, "Not found\n")


async def share_terminal(req: Request, s: dict, reader, w):
    name = s["workspace"]
    if not load_ws(name):
        return await respond(w, 404, "No such workspace\n")
    ws_accept(req, w)
    await w.drain()
    session = f"=cl-{name}"           # exactly this session, never a prefix match
    if (await run(*TMUX, "has-session", "-t", session))[0] != 0:
        w.write(ws_frame(0x2, b"\r\n\x1b[33mClaude isn't running in this workspace right now.\x1b[0m\r\n"))
        w.write(ws_frame(0x8, struct.pack("!H", 1000)))
        await w.drain()
        return
    view = s["terminal"] != "drive"
    argv = [*TMUX, "attach-session", "-t", session, *(["-f", "read-only,ignore-size"] if view else [])]
    shares.log(f"{s['id']} {s['label']} {'watching' if view else 'driving'} {name}'s terminal")
    try:
        with shares.tracked(s["id"], w, terminal=True):
            await attach_pty(req, reader, w, argv, readonly=view)
    finally:
        shares.log(f"{s['id']} {s['label']} left {name}'s terminal")


async def guest_path(ws: dict, raw: str) -> str | None:
    """A path in the project (in the sandbox container), symlinks resolved:
    guests see the project folder only."""
    p = clean_container_path(raw)
    root = CONTAINER_WORKSPACE
    if not p or not (p == root or p.startswith(root + "/")):
        return None
    rc, out, _ = await run(*sandbox_exec(ws, "realpath", "-e", "--", p), timeout=30)
    real = out.strip()
    return real if rc == 0 and (real == root or real.startswith(root + "/")) else None


async def share_api(req: Request, s: dict, cfg: dict, reader, w):
    parts = [p for p in req.path.split("/") if p][1:]
    m = req.method
    ws = load_ws(s["workspace"])
    if not ws:
        return await send_json(w, {"error": "The workspace is gone"}, 404)
    if parts == ["me"] and m == "GET":
        return await send_json(w, {"workspace": s["workspace"], "label": s["label"], "terminal": s["terminal"],
                                   "files": s["files"], "expires": s["expires"], "now": shares.now(),
                                   "root": CONTAINER_WORKSPACE, "desktop": share_desktop_url(cfg, s, ws)})
    if parts not in (["files"], ["download"], ["upload"]):
        return await send_json(w, {"error": "Not found"}, 404)
    if s["files"] == "none" or (parts == ["upload"] and s["files"] != "upload"):
        return await send_json(w, {"error": "This share doesn't include that"}, 403)
    if is_microvm(ws) and not vm_browser(ws):
        return await send_json(w, {"error": "This workspace has no browser container, so no file access"}, 404)
    path = await guest_path(ws, req.query.get("path") or CONTAINER_WORKSPACE)
    if not path:
        return await send_json(w, {"error": f"Only files in the project ({CONTAINER_WORKSPACE}) are shared"}, 403)
    req.query["path"] = path
    if parts == ["files"] and m == "GET":
        return await list_files(ws, req, w)
    if parts == ["download"] and m == "GET":
        shares.log(f"{s['id']} {s['label']} downloaded {path}")
        return await download(ws, req, w)
    if parts == ["upload"] and m == "PUT":
        shares.log(f"{s['id']} {s['label']} uploading {req.query.get('name', '')!r} into {path}")
        return await upload(s["workspace"], req, reader, w)
    return await send_json(w, {"error": "Not found"}, 404)


async def share_desktop(req: Request, cfg: dict, reader, w):
    """The sandbox's browser desktop (noVNC and its websockify), on its own
    origin: its pages are agent-controlled, so never the guest page's."""
    raw = req.target.split("?", 1)[0]
    mt = re.fullmatch(r"/__g/([a-f0-9]{40})(/[A-Za-z0-9._~/-]*)?", raw)
    s = shares.by_cap(mt[1]) if mt else None
    if not s:
        return await respond(w, 404, SHARE_ENDED, "text/html; charset=utf-8")
    rest = mt[2] or "/"
    if "/." in rest or "//" in rest or not (rest.startswith("/vnc/") or rest == "/websockify"):
        return await respond(w, 403, "Only the sandbox's browser desktop is shared\n")
    ws = load_ws(s["workspace"])
    if not ws or (is_microvm(ws) and not vm_browser(ws)):
        return await respond(w, 404, "This workspace has no browser container\n")
    with shares.tracked(s["id"], w):
        await handle_proxy(req, s["workspace"], reader, w, prefix=shares.desktop_prefix(s), scheme=cfg["scheme"])


async def shares_api(req: Request, parts: list[str], w, ws: dict | None = None):
    """Admin: a workspace's shares (GET / POST), and revoke / new link."""
    m, cfg = req.method, shares.config()
    if ws is not None:
        if m == "GET":
            return await send_json(w, {"shares": shares.listing(ws["WS_NAME"]), "enabled": cfg["enabled"],
                                       "origin": cfg["origin"] if cfg["enabled"] else "",
                                       "desktop": bool(cfg["desktop_host"]) and (not is_microvm(ws) or vm_browser(ws))})
        if m == "POST":
            if not cfg["enabled"] or not share_servers:
                return await send_json(w, {"error": "Sharing isn't set up: see Settings, Sharing relay"}, 409)
            try:
                s, token = shares.create(ws["WS_NAME"], json.loads(req.body or b"{}"))
            except (ValueError, json.JSONDecodeError) as e:
                return await send_json(w, {"error": str(e)}, 400)
            return await send_json(w, {"share": shares.public(s), "link": f"{cfg['origin']}/s/{token}"}, 201)
        return await respond(w, 404, "Not found\n")
    if len(parts) == 1 and shares.ID_RE.match(parts[0]) and m == "DELETE":
        if not shares.revoke(parts[0]):
            return await send_json(w, {"error": "No such share"}, 404)
        return await send_json(w, {"ok": True})
    if len(parts) == 2 and shares.ID_RE.match(parts[0]) and parts[1] == "link" and m == "POST":
        r = shares.rotate(parts[0])
        if not r:
            return await send_json(w, {"error": "That share has ended"}, 404)
        return await send_json(w, {"share": shares.public(r[0]), "link": f"{cfg['origin']}/s/{r[1]}"})
    return await respond(w, 404, "Not found\n")


async def sharing_status() -> dict:
    cfg, env = shares.config(), relay.settings()
    return {"enabled": cfg["enabled"], "origin": cfg["origin"] if cfg["enabled"] else "",
            "desktop": cfg["desktop_origin"], "port": cfg["port"], "listening": bool(share_servers),
            "settings": env, "hostKey": await relay.pinned(), "publicKey": relay.public_key(),
            "tunnelKey": await relay.key_fingerprint(),
            "tunnel": relay.tunnel.status(), "vpsScript": relay.vps_script(),
            "active": sum(1 for x in shares.listing() if x["active"])}


async def sharing_api(req: Request, parts: list[str], w):
    """Settings, Sharing relay: save (pinning the VPS's host key once you
    confirm its fingerprint), the tunnel on / off, the end-to-end check, off."""
    m = req.method
    if parts == [] and m == "GET":
        return await send_json(w, await sharing_status())
    if parts == ["check"] and m == "POST":
        return await send_json(w, await sharing_check())
    if sharing_lock.locked():
        return await send_json(w, {"error": "The relay is already being changed"}, 409)
    async with sharing_lock:
        if parts == [] and m == "PUT":
            try:
                body = json.loads(req.body or b"{}")
                cfg = relay.clean(body)
                host = relay.known_host(cfg["vps"], cfg["sshPort"])
                pin = await relay.pinned()
                if body.get("repin") or pin.get("host") != host:
                    line, fp = await relay.scan(cfg["vps"], cfg["sshPort"])
                    if body.get("fingerprint") != fp:
                        return await send_json(w, {"confirm": {"host": host, "fingerprint": fp}})
                    relay.pin(line)
                    shares.log(f"relay: pinned {host}'s host key {fp}")
                await relay.ensure_key()
                was = relay.settings()
                relay.write_env(cfg, was["tunnel"] or not was["vps"])
            except (ValueError, json.JSONDecodeError, RuntimeError, OSError, TimeoutError) as e:
                return await send_json(w, {"error": str(e)}, 400)
        elif parts == ["tunnel"] and m == "POST":
            if not relay.tunnel.ready():
                return await send_json(w, {"error": "Save the relay's settings first"}, 409)
            relay.set_tunnel(bool(json.loads(req.body or b"{}").get("on")))
        elif parts == [] and m == "DELETE":
            await relay.tunnel.stop()
            relay.forget()
            shares.log("relay: turned off (settings removed)")
        else:
            return await respond(w, 404, "Not found\n")
        await reopen_share_listener()
        await relay.tunnel.apply()
    return await send_json(w, await sharing_status())


async def sharing_check() -> dict:
    """GET <origin>/__relay/ping through the VPS, for the share name and the
    desktop's: DNS, the TLS certificate (Cloudflare's or Caddy's), Caddy and the tunnel."""
    cfg = shares.config()
    if not cfg["enabled"]:
        return {"ok": False, "error": "Sharing isn't set up yet"}
    cloudflare = relay.settings()["cloudflare"]
    results = [await probe(cfg["origin"], cloudflare)]
    if cfg["desktop_origin"]:
        results.append(await probe(cfg["desktop_origin"], cloudflare))
    bad = [r for r in results if not r["ok"]]
    return {"ok": not bad, "url": " and ".join(r["url"].split("/__")[0] for r in results),
            "error": " ".join(f"{r['url'].split('/__')[0]}: {r['error']}" for r in bad)}


async def probe(origin: str, cloudflare: bool) -> dict:
    nonce = secrets.token_hex(8)
    url = f"{origin}/__relay/ping?n={nonce}"

    def fetch():
        import urllib.error
        import urllib.request

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
        try:
            with opener.open(urllib.request.Request(url, headers={"User-Agent": "agent-sandboxes"}), timeout=15) as r:
                return r.status, dict(r.headers), r.read(200).decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read(200).decode(errors="replace")
    try:
        status, headers, body = await asyncio.to_thread(fetch)
    except Exception as e:
        reason = getattr(e, "reason", e)
        err = f"{type(e).__name__}: {reason}"
        if "SSL" in err or "handshake" in err.lower():
            host = origin.split("://", 1)[1].split(":")[0]
            if cloudflare and host.count(".") >= 3:
                err += (f". Cloudflare's free certificate covers your domain and one level below it "
                        f"(*.example.com), not {host}: use a name one level down, e.g. "
                        f"{host.replace('.', '-', 1)}, or Cloudflare's Advanced Certificate Manager.")
            else:
                err += ". The TLS handshake failed: the certificate for this name isn't ready (Caddy's log on the VPS)."
        return {"ok": False, "url": url, "error": err}
    ok = status == 200 and body.strip() == f"aio-share {nonce}"
    return {"ok": ok, "url": url, "error": "" if ok else check_advice(status, headers, body, url)}


def check_advice(status: int, headers: dict, body: str, url: str) -> str:
    """What a failed relay check most likely means, Cloudflare in front or not."""
    h = {k.lower(): v for k, v in headers.items()}
    cf = h.get("server", "").lower() == "cloudflare" or "cf-ray" in h
    loc = h.get("location", "")
    if status in (301, 302, 307, 308) and loc.split("?")[0] == url.split("?")[0]:
        return (f"HTTP {status}: redirected to itself. " + (
            "Cloudflare's SSL/TLS mode is Flexible, so it reaches the VPS over plain HTTP and Caddy sends it back "
            "to HTTPS, in a loop. Set SSL/TLS to Full (strict) for these names (zone-wide, or a Configuration "
            "Rule for just them)." if cf else "Something in front of Caddy reaches it over plain HTTP."))
    if status in (301, 302, 307, 308):
        return f"HTTP {status}: redirected to {loc[:120]}"
    if cf and status == 526:
        return ("Cloudflare 526: the VPS's certificate isn't valid yet. Caddy may still be getting it from "
                "Let's Encrypt: see journalctl -u caddy on the VPS.")
    if cf and status == 525:
        return "Cloudflare 525: no TLS handshake with the VPS. Is Caddy running, with a site for this name?"
    if cf and status in (521, 522, 523):
        return f"Cloudflare {status}: it can't reach the VPS on 443 (Caddy down, a firewall, or the DNS record's IP)."
    if status == 502:
        return "HTTP 502: Caddy is up but the tunnel isn't (see the tunnel state above)."
    if status == 200:
        return f"Something else answered: {body[:80]!r}"
    return f"HTTP {status}{' from Cloudflare' if cf else ''}: {body[:80]!r}"


async def reopen_share_listener():
    """The share listener, when sharing is set up (and only then); its port can change."""
    cfg = shares.config()
    want = cfg["port"] if cfg["enabled"] else None
    have = share_servers[0].sockets[0].getsockname()[1] if share_servers else None
    if want == have:
        return
    while share_servers:
        srv = share_servers.pop()
        srv.close()
        for sid in {x["id"] for x in shares.listing()}:
            shares.end_guests(sid)
        await srv.wait_closed()
        print("Sharing: listener closed", flush=True)
    if want is None:
        return
    try:
        share_servers.append(await asyncio.start_server(lambda r, w: handle(r, w, share=True), "127.0.0.1",
                                                        want, limit=MAX_HEAD))
        print(f"Sharing: guests at {cfg['origin']} (listening on 127.0.0.1:{want})", flush=True)
    except OSError as e:
        print(f"Sharing: can't listen on 127.0.0.1:{want}: {e.strerror}", flush=True)


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


# --------------------------------------------------------------- the proxy service
# The HTTP API bridge, the port filters and the container proxies / forwarders
# run in ui/proxyd.py (unit agent-sandboxes-proxy), so a restart of this server
# leaves sandbox connections alone. It follows the workspace files by itself;
# we ask it to catch up at once after changing them.

async def proxyd(req: dict, timeout: float = 30) -> dict:
    """One request to the proxy service on its control socket."""
    try:
        r, w = await asyncio.wait_for(asyncio.open_unix_connection(str(PROXYD_SOCK)), 5)
        try:
            w.write(json.dumps(req).encode() + b"\n")
            await w.drain()
            return json.loads(await asyncio.wait_for(r.readline(), timeout))
        finally:
            w.close()
    except (OSError, ValueError, asyncio.TimeoutError) as e:
        return {"error": f"The proxy service isn't answering ({getattr(e, 'strerror', None) or type(e).__name__}); "
                         "see systemctl status agent-sandboxes-proxy"}


async def sync_proxies(name: str | None = None, restart: bool = False) -> list[str]:
    """Have the proxy service apply the workspace files now; `restart`
    reloads `name`'s container proxy. Returns its problems (all, or name's)."""
    res = await proxyd({"op": "sync", "restart": [name] if restart and name else []})
    if "error" in res:
        return [res["error"]]
    errors = res.get("errors", {})
    return errors.get(name, []) if name else [m for v in errors.values() for m in v]


async def proxyd_startup():
    """Bring the proxy service up to date with the files (they may have
    changed while this server was down) and say if it runs older code."""
    for attempt in range(30):
        res = await proxyd({"op": "sync"})
        if "error" not in res or attempt == 29:
            break
        await asyncio.sleep(2)
    if "error" in res:
        print(res["error"], flush=True)
        return
    for msg in (m for v in res.get("errors", {}).values() for m in v):
        print(f"proxy service: {msg}", flush=True)
    if res.get("version") != proxyd_source_version():
        print("proxy service runs older code than ui/proxyd.py / ui/common.py: "
              "sudo systemctl restart agent-sandboxes-proxy (drops open sandbox connections)", flush=True)


# --------------------------------------------------------------- HTTP API bridge
# Token routes for http:// APIs point at the proxy service's bridge (ui/proxyd.py).

def bridge_upstream(tid: str, upstream: str) -> str:
    if not upstream.startswith("http://"):
        return upstream
    host, port = HTTP_BRIDGE
    return f"http://{host}:{port}/{tid}{urllib.parse.urlsplit(upstream).path}"


# --------------------------------------------------------------- container network
# Access tab -> Container network "filtered": the AIO container gets the same
# allowlist and API tokens as Claude. compose() adds a generated override:
# an internal network (no route out, no published port) with the container
# at .2, and an env file pointing everything (GOST for Chromium via
# PROXY_SERVER, shells via HTTP(S)_PROXY) at a nono proxy we run on the
# gateway .1 with the workspace's profile. Its password is also the token
# placeholder there. 127.0.0.1:<sandbox port> is forwarded to .2:8080, so MCP
# and the UI reach the container as before.


def container_override_path(name: str) -> Path:
    return WS_ROOT / f"{name}.compose-filtered.yaml"


def container_limits_path(name: str) -> Path:
    return WS_ROOT / f"{name}.compose-limits.yaml"


def browser_memory_mb(pol: dict) -> int:
    return mem_mb(pol["limits"]["browser_memory"] or BROWSER_MEMORY)


def container_limits_text(pol: dict) -> str:
    """The AIO container's size (Access tab -> Resource limits). /dev/shm
    (Chromium's) is charged to the container's memory, so it gets the same size."""
    mb = browser_memory_mb(pol)
    return f"""# Generated by agent-sandboxes (Access tab -> Resource limits). Don't edit.
services:
  sandbox:
    mem_limit: "{mb}m"
    shm_size: "{mb}m"
    cpus: "{pol['limits']['browser_cpus'] or BROWSER_CPUS}"
"""


async def apply_container_limits(ws: dict[str, str], old: dict, pol: dict, notes: list[str]) -> list[str]:
    """After a policy save: recreate a running container whose size changed
    (shm_size can't change in place)."""
    keys = ("browser_memory", "browser_cpus")
    if all(old["limits"][k] == pol["limits"][k] for k in keys) or not await container_running(ws["WS_NAME"]):
        return []
    if any(n.startswith("Container recreated") for n in notes):    # already, with these files
        return []
    rc, out, err = await run(*compose(ws, "up", "-d", "--remove-orphans"), timeout=600)
    return ["Container recreated with the new limits (its browser session restarts)." if rc == 0
            else f"Recreating the container failed: {(err or out).strip()[-300:]}"]


def container_env_path(name: str) -> Path:
    return WS_ROOT / f"{name}.container.env"


def container_ca(name: str) -> tuple[Path, Path]:
    """The workspace's persistent CA for its container proxy's TLS interception
    (token routes at their real HTTPS URL). Key stays in secrets/; the
    container only gets the certificate."""
    crt, key = container_ca_paths(name)
    if not (crt.is_file() and key.is_file()):
        CONTAINER_PROXY_SECRETS.mkdir(mode=0o700, parents=True, exist_ok=True)
        old = os.umask(0o077)
        try:
            subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                            "-out", str(key)], check=True, capture_output=True)
            subprocess.run(["openssl", "req", "-x509", "-new", "-key", str(key), "-out", str(crt), "-days", "3650",
                            "-subj", f"/CN=agent-sandboxes {name} container proxy CA",
                            "-addext", "basicConstraints=critical,CA:TRUE",
                            "-addext", "keyUsage=critical,keyCertSign,cRLSign"], check=True, capture_output=True)
        finally:
            os.umask(old)
    return crt, key


def container_ca_files(name: str) -> tuple[Path, Path]:
    """Public copies the container mounts: the PEM (system store) and a
    Chromium managed policy trusting it (Chromium ignores the system store)."""
    return WS_ROOT / f"{name}.container-ca.crt", WS_ROOT / f"{name}.container-ca-policy.json"


def container_password(name: str) -> str:
    path = container_password_path(name)
    try:
        return path.read_text().strip()
    except FileNotFoundError:
        CONTAINER_PROXY_SECRETS.mkdir(mode=0o700, parents=True, exist_ok=True)
        pw = secrets.token_hex(32)
        private_write(path, pw)
        return pw


def container_env_text(ws: dict[str, str], pol: dict, gw: str | None = None,
                       port: int = CONTAINER_PROXY_PORT) -> str:
    """The AIO container's environment: everything through the workspace proxy
    (on its Docker gateway; in a microVM, the guest's relay on Docker's bridge)."""
    gw = gw or container_net(ws)[1]
    pw = container_password(ws["WS_NAME"])
    proxy = f"http://nono:{pw}@{gw}:{port}"
    no_proxy = f"localhost,127.0.0.1,{gw}"     # the token routes are plain requests to the proxy
    bundle = "/etc/ssl/certs/ca-certificates.crt"      # with the proxy CA, after the init hook
    env = {"PROXY_SERVER": f"nono:{pw}@{gw}:{port}",   # AIO's GOST -> Chromium
           "HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "http_proxy": proxy, "https_proxy": proxy,
           "NO_PROXY": no_proxy, "no_proxy": no_proxy,
           # AIO runs this as root at every start: add the mounted proxy CA to the system store
           "RUN_HOOK_INIT": "update-ca-certificates",
           "NODE_EXTRA_CA_CERTS": CONTAINER_CA_MOUNT, "REQUESTS_CA_BUNDLE": bundle, "PIP_CERT": bundle,
           "NODE_USE_ENV_PROXY": "1"}      # Node's own fetch honours HTTPS_PROXY (as nono sets for Claude)
    for tid in pol["tokens"]:
        if (meta := token_meta(tid)) and meta["service"] == "plain":
            if (v := plain_value(tid)) is not None:
                env[meta["env_var"]] = v
        elif meta:
            env[meta["env_var"]] = pw
            env[base_url_var(tid)] = f"http://{gw}:{port}/pool_{tid.replace('-', '_')}"
    return "# Generated by agent-sandboxes (Access tab -> Container network). Don't edit.\n" + \
        "".join(f"{k}={v}\n" for k, v in env.items())


def container_override_text(ws: dict[str, str]) -> str:
    subnet, gw, ip = container_net(ws)
    ca_crt, ca_policy = container_ca_files(ws["WS_NAME"])
    return f"""# Generated by agent-sandboxes (Access tab -> Container network: filtered). Don't edit.
# No route out and no published port: the container reaches the world only
# through its nono proxy on {gw}:{CONTAINER_PROXY_PORT}; the web UI forwards 127.0.0.1:{ws['WS_PORT']} to it.
services:
  sandbox:
    ports: !reset []
    networks:
      ws:
        ipv4_address: {ip}
    env_file:
      - {container_env_path(ws['WS_NAME'])}
    volumes:
      - {ca_crt}:{CONTAINER_CA_MOUNT}:ro
      - {ca_policy}:/etc/chromium/policies/managed/agent-sandboxes-proxy-ca.json:ro
networks:
  ws:
    internal: true
    ipam:
      config:
        - subnet: {subnet}
          gateway: {gw}
"""


def write_if_changed(path: Path, text: str) -> bool:
    try:
        if path.read_text() == text:
            return False
    except OSError:
        pass
    private_write(path, text)
    return True


def write_container_files(ws: dict[str, str]) -> bool:
    """Bring the override, env file and proxy profile in line with the
    policy. Returns whether the container is filtered."""
    name = ws["WS_NAME"]
    pol = load_policy(name)
    if is_microvm(ws):
        # The proxy service runs the VM's nono proxy with these; no container
        container_ca(name)
        container_password(name)
        write_if_changed(container_profile_path(name), profile_text(ws))
        return False
    if pol["network"]["container"] != "filtered":
        for p in (container_override_path(name), container_env_path(name), container_profile_path(name),
                  *container_ca_files(name)):
            p.unlink(missing_ok=True)
        return False
    crt, _ = container_ca(name)
    pem = crt.read_text()
    der = ssl.PEM_cert_to_DER_cert(pem)
    ca_crt, ca_policy = container_ca_files(name)
    write_if_changed(ca_crt, pem)
    write_if_changed(ca_policy, json.dumps({"CACertificates": [base64.b64encode(der).decode()]}) + "\n")
    for p in (ca_crt, ca_policy):
        p.chmod(0o644)       # public; read by the container's root and Chromium
    write_if_changed(container_env_path(name), container_env_text(ws, pol))
    write_if_changed(container_override_path(name), container_override_text(ws))
    write_if_changed(container_profile_path(name), profile_text(ws))
    return True


# --------------------------------------------------------------- microVM workspaces
# WS_KIND=microvm: Claude runs as root-capable `dev` in a VM (bin/microvm) with
# no network interface. Its HTTP(S)_PROXY is the guest's relay on
# 127.0.0.1:3128, which goes over vsock to the proxy service and on to the
# workspace's nono proxy (the same profile, CA and password as a filtered
# container's). The guest gets those settings on a read-only config disk,
# rebuilt at every start from vm/<name>/config/.

def vm_dir(name: str) -> Path:
    return VM_ROOT / name


def vm_memory_mb(pol: dict) -> int:
    if pol["limits"]["memory"]:
        return mem_mb(pol["limits"]["memory"])
    return VM_BROWSER_HEADROOM_MB + browser_memory_mb(pol) if pol["vm_browser"] else mem_mb(VM_DEFAULT_MEMORY)


def vm_vcpus(pol: dict) -> int:
    return pol["limits"]["cpus"] or VM_VCPUS


def vm_disk_gb(pol: dict) -> int:
    """The size bin/microvm grows the VM's (sparse) disk to; it never shrinks."""
    disk = pol["limits"]["disk"]
    return int(disk[:-1]) if disk else VM_BROWSER_DISK_GB if pol["vm_browser"] else VM_DISK_GB


def vm_proxy_env_text(ws: dict[str, str], pol: dict) -> str:
    pw = container_password(ws["WS_NAME"])
    relay = f"127.0.0.1:{VM_RELAY_PORT}"
    proxy = f"http://nono:{pw}@{relay}"
    bundle = "/etc/ssl/certs/ca-certificates.crt"
    env = {"HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "http_proxy": proxy, "https_proxy": proxy,
           "NO_PROXY": "localhost,127.0.0.1", "no_proxy": "localhost,127.0.0.1",
           "NODE_EXTRA_CA_CERTS": VM_GUEST_CA, "REQUESTS_CA_BUNDLE": bundle, "PIP_CERT": bundle,
           "NODE_USE_ENV_PROXY": "1", "AIO_WORKSPACE": ws["WS_NAME"]}
    if pol["vm_browser"]:     # .mcp.json's aio-sandbox server: the container in the VM
        env.update({"AIO_PORT": str(VM_BROWSER_PORT), "AIO_KEY": ws["WS_KEY"]})
    for tid in pol["tokens"]:
        if (meta := token_meta(tid)) and meta["service"] == "plain":
            if (v := plain_value(tid)) is not None:
                env[meta["env_var"]] = v
        elif meta:
            env[meta["env_var"]] = pw
            env[base_url_var(tid)] = f"http://{relay}/pool_{tid.replace('-', '_')}"
    if pol["builds"]:
        env.update({"AIO_BUILD_KEY": pw, "AIO_BUILD_BASE_URL": f"http://{relay}/{builds.ROUTE}"})
    return "".join(f"{k}={v}\n" for k, v in env.items())


def aio_image() -> str:
    """The AIO Sandbox image compose.workspace.yaml pins."""
    m = re.search(r"^\s*image:\s*(\S+)", COMPOSE_FILE.read_text(), re.M)
    return m[1] if m else ""


def vm_browser_compose_text(ws: dict[str, str], pol: dict) -> str:
    """The AIO container inside the VM, as compose.workspace.yaml has it on the
    host, but on the guest's Docker bridge, through the guest's relay."""
    return f"""# Generated by agent-sandboxes (Access tab -> Browser container in the VM). Don't edit.
services:
  sandbox:
    image: {aio_image()}
    container_name: aio-browser
    security_opt:
      - seccomp:unconfined
    restart: unless-stopped
    shm_size: "{browser_memory_mb(pol)}m"
    mem_limit: "{browser_memory_mb(pol)}m"
    cpus: "{pol['limits']['browser_cpus'] or min(BROWSER_CPUS, vm_vcpus(pol))}"
    network_mode: bridge
    ports:
      - "127.0.0.1:{VM_BROWSER_PORT}:8080"
    env_file:
      - /run/aio-config/browser.env
    environment:
      SANDBOX_API_KEY: {ws['WS_KEY']}
      TZ: Etc/UTC
      WORKSPACE: /home/gem/workspace
      DISABLE_JUPYTER: "true"
      DISABLE_CODE_SERVER: "false"
    volumes:
      - /project:/home/gem/workspace
      - /run/aio-config/ca.crt:{CONTAINER_CA_MOUNT}:ro
      - /run/aio-config/chromium-ca-policy.json:/etc/chromium/policies/managed/agent-sandboxes-proxy-ca.json:ro
"""


def ensure_ws_key(ws: dict[str, str]) -> dict[str, str]:
    """The AIO API key (microVM workspaces made before the browser option have none)."""
    if ws.get("WS_KEY"):
        return ws
    path = WS_ROOT / f"{ws['WS_NAME']}.env"
    with open(path, "a") as f:
        f.write(f"WS_KEY={secrets.token_hex(32)}\n")
    return read_env(path)


def vm_host_profile(ws: dict[str, str]) -> dict:
    """nono profile for QEMU on the host: its own files, /dev/kvm and
    /dev/vhost-vsock, the virtiofsd socket; no network, no other sockets."""
    d = vm_dir(ws["WS_NAME"])
    return {
        "meta": {"name": f"vm-{ws['WS_NAME']}", "version": "1.0.0",
                 "description": f"Generated by agent-sandboxes: QEMU for microVM workspace {ws['WS_NAME']}"},
        "extends": "default",
        "linux": {"af_unix_mediation": "pathname"},
        "filesystem": {"allow": [str(d)], "allow_file": ["/dev/kvm", "/dev/vhost-vsock"],
                       "read": [p for p in QEMU_DATA if os.path.isdir(p)],
                       "unix_socket": [str(d / "vfs.sock")]},
        "network": {"block": True},
    }


def vm_apt_hosts() -> list[str]:
    """The archive hosts the guest's apt uses (bin/microvm-image takes the host's)."""
    hosts = []
    try:
        for line in Path("/etc/apt/sources.list.d/ubuntu.sources").read_text().splitlines():
            if line.startswith("URIs:"):
                hosts += [urllib.parse.urlsplit(u).hostname for u in line.split()[1:]]
    except OSError:
        pass
    # and Docker images' own (ubuntu:*, for apt in a docker build)
    return [h for h in dict.fromkeys(hosts + ["security.ubuntu.com", "archive.ubuntu.com"]) if h]


def vm_problems() -> list[str]:
    """What's missing on this host for microVM workspaces."""
    out = []
    for tool, pkg in (("qemu-system-x86_64", "qemu-system-x86"), ("/usr/libexec/virtiofsd", "virtiofsd"),
                      ("mke2fs", "e2fsprogs")):
        if not shutil.which(tool):
            out.append(f"{tool} is missing (sudo apt install {pkg})")
    if not os.path.exists("/dev/kvm"):
        out.append("/dev/kvm is missing (no hardware virtualisation: enable nested virtualisation for this VM)")
    try:
        user = pwd.getpwuid(os.getuid()).pw_name
        if user not in grp.getgrnam("kvm").gr_mem and os.getgid() != grp.getgrnam("kvm").gr_gid:
            out.append(f"{user} isn't in the kvm group (sudo usermod -aG kvm {user})")
    except KeyError:
        out.append("there's no kvm group")
    if not all((VM_BASE / f).is_file() for f in VM_DISK_FILES):
        out.append("no microVM image yet (run bin/microvm-image)")
    return out


def vm_prepare(name: str) -> None:
    """Everything bin/microvm start needs: the VM's own copy of the image
    (first time), its ssh key, the config disk's contents, QEMU's nono profile
    and vm.env, and the workspace proxy's files."""
    ws = load_ws(name)
    if not is_microvm(ws):
        raise SystemExit(f"'{name}' isn't a microVM workspace")
    pol = load_policy(name)
    d = vm_dir(name)
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not all((d / f).is_file() for f in VM_DISK_FILES):
        if missing := [f for f in VM_DISK_FILES if not (VM_BASE / f).is_file()]:
            raise SystemExit(f"No microVM image ({', '.join(missing)} missing in {VM_BASE}): run bin/microvm-image")
        for f in VM_DISK_FILES:      # the kernel too: its modules are on this disk
            subprocess.run(["cp", "--sparse=always", "--reflink=auto", str(VM_BASE / f), str(d / f)], check=True)
            (d / f).chmod(0o600)
    key = d / "id_ed25519"
    if not key.is_file():
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"agent-sandboxes {name} host",
                        "-f", str(key)], check=True)
    ws = ensure_ws_key(ws)
    write_container_files(ws)                     # the proxy's profile, CA and password
    crt, _ = container_ca(name)
    pem = crt.read_text()
    cfg = d / "config"
    cfg.mkdir(mode=0o700, exist_ok=True)
    write_if_changed(cfg / "hostname", name + "\n")
    write_if_changed(cfg / "authorized_keys", (d / "id_ed25519.pub").read_text())
    write_if_changed(cfg / "proxy.env", vm_proxy_env_text(ws, pol))
    sync_builds_mcp(ws["WS_DIR"], pol["builds"])
    write_if_changed(cfg / "ca.crt", pem)
    browser = cfg / "browser-compose.yaml", cfg / "browser.env", cfg / "chromium-ca-policy.json"
    if pol["vm_browser"]:
        ensure_mcp_json(ws["WS_DIR"])
        der = ssl.PEM_cert_to_DER_cert(pem)
        write_if_changed(browser[0], vm_browser_compose_text(ws, pol))
        write_if_changed(browser[1], container_env_text(ws, pol, VM_BRIDGE, VM_RELAY_PORT))
        write_if_changed(browser[2], json.dumps({"CACertificates": [base64.b64encode(der).decode()]}) + "\n")
    else:
        for p in browser:
            p.unlink(missing_ok=True)
    write_if_changed(d / "host-profile.json", json.dumps(vm_host_profile(ws), indent=2) + "\n")
    write_if_changed(d / "vm.env", f"VM_CID={vm_cid(ws)}\nVM_MEMORY_MB={vm_memory_mb(pol)}\n"
                                   f"VM_VCPUS={vm_vcpus(pol)}\nWS_DIR={shlex.quote(ws['WS_DIR'])}\n"
                                   f"VM_DISK_GB={vm_disk_gb(pol)}\n"
                                   f"VM_BROWSER={int(pol['vm_browser'])}\n"
                                   f"VM_BROWSER_IMAGE={shlex.quote(aio_image())}\n")


async def vm_states() -> dict[str, str]:
    """systemd --user state of each aio-vm-<name> unit."""
    rc, out, _ = await run("systemctl", "--user", "list-units", "--all", "--plain", "--no-legend",
                           "--type=service", "aio-vm-*")
    states = {}
    for line in out.splitlines():
        f = line.split()
        if len(f) >= 4 and f[0].startswith("aio-vm-") and f[0].endswith(".service"):
            states[f[0][len("aio-vm-"):-len(".service")]] = f[2]
    return states


def vm_container_state(name: str, unit_state: str | None) -> str:
    """In the UI's container terms."""
    if unit_state == "active":
        return "running"
    if unit_state in ("activating", "reloading"):
        return "restarting"
    if unit_state == "deactivating":
        return "exited"
    return "exited" if (vm_dir(name) / "rootfs.img").is_file() else "absent"


async def apply_vm_policy(ws: dict[str, str], old: dict, pol: dict) -> list[str]:
    """After a policy save: the VM's proxy takes allowlist changes at once; token
    variables and memory are on the config disk / QEMU's command line."""
    name = ws["WS_NAME"]
    write_container_files(ws)
    notes = await sync_proxies(name, restart=True)
    sized = {k: v for k, v in old["limits"].items() if k != "pids"} != \
        {k: v for k, v in pol["limits"].items() if k != "pids"}
    if (old["tokens"] != pol["tokens"] or sized
            or old["vm_browser"] != pol["vm_browser"]) and (await vm_states()).get(name) == "active":
        notes.append("Network changes apply now; restart the VM (Stop, then Start) for token, memory, CPU, "
                     "disk or browser container changes.")
    if pol["vm_browser"] and not old["vm_browser"]:
        notes.append("The first start with the browser container copies its image (about 13 GB) into the VM: "
                     "the Browser tab works a few minutes after that.")
    return notes


async def container_running(name: str) -> bool:
    rc, out, _ = await run("docker", "inspect", "-f", "{{.State.Running}}", container(name))
    return rc == 0 and out.strip() == "true"


async def apply_container_network(ws: dict[str, str], old: dict) -> list[str]:
    """After a policy save: recreate the container if its network or env
    changed (it's running), restart its proxy if only the profile did."""
    name = ws["WS_NAME"]
    was = old["network"]["container"] == "filtered"
    now = container_filtered(name)
    notes = []
    if not was and not now:
        return notes
    old_env = container_env_path(name).read_text() if container_env_path(name).exists() else None
    running = await container_running(name)
    if was and not now:
        notes += await sync_proxies(name)     # forwarder gone: Docker publishes the port again
    files = compose(ws, "up", "-d", "--remove-orphans")     # rewrites the files
    env_changed = now and container_env_path(name).read_text() != old_env
    if running and (was != now or env_changed):
        rc, out, err = await run(*files, timeout=600)
        notes.append("Container recreated with the new network settings." if rc == 0
                     else f"Recreating the container failed: {(err or out).strip()[-300:]}")
    if now:
        notes += await sync_proxies(name, restart=True)
    return notes


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
        write_container_files(ws)        # the container proxies' profiles, for the proxy service
        await open_sandbox_listener(ws)
    try:
        mcp_server = await builds.serve_mcp(load_ws, lambda n: load_policy(n)["builds"])
    except OSError as e:          # the UI runs on without the agents' build tools
        print(f"Apple builds: no MCP socket at {builds.MCP_SOCK}: {e}", flush=True)
        mcp_server = None
    await reopen_share_listener()
    await relay.tunnel.apply()
    builds.monitor.start()
    drop_ambient_caps()
    for addr in BIND:
        print(f"Agent Sandboxes UI on {SCHEME}://{addr}:{LISTEN_PORT}/", flush=True)
    await asyncio.gather(renew_daily(), backup_scheduler(), proxyd_startup(), shares.expiry_watch(),
                         *(s.serve_forever() for s in servers + ([mcp_server] if mcp_server else [])))


def cli_prepare(name: str, aux: bool = False):
    """bin/claude-in calls this (outside nono) and evals the output."""
    info = asyncio.run(prepare(name, aux))
    print(f"WS_PROFILE={shlex.quote(info['profile'])}")
    print(f"WS_MEMORY={shlex.quote(info['memory'])}")
    print(f"WS_PIDS={int(info['pids'])}")
    print(f"WS_CPUS={int(info['cpus'])}")
    print(f"WS_PROMPT={shlex.quote(info['prompt'])}")


if __name__ == "__main__":
    if sys.argv[1:2] == ["vm-prepare"] and len(sys.argv) == 3:
        ensure_dirs()
        vm_prepare(sys.argv[2])
        sys.exit(0)
    if sys.argv[1:2] == ["prepare"] and len(sys.argv) in (3, 4) and sys.argv[3:] in ([], ["--aux"]):
        cli_prepare(sys.argv[2], aux=sys.argv[3:] == ["--aux"])
        sys.exit(0)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
