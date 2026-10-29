#!/usr/bin/env python3
"""Agent Sandboxes network proxies (system unit agent-sandboxes-proxy).

The parts of the workspaces' network paths that run outside nono, kept out
of the web UI so that restarting the UI doesn't cut Claude's or the
containers' connections:
  - the HTTP API bridge (127.0.0.2:7100), for tokens on plain-HTTP APIs;
  - each workspace's port filter (127.0.0.1:<sandbox port - 1000>), nono's
    upstream_proxy when the allowlist has host:port entries;
  - for Container network "Same as Claude": the container's nono proxy on
    its Docker gateway, and 127.0.0.1:<sandbox port> forwarded to the
    container (MCP and the UI's sandbox view).

What runs follows the workspace files the UI writes (workspaces/*.env and
policies): rescanned every RESCAN seconds, and at once when the UI asks on
the control socket ($XDG_RUNTIME_DIR/agent-sandboxes/proxyd.sock: one JSON
request, one JSON reply). Per-connection decisions (allowed ports, token
upstreams) read the files each time. The container proxies' profiles, CAs
and passwords are the UI's to write; this only runs them.

Stdlib only. Restarting it drops the connections open through it.
"""

import asyncio
import ipaddress
import json
import os
import re
import signal
import socket
import sys
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (CONTAINER_PROXY_PORT, HTTP_BRIDGE, MAX_HEAD, NAME_RE, PROXYD_SOCK, RUNTIME,  # noqa: E402
                    all_ws, container_ca_paths, container_filtered, container_net, container_password_path,
                    container_profile_path, die_with_parent, egress_port, load_policy, load_ws, parse_net_entry,
                    proxyd_source_version, token_meta, unsafe_ip)


VERSION = proxyd_source_version()
STARTED = time.time()
RESCAN = 10                     # seconds between checks of the workspace files
egress_listeners: dict[str, asyncio.Server] = {}
bridge_server: asyncio.Server | None = None
problems: dict[tuple[str, str], str] = {}      # (workspace, part) -> current error
logged: set[tuple[str, str]] = set()
denied: dict[str, int] = {}                     # port-filter denials per workspace since start
sync_lock = asyncio.Lock()


def problem(name: str, part: str, msg: str | None):
    """Remember what's wrong with one part of a workspace (None: nothing now).
    Logged once, if it's still so at the next attempt: e.g. while the UI
    recreates a container, Docker holds its port for a moment."""
    key = (name, part)
    if msg is None:
        problems.pop(key, None)
        logged.discard(key)
    elif problems.get(key) != msg:
        problems[key] = msg
        logged.discard(key)
    elif key not in logged:
        logged.add(key)
        print(msg, flush=True)


# --------------------------------------------------------------- egress port filter
# nono's proxy allowlists hosts but not ports. When a workspace has host:port
# allow entries its profile sets this as nono's upstream_proxy: nono checks
# the host as usual, then sends us "CONNECT host:port" (plain HTTP too), and
# we refuse ports those entries don't list. Only nono's proxy can reach this
# listener: the sandbox may connect to its own open_port and the proxy alone.

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
            denied[name] = denied.get(name, 0) + 1
            print(f"port-filter workspace={name} decision=deny host={host} port={port}", flush=True)
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


async def open_egress_filter(ws: dict[str, str]):
    name, port = ws["WS_NAME"], egress_port(ws)
    try:
        egress_listeners[name] = await asyncio.start_server(
            lambda r, w: handle_egress(r, w, name), "127.0.0.1", port, limit=MAX_HEAD)
    except OSError as e:
        problem(name, "port-filter", f"Can't run the port filter for '{name}' on 127.0.0.1:{port}: {e.strerror}")
        return
    problem(name, "port-filter", None)


def close_egress_filter(name: str):
    if s := egress_listeners.pop(name, None):
        s.close()


# --------------------------------------------------------------- HTTP API bridge
# A token for an http:// API gets the nono route http://127.0.0.2:7100/<id><path>;
# nono adds the token and we relay to the real host. One request per
# connection (Connection: close both ways), so nono's keep-alive can't carry a
# request for one token on to another token's host. Only nono's proxy can
# reach this: it's not one of the sandbox's ports.

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


async def open_bridge():
    global bridge_server
    try:
        bridge_server = await asyncio.start_server(handle_bridge, *HTTP_BRIDGE, limit=MAX_HEAD)
    except OSError as e:
        problem("", "bridge", f"HTTP API bridge not running on {HTTP_BRIDGE[0]}:{HTTP_BRIDGE[1]}: {e.strerror}")
        return
    problem("", "bridge", None)


# --------------------------------------------------------------- container network
# Container network "Same as Claude" (policy "filtered"): the container sits on
# an internal Docker network and reaches the world only through a nono proxy
# on its gateway, run here with the profile the UI renders. Its password is
# also the token placeholder there. 127.0.0.1:<sandbox port> is forwarded to
# the container's .2:8080, so MCP and the UI reach it as before.

container_proxies: dict[str, asyncio.Task] = {}
container_proxy_procs: dict[str, asyncio.subprocess.Process] = {}
container_forwarders: dict[str, asyncio.Server] = {}


async def supervise_container_proxy(ws: dict[str, str]):
    """Keep the container's nono proxy running while the policy says filtered.
    It can only bind once Docker has created the network, so it retries."""
    name = ws["WS_NAME"]
    _, gw, _ = container_net(ws)
    last_err = None
    while load_ws(name) and container_filtered(name):
        ca_crt, ca_key = container_ca_paths(name)
        files = (container_profile_path(name), ca_crt, ca_key, container_password_path(name))
        if missing := [p.name for p in files if not p.is_file()]:
            msg = f"container-proxy {name}: waiting for {', '.join(missing)} (the web UI writes them)"
            if msg != last_err:
                print(msg, flush=True)
                last_err = msg
            await asyncio.sleep(3)
            continue
        proc = await asyncio.create_subprocess_exec(
            "nono", "proxy", "--silent", "--profile", str(container_profile_path(name)),
            "--listen", gw, "--port", str(CONTAINER_PROXY_PORT),
            "--proxy-ca-cert", str(ca_crt), "--proxy-ca-key", str(ca_key),
            env={**os.environ, "NONO_PROXY_PASS": container_password_path(name).read_text().strip()},
            stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE, preexec_fn=die_with_parent)
        container_proxy_procs[name] = proc
        started = time.monotonic()
        while line := await proc.stderr.readline():
            msg = re.sub(r"\x1b\[[0-9;]*m", "", line.decode(errors="replace")).strip()
            if msg and msg != last_err:
                print(f"container-proxy {name}: {msg[:300]}", flush=True)
                last_err = msg
        await proc.wait()
        container_proxy_procs.pop(name, None)
        if time.monotonic() - started > 30:
            last_err = None      # it ran fine for a while: report the next failure again
        await asyncio.sleep(3)
    container_proxies.pop(name, None)


def ensure_container_proxy(ws: dict[str, str]):
    name = ws["WS_NAME"]
    if container_filtered(name) and name not in container_proxies:
        container_proxies[name] = asyncio.create_task(supervise_container_proxy(ws))
    elif not container_filtered(name):
        restart_container_proxy(name)      # the supervisor sees the policy and stops


def restart_container_proxy(name: str):
    """The supervisor starts it again with the current profile."""
    if proc := container_proxy_procs.get(name):
        try:
            proc.terminate()
        except ProcessLookupError:
            pass


def stop_container_proxy(name: str):
    if task := container_proxies.pop(name, None):
        task.cancel()
    restart_container_proxy(name)


async def splice(r1, w1, r2, w2):
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
        await asyncio.gather(pump(r1, w2), pump(r2, w1))
    finally:
        w1.close()
        w2.close()


async def open_container_forwarder(ws: dict[str, str]):
    """127.0.0.1:<sandbox port> -> the filtered container, as Docker's
    published port would (internal networks can't publish)."""
    name, port = ws["WS_NAME"], int(ws["WS_PORT"])
    if name in container_forwarders:
        return
    _, _, ip = container_net(ws)

    async def forward(reader, writer):
        try:
            up_r, up_w = await asyncio.wait_for(asyncio.open_connection(ip, 8080), 10)
        except (OSError, asyncio.TimeoutError):
            writer.close()
            return
        await splice(reader, writer, up_r, up_w)

    try:
        container_forwarders[name] = await asyncio.start_server(forward, "127.0.0.1", port)
    except OSError as e:
        problem(name, "forwarder", f"Can't forward 127.0.0.1:{port} to '{name}''s container: {e.strerror}")
        return
    problem(name, "forwarder", None)


def close_container_forwarder(name: str):
    if s := container_forwarders.pop(name, None):
        s.close()


# --------------------------------------------------------------- following the workspace files

async def sync(restart: list[str] = ()) -> dict[str, list[str]]:
    """Run what the workspace files ask for and stop the rest. `restart`:
    workspaces whose container proxy should reload its profile."""
    async with sync_lock:
        if bridge_server is None:
            await open_bridge()
        seen = set()
        for ws in all_ws():
            name = ws.get("WS_NAME", "")
            if not (NAME_RE.match(name) and ws.get("WS_PORT", "").isdigit()):
                continue           # e.g. being written
            seen.add(name)
            if name not in egress_listeners:
                await open_egress_filter(ws)
            if container_filtered(name):
                await open_container_forwarder(ws)
                ensure_container_proxy(ws)
                if name in restart:
                    restart_container_proxy(name)
            else:
                close_container_forwarder(name)
                problem(name, "forwarder", None)
                stop_container_proxy(name)
        for name in (set(egress_listeners) | set(container_forwarders) | set(container_proxies)) - seen:
            close_egress_filter(name)
            close_container_forwarder(name)
            stop_container_proxy(name)
            denied.pop(name, None)
        for key in [k for k in problems if k[0] and k[0] not in seen]:
            del problems[key]
            logged.discard(key)
        out: dict[str, list[str]] = {}
        for (name, _), msg in problems.items():
            out.setdefault(name, []).append(msg)
        return out


async def rescan():
    while True:
        await asyncio.sleep(RESCAN)
        await sync()


def status() -> dict:
    return {"version": VERSION, "started": STARTED, "pid": os.getpid(),
            "bridge": bridge_server is not None,
            "port_filters": sorted(egress_listeners), "forwarders": sorted(container_forwarders),
            "container_proxies": {n: "running" if n in container_proxy_procs else "starting"
                                  for n in sorted(container_proxies)},
            "port_filter_denied": denied, "problems": [m for m in problems.values()]}


async def handle_control(reader, w):
    try:
        req = json.loads(await asyncio.wait_for(reader.readline(), 10))
        if req.get("op") == "sync":
            restart = [n for n in req.get("restart", []) if isinstance(n, str)]
            res = {"ok": True, "errors": await sync(restart), "version": VERSION}
        elif req.get("op") == "status":
            res = status()
        else:
            res = {"error": "unknown op"}
        w.write(json.dumps(res).encode() + b"\n")
        await w.drain()
    except (OSError, ValueError, AttributeError, asyncio.IncompleteReadError, asyncio.TimeoutError):
        pass
    finally:
        w.close()


async def main():
    RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
    PROXYD_SOCK.unlink(missing_ok=True)
    old = os.umask(0o077)
    try:
        control = await asyncio.start_unix_server(handle_control, str(PROXYD_SOCK))
    finally:
        os.umask(old)
    errors = await sync()
    print(f"Agent Sandboxes proxies {VERSION}: bridge {HTTP_BRIDGE[0]}:{HTTP_BRIDGE[1]}, "
          f"{len(egress_listeners)} port filter(s), {len(container_forwarders)} container forwarder(s)"
          + (f", {sum(map(len, errors.values()))} problem(s)" if errors else ""), flush=True)
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    tasks = [asyncio.create_task(rescan()), asyncio.create_task(control.serve_forever())]
    await stop.wait()
    for t in tasks:
        t.cancel()
    for name in list(container_proxies):
        stop_container_proxy(name)
    for proc in list(container_proxy_procs.values()):
        await proc.wait()
    PROXYD_SOCK.unlink(missing_ok=True)


if __name__ == "__main__":
    asyncio.run(main())
