"""Shared by the web UI (server.py) and the proxy service (proxyd.py): paths,
workspace and policy files, and the network helpers both sides need.

The proxy service loads this once at start, so a change here takes effect
there only after `sudo systemctl restart agent-sandboxes-proxy` (which drops
the connections open through it); the UI warns when the two differ.
"""

import ctypes
import hashlib
import ipaddress
import json
import os
import re
import signal
from pathlib import Path

ROOT = Path(os.environ.get("AIO_ROOT", Path.home() / "agent-sandboxes"))
WS_ROOT = ROOT / "workspaces"
SECRETS = ROOT / "secrets"              # key/token pool; never readable inside nono
SSH_POOL = SECRETS / "ssh"
TOKEN_POOL = SECRETS / "tokens"
RUNTIME = Path(os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}") / "agent-sandboxes"
PROXYD_SOCK = RUNTIME / "proxyd.sock"   # the proxy service's control socket (the UI's requests)
SANDBOX_PORTS = range(8101, 8200)
EGRESS_PORT_OFFSET = -1000        # a workspace's port filter (host:port allow entries) is on 7101
# nono only injects tokens into plain-HTTP upstreams on loopback: HTTP API
# tokens go to this bridge (127.0.0.2: loopback, but not in nono's NO_PROXY)
HTTP_BRIDGE = ("127.0.0.2", int(os.environ.get("AIO_BRIDGE_PORT", "7100")))
# Container network "filtered": the AIO container sits on an internal Docker
# network (10.231.<port-8100>.0/24, no route out) and reaches the world only
# through its own nono proxy on the gateway, with the workspace's profile.
CONTAINER_NET = os.environ.get("AIO_CONTAINER_NET", "10.231")
CONTAINER_PROXY_PORT = 3128
CONTAINER_PROXY_SECRETS = SECRETS / "container-proxy"   # per-workspace proxy password (= token placeholder there)
NONO_LOGS = ROOT / "monitoring" / "data" / "nono-logs"   # nono's --log-file (bin/claude-in, container proxies)
# microVM workspaces (WS_KIND=microvm): Claude runs in a VM with no network
# interface; its only way out is vsock to the proxy service (port VM_RELAY_PORT),
# which hands it to the workspace's nono proxy on 127.0.0.1:<sandbox port - 2000>.
VM_ROOT = ROOT / "vm"                  # base/ image, <name>/ disk, config, key (bin/microvm)
VM_RELAY_PORT = 3128
VM_PROXY_OFFSET = -2000
VM_CID_BASE = 1000                     # guest CID = 1000 + slot (sandbox port 8101 -> CID 1001)
VM_BROWSER_PORT = 8080                 # the AIO container in the VM (Browser container ticked): guest vsock port
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,29}$")
ITEM_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")          # pool key / token ids
DOMAIN_RE = re.compile(r"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$")
MAX_HEAD = 64 * 1024
PROXYD_SOURCES = [Path(__file__).resolve(), Path(__file__).resolve().with_name("proxyd.py")]

DEFAULT_POLICY = {"ssh_keys": [], "tokens": [], "claude_md": False, "vm_browser": False,
                  "network": {"mode": "claude-code", "allow": [], "deny": [], "container": "open", "listen": []},
                  "limits": {"memory": "", "pids": 0}}


def die_with_parent():
    """preexec_fn: the child gets SIGTERM when we exit. A container proxy left
    behind would keep enforcing a stale policy and hold the next one's port;
    a backup's tar or smbclient would run on unwatched."""
    ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGTERM)    # PR_SET_PDEATHSIG


def proxyd_source_version() -> str:
    """Of the code on disk; the running proxy service reports the one it loaded."""
    h = hashlib.sha256()
    for p in PROXYD_SOURCES:
        h.update(p.read_bytes())
    return h.hexdigest()[:12]


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
    # <name>.env only (not e.g. <name>.container.env)
    return [read_env(p) for p in sorted(WS_ROOT.glob("*.env")) if NAME_RE.match(p.stem)]


def policy_path(name: str) -> Path:
    return WS_ROOT / f"{name}.policy.json"


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
    pol["claude_md"] = saved.get("claude_md") is True
    pol["vm_browser"] = saved.get("vm_browser") is True
    return pol


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


def token_meta(tid: str) -> dict | None:
    if not ITEM_RE.match(tid):
        return None
    try:
        return json.loads((TOKEN_POOL / f"{tid}.json").read_text())
    except (OSError, json.JSONDecodeError):
        return None


def egress_port(ws: dict[str, str]) -> int:
    return int(ws["WS_PORT"]) + EGRESS_PORT_OFFSET


def container_filtered(name: str) -> bool:
    return load_policy(name)["network"]["container"] == "filtered"


def is_microvm(ws: dict[str, str] | None) -> bool:
    return bool(ws) and ws.get("WS_KIND") == "microvm"


def vm_cid(ws: dict[str, str]) -> int:
    """Its vsock address, set by the host: the proxy service trusts it to pick the workspace."""
    return VM_CID_BASE + int(ws["WS_PORT"]) - SANDBOX_PORTS.start + 1


def vm_proxy_port(ws: dict[str, str]) -> int:
    return int(ws["WS_PORT"]) + VM_PROXY_OFFSET


def vm_browser(ws: dict[str, str]) -> bool:
    """A microVM workspace with the AIO browser container running in its VM."""
    return is_microvm(ws) and load_policy(ws["WS_NAME"])["vm_browser"]


def wants_ws_proxy(ws: dict[str, str]) -> bool:
    """Whether the proxy service runs a nono proxy for it (filtered container, or microVM)."""
    return is_microvm(ws) or container_filtered(ws["WS_NAME"])


def container_net(ws: dict[str, str]) -> tuple[str, str, str]:
    """(subnet, gateway = proxy address, container address)."""
    n = int(ws["WS_PORT"]) - SANDBOX_PORTS.start + 1
    return f"{CONTAINER_NET}.{n}.0/24", f"{CONTAINER_NET}.{n}.1", f"{CONTAINER_NET}.{n}.2"


def container_profile_path(name: str) -> Path:
    return WS_ROOT / f"{name}.container-profile.json"


def container_ca_paths(name: str) -> tuple[Path, Path]:
    """The container proxy's CA certificate and key (made by the UI)."""
    return CONTAINER_PROXY_SECRETS / f"{name}.ca.crt", CONTAINER_PROXY_SECRETS / f"{name}.ca.key"


def container_password_path(name: str) -> Path:
    return CONTAINER_PROXY_SECRETS / name
