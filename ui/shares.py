"""Sharing one workspace with someone online: share links, guest sessions.

A share gives one guest (by link) one workspace's Claude terminal, to watch
or to drive, and optionally its project files and the sandbox's browser
desktop, until it expires or is revoked. Guests reach the UI's separate
share listener (127.0.0.1:SHARE_PORT), which only ever serves guest routes;
bin/share-relay keeps it reachable from the internet through a reverse SSH
tunnel to your own VPS (Caddy there holds the public name and certificate).

Only a hash of each link's token is stored. Guest sessions (the asg cookie)
live in memory: after a UI restart the guest opens the link again.
"""

import asyncio
import hashlib
import json
import os
import re
import secrets
import time
from pathlib import Path

from common import ROOT

SHARES_FILE = ROOT / "ui" / "shares.json"
SHARE_ENV = ROOT / "ui" / "share.env"
SHARE_LOG = ROOT / "ui" / "shares.log"
COOKIE = "asg"
DEFAULT_PORT = 9443
RELAY_PORT = 18443                 # the VPS end of the tunnel (its 127.0.0.1), Caddy's upstream
TTLS = {"1h": 3600, "8h": 8 * 3600, "24h": 86400, "7d": 7 * 86400}
TERMINAL_MODES = ("view", "drive")
FILE_MODES = ("none", "download", "upload")
LABEL_RE = re.compile(r"^[^\x00-\x1f\x7f<>\"'&]{1,60}$")
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
ID_RE = re.compile(r"^[a-f0-9]{12}$")


def now() -> int:
    return int(time.time())


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def log(line: str):
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print(f"share: {line}", flush=True)
    try:
        fd = os.open(SHARE_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(f"{stamp} {line}\n")
    except OSError:
        pass


# ---------------------------------------------------------------- config (ui/share.env)

def config() -> dict:
    """SHARE_HOST / SHARE_DESKTOP_HOST: the public names (on the VPS);
    SHARE_PORT: the local listener; RELAY: user@vps (bin/share-relay)."""
    env = {}
    try:
        for line in SHARE_ENV.read_text().splitlines():
            k, sep, v = line.partition("=")
            if sep and not k.strip().startswith("#"):
                env[k.strip()] = v.strip().strip("'\"")
    except OSError:
        pass
    # host[:port]: the port only when guests use a non-default one (local testing)
    host, _, hport = env.get("SHARE_HOST", "").lower().partition(":")
    desktop, _, dport = env.get("SHARE_DESKTOP_HOST", "").lower().partition(":")
    try:
        port = int(env.get("SHARE_PORT") or os.environ.get("AIO_SHARE_PORT") or DEFAULT_PORT)
    except ValueError:
        port = DEFAULT_PORT
    scheme = "http" if env.get("SHARE_SCHEME") == "http" else "https"     # http: local testing only
    ok = bool(HOST_RE.match(host) or host in ("localhost", "127.0.0.1")) and (not hport or hport.isdigit())
    dok = desktop != host and bool(HOST_RE.match(desktop) or desktop.endswith(".localhost")) \
        and (not dport or dport.isdigit())
    return {"enabled": ok, "host": host if ok else "", "origin": f"{scheme}://{host}{':' + hport if hport else ''}",
            "port": port, "scheme": scheme, "desktop_host": desktop if ok and dok else "",
            "desktop_origin": f"{scheme}://{desktop}{':' + dport if dport else ''}" if ok and dok else "",
            "relay": env.get("RELAY", ""), "relay_port": RELAY_PORT}


# ---------------------------------------------------------------- shares

def load() -> dict:
    try:
        data = json.loads(SHARES_FILE.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save(shares: dict):
    tmp = SHARES_FILE.with_name(f".{SHARES_FILE.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(shares, indent=1) + "\n")
    os.replace(tmp, SHARES_FILE)


def active(s: dict | None) -> bool:
    return bool(s) and not s.get("revoked") and s.get("expires", 0) > now()


def clean(body: dict) -> dict:
    """The options of a new share, checked."""
    label = str(body.get("label") or "").strip()
    if not LABEL_RE.match(label):
        raise ValueError("Guest name: up to 60 characters (no < > \" ' &)")
    terminal = body.get("terminal", "view")
    if terminal not in TERMINAL_MODES:
        raise ValueError("Terminal: view or drive")
    files = body.get("files", "none")
    if files not in FILE_MODES:
        raise ValueError("Files: none, download or upload")
    desktop = body.get("desktop") is True
    if desktop and terminal != "drive":
        raise ValueError("The browser desktop is interactive: share it only with a guest who drives")
    ttl = body.get("expires", "8h")
    if ttl not in TTLS:
        raise ValueError(f"Expires: one of {', '.join(TTLS)}")
    return {"label": label, "terminal": terminal, "files": files, "desktop": desktop, "ttl": TTLS[ttl]}


def create(workspace: str, body: dict) -> tuple[dict, str]:
    opts = clean(body)
    shares = load()
    sid = secrets.token_hex(6)
    token = secrets.token_urlsafe(32)
    t = now()
    s = {"id": sid, "workspace": workspace, "label": opts["label"], "terminal": opts["terminal"],
         "files": opts["files"], "desktop": opts["desktop"], "created": t, "expires": t + opts["ttl"],
         "revoked": 0, "token_sha256": _hash(token), "cap": secrets.token_hex(20)}
    shares[sid] = s
    _prune(shares)
    save(shares)
    log(f"{sid} created for {workspace} ({s['label']}: terminal {s['terminal']}, files {s['files']}, "
        f"desktop {'on' if s['desktop'] else 'off'}, until {time.strftime('%Y-%m-%d %H:%M', time.localtime(s['expires']))})")
    return s, token


def _prune(shares: dict):
    """Forget shares that ended over a week ago."""
    cutoff = now() - 7 * 86400
    for k in [k for k, s in shares.items() if (s.get("revoked") or s.get("expires", 0)) < cutoff]:
        del shares[k]


def rotate(sid: str) -> tuple[dict, str] | None:
    """A new link (and desktop capability) for a share; the old one stops working."""
    shares = load()
    s = shares.get(sid)
    if not active(s):
        return None
    token = secrets.token_urlsafe(32)
    s["token_sha256"], s["cap"] = _hash(token), secrets.token_hex(20)
    save(shares)
    end_guests(sid)
    log(f"{sid} new link ({s['label']}); old link and guest sessions ended")
    return s, token


def revoke(sid: str) -> bool:
    shares = load()
    s = shares.get(sid)
    if not s:
        return False
    if not s.get("revoked"):
        s["revoked"] = now()
        save(shares)
        log(f"{sid} revoked ({s['label']}, {s['workspace']})")
    end_guests(sid)
    return True


def revoke_workspace(workspace: str) -> int:
    n = 0
    for sid, s in load().items():
        if s["workspace"] == workspace and active(s):
            n += revoke(sid)
    return n


def by_token(token: str) -> dict | None:
    if not token or len(token) > 100:
        return None
    h = _hash(token)
    for s in load().values():
        if secrets.compare_digest(s.get("token_sha256", ""), h) and active(s):
            return s
    return None


def get(sid: str) -> dict | None:
    s = load().get(sid)
    return s if active(s) else None


def public(s: dict) -> dict:
    return {k: s[k] for k in ("id", "workspace", "label", "terminal", "files", "desktop", "created", "expires",
                              "revoked")} | {"active": active(s), "connected": connected(s["id"])}


def listing(workspace: str | None = None) -> list[dict]:
    out = [public(s) for s in load().values() if workspace is None or s["workspace"] == workspace]
    return sorted(out, key=lambda s: (not s["active"], -s["created"]))


def by_cap(cap: str) -> dict | None:
    """The active share whose browser desktop this capability opens."""
    for s in load().values():
        if s.get("desktop") and secrets.compare_digest(s.get("cap", ""), cap) and active(s):
            return s
    return None


def desktop_prefix(s: dict) -> str:
    return f"/__g/{s['cap']}"


# ---------------------------------------------------------------- bad links (rate limit)
# Apart from the UI's sign-in limiter: strangers trying links must never lock
# you out of your own UI.

_bad: list[tuple[float, str]] = []
BAD_WINDOW, BAD_PER_IP, BAD_ALL = 600, 5, 200


def limited(ip: str) -> bool:
    t = time.monotonic()
    _bad[:] = [(bt, bip) for bt, bip in _bad if t - bt < BAD_WINDOW]
    return len(_bad) >= BAD_ALL or sum(1 for _, bip in _bad if bip == ip) >= BAD_PER_IP


def bad_link(ip: str):
    _bad.append((time.monotonic(), ip))


# ---------------------------------------------------------------- guest sessions (memory only)

_guests: dict[str, dict] = {}            # sha256(cookie) -> {"share", "ip", "since"}
_live: dict[str, set] = {}               # share id -> writers of its open connections
_terminals: dict[str, int] = {}          # share id -> open terminal connections (presence)


def new_guest(s: dict, ip: str) -> str:
    cookie = secrets.token_urlsafe(32)
    _guests[_hash(cookie)] = {"share": s["id"], "ip": ip, "since": now()}
    log(f"{s['id']} opened by {s['label']} from {ip}")
    return cookie


def guest(cookie: str) -> dict | None:
    """The (active) share a guest cookie belongs to."""
    if not cookie or len(cookie) > 100:
        return None
    g = _guests.get(_hash(cookie))
    if not g:
        return None
    s = get(g["share"])
    if not s:
        _guests.pop(_hash(cookie), None)
    return s


def cookie_header(cookie: str, secure: bool, max_age: int) -> str:
    return (f"{COOKIE}={cookie}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max(0, max_age)}"
            + ("; Secure" if secure else ""))


def end_guests(sid: str):
    """Sign out a share's guests and close their open connections now."""
    for k in [k for k, g in _guests.items() if g["share"] == sid]:
        del _guests[k]
    for w in list(_live.get(sid, ())):
        try:
            w.close()
        except Exception:
            pass


class tracked:
    """Context manager: a guest's long-lived connection (terminal, desktop),
    closed by end_guests; terminal ones count as 'connected'."""

    def __init__(self, sid: str, w, terminal: bool = False):
        self.sid, self.w, self.terminal = sid, w, terminal

    def __enter__(self):
        _live.setdefault(self.sid, set()).add(self.w)
        if self.terminal:
            _terminals[self.sid] = _terminals.get(self.sid, 0) + 1
        return self

    def __exit__(self, *exc):
        _live.get(self.sid, set()).discard(self.w)
        if self.terminal:
            _terminals[self.sid] = max(0, _terminals.get(self.sid, 1) - 1)


def connected(sid: str) -> int:
    return _terminals.get(sid, 0)


def connected_by_workspace() -> dict[str, list[str]]:
    """workspace -> labels of guests with a terminal open now."""
    out: dict[str, list[str]] = {}
    shares = load()
    for sid, n in _terminals.items():
        if n and sid in shares:
            out.setdefault(shares[sid]["workspace"], []).append(shares[sid]["label"])
    return out


async def expiry_watch():
    """Close the connections of shares that have expired."""
    ended: set[str] = set()
    while True:
        await asyncio.sleep(10)
        shares = load()
        for sid in set(_live) | {g["share"] for g in _guests.values()}:
            if not active(shares.get(sid)) and (_live.get(sid) or any(g["share"] == sid for g in _guests.values())):
                if sid not in ended:
                    log(f"{sid} ended (expired or revoked); closing its connections")
                    ended.add(sid)
                end_guests(sid)
