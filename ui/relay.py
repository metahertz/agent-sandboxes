"""The sharing relay: a reverse SSH tunnel from this host to your own VPS, so
guests reach the share listener with no port forward or static IP here.

  guest --https--> Caddy on the VPS (Let's Encrypt) --> VPS 127.0.0.1:RELAY_PORT
        --reverse SSH tunnel (run by the UI)--> the share listener, 127.0.0.1:SHARE_PORT

Everything is set up from Settings, Sharing relay: the names, the VPS, its
host key (pinned once you confirm the fingerprint), the tunnel key, and the
script to run on the VPS. The UI runs the tunnel itself and restarts it when
it drops, so it is up whenever the UI is.
"""

import asyncio
import os
import re
import time

import shares
from common import ROOT, die_with_parent, read_env

DIR = ROOT / "secrets" / "relay"
KEY = DIR / "id_ed25519"
KNOWN = DIR / "known_hosts"
RELAY_USER = "aio-relay"
VPS_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9.-]*[a-z0-9])?$|^[0-9a-f:]{2,39}$")
FP_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")


def settings() -> dict:
    try:
        env = read_env(shares.SHARE_ENV)
    except OSError:
        env = {}
    port = env.get("RELAY_SSH_PORT", "")
    return {"shareHost": env.get("SHARE_HOST", ""), "desktopHost": env.get("SHARE_DESKTOP_HOST", ""),
            "vps": env.get("RELAY", "").partition("@")[2], "sshPort": int(port) if port.isdigit() else 22,
            "tunnel": env.get("RELAY_ENABLED", "1") != "0", "cloudflare": env.get("SHARE_CLOUDFLARE") == "1"}


def clean(body: dict) -> dict:
    share = str(body.get("shareHost") or "").strip().lower()
    desktop = str(body.get("desktopHost") or "").strip().lower()
    vps = str(body.get("vps") or "").strip().lower()
    port = str(body.get("sshPort") or "22").strip()
    if not shares.HOST_RE.match(share):
        raise ValueError("Share name: a DNS name pointing at the VPS, e.g. share.example.com")
    if desktop and (not shares.HOST_RE.match(desktop) or desktop == share):
        raise ValueError("Desktop name: a second DNS name, e.g. desktop.share.example.com (or leave it empty)")
    if not VPS_RE.match(vps):
        raise ValueError("VPS: its hostname or IP address (what you ssh to)")
    if not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError("SSH port: a number")
    return {"shareHost": share, "desktopHost": desktop, "vps": vps, "sshPort": int(port),
            "cloudflare": bool(body.get("cloudflare"))}


def write_env(cfg: dict, tunnel: bool):
    port = shares.config()["port"]
    DIR.parent.mkdir(mode=0o700, exist_ok=True)
    text = ("# The sharing relay: written by Settings, Sharing relay.\n"
            f"SHARE_HOST={cfg['shareHost']}\nSHARE_DESKTOP_HOST={cfg['desktopHost']}\nSHARE_PORT={port}\n"
            f"RELAY={RELAY_USER}@{cfg['vps']}\nRELAY_SSH_PORT={cfg['sshPort']}\n"
            f"RELAY_PORT={shares.RELAY_PORT}\nRELAY_ENABLED={1 if tunnel else 0}\n"
            f"SHARE_CLOUDFLARE={1 if cfg.get('cloudflare') else 0}\n")
    tmp = shares.SHARE_ENV.with_name(f".{shares.SHARE_ENV.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(tmp, shares.SHARE_ENV)


def set_tunnel(on: bool):
    write_env(settings(), on)


async def _run(*cmd: str, timeout: float = 20) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(*cmd, stdin=asyncio.subprocess.DEVNULL,
                                                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except TimeoutError:
        proc.kill()
        return 124, "", "timed out"
    return proc.returncode, out.decode(errors="replace"), err.decode(errors="replace")


async def ensure_key() -> str:
    """The tunnel's key (made once; the VPS's authorized_keys holds its public half)."""
    if not KEY.is_file():
        DIR.mkdir(parents=True, mode=0o700, exist_ok=True)
        rc, _, err = await _run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                                f"agent-sandboxes relay {os.uname().nodename}", "-f", str(KEY))
        if rc != 0:
            raise RuntimeError(f"ssh-keygen: {err.strip()}")
    return KEY.with_suffix(".pub").read_text().strip()


def public_key() -> str:
    try:
        return KEY.with_suffix(".pub").read_text().strip()
    except OSError:
        return ""


async def scan(vps: str, port: int) -> tuple[str, str]:
    """The VPS's ed25519 host key: (known_hosts line, its SHA256 fingerprint)."""
    rc, out, _ = await _run("ssh-keyscan", "-T", "10", "-p", str(port), "-t", "ed25519", vps, timeout=20)
    lines = [ln for ln in out.splitlines() if ln and not ln.startswith("#")]
    if not lines:
        raise RuntimeError(f"Couldn't get {vps}'s SSH host key on port {port}: is it reachable from this host?")
    return lines[0], await fingerprint(lines[0])


async def fingerprint(line: str) -> str:
    proc = await asyncio.create_subprocess_exec("ssh-keygen", "-lf", "-", stdin=asyncio.subprocess.PIPE,
                                                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    out, _ = await asyncio.wait_for(proc.communicate((line + "\n").encode()), 10)
    m = re.search(r"SHA256:[A-Za-z0-9+/]{43}", out.decode())
    if not m:
        raise RuntimeError("Couldn't read the VPS's host key")
    return m[0]


async def pinned() -> dict:
    """{host, fingerprint} of the pinned VPS host key, or {}."""
    try:
        line = next(ln for ln in KNOWN.read_text().splitlines() if ln.strip())
    except (OSError, StopIteration):
        return {}
    try:
        return {"host": line.split()[0], "fingerprint": await fingerprint(line)}
    except (RuntimeError, TimeoutError):
        return {}


def pin(line: str):
    DIR.mkdir(parents=True, mode=0o700, exist_ok=True)
    fd = os.open(KNOWN, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(line + "\n")


def known_host(vps: str, port: int) -> str:
    return vps if port == 22 else f"[{vps}]:{port}"


def forget():
    for p in (shares.SHARE_ENV, KNOWN):
        try:
            p.unlink()
        except FileNotFoundError:
            pass


def caddy_cloudflare(names: str, p: int) -> str:
    """Behind Cloudflare's proxy: only its edge may reach the site (so the
    guest's CF-Connecting-IP can be trusted), with Let's Encrypt certificates
    for Cloudflare's SSL/TLS mode Full (strict)."""
    return f"""# 2. Caddy: HTTPS for {names} (Let's Encrypt), behind Cloudflare's proxy, to the tunnel.
#    Only Cloudflare's edge may connect, so its CF-Connecting-IP (the guest) can be trusted.
#    Cloudflare: SSL/TLS mode "Full (strict)" for these names, not "Flexible" (that loops on redirects).
command -v caddy >/dev/null 2>&1 || {{ apt-get update && apt-get install -y caddy; }}
command -v curl >/dev/null 2>&1 || {{ apt-get update && apt-get install -y curl; }}
cf=$(curl -fsS https://www.cloudflare.com/ips-v4; echo; curl -fsS https://www.cloudflare.com/ips-v6)
cf=$(echo $cf)
case $cf in *.*/*:*/*) ;; *) echo "couldn't fetch Cloudflare's address ranges" >&2; exit 1 ;; esac
cat > /etc/caddy/aio-share.caddy <<CADDY
{names} {{
	@notcloudflare not remote_ip $cf
	abort @notcloudflare
	reverse_proxy 127.0.0.1:{p} {{
		header_up X-Forwarded-For {{http.request.header.CF-Connecting-IP}}
	}}
}}
CADDY
"""


def vps_script() -> str:
    cfg, pub = settings(), public_key()
    if not cfg["shareHost"] or not pub:
        return ""
    names = cfg["shareHost"] + (f", {cfg['desktopHost']}" if cfg["desktopHost"] else "")
    u, p = RELAY_USER, shares.RELAY_PORT
    caddy = caddy_cloudflare(names, p) if cfg["cloudflare"] else f"""# 2. Caddy: HTTPS for {names} (Let's Encrypt), to the tunnel
command -v caddy >/dev/null 2>&1 || {{ apt-get update && apt-get install -y caddy; }}
cat > /etc/caddy/aio-share.caddy <<'CADDY'
{names} {{
	reverse_proxy 127.0.0.1:{p} {{
		header_up X-Forwarded-For {{remote_host}}
	}}
}}
CADDY
"""
    return f"""#!/bin/sh
# Agent Sandboxes sharing relay: run this on the VPS as root (Debian / Ubuntu).
# Needs DNS for {names} pointing at this VPS, and ports 80 and 443 open.
set -eu

# 1. A user that may only open the tunnel: no shell, no other forwards
nologin=/usr/sbin/nologin; [ -x $nologin ] || nologin=/bin/false
id {u} >/dev/null 2>&1 || useradd --system --create-home --home-dir /var/lib/{u} --shell $nologin {u}
usermod -p '*' {u}     # no password, but not "locked": sshd refuses locked accounts without PAM
install -d -m 700 -o {u} -g {u} /var/lib/{u}/.ssh
cat > /var/lib/{u}/.ssh/authorized_keys <<'KEY'
restrict,port-forwarding,permitlisten="127.0.0.1:{p}",command="/bin/false" {pub}
KEY
chown {u}:{u} /var/lib/{u}/.ssh/authorized_keys
chmod 600 /var/lib/{u}/.ssh/authorized_keys
if [ -d /etc/ssh/sshd_config.d ] && grep -qi '^Include /etc/ssh/sshd_config.d' /etc/ssh/sshd_config; then
  cat > /etc/ssh/sshd_config.d/{u}.conf <<'SSHD'
Match User {u}
    AllowTcpForwarding remote
    PermitListen 127.0.0.1:{p}
    PermitTTY no
    X11Forwarding no
    AllowAgentForwarding no
    PasswordAuthentication no
SSHD
  sshd -t && (systemctl reload ssh 2>/dev/null || systemctl reload sshd)
else
  echo "note: no sshd_config.d include; the authorized_keys options above still limit {u}" >&2
fi
grep -q '^AllowUsers' /etc/ssh/sshd_config && echo "note: sshd has AllowUsers: add {u} to it" >&2

{caddy}grep -q '^import /etc/caddy/aio-share.caddy' /etc/caddy/Caddyfile 2>/dev/null || \\
  printf '\\nimport /etc/caddy/aio-share.caddy\\n' >> /etc/caddy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
systemctl reload caddy || systemctl restart caddy
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then ufw allow 80/tcp; ufw allow 443/tcp; fi
echo "Relay ready: back in Settings, Sharing relay, check it from the internet."
"""


# ---------------------------------------------------------------- the tunnel

class Tunnel:
    """ssh -N -R, restarted with a growing delay when it exits; state for Settings."""

    def __init__(self):
        self.proc: asyncio.subprocess.Process | None = None
        self.task: asyncio.Task | None = None
        self.state = "off"
        self.error = ""
        self.since = 0.0

    def command(self) -> list[str]:
        env, cfg = settings(), shares.config()
        return ["ssh", "-F", "none", "-N", "-T", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                "-i", str(KEY), "-o", f"UserKnownHostsFile={KNOWN}", "-o", "StrictHostKeyChecking=yes",
                "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
                "-o", "ConnectTimeout=15", "-p", str(env["sshPort"]),
                "-R", f"127.0.0.1:{shares.RELAY_PORT}:127.0.0.1:{cfg['port']}", f"{RELAY_USER}@{env['vps']}"]

    def ready(self) -> bool:
        env = settings()
        return bool(env["vps"] and env["shareHost"] and KEY.is_file() and KNOWN.is_file())

    async def apply(self):
        """Start, restart or stop it to match the settings."""
        await self.stop()
        env = settings()
        if env["tunnel"] and self.ready():
            self.task = asyncio.create_task(self._loop())

    async def stop(self):
        task, self.task = self.task, None
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self.state, self.error = "off", ""

    async def _loop(self):
        delay = 5
        try:
            while True:
                self.state, self.since = "connecting", time.time()
                self.proc = await asyncio.create_subprocess_exec(
                    *self.command(), stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE, preexec_fn=die_with_parent)
                watch = asyncio.create_task(self._up_after(self.proc))
                raw = b""
                while chunk := await self.proc.stderr.read(4096):
                    raw = (raw + chunk)[-4000:]
                err = raw.decode(errors="replace")
                rc = await self.proc.wait()
                watch.cancel()
                lived = time.time() - self.since
                msg = " ".join(ln for ln in err.strip().splitlines()
                               if not ln.startswith("Warning: Permanently added"))[-300:]
                self.error = msg or f"ssh exited ({rc})"
                self.state = "down"
                shares.log(f"relay tunnel down after {lived:.0f} s: {self.error}")
                delay = 5 if lived > 120 else min(delay * 2, 120)
                await asyncio.sleep(delay)
        finally:
            if self.proc and self.proc.returncode is None:
                self.proc.terminate()
                try:
                    await asyncio.wait_for(self.proc.wait(), 5)
                except TimeoutError:
                    self.proc.kill()
            self.proc = None

    async def _up_after(self, proc):
        """ExitOnForwardFailure: still running a few seconds in means the forward is up."""
        await asyncio.sleep(6)
        if proc.returncode is None and proc is self.proc:
            self.state, self.error = "up", ""
            shares.log("relay tunnel up")

    def status(self) -> dict:
        return {"state": self.state, "error": self.error, "since": int(self.since)}


tunnel = Tunnel()
