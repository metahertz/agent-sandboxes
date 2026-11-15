"""Sign-in for the web UI: one user (the one the UI runs as), with their
system password (PAM) or a passkey (WebAuthn), plus the login token as a
break-glass. Server-side sessions, so they expire and can be signed out.

Files (ui/, which sandboxes can't write; 0600):
  sessions.json   SHA-256 of each session id -> how and when it signed in
  passkeys.json   the user handle and each passkey's public key (PEM)

Passkeys are checked with the openssl CLI (no Python crypto package needed).
Attestation isn't checked ("none"): any authenticator may register, which is
what a passkey setup for one person wants.
"""
import asyncio
import base64
import hashlib
import ipaddress
import json
import os
import pwd
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from common import ROOT, RUNTIME

USER = pwd.getpwuid(os.getuid()).pw_name
SESSIONS_FILE = ROOT / "ui" / "sessions.json"
PASSKEYS_FILE = ROOT / "ui" / "passkeys.json"
PAM_HELPER = ROOT / "ui" / "pam_check.py"
COOKIE = "asui"
SESSION_IDLE = 7 * 86400          # signed out after a week unused
SESSION_MAX = 30 * 86400          # and after 30 days regardless
FRESH = 10 * 60                   # adding a passkey needs a password check this recent
CHALLENGE_TTL = 300
FAIL_WINDOW, FAIL_PER_IP, FAIL_ALL = 15 * 60, 5, 20
TOKEN_LOGIN = os.environ.get("AIO_TOKEN_LOGIN", "1") != "0"

ALG_ES256, ALG_EDDSA, ALG_RS256 = -7, -8, -257


def now() -> int:
    return int(time.time())


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s: str) -> bytes:
    if not isinstance(s, str) or len(s) > 65536:
        raise ValueError("bad base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def private_write(path: Path, text: str):
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(tmp, path)


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return default


# ---------------------------------------------------------------- sessions

_sessions: dict[str, dict] = {}
_sessions_loaded = False


def _key(sid: str) -> str:
    return hashlib.sha256(sid.encode()).hexdigest()


def _load_sessions():
    global _sessions_loaded
    if not _sessions_loaded:
        _sessions.update(load_json(SESSIONS_FILE, {}))
        _sessions_loaded = True


def _save_sessions():
    t = now()
    for k in [k for k, s in _sessions.items() if t - s["seen"] > SESSION_IDLE or t - s["created"] > SESSION_MAX]:
        del _sessions[k]
    private_write(SESSIONS_FILE, json.dumps(_sessions, indent=1) + "\n")


def new_session(method: str, ip: str, ua: str) -> str:
    """method: password, passkey or token. Returns the cookie value."""
    _load_sessions()
    sid = secrets.token_urlsafe(32)
    t = now()
    _sessions[_key(sid)] = {"created": t, "seen": t, "method": method, "ip": ip, "ua": ua[:200],
                            "pw_at": t if method == "password" else 0}
    _save_sessions()
    return sid


def session(sid: str) -> dict | None:
    _load_sessions()
    if not sid or len(sid) > 100:
        return None
    s = _sessions.get(_key(sid))
    t = now()
    if not s or t - s["seen"] > SESSION_IDLE or t - s["created"] > SESSION_MAX:
        return None
    if t - s["seen"] > 3600:          # don't write the file on every request
        s["seen"] = t
        _save_sessions()
    return s


def mark_password(sid: str):
    if s := session(sid):
        s["pw_at"] = now()
        _save_sessions()


def end_session(sid: str):
    _load_sessions()
    if _sessions.pop(_key(sid or ""), None) is not None:
        _save_sessions()


def end_other_sessions(sid: str) -> int:
    _load_sessions()
    keep = _key(sid)
    n = len([k for k in _sessions if k != keep])
    for k in [k for k in _sessions if k != keep]:
        del _sessions[k]
    _save_sessions()
    return n


def session_count() -> int:
    _load_sessions()
    t = now()
    return sum(1 for s in _sessions.values() if t - s["seen"] <= SESSION_IDLE and t - s["created"] <= SESSION_MAX)


def cookie_header(sid: str, secure: bool) -> str:
    return (f"{COOKIE}={sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_MAX}"
            + ("; Secure" if secure else ""))


def clear_cookie_header(secure: bool) -> str:
    return f"{COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0" + ("; Secure" if secure else "")


# ---------------------------------------------------------------- rate limit

_failures: list[tuple[float, str]] = []


def limited(ip: str) -> bool:
    t = time.monotonic()
    _failures[:] = [(ft, fip) for ft, fip in _failures if t - ft < FAIL_WINDOW]
    return len(_failures) >= FAIL_ALL or sum(1 for _, fip in _failures if fip == ip) >= FAIL_PER_IP


def failed(ip: str):
    _failures.append((time.monotonic(), ip))


# ---------------------------------------------------------------- PAM

_pam_lock = asyncio.Lock()


def no_new_privs() -> bool:
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("NoNewPrivs:"):
                return line.split()[1] == "1"
    except OSError:
        pass
    return False


async def check_password(username: str, password: str, ip: str) -> tuple[bool, str]:
    """(accepted, error): error is set when PAM couldn't check at all."""
    if username != USER or not password or len(password) > 1024:
        await asyncio.sleep(1)
        return False, ""
    helper = [sys.executable, "-I", str(PAM_HELPER), ip]
    async with _pam_lock:
        proc = await asyncio.create_subprocess_exec("systemctl", "--user", "show-environment",
                                                    stdout=asyncio.subprocess.DEVNULL,
                                                    stderr=asyncio.subprocess.DEVNULL)
        if await proc.wait() == 0:
            argv = ["systemd-run", "--user", "--pipe", "--wait", "--quiet", "--collect",
                    f"--unit=aio-pam-{secrets.token_hex(4)}", *helper]
        elif no_new_privs():
            return False, ("password sign-in needs a systemd --user instance (sudo loginctl enable-linger "
                           f"{USER}): this service runs with NoNewPrivileges, so PAM can't check passwords here")
        else:
            argv = helper
        proc = await asyncio.create_subprocess_exec(
            *argv, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            _, err = await asyncio.wait_for(proc.communicate(username.encode() + b"\0" + password.encode()), 30)
        except TimeoutError:
            proc.kill()
            return False, "PAM didn't answer within 30 s"
    if proc.returncode == 0:
        return True, ""
    if proc.returncode == 1:
        return False, ""
    return False, (err.decode(errors="replace").strip() or f"the PAM helper failed ({proc.returncode})")[-300:]


# ---------------------------------------------------------------- WebAuthn

def cbor_decode(data: bytes, i: int = 0):
    """Minimal CBOR (definite lengths, as WebAuthn uses). Returns (value, next index)."""
    ib = data[i]
    major, info = ib >> 5, ib & 0x1F
    i += 1
    if info < 24:
        arg = info
    elif info in (24, 25, 26, 27):
        n = 1 << (info - 24)
        arg = int.from_bytes(data[i:i + n], "big")
        if len(data) < i + n:
            raise ValueError("CBOR: truncated")
        i += n
    else:
        raise ValueError("CBOR: indefinite lengths aren't supported")
    if major == 0:
        return arg, i
    if major == 1:
        return -1 - arg, i
    if major in (2, 3):
        if len(data) < i + arg:
            raise ValueError("CBOR: truncated")
        v = data[i:i + arg]
        return (v if major == 2 else v.decode()), i + arg
    if major == 4:
        out = []
        for _ in range(arg):
            v, i = cbor_decode(data, i)
            out.append(v)
        return out, i
    if major == 5:
        out = {}
        for _ in range(arg):
            k, i = cbor_decode(data, i)
            v, i = cbor_decode(data, i)
            out[k] = v
        return out, i
    if major == 6:
        return cbor_decode(data, i)       # a tag: take the tagged value
    if major == 7 and info in (20, 21, 22):
        return {20: False, 21: True, 22: None}[info], i
    raise ValueError("CBOR: unsupported item")


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def _der_int(b: bytes) -> bytes:
    b = b.lstrip(b"\0") or b"\0"
    return _der(0x02, (b"\0" + b) if b[0] & 0x80 else b)


def cose_to_pem(cose: dict) -> tuple[int, str]:
    """A COSE public key -> (alg, SubjectPublicKeyInfo PEM)."""
    kty, alg = cose.get(1), cose.get(3)
    if kty == 2 and alg == ALG_ES256 and cose.get(-1) == 1:          # EC2, P-256
        x, y = cose.get(-2), cose.get(-3)
        if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == len(y) == 32):
            raise ValueError("bad P-256 key")
        der = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200") + b"\x04" + x + y
    elif kty == 1 and alg == ALG_EDDSA and cose.get(-1) == 6:        # OKP, Ed25519
        x = cose.get(-2)
        if not (isinstance(x, bytes) and len(x) == 32):
            raise ValueError("bad Ed25519 key")
        der = bytes.fromhex("302a300506032b6570032100") + x
    elif kty == 3 and alg == ALG_RS256:                               # RSA
        n, e = cose.get(-1), cose.get(-2)
        if not (isinstance(n, bytes) and isinstance(e, bytes) and len(n) >= 256):
            raise ValueError("bad RSA key")
        rsa = _der(0x30, _der_int(n) + _der_int(e))
        algid = _der(0x30, _der(0x06, bytes.fromhex("2a864886f70d010101")) + b"\x05\x00")
        der = _der(0x30, algid + _der(0x03, b"\0" + rsa))
    else:
        raise ValueError(f"unsupported key type (kty {kty}, alg {alg})")
    b64 = base64.b64encode(der).decode()
    pem = "-----BEGIN PUBLIC KEY-----\n" + "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64)) + \
        "\n-----END PUBLIC KEY-----\n"
    return alg, pem


def _openssl(*args: str, data: bytes = b"") -> bool:
    return subprocess.run(["openssl", *args], input=data, capture_output=True, timeout=10).returncode == 0


def pem_valid(pem: str) -> bool:
    with tempfile.TemporaryDirectory(dir=RUNTIME) as d:
        (Path(d) / "k.pem").write_text(pem)
        return _openssl("pkey", "-pubin", "-in", f"{d}/k.pem", "-noout")


def verify_sig(alg: int, pem: str, data: bytes, sig: bytes) -> bool:
    with tempfile.TemporaryDirectory(dir=RUNTIME) as d:
        (Path(d) / "k.pem").write_text(pem)
        (Path(d) / "sig").write_bytes(sig)
        if alg == ALG_EDDSA:
            (Path(d) / "data").write_bytes(data)
            return _openssl("pkeyutl", "-verify", "-pubin", "-inkey", f"{d}/k.pem", "-rawin",
                            "-in", f"{d}/data", "-sigfile", f"{d}/sig")
        if alg in (ALG_ES256, ALG_RS256):
            return _openssl("dgst", "-sha256", "-verify", f"{d}/k.pem", "-signature", f"{d}/sig", data=data)
    return False


def rp_id_for(hostname: str) -> str:
    """The relying party ID: the UI's hostname. Browsers refuse IP addresses."""
    h = hostname.strip("[]")
    try:
        ipaddress.ip_address(h)
    except ValueError:
        return h
    raise ValueError(f"Passkeys need the UI opened by a hostname, not an IP address ({h}): "
                     "use a DNS name or /etc/hosts entry, listed in ui/extra-hostnames so the "
                     "certificate covers it")


def store() -> dict:
    s = load_json(PASSKEYS_FILE, {})
    if not s.get("user_handle"):
        s = {"user_handle": b64u(secrets.token_bytes(32)), "passkeys": s.get("passkeys", [])}
        private_write(PASSKEYS_FILE, json.dumps(s, indent=1) + "\n")
    s.setdefault("passkeys", [])
    return s


def save_store(s: dict):
    private_write(PASSKEYS_FILE, json.dumps(s, indent=1) + "\n")


def public_passkeys() -> list[dict]:
    return [{k: p.get(k) for k in ("id", "name", "rp_id", "created", "last_used", "transports")}
            for p in store()["passkeys"]]


_challenges: dict[str, dict] = {}


def new_challenge(kind: str, rp_id: str, sess: str = "") -> tuple[str, bytes]:
    t = time.monotonic()
    for k in [k for k, c in _challenges.items() if t - c["t"] > CHALLENGE_TTL]:
        del _challenges[k]
    if len(_challenges) > 200:       # unauthenticated callers can make these
        _challenges.pop(next(iter(_challenges)))
    cid, ch = secrets.token_urlsafe(16), secrets.token_bytes(32)
    _challenges[cid] = {"t": t, "kind": kind, "challenge": ch, "rp_id": rp_id, "sess": sess}
    return cid, ch


def take_challenge(cid: str, kind: str) -> dict:
    c = _challenges.pop(str(cid), None)
    if not c or c["kind"] != kind or time.monotonic() - c["t"] > CHALLENGE_TTL:
        raise ValueError("The passkey request expired: try again")
    return c


def check_client_data(raw: bytes, kind: str, challenge: bytes, origin: str):
    cd = json.loads(raw)
    if cd.get("type") != kind:
        raise ValueError("Wrong WebAuthn ceremony")
    if not secrets.compare_digest(unb64u(cd.get("challenge", "")), challenge):
        raise ValueError("Challenge mismatch")
    if cd.get("origin") != origin:
        raise ValueError(f"Wrong origin ({cd.get('origin')})")
    if cd.get("crossOrigin"):
        raise ValueError("Cross-origin request")


def parse_auth_data(ad: bytes, rp_id: str, attested: bool) -> dict:
    if len(ad) < 37:
        raise ValueError("Authenticator data too short")
    if not secrets.compare_digest(ad[:32], hashlib.sha256(rp_id.encode()).digest()):
        raise ValueError("Passkey is for another site")
    flags = ad[32]
    if not flags & 0x01:
        raise ValueError("No user presence")
    if not flags & 0x04:
        raise ValueError("The authenticator didn't verify you (PIN, fingerprint or face)")
    out = {"flags": flags, "sign_count": int.from_bytes(ad[33:37], "big")}
    if attested:
        if not flags & 0x40 or len(ad) < 55:
            raise ValueError("No credential in the authenticator data")
        out["aaguid"] = ad[37:53].hex()
        n = int.from_bytes(ad[53:55], "big")
        out["cred_id"] = ad[55:55 + n]
        out["cose"], _ = cbor_decode(ad, 55 + n)
        if len(out["cred_id"]) != n or not 16 <= n <= 1023:
            raise ValueError("Bad credential ID")
    return out


def registration_options(rp_id: str, sess_key: str) -> dict:
    s = store()
    cid, ch = new_challenge("create", rp_id, sess_key)
    return {"challengeId": cid, "publicKey": {
        "rp": {"id": rp_id, "name": "Agent Sandboxes"},
        "user": {"id": s["user_handle"], "name": USER, "displayName": f"{USER} (Agent Sandboxes)"},
        "challenge": b64u(ch),
        "pubKeyCredParams": [{"type": "public-key", "alg": a} for a in (ALG_ES256, ALG_EDDSA, ALG_RS256)],
        "timeout": CHALLENGE_TTL * 1000,
        "attestation": "none",
        "authenticatorSelection": {"residentKey": "required", "requireResidentKey": True,
                                   "userVerification": "required"},
        "excludeCredentials": [{"type": "public-key", "id": p["id"]}
                               for p in s["passkeys"] if p["rp_id"] == rp_id],
    }}


def register(body: dict, origin: str, sess_key: str) -> dict:
    c = take_challenge(body.get("challengeId"), "create")
    if c["sess"] != sess_key:
        raise ValueError("The passkey request belongs to another session")
    cred = body.get("credential") or {}
    resp = cred.get("response") or {}
    check_client_data(unb64u(resp.get("clientDataJSON", "")), "webauthn.create", c["challenge"], origin)
    att, _ = cbor_decode(unb64u(resp.get("attestationObject", "")))
    if not isinstance(att, dict) or not isinstance(att.get("authData"), bytes):
        raise ValueError("Bad attestation object")
    ad = parse_auth_data(att["authData"], c["rp_id"], attested=True)
    if b64u(ad["cred_id"]) != cred.get("id"):
        raise ValueError("Credential ID mismatch")
    alg, pem = cose_to_pem(ad["cose"])
    if not pem_valid(pem):
        raise ValueError("The passkey's public key doesn't parse")
    s = store()
    if any(p["id"] == cred["id"] for p in s["passkeys"]):
        raise ValueError("That passkey is already registered")
    if len(s["passkeys"]) >= 50:
        raise ValueError("At most 50 passkeys")
    name = " ".join(str(body.get("name") or "").split())[:60] or "Passkey"
    transports = [t for t in resp.get("transports") or [] if isinstance(t, str)][:6]
    p = {"id": cred["id"], "name": name, "rp_id": c["rp_id"], "alg": alg, "public_key": pem,
         "sign_count": ad["sign_count"], "aaguid": ad["aaguid"], "transports": transports,
         "created": now(), "last_used": 0}
    s["passkeys"].append(p)
    save_store(s)
    return {k: p[k] for k in ("id", "name", "rp_id", "created")}


def login_options(rp_id: str) -> dict:
    cid, ch = new_challenge("get", rp_id)
    # No allowCredentials: the browser offers the passkeys it has for this site
    return {"challengeId": cid, "publicKey": {"challenge": b64u(ch), "rpId": rp_id,
                                              "timeout": CHALLENGE_TTL * 1000, "userVerification": "required"}}


def authenticate(body: dict, origin: str) -> str:
    """Checks a passkey assertion; returns the passkey's name."""
    c = take_challenge(body.get("challengeId"), "get")
    cred = body.get("credential") or {}
    resp = cred.get("response") or {}
    s = store()
    p = next((p for p in s["passkeys"] if p["id"] == cred.get("id")), None)
    if not p or p["rp_id"] != c["rp_id"]:
        raise ValueError("Unknown passkey: it may have been removed here")
    if resp.get("userHandle") and resp["userHandle"] != s["user_handle"]:
        raise ValueError("The passkey belongs to another account")
    cdj = unb64u(resp.get("clientDataJSON", ""))
    check_client_data(cdj, "webauthn.get", c["challenge"], origin)
    raw_ad = unb64u(resp.get("authenticatorData", ""))
    ad = parse_auth_data(raw_ad, c["rp_id"], attested=False)
    if not verify_sig(p["alg"], p["public_key"], raw_ad + hashlib.sha256(cdj).digest(),
                      unb64u(resp.get("signature", ""))):
        raise ValueError("The passkey's signature doesn't verify")
    if (ad["sign_count"] or p["sign_count"]) and ad["sign_count"] <= p["sign_count"]:
        raise ValueError("The passkey's counter went backwards: it may have been cloned")
    p["sign_count"], p["last_used"] = ad["sign_count"], now()
    save_store(s)
    return p["name"]


def remove_passkey(pid: str) -> bool:
    s = store()
    keep = [p for p in s["passkeys"] if p["id"] != pid]
    if len(keep) == len(s["passkeys"]):
        return False
    s["passkeys"] = keep
    save_store(s)
    return True


def rename_passkey(pid: str, name: str) -> bool:
    s = store()
    for p in s["passkeys"]:
        if p["id"] == pid:
            p["name"] = " ".join(str(name).split())[:60] or p["name"]
            save_store(s)
            return True
    return False
