"""Apple signing identities: a certificate with its private key (.p12) and the
provisioning profiles that go with it, kept on this host.

Keys & tokens -> Apple signing holds them in secrets/apple/identities/<id>/:

    cert.p12        as uploaded (0600)
    password        the .p12's password (0600)
    profiles/<uuid>.mobileprovision
    meta.json       what the UI and the agent are told: the certificate's
                    name, team, expiry, SHA-1, and each profile's name, app
                    ID, type, devices, expiry, entitlements

A private key is used for local cryptography, so no proxy can swap it in the
way it swaps an API token: nothing here ever enters a sandbox. A workspace
with an identity ticked (policy "signing") can ask for signing through the
aio-builds MCP server: on this host (sign_ipa, rcodesign) or on a Mac
(export_build, xcodebuild -exportArchive in a fresh VM, with the identity
sealed for the worker).
"""

import base64
import datetime
import hashlib
import json
import os
import plistlib
import re
import shutil
import subprocess
from pathlib import Path

from common import SECRETS

APPLE_DIR = SECRETS / "apple"
IDENTITIES = APPLE_DIR / "identities"
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
UUID_RE = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")
MAX_P12 = 64 * 1024
MAX_PROFILE = 256 * 1024
# xcodebuild -exportArchive's method for each profile type
EXPORT_METHOD = {"app-store": "app-store-connect", "ad-hoc": "release-testing",
                 "development": "debugging", "enterprise": "enterprise"}


class SignError(Exception):
    pass


def _write(path: Path, data: bytes):
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def openssl(*args: str, input: bytes = b"", password: str | None = None) -> subprocess.CompletedProcess:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    if password is not None:
        env["AIO_P12_PW"] = password
    return subprocess.run(["openssl", *args], input=input, capture_output=True, timeout=30, env=env)


def p12_certificate(data: bytes, password: str) -> tuple[bytes, bool]:
    """The .p12's certificate (PEM), and whether it needed -legacy (RC2/3DES,
    as macOS Keychain Access exports). Raises if the password is wrong or
    there's no private key."""
    for legacy in ((), ("-legacy",)):
        cert = openssl("pkcs12", *legacy, "-nokeys", "-clcerts", "-passin", "env:AIO_P12_PW",
                       input=data, password=password)
        if cert.returncode == 0 and b"BEGIN CERTIFICATE" in cert.stdout:
            key = openssl("pkcs12", *legacy, "-nocerts", "-nodes", "-passin", "env:AIO_P12_PW",
                          input=data, password=password)
            if key.returncode != 0 or b"PRIVATE KEY" not in key.stdout:
                raise SignError("The .p12 holds no private key: export the certificate together with its key "
                                "(Keychain Access → My Certificates → Export)")
            return cert.stdout, bool(legacy)
        err = cert.stderr.decode(errors="replace")
        if "mac verify failure" in err.lower() or "invalid password" in err.lower():
            raise SignError("Wrong password for the .p12")
    raise SignError("That isn't a .p12 openssl can read (wrong password?)")


def cert_info(pem: bytes) -> dict:
    out = openssl("x509", "-noout", "-subject", "-enddate", "-fingerprint", "-sha1", "-nameopt", "RFC2253",
                  input=pem)
    if out.returncode != 0:
        raise SignError("Can't read the certificate in the .p12")
    info = {}
    for line in out.stdout.decode(errors="replace").splitlines():
        k, _, v = line.partition("=")
        if k == "subject":
            fields = dict(x.split("=", 1) for x in re.split(r"(?<!\\),", v) if "=" in x)
            info["name"] = fields.get("CN", v).replace("\\,", ",")
            info["team"] = fields.get("OU", "")
        elif k == "notAfter":
            info["expires"] = datetime.datetime.strptime(v.replace("  ", " "), "%b %d %H:%M:%S %Y %Z") \
                .replace(tzinfo=datetime.timezone.utc).isoformat()
        elif "Fingerprint" in k:
            info["sha1"] = line.split("=", 1)[1].replace(":", "").upper()
    if not info.get("team"):
        raise SignError("The certificate names no team (OU): is it an Apple signing certificate?")
    return info


def profile_info(data: bytes) -> dict:
    """A .mobileprovision (or .provisionprofile): a CMS-signed plist. The plist
    is read straight out of it (the signature is Apple's; it's checked again
    by whoever installs the app)."""
    start, end = data.find(b"<?xml"), data.find(b"</plist>")
    if start < 0 or end < 0:
        raise SignError("That isn't a provisioning profile (.mobileprovision)")
    try:
        p = plistlib.loads(data[start:end + len(b"</plist>")])
    except Exception:
        raise SignError("Can't read the provisioning profile") from None
    ent = p.get("Entitlements", {}) or {}
    team = (p.get("TeamIdentifier") or [""])[0]
    app_id = str(ent.get("application-identifier") or ent.get("com.apple.application-identifier") or "")
    if p.get("ProvisionsAllDevices"):
        kind = "enterprise"
    elif p.get("ProvisionedDevices"):
        kind = "development" if ent.get("get-task-allow") else "ad-hoc"
    else:
        kind = "app-store"
    uuid = str(p.get("UUID", ""))
    if not UUID_RE.match(uuid):
        raise SignError("The provisioning profile has no UUID")
    expires = p.get("ExpirationDate")
    return {"uuid": uuid, "name": str(p.get("Name", "")), "team": team, "app_id": app_id,
            "bundle_id": app_id.split(".", 1)[1] if "." in app_id else app_id,
            "type": kind, "platforms": [str(x) for x in p.get("Platform", [])],
            "devices": len(p.get("ProvisionedDevices", []) or []),
            "expires": expires.replace(tzinfo=datetime.timezone.utc).isoformat() if expires else "",
            "certs": [hashlib.sha1(c).hexdigest().upper() for c in p.get("DeveloperCertificates", [])],
            "entitlements": json.loads(json.dumps(ent, default=str))}


# ---------------------------------------------------------------- the store
def ident_dir(iid: str) -> Path:
    if not ID_RE.match(iid):
        raise SignError("Identity name: lowercase letters, digits and dashes, max 40")
    return IDENTITIES / iid


def meta(iid: str) -> dict | None:
    try:
        return json.loads((ident_dir(iid) / "meta.json").read_text())
    except (OSError, ValueError, SignError):
        return None


def identities() -> list[dict]:
    out = []
    if IDENTITIES.is_dir():
        for d in sorted(IDENTITIES.iterdir()):
            if (m := meta(d.name)) and (d / "cert.p12").is_file():
                out.append(m)
    return out


def check_profile_for(m: dict, prof: dict):
    if prof["team"] != m["team"]:
        raise SignError(f"The profile {prof['name']!r} is for team {prof['team']}, the certificate for {m['team']}")
    if prof["certs"] and m["sha1"] not in prof["certs"]:
        raise SignError(f"The profile {prof['name']!r} doesn't include this certificate: regenerate it with the "
                        "certificate ticked (developer.apple.com → Profiles)")


def add_identity(iid: str, p12: bytes, password: str, profiles: list[bytes]) -> dict:
    d = ident_dir(iid)
    if d.exists():
        raise SignError(f"There's already an identity {iid!r}")
    if not p12 or len(p12) > MAX_P12:
        raise SignError("Pick the .p12 file")
    if len(password) > 1024 or any(c in password for c in "\r\n\0"):
        raise SignError("Bad password")
    pem, legacy = p12_certificate(p12, password)
    m = {"id": iid, **cert_info(pem), "legacy_p12": legacy, "profiles": []}
    parsed = [profile_info(x) for x in profiles if len(x) <= MAX_PROFILE]
    if len(parsed) != len(profiles):
        raise SignError("A provisioning profile is too big")
    for prof in parsed:
        check_profile_for(m, prof)
    APPLE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    IDENTITIES.mkdir(mode=0o700, exist_ok=True)
    d.mkdir(mode=0o700)
    (d / "profiles").mkdir(mode=0o700)
    try:
        _write(d / "cert.p12", p12)
        _write(d / "password", password.encode())
        for raw, prof in zip(profiles, parsed):
            _write(d / "profiles" / f"{prof['uuid']}.mobileprovision", raw)
            m["profiles"] = [x for x in m["profiles"] if x["uuid"] != prof["uuid"]] + [prof]
        _write(d / "meta.json", json.dumps(m, indent=1).encode())
    except BaseException:
        shutil.rmtree(d, ignore_errors=True)
        raise
    return m


def add_profile(iid: str, raw: bytes) -> dict:
    m = meta(iid)
    if not m:
        raise SignError("No such identity")
    if len(raw) > MAX_PROFILE:
        raise SignError("That profile is too big")
    prof = profile_info(raw)
    check_profile_for(m, prof)
    _write(ident_dir(iid) / "profiles" / f"{prof['uuid']}.mobileprovision", raw)
    m["profiles"] = [x for x in m["profiles"] if x["uuid"] != prof["uuid"]] + [prof]
    _write(ident_dir(iid) / "meta.json", json.dumps(m, indent=1).encode())
    return m


def remove_profile(iid: str, uuid: str) -> dict:
    m = meta(iid)
    if not m or not UUID_RE.match(uuid):
        raise SignError("No such profile")
    (ident_dir(iid) / "profiles" / f"{uuid}.mobileprovision").unlink(missing_ok=True)
    m["profiles"] = [x for x in m["profiles"] if x["uuid"] != uuid]
    _write(ident_dir(iid) / "meta.json", json.dumps(m, indent=1).encode())
    return m


def remove_identity(iid: str):
    shutil.rmtree(ident_dir(iid), ignore_errors=True)


def find_profile(m: dict, which: str) -> dict:
    """A profile of the identity by UUID, name or bundle ID."""
    hits = [p for p in m["profiles"] if which in (p["uuid"], p["name"], p["bundle_id"])]
    if len(hits) != 1:
        names = ", ".join(f"{p['name']} ({p['bundle_id']}, {p['type']})" for p in m["profiles"]) or "none"
        raise SignError(f"{'No' if not hits else 'More than one'} profile {which!r} for {m['id']} "
                        f"(its profiles: {names}); use the UUID")
    return hits[0]


def summary(m: dict) -> str:
    profs = "; ".join(f"{p['name']}: {p['bundle_id']}, {p['type']}, expires {p['expires'][:10]} ({p['uuid']})"
                      for p in m["profiles"]) or "no profiles yet"
    return f"{m['id']}: {m['name']} (team {m['team']}, expires {m['expires'][:10]}). Profiles: {profs}"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()
