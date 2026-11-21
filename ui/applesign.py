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


# ---------------------------------------------------------------- signing on this host (sign_ipa)
# rcodesign (bin/install-rcodesign) re-signs an app bundle with the
# identity's .p12. The input comes from the agent, so it's unpacked here with
# checks (no paths outside the folder, no links out, size and count caps),
# and the entitlements signed in are only what the profile grants.

RCODESIGN = Path(__file__).resolve().parent.parent / "opt" / "rcodesign" / "rcodesign"
MAX_UNPACKED = 8 << 30
MAX_FILES = 200_000
LC_CODE_SIGNATURE = 0x1D
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
# Set from the profile, never kept from the app's own signature
FIXED_KEYS = {"application-identifier", "com.apple.application-identifier", "com.apple.developer.team-identifier",
              "get-task-allow", "beta-reports-active"}


def macho_entitlements(path: Path) -> dict:
    """The entitlements in a Mach-O's code signature (the first slice of a fat
    binary that has any), or {} if it's unsigned."""
    import struct
    data = path.read_bytes()
    offsets = []
    magic_be = struct.unpack_from(">I", data, 0)[0] if len(data) >= 8 else 0
    if magic_be in (0xCAFEBABE, 0xCAFEBABF):           # fat: big-endian headers
        n = struct.unpack_from(">I", data, 4)[0]
        size = 20 if magic_be == 0xCAFEBABE else 32
        for i in range(min(n, 16)):
            fields = struct.unpack_from(">iiIII" if size == 20 else ">iiQQI", data, 8 + i * size)
            offsets.append(fields[2])
    else:
        offsets.append(0)
    for base in offsets:
        if base + 32 > len(data):
            continue
        magic = struct.unpack_from("<I", data, base)[0]
        if magic not in (0xFEEDFACF, 0xFEEDFACE):
            continue
        ncmds = struct.unpack_from("<I", data, base + 16)[0]
        p = base + (32 if magic == 0xFEEDFACF else 28)
        for _ in range(min(ncmds, 10_000)):
            if p + 8 > len(data):
                break
            cmd, size = struct.unpack_from("<II", data, p)
            if cmd == LC_CODE_SIGNATURE:
                off, _ = struct.unpack_from("<II", data, p + 8)
                sb = base + off
                if struct.unpack_from(">I", data, sb)[0] != CSMAGIC_EMBEDDED_SIGNATURE:
                    break
                count = struct.unpack_from(">I", data, sb + 8)[0]
                for j in range(min(count, 64)):
                    _, boff = struct.unpack_from(">II", data, sb + 12 + j * 8)
                    bmagic, blen = struct.unpack_from(">II", data, sb + boff)
                    if bmagic == CSMAGIC_EMBEDDED_ENTITLEMENTS:
                        try:
                            return plistlib.loads(data[sb + boff + 8:sb + boff + blen])
                        except Exception:
                            return {}
                break
            if size < 8:
                break
            p += size
    return {}


def _match(value, pattern) -> bool:
    import fnmatch
    if isinstance(pattern, str) and isinstance(value, str):
        return value == pattern or fnmatch.fnmatchcase(value, pattern)
    return value == pattern


def merge_entitlements(app: dict, prof: dict, team: str, bundle_id: str) -> tuple[dict, list[str]]:
    """What gets signed in: the app's own entitlements as far as the profile
    grants them, plus the identity keys from the profile. Returns it and what
    was dropped."""
    pent = prof["entitlements"]
    pid = str(pent.get("application-identifier") or pent.get("com.apple.application-identifier") or "")
    if not _match(f"{team}.{bundle_id}", pid):
        raise SignError(f"The profile {prof['name']!r} is for {pid}, not {team}.{bundle_id}")
    out = {"application-identifier": f"{team}.{bundle_id}", "com.apple.developer.team-identifier": team}
    if "get-task-allow" in pent:
        out["get-task-allow"] = bool(pent["get-task-allow"])
    if pent.get("beta-reports-active"):
        out["beta-reports-active"] = True
    dropped = []
    for k, v in app.items():
        if k in FIXED_KEYS:
            continue
        if k not in pent:
            dropped.append(k)
            continue
        allowed = pent[k]
        if isinstance(v, list):
            pats = allowed if isinstance(allowed, list) else [allowed]
            keep = [x for x in v if any(_match(x, p) for p in pats)]
            if len(keep) != len(v):
                dropped.append(f"{k} ({', '.join(str(x) for x in v if x not in keep)})")
            if keep:
                out[k] = keep
        elif isinstance(allowed, list):
            if any(_match(v, p) for p in allowed):
                out[k] = v
            else:
                dropped.append(k)
        elif _match(v, allowed) or allowed is True:
            out[k] = v
        else:
            dropped.append(f"{k} ({v} → {allowed})")
            out[k] = allowed
    # aps-environment etc. the profile sets but the app didn't ask for stay out
    return out, dropped


def safe_unzip(zpath: Path, dest: Path):
    """Unpack an agent-made zip: no absolute paths or '..', symlinks only to
    places inside, caps on size and count."""
    import stat
    import zipfile
    total = 0
    with zipfile.ZipFile(zpath) as z:
        infos = z.infolist()
        if len(infos) > MAX_FILES:
            raise SignError("Too many files in the archive")
        for info in infos:
            name = info.filename
            parts = Path(name).parts
            if name.startswith("/") or ".." in parts or "\\" in name or not parts:
                raise SignError(f"Unsafe path in the archive: {name[:100]}")
            target = dest.joinpath(*parts)
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                link = z.read(info).decode("utf-8", "replace")
                if link.startswith("/") or not (target.parent / link).resolve().is_relative_to(dest.resolve()):
                    raise SignError(f"A link in the archive points outside it: {name[:100]}")
                target.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(link, target)
                continue
            if name.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
                continue
            total += info.file_size
            if total > MAX_UNPACKED:
                raise SignError("The archive unpacks to more than 8 GB")
            if not target.parent.resolve().is_relative_to(dest.resolve()):
                raise SignError(f"Unsafe path in the archive: {name[:100]}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as src, open(target, "xb") as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
            os.chmod(target, 0o755 if mode & 0o111 else 0o644)


def find_app(root: Path) -> Path:
    """The .app in an unpacked .ipa (Payload/), .xcarchive (Products/Applications/), or zip of one."""
    for pattern in ("Payload/*.app", "*.xcarchive/Products/Applications/*.app", "Products/Applications/*.app",
                    "*.app"):
        hits = [p for p in root.glob(pattern) if p.is_dir() and not p.is_symlink()]
        if len(hits) == 1:
            return hits[0]
        if len(hits) > 1:
            raise SignError(f"More than one app in the archive ({', '.join(h.name for h in hits)})")
    raise SignError("No .app in it: give an .ipa, a zipped .xcarchive (the archive action's artifact) or a "
                    "zipped .app")


def bundle_info(app: Path) -> tuple[dict, bool]:
    """Info.plist and whether it's a macOS bundle (Contents/)."""
    mac = (app / "Contents" / "Info.plist").is_file()
    p = app / "Contents" / "Info.plist" if mac else app / "Info.plist"
    try:
        return plistlib.loads(p.read_bytes()), mac
    except Exception:
        raise SignError(f"Can't read {p.name} in {app.name}") from None


def nested_bundles(app: Path, mac: bool) -> list[Path]:
    """App extensions and watch/App Clip apps: each needs its own profile."""
    base = app / "Contents" if mac else app
    out = []
    for sub in ("PlugIns", "Extensions", "Watch", "AppClips"):
        d = base / sub
        if d.is_dir() and not d.is_symlink():
            out += [p for p in d.iterdir() if p.suffix in (".appex", ".app") and p.is_dir() and not p.is_symlink()]
    return out


# ---------------------------------------------------------------- sealing for a Mac (export_build)
# The keys travel to the build host encrypted for the Mac workers' seal keys.
# A seal key is trusted only if its public half is signed with the worker's
# ssh key as this UI added it (secrets/builds/workers.json; workers added
# before that are taken from the build host once, then pinned here).

def verify_seal_key(name: str, ssh_pubkey: str, seal: dict) -> bool:
    import tempfile
    pem, sig = seal.get("pem", ""), seal.get("sig", "")
    if not pem.startswith("-----BEGIN PUBLIC KEY-----") or "BEGIN SSH SIGNATURE" not in sig:
        return False
    with tempfile.TemporaryDirectory() as d:
        Path(d, "allowed").write_text(f"{name} {' '.join(ssh_pubkey.split()[:2])}\n")
        Path(d, "sig").write_text(sig)
        p = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", f"{d}/allowed", "-I", name, "-n", "aio-seal",
                            "-s", f"{d}/sig"], input=pem.encode(), capture_output=True, timeout=30)
        return p.returncode == 0


def seal(files: dict[str, bytes], recipients: dict[str, str]) -> bytes:
    """A tar of files, AES-256-CBC + HMAC-SHA256 with fresh keys, which are
    wrapped with RSA-OAEP for each recipient (worker name -> public PEM)."""
    import hmac
    import io
    import secrets
    import tarfile
    import tempfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o600
            t.addfile(info, io.BytesIO(data))
    k_enc, k_mac, iv = secrets.token_bytes(32), secrets.token_bytes(32), secrets.token_bytes(16)
    p = openssl("enc", "-aes-256-cbc", "-K", k_enc.hex(), "-iv", iv.hex(), input=buf.getvalue())
    if p.returncode != 0:
        raise SignError("openssl couldn't encrypt the keys")
    ct = p.stdout
    box = {"v": 1, "iv": b64(iv), "ct": b64(ct), "workers": {},
           "mac": b64(hmac.new(k_mac, iv + ct, hashlib.sha256).digest())}
    with tempfile.TemporaryDirectory() as d:
        for name, pem in recipients.items():
            Path(d, "pub.pem").write_text(pem)
            p = openssl("pkeyutl", "-encrypt", "-pubin", "-inkey", f"{d}/pub.pem", "-pkeyopt",
                        "rsa_padding_mode:oaep", input=k_enc + k_mac)
            if p.returncode != 0:
                raise SignError(f"couldn't seal for {name}: {p.stderr.decode(errors='replace').strip()[:200]}")
            box["workers"][name] = b64(p.stdout)
    return json.dumps(box).encode()


def export_options(m: dict, method: str, upload: bool) -> tuple[bytes, list[dict]]:
    """ExportOptions.plist for xcodebuild -exportArchive (manual signing with
    this identity), and the profiles it uses: every one of the identity's
    profiles of the method's type, by bundle ID."""
    kind = {v: k for k, v in EXPORT_METHOD.items()}[method]
    profiles = [p for p in m["profiles"] if p["type"] == kind and "*" not in p["bundle_id"]]
    if not profiles:
        raise SignError(f"{m['id']} has no {kind} provisioning profile (for {method}): add one under Keys & tokens "
                        "→ Apple signing")
    opts = {"method": method, "signingStyle": "manual", "teamID": m["team"], "signingCertificate": m["sha1"],
            "provisioningProfiles": {p["bundle_id"]: p["uuid"] for p in profiles},
            "destination": "upload" if upload else "export", "uploadSymbols": True,
            "manageAppVersionAndBuildNumber": False, "stripSwiftSymbols": True}
    return plistlib.dumps(opts), profiles


def legacy_p12(p12: bytes, password: str) -> bytes:
    """The same identity as a 3DES/SHA-1 .p12, which every macOS `security
    import` reads (older ones refuse OpenSSL 3's AES-encrypted default)."""
    pem = openssl("pkcs12", "-nodes", "-passin", "env:AIO_P12_PW", input=p12, password=password)
    if pem.returncode != 0:
        raise SignError("Can't open the identity's .p12")
    import tempfile
    from common import RUNTIME
    RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="p12-", dir=RUNTIME) as d:     # openssl reads -in twice: a file
        fd = os.open(f"{d}/id.pem", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem.stdout)
        out = openssl("pkcs12", "-export", "-legacy", "-in", f"{d}/id.pem", "-passout", "env:AIO_P12_PW",
                      password=password)
    if out.returncode != 0:
        raise SignError("Can't re-export the .p12 for macOS")
    return out.stdout


def export_files(iid: str, method: str, asc: dict | None) -> dict[str, bytes]:
    """What goes into the seal for an export: the identity, its profiles for
    the method, ExportOptions.plist, and for an upload the App Store Connect key."""
    m = meta(iid)
    if not m:
        raise SignError(f"No signing identity {iid!r}")
    d = ident_dir(iid)
    opts, profiles = export_options(m, method, asc is not None)
    p12, password = (d / "cert.p12").read_bytes(), (d / "password").read_text()
    if not m.get("legacy_p12"):
        p12 = legacy_p12(p12, password)
    files = {"cert.p12": p12, "password": password.encode(), "ExportOptions.plist": opts}
    for p in profiles:
        files[f"profiles/{p['uuid']}.mobileprovision"] = (d / "profiles" / f"{p['uuid']}.mobileprovision").read_bytes()
    if asc:
        files.update({"asc.p8": asc["p8"], "asc_key_id": asc["key_id"].encode(),
                      "asc_issuer_id": asc["issuer_id"].encode()})
    return files


def zip_tree(root: Path, out: Path):
    """Zip root's contents (as an .ipa / app zip), keeping symlinks and modes."""
    import stat
    import zipfile
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for dirpath, dirs, files in os.walk(root):
            dirs.sort()
            for name in sorted(dirs) + sorted(files):
                p = Path(dirpath) / name
                rel = p.relative_to(root).as_posix()
                if p.is_symlink():
                    info = zipfile.ZipInfo(rel)
                    info.external_attr = (stat.S_IFLNK | 0o755) << 16
                    z.writestr(info, os.readlink(p))
                elif p.is_dir():
                    info = zipfile.ZipInfo(rel + "/")
                    info.external_attr = (stat.S_IFDIR | 0o755) << 16
                    z.writestr(info, b"")
                else:
                    info = zipfile.ZipInfo.from_file(p, rel)
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.external_attr = (stat.S_IFREG | (0o755 if os.access(p, os.X_OK) else 0o644)) << 16
                    with open(p, "rb") as src, z.open(info, "w") as dst:
                        shutil.copyfileobj(src, dst, 1 << 20)


def profile_for(m: dict, first: dict, bundle_id: str) -> dict:
    """The profile for a nested bundle: the identity's profile of the same
    type for its bundle ID (exact, else a wildcard one)."""
    team = m["team"]
    same = [p for p in m["profiles"] if p["type"] == first["type"]]
    exact = [p for p in same if p["bundle_id"] == bundle_id]
    if exact:
        return exact[0]
    wild = [p for p in same if "*" in p["bundle_id"] and _match(f"{team}.{bundle_id}", p["app_id"])]
    if wild:
        return wild[0]
    raise SignError(f"No {first['type']} profile for {bundle_id} (an extension or embedded app) in {m['id']}: "
                    "add one under Keys & tokens → Apple signing")


def sign_tree(m: dict, prof: dict, work: Path) -> tuple[Path, Path, list[str]]:
    """Unpack work/in.zip, embed profiles, work out entitlements, run rcodesign.
    Returns (folder to zip, the app, notes). Blocking: run it in a thread."""
    x = work / "x"
    x.mkdir()
    safe_unzip(work / "in.zip", x)
    app = find_app(x)
    info, mac = bundle_info(app)
    if not mac and app.parent.name == "Payload" and app.parent.parent == x:     # an .ipa: keep its layout
        pkg = x
    else:            # an .xcarchive or a bare .app: Payload/<app> (iOS) or <app> (macOS) in a folder of its own
        pkg = work / "pkg"
        (pkg / ("" if mac else "Payload")).mkdir(parents=True)
        swift = app.parent.parent.parent / "SwiftSupport"
        if not mac and app.parent.name == "Applications" and swift.is_dir() and not swift.is_symlink():
            shutil.copytree(swift, pkg / "SwiftSupport", symlinks=True)
        shutil.move(str(app), str(pkg / ("" if mac else "Payload") / app.name))
        app = pkg / ("" if mac else "Payload") / app.name
    notes, args = [], []
    for i, b in enumerate([app, *nested_bundles(app, mac)]):
        binfo, bmac = bundle_info(b)
        bid, exe = str(binfo.get("CFBundleIdentifier", "")), str(binfo.get("CFBundleExecutable", ""))
        if not bid or not exe or "/" in exe:
            raise SignError(f"{b.name}: no CFBundleIdentifier / CFBundleExecutable")
        p = prof if i == 0 else profile_for(m, prof, bid)
        if i == 0 and not _match(f"{m['team']}.{bid}", p["app_id"]):
            raise SignError(f"The profile {p['name']!r} is for {p['app_id']}, the app is {m['team']}.{bid}")
        exe_path = b / ("Contents/MacOS" if bmac else "") / exe
        if exe_path.is_symlink() or not exe_path.is_file():
            raise SignError(f"{b.name}: its executable {exe} is missing")
        raw = (ident_dir(m["id"]) / "profiles" / f"{p['uuid']}.mobileprovision").read_bytes()
        target = b / ("Contents/embedded.provisionprofile" if bmac else "embedded.mobileprovision")
        if target.is_symlink():
            target.unlink()
        target.write_bytes(raw)
        ent, dropped = merge_entitlements(macho_entitlements(exe_path), p, m["team"], bid)
        entf = work / f"ent-{i}.plist"
        entf.write_bytes(plistlib.dumps(ent))
        # scoped to the executable itself: rcodesign keeps a bundle's existing
        # entitlements otherwise
        args += ["--entitlements-xml-file", f"{exe_path.relative_to(app).as_posix()}:{entf}"]
        if dropped:
            notes.append(f"{b.name}: left out (the profile doesn't grant): {', '.join(dropped)}")
        notes.append(f"{b.name}: {bid}, profile {p['name']} ({p['type']})")
    # rcodesign can't open an AES-encrypted .p12 (OpenSSL 3's and newer
    # Keychain exports): it gets the key and certificate as PEM, in this job's
    # folder on the runtime tmpfs (0700), deleted with it
    pem = work / "identity.pem"
    password = (ident_dir(m["id"]) / "password").read_text()
    for legacy in ((), ("-legacy",)):
        p = openssl("pkcs12", *legacy, "-nodes", "-clcerts", "-passin", "env:AIO_P12_PW",
                    input=(ident_dir(m["id"]) / "cert.p12").read_bytes(), password=password)
        if p.returncode == 0 and b"PRIVATE KEY" in p.stdout:
            break
    else:
        raise SignError("Can't open the identity's .p12")
    fd = os.open(pem, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(p.stdout)
    cmd = [str(RCODESIGN), "sign", "--pem-file", str(pem), *args,
           # iOS signatures carry no secure timestamp (as Xcode's); macOS ones get Apple's
           *(() if mac else ("--timestamp-url", "none")), str(app)]
    env = {"PATH": "/usr/bin:/bin", "HOME": str(work), "LANG": "C.UTF-8"}
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, env=env, cwd=work)
    if p.returncode != 0:
        raise SignError("rcodesign failed: " + (p.stderr or p.stdout).strip()[-1500:])
    return pkg, app, notes


async def sign_on_host(ws: str, ws_dir: str, pol: dict, args: dict) -> tuple[str, str]:
    """sign_ipa: re-sign an app from the project or a build's artifact with an
    identity assigned to the workspace; the signed .ipa (.zip for macOS) goes
    to .aio-builds/signed/ in the project."""
    import asyncio
    import tempfile
    import builds
    from common import RUNTIME
    iid = str(args.get("identity") or "")
    if iid not in pol["signing"]:
        raise SignError(f"Signing identity {iid!r} isn't assigned to this workspace"
                        + (f" (it has: {', '.join(pol['signing'])})" if pol["signing"] else ""))
    m = meta(iid)
    if not m:
        raise SignError(f"No signing identity {iid!r}")
    if not RCODESIGN.is_file():
        raise SignError("rcodesign isn't installed on the host (bin/install-rcodesign)")
    prof = find_profile(m, str(args.get("profile") or ""))
    RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="sign-", dir=RUNTIME))
    try:
        inp = work / "in.zip"
        if args.get("path"):
            try:
                fd = builds.open_in_workspace(ws_dir, str(args["path"]))
            except builds.BuildError as e:
                raise SignError(str(e)) from None
            with os.fdopen(fd, "rb") as src, open(inp, "wb") as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
        elif args.get("id") and args.get("name"):
            proc = await builds.artifact_stream(ws, str(args["id"]), str(args["name"]))
            with open(inp, "wb") as dst:
                while chunk := await proc.stdout.read(1 << 20):
                    dst.write(chunk)
            err = (await proc.stderr.read()).decode(errors="replace").strip()
            if await proc.wait() != 0:
                raise SignError(err.removeprefix("aio-buildd: ") or "couldn't get the artifact")
        else:
            raise SignError("Give path (a file in the project) or id + name (a build's artifact)")
        if inp.stat().st_size > MAX_UNPACKED:
            raise SignError("That file is too big")
        pkg, app, notes = await asyncio.to_thread(sign_tree, m, prof, work)
        mac = (app / "Contents").is_dir()
        out = str(args.get("output") or f"{app.stem}-{iid}.{'zip' if mac else 'ipa'}")
        signed = work / "signed.zip"
        await asyncio.to_thread(zip_tree, pkg, signed)

        async def chunks():
            with open(signed, "rb") as f:
                while chunk := f.read(1 << 20):
                    yield chunk
        try:
            rel = await builds.write_into_workspace(ws_dir, [builds.OUT_DIR, "signed"], out, chunks())
        except builds.BuildError as e:
            raise SignError(str(e)) from None
        return rel, "\n".join(notes)
    finally:
        shutil.rmtree(work, ignore_errors=True)
