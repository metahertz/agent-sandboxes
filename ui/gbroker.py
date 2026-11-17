"""Google access for workspaces, narrower than OAuth scopes allow.

A Google *account* (Keys & tokens -> Google accounts) is your OAuth consent with
your own OAuth client; its refresh token stays in secrets/google/. A *grant* is
a pool token (secrets/tokens/<id>.json, service "google") naming an account
and a preset: what a workspace may do with that account. The sandbox sees a
placeholder and a base URL, as for any pool token; nono's proxy:

  - asks bin/google-token for a fresh access token (cmd:// credential,
    cached for CAPTURE_TTL), so the sandbox never holds even that;
  - lets through only the preset's method + path rules (endpoint_rules,
    default-deny), e.g. GETs on messages and threads, nothing that sends,
    modifies, deletes or reads settings or attachments.

Presets whose rules depend on the query or on the message itself (one Gmail
label only) go through the proxy service's HTTP bridge instead (ui/proxyd.py),
which checks each request with check_request() below and, for a single
message or thread, asks Google for its labels first.

Stdlib only: the UI, the proxy service and bin/google-token import this.
"""

import json
import os
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from common import SECRETS

GOOGLE_DIR = SECRETS / "google"
CLIENT_FILE = GOOGLE_DIR / "client.json"        # {"client_id", "client_secret", "type", "redirect_uris"}
ACCOUNTS = GOOGLE_DIR / "accounts"              # <id>.json: email, refresh_token, scopes
CACHE = GOOGLE_DIR / "cache"                    # <id>.json: access_token, expires (bin/google-token)
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
REVOKE_URL = "https://oauth2.googleapis.com/revoke"
USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
# A "Desktop app" OAuth client may redirect to any loopback port. Nothing
# listens on this one: you copy the address the browser fails to open back
# into the UI, so this works whatever host and name the UI has. A "Web
# application" client redirects to the UI itself (CALLBACK_PATH) instead,
# which Google allows only for a name under a public TLD, or localhost.
REDIRECT_URI = "http://127.0.0.1:1/"
CALLBACK_PATH = "/oauth/google/callback"
# Names Google won't take as a web redirect (no public suffix)
PRIVATE_TLDS = {"local", "lan", "home", "internal", "localdomain", "arpa", "test", "invalid", "example",
                "corp", "intranet", "private", "intra", "localhost", "router", "box"}
CAPTURE_TTL = 2700                              # access tokens last 3600 s
ACCOUNT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
LABEL_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")  # a Gmail label id (INBOX, Label_123…)
# Query parameters a broker grant never passes on: other credentials, response
# rewriting (JSONP, alternate formats), uploads, and spam/trash
FORBIDDEN_PARAMS = {"access_token", "key", "alt", "$.xgafv", "callback", "uploadtype", "upload_protocol",
                    "oauth_token", "bearer_token", "includespamtrash"}

SCOPES = {
    "gmail.readonly": "https://www.googleapis.com/auth/gmail.readonly",
    "gmail.metadata": "https://www.googleapis.com/auth/gmail.metadata",
    "calendar.readonly": "https://www.googleapis.com/auth/calendar.readonly",
}

_GMAIL_READ = [
    ("GET", "/gmail/v1/users/me/profile"),
    ("GET", "/gmail/v1/users/me/labels"),
    ("GET", "/gmail/v1/users/me/labels/*"),
    ("GET", "/gmail/v1/users/me/messages"),
    ("GET", "/gmail/v1/users/me/messages/*"),
    ("GET", "/gmail/v1/users/me/threads"),
    ("GET", "/gmail/v1/users/me/threads/*"),
]

# label: "env" names the variables (GMAIL_..., GCAL_...); "broker": through the bridge
PRESETS = {
    "gmail-read": {
        "label": "Gmail: read messages and threads",
        "detail": "Search, list and read messages, threads and labels. No sending, drafts, changes, "
                  "deleting, settings, history or attachments.",
        "host": "gmail.googleapis.com", "scope": "gmail.readonly", "env": "GMAIL", "rules": _GMAIL_READ},
    "gmail-metadata": {
        "label": "Gmail: headers only",
        "detail": "As above, but Google returns only headers and labels, never bodies, and there is "
                  "no full-text search (the gmail.metadata scope).",
        "host": "gmail.googleapis.com", "scope": "gmail.metadata", "env": "GMAIL", "rules": _GMAIL_READ},
    "gmail-label": {
        "label": "Gmail: read one label only",
        "detail": "Read access as Gmail read, limited to messages and threads that carry one label "
                  "(e.g. a filter's label): lists are narrowed to it, and any other message is refused. "
                  "No attachments.",
        "host": "gmail.googleapis.com", "scope": "gmail.readonly", "env": "GMAIL", "rules": _GMAIL_READ,
        "broker": True, "needs_label": True},
    "calendar-read": {
        "label": "Calendar: read events",
        "detail": "List your calendars and read their events. No creating, changing or deleting, "
                  "no sharing settings.",
        "host": "www.googleapis.com", "scope": "calendar.readonly", "env": "GCAL",
        "rules": [("GET", "/calendar/v3/users/me/calendarList"),
                  ("GET", "/calendar/v3/users/me/calendarList/*"),
                  ("GET", "/calendar/v3/calendars/*/events"),
                  ("GET", "/calendar/v3/calendars/*/events/*")]},
}


# ---------------------------------------------------------------- OAuth

def private_write_bytes(path: Path, data: bytes):
    """Create/replace a 0600 file atomically."""
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def client() -> dict | None:
    try:
        c = json.loads(CLIENT_FILE.read_text())
        return c if c.get("client_id") and c.get("client_secret") else None
    except (OSError, ValueError):
        return None


def account_path(aid: str) -> Path:
    if not ACCOUNT_RE.match(aid):
        raise ValueError("Bad account id")
    return ACCOUNTS / f"{aid}.json"


def account(aid: str) -> dict | None:
    try:
        return json.loads(account_path(aid).read_text())
    except (OSError, ValueError):
        return None


def accounts() -> list[dict]:
    out = []
    for p in sorted(ACCOUNTS.glob("*.json")):
        if (a := account(p.stem)) is not None:
            out.append({"id": p.stem, "email": a.get("email", ""), "scopes": a.get("scopes", []),
                        "created": a.get("created", 0)})
    return out


def _post(url: str, form: dict, timeout: float = 20) -> dict:
    req = urllib.request.Request(url, data=urllib.parse.urlencode(form).encode(),
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read() or b"{}")
        except ValueError:
            body = {}
        raise ValueError(f"Google said {e.code}: {body.get('error_description') or body.get('error') or e.reason}")


def parse_client(body: dict) -> dict:
    """Your OAuth client, from the JSON Google Cloud Console downloads (its
    "web" or "installed" object) or from the ID and secret typed in."""
    raw = str(body.get("json", "") or "").strip()
    if raw:
        try:
            doc = json.loads(raw)
        except ValueError:
            raise ValueError("That isn't the client's JSON file (client_secret_….json)") from None
        kind = "web" if "web" in doc else "desktop" if "installed" in doc else ""
        if not kind or not isinstance(doc.get("web" if kind == "web" else "installed"), dict):
            raise ValueError("That JSON has no \"web\" or \"installed\" client in it")
        c = doc["web" if kind == "web" else "installed"]
        cid, secret = str(c.get("client_id", "")), str(c.get("client_secret", ""))
        uris = [u for u in c.get("redirect_uris", []) if isinstance(u, str)][:50]
    else:
        cid, secret = str(body.get("client_id", "")).strip(), str(body.get("client_secret", "")).strip()
        kind = "web" if body.get("type") == "web" else "desktop"
        uris = []
    if not re.fullmatch(r"[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com", cid):
        raise ValueError("Client ID: the ….apps.googleusercontent.com one from Google Cloud Console")
    if not re.fullmatch(r"[A-Za-z0-9_-]{10,100}", secret):
        raise ValueError("Paste the client secret")
    return {"client_id": cid, "client_secret": secret, "type": kind, "redirect_uris": uris}


def callback_problem(hostname: str) -> str:
    """Why Google won't redirect back to the UI at this name ("" if it will)."""
    import ipaddress
    h = hostname.lower().rstrip(".")
    if h == "localhost":
        return ""
    try:
        ip = ipaddress.ip_address(h.strip("[]"))
        return "" if ip.is_loopback else (
            f"Google won't redirect to an IP address ({h}). Open this page by a DNS name instead "
            "(add it to ui/extra-hostnames), or connect with the paste-back way below.")
    except ValueError:
        pass
    if "." not in h or h.rsplit(".", 1)[1] in PRIVATE_TLDS:
        return (f"Google only redirects to a name under a public top-level domain (.com, .net, .uk…); "
                f"{h} isn't one. The name needn't resolve on the internet: a public-domain name in your "
                "local DNS works. Or connect with the paste-back way below.")
    return ""


def auth_url(scopes: list[str], state: str, challenge: str, redirect_uri: str = REDIRECT_URI) -> str:
    c = client()
    if not c:
        raise ValueError("Add your OAuth client first")
    return AUTH_URL + "?" + urllib.parse.urlencode({
        "client_id": c["client_id"], "redirect_uri": redirect_uri, "response_type": "code",
        "scope": " ".join(["openid", "email"] + [SCOPES[s] for s in scopes]),
        "access_type": "offline", "prompt": "consent", "include_granted_scopes": "false",
        "state": state, "code_challenge": challenge, "code_challenge_method": "S256"})


def exchange(code: str, verifier: str, redirect_uri: str = REDIRECT_URI) -> dict:
    """The consent's code for tokens; returns {email, refresh_token, scopes}."""
    c = client()
    if not c:
        raise ValueError("No OAuth client")
    tok = _post(TOKEN_URL, {"code": code, "client_id": c["client_id"], "client_secret": c["client_secret"],
                            "redirect_uri": redirect_uri, "grant_type": "authorization_code",
                            "code_verifier": verifier})
    if not tok.get("refresh_token"):
        raise ValueError("Google sent no refresh token; remove this app's access in your Google account "
                         "(myaccount.google.com/permissions) and connect again")
    req = urllib.request.Request(USERINFO_URL, headers={"Authorization": f"Bearer {tok['access_token']}"})
    with urllib.request.urlopen(req, timeout=20) as r:
        email = json.loads(r.read()).get("email", "")
    granted = set(tok.get("scope", "").split())
    return {"email": email, "refresh_token": tok["refresh_token"],
            "scopes": [k for k, v in SCOPES.items() if v in granted]}


def save_account(aid: str, data: dict):
    ACCOUNTS.mkdir(mode=0o700, parents=True, exist_ok=True)
    private_write_bytes(account_path(aid), (json.dumps({**data, "created": int(time.time())}, indent=2)
                                            + "\n").encode())


def remove_account(aid: str):
    a = account(aid)
    if a and a.get("refresh_token"):
        try:
            _post(REVOKE_URL, {"token": a["refresh_token"]}, timeout=10)
        except (ValueError, OSError):
            pass        # deleted here either way
    account_path(aid).unlink(missing_ok=True)
    (CACHE / f"{aid}.json").unlink(missing_ok=True)


def access_token(aid: str) -> str:
    """A current access token for the account (bin/google-token; the UI when
    checking a label). Cached on disk until shortly before it expires."""
    account_path(aid)                       # checks the id
    cache = CACHE / f"{aid}.json"
    try:
        c = json.loads(cache.read_text())
        if c.get("expires", 0) > time.time() + 300:
            return c["access_token"]
    except (OSError, ValueError, KeyError):
        pass
    a, cl = account(aid), client()
    if not a or not cl:
        raise ValueError(f"No Google account '{aid}' (or no OAuth client)")
    tok = _post(TOKEN_URL, {"client_id": cl["client_id"], "client_secret": cl["client_secret"],
                            "refresh_token": a["refresh_token"], "grant_type": "refresh_token"})
    CACHE.mkdir(mode=0o700, parents=True, exist_ok=True)
    private_write_bytes(cache, json.dumps({"access_token": tok["access_token"],
                                           "expires": time.time() + int(tok.get("expires_in", 3600))}).encode())
    return tok["access_token"]


def gmail_labels(aid: str) -> list[dict]:
    req = urllib.request.Request("https://gmail.googleapis.com/gmail/v1/users/me/labels",
                                 headers={"Authorization": f"Bearer {access_token(aid)}"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return [{"id": x["id"], "name": x.get("name", x["id"])} for x in json.loads(r.read()).get("labels", [])]


# ---------------------------------------------------------------- grants

def grant_meta(tid: str, aid: str, preset: str, label: str = "", label_name: str = "") -> dict:
    """The pool token's metadata for a grant (validated)."""
    p = PRESETS.get(preset)
    if not p:
        raise ValueError("Unknown preset")
    a = account(aid)
    if not a:
        raise ValueError(f"No Google account '{aid}'")
    if p["scope"] not in a.get("scopes", []):
        raise ValueError(f"{a.get('email', aid)} wasn't connected with {p['scope']}: connect it again "
                         "with that ticked")
    if p.get("needs_label") and not LABEL_RE.match(label):
        raise ValueError("Pick the label")
    var = f"{p['env']}_{tid.replace('-', '_').upper()}"
    meta = {"service": "google", "label": f"{p['label']} ({a.get('email', aid)})",
            "upstream": f"https://{p['host']}", "inject_header": "Authorization",
            "credential_format": "Bearer {}", "env_var": f"{var}_TOKEN",
            "account": aid, "preset": preset,
            "endpoint_rules": [{"method": m, "path": path} for m, path in p["rules"]]}
    if p.get("broker"):
        meta.update(broker=True, gmail_label=label, gmail_label_name=label_name or label)
    return meta


def grant_summary(meta: dict) -> str:
    p = PRESETS.get(meta.get("preset", ""), {})
    s = p.get("detail", "")
    if meta.get("gmail_label"):
        s += f" Label: {meta.get('gmail_label_name') or meta['gmail_label']}."
    return s


# ---------------------------------------------------------------- the bridge's checks (broker presets)

_MSG = re.compile(r"^/gmail/v1/users/me/(messages|threads)(?:/([A-Za-z0-9]{1,64}))?$")


def check_request(meta: dict, method: str, target: str):
    """For a broker grant: what to do with this request (path + query as sent).

    Returns ("deny", reason) | ("forward", new_target) |
    ("verify", new_target, lookup_target, kind) where lookup_target is a
    minimal GET whose labels must include the grant's label before
    new_target is sent (kind "messages" or "threads").
    """
    label = meta.get("gmail_label", "")
    if method != "GET":
        return ("deny", "only GET requests are allowed")
    path, _, query = target.partition("?")
    # Anything a server might normalise differently from us: refuse outright
    if "%" in path or "//" in path or "/./" in path or "/../" in path or path.endswith(("/.", "/..")) \
            or "\\" in path or ";" in path:
        return ("deny", "unusual characters in the path")
    try:
        params = urllib.parse.parse_qsl(query, keep_blank_values=True, strict_parsing=bool(query))
    except ValueError:
        return ("deny", "malformed query")
    if any(k.lower() in FORBIDDEN_PARAMS for k, _ in params):
        return ("deny", "query parameter not allowed")
    if path in ("/gmail/v1/users/me/profile", "/gmail/v1/users/me/labels",
                f"/gmail/v1/users/me/labels/{label}"):
        return ("forward", target)
    m = _MSG.match(path)
    if not m:
        return ("deny", "not an allowed Gmail endpoint")
    kind, item = m[1], m[2]
    if item is None:
        # A list or search: narrowed to the label (labelIds are ANDed)
        params = [(k, v) for k, v in params if k != "labelIds"] + [("labelIds", label)] + \
                 [(k, v) for k, v in params if k == "labelIds" and v != label]
        return ("forward", path + "?" + urllib.parse.urlencode(params))
    lookup = f"/gmail/v1/users/me/{kind}/{item}?" + urllib.parse.urlencode(
        [("format", "minimal")] + ([("fields", "messages/labelIds")] if kind == "threads" else
                                   [("fields", "labelIds")]))
    return ("verify", target, lookup, kind)


def lookup_allows(meta: dict, kind: str, body: bytes) -> bool:
    """Does the minimal lookup's answer show the grant's label (on every
    message of a thread)?"""
    label = meta.get("gmail_label", "")
    try:
        data = json.loads(body)
    except ValueError:
        return False
    if kind == "messages":
        return label in (data.get("labelIds") or [])
    msgs = data.get("messages") or []
    return bool(msgs) and all(label in (m.get("labelIds") or []) for m in msgs)


def audit(line: dict, path: Path):
    """One JSON line per broker decision (never the token, never query values)."""
    try:
        with open(path, "a") as f:
            f.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **line}) + "\n")
        os.chmod(path, 0o600)
    except OSError:
        pass
