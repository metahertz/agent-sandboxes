"use strict";
// The sign-in page: the system password (PAM) or a passkey (WebAuthn).

const $ = (sel) => document.querySelector(sel);

const b64u = {
  enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
  dec: (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4)), (c) => c.charCodeAt(0)),
};

async function post(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "X-Requested-With": "sbui", "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function say(text, isErr = false) {
  $("#msg").textContent = text;
  $("#msg").classList.toggle("err", isErr);
}

// Back to where we were (the dashboard's hash survives), or the dashboard
const done = () => location.replace(location.pathname === "/login" ? "/" : location.href);

$("#pw-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  const btn = f.querySelector("button");
  btn.disabled = true;
  say("Checking…");
  try {
    await post("/auth/password", { username: f.elements.username.value.trim(), password: f.elements.password.value });
    say("Signed in.");
    done();
  } catch (e) {
    say(e.message, true);
    f.elements.password.select();
  }
  btn.disabled = false;
});

// A passkey sign-in: "conditional" offers passkeys in the username field's
// autofill while the page is open; the button asks right away.
let conditional = null;

async function passkey(mediation) {
  const opts = await post("/auth/passkey/options", {});
  const ctl = new AbortController();
  if (mediation === "conditional") conditional = ctl;
  else conditional?.abort();
  const pk = opts.publicKey;
  const cred = await navigator.credentials.get({
    publicKey: { ...pk, challenge: b64u.dec(pk.challenge) },
    mediation,
    signal: ctl.signal,
  });
  if (!cred) return;
  say("Checking…");
  const r = cred.response;
  await post("/auth/passkey/verify", {
    challengeId: opts.challengeId,
    credential: {
      id: cred.id,
      response: {
        clientDataJSON: b64u.enc(r.clientDataJSON),
        authenticatorData: b64u.enc(r.authenticatorData),
        signature: b64u.enc(r.signature),
        userHandle: r.userHandle ? b64u.enc(r.userHandle) : null,
      },
    },
  });
  say("Signed in.");
  done();
}

const quiet = (e) => e.name === "AbortError" || e.name === "NotAllowedError";

if (!window.PublicKeyCredential) {
  $("#passkey").disabled = true;
  $("#passkey").title = "This browser (or a page without HTTPS) can't use passkeys";
} else {
  $("#passkey").addEventListener("click", () =>
    passkey("optional").catch((e) => say(quiet(e) ? "Passkey sign-in cancelled." : e.message, !quiet(e))));
  // In the background: a problem here (e.g. the page opened by IP address) is
  // only a note; the button reports it properly when used
  PublicKeyCredential.isConditionalMediationAvailable?.().then((ok) => {
    if (ok) passkey("conditional").catch((e) => { if (!quiet(e)) say(e.message); });
  });
}
