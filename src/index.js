/**
 * ghgen v2 — email auth + pool claims with regions + limits
 * Env: POOL_KEY, UPLOAD_SECRET, RESEND_API_KEY
 * Discord OAuth: DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET
 */

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-Upload-Secret",
};

const SESSION_TTL = 7 * 24 * 60 * 60;
const DAY_WINDOW = 24 * 60 * 60;
const CODE_TTL = 10 * 60;

const PLAN_LIMITS = {
  day:   { limit: 3,  cooldown: 20 },
  week:  { limit: 10, cooldown: 30 },
  month: { limit: 30, cooldown: 60 },
  year:  { limit: 40, cooldown: 70 },
};

const jsonHeaders = { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" };
let MAIN_SITE = "https://greedyhudzell.xyz";
function setMainSite(v) { if (v) MAIN_SITE = v; }

const now = () => Math.floor(Date.now() / 1000);

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), { status, headers: { ...jsonHeaders, ...CORS, ...extra } });
}
function html(body, status = 200, extra = {}) {
  return new Response(body, { status, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...extra } });
}
function getIP(request) {
  return request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() || "";
}
async function sha256(str) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, "0")).join("");
}
function randomId(len = 24) {
  const b = new Uint8Array(len);
  crypto.getRandomValues(b);
  return [...b].map(x => x.toString(16).padStart(2, "0")).join("");
}
function randomCode6() {
  const b = new Uint8Array(4);
  crypto.getRandomValues(b);
  const n = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
  return String(n % 1000000).padStart(6, "0");
}
function cookieHeader(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}
function clearCookieHeader(name) {
  return `${name}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`;
}
function getCookie(request, name) {
  const c = request.headers.get("Cookie") || "";
  for (const part of c.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return decodeURIComponent(rest.join("="));
  }
  return null;
}
function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToB64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function validEmail(e) { return /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(e); }
function validUsername(u) { return /^[A-Za-z0-9_]{3,32}$/.test(u); }
function validRobloxUsername(u) { return /^[A-Za-z0-9_]{3,20}$/.test(u); }

// ============================================================
//  ENV HELPERS (never hardcode)
// ============================================================
async function getPoolKey(env) {
  const raw = env.POOL_KEY;
  if (!raw) throw new Error("POOL_KEY not set");
  const kb = b64ToBytes(raw);
  if (kb.length !== 32) throw new Error("POOL_KEY must be 32 bytes");
  return crypto.subtle.importKey("raw", kb, "AES-GCM", false, ["encrypt", "decrypt"]);
}
async function encryptPayload(env, obj) {
  const key = await getPoolKey(env);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(JSON.stringify(obj));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
  return `${bytesToB64(iv)}:${bytesToB64(new Uint8Array(ct))}`;
}
async function decryptPayload(env, stored) {
  const key = await getPoolKey(env);
  const [ivB64, ctB64] = stored.split(":");
  const iv = b64ToBytes(ivB64);
  const ct = b64ToBytes(ctB64);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return JSON.parse(new TextDecoder().decode(pt));
}

// ============================================================
//  EMAIL (Resend)
// ============================================================
async function sendEmail(env, to, code) {
  const apiKey = env.RESEND_API_KEY;
  if (!apiKey) {
    console.error("sendEmail: RESEND_API_KEY not set");
    return { ok: false, error: "RESEND_API_KEY_not_set" };
  }

  const html = `
    <div style="font-family:-apple-system,sans-serif;background:#0c0c0d;color:#e8e8ea;padding:40px;border-radius:12px;max-width:480px;margin:0 auto">
      <div style="font-size:22px;font-weight:800;color:#c9a227;letter-spacing:2px;margin-bottom:20px">GHGen</div>
      <p style="color:#e8e8ea;margin:0 0 12px">Your verification code:</p>
      <div style="font-size:34px;font-weight:700;letter-spacing:8px;color:#c9a227;background:#18181b;padding:22px;border-radius:10px;text-align:center;margin:16px 0;font-family:ui-monospace,monospace">${code}</div>
      <p style="color:#8a8a93;font-size:13px;margin:16px 0 0">Expires in 10 minutes.</p>
      <p style="color:#5a5a63;font-size:12px;margin:24px 0 0;padding-top:16px;border-top:1px solid #27272a">If you didn't request this, ignore this email.</p>
    </div>
  `;

  const payload = {
    from: "GHGen <support@gen.greedyhudzell.xyz>",
    to: [to],
    subject: "GHGen — verification code",
    html,
  };

  let res;
  try {
    res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        "User-Agent": "GHGen-Worker/1.0",
      },
      body: JSON.stringify(payload),
    });
  } catch (e) {
    console.error("sendEmail fetch error:", String(e));
    return { ok: false, error: "fetch_failed", message: String(e.message || e) };
  }

  const bodyText = await res.text().catch(() => "");
  console.log("resend response:", res.status, bodyText.slice(0, 500));

  if (!res.ok) {
    let parsed = null;
    try { parsed = JSON.parse(bodyText); } catch {}
    return {
      ok: false,
      error: `resend_http_${res.status}`,
      message: (parsed && (parsed.message || parsed.error)) || bodyText.slice(0, 200),
    };
  }
  return { ok: true };
}

// ============================================================
//  SESSIONS
// ============================================================
async function createSession(env, userId, ip) {
  const sid = randomId(32);
  const ts = now();
  const ipHash = ip ? await sha256(ip) : null;
  await env.DB.prepare(
    `INSERT INTO ghgen_sessions (session_id, user_id, created_at, expires_at, ip_hash) VALUES (?, ?, ?, ?, ?)`
  ).bind(sid, userId, ts, ts + SESSION_TTL, ipHash).run();
  return sid;
}
async function getUser(env, sessionId) {
  if (!sessionId) return null;
  const s = await env.DB.prepare(
    `SELECT u.id, u.key, u.ghgen_username, u.roblox_username, u.email, u.discord_id
     FROM ghgen_sessions s JOIN ghgen_users u ON u.id = s.user_id
     WHERE s.session_id = ? AND s.expires_at > ? LIMIT 1`
  ).bind(sessionId, now()).first();
  return s || null;
}
function requireUser(env, request) {
  return getUser(env, getCookie(request, "GHGEN_SESSION"));
}

async function loadKeyStatus(env, key) {
  const r = await env.DB.prepare(`SELECT * FROM keys WHERE key = ? LIMIT 1`).bind(key).first();
  if (!r) return { valid: false, reason: "invalid_key" };
  if (r.revoked === 1) return { valid: false, reason: "revoked", plan: r.plan };
  if (Number(r.expires_at) <= now()) return { valid: false, reason: "expired", plan: r.plan, expires_at: r.expires_at };
  return { valid: true, plan: r.plan || "day", expires_at: r.expires_at, key_username: r.username };
}

// ============================================================
//  HTML
// ============================================================
function pageShell(title, content) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${title} · GHGen</title>
<style>
:root{--bg:#0c0c0d;--bg2:#131316;--card:#18181b;--line:#27272a;--text:#e8e8ea;--muted:#8a8a93;--accent:#c9a227;--ok:#4caf7a;--bad:#e85d5d}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Inter,system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;line-height:1.5}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.wrap{width:min(960px,94vw);margin:0 auto;padding:28px 0 80px}
.top{border-bottom:1px solid var(--line);background:rgba(12,12,13,.85);backdrop-filter:blur(12px);position:sticky;top:0;z-index:10}
.top-inner{width:min(960px,94vw);margin:0 auto;display:flex;align-items:center;justify-content:space-between;padding:14px 0}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;color:var(--text)}
.brand-mark{width:32px;height:32px;border-radius:8px;background:#1a1a1d;border:1px solid var(--accent);display:grid;place-items:center;color:var(--accent);font-size:12px;font-weight:800}
.nav{display:flex;gap:6px;align-items:center}
.nav a{color:var(--muted);padding:7px 12px;border-radius:8px;font-size:13px;font-weight:500}
.nav a:hover{color:var(--text);background:var(--bg2);text-decoration:none}
h1{font-size:1.6rem;font-weight:700;margin-bottom:6px}
h2{font-size:1.05rem;font-weight:600;margin-bottom:10px}
.sub{color:var(--muted);font-size:14px;margin-bottom:22px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin:12px 0}
label{display:block;color:var(--muted);font-size:12px;font-weight:600;margin:10px 0 6px}
input,select,textarea{width:100%;background:#0e0e11;border:1px solid var(--line);color:var(--text);padding:11px 12px;border-radius:8px;font-size:14px;font-family:inherit}
input:focus,select:focus,textarea:focus{outline:1px solid var(--accent)}
button,.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:11px 18px;border-radius:8px;border:1px solid var(--line);background:var(--bg2);color:var(--text);font-weight:600;font-size:13px;cursor:pointer;font-family:inherit}
button:hover,.btn:hover{border-color:var(--accent);color:var(--accent);text-decoration:none}
button.primary{background:var(--accent);color:#0a0a0a;border-color:var(--accent)}
button.primary:hover{color:#0a0a0a;filter:brightness(1.08)}
button:disabled{opacity:.45;cursor:not-allowed}
button:disabled:hover{color:var(--text);border-color:var(--line)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:760px){.grid{grid-template-columns:1fr}}
.muted{color:var(--muted);font-size:13px}
.ok{color:var(--ok)}.err{color:var(--bad)}
.mono{font-family:ui-monospace,monospace;font-size:12px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
.badge{display:inline-block;font-size:11px;font-weight:600;padding:2px 8px;border-radius:999px;background:rgba(201,162,39,.12);color:var(--accent);border:1px solid rgba(201,162,39,.25)}
.badge.ok{background:rgba(76,175,122,.12);color:var(--ok);border-color:rgba(76,175,122,.3)}
.badge.err{background:rgba(232,93,93,.12);color:var(--bad);border-color:rgba(232,93,93,.3)}
.note{color:var(--muted);font-size:12px;margin-top:14px}
.why{margin-top:14px;padding-top:12px;border-top:1px solid var(--line);color:var(--muted);font-size:12px;font-style:italic}
.reveal{background:#0a0a0c;border:1px dashed var(--line);padding:6px 10px;border-radius:6px;cursor:pointer;display:inline-block;color:var(--muted);font-size:12px;user-select:none}
.reveal:hover{border-color:var(--accent);color:var(--accent)}
.reveal.copied{border-color:var(--ok);color:var(--ok)}
.limit-banner{display:none;background:rgba(232,93,93,.1);border:1px solid rgba(232,93,93,.35);color:#f8b0b0;padding:14px 18px;border-radius:10px;margin:12px 0;font-weight:600;text-align:center;font-size:14px}
.limit-banner.show{display:block}
.limit-banner .time{color:#fff;font-family:ui-monospace,monospace;font-size:16px;margin-left:8px}
.reset-bar{background:var(--bg2);border:1px solid var(--line);border-radius:8px;padding:10px 14px;margin-bottom:14px;font-size:13px;color:var(--muted);display:flex;justify-content:space-between;align-items:center}
.reset-bar b{color:var(--text);font-family:ui-monospace,monospace}
.counter{font-size:28px;font-weight:700;color:var(--accent);font-family:ui-monospace,monospace}
.counter span{color:var(--muted);font-size:15px;font-weight:500}
.region-select{display:flex;gap:10px;align-items:flex-end}
.region-select > div:first-child{flex:1}
.region-hint{margin-top:8px;padding:10px 12px;background:#0e0e11;border:1px solid var(--line);border-radius:8px;font-size:12px;color:var(--muted);line-height:1.7;max-height:150px;overflow-y:auto}
.region-hint .r{display:flex;justify-content:space-between;padding:2px 0}
.region-hint .r b{color:var(--text);font-weight:500}
</style>
</head>
<body>
<header class="top">
  <div class="top-inner">
    <a class="brand" href="/"><div class="brand-mark">GH</div><span>GHGen</span></a>
    <nav class="nav">
      <a href="/dashboard">Dashboard</a>
      <a href="/docs">Docs</a>
      <a href="${MAIN_SITE}">Main site ↗</a>
    </nav>
  </div>
</header>
<main class="wrap">${content}</main>
</body>
</html>`;
}

function authPage(msg = "") {
  return pageShell("Auth", `
  <h1>Sign in / Register</h1>
  <p class="sub">Enter your email — we'll send a verification code.</p>

  <div id="step1" class="card">
    ${msg ? `<p class="err" style="margin-bottom:12px">${msg}</p>` : ""}
    <label>Email</label>
    <input id="email" type="email" placeholder="you@gmail.com" autocomplete="email"/>
    <button class="primary" id="btn-send" style="width:100%;margin-top:16px">Send code</button>
    <p class="note" id="s1-out"></p>
  </div>

  <div id="step2" class="card" style="display:none">
    <p class="muted" style="margin-bottom:10px">Code sent to <b id="email-shown"></b> (expires in 10 min)</p>
    <label>Verification code</label>
    <input id="code" type="text" maxlength="6" inputmode="numeric" placeholder="123456" autocomplete="one-time-code"/>
    <button class="primary" id="btn-verify" style="width:100%;margin-top:16px">Verify</button>
    <p class="note" id="s2-out"></p>
  </div>

  <div id="step3" class="card" style="display:none">
    <p class="muted" style="margin-bottom:12px">New email — complete registration:</p>
    <label>Key</label>
    <input id="reg-key" placeholder="GH-XXXX-XXXX-XXXX" autocomplete="off"/>
    <label>Roblox username</label>
    <input id="reg-rbx" placeholder="Not display name" autocomplete="off"/>
    <label>GHGen username</label>
    <input id="reg-user" placeholder="3-32 chars, A-Za-z0-9_" autocomplete="off"/>
    <button class="primary" id="btn-register" style="width:100%;margin-top:16px">Create account</button>
    <p class="note" id="s3-out"></p>
  </div>

  <script>
  let currentEmail = "";

  document.getElementById('btn-send').addEventListener('click', async () => {
    const email = document.getElementById('email').value.trim();
    const out = document.getElementById('s1-out');
    if (!email) { out.className = 'note err'; out.textContent = 'Enter email'; return; }
    out.className = 'note'; out.textContent = 'Sending…';
    const r = await fetch('/api/auth/send-code', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ email })
    });
    const d = await r.json();
    if (!d.ok) { out.className = 'note err'; out.textContent = d.error || 'error'; return; }
    currentEmail = email;
    document.getElementById('step1').style.display = 'none';
    document.getElementById('step2').style.display = 'block';
    document.getElementById('email-shown').textContent = email;
    document.getElementById('code').focus();
  });

  document.getElementById('btn-verify').addEventListener('click', async () => {
    const code = document.getElementById('code').value.trim();
    const out = document.getElementById('s2-out');
    out.className = 'note'; out.textContent = 'Verifying…';
    const r = await fetch('/api/auth/verify', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ email: currentEmail, code })
    });
    const d = await r.json();
    if (!d.ok) { out.className = 'note err'; out.textContent = d.error || 'error'; return; }
    if (d.mode === 'login') { window.location.href = '/dashboard'; return; }
    document.getElementById('step2').style.display = 'none';
    document.getElementById('step3').style.display = 'block';
  });

  document.getElementById('btn-register').addEventListener('click', async () => {
    const key = document.getElementById('reg-key').value.trim();
    const roblox_username = document.getElementById('reg-rbx').value.trim();
    const ghgen_username = document.getElementById('reg-user').value.trim();
    const out = document.getElementById('s3-out');
    out.className = 'note'; out.textContent = 'Creating…';
    const r = await fetch('/api/auth/register', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ email: currentEmail, key, roblox_username, ghgen_username })
    });
    const d = await r.json();
    if (!d.ok) { out.className = 'note err'; out.textContent = d.error || 'error'; return; }
    window.location.href = '/dashboard';
  });

  document.getElementById('code').addEventListener('keydown', e => {
    if (e.key === 'Enter') document.getElementById('btn-verify').click();
  });
  </script>
  `);
}

function dashboardPage(user, keyStatus) {
  return pageShell("Dashboard", `
  <h1>Dashboard</h1>
  <p class="sub">Signed in as <b>${escapeHtml(user.ghgen_username)}</b> · <a href="/logout">Logout</a></p>

  <div id="limit-banner" class="limit-banner">
    You reached your daily limit!<span class="time" id="limit-time">00:00:00 left</span>
  </div>

  <div class="reset-bar">
    <span>Key: <b>${escapeHtml(user.key)}</b> · Plan: <b>${keyStatus.plan || '—'}</b></span>
    <span>Reset in: <b id="reset-in">—</b></span>
  </div>

  <div class="grid">
    <div class="card">
      <h2>Claim account</h2>
      <div class="region-select">
        <div>
          <label>Region</label>
          <select id="region">
            <option value="">🎲 Random</option>
          </select>
        </div>
        <button class="primary" id="btn-claim" style="min-width:150px">Claim account</button>
      </div>
      <div class="region-hint" id="region-hint"></div>
      <p class="note" id="claim-out"></p>
      <p class="why">Why? I am generating these accounts alone, the pool is not big</p>
    </div>
    <div class="card">
      <h2>Your limit</h2>
      <p><span class="counter" id="counter">—</span> <span>today</span></p>
      <p class="muted" style="margin-top:8px">Plan: <b>${keyStatus.plan || '—'}</b></p>
      <p class="muted">Cooldown: <b id="cooldown-sec">—</b> sec between claims</p>
      <p style="margin-top:14px">
        ${keyStatus.valid ? `<span class="badge ok">ACTIVE</span>` : `<span class="badge err">${keyStatus.reason || 'INVALID'}</span>`}
      </p>
    </div>
  </div>

  <div class="card">
    <h2>Your accounts</h2>
    <div id="accounts-list"><p class="muted">Loading…</p></div>
  </div>

  <script>
  const USER_KEY = ${JSON.stringify(user.key)};
  function mask(v){ if(!v) return '—'; const s=String(v); if(s.length<=6) return s[0]+'•••'; return s.slice(0,3)+'•••'+s.slice(-2); }
  function fmtHMS(sec){ const h=Math.floor(sec/3600),m=Math.floor((sec%3600)/60),s=sec%60; return String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+String(s).padStart(2,'0'); }

  let resetInSec = 0;
  let cooldownSec = 20;
  let limitMax = 3;
  let limitUsed = 0;
  let cooldownTimer = null;

  async function loadState() {
    const r = await fetch('/api/state', { credentials: 'same-origin' });
    const d = await r.json();
    if (!d.ok) return;
    resetInSec = d.reset_in || 0;
    cooldownSec = d.cooldown_seconds || 20;
    limitMax = d.limit || 3;
    limitUsed = d.used || 0;
    document.getElementById('counter').innerHTML = limitUsed + ' <span>/ ' + limitMax + '</span>';
    document.getElementById('cooldown-sec').textContent = cooldownSec;
    document.getElementById('reset-in').textContent = fmtHMS(resetInSec);
    updateLimitBanner();
    if (d.next_claim_in > 0) startCooldown(d.next_claim_in);
  }

  function updateLimitBanner() {
    const banner = document.getElementById('limit-banner');
    const timeEl = document.getElementById('limit-time');
    const btn = document.getElementById('btn-claim');
    if (limitUsed >= limitMax) {
      banner.classList.add('show');
      timeEl.textContent = fmtHMS(resetInSec) + ' left';
      btn.disabled = true;
    } else {
      banner.classList.remove('show');
    }
  }

  async function loadRegions() {
    const r = await fetch('/api/regions', { credentials: 'same-origin' });
    const d = await r.json();
    if (!d.ok) return;
    const sel = document.getElementById('region');
    sel.innerHTML = '<option value="">🎲 Random</option>' +
      d.regions.map(x => '<option value="' + x.region + '">' + x.region + ' — ' + x.count + '</option>').join('');
    const hint = document.getElementById('region-hint');
    if (!d.regions.length) { hint.textContent = 'Pool is empty.'; return; }
    hint.innerHTML = d.regions.map(x =>
      '<div class="r"><b>' + x.region + '</b><span>' + x.count + ' available</span></div>'
    ).join('');
  }

  async function loadAccounts() {
    const el = document.getElementById('accounts-list');
    const r = await fetch('/api/accounts', { credentials: 'same-origin' });
    const d = await r.json();
    if (!d.ok) { el.innerHTML = '<p class="err">' + (d.error || 'error') + '</p>'; return; }
    if (!d.accounts.length) { el.innerHTML = '<p class="muted">No accounts yet.</p>'; return; }
    el.innerHTML = '<table><thead><tr><th>Username</th><th>Password</th><th>Location</th><th>Cookie</th><th>Claimed</th></tr></thead><tbody>'
      + d.accounts.map((a, i) => '<tr>'
        + '<td class="mono">' + a.u + '</td>'
        + '<td><span class="reveal reveal-pass" data-val="' + encodeURIComponent(a.p || '') + '">' + mask(a.p) + '</span></td>'
        + '<td>' + ((a.c || '') + (a.ci ? ', ' + a.ci : '') || '—') + (a.ip ? '<br><span class="muted mono">' + a.ip + '</span>' : '') + '</td>'
        + '<td>' + (a.ck ? '<span class="reveal reveal-cookie" data-val="' + encodeURIComponent(a.ck) + '">Copy cookie</span>' : '<span class="muted">—</span>') + '</td>'
        + '<td class="muted">' + new Date(a.issued_at * 1000).toLocaleString() + '</td>'
        + '</tr>').join('') + '</tbody></table>';

    document.querySelectorAll('.reveal-pass').forEach(el => {
      el.addEventListener('click', function(){
        const v = decodeURIComponent(this.dataset.val);
        if (this.dataset.revealed === '1') { this.textContent = mask(v); this.dataset.revealed = '0'; }
        else { this.textContent = v; this.dataset.revealed = '1'; }
      });
    });
    document.querySelectorAll('.reveal-cookie').forEach(el => {
      el.addEventListener('click', async function(){
        const v = decodeURIComponent(this.dataset.val);
        try {
          await navigator.clipboard.writeText(v);
          const old = this.textContent;
          this.textContent = 'Copied!';
          this.classList.add('copied');
          setTimeout(() => { this.textContent = old; this.classList.remove('copied'); }, 1500);
        } catch(e) { this.textContent = 'Failed'; setTimeout(() => { this.textContent = 'Copy cookie'; }, 1500); }
      });
    });
  }

  function startCooldown(sec) {
    const btn = document.getElementById('btn-claim');
    btn.disabled = true;
    let left = sec;
    if (cooldownTimer) clearInterval(cooldownTimer);
    btn.textContent = 'Wait ' + left + 's';
    cooldownTimer = setInterval(() => {
      left -= 1;
      if (left <= 0) {
        clearInterval(cooldownTimer);
        cooldownTimer = null;
        btn.textContent = 'Claim account';
        if (limitUsed < limitMax) btn.disabled = false;
      } else {
        btn.textContent = 'Wait ' + left + 's';
      }
    }, 1000);
  }

  document.getElementById('btn-claim').addEventListener('click', async () => {
    const btn = document.getElementById('btn-claim');
    const out = document.getElementById('claim-out');
    const region = document.getElementById('region').value;
    out.className = 'note'; out.textContent = 'Claiming…';
    btn.disabled = true;
    try {
      const r = await fetch('/api/claim', {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ region: region || null })
      });
      const d = await r.json();
      if (d.ok) {
        out.className = 'note ok';
        out.textContent = 'Claimed: ' + d.account.u;
        limitUsed += 1;
        document.getElementById('counter').innerHTML = limitUsed + ' <span>/ ' + limitMax + '</span>';
        updateLimitBanner();
        loadAccounts();
        loadRegions();
        startCooldown(cooldownSec);
      } else if (d.error === 'cooldown') {
        out.className = 'note err'; out.textContent = d.message || 'Cooldown';
        startCooldown(d.wait_seconds || cooldownSec);
      } else if (d.error === 'daily_limit') {
        out.className = 'note err'; out.textContent = 'Daily limit reached';
        resetInSec = d.reset_in || 0;
        updateLimitBanner();
      } else if (d.error === 'pool_empty') {
        out.className = 'note err'; out.textContent = 'No accounts in this region. Try Random.';
        btn.disabled = false;
      } else if (d.error === 'key_expired' || d.error === 'key_revoked' || d.error === 'key_invalid') {
        out.className = 'note err'; out.textContent = 'Your key is ' + d.error.replace('key_','') + '. Cannot claim.';
      } else {
        out.className = 'note err'; out.textContent = d.error || 'error';
        btn.disabled = false;
      }
    } catch(e) {
      out.className = 'note err'; out.textContent = String(e); btn.disabled = false;
    }
  });

  // tick reset timer every second
  setInterval(() => {
    if (resetInSec > 0) resetInSec -= 1;
    document.getElementById('reset-in').textContent = fmtHMS(Math.max(0, resetInSec));
    if (limitUsed >= limitMax) {
      document.getElementById('limit-time').textContent = fmtHMS(Math.max(0, resetInSec)) + ' left';
    }
  }, 1000);

  loadState();
  loadRegions();
  loadAccounts();
  </script>
  `);
}

function docsPage() {
  return pageShell("Docs", `
  <h1>Docs</h1>
  <p class="sub">How GHGen works.</p>
  <div class="card"><h2>Register</h2><p class="muted">Enter your email, receive a code, then provide your key + Roblox username + GHGen username.</p></div>
  <div class="card"><h2>Claim</h2><p class="muted">Pick a region (or Random) and click Claim. Server checks your daily limit and cooldown.</p></div>
  <div class="card"><h2>Limits</h2><p class="muted">Day: 3/20s · Week: 10/30s · Month: 30/60s · Year: 40/70s. 24h window starts on first claim.</p></div>
  `);
}

function escapeHtml(s) {
  return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ============================================================
//  AUTH HANDLERS
// ============================================================
async function handleSendCode(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ ok: false, error: "invalid_json" }, 400); }
  const email = String(body.email || "").trim().toLowerCase();
  if (!validEmail(email)) return json({ ok: false, error: "invalid_email" }, 400);

  const existing = await env.DB.prepare(`SELECT id FROM ghgen_users WHERE email = ? LIMIT 1`).bind(email).first();
  const purpose = existing ? "login" : "register";

  const code = randomCode6();
  const ts = now();

  // Удаляем старые неиспользованные коды для этого email
  await env.DB.prepare(`DELETE FROM ghgen_verifications WHERE email = ? AND used = 0`).bind(email).run();

  await env.DB.prepare(
    `INSERT INTO ghgen_verifications (email, code, purpose, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`
  ).bind(email, code, purpose, ts, ts + CODE_TTL).run();

  const sent = await sendEmail(env, email, code);
  if (!sent.ok) {
    return json({ ok: false, error: "email_send_failed", message: sent.error }, 500);
  }
  return json({ ok: true, purpose });
}

async function handleVerifyCode(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ ok: false, error: "invalid_json" }, 400); }
  const email = String(body.email || "").trim().toLowerCase();
  const code = String(body.code || "").trim();
  if (!validEmail(email) || !/^\d{6}$/.test(code)) return json({ ok: false, error: "invalid_input" }, 400);

  const row = await env.DB.prepare(
    `SELECT * FROM ghgen_verifications WHERE email = ? AND code = ? AND used = 0 ORDER BY id DESC LIMIT 1`
  ).bind(email, code).first();
  if (!row) return json({ ok: false, error: "invalid_code" }, 400);
  if (Number(row.expires_at) <= now()) return json({ ok: false, error: "code_expired" }, 400);

  if (row.purpose === "login") {
    const user = await env.DB.prepare(`SELECT id FROM ghgen_users WHERE email = ? LIMIT 1`).bind(email).first();
    if (!user) return json({ ok: false, error: "user_not_found" }, 400);
    await env.DB.prepare(`UPDATE ghgen_verifications SET used = 1 WHERE id = ?`).bind(row.id).run();
    const sid = await createSession(env, user.id, getIP(request));
    await env.DB.prepare(`UPDATE ghgen_users SET last_login = ? WHERE id = ?`).bind(now(), user.id).run();
    return json({ ok: true, mode: "login" }, 200, { "Set-Cookie": cookieHeader("GHGEN_SESSION", sid, SESSION_TTL) });
  }

  // register mode — ждём заполнения полей в /api/auth/register
  await env.DB.prepare(`UPDATE ghgen_verifications SET used = 1 WHERE id = ?`).bind(row.id).run();
  return json({ ok: true, mode: "register" });
}

async function handleRegister(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ ok: false, error: "invalid_json" }, 400); }

  const email = String(body.email || "").trim().toLowerCase();
  const key = String(body.key || "").trim();
  const roblox_username = String(body.roblox_username || "").trim();
  const ghgen_username = String(body.ghgen_username || "").trim();

  if (!validEmail(email)) return json({ ok: false, error: "invalid_email" }, 400);
  if (!/^GH-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/i.test(key) && !key.startsWith("GH-PAID-")) {
    return json({ ok: false, error: "invalid_key_format" }, 400);
  }
  if (!validRobloxUsername(roblox_username)) return json({ ok: false, error: "invalid_roblox_username" }, 400);
  if (!validUsername(ghgen_username)) return json({ ok: false, error: "invalid_ghgen_username" }, 400);

  const ks = await loadKeyStatus(env, key);
  if (!ks.valid) return json({ ok: false, error: ks.reason }, 403);

  // Проверка bind к Roblox username
  const keyUser = String(ks.key_username || "");
  if (!keyUser.startsWith("pending_") && keyUser.toLowerCase() !== roblox_username.toLowerCase()) {
    return json({ ok: false, error: "roblox_username_mismatch", bound: keyUser }, 403);
  }

  // Уникальность
  if (await env.DB.prepare(`SELECT id FROM ghgen_users WHERE key = ? LIMIT 1`).bind(key).first()) {
    return json({ ok: false, error: "key_already_registered" }, 409);
  }
  if (await env.DB.prepare(`SELECT id FROM ghgen_users WHERE email = ? LIMIT 1`).bind(email).first()) {
    return json({ ok: false, error: "email_already_registered" }, 409);
  }
  if (await env.DB.prepare(`SELECT id FROM ghgen_users WHERE ghgen_username = ? LIMIT 1`).bind(ghgen_username).first()) {
    return json({ ok: false, error: "ghgen_username_taken" }, 409);
  }
  if (await env.DB.prepare(`SELECT id FROM ghgen_users WHERE roblox_username = ? LIMIT 1`).bind(roblox_username).first()) {
    return json({ ok: false, error: "roblox_username_taken" }, 409);
  }

  const ts = now();
  await env.DB.prepare(
    `INSERT INTO ghgen_users (key, roblox_username, ghgen_username, email, created_at) VALUES (?, ?, ?, ?, ?)`
  ).bind(key, roblox_username, ghgen_username, email, ts).run();

  // Если key был pending_* — привязываем реальный Roblox username
  if (keyUser.startsWith("pending_")) {
    try { await env.DB.prepare(`UPDATE keys SET username = ? WHERE key = ?`).bind(roblox_username, key).run(); } catch(e) {}
  }

  const userRow = await env.DB.prepare(`SELECT id FROM ghgen_users WHERE email = ? LIMIT 1`).bind(email).first();
  const sid = await createSession(env, userRow.id, getIP(request));
  await env.DB.prepare(`INSERT INTO ghgen_log (user_id, action, ip, created_at) VALUES (?, ?, ?, ?)`)
    .bind(userRow.id, "register", getIP(request), ts).run();

  return json({ ok: true }, 200, { "Set-Cookie": cookieHeader("GHGEN_SESSION", sid, SESSION_TTL) });
}

async function handleLogout(env, request) {
  const sid = getCookie(request, "GHGEN_SESSION");
  if (sid) await env.DB.prepare(`DELETE FROM ghgen_sessions WHERE session_id = ?`).bind(sid).run();
  return html("", 302, { "Location": "/", "Set-Cookie": clearCookieHeader("GHGEN_SESSION") });
}

// ============================================================
//  STATE / REGIONS / ACCOUNTS / CLAIM
// ============================================================
async function handleState(env, request) {
  const user = await requireUser(env, request);
  if (!user) return json({ ok: false, error: "unauthorized" }, 401);

  const ks = await loadKeyStatus(env, user.key);
  const plan = PLAN_LIMITS[ks.plan] || PLAN_LIMITS.day;

  const bucket = await env.DB.prepare(`SELECT * FROM ghgen_buckets WHERE key = ? LIMIT 1`).bind(user.key).first();
  let dayBucket, count, lastClaimAt;
  const t = now();
  if (!bucket || t - Number(bucket.day_bucket) >= DAY_WINDOW) {
    dayBucket = t; count = 0; lastClaimAt = bucket ? Number(bucket.last_claim_at || 0) : 0;
  } else {
    dayBucket = Number(bucket.day_bucket);
    count = Number(bucket.count);
    lastClaimAt = Number(bucket.last_claim_at || 0);
  }

  const resetIn = Math.max(0, dayBucket + DAY_WINDOW - t);
  const nextClaimIn = lastClaimAt ? Math.max(0, plan.cooldown - (t - lastClaimAt)) : 0;

  return json({
    ok: true,
    limit: plan.limit,
    cooldown_seconds: plan.cooldown,
    used: count,
    reset_in: resetIn,
    next_claim_in: nextClaimIn,
    key_valid: ks.valid,
    plan: ks.plan || "day",
  });
}

async function handleRegions(env, request) {
  const user = await requireUser(env, request);
  if (!user) return json({ ok: false, error: "unauthorized" }, 401);

  const rows = await env.DB.prepare(
    `SELECT region, COUNT(*) as c FROM ghgen_pool WHERE status='available' AND region IS NOT NULL AND region != '' GROUP BY region ORDER BY c DESC`
  ).all();
  const regions = (rows.results || []).map(r => ({ region: r.region, count: Number(r.c) }));
  return json({ ok: true, regions });
}

async function handleAccounts(env, request) {
  const user = await requireUser(env, request);
  if (!user) return json({ ok: false, error: "unauthorized" }, 401);

  const rows = await env.DB.prepare(
    `SELECT id, payload, issued_at FROM ghgen_pool WHERE issued_to = ? ORDER BY issued_at DESC LIMIT 100`
  ).bind(user.id).all();

  const accounts = [];
  for (const row of rows.results || []) {
    try {
      const dec = await decryptPayload(env, row.payload);
      accounts.push({ ...dec, issued_at: row.issued_at });
    } catch (e) {}
  }
  return json({ ok: true, accounts });
}

async function handleClaim(env, request) {
  const user = await requireUser(env, request);
  if (!user) return json({ ok: false, error: "unauthorized" }, 401);

  let body = {};
  try { body = await request.json(); } catch {}
  const region = body.region ? String(body.region).trim() : null;

  const ks = await loadKeyStatus(env, user.key);
  if (!ks.valid) return json({ ok: false, error: "key_" + ks.reason }, 403);

  const plan = PLAN_LIMITS[ks.plan] || PLAN_LIMITS.day;
  const t = now();

  // Bucket state
  const bucket = await env.DB.prepare(`SELECT * FROM ghgen_buckets WHERE key = ? LIMIT 1`).bind(user.key).first();
  let dayBucket, count, lastClaimAt;
  if (!bucket || t - Number(bucket.day_bucket) >= DAY_WINDOW) {
    dayBucket = t; count = 0; lastClaimAt = bucket ? Number(bucket.last_claim_at || 0) : 0;
  } else {
    dayBucket = Number(bucket.day_bucket);
    count = Number(bucket.count);
    lastClaimAt = Number(bucket.last_claim_at || 0);
  }

  if (count >= plan.limit) {
    return json({ ok: false, error: "daily_limit", reset_in: dayBucket + DAY_WINDOW - t }, 429);
  }
  if (lastClaimAt && t - lastClaimAt < plan.cooldown) {
    return json({ ok: false, error: "cooldown", wait_seconds: plan.cooldown - (t - lastClaimAt) }, 429);
  }

  // Выдаём аккаунт
  let res;
  if (region) {
    res = await env.DB.prepare(
      `UPDATE ghgen_pool SET status='issued', issued_to=?, issued_at=? WHERE id = (
        SELECT id FROM ghgen_pool WHERE status='available' AND region = ? ORDER BY RANDOM() LIMIT 1
      ) RETURNING id, payload`
    ).bind(user.id, t, region).first();
  } else {
    res = await env.DB.prepare(
      `UPDATE ghgen_pool SET status='issued', issued_to=?, issued_at=? WHERE id = (
        SELECT id FROM ghgen_pool WHERE status='available' ORDER BY RANDOM() LIMIT 1
      ) RETURNING id, payload`
    ).bind(user.id, t).first();
  }

  if (!res) return json({ ok: false, error: "pool_empty" }, 404);

  // Обновляем bucket
  await env.DB.prepare(
    `INSERT INTO ghgen_buckets (key, day_bucket, count, last_claim_at) VALUES (?, ?, 1, ?)
     ON CONFLICT(key) DO UPDATE SET day_bucket = excluded.day_bucket, count = excluded.count, last_claim_at = excluded.last_claim_at`
  ).bind(user.key, dayBucket, t).run();

  // Лог claim
  await env.DB.prepare(
    `INSERT INTO ghgen_claims (key, user_id, pool_id, region, claimed_at) VALUES (?, ?, ?, ?, ?)`
  ).bind(user.key, user.id, res.id, region, t).run();

  try {
    const dec = await decryptPayload(env, res.payload);
    return json({
      ok: true,
      account: { ...dec, issued_at: t },
      used: count + 1,
      limit: plan.limit,
    });
  } catch (e) {
    return json({ ok: false, error: "decrypt_failed", message: String(e.message || e) }, 500);
  }
}

// ============================================================
//  POOL ADMIN
// ============================================================
async function handlePoolUpload(request, env) {
  const secret = request.headers.get("X-Upload-Secret");
  if (!env.UPLOAD_SECRET || secret !== env.UPLOAD_SECRET) {
    return json({ ok: false, error: "unauthorized" }, 401);
  }
  let body;
  try { body = await request.json(); } catch { return json({ ok: false, error: "invalid_json" }, 400); }
  const accounts = Array.isArray(body.accounts) ? body.accounts : [];
  if (!accounts.length) return json({ ok: false, error: "no_accounts" }, 400);
  if (accounts.length > 500) return json({ ok: false, error: "too_many" }, 413);

  try { await getPoolKey(env); } catch (e) {
    return json({ ok: false, error: "pool_key_invalid", message: String(e.message || e) }, 500);
  }

  let added = 0, skipped = 0;
  const errors = [];
  const ts = now();
  for (const a of accounts) {
    if (!a || typeof a.u !== "string" || typeof a.p !== "string") { skipped++; continue; }
    const clean = {
      u: a.u.trim(), p: a.p,
      c: a.c ? String(a.c).trim() : null,
      ci: a.ci ? String(a.ci).trim() : null,
      ip: a.ip ? String(a.ip).trim() : null,
      ck: a.ck ? String(a.ck) : null,
    };
    const region = clean.c || null;
    try {
      const payload = await encryptPayload(env, clean);
      await env.DB.prepare(
        `INSERT INTO ghgen_pool (payload, status, created_at, region) VALUES (?, 'available', ?, ?)`
      ).bind(payload, ts, region).run();
      added++;
    } catch (e) {
      skipped++;
      if (errors.length < 3) errors.push(`${clean.u}: ${String(e.message || e)}`);
    }
  }
  return json({ ok: true, added, skipped, errors: errors.length ? errors : undefined });
}

async function handlePoolStats(request, env) {
  const secret = request.headers.get("X-Upload-Secret");
  const expected = env.UPLOAD_SECRET;

  // ДИАГНОСТИКА: что воркер видит в env
  const envDebug = {
    has_upload_secret: !!env.UPLOAD_SECRET,
    has_pool_key: !!env.POOL_KEY,
    has_resend_key: !!env.RESEND_API_KEY,
    upload_secret_length: env.UPLOAD_SECRET ? env.UPLOAD_SECRET.length : 0,
    got_secret_length: secret ? secret.length : 0,
    match: secret === expected,
    env_keys: Object.keys(env).filter(k => !k.startsWith("__")),
  };

  if (!expected || secret !== expected) {
    return json({ ok: false, error: "unauthorized", debug: envDebug }, 401);
  }

  let poolKeyOk = true, poolKeyError = null;
  try { await getPoolKey(env); } catch (e) { poolKeyOk = false; poolKeyError = String(e.message || e); }
  const avail = await env.DB.prepare(`SELECT COUNT(*) as c FROM ghgen_pool WHERE status='available'`).first();
  const issued = await env.DB.prepare(`SELECT COUNT(*) as c FROM ghgen_pool WHERE status='issued'`).first();
  return json({
    ok: true,
    available: avail.c, issued: issued.c, total: avail.c + issued.c,
    pool_key_ok: poolKeyOk, pool_key_error: poolKeyError,
    using_env_secret: !!env.UPLOAD_SECRET,
    using_env_pool_key: !!env.POOL_KEY,
    using_resend_key: !!env.RESEND_API_KEY,
  });
}

// ============================================================
//  ROUTER
// ============================================================
export default {
  async fetch(request, env) {
    setMainSite(env.MAIN_SITE);
    try {
      if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
      const url = new URL(request.url);
      let path = url.pathname;
      if (path.length > 1 && path.endsWith("/")) path = path.slice(0, -1);

      // auth
      if (request.method === "POST" && path === "/api/auth/send-code") return await handleSendCode(request, env);
      if (request.method === "POST" && path === "/api/auth/verify") return await handleVerifyCode(request, env);
      if (request.method === "POST" && path === "/api/auth/register") return await handleRegister(request, env);
      if (request.method === "GET" && path === "/logout") return await handleLogout(env, request);

      // user
      if (request.method === "GET" && path === "/api/state") return await handleState(env, request);
      if (request.method === "GET" && path === "/api/regions") return await handleRegions(env, request);
      if (request.method === "GET" && path === "/api/accounts") return await handleAccounts(env, request);
      if (request.method === "POST" && path === "/api/claim") return await handleClaim(env, request);

      // pool admin
      if (request.method === "POST" && path === "/api/pool/upload") return await handlePoolUpload(request, env);
      if (request.method === "GET" && path === "/api/pool/stats") return await handlePoolStats(request, env);

      // pages
      const user = await requireUser(env, request);
      if (request.method === "GET" && path === "/") {
        if (user) return html("", 302, { "Location": "/dashboard" });
        return html(authPage());
      }
      if (request.method === "GET" && path === "/dashboard") {
        if (!user) return html("", 302, { "Location": "/" });
        const ks = await loadKeyStatus(env, user.key);
        return html(dashboardPage(user, ks));
      }
      if (request.method === "GET" && path === "/docs") return html(docsPage());

      return html(pageShell("404", `<h1>404</h1><p class="sub">Not found.</p>`), 404);
    } catch (e) {
      console.error("ghgen error:", e);
      return json({ ok: false, error: "internal", message: String(e?.message || e) }, 500);
    }
  },
};
