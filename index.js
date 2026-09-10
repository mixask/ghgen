/**
 * ghgen — GHGen dashboard worker
 * Bindings: DB (D1)
 * Vars: SITE_NAME, MAIN_SITE
 * Secrets: (none required)
 *
 * Share D1 with greedyhudzell worker. Reads keys table, writes ghgen_* tables only.
 */

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

const SESSION_TTL = 7 * 24 * 60 * 60;      // 7 дней
const PBKDF2_ITER = 100_000;
const PBKDF2_HASH = "SHA-256";

const jsonHeaders = { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" };

// ---------- utils ----------
const now = () => Math.floor(Date.now() / 1000);

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), { status, headers: { ...jsonHeaders, ...CORS, ...extra } });
}

function html(body, status = 200, extra = {}) {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...extra },
  });
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

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITER, hash: PBKDF2_HASH },
    keyMaterial,
    256
  );
  const hex = (u8) => [...u8].map(b => b.toString(16).padStart(2, "0")).join("");
  return `pbkdf2$${PBKDF2_ITER}$${hex(salt)}$${hex(new Uint8Array(bits))}`;
}

async function verifyPassword(stored, password) {
  try {
    const [scheme, iterStr, saltHex, hashHex] = stored.split("$");
    if (scheme !== "pbkdf2") return false;
    const iterations = parseInt(iterStr, 10);
    const salt = new Uint8Array(saltHex.match(/.{2}/g).map(b => parseInt(b, 16)));
    const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt, iterations, hash: PBKDF2_HASH },
      keyMaterial,
      256
    );
    const computed = [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, "0")).join("");
    return computed === hashHex;
  } catch { return false; }
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

// ---------- sessions ----------
async function createSession(env, userId, ip) {
  const sid = randomId(32);
  const ts = now();
  const ipHash = ip ? await sha256(ip) : null;
  await env.DB.prepare(
    `INSERT INTO ghgen_sessions (session_id, user_id, created_at, expires_at, ip_hash)
     VALUES (?, ?, ?, ?, ?)`
  ).bind(sid, userId, ts, ts + SESSION_TTL, ipHash).run();
  return sid;
}

async function getSessionUser(env, sessionId) {
  if (!sessionId) return null;
  const s = await env.DB.prepare(
    `SELECT s.session_id, s.expires_at, u.id, u.username, u.key, u.discord_id
     FROM ghgen_sessions s JOIN ghgen_users u ON u.id = s.user_id
     WHERE s.session_id = ? LIMIT 1`
  ).bind(sessionId).first();
  if (!s) return null;
  if (Number(s.expires_at) <= now()) return null;
  return s;
}

function requireUser(env, request) {
  return getSessionUser(env, getCookie(request, "GHGEN_SESSION"));
}

// ---------- HTML ----------
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
.wrap{width:min(900px,92vw);margin:0 auto;padding:32px 0 80px}
.top{border-bottom:1px solid var(--line);background:rgba(12,12,13,.85);backdrop-filter:blur(12px);position:sticky;top:0;z-index:10}
.top-inner{width:min(900px,92vw);margin:0 auto;display:flex;align-items:center;justify-content:space-between;padding:14px 0}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;color:var(--text)}
.brand-mark{width:32px;height:32px;border-radius:8px;background:#1a1a1d;border:1px solid var(--accent);display:grid;place-items:center;color:var(--accent);font-size:12px;font-weight:800}
.nav{display:flex;gap:6px;align-items:center}
.nav a{color:var(--muted);padding:7px 12px;border-radius:8px;font-size:13px;font-weight:500}
.nav a:hover{color:var(--text);background:var(--bg2);text-decoration:none}
.nav a.active{color:var(--text);background:var(--bg2)}
h1{font-size:1.6rem;font-weight:700;margin-bottom:6px}
h2{font-size:1.1rem;font-weight:600;margin-bottom:8px}
.sub{color:var(--muted);font-size:14px;margin-bottom:22px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin:12px 0}
label{display:block;color:var(--muted);font-size:12px;font-weight:600;margin:10px 0 6px}
input,select,textarea{width:100%;background:#0e0e11;border:1px solid var(--line);color:var(--text);padding:11px 12px;border-radius:8px;font-size:14px;font-family:inherit}
input:focus,select:focus,textarea:focus{outline:1px solid var(--accent)}
button,.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:11px 18px;border-radius:8px;border:1px solid var(--line);background:var(--bg2);color:var(--text);font-weight:600;font-size:13px;cursor:pointer;font-family:inherit}
button:hover,.btn:hover{border-color:var(--accent);color:var(--accent);text-decoration:none}
button.primary{background:var(--accent);color:#0a0a0a;border-color:var(--accent)}
button.primary:hover{color:#0a0a0a;filter:brightness(1.08)}
button:disabled{opacity:.5;cursor:not-allowed}
.row{display:flex;gap:10px;flex-wrap:wrap}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:700px){.grid{grid-template-columns:1fr}}
.muted{color:var(--muted);font-size:13px}
.ok{color:var(--ok)}.err{color:var(--bad)}
.mono{font-family:ui-monospace,monospace;font-size:12px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
.badge{display:inline-block;font-size:11px;font-weight:600;padding:2px 8px;border-radius:999px;background:rgba(201,162,39,.12);color:var(--accent);border:1px solid rgba(201,162,39,.25)}
.badge.ok{background:rgba(76,175,122,.12);color:var(--ok);border-color:rgba(76,175,122,.3)}
.badge.err{background:rgba(232,93,93,.12);color:var(--bad);border-color:rgba(232,93,93,.3)}
.status-pill{display:inline-block;font-size:11px;padding:2px 8px;border-radius:999px;background:var(--bg2);border:1px solid var(--line)}
.status-pill.success{color:var(--ok);border-color:rgba(76,175,122,.3)}
.status-pill.fail{color:var(--bad);border-color:rgba(232,93,93,.3)}
.status-pill.pending,.status-pill.running{color:var(--accent);border-color:rgba(201,162,39,.3)}
.note{color:var(--muted);font-size:12px;margin-top:14px}
.tabs{display:flex;gap:4px;border-bottom:1px solid var(--line);margin-bottom:18px}
.tabs button{background:none;border:0;border-bottom:2px solid transparent;border-radius:0;padding:10px 14px;color:var(--muted)}
.tabs button.active{color:var(--text);border-bottom-color:var(--accent)}
</style>
</head>
<body>
<header class="top">
  <div class="top-inner">
    <a class="brand" href="/">
      <div class="brand-mark">GH</div>
      <span>GHGen</span>
    </a>
    <nav class="nav">
      <a href="/dashboard">Dashboard</a>
      <a href="/accounts">Accounts</a>
      <a href="/docs">Docs</a>
      <a href="${MAIN_SITE}">Main site ↗</a>
    </nav>
  </div>
</header>
<main class="wrap">${content}</main>
</body>
</html>`;
}

// Since MAIN_SITE not available at module scope, we inject at request time via a setter.
let MAIN_SITE = "https://greedyhudzell.xyz";
function setMainSite(v) { if (v) MAIN_SITE = v; }

function loginPage(msg = "") {
  return pageShell("Login", `
  <h1>Sign in</h1>
  <p class="sub">Use your GH key and account credentials.</p>
  <div class="card">
    ${msg ? `<p class="err" style="margin-bottom:12px">${msg}</p>` : ""}
    <form method="POST" action="/api/login">
      <label>Username</label>
      <input name="username" required autocomplete="username" maxlength="32"/>
      <label>Password</label>
      <input name="password" type="password" required autocomplete="current-password"/>
      <button class="primary" style="width:100%;margin-top:16px" type="submit">Sign in</button>
    </form>
    <p class="note">No account? <a href="/register">Register with key</a></p>
  </div>
  `);
}

function registerPage(msg = "") {
  return pageShell("Register", `
  <h1>Create account</h1>
  <p class="sub">Register with a valid GH key.</p>
  <div class="card">
    ${msg ? `<p class="err" style="margin-bottom:12px">${msg}</p>` : ""}
    <form method="POST" action="/api/register">
      <label>Key</label>
      <input name="key" required placeholder="GH-XXXX-XXXX-XXXX" autocomplete="off"/>
      <label>Username</label>
      <input name="username" required autocomplete="username" maxlength="32" pattern="[A-Za-z0-9_]{3,32}"/>
      <label>Password</label>
      <input name="password" type="password" required minlength="8" autocomplete="new-password"/>
      <label>Confirm password</label>
      <input name="password2" type="password" required minlength="8" autocomplete="new-password"/>
      <button class="primary" style="width:100%;margin-top:16px" type="submit">Create account</button>
    </form>
    <p class="note">Already registered? <a href="/login">Sign in</a></p>
  </div>
  `);
}

function dashboardPage(user, keyStatus) {
  return pageShell("Dashboard", `
  <h1>Dashboard</h1>
  <p class="sub">Signed in as <b>${escapeHtml(user.username)}</b></p>

  <div class="grid">
    <div class="card">
      <h2>Key</h2>
      <p class="mono" style="margin:6px 0">${escapeHtml(user.key)}</p>
      <p class="muted">Plan: <b>${keyStatus.plan || "—"}</b></p>
      <p class="muted">Expires: <b>${keyStatus.expires_at ? new Date(keyStatus.expires_at * 1000).toLocaleString() : "—"}</b></p>
      <p style="margin-top:10px">
        ${keyStatus.valid
          ? `<span class="badge ok">ACTIVE</span>`
          : `<span class="badge err">${keyStatus.reason || "INVALID"}</span>`}
      </p>
    </div>
    <div class="card">
      <h2>Generate</h2>
      <p class="muted">Request a new Roblox account.</p>
      <button class="primary" id="btn-gen" style="margin-top:12px;width:100%">Generate account</button>
      <p class="note" id="gen-out"></p>
    </div>
  </div>

  <div class="card">
    <h2>Recent accounts</h2>
    <div id="accounts-list"><p class="muted">Loading…</p></div>
  </div>

  <script>
  async function loadAccounts() {
    const el = document.getElementById('accounts-list');
    try {
      const r = await fetch('/api/accounts', { credentials: 'same-origin' });
      const d = await r.json();
      if (!d.ok) { el.innerHTML = '<p class="err">' + (d.error || 'error') + '</p>'; return; }
      if (!d.accounts.length) { el.innerHTML = '<p class="muted">No accounts yet.</p>'; return; }
      el.innerHTML = '<table><thead><tr><th>Username</th><th>Location</th><th>Status</th><th>Created</th></tr></thead><tbody>'
        + d.accounts.map(a => '<tr>'
          + '<td class="mono">' + (a.roblox_username || '—') + '</td>'
          + '<td>' + (a.country || '') + (a.city ? ', ' + a.city : '') + '</td>'
          + '<td><span class="status-pill ' + a.status + '">' + a.status + '</span></td>'
          + '<td class="muted">' + new Date(a.created_at * 1000).toLocaleString() + '</td>'
          + '</tr>').join('') + '</tbody></table>';
    } catch (e) {
      el.innerHTML = '<p class="err">' + e + '</p>';
    }
  }
  document.getElementById('btn-gen').addEventListener('click', async () => {
    const out = document.getElementById('gen-out');
    out.className = 'note'; out.textContent = 'Queueing…';
    const r = await fetch('/api/generate', { method: 'POST', credentials: 'same-origin' });
    const d = await r.json();
    if (d.ok) { out.className = 'note ok'; out.textContent = 'Queued (id ' + d.job_id + ').'; loadAccounts(); }
    else { out.className = 'note err'; out.textContent = d.error || 'error'; }
  });
  loadAccounts();
  setInterval(loadAccounts, 5000);
  </script>
  `);
}

function docsPage() {
  return pageShell("Docs", `
  <h1>Docs</h1>
  <p class="sub">How to use GHGen.</p>
  <div class="card">
    <h2>Register</h2>
    <p class="muted">You need a valid GH key (free via Work.ink or paid via Discord). One key = one GHGen account.</p>
  </div>
  <div class="card">
    <h2>Generate</h2>
    <p class="muted">Click "Generate account" on the dashboard. The bot picks up the job, creates the account, and it appears in your list.</p>
  </div>
  <div class="card">
    <h2>Rules</h2>
    <p class="muted">Do not share your account. Do not resell generated accounts. Abuse = ban.</p>
  </div>
  `);
}

function escapeHtml(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ---------- KEY VALIDATION (reads from shared keys table) ----------
async function loadKeyStatus(env, key) {
  const record = await env.DB.prepare(`SELECT * FROM keys WHERE key = ? LIMIT 1`).bind(key).first();
  if (!record) return { valid: false, reason: "invalid_key" };
  if (record.revoked === 1) return { valid: false, reason: "revoked", plan: record.plan };
  if (Number(record.expires_at) <= now()) return { valid: false, reason: "expired", plan: record.plan, expires_at: record.expires_at };
  return {
    valid: true,
    plan: record.plan || "day",
    expires_at: record.expires_at,
    activated: record.activated === 1,
  };
}

// ---------- ROUTES ----------
async function handleRegister(request, env) {
  const ct = request.headers.get("Content-Type") || "";
  let body;
  if (ct.includes("application/json")) {
    body = await request.json().catch(() => ({}));
  } else {
    const fd = await request.formData();
    body = {
      key: fd.get("key"),
      username: fd.get("username"),
      password: fd.get("password"),
      password2: fd.get("password2"),
    };
  }

  const key = String(body.key || "").trim();
  const username = String(body.username || "").trim();
  const password = String(body.password || "");
  const password2 = String(body.password2 || password);

  const wantsHtml = !ct.includes("application/json");

  if (!/^GH-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/i.test(key) && !key.startsWith("GH-PAID-")) {
    return wantsHtml ? html(registerPage("Invalid key format."), 400) : json({ ok: false, error: "invalid_key_format" }, 400);
  }
  if (!/^[A-Za-z0-9_]{3,32}$/.test(username)) {
    return wantsHtml ? html(registerPage("Username: 3-32 chars, A-Za-z0-9_."), 400) : json({ ok: false, error: "invalid_username" }, 400);
  }
  if (password.length < 8) {
    return wantsHtml ? html(registerPage("Password must be at least 8 chars."), 400) : json({ ok: false, error: "weak_password" }, 400);
  }
  if (password !== password2) {
    return wantsHtml ? html(registerPage("Passwords do not match."), 400) : json({ ok: false, error: "password_mismatch" }, 400);
  }

  // Validate key
  const ks = await loadKeyStatus(env, key);
  if (!ks.valid) {
    return wantsHtml ? html(registerPage(`Key: ${ks.reason}`), 403) : json({ ok: false, error: ks.reason }, 403);
  }

  // Check uniqueness
  const dupKey = await env.DB.prepare(`SELECT id FROM ghgen_users WHERE key = ? LIMIT 1`).bind(key).first();
  if (dupKey) {
    return wantsHtml ? html(registerPage("Key already registered."), 409) : json({ ok: false, error: "key_already_registered" }, 409);
  }
  const dupUser = await env.DB.prepare(`SELECT id FROM ghgen_users WHERE username = ? LIMIT 1`).bind(username).first();
  if (dupUser) {
    return wantsHtml ? html(registerPage("Username taken."), 409) : json({ ok: false, error: "username_taken" }, 409);
  }

  const hash = await hashPassword(password);
  const ts = now();
  await env.DB.prepare(
    `INSERT INTO ghgen_users (username, password_hash, key, created_at)
     VALUES (?, ?, ?, ?)`
  ).bind(username, hash, key, ts).run();

  // Auto-login
  const userRow = await env.DB.prepare(`SELECT id FROM ghgen_users WHERE username = ? LIMIT 1`).bind(username).first();
  const sid = await createSession(env, userRow.id, getIP(request));
  await env.DB.prepare(`INSERT INTO ghgen_log (user_id, action, ip, created_at) VALUES (?, ?, ?, ?)`)
    .bind(userRow.id, "register", getIP(request), ts).run();

  if (wantsHtml) {
    return html("", 302, { "Location": "/dashboard", "Set-Cookie": cookieHeader("GHGEN_SESSION", sid, SESSION_TTL) });
  }
  return json({ ok: true }, 200, { "Set-Cookie": cookieHeader("GHGEN_SESSION", sid, SESSION_TTL) });
}

async function handleLogin(request, env) {
  const ct = request.headers.get("Content-Type") || "";
  let body;
  if (ct.includes("application/json")) {
    body = await request.json().catch(() => ({}));
  } else {
    const fd = await request.formData();
    body = { username: fd.get("username"), password: fd.get("password") };
  }

  const username = String(body.username || "").trim();
  const password = String(body.password || "");
  const wantsHtml = !ct.includes("application/json");

  if (!username || !password) {
    return wantsHtml ? html(loginPage("Fill all fields."), 400) : json({ ok: false, error: "missing_fields" }, 400);
  }

  const user = await env.DB.prepare(`SELECT * FROM ghgen_users WHERE username = ? LIMIT 1`).bind(username).first();
  if (!user) {
    return wantsHtml ? html(loginPage("Invalid credentials."), 401) : json({ ok: false, error: "invalid_credentials" }, 401);
  }

  const ok = await verifyPassword(user.password_hash, password);
  if (!ok) {
    return wantsHtml ? html(loginPage("Invalid credentials."), 401) : json({ ok: false, error: "invalid_credentials" }, 401);
  }

  const sid = await createSession(env, user.id, getIP(request));
  await env.DB.prepare(`UPDATE ghgen_users SET last_login = ? WHERE id = ?`).bind(now(), user.id).run();
  await env.DB.prepare(`INSERT INTO ghgen_log (user_id, action, ip, created_at) VALUES (?, ?, ?, ?)`)
    .bind(user.id, "login", getIP(request), now()).run();

  if (wantsHtml) {
    return html("", 302, { "Location": "/dashboard", "Set-Cookie": cookieHeader("GHGEN_SESSION", sid, SESSION_TTL) });
  }
  return json({ ok: true }, 200, { "Set-Cookie": cookieHeader("GHGEN_SESSION", sid, SESSION_TTL) });
}

async function handleLogout(env, request) {
  const sid = getCookie(request, "GHGEN_SESSION");
  if (sid) {
    await env.DB.prepare(`DELETE FROM ghgen_sessions WHERE session_id = ?`).bind(sid).run();
  }
  return html("", 302, { "Location": "/login", "Set-Cookie": clearCookieHeader("GHGEN_SESSION") });
}

async function handleMe(env, request) {
  const user = await requireUser(env, request);
  if (!user) return json({ ok: false, error: "unauthorized" }, 401);
  const ks = await loadKeyStatus(env, user.key);
  return json({ ok: true, user: { username: user.username, key: user.key }, key: ks });
}

async function handleAccounts(env, request) {
  const user = await requireUser(env, request);
  if (!user) return json({ ok: false, error: "unauthorized" }, 401);
  const rows = await env.DB.prepare(
    `SELECT id, roblox_username, country, city, ip, status, reason, created_at, finished_at
     FROM ghgen_accounts WHERE user_id = ? ORDER BY created_at DESC LIMIT 50`
  ).bind(user.id).all();
  return json({ ok: true, accounts: rows.results || [] });
}

async function handleGenerate(env, request) {
  const user = await requireUser(env, request);
  if (!user) return json({ ok: false, error: "unauthorized" }, 401);

  // Key still valid?
  const ks = await loadKeyStatus(env, user.key);
  if (!ks.valid) return json({ ok: false, error: "key_" + ks.reason }, 403);

  // Anti-spam: не больше 1 pending на пользователя
  const pending = await env.DB.prepare(
    `SELECT id FROM ghgen_accounts WHERE user_id = ? AND status IN ('pending','running') LIMIT 1`
  ).bind(user.id).first();
  if (pending) return json({ ok: false, error: "already_pending", job_id: pending.id }, 429);

  const ts = now();
  const res = await env.DB.prepare(
    `INSERT INTO ghgen_accounts (user_id, status, created_at) VALUES (?, 'pending', ?)`
  ).bind(user.id, ts).run();

  await env.DB.prepare(`INSERT INTO ghgen_log (user_id, action, meta, ip, created_at) VALUES (?, ?, ?, ?, ?)`)
    .bind(user.id, "generate", JSON.stringify({ job_id: res.meta.last_row_id }), getIP(request), ts).run();

  return json({ ok: true, job_id: res.meta.last_row_id });
}

// ---------- MAIN ----------
export default {
  async fetch(request, env) {
    setMainSite(env.MAIN_SITE);
    try {
      if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });

      const url = new URL(request.url);
      let path = url.pathname;
      if (path.length > 1 && path.endsWith("/")) path = path.slice(0, -1);

      // Auth routes
      if (request.method === "POST" && path === "/api/register") return await handleRegister(request, env);
      if (request.method === "POST" && path === "/api/login") return await handleLogin(request, env);
      if (request.method === "GET" && path === "/api/logout") return await handleLogout(env, request);
      if (request.method === "GET" && path === "/api/me") return await handleMe(env, request);
      if (request.method === "GET" && path === "/api/accounts") return await handleAccounts(env, request);
      if (request.method === "POST" && path === "/api/generate") return await handleGenerate(env, request);

      // Pages
      const user = await requireUser(env, request);

      if (request.method === "GET" && path === "/") {
        return html("", 302, { "Location": user ? "/dashboard" : "/login" });
      }
      if (request.method === "GET" && path === "/login") {
        if (user) return html("", 302, { "Location": "/dashboard" });
        return html(loginPage());
      }
      if (request.method === "GET" && path === "/register") {
        if (user) return html("", 302, { "Location": "/dashboard" });
        return html(registerPage());
      }
      if (request.method === "GET" && path === "/dashboard") {
        if (!user) return html("", 302, { "Location": "/login" });
        const ks = await loadKeyStatus(env, user.key);
        return html(dashboardPage(user, ks));
      }
      if (request.method === "GET" && path === "/docs") {
        return html(docsPage());
      }

      // API for bot: list pending jobs (без auth — но закройте через Cloudflare Access или добавьте секрет)
      if (request.method === "GET" && path === "/api/bot/pending") {
        const rows = await env.DB.prepare(
          `SELECT a.id, a.user_id, u.username as site_username, u.key
           FROM ghgen_accounts a JOIN ghgen_users u ON u.id = a.user_id
           WHERE a.status = 'pending' ORDER BY a.created_at ASC LIMIT 10`
        ).all();
        return json({ ok: true, jobs: rows.results || [] });
      }

      return html(pageShell("404", `<h1>404</h1><p class="sub">Not found.</p>`), 404);
    } catch (e) {
      console.error("ghgen error:", e);
      return json({ ok: false, error: "internal", message: String(e?.message || e) }, 500);
    }
  },
};
