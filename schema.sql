-- Пользователи GHGen-дашборда.
-- key — FK на keys.key (существующая таблица). Один ключ = один аккаунт дашборда.
CREATE TABLE IF NOT EXISTS ghgen_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    key TEXT UNIQUE NOT NULL,
    discord_id TEXT,
    created_at INTEGER NOT NULL,
    last_login INTEGER
);
CREATE INDEX IF NOT EXISTS idx_ghgen_users_key ON ghgen_users(key);
CREATE INDEX IF NOT EXISTS idx_ghgen_users_discord ON ghgen_users(discord_id);

-- Сессии (cookie-based)
CREATE TABLE IF NOT EXISTS ghgen_sessions (
    session_id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    ip_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_ghgen_sessions_user ON ghgen_sessions(user_id);

-- Сгенерированные аккаунты. Бот забирает status='pending'.
CREATE TABLE IF NOT EXISTS ghgen_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    roblox_username TEXT,
    roblox_password TEXT,
    cookie TEXT,
    country TEXT,
    city TEXT,
    ip TEXT,
    status TEXT NOT NULL DEFAULT 'pending', -- pending|running|success|fail
    reason TEXT,
    created_at INTEGER NOT NULL,
    finished_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_ghgen_accounts_user ON ghgen_accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_ghgen_accounts_status ON ghgen_accounts(status);

-- Аудит-лог (кто что делал)
CREATE TABLE IF NOT EXISTS ghgen_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    meta TEXT,
    ip TEXT,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ghgen_log_user ON ghgen_log(user_id);
