-- ─────────────────────────────────────────────────────────────────────────────
-- Persistent sessions.
--
-- Sessions previously lived only in the app process's memory (a plain dict in
-- app/services/auth_service.py), so every restart/redeploy silently logged
-- everyone out — "remember me" couldn't actually keep anyone remembered
-- across a restart. Moving the session store here fixes that: a session now
-- survives the app process restarting, same as the credentials already do.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS sessions (
    token       TEXT PRIMARY KEY,
    email       TEXT NOT NULL,
    role        TEXT NOT NULL,
    expires_at  DOUBLE PRECISION NOT NULL,  -- unix epoch seconds
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
