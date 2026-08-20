-- ─────────────────────────────────────────────────────────────────────────────
-- Real user accounts (Phase 1 of the SOC-hardening roadmap).
--
-- Replaces the hardcoded VALID_USERS dict in app/routes/auth.py with hashed
-- credentials in Postgres. Additive and idempotent — touches nothing else.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL CHECK(role IN ('admin','engineer','analyst')),
    full_name     TEXT,
    is_active     BOOLEAN NOT NULL DEFAULT true,
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(LOWER(email));
