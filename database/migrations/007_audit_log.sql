-- ─────────────────────────────────────────────────────────────────────────────
-- Audit trail (Phase 2 of the SOC-hardening roadmap).
--
-- Records who did what to which resource, so approve/reject/deploy/save/delete
-- actions carry real accountability. Additive and idempotent.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_email TEXT    NOT NULL,
    actor_role  TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    target_type TEXT    NOT NULL,
    target_id   TEXT,
    detail      TEXT,
    created_at  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log(actor_email);
CREATE INDEX IF NOT EXISTS idx_audit_log_target ON audit_log(target_type, target_id);
