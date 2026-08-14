-- Persisted Web (DVWA) and Linux (SSH) attack validation runs. Deliberately
-- decoupled from ad_attack_tests/ad_validation_runs (no FK to either) so this
-- migration can never touch AD/Windows data or constraints.
CREATE TABLE IF NOT EXISTS web_linux_validation_runs (
    id                  INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id              TEXT NOT NULL,
    surface             TEXT NOT NULL CHECK(surface IN ('web','linux')),
    attack_id           TEXT,              -- NULL for NOT_EXECUTED (preflight-failed) attempts
    attack_name         TEXT,
    mitre_technique     TEXT,
    target              TEXT,
    source_ip           TEXT,
    started_at          TEXT,
    ended_at            TEXT,
    execution_status    TEXT NOT NULL DEFAULT 'EXECUTED',  -- EXECUTED | NOT_EXECUTED
    wazuh_detected      INTEGER,
    wazuh_rule_ids_json TEXT NOT NULL DEFAULT '[]',
    sigma_supported     INTEGER NOT NULL DEFAULT 0,
    sigma_matched       INTEGER,
    sigma_rule_ids_json TEXT NOT NULL DEFAULT '[]',
    verdict             TEXT,              -- VERIFIED_OVERLAP | WAZUH_ONLY | SIGMA_ONLY | NO_DETECTION_IN_EITHER | EVALUATOR_UNSUPPORTED | NOT_EXECUTED
    error_code          TEXT,
    error_reason        TEXT,
    evidence_count      INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT NOT NULL,
    UNIQUE(run_id, attack_id)
);
CREATE INDEX IF NOT EXISTS idx_wlvr_surface ON web_linux_validation_runs(surface);
CREATE INDEX IF NOT EXISTS idx_wlvr_run ON web_linux_validation_runs(run_id);

CREATE TABLE IF NOT EXISTS web_linux_evidence (
    evidence_id      INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id           TEXT NOT NULL,
    attack_id        TEXT NOT NULL,
    wazuh_rule_id    TEXT,
    rule_description TEXT,
    rule_level       INTEGER,
    full_log         TEXT,
    agent_id         TEXT,
    agent_name       TEXT,
    event_timestamp  TEXT,
    imported_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_wle_run_attack ON web_linux_evidence(run_id, attack_id);
