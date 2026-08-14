-- ─────────────────────────────────────────────────────────────────────────────
-- AI Detection Rule Recommendation workflow (Gemini)
--
-- Additive and idempotent: creates only new tables, touches nothing that the
-- AD/Windows or Web/Linux validation surfaces already rely on. Every draft is
-- versioned (versions are never overwritten) and every state change is
-- recorded in ai_rule_actions for audit.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ai_rule_suggestions (
    id                   INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    attack_id            TEXT    NOT NULL,
    surface              TEXT    NOT NULL CHECK(surface IN ('ad','windows','linux','web')),
    validation_run_id    TEXT,
    verdict              TEXT    NOT NULL,   -- canonical deterministic verdict at generation time
    raw_verdict          TEXT,               -- verdict exactly as the validation engine reported it
    target_type          TEXT    NOT NULL,   -- wazuh_rule | sigma_rule | both_rules | telemetry | evaluator
    status               TEXT    NOT NULL DEFAULT 'not_requested',
    provider             TEXT    NOT NULL DEFAULT 'gemini',
    model                TEXT,
    summary              TEXT,
    reasoning_summary    TEXT,
    confidence           INTEGER,
    evidence_fingerprint TEXT,
    current_version      INTEGER NOT NULL DEFAULT 0,
    created_by           TEXT,
    created_at           TEXT    NOT NULL,
    updated_at           TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ai_sugg_attack
    ON ai_rule_suggestions(surface, attack_id);
CREATE INDEX IF NOT EXISTS idx_ai_sugg_run
    ON ai_rule_suggestions(validation_run_id);
CREATE INDEX IF NOT EXISTS idx_ai_sugg_fingerprint
    ON ai_rule_suggestions(evidence_fingerprint);


CREATE TABLE IF NOT EXISTS ai_rule_versions (
    id                         INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    suggestion_id              INTEGER NOT NULL,
    version_number             INTEGER NOT NULL,
    origin                     TEXT    NOT NULL DEFAULT 'generated',  -- generated | regenerated | edited
    gap_type                   TEXT,
    summary                    TEXT,
    reasoning_summary          TEXT,
    confidence                 INTEGER,
    wazuh_xml                  TEXT,
    wazuh_meta_json            TEXT NOT NULL DEFAULT '{}',
    sigma_yaml                 TEXT,
    sigma_meta_json            TEXT NOT NULL DEFAULT '{}',
    telemetry_json             TEXT NOT NULL DEFAULT '[]',
    assumptions_json           TEXT NOT NULL DEFAULT '[]',
    required_data_sources_json TEXT NOT NULL DEFAULT '[]',
    false_positives_json       TEXT NOT NULL DEFAULT '[]',
    tuning_notes_json          TEXT NOT NULL DEFAULT '[]',
    deployment_risks_json      TEXT NOT NULL DEFAULT '[]',
    mitre_json                 TEXT NOT NULL DEFAULT '{}',
    engineer_feedback          TEXT,
    validation_result_json     TEXT,
    generated_at               TEXT NOT NULL,
    generated_by               TEXT,
    FOREIGN KEY (suggestion_id) REFERENCES ai_rule_suggestions(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_ver_unique
    ON ai_rule_versions(suggestion_id, version_number);


CREATE TABLE IF NOT EXISTS ai_rule_actions (
    id            INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    suggestion_id INTEGER NOT NULL,
    version_id    INTEGER,
    action        TEXT    NOT NULL,
    actor         TEXT,
    comment       TEXT,
    metadata_json TEXT    NOT NULL DEFAULT '{}',
    created_at    TEXT    NOT NULL,
    FOREIGN KEY (suggestion_id) REFERENCES ai_rule_suggestions(id),
    FOREIGN KEY (version_id)    REFERENCES ai_rule_versions(id)
);

CREATE INDEX IF NOT EXISTS idx_ai_act_sugg
    ON ai_rule_actions(suggestion_id, id);


-- Idempotency ledger for "Save to Platform": one detections row per
-- (suggestion, version). A repeat click returns the existing detection_id
-- instead of inserting a duplicate rule.
CREATE TABLE IF NOT EXISTS ai_rule_platform_saves (
    id            INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    suggestion_id INTEGER NOT NULL,
    version_id    INTEGER NOT NULL,
    detection_id  INTEGER NOT NULL,
    created_at    TEXT    NOT NULL,
    created_by    TEXT,
    FOREIGN KEY (suggestion_id) REFERENCES ai_rule_suggestions(id),
    FOREIGN KEY (version_id)    REFERENCES ai_rule_versions(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_platform_save_unique
    ON ai_rule_platform_saves(suggestion_id, version_id);
