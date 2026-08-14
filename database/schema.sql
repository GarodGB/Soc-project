-- PostgreSQL schema for the ABSEGA Detection Platform.
-- Generated from the live SQLite database's actual schema (sqlite_master),
-- which is the ground truth — the old MySQL-flavored schema.sql this file
-- replaces was never applied by the app and had drifted from reality.

CREATE TABLE IF NOT EXISTS mitre_techniques (
    technique_id    TEXT    PRIMARY KEY,
    name            TEXT    NOT NULL,
    tactic          TEXT    NOT NULL,
    description     TEXT,
    url             TEXT
);

CREATE TABLE IF NOT EXISTS telemetry_sources (
    source_id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT,
    status TEXT,
    details TEXT
);

CREATE TABLE IF NOT EXISTS detections (
    detection_id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    rule_logic TEXT,
    severity TEXT,
    status TEXT,
    author TEXT,
    created_at TEXT,
    updated_at TEXT,
    platform TEXT,
    sigma_id TEXT,
    logsource TEXT,
    falsepositives TEXT,
    modified TEXT,
    reference_urls TEXT,
    tags TEXT,
    raw_yaml TEXT
);

CREATE TABLE IF NOT EXISTS detection_technique_mapping (
    id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    detection_id INTEGER NOT NULL,
    technique_id TEXT NOT NULL,
    FOREIGN KEY (detection_id) REFERENCES detections(detection_id),
    FOREIGN KEY (technique_id) REFERENCES mitre_techniques(technique_id)
);

CREATE TABLE IF NOT EXISTS detection_telemetry (
    id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    detection_id INTEGER NOT NULL,
    source_id INTEGER NOT NULL,
    FOREIGN KEY (detection_id) REFERENCES detections(detection_id),
    FOREIGN KEY (source_id) REFERENCES telemetry_sources(source_id)
);

CREATE TABLE IF NOT EXISTS validation_cases (
    case_id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    detection_id INTEGER NOT NULL,
    sample_event TEXT,
    expected_result TEXT,
    actual_result TEXT,
    status TEXT,
    tested_at TEXT,
    attack_name TEXT,
    detection_title TEXT,
    sample_type TEXT,
    source TEXT DEFAULT 'manual',
    source_ref TEXT,
    platform TEXT,
    FOREIGN KEY (detection_id) REFERENCES detections(detection_id)
);

CREATE TABLE IF NOT EXISTS simulation_results (
    result_id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    detection_id INTEGER NOT NULL,
    case_id INTEGER NOT NULL,
    attack_name TEXT,
    sample_type TEXT,
    expected_result TEXT,
    actual_result TEXT,
    passed INTEGER,
    verdict TEXT,
    mode TEXT,
    notes TEXT,
    run_date TEXT,
    evaluation_details TEXT,
    FOREIGN KEY (detection_id) REFERENCES detections(detection_id),
    FOREIGN KEY (case_id) REFERENCES validation_cases(case_id)
);

CREATE TABLE IF NOT EXISTS atomic_runs (
    run_id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    detection_id INTEGER NOT NULL,
    technique_id TEXT NOT NULL,
    atomic_test TEXT,
    target_host TEXT,
    operator TEXT,
    status TEXT DEFAULT 'planned',
    notes TEXT,
    created_at TEXT,
    updated_at TEXT,
    completed_at TEXT,
    FOREIGN KEY (detection_id) REFERENCES detections(detection_id)
);

CREATE TABLE IF NOT EXISTS wazuh_rule_catalog (
    wazuh_rule_id       INTEGER PRIMARY KEY,
    level               INTEGER,
    description         TEXT,
    filename            TEXT,
    relative_dir        TEXT,
    groups_json         TEXT NOT NULL DEFAULT '[]',
    mitre_json          TEXT NOT NULL DEFAULT '[]',
    details_json        TEXT NOT NULL DEFAULT '{}',
    effective_logic_json TEXT NOT NULL DEFAULT '{}',
    raw_rule_json       TEXT NOT NULL DEFAULT '{}',
    content_hash        TEXT NOT NULL,
    imported_at         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ad_attack_tests (
    test_id              TEXT PRIMARY KEY,
    behavior_name        TEXT NOT NULL,
    technique_id         TEXT NOT NULL,
    execution_host       TEXT,
    target_host          TEXT,
    expected_channels_json TEXT NOT NULL DEFAULT '[]',
    expected_event_ids_json TEXT NOT NULL DEFAULT '[]',
    expected_fields_json TEXT NOT NULL DEFAULT '{}',
    simulation_command   TEXT,
    cleanup_command      TEXT,
    risk_tier            TEXT NOT NULL DEFAULT 'low',
    enabled              INTEGER NOT NULL DEFAULT 1,
    attack_key TEXT,
    display_name TEXT,
    description TEXT,
    attack_category TEXT,
    mitre_tactic TEXT,
    attack_stage TEXT,
    required_privileges TEXT,
    prerequisites_json TEXT NOT NULL DEFAULT '[]',
    required_tools_json TEXT NOT NULL DEFAULT '[]',
    expected_sysmon_ids_json TEXT NOT NULL DEFAULT '[]',
    expected_protocols_json TEXT NOT NULL DEFAULT '[]',
    required_wazuh_telemetry_json TEXT NOT NULL DEFAULT '[]',
    expected_wazuh_rules_json TEXT NOT NULL DEFAULT '[]',
    expected_sigma_rules_json TEXT NOT NULL DEFAULT '[]',
    false_positive_notes TEXT,
    support_mode TEXT NOT NULL DEFAULT 'manual_only',
    prerequisite_status TEXT NOT NULL DEFAULT 'unknown',
    rollback_requirements TEXT,
    implementation_status TEXT NOT NULL DEFAULT 'defined',
    telemetry_components_json TEXT NOT NULL DEFAULT '[]',
    seed_version INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ad_telemetry_components (
    component_key TEXT PRIMARY KEY,
    description   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ad_validation_runs (
    run_id               TEXT PRIMARY KEY,
    test_id              TEXT NOT NULL,
    started_at           TEXT NOT NULL,
    ended_at             TEXT,
    source_host          TEXT,
    target_host          TEXT,
    source_ip            TEXT,
    status               TEXT NOT NULL DEFAULT 'running',
    notes                TEXT,
    created_at           TEXT NOT NULL,
    FOREIGN KEY (test_id) REFERENCES ad_attack_tests(test_id)
);

CREATE TABLE IF NOT EXISTS ad_evidence (
    evidence_id          INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id               TEXT NOT NULL,
    evidence_type        TEXT NOT NULL,
    original_filename    TEXT,
    event_fingerprint    TEXT,
    agent_name           TEXT,
    channel              TEXT,
    event_id             TEXT,
    event_timestamp      TEXT,
    wazuh_rule_id        INTEGER,
    payload_json         TEXT NOT NULL,
    imported_at          TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES ad_validation_runs(run_id),
    FOREIGN KEY (wazuh_rule_id) REFERENCES wazuh_rule_catalog(wazuh_rule_id)
);

CREATE INDEX IF NOT EXISTS idx_ad_evidence_run ON ad_evidence(run_id);
CREATE INDEX IF NOT EXISTS idx_ad_evidence_fingerprint ON ad_evidence(event_fingerprint);
CREATE INDEX IF NOT EXISTS idx_ad_evidence_event ON ad_evidence(channel, event_id);

CREATE TABLE IF NOT EXISTS ad_rule_comparisons (
    comparison_id        INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id               TEXT,
    wazuh_rule_id        INTEGER,
    detection_id         INTEGER,
    logsource_score      REAL NOT NULL DEFAULT 0,
    event_id_score       REAL NOT NULL DEFAULT 0,
    field_score          REAL NOT NULL DEFAULT 0,
    value_score          REAL NOT NULL DEFAULT 0,
    dependency_score     REAL NOT NULL DEFAULT 0,
    mitre_score          REAL NOT NULL DEFAULT 0,
    total_score          REAL NOT NULL DEFAULT 0,
    static_verdict       TEXT NOT NULL,
    wazuh_fired          INTEGER,
    sigma_matched        INTEGER,
    behavioral_verdict   TEXT,
    matched_fields_json  TEXT NOT NULL DEFAULT '[]',
    missing_fields_json  TEXT NOT NULL DEFAULT '[]',
    tuning_notes         TEXT,
    compared_at          TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES ad_validation_runs(run_id),
    FOREIGN KEY (wazuh_rule_id) REFERENCES wazuh_rule_catalog(wazuh_rule_id),
    FOREIGN KEY (detection_id) REFERENCES detections(detection_id)
);

CREATE INDEX IF NOT EXISTS idx_ad_compare_run ON ad_rule_comparisons(run_id);
CREATE INDEX IF NOT EXISTS idx_ad_compare_wazuh ON ad_rule_comparisons(wazuh_rule_id);
CREATE INDEX IF NOT EXISTS idx_ad_compare_detection ON ad_rule_comparisons(detection_id);

CREATE TABLE IF NOT EXISTS web_linux_validation_runs (
    id                  INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id              TEXT NOT NULL,
    surface             TEXT NOT NULL CHECK(surface IN ('web','linux')),
    attack_id           TEXT,
    attack_name         TEXT,
    mitre_technique     TEXT,
    target              TEXT,
    source_ip           TEXT,
    started_at          TEXT,
    ended_at            TEXT,
    execution_status    TEXT NOT NULL DEFAULT 'EXECUTED',
    wazuh_detected      INTEGER,
    wazuh_rule_ids_json TEXT NOT NULL DEFAULT '[]',
    sigma_supported     INTEGER NOT NULL DEFAULT 0,
    sigma_matched       INTEGER,
    sigma_rule_ids_json TEXT NOT NULL DEFAULT '[]',
    verdict             TEXT,
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

CREATE TABLE IF NOT EXISTS ai_rule_suggestions (
    id                   INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    attack_id            TEXT    NOT NULL,
    surface              TEXT    NOT NULL CHECK(surface IN ('ad','windows','linux','web')),
    validation_run_id    TEXT,
    verdict              TEXT    NOT NULL,
    raw_verdict          TEXT,
    target_type          TEXT    NOT NULL,
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

CREATE INDEX IF NOT EXISTS idx_ai_sugg_attack ON ai_rule_suggestions(surface, attack_id);
CREATE INDEX IF NOT EXISTS idx_ai_sugg_run ON ai_rule_suggestions(validation_run_id);
CREATE INDEX IF NOT EXISTS idx_ai_sugg_fingerprint ON ai_rule_suggestions(evidence_fingerprint);

CREATE TABLE IF NOT EXISTS ai_rule_versions (
    id                         INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    suggestion_id              INTEGER NOT NULL,
    version_number             INTEGER NOT NULL,
    origin                     TEXT    NOT NULL DEFAULT 'generated',
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

CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_ver_unique ON ai_rule_versions(suggestion_id, version_number);

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

CREATE INDEX IF NOT EXISTS idx_ai_act_sugg ON ai_rule_actions(suggestion_id, id);

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

CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_platform_save_unique ON ai_rule_platform_saves(suggestion_id, version_id);

CREATE TABLE IF NOT EXISTS schema_migrations (
    filename   TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
);
