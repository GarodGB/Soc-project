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
    enabled              INTEGER NOT NULL DEFAULT 1
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
