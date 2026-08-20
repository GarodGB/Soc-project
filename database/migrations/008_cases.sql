-- ─────────────────────────────────────────────────────────────────────────────
-- Case/alert workflow (Phase 3 of the SOC-hardening roadmap).
--
-- A case is opened against a live Wazuh alert (alerts themselves are not
-- stored in this DB — they're fetched live from the Indexer — so the
-- originating alert is snapshotted onto the case at creation time).
-- Analyst has full ownership here (create/assign/update/close) — the one
-- deliberate carve-out from "Analyst is read-only everywhere".
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS cases (
    id                 INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    title              TEXT    NOT NULL,
    status             TEXT    NOT NULL DEFAULT 'open' CHECK(status IN ('open','investigating','closed')),
    disposition        TEXT    CHECK(disposition IS NULL OR disposition IN
                                     ('true_positive','false_positive','benign','duplicate','other')),
    assigned_to        TEXT,
    created_by         TEXT    NOT NULL,
    -- Snapshot of the originating Wazuh alert (alerts live in the Indexer,
    -- not this DB, so the fields that matter for triage are copied in).
    alert_id           TEXT,
    alert_rule_id      TEXT,
    alert_description  TEXT,
    alert_agent_name   TEXT,
    alert_timestamp    TEXT,
    created_at         TEXT    NOT NULL,
    updated_at         TEXT    NOT NULL,
    closed_at          TEXT
);

CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_assigned_to ON cases(assigned_to);
CREATE INDEX IF NOT EXISTS idx_cases_created_at ON cases(created_at DESC);

-- Append-only investigation notes, oldest first per case.
CREATE TABLE IF NOT EXISTS case_notes (
    id          INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    case_id     INTEGER NOT NULL,
    author      TEXT    NOT NULL,
    note        TEXT    NOT NULL,
    created_at  TEXT    NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(id)
);

CREATE INDEX IF NOT EXISTS idx_case_notes_case ON case_notes(case_id, id);
