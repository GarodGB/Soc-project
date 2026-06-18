from app.database import get_connection


def _columns(conn, table_name):
    try:
        return {row[1] for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()}
    except Exception:
        return set()


def _add_column(conn, table_name, column_name, column_sql):
    if column_name not in _columns(conn, table_name):
        conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_sql}")


def init_db():
    conn = get_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS detections (
                detection_id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                rule_logic TEXT,
                severity TEXT DEFAULT 'medium',
                status TEXT DEFAULT 'test',
                author TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT,
                platform TEXT DEFAULT 'windows',
                sigma_id TEXT,
                logsource TEXT,
                falsepositives TEXT,
                modified TEXT,
                reference_urls TEXT,
                tags TEXT,
                raw_yaml TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS mitre_techniques (
                technique_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                tactic TEXT NOT NULL,
                description TEXT,
                url TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS telemetry_sources (
                source_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                category TEXT,
                status TEXT DEFAULT 'active',
                coverage TEXT,
                event_rate TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS validation_cases (
                case_id INTEGER PRIMARY KEY AUTOINCREMENT,
                detection_id INTEGER NOT NULL,
                detection_title TEXT,
                attack_name TEXT,
                sample_type TEXT,
                sample_event TEXT,
                expected_result TEXT,
                actual_result TEXT,
                status TEXT DEFAULT 'untested',
                source TEXT DEFAULT 'manual',
                source_ref TEXT,
                platform TEXT,
                notes TEXT,
                tested_at TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS simulation_results (
                result_id INTEGER PRIMARY KEY AUTOINCREMENT,
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
                evaluation_details TEXT,
                run_date TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS detection_technique_mapping (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                detection_id INTEGER NOT NULL,
                technique_id TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS detection_telemetry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                detection_id INTEGER NOT NULL,
                source_id INTEGER NOT NULL,
                required INTEGER DEFAULT 1,
                notes TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS detection_suggestions (
                suggestion_id INTEGER PRIMARY KEY AUTOINCREMENT,
                technique_id TEXT,
                title TEXT NOT NULL,
                reason TEXT,
                suggested_sigma TEXT,
                required_telemetry TEXT,
                priority TEXT DEFAULT 'medium',
                status TEXT DEFAULT 'open',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT,
                action TEXT,
                target_type TEXT,
                target_id TEXT,
                details TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        _add_column(conn, "validation_cases", "detection_title", "detection_title TEXT")
        _add_column(conn, "validation_cases", "attack_name", "attack_name TEXT")
        _add_column(conn, "validation_cases", "sample_type", "sample_type TEXT")
        _add_column(conn, "validation_cases", "source", "source TEXT DEFAULT 'manual'")
        _add_column(conn, "validation_cases", "source_ref", "source_ref TEXT")
        _add_column(conn, "validation_cases", "platform", "platform TEXT")
        _add_column(conn, "validation_cases", "notes", "notes TEXT")
        _add_column(conn, "validation_cases", "tested_at", "tested_at TEXT")

        _add_column(conn, "telemetry_sources", "event_rate", "event_rate TEXT")
        _add_column(conn, "simulation_results", "evaluation_details", "evaluation_details TEXT")
        _add_column(conn, "detection_telemetry", "required", "required INTEGER DEFAULT 1")
        _add_column(conn, "detection_telemetry", "notes", "notes TEXT")

        conn.commit()
    finally:
        conn.close()
