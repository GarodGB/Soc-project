"""Idempotent Postgres migration runner.

The platform historically applied ``database/migrations/*.sql`` by hand. Every
migration file is written with ``CREATE TABLE IF NOT EXISTS`` / ``CREATE INDEX
IF NOT EXISTS``, so re-applying one against an already-migrated database is a
no-op. This runner keeps a ``schema_migrations`` ledger so each file is only
executed once, and is safe to call on every application start.

Failures are logged rather than raised for pre-existing migrations (a broken
legacy migration must not stop the server booting), but the caller can assert
that a specific migration's tables now exist via :func:`tables_exist`.
"""
from __future__ import annotations

import logging
import os

import app.database as database

logger = logging.getLogger(__name__)

MIGRATIONS_DIR = os.path.join(os.path.dirname(__file__), "..", "database", "migrations")

_LEDGER_DDL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    filename   TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
)
"""


def _migration_files() -> list[str]:
    directory = os.path.abspath(MIGRATIONS_DIR)
    if not os.path.isdir(directory):
        return []
    return sorted(
        os.path.join(directory, name)
        for name in os.listdir(directory)
        if name.lower().endswith(".sql")
    )


def _statements(sql: str) -> list[str]:
    """Split a migration file into individual statements.

    Postgres (unlike sqlite3's executescript) has no single-call "run this
    whole file" primitive when statements need separate error handling, so
    each ``;``-terminated statement is executed on its own.
    """
    return [s.strip() for s in sql.split(";") if s.strip()]


def run_migrations() -> dict[str, list[str]]:
    """Apply every not-yet-recorded migration file, in filename order.

    Returns ``{"applied": [...], "skipped": [...], "failed": [...]}`` using
    bare filenames.
    """
    applied: list[str] = []
    skipped: list[str] = []
    failed: list[str] = []

    conn = database.get_connection()
    try:
        conn.execute(_LEDGER_DDL)
        conn.commit()
        done = {row[0] for row in conn.execute("SELECT filename FROM schema_migrations")}

        for full_path in _migration_files():
            name = os.path.basename(full_path)
            if name in done:
                skipped.append(name)
                continue
            try:
                with open(full_path, "r", encoding="utf-8") as handle:
                    sql = handle.read()
                for statement in _statements(sql):
                    conn.execute(statement)
                conn.execute(
                    "INSERT INTO schema_migrations (filename, applied_at) "
                    "VALUES (%s, now()::text) "
                    "ON CONFLICT (filename) DO UPDATE SET applied_at = EXCLUDED.applied_at",
                    (name,),
                )
                conn.commit()
                applied.append(name)
                logger.info("applied migration %s", name)
            except Exception:
                conn.rollback()
                failed.append(name)
                logger.exception("migration %s failed", name)
    finally:
        conn.close()

    return {"applied": applied, "skipped": skipped, "failed": failed}


def tables_exist(names: list[str]) -> bool:
    """True when every table in *names* is present in the database."""
    conn = database.get_connection()
    try:
        present = {
            row[0]
            for row in conn.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
            )
        }
    finally:
        conn.close()
    return all(name in present for name in names)


#: Tables the AI Detection Rule Recommendation workflow cannot run without.
AI_RULE_TABLES = [
    "ai_rule_suggestions",
    "ai_rule_versions",
    "ai_rule_actions",
    "ai_rule_platform_saves",
]


def ensure_ai_rule_tables() -> None:
    """Run migrations and hard-fail if the AI workflow tables are still absent."""
    run_migrations()
    if not tables_exist(AI_RULE_TABLES):
        raise RuntimeError(
            "AI rule suggestion tables are missing — "
            "database/migrations/005_ai_rule_suggestions.sql did not apply."
        )
