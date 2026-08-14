"""Persistence for AI rule suggestions, versions and audit actions.

Every write goes through a parameterised statement inside a transaction.
Versions are append-only: regenerating or editing a draft always creates the
next ``version_number`` and never rewrites an earlier one, so the engineer can
always see what the model originally proposed and what changed after their
feedback.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from app.database import get_connection

# ── Status vocabulary ────────────────────────────────────────────────────────

STATUSES = (
    "not_requested", "generating", "draft", "validation_failed",
    "ready_for_review", "revision_requested", "approved", "rejected",
    "saved_to_platform", "staged_for_wazuh", "deployed", "deployment_failed",
    "rolled_back", "superseded",
)

ACTIONS = (
    "generated", "regenerated", "edited", "validated", "approved", "rejected",
    "saved_to_platform", "deployment_requested", "staged", "deployed",
    "deployment_failed", "rolled_back",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dumps(value: Any) -> str:
    return json.dumps(value if value is not None else [], default=str)


def _loads(value: Any, default: Any) -> Any:
    if value in (None, ""):
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


class transaction:
    """Context manager giving one connection with commit/rollback semantics."""

    def __init__(self, conn: sqlite3.Connection | None = None):
        self._external = conn is not None
        self.conn = conn or get_connection()

    def __enter__(self) -> sqlite3.Connection:
        if not self._external:
            self.conn.execute("BEGIN")
        return self.conn

    def __exit__(self, exc_type, exc, tb) -> bool:
        if self._external:
            return False
        try:
            if exc_type is None:
                self.conn.commit()
            else:
                self.conn.rollback()
        finally:
            self.conn.close()
        return False


# ── Suggestions ──────────────────────────────────────────────────────────────

def find_suggestion_for_attack(surface: str, attack_id: str,
                               validation_run_id: str | None = None,
                               conn: sqlite3.Connection | None = None) -> dict | None:
    """Newest suggestion for an attack (optionally scoped to one run)."""
    owns = conn is None
    conn = conn or get_connection()
    try:
        if validation_run_id:
            row = conn.execute(
                "SELECT * FROM ai_rule_suggestions WHERE surface=%s AND attack_id=%s "
                "AND validation_run_id=%s ORDER BY id DESC LIMIT 1",
                (surface, attack_id, validation_run_id),
            ).fetchone()
            if row is not None:
                return dict(row)
        row = conn.execute(
            "SELECT * FROM ai_rule_suggestions WHERE surface=%s AND attack_id=%s "
            "ORDER BY id DESC LIMIT 1",
            (surface, attack_id),
        ).fetchone()
        return dict(row) if row else None
    finally:
        if owns:
            conn.close()


def get_suggestion(suggestion_id: int,
                   conn: sqlite3.Connection | None = None) -> dict | None:
    owns = conn is None
    conn = conn or get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM ai_rule_suggestions WHERE id=%s", (suggestion_id,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        if owns:
            conn.close()


def create_suggestion(*, surface: str, attack_id: str, validation_run_id: str | None,
                      verdict: str, raw_verdict: str, target_type: str,
                      created_by: str, conn: sqlite3.Connection) -> int:
    now = utc_now()
    cursor = conn.execute(
        "INSERT INTO ai_rule_suggestions "
        "(attack_id, surface, validation_run_id, verdict, raw_verdict, target_type, "
        " status, provider, current_version, created_by, created_at, updated_at) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
        (attack_id, surface, validation_run_id, verdict, raw_verdict, target_type,
         "generating", "gemini", 0, created_by, now, now),
    )
    return int(cursor.fetchone()[0])


def update_suggestion(suggestion_id: int, conn: sqlite3.Connection, **fields: Any) -> None:
    allowed = {
        "verdict", "raw_verdict", "target_type", "status", "model", "summary",
        "reasoning_summary", "confidence", "evidence_fingerprint",
        "current_version", "validation_run_id",
    }
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return
    updates["updated_at"] = utc_now()
    columns = ", ".join(f"{k}=%s" for k in updates)
    conn.execute(
        f"UPDATE ai_rule_suggestions SET {columns} WHERE id=%s",
        (*updates.values(), suggestion_id),
    )


# ── Versions ─────────────────────────────────────────────────────────────────

def next_version_number(suggestion_id: int, conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT COALESCE(MAX(version_number), 0) FROM ai_rule_versions WHERE suggestion_id=%s",
        (suggestion_id,),
    ).fetchone()
    return int(row[0]) + 1


def create_version(*, suggestion_id: int, conn: sqlite3.Connection,
                   origin: str = "generated", gap_type: str = "",
                   summary: str = "", reasoning_summary: str = "",
                   confidence: int | None = None,
                   wazuh_xml: str | None = None, wazuh_meta: dict | None = None,
                   sigma_yaml: str | None = None, sigma_meta: dict | None = None,
                   telemetry: list | None = None, assumptions: list | None = None,
                   required_data_sources: list | None = None,
                   false_positives: list | None = None,
                   tuning_notes: list | None = None,
                   deployment_risks: list | None = None,
                   mitre: dict | None = None,
                   engineer_feedback: str | None = None,
                   validation_result: dict | None = None,
                   generated_by: str = "") -> tuple[int, int]:
    """Insert the next version. Returns ``(version_id, version_number)``."""
    version_number = next_version_number(suggestion_id, conn)
    cursor = conn.execute(
        "INSERT INTO ai_rule_versions "
        "(suggestion_id, version_number, origin, gap_type, summary, reasoning_summary, "
        " confidence, wazuh_xml, wazuh_meta_json, sigma_yaml, sigma_meta_json, "
        " telemetry_json, assumptions_json, required_data_sources_json, "
        " false_positives_json, tuning_notes_json, deployment_risks_json, mitre_json, "
        " engineer_feedback, validation_result_json, generated_at, generated_by) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
        (suggestion_id, version_number, origin, gap_type, summary, reasoning_summary,
         confidence, wazuh_xml, json.dumps(wazuh_meta or {}, default=str),
         sigma_yaml, json.dumps(sigma_meta or {}, default=str),
         _dumps(telemetry), _dumps(assumptions), _dumps(required_data_sources),
         _dumps(false_positives), _dumps(tuning_notes), _dumps(deployment_risks),
         json.dumps(mitre or {}, default=str), engineer_feedback,
         json.dumps(validation_result, default=str) if validation_result is not None else None,
         utc_now(), generated_by),
    )
    return int(cursor.fetchone()[0]), version_number


def get_version(version_id: int, conn: sqlite3.Connection | None = None) -> dict | None:
    owns = conn is None
    conn = conn or get_connection()
    try:
        row = conn.execute("SELECT * FROM ai_rule_versions WHERE id=%s", (version_id,)).fetchone()
        return version_to_dict(dict(row)) if row else None
    finally:
        if owns:
            conn.close()


def get_current_version(suggestion: dict,
                        conn: sqlite3.Connection | None = None) -> dict | None:
    owns = conn is None
    conn = conn or get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM ai_rule_versions WHERE suggestion_id=%s AND version_number=%s",
            (suggestion["id"], suggestion.get("current_version") or 0),
        ).fetchone()
        if row is None:
            row = conn.execute(
                "SELECT * FROM ai_rule_versions WHERE suggestion_id=%s "
                "ORDER BY version_number DESC LIMIT 1",
                (suggestion["id"],),
            ).fetchone()
        return version_to_dict(dict(row)) if row else None
    finally:
        if owns:
            conn.close()


def list_versions(suggestion_id: int,
                  conn: sqlite3.Connection | None = None) -> list[dict]:
    owns = conn is None
    conn = conn or get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM ai_rule_versions WHERE suggestion_id=%s ORDER BY version_number",
            (suggestion_id,),
        ).fetchall()
        return [version_to_dict(dict(r)) for r in rows]
    finally:
        if owns:
            conn.close()


def set_version_validation(version_id: int, validation_result: dict,
                           conn: sqlite3.Connection) -> None:
    conn.execute(
        "UPDATE ai_rule_versions SET validation_result_json=%s WHERE id=%s",
        (json.dumps(validation_result, default=str), version_id),
    )


def version_to_dict(row: dict) -> dict:
    """Decode the JSON columns of a version row for API output."""
    return {
        "version_id": row["id"],
        "suggestion_id": row["suggestion_id"],
        "version_number": row["version_number"],
        "origin": row.get("origin"),
        "gap_type": row.get("gap_type"),
        "summary": row.get("summary"),
        "reasoning_summary": row.get("reasoning_summary"),
        "confidence": row.get("confidence"),
        "wazuh_xml": row.get("wazuh_xml"),
        "wazuh_meta": _loads(row.get("wazuh_meta_json"), {}),
        "sigma_yaml": row.get("sigma_yaml"),
        "sigma_meta": _loads(row.get("sigma_meta_json"), {}),
        "telemetry_recommendations": _loads(row.get("telemetry_json"), []),
        "assumptions": _loads(row.get("assumptions_json"), []),
        "required_data_sources": _loads(row.get("required_data_sources_json"), []),
        "false_positives": _loads(row.get("false_positives_json"), []),
        "tuning_notes": _loads(row.get("tuning_notes_json"), []),
        "deployment_risks": _loads(row.get("deployment_risks_json"), []),
        "mitre": _loads(row.get("mitre_json"), {}),
        "engineer_feedback": row.get("engineer_feedback"),
        "validation_result": _loads(row.get("validation_result_json"), None),
        "generated_at": row.get("generated_at"),
        "generated_by": row.get("generated_by"),
    }


# ── Actions (audit trail) ────────────────────────────────────────────────────

def record_action(*, suggestion_id: int, action: str, conn: sqlite3.Connection,
                  version_id: int | None = None, actor: str = "",
                  comment: str = "", metadata: dict | None = None) -> int:
    cursor = conn.execute(
        "INSERT INTO ai_rule_actions "
        "(suggestion_id, version_id, action, actor, comment, metadata_json, created_at) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
        (suggestion_id, version_id, action, actor, comment,
         json.dumps(metadata or {}, default=str), utc_now()),
    )
    return int(cursor.fetchone()[0])


def list_actions(suggestion_id: int,
                 conn: sqlite3.Connection | None = None) -> list[dict]:
    owns = conn is None
    conn = conn or get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM ai_rule_actions WHERE suggestion_id=%s ORDER BY id",
            (suggestion_id,),
        ).fetchall()
        return [
            {
                "id": r["id"],
                "version_id": r["version_id"],
                "action": r["action"],
                "actor": r["actor"],
                "comment": r["comment"],
                "metadata": _loads(r["metadata_json"], {}),
                "created_at": r["created_at"],
            }
            for r in rows
        ]
    finally:
        if owns:
            conn.close()


def last_action(suggestion_id: int, conn: sqlite3.Connection | None = None) -> dict | None:
    actions = list_actions(suggestion_id, conn)
    return actions[-1] if actions else None


# ── Save-to-platform idempotency ─────────────────────────────────────────────

def existing_platform_save(suggestion_id: int, version_id: int,
                           conn: sqlite3.Connection | None = None) -> dict | None:
    owns = conn is None
    conn = conn or get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM ai_rule_platform_saves WHERE suggestion_id=%s AND version_id=%s",
            (suggestion_id, version_id),
        ).fetchone()
        return dict(row) if row else None
    finally:
        if owns:
            conn.close()


def record_platform_save(*, suggestion_id: int, version_id: int, detection_id: int,
                         created_by: str, conn: sqlite3.Connection) -> None:
    conn.execute(
        "INSERT INTO ai_rule_platform_saves "
        "(suggestion_id, version_id, detection_id, created_at, created_by) "
        "VALUES (%s,%s,%s,%s,%s) "
        "ON CONFLICT (suggestion_id, version_id) DO NOTHING",
        (suggestion_id, version_id, detection_id, utc_now(), created_by),
    )


def platform_saves(suggestion_id: int,
                   conn: sqlite3.Connection | None = None) -> list[dict]:
    owns = conn is None
    conn = conn or get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM ai_rule_platform_saves WHERE suggestion_id=%s ORDER BY id",
            (suggestion_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        if owns:
            conn.close()
