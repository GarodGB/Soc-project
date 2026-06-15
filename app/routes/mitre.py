from fastapi import APIRouter, Query
from typing import Optional
from app.database import get_connection

router = APIRouter()


def _ensure_simulation_results(conn):
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
            run_date TEXT
        )
    """)


@router.get("/")
def get_techniques(
    tactic: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
):
    """Return MITRE ATT&CK techniques, optionally filtered."""
    conn = get_connection()
    try:
        sql, params = "SELECT * FROM mitre_techniques WHERE 1=1", []
        if tactic:
            sql += " AND tactic LIKE ?"
            params.append(f"%{tactic}%")
        if search:
            sql += " AND (name LIKE ? OR technique_id LIKE ?)"
            like = f"%{search}%"
            params.extend([like, like])
        sql += " ORDER BY technique_id"
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@router.get("/coverage")
def get_coverage_summary():
    """
    Per-technique coverage state, derived from validation evidence:

      • covered  – ≥1 mapped rule has fired correctly on a real attack sample
                   (manual case marked passed, OR atomic case marked passed).
      • failing  – ≥1 mapped rule has a *manual* case that failed (the engineer
                   said "should fire" and it didn't, or vice versa). Atomic-
                   sourced misses don't mark the technique failing — a narrowly-
                   scoped rule legitimately won't catch every attack variant.
      • partial  – rules exist but none have a passing test yet.
      • gap      – no rules mapped to this technique.
    """
    conn = get_connection()
    try:
        _ensure_simulation_results(conn)
        rows = conn.execute("""
            WITH validation_evidence AS (
                SELECT
                    detection_id,
                    CASE WHEN status = 'passed' THEN 1 ELSE 0 END AS passed,
                    CASE WHEN status = 'failed' THEN 1 ELSE 0 END AS failed,
                    COALESCE(source, 'manual') AS src
                FROM validation_cases
                WHERE status IN ('passed', 'failed')
            ),
            validation_rollup AS (
                SELECT
                    detection_id,
                    SUM(passed) AS pass_count,
                    SUM(CASE WHEN failed = 1 AND src = 'manual' THEN 1 ELSE 0 END) AS manual_fail_count
                FROM validation_evidence
                GROUP BY detection_id
            )
            SELECT
                mt.technique_id,
                mt.name,
                mt.tactic,
                COUNT(DISTINCT d.detection_id)                                AS total_detections,
                SUM(CASE WHEN d.status IN ('stable','active') THEN 1 ELSE 0 END) AS active_detections,
                SUM(CASE WHEN d.status IN ('test','testing','experimental') THEN 1 ELSE 0 END) AS testing_detections,
                SUM(CASE WHEN COALESCE(vr.pass_count, 0) > 0 THEN 1 ELSE 0 END) AS validated_detections,
                SUM(CASE WHEN COALESCE(vr.pass_count, 0) = 0 AND COALESCE(vr.manual_fail_count, 0) > 0 THEN 1 ELSE 0 END) AS failing_detections
            FROM mitre_techniques mt
            LEFT JOIN detection_technique_mapping dtm ON mt.technique_id = dtm.technique_id
            LEFT JOIN detections d ON dtm.detection_id = d.detection_id
            LEFT JOIN validation_rollup vr ON d.detection_id = vr.detection_id
            GROUP BY mt.technique_id
            ORDER BY mt.tactic, mt.technique_id
        """).fetchall()

        result = []
        for r in rows:
            d = dict(r)
            if d["validated_detections"] and d["validated_detections"] > 0:
                state = "covered"
            elif d["failing_detections"] and d["failing_detections"] > 0:
                state = "failing"
            elif d["total_detections"] and d["total_detections"] > 0:
                state = "partial"
            else:
                state = "gap"
            d["coverage_state"] = state
            result.append(d)
        return result
    finally:
        conn.close()


@router.get("/{technique_id}")
def get_technique(technique_id: str):
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM mitre_techniques WHERE technique_id = ?", (technique_id,)
        ).fetchone()
        if not row:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="Technique not found")
        return dict(row)
    finally:
        conn.close()
