"""
Persisted Web (DVWA) and Linux (SSH) attack validation runs.

Read-only (plus one small insert) surface over the web_linux_validation_runs /
web_linux_evidence tables created by database/migrations/004_web_linux_validation.sql.
Rows are written by app/routes/wazuh.py's validate-live / validate-linux
endpoints (real Wazuh + Sigma evaluation, never fabricated) and by
POST /not-executed when a pre-flight check fails before an attack ever runs.

Mount in app/main.py:
    from app.routes import validation_runs
    app.include_router(validation_runs.router, prefix="/api/validation-runs", tags=["validation-runs"])
"""

import json as _json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from app.database import get_connection
from app.services.ad_catalog import mask_sensitive
from app.services.auth_service import ROLE_ADMIN, current_actor, require_read_access, require_write_access

router = APIRouter(dependencies=[Depends(require_read_access)])

_SURFACES = ("web", "linux")


class _NotExecutedReq(BaseModel):
    surface: str
    target: str = ""
    error_code: str = "UNREACHABLE"
    error_reason: str = ""


def _row_to_item(row: dict) -> dict:
    return {
        "run_id": row["run_id"],
        "surface": row["surface"],
        "attack_id": row["attack_id"],
        "attack_name": row["attack_name"],
        "mitre_technique": row["mitre_technique"],
        "status": "not_executed" if row["execution_status"] == "NOT_EXECUTED" else "completed",
        "execution_status": row["execution_status"],
        "started_at": row["started_at"],
        "ended_at": row["ended_at"],
        "target": row["target"],
        "wazuh_detected": bool(row["wazuh_detected"]) if row["wazuh_detected"] is not None else None,
        "wazuh_rule_ids": _json.loads(row["wazuh_rule_ids_json"] or "[]"),
        "sigma_supported": bool(row["sigma_supported"]),
        "sigma_matched": bool(row["sigma_matched"]) if row["sigma_matched"] is not None else None,
        "sigma_rule_ids": _json.loads(row["sigma_rule_ids_json"] or "[]"),
        "verdict": row["verdict"],
        "evidence_count": row["evidence_count"],
        "error_code": row["error_code"],
        "error_reason": row["error_reason"],
    }


@router.get("")
@router.get("/")
def list_validation_runs(surface: str = Query(default="all"), limit: int = Query(default=200, le=1000)):
    """Flat per-attack-behavior rows, newest first."""
    conn = get_connection()
    try:
        if surface in _SURFACES:
            rows = conn.execute(
                "SELECT * FROM web_linux_validation_runs WHERE surface=%s ORDER BY created_at DESC LIMIT %s",
                (surface, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM web_linux_validation_runs ORDER BY created_at DESC LIMIT %s",
                (limit,),
            ).fetchall()
        items = [_row_to_item(dict(r)) for r in rows]
        return {"total": len(items), "limit": limit, "items": items}
    finally:
        conn.close()


@router.get("/runs")
def list_runs_grouped(surface: str = Query(default="all"), limit: int = Query(default=50, le=500)):
    """One row per run_id (a batch of attack behaviors executed together) —
    feeds the 'Recent Runs' list in the Web/Linux workspaces."""
    conn = get_connection()
    try:
        where = "WHERE surface=%s" if surface in _SURFACES else ""
        params = (surface,) if surface in _SURFACES else ()
        rows = conn.execute(
            f"SELECT * FROM web_linux_validation_runs {where} ORDER BY created_at DESC",
            params,
        ).fetchall()

        grouped: dict = {}
        order: list = []
        for r in rows:
            rid = r["run_id"]
            if rid not in grouped:
                grouped[rid] = {
                    "run_id": rid,
                    "surface": r["surface"],
                    "target": r["target"],
                    "started_at": r["started_at"],
                    "ended_at": r["ended_at"],
                    "execution_status": r["execution_status"],
                    "error_code": r["error_code"],
                    "error_reason": r["error_reason"],
                    "attack_count": 0,
                    "verdict_counts": {},
                    "evidence_count": 0,
                }
                order.append(rid)
            g = grouped[rid]
            g["attack_count"] += 1
            g["evidence_count"] += r["evidence_count"] or 0
            v = r["verdict"] or "UNKNOWN"
            g["verdict_counts"][v] = g["verdict_counts"].get(v, 0) + 1
            if r["ended_at"] and (not g["ended_at"] or r["ended_at"] > g["ended_at"]):
                g["ended_at"] = r["ended_at"]

        items = [grouped[rid] for rid in order][:limit]
        return {"total": len(items), "items": items}
    finally:
        conn.close()


@router.get("/summary")
def validation_runs_summary(surface: str = Query(default="all")):
    """Aggregate verdict counts for one surface's stat cards."""
    conn = get_connection()
    try:
        where = "WHERE surface=%s" if surface in _SURFACES else ""
        params = (surface,) if surface in _SURFACES else ()
        rows = conn.execute(
            f"SELECT verdict, execution_status, evidence_count FROM web_linux_validation_runs {where}",
            params,
        ).fetchall()

        counts = {
            "total_behaviors": 0,
            "verified_overlap": 0,
            "wazuh_only": 0,
            "sigma_only": 0,
            "no_detection_in_either": 0,
            "evaluator_unsupported": 0,
            "not_executed": 0,
            "evidence_total": 0,
        }
        run_ids = set()
        for r in rows:
            counts["total_behaviors"] += 1
            counts["evidence_total"] += r["evidence_count"] or 0
            if r["execution_status"] == "NOT_EXECUTED":
                counts["not_executed"] += 1
                continue
            v = (r["verdict"] or "").lower()
            if v == "verified_overlap":
                counts["verified_overlap"] += 1
            elif v == "wazuh_only":
                counts["wazuh_only"] += 1
            elif v == "sigma_only":
                counts["sigma_only"] += 1
            elif v == "no_detection_in_either":
                counts["no_detection_in_either"] += 1
            elif v == "evaluator_unsupported":
                counts["evaluator_unsupported"] += 1

        run_rows = conn.execute(
            f"SELECT DISTINCT run_id FROM web_linux_validation_runs {where}", params
        ).fetchall()
        counts["run_count"] = len(run_rows)
        return counts
    finally:
        conn.close()


@router.get("/{run_id}")
def get_validation_run(run_id: str, request: Request):
    """Full detail for one run: every attack behavior tested + its evidence."""
    mask = current_actor(request).role != ROLE_ADMIN
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM web_linux_validation_runs WHERE run_id=%s ORDER BY id", (run_id,)
        ).fetchall()
        if not rows:
            raise HTTPException(404, f"No validation run found for run_id={run_id}")

        items = []
        for r in rows:
            item = _row_to_item(dict(r))
            ev_rows = conn.execute(
                "SELECT * FROM web_linux_evidence WHERE run_id=%s AND attack_id=%s ORDER BY evidence_id",
                (run_id, r["attack_id"]),
            ).fetchall()
            item["evidence"] = [mask_sensitive(dict(e)) if mask else dict(e) for e in ev_rows]
            items.append(item)

        return {"run_id": run_id, "surface": rows[0]["surface"], "items": items}
    finally:
        conn.close()


@router.post("/not-executed", dependencies=[Depends(require_write_access)])
def record_not_executed(req: _NotExecutedReq):
    """Record a run that never started because pre-flight failed. Never a
    detection gap, never a telemetry gap — just an honest audit trail entry."""
    if req.surface not in _SURFACES:
        raise HTTPException(400, f"surface must be one of {_SURFACES}")

    now = datetime.now(timezone.utc).isoformat()
    run_id = f"NOT_EXECUTED_{req.surface.upper()}_{now.replace(':', '').replace('-', '').replace('.', '')}"

    conn = get_connection()
    try:
        conn.execute(
            """INSERT INTO web_linux_validation_runs
               (run_id, surface, attack_id, attack_name, mitre_technique, target,
                source_ip, started_at, ended_at, execution_status, wazuh_detected,
                wazuh_rule_ids_json, sigma_supported, sigma_matched, sigma_rule_ids_json,
                verdict, error_code, error_reason, evidence_count, created_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (run_id, req.surface, None, None, None, req.target or None,
             None, now, now, "NOT_EXECUTED", None,
             "[]", 0, None, "[]",
             "NOT_EXECUTED", req.error_code, req.error_reason, 0, now),
        )
        conn.commit()
        return {"run_id": run_id, "execution_status": "NOT_EXECUTED"}
    finally:
        conn.close()
