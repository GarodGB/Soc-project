"""
ABSEGA - AD Attack Catalog router (additive). Prefix: /api/ad-catalog

Read + plan endpoints for the 30 new attack definitions. Run creation, evidence,
compare, recheck, CSV export all continue to use the existing
/api/ad-validation/* endpoints (no duplicate logic). This router only adds the
catalog browse/detail/plan/readiness surface the new UI needs.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.database import get_connection
from app.services import ad_catalog as C
from app.services.auth_service import require_read_access, require_write_access

router = APIRouter(prefix="/api/ad-catalog", tags=["AD Catalog"],
                    dependencies=[Depends(require_read_access)])

# attacks NOT part of the new catalog (the original 6) - excluded from catalog list
_LEGACY_KEYS = {
    "AD-T1059.001-ENCODED-POWERSHELL", "AD-T1558.003-KERBEROAST",
    "AD-T1558.004-ASREP-ROAST", "AD-T1110.003-SMB-SPRAY",
    "AD-T1110.003-LDAP-SPRAY", "AD-T1569.002-PSEXEC",
}


def _latest_run_for(connection, test_id: str) -> dict[str, Any] | None:
    """Newest non-superseded run for this attack + its newest comparison."""
    run = connection.execute(
        """
        SELECT run_id, started_at, status
        FROM ad_validation_runs
        WHERE test_id = %s AND status != 'superseded'
        ORDER BY started_at DESC LIMIT 1
        """,
        (test_id,),
    ).fetchone()
    if run is None:
        return None
    out = dict(run)
    cmp = connection.execute(
        """
        SELECT wazuh_fired, sigma_matched, static_verdict, behavioral_verdict
        FROM ad_rule_comparisons
        WHERE run_id = %s
        ORDER BY comparison_id DESC LIMIT 1
        """,
        (run["run_id"],),
    ).fetchone()
    if cmp is not None:
        out.update(dict(cmp))
    return out


@router.get("/attacks")
def list_attacks(
    category: str | None = None,
    risk: str | None = None,
    support_mode: str | None = None,
    prerequisite_status: str | None = None,
    technique: str | None = None,
    readiness: str | None = Query(None, description="ready|partially_ready|missing|unknown"),
    q: str | None = None,
    include_legacy: bool = False,
) -> dict[str, Any]:
    connection = get_connection()
    try:
        observed = C.observed_components(connection)
        rows = connection.execute(
            "SELECT * FROM ad_attack_tests WHERE enabled = 1 ORDER BY attack_category, display_name"
        ).fetchall()

        items: list[dict[str, Any]] = []
        for row in rows:
            key = row["attack_key"] or row["test_id"]
            if not include_legacy and key in _LEGACY_KEYS:
                continue
            latest = _latest_run_for(connection, row["test_id"])
            obj = C.serialize_attack(row, observed, latest)

            if category and (obj["attack_category"] or "").lower() != category.lower():
                continue
            if risk and (obj["risk_tier"] or "").lower() != risk.lower():
                continue
            if support_mode and (obj["support_mode"] or "").lower() != support_mode.lower():
                continue
            if prerequisite_status and (obj["prerequisite_status"] or "").lower() != prerequisite_status.lower():
                continue
            if technique and technique.lower() not in (obj["technique_id"] or "").lower():
                continue
            if readiness and obj["telemetry_readiness"] != readiness:
                continue
            if q:
                blob = " ".join(str(obj.get(f) or "") for f in
                                ("display_name", "description", "technique_id", "attack_category")).lower()
                if q.lower() not in blob:
                    continue
            items.append(obj)

        return {"count": len(items), "attacks": items}
    finally:
        connection.close()


@router.get("/attacks/{attack_key}")
def get_attack(attack_key: str) -> dict[str, Any]:
    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT * FROM ad_attack_tests WHERE attack_key = %s OR test_id = %s",
            (attack_key, attack_key),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="attack_key not found")
        observed = C.observed_components(connection)
        latest = _latest_run_for(connection, row["test_id"])
        obj = C.serialize_attack(row, observed, latest)

        # attach recent run history (masked) for the drawer timeline
        history = connection.execute(
            """
            SELECT run_id, started_at, status, source_host, target_host, source_ip
            FROM ad_validation_runs
            WHERE test_id = %s
            ORDER BY started_at DESC LIMIT 10
            """,
            (row["test_id"],),
        ).fetchall()
        obj["run_history"] = [dict(h) for h in history]
        return obj
    finally:
        connection.close()


@router.get("/attacks/{attack_key}/plan")
def get_plan(attack_key: str) -> dict[str, Any]:
    """PLAN MODE - never executes. Returns the simulation plan + a target
    allowlist check the UI must pass before offering a run."""
    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT * FROM ad_attack_tests WHERE attack_key = %s OR test_id = %s",
            (attack_key, attack_key),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="attack_key not found")
        obj = C.serialize_attack(row, C.observed_components(connection),
                                 _latest_run_for(connection, row["test_id"]))
        ok, violations = C.validate_targets(
            obj["execution_host"], obj["target_host"], None, None
        )
        return {
            "mode": "plan",
            "executes": False,
            "attack_key": obj["attack_key"],
            "display_name": obj["display_name"],
            "support_mode": obj["support_mode"],
            "risk_tier": obj["risk_tier"],
            "prerequisite_status": obj["prerequisite_status"],
            "target_allowlist_ok": ok,
            "target_violations": violations,
            "requires_snapshot": obj["risk_tier"] in ("high", "critical"),
            "simulation_plan": obj["simulation_command"],
            "expected_channels": obj["expected_channels"],
            "expected_event_ids": obj["expected_event_ids"],
            "expected_sysmon_ids": obj["expected_sysmon_ids"],
            "prerequisites": obj["prerequisites"],
            "required_tools": obj["required_tools"],
            "cleanup_command": obj["cleanup_command"],
            "rollback_requirements": obj["rollback_requirements"],
            "false_positive_notes": obj["false_positive_notes"],
        }
    finally:
        connection.close()


@router.get("/telemetry/components")
def telemetry_components() -> dict[str, Any]:
    connection = get_connection()
    try:
        observed = C.observed_components(connection)
        rows = connection.execute(
            "SELECT component_key, description FROM ad_telemetry_components ORDER BY component_key"
        ).fetchall()
        return {
            "observed_count": len(observed),
            "components": [
                {"component_key": r["component_key"], "description": r["description"],
                 "observed": r["component_key"] in observed}
                for r in rows
            ],
        }
    finally:
        connection.close()


@router.get("/summary")
def catalog_summary() -> dict[str, Any]:
    """Live, computed counts - never hardcoded."""
    connection = get_connection()
    try:
        def group(col: str) -> dict[str, int]:
            rows = connection.execute(
                f"SELECT {col} AS k, COUNT(*) AS n FROM ad_attack_tests "
                f"WHERE enabled=1 AND attack_key NOT IN ({','.join(['%s'] * len(_LEGACY_KEYS))}) "
                f"GROUP BY {col}",
                tuple(_LEGACY_KEYS),
            ).fetchall()
            return {str(r["k"]): r["n"] for r in rows}

        total = connection.execute(
            f"SELECT COUNT(*) FROM ad_attack_tests WHERE enabled=1 AND "
            f"attack_key NOT IN ({','.join(['%s'] * len(_LEGACY_KEYS))})",
            tuple(_LEGACY_KEYS),
        ).fetchone()[0]

        tested = connection.execute(
            f"""
            SELECT COUNT(DISTINCT t.test_id) FROM ad_attack_tests t
            JOIN ad_validation_runs r ON r.test_id = t.test_id
            WHERE r.status != 'superseded'
              AND t.attack_key NOT IN ({','.join(['%s'] * len(_LEGACY_KEYS))})
            """,
            tuple(_LEGACY_KEYS),
        ).fetchone()[0]

        return {
            "total_new_attacks": total,
            "tested": tested,
            "never_tested": total - tested,
            "by_category": group("attack_category"),
            "by_support_mode": group("support_mode"),
            "by_prerequisite_status": group("prerequisite_status"),
            "by_risk": group("risk_tier"),
        }
    finally:
        connection.close()


class TargetCheckRequest(BaseModel):
    source_host: str | None = None
    target_host: str | None = None
    source_ip: str | None = None
    target_ip: str | None = None


@router.post("/validate-targets", dependencies=[Depends(require_write_access)])
def validate_targets_endpoint(request: TargetCheckRequest) -> dict[str, Any]:
    ok, violations = C.validate_targets(
        request.source_host, request.target_host, request.source_ip, request.target_ip
    )
    return {"allowed": ok, "violations": violations,
            "allowlist": {"hosts": sorted(C.ALLOWED_HOSTS), "domain": C.ALLOWED_DOMAIN,
                          "ips": sorted(C.ALLOWED_IPS)}}


@router.post("/runs/{run_id}/supersede", dependencies=[Depends(require_write_access)])
def supersede_run(run_id: str) -> dict[str, Any]:
    """Mark a run superseded (kept in history, filtered from active lists)."""
    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT status FROM ad_validation_runs WHERE run_id = %s", (run_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="run_id not found")
        connection.execute(
            "UPDATE ad_validation_runs SET status = 'superseded' WHERE run_id = %s",
            (run_id,),
        )
        connection.commit()
        return {"run_id": run_id, "previous_status": row["status"], "status": "superseded"}
    finally:
        connection.close()
