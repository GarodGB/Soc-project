from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import json
from app.database import get_connection
from app.sigma_eval import SigmaEvaluationError, evaluate_sigma_rule

router = APIRouter()


# ── Models ────────────────────────────────────────────────────────────────────

class ValidationRun(BaseModel):
    detection_id: int
    actual_result: str          # "fire" | "no_fire"
    notes: Optional[str] = None


class SimulationRequest(BaseModel):
    detection_id: int
    case_id: int
    mode: str = "auto"          # auto | tp | tn | fp
    notes: Optional[str] = None


class ValidationCaseUpdate(BaseModel):
    detection_id: Optional[int] = None
    attack_name: Optional[str] = None
    sample_event: Optional[str] = None
    expected_result: Optional[str] = None
    sample_type: Optional[str] = None
    status: Optional[str] = None


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
            evaluation_details TEXT,
            run_date TEXT,
            FOREIGN KEY (detection_id) REFERENCES detections(detection_id),
            FOREIGN KEY (case_id) REFERENCES validation_cases(case_id)
        )
    """)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(simulation_results)").fetchall()}
    if "evaluation_details" not in cols:
        conn.execute("ALTER TABLE simulation_results ADD COLUMN evaluation_details TEXT")


def _rule_fires_for_sample(detection: dict, case: dict, mode: str) -> tuple[bool, dict]:
    if mode == "tp":
        return True, {"engine": "manual_override", "mode": mode}
    if mode == "tn":
        return False, {"engine": "manual_override", "mode": mode}
    if mode == "fp":
        return True, {"engine": "manual_override", "mode": mode}

    details = evaluate_sigma_rule(detection.get("raw_yaml") or "", case.get("sample_event") or "")
    details["engine"] = "local_sigma_evaluator"
    return bool(details["matched"]), details


def _verdict(expected: str, actual: str) -> str:
    expected_fire = expected in ("fire", "match")
    actual_fire = actual in ("fire", "match")
    if expected_fire and actual_fire:
        return "TP"
    if expected_fire and not actual_fire:
        return "MISS"
    if not expected_fire and actual_fire:
        return "FP"
    return "TN"


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/")
def get_validation_cases(
    detection_id: Optional[int] = Query(None),
    status:       Optional[str] = Query(None),
    limit:        int           = Query(200, le=10000),
):
    """Return validation test cases, optionally filtered by detection or status."""
    conn = get_connection()
    try:
        sql, params = "SELECT * FROM validation_cases WHERE 1=1", []
        if detection_id:
            sql += " AND detection_id = ?"
            params.append(detection_id)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY case_id DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@router.get("/summary")
def get_validation_summary():
    """Aggregate pass/fail counts across all test cases."""
    conn = get_connection()
    try:
        _ensure_simulation_results(conn)
        total    = conn.execute("SELECT COUNT(*) FROM validation_cases").fetchone()[0]
        passed   = conn.execute(
            "SELECT COUNT(*) FROM validation_cases WHERE status = 'passed'"
        ).fetchone()[0]
        failed   = conn.execute(
            "SELECT COUNT(*) FROM validation_cases WHERE status = 'failed'"
        ).fetchone()[0]
        untested = conn.execute(
            "SELECT COUNT(*) FROM validation_cases WHERE status = 'untested'"
        ).fetchone()[0]
        return {
            "total":    total,
            "passed":   passed,
            "failed":   failed,
            "untested": untested,
            "simulation_runs": conn.execute("SELECT COUNT(*) FROM simulation_results").fetchone()[0],
            "simulation_passed": conn.execute("SELECT COUNT(*) FROM simulation_results WHERE passed = 1").fetchone()[0],
            "simulation_failed": conn.execute("SELECT COUNT(*) FROM simulation_results WHERE passed = 0").fetchone()[0],
            "pass_rate": round(passed / total * 100, 1) if total else 0,
        }
    finally:
        conn.close()


@router.get("/simulation-results")
def get_simulation_results(limit: int = Query(100, le=1000)):
    conn = get_connection()
    try:
        _ensure_simulation_results(conn)
        rows = conn.execute("""
            SELECT sr.*, d.title AS detection_title, vc.sample_event
            FROM simulation_results sr
            LEFT JOIN detections d ON sr.detection_id = d.detection_id
            LEFT JOIN validation_cases vc ON sr.case_id = vc.case_id
            ORDER BY sr.result_id DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@router.get("/{case_id}/matching-rules")
def get_matching_rules_for_case(case_id: int, limit: int = Query(20, le=100)):
    conn = get_connection()
    try:
        case = conn.execute(
            "SELECT * FROM validation_cases WHERE case_id = ?", (case_id,)
        ).fetchone()
        if not case:
            raise HTTPException(status_code=404, detail="Validation case not found")
        case = dict(case)

        matches = []
        errors = []
        rows = conn.execute("""
            SELECT detection_id, title, severity, status, platform, tags, raw_yaml
            FROM detections
            WHERE raw_yaml IS NOT NULL AND length(raw_yaml) > 0
        """).fetchall()
        for row in rows:
            detection = dict(row)
            try:
                details = evaluate_sigma_rule(detection.get("raw_yaml") or "", case.get("sample_event") or "")
            except SigmaEvaluationError as exc:
                if len(errors) < 10:
                    errors.append({"detection_id": detection["detection_id"], "error": str(exc)})
                continue
            if details["matched"]:
                matches.append({
                    "detection_id": detection["detection_id"],
                    "title": detection["title"],
                    "severity": detection["severity"],
                    "status": detection["status"],
                    "platform": detection["platform"],
                    "tags": detection["tags"],
                    "matched_selections": details["matched_selections"],
                })
                if len(matches) >= limit:
                    break
        return {"case_id": case_id, "matches": matches, "errors": errors}
    finally:
        conn.close()


@router.patch("/{case_id}")
def update_validation_case(case_id: int, body: ValidationCaseUpdate):
    allowed_expected = {"fire", "no_fire", "match", "no_match"}
    allowed_sample_type = {"positive", "negative"}
    allowed_status = {"passed", "failed", "untested"}
    updates = body.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")
    if "expected_result" in updates and updates["expected_result"] not in allowed_expected:
        raise HTTPException(status_code=400, detail="Invalid expected_result")
    if "sample_type" in updates and updates["sample_type"] not in allowed_sample_type:
        raise HTTPException(status_code=400, detail="Invalid sample_type")
    if "status" in updates and updates["status"] not in allowed_status:
        raise HTTPException(status_code=400, detail="Invalid status")

    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM validation_cases WHERE case_id = ?", (case_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Validation case not found")

        if "detection_id" in updates:
            detection = conn.execute(
                "SELECT title FROM detections WHERE detection_id = ?", (updates["detection_id"],)
            ).fetchone()
            if not detection:
                raise HTTPException(status_code=404, detail="Target detection not found")
            updates["detection_title"] = detection["title"]

        updates["actual_result"] = None
        updates["tested_at"] = None
        if "status" not in updates:
            updates["status"] = "untested"

        set_clause = ", ".join(f"{key}=?" for key in updates)
        conn.execute(
            f"UPDATE validation_cases SET {set_clause} WHERE case_id=?",
            [*updates.values(), case_id],
        )
        conn.commit()
        updated = conn.execute(
            "SELECT * FROM validation_cases WHERE case_id = ?", (case_id,)
        ).fetchone()
        return dict(updated)
    finally:
        conn.close()


@router.post("/simulate")
def simulate_detection_against_case(req: SimulationRequest):
    conn = get_connection()
    try:
        _ensure_simulation_results(conn)
        detection = conn.execute(
            "SELECT * FROM detections WHERE detection_id = ?", (req.detection_id,)
        ).fetchone()
        if not detection:
            raise HTTPException(status_code=404, detail="Detection not found")

        case = conn.execute(
            "SELECT * FROM validation_cases WHERE case_id = ?", (req.case_id,)
        ).fetchone()
        if not case:
            raise HTTPException(status_code=404, detail="Validation case not found")

        detection = dict(detection)
        case = dict(case)
        if str(case.get("detection_id")) != str(req.detection_id):
            raise HTTPException(
                status_code=400,
                detail="This sample log does not target the selected detection rule",
            )
        try:
            fired, eval_details = _rule_fires_for_sample(detection, case, req.mode)
        except SigmaEvaluationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        actual = "fire" if fired else "no_fire"
        expected = case.get("expected_result") or ("fire" if case.get("sample_type") == "positive" else "no_fire")
        passed = expected == actual
        status = "passed" if passed else "failed"
        verdict = _verdict(expected, actual)
        now = datetime.utcnow().isoformat()

        conn.execute("""
            INSERT INTO simulation_results
              (detection_id, case_id, attack_name, sample_type, expected_result,
               actual_result, passed, verdict, mode, notes, evaluation_details, run_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            req.detection_id,
            req.case_id,
            case.get("attack_name", ""),
            case.get("sample_type", ""),
            expected,
            actual,
            1 if passed else 0,
            verdict,
            req.mode,
            req.notes or eval_details.get("engine", ""),
            json.dumps(eval_details),
            now,
        ))

        conn.execute("""
            UPDATE validation_cases
            SET actual_result=?, status=?, tested_at=?
            WHERE case_id=?
        """, (actual, status, now, req.case_id))

        conn.commit()
        return {
            "detection_id": req.detection_id,
            "detection_title": detection.get("title", ""),
            "case_id": req.case_id,
            "attack_name": case.get("attack_name", ""),
            "sample_type": case.get("sample_type", ""),
            "expected": expected,
            "actual": actual,
            "fired": fired,
            "passed": passed,
            "status": status,
            "verdict": verdict,
            "run_date": now,
            "evaluation": eval_details,
        }
    finally:
        conn.close()


@router.post("/{case_id}/run")
def run_validation_case(case_id: int, body: ValidationRun):
    """
    Record the actual result of running a validation test case.
    Marks the case as passed/failed based on expected vs actual result.
    """
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM validation_cases WHERE case_id = ?", (case_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Validation case not found")

        case = dict(row)
        passed = (case["expected_result"] == body.actual_result)
        status = "passed" if passed else "failed"

        conn.execute("""
            UPDATE validation_cases
            SET actual_result=?, status=?, tested_at=?
            WHERE case_id=?
        """, (body.actual_result, status, datetime.utcnow().isoformat(), case_id))
        conn.commit()

        return {
            "case_id":        case_id,
            "detection_id":   case["detection_id"],
            "detection_title": case["detection_title"],
            "attack_name":    case["attack_name"],
            "expected":       case["expected_result"],
            "actual":         body.actual_result,
            "passed":         passed,
            "status":         status,
        }
    finally:
        conn.close()


@router.post("/test-rule/{detection_id}")
def test_rule(detection_id: int):
    """
    Run every validation case attached to this detection through the Sigma
    engine, store each result as a simulation_result, refresh the case row,
    and return a per-case + aggregate summary the UI can render directly.
    """
    conn = get_connection()
    try:
        _ensure_simulation_results(conn)
        detection = conn.execute(
            "SELECT * FROM detections WHERE detection_id = ?", (detection_id,)
        ).fetchone()
        if not detection:
            raise HTTPException(status_code=404, detail="Detection not found")
        detection = dict(detection)
        if not detection.get("raw_yaml"):
            raise HTTPException(status_code=422, detail="Detection has no Sigma YAML to test")

        cases = conn.execute(
            "SELECT * FROM validation_cases WHERE detection_id = ?",
            (detection_id,),
        ).fetchall()
        cases = [dict(c) for c in cases]
        if not cases:
            return {
                "detection_id": detection_id,
                "detection_title": detection.get("title", ""),
                "ran": 0,
                "passed": 0,
                "failed": 0,
                "fired": 0,
                "results": [],
                "note": "No validation cases attached to this rule yet.",
            }

        now = datetime.utcnow().isoformat()
        results = []
        passed_total = failed_total = fired_total = 0
        for case in cases:
            try:
                fired, eval_details = _rule_fires_for_sample(detection, case, "auto")
            except SigmaEvaluationError as exc:
                eval_details = {"engine": "pysigma", "error": str(exc)}
                fired = False

            actual = "fire" if fired else "no_fire"
            expected = case.get("expected_result") or (
                "fire" if case.get("sample_type") == "positive" else "no_fire"
            )
            passed = (expected == actual)
            status = "passed" if passed else "failed"
            verdict = _verdict(expected, actual)
            passed_total += int(passed)
            failed_total += int(not passed)
            fired_total += int(fired)

            conn.execute("""
                INSERT INTO simulation_results
                  (detection_id, case_id, attack_name, sample_type, expected_result,
                   actual_result, passed, verdict, mode, notes, evaluation_details, run_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                detection_id,
                case["case_id"],
                case.get("attack_name", ""),
                case.get("sample_type", ""),
                expected,
                actual,
                1 if passed else 0,
                verdict,
                "auto",
                eval_details.get("engine", "pysigma"),
                json.dumps(eval_details),
                now,
            ))
            conn.execute("""
                UPDATE validation_cases
                SET actual_result=?, status=?, tested_at=?
                WHERE case_id=?
            """, (actual, status, now, case["case_id"]))

            results.append({
                "case_id":      case["case_id"],
                "attack_name":  case.get("attack_name", ""),
                "sample_type":  case.get("sample_type", ""),
                "source":       case.get("source", "manual"),
                "expected":     expected,
                "actual":       actual,
                "fired":        fired,
                "passed":       passed,
                "verdict":      verdict,
                "engine":       eval_details.get("engine", "pysigma"),
                "failure_reasons": (eval_details.get("failure_reasons") or [])[:3],
            })
        conn.commit()

        return {
            "detection_id":    detection_id,
            "detection_title": detection.get("title", ""),
            "ran":             len(results),
            "passed":          passed_total,
            "failed":          failed_total,
            "fired":           fired_total,
            "pass_rate":       round(passed_total / len(results) * 100, 1) if results else 0,
            "fire_rate":       round(fired_total / len(results) * 100, 1) if results else 0,
            "results":         results,
        }
    finally:
        conn.close()


@router.post("/run-all")
def run_all_cases():
    """
    Evaluate all validation cases with the local Sigma evaluator.
    Returns a summary.
    """
    conn = get_connection()
    try:
        cases = conn.execute(
            "SELECT * FROM validation_cases"
        ).fetchall()

        results = []
        now = datetime.utcnow().isoformat()
        for c in cases:
            c = dict(c)
            detection = conn.execute(
                "SELECT * FROM detections WHERE detection_id = ?", (c["detection_id"],)
            ).fetchone()
            if not detection:
                simulated = "no_fire"
                passed = False
                status = "failed"
                error = "Detection not found"
            else:
                try:
                    fired, _details = _rule_fires_for_sample(dict(detection), c, "auto")
                    simulated = "fire" if fired else "no_fire"
                    passed = (c["expected_result"] == simulated)
                    status = "passed" if passed else "failed"
                    error = None
                except SigmaEvaluationError as exc:
                    simulated = "no_fire"
                    passed = False
                    status = "failed"
                    error = str(exc)

            conn.execute("""
                UPDATE validation_cases
                SET actual_result=?, status=?, tested_at=?
                WHERE case_id=?
            """, (simulated, status, now, c["case_id"]))
            results.append({
                "case_id":    c["case_id"],
                "name":       c.get("detection_title", ""),
                "attack":     c.get("attack_name", ""),
                "expected":   c.get("expected_result", ""),
                "actual":     simulated,
                "passed":     passed,
                "status":     status,
                "error":      error,
            })
        conn.commit()

        total  = len(results)
        passed = sum(1 for r in results if r["passed"])
        return {
            "ran":    total,
            "passed": passed,
            "failed": total - passed,
            "results": results,
        }
    finally:
        conn.close()
