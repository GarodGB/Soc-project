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


class TelemetryParseRequest(BaseModel):
    sample_event: str
    source_hint: Optional[str] = None


class ValidationCaseCreate(BaseModel):
    detection_id: int
    attack_name: str = "Real Telemetry Input"
    sample_event: str
    expected_result: str = "fire"
    sample_type: str = "positive"
    source: str = "real_telemetry"
    source_ref: Optional[str] = None
    platform: Optional[str] = None
    notes: Optional[str] = None


class ValidationCaseCreate(BaseModel):
    detection_id: int
    attack_name: str = "Real Telemetry Input"
    sample_event: str
    expected_result: str = "fire"       # fire | no_fire
    sample_type: str = "positive"       # positive | negative | false_positive
    source: str = "real_telemetry"
    source_ref: Optional[str] = None
    platform: Optional[str] = None
    notes: Optional[str] = None


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

def _normalize_result(value: str) -> str:
    value = (value or "").strip().lower()

    if value in ("match", "fire", "detected", "true", "tp"):
        return "fire"

    if value in ("no_match", "no-fire", "no_fire", "not_detected", "false", "tn"):
        return "no_fire"

    return value


def _verdict(expected: str, actual: str) -> str:
    expected_fire = _normalize_result(expected) == "fire"
    actual_fire = _normalize_result(actual) == "fire"

    if expected_fire and actual_fire:
        return "TP"
    if expected_fire and not actual_fire:
        return "MISS"
    if not expected_fire and actual_fire:
        return "FP"
    return "TN"




def _safe_lower(value):
    return str(value or "").lower()


def _infer_required_telemetry_from_detection(detection: dict) -> list[str]:
    """
    Infer required telemetry from Sigma logsource, tags, title, and rule body.
    This is not perfect, but it is useful when detection_telemetry mapping is missing.
    """
    text_blob = " ".join([
        str(detection.get("title") or ""),
        str(detection.get("description") or ""),
        str(detection.get("tags") or ""),
        str(detection.get("logsource") or ""),
        str(detection.get("raw_yaml") or ""),
        str(detection.get("rule_logic") or ""),
        str(detection.get("platform") or ""),
    ]).lower()

    required = set()

    if any(x in text_blob for x in ["eventid: 4688", "eventid 4688", "process creation", "commandline", "newprocessname"]):
        required.add("Windows Security 4688 / Process Creation")

    if any(x in text_blob for x in ["eventid: 4624", "eventid 4624", "successful logon"]):
        required.add("Windows Security 4624 / Successful Logon")

    if any(x in text_blob for x in ["eventid: 4625", "eventid 4625", "failed logon", "password spraying", "brute force"]):
        required.add("Windows Security 4625 / Failed Logon")

    if any(x in text_blob for x in ["eventid: 4768", "eventid 4768", "kerberos authentication"]):
        required.add("Windows Security 4768 / Kerberos TGT")

    if any(x in text_blob for x in ["eventid: 4769", "eventid 4769", "tgs", "kerberoast", "service ticket"]):
        required.add("Windows Security 4769 / Kerberos TGS")

    if any(x in text_blob for x in ["eventid: 4771", "eventid 4771", "pre-authentication", "as-rep", "asrep"]):
        required.add("Windows Security 4771 / Kerberos Pre-Auth Failed")

    if any(x in text_blob for x in ["sysmon", "image", "parentimage", "process_guid", "processguid"]):
        required.add("Sysmon Process Events")

    if any(x in text_blob for x in ["powershell", "scriptblock", "script block", "4104", "4103"]):
        required.add("PowerShell 4103/4104")

    if any(x in text_blob for x in ["dns", "queryname", "query_name", "domain"]):
        required.add("DNS Logs")

    if any(x in text_blob for x in ["firewall", "src_ip", "dst_ip", "sourceip", "destinationip"]):
        required.add("Firewall / Network Logs")

    if any(x in text_blob for x in ["ldap", "dcsync", "replication", "directory service"]):
        required.add("Domain Controller / LDAP Logs")

    if "linux" in text_blob:
        required.add("Linux Auth / Audit Logs")

    if not required:
        platform = _safe_lower(detection.get("platform"))
        if "linux" in platform:
            required.add("Linux Auth / Audit Logs")
        elif "identity" in platform:
            required.add("Identity Provider / AD Logs")
        else:
            required.add("Windows Security Logs")

    return sorted(required)


def _available_telemetry_names(conn) -> list[str]:
    try:
        rows = conn.execute("SELECT name, category, status FROM telemetry_sources").fetchall()
        available = []
        for r in rows:
            status = _safe_lower(r["status"])
            if status in ("active", "healthy", "available", "enabled", ""):
                available.append(str(r["name"] or r["category"] or ""))
        return available
    except Exception:
        return []


def _is_telemetry_available(required_name: str, available_names: list[str]) -> bool:
    req = required_name.lower()
    aliases = {
        "windows security": ["windows", "security", "event"],
        "sysmon": ["sysmon"],
        "powershell": ["powershell", "4104", "4103"],
        "dns": ["dns"],
        "firewall": ["firewall", "network"],
        "domain controller": ["domain", "ldap", "identity", "active directory", "ad"],
        "linux": ["linux", "auth", "audit"],
        "identity": ["identity", "active directory", "ad"],
    }

    for available in available_names:
        av = available.lower()
        if req in av or av in req:
            return True

        for key, terms in aliases.items():
            if key in req and any(term in av for term in terms):
                return True

    return False


def _parse_telemetry_sample(sample_event: str, source_hint: Optional[str] = None) -> dict:
    raw = sample_event or ""
    raw_lower = raw.lower()
    parsed = {}
    detected_type = "Unknown / Custom"
    confidence = "low"

    # Try JSON first
    try:
        parsed_json = json.loads(raw)
        if isinstance(parsed_json, dict):
            parsed = parsed_json
            confidence = "high"
    except Exception:
        parsed = {}

    # If not JSON, try key=value parsing
    if not parsed:
        pairs = re.findall(r'([A-Za-z0-9_.-]+)\s*[:=]\s*("[^"]+"|\'[^\']+\'|[^,\s]+)', raw)
        for k, v in pairs:
            parsed[k] = str(v).strip('"').strip("'")
        if parsed:
            confidence = "medium"

    keys_lower = {str(k).lower(): v for k, v in parsed.items()}
    field_names = list(parsed.keys())

    def has_key(*names):
        names = [n.lower() for n in names]
        return any(n in keys_lower for n in names)

    def has_text(*terms):
        return any(t.lower() in raw_lower for t in terms)

    if source_hint:
        detected_type = source_hint

    if has_key("eventid", "event_id") or has_text("eventid", "event id"):
        event_id = str(keys_lower.get("eventid") or keys_lower.get("event_id") or "")
        if event_id in ("4688",):
            detected_type = "Windows Security Event - Process Creation"
        elif event_id in ("4624", "4625", "4672", "4768", "4769", "4771", "4776"):
            detected_type = "Windows Security Event - Authentication / Kerberos"
        else:
            detected_type = "Windows Security Event"
        confidence = "high"

    if has_key("image", "parentimage", "processguid", "process_guid") or has_text("sysmon"):
        detected_type = "Sysmon / Endpoint Process Telemetry"
        confidence = "high"

    if has_key("scriptblocktext") or has_text("scriptblock", "powershell 4104", "eventid 4104", '"eventid": 4104'):
        detected_type = "PowerShell 4104 Script Block"
        confidence = "high"

    if has_key("src_ip", "sourceip", "source_ip", "dst_ip", "destinationip", "destination_ip"):
        if "dns" in raw_lower or has_key("queryname", "query_name", "dns_query"):
            detected_type = "DNS / Network Telemetry"
        else:
            detected_type = "Firewall / Network Telemetry"
        confidence = "medium" if confidence == "low" else confidence

    if has_text("failed password", "sshd", "pam_unix", "/var/log/auth"):
        detected_type = "Linux Auth Log"
        confidence = "high"

    important_fields = []
    for f in [
        "EventID", "Computer", "User", "SubjectUserName", "TargetUserName",
        "Image", "ParentImage", "CommandLine", "ScriptBlockText",
        "SourceIp", "DestinationIp", "src_ip", "dst_ip", "QueryName",
        "ServiceName", "IpAddress"
    ]:
        if f in parsed or f.lower() in keys_lower:
            important_fields.append(f)

    missing_common = []
    dtype = detected_type.lower()

    if "process" in dtype or "sysmon" in dtype:
        for f in ["Image", "CommandLine", "ParentImage", "User"]:
            if f.lower() not in keys_lower:
                missing_common.append(f)

    if "authentication" in dtype or "kerberos" in dtype:
        for f in ["EventID", "TargetUserName", "IpAddress", "Computer"]:
            if f.lower() not in keys_lower:
                missing_common.append(f)

    if "powershell" in dtype:
        for f in ["ScriptBlockText", "User", "Computer"]:
            if f.lower() not in keys_lower:
                missing_common.append(f)

    indicators = []
    suspicious_terms = [
        "mimikatz", "lsass", "procdump", "powershell -enc", "-enc",
        "encodedcommand", "rundll32", "regsvr32", "psexec", "wmic",
        "dcsync", "kerberoast", "as-rep", "asrep", "ntds.dit",
        "password spraying", "brute force", "crackmapexec"
    ]

    for term in suspicious_terms:
        if term in raw_lower:
            indicators.append(term)

    recommendations = []
    if not parsed:
        recommendations.append("Use JSON or key=value format for better parsing.")
    if missing_common:
        recommendations.append("Add missing common fields to improve detection quality.")
    if not indicators:
        recommendations.append("No obvious suspicious keyword found. Use this as benign/negative telemetry if expected.")
    else:
        recommendations.append("Suspicious indicators found. Use this as positive validation telemetry.")

    return {
        "detected_type": detected_type,
        "confidence": confidence,
        "fields_found": field_names,
        "important_fields": sorted(set(important_fields)),
        "missing_common_fields": sorted(set(missing_common)),
        "indicators": sorted(set(indicators)),
        "recommendations": recommendations,
        "parsed_preview": parsed,
        "length": len(raw)
    }



# ── Routes ────────────────────────────────────────────────────────────────────



@router.get("/readiness/{detection_id}")
def get_detection_readiness(detection_id: int):
    """
    Detection readiness score:
    - validation pass rate
    - telemetry availability
    - MITRE mapping
    - false positive documentation
    - deployment documentation / rule content
    """
    conn = get_connection()
    try:
        detection = conn.execute(
            "SELECT * FROM detections WHERE detection_id = ?",
            (detection_id,)
        ).fetchone()

        if not detection:
            raise HTTPException(status_code=404, detail="Detection not found")

        detection = dict(detection)

        validation_rows = conn.execute("""
            SELECT status, expected_result, actual_result
            FROM validation_cases
            WHERE detection_id = ?
        """, (detection_id,)).fetchall()

        total_cases = len(validation_rows)
        passed_cases = sum(1 for r in validation_rows if r["status"] == "passed")
        failed_cases = sum(1 for r in validation_rows if r["status"] == "failed")

        validation_score = 0
        if total_cases > 0:
            validation_score = round((passed_cases / total_cases) * 40, 1)

        required_telemetry = _infer_required_telemetry_from_detection(detection)
        available_telemetry = _available_telemetry_names(conn)

        missing_telemetry = [
            t for t in required_telemetry
            if not _is_telemetry_available(t, available_telemetry)
        ]

        if required_telemetry:
            available_count = len(required_telemetry) - len(missing_telemetry)
            telemetry_score = round((available_count / len(required_telemetry)) * 20, 1)
        else:
            telemetry_score = 0

        mitre_exists = bool(
            detection.get("tags")
            or conn.execute(
                "SELECT COUNT(*) FROM detection_technique_mapping WHERE detection_id = ?",
                (detection_id,)
            ).fetchone()[0]
        )
        mitre_score = 15 if mitre_exists else 0

        fp_exists = bool(detection.get("falsepositives") or detection.get("false_positives"))
        fp_score = 15 if fp_exists else 0

        deploy_exists = bool(detection.get("raw_yaml") or detection.get("rule_logic") or detection.get("description"))
        deploy_score = 10 if deploy_exists else 0

        total_score = round(validation_score + telemetry_score + mitre_score + fp_score + deploy_score, 1)

        if total_score >= 80:
            readiness_status = "Ready for Production"
        elif total_score >= 50:
            readiness_status = "Needs Tuning"
        else:
            readiness_status = "Not Ready"

        blockers = []
        if total_cases == 0:
            blockers.append("No validation cases exist yet.")
        if failed_cases > 0:
            blockers.append(f"{failed_cases} validation case(s) failed.")
        if missing_telemetry:
            blockers.append("Required telemetry is missing or not mapped.")
        if not mitre_exists:
            blockers.append("MITRE ATT&CK mapping is missing.")
        if not fp_exists:
            blockers.append("False positive notes are missing.")

        return {
            "detection_id": detection_id,
            "title": detection.get("title"),
            "score": total_score,
            "status": readiness_status,
            "components": {
                "validation": validation_score,
                "telemetry": telemetry_score,
                "mitre_mapping": mitre_score,
                "false_positive_notes": fp_score,
                "deployment_documentation": deploy_score
            },
            "validation": {
                "total_cases": total_cases,
                "passed": passed_cases,
                "failed": failed_cases,
                "pass_rate": round((passed_cases / total_cases) * 100, 1) if total_cases else 0
            },
            "telemetry": {
                "required": required_telemetry,
                "available": available_telemetry,
                "missing": missing_telemetry
            },
            "blockers": blockers,
            "next_actions": [
                "Generate or add validation cases." if total_cases == 0 else None,
                "Fix failed validation cases." if failed_cases > 0 else None,
                "Map or enable missing telemetry." if missing_telemetry else None,
                "Add MITRE ATT&CK mapping." if not mitre_exists else None,
                "Document known false positives." if not fp_exists else None
            ]
        }
    finally:
        conn.close()


@router.get("/telemetry-warning/{detection_id}")
def get_detection_telemetry_warning(detection_id: int):
    conn = get_connection()
    try:
        detection = conn.execute(
            "SELECT * FROM detections WHERE detection_id = ?",
            (detection_id,)
        ).fetchone()

        if not detection:
            raise HTTPException(status_code=404, detail="Detection not found")

        detection = dict(detection)
        required = _infer_required_telemetry_from_detection(detection)
        available = _available_telemetry_names(conn)
        missing = [t for t in required if not _is_telemetry_available(t, available)]

        impact = "Low"
        if missing and len(missing) == len(required):
            impact = "High"
        elif missing:
            impact = "Medium"

        return {
            "detection_id": detection_id,
            "required_telemetry": required,
            "available_telemetry": available,
            "missing_telemetry": missing,
            "impact": impact,
            "message": "Detection may fail or produce weak coverage because required telemetry is missing." if missing else "Required telemetry appears available."
        }
    finally:
        conn.close()


@router.post("/parse-telemetry")
def parse_real_telemetry(body: TelemetryParseRequest):
    return _parse_telemetry_sample(body.sample_event, body.source_hint)


@router.post("/cases")
def create_validation_case(body: ValidationCaseCreate):
    """
    Save pasted telemetry as a reusable validation case.
    """
    conn = get_connection()
    try:
        detection = conn.execute(
            "SELECT detection_id, title, platform FROM detections WHERE detection_id = ?",
            (body.detection_id,)
        ).fetchone()

        if not detection:
            raise HTTPException(status_code=404, detail="Detection not found")

        expected = (body.expected_result or "fire").strip().lower()
        if expected in ("match", "detected", "true", "tp"):
            expected = "fire"
        elif expected in ("no_match", "not_detected", "false", "tn"):
            expected = "no_fire"

        sample_type = body.sample_type or ("positive" if expected == "fire" else "negative")

        conn.execute("""
            INSERT INTO validation_cases
              (detection_id, detection_title, attack_name, sample_type,
               sample_event, expected_result, actual_result, status,
               source, source_ref, platform, notes, tested_at)
            VALUES (?, ?, ?, ?, ?, ?, NULL, 'untested', ?, ?, ?, ?, NULL)
        """, (
            body.detection_id,
            detection["title"],
            body.attack_name,
            sample_type,
            body.sample_event,
            expected,
            body.source,
            body.source_ref,
            body.platform or detection["platform"],
            body.notes,
        ))

        conn.commit()
        case_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        return {
            "message": "Telemetry saved as validation case",
            "case_id": case_id,
            "detection_id": body.detection_id,
            "expected_result": expected,
            "status": "untested"
        }
    finally:
        conn.close()


@router.post("/cases")
def create_validation_case(body: ValidationCaseCreate):
    """
    Save a real telemetry sample as a reusable validation case.
    This lets the Test Runner turn pasted logs into validation data.
    """
    conn = get_connection()
    try:
        detection = conn.execute(
            "SELECT detection_id, title, platform FROM detections WHERE detection_id = ?",
            (body.detection_id,)
        ).fetchone()

        if not detection:
            raise HTTPException(status_code=404, detail="Detection not found")

        expected = (body.expected_result or "fire").strip().lower()
        if expected in ("match", "detected", "true", "tp"):
            expected = "fire"
        elif expected in ("no_match", "not_detected", "false", "tn"):
            expected = "no_fire"

        sample_type = body.sample_type or ("positive" if expected == "fire" else "negative")

        conn.execute("""
            INSERT INTO validation_cases
              (detection_id, detection_title, attack_name, sample_type,
               sample_event, expected_result, actual_result, status,
               source, source_ref, platform, notes, tested_at)
            VALUES (?, ?, ?, ?, ?, ?, NULL, 'untested', ?, ?, ?, ?, NULL)
        """, (
            body.detection_id,
            detection["title"],
            body.attack_name,
            sample_type,
            body.sample_event,
            expected,
            body.source,
            body.source_ref,
            body.platform or detection["platform"],
            body.notes,
        ))

        conn.commit()
        case_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        return {
            "message": "Real telemetry saved as validation case",
            "case_id": case_id,
            "detection_id": body.detection_id,
            "expected_result": expected,
            "status": "untested"
        }
    finally:
        conn.close()


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
        expected = _normalize_result(expected)
        actual = _normalize_result(actual)
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
        expected = _normalize_result(case["expected_result"])
        actual = _normalize_result(body.actual_result)
        passed = expected == actual
        status = "passed" if passed else "failed"

        conn.execute("""
            UPDATE validation_cases
            SET actual_result=?, status=?, tested_at=?
            WHERE case_id=?
        """, (actual, status, datetime.utcnow().isoformat(), case_id))
        conn.commit()

        return {
            "case_id":        case_id,
            "detection_id":   case["detection_id"],
            "detection_title": case["detection_title"],
            "attack_name":    case["attack_name"],
            "expected":       expected,
            "actual":         actual,
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
            expected = _normalize_result(expected)
            actual = _normalize_result(actual)
            passed = expected == actual
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
                    expected = _normalize_result(c.get("expected_result"))
                    simulated = _normalize_result(simulated)
                    passed = expected == simulated
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
