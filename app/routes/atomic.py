from datetime import datetime
import re
import shutil
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.database import get_connection

router = APIRouter()


class AtomicRunCreate(BaseModel):
    detection_id: int
    technique_id: str
    atomic_test: Optional[str] = None
    target_host: Optional[str] = None
    operator: Optional[str] = None
    notes: Optional[str] = None


class AtomicRunUpdate(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = None


class AtomicLogIngest(BaseModel):
    sample_event: str
    expected_result: str = "fire"
    sample_type: str = "positive"
    attack_name: Optional[str] = None


def _ensure_atomic_runs(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS atomic_runs (
            run_id INTEGER PRIMARY KEY AUTOINCREMENT,
            detection_id INTEGER NOT NULL,
            technique_id TEXT NOT NULL,
            atomic_test TEXT,
            target_host TEXT,
            operator TEXT,
            status TEXT DEFAULT 'planned',
            notes TEXT,
            created_at TEXT,
            updated_at TEXT,
            completed_at TEXT,
            FOREIGN KEY (detection_id) REFERENCES detections(detection_id)
        )
    """)


def _techniques_from_detection(detection: dict) -> list[str]:
    text = f"{detection.get('tags') or ''}\n{detection.get('raw_yaml') or ''}"
    techniques = re.findall(r"attack\.?(t\d{4}(?:\.\d{3})?)", text, flags=re.I)
    techniques += re.findall(r"\b(t\d{4}(?:\.\d{3})?)\b", text, flags=re.I)
    seen = []
    for t in techniques:
        tid = t.upper()
        if tid not in seen:
            seen.append(tid)
    return seen


def _atomic_commands(technique_id: str) -> dict:
    tid = technique_id.upper()
    return {
        "inspect": f"Invoke-AtomicTest {tid} -ShowDetailsBrief",
        "check_prereqs": f"Invoke-AtomicTest {tid} -CheckPrereqs",
        "get_prereqs": f"Invoke-AtomicTest {tid} -GetPrereqs",
        "execute": f"Invoke-AtomicTest {tid}",
        "cleanup": f"Invoke-AtomicTest {tid} -Cleanup",
    }


@router.get("/status")
def get_atomic_status():
    pwsh_path = shutil.which("pwsh") or shutil.which("powershell")
    return {
        "server_can_run_powershell": bool(pwsh_path),
        "powershell_path": pwsh_path,
        "execution_mode": "manual_lab",
        "safety_note": (
            "Atomic Red Team tests should be run on a controlled lab endpoint. "
            "This app prepares and tracks tests but does not execute them automatically."
        ),
    }


@router.get("/plan/{detection_id}")
def plan_atomic_tests(detection_id: int):
    conn = get_connection()
    try:
        detection = conn.execute(
            "SELECT * FROM detections WHERE detection_id = ?", (detection_id,)
        ).fetchone()
        if not detection:
            raise HTTPException(status_code=404, detail="Detection not found")
        detection = dict(detection)
        techniques = _techniques_from_detection(detection)
        plans = [
            {
                "technique_id": tid,
                "commands": _atomic_commands(tid),
                "workflow": [
                    "Run inspect to choose a safe atomic test for your lab.",
                    "Run check_prereqs and get_prereqs if needed.",
                    "Run execute on the lab endpoint.",
                    "Collect the generated logs from EDR/SIEM.",
                    "Paste the real log back into this app as a validation sample.",
                    "Run local Sigma validation against the collected log.",
                    "Run cleanup on the lab endpoint.",
                ],
            }
            for tid in techniques
        ]
        return {
            "detection_id": detection_id,
            "title": detection.get("title", ""),
            "techniques": techniques,
            "plans": plans,
        }
    finally:
        conn.close()


@router.post("/runs", status_code=201)
def create_atomic_run(body: AtomicRunCreate):
    conn = get_connection()
    try:
        _ensure_atomic_runs(conn)
        detection = conn.execute(
            "SELECT title FROM detections WHERE detection_id = ?", (body.detection_id,)
        ).fetchone()
        if not detection:
            raise HTTPException(status_code=404, detail="Detection not found")
        now = datetime.utcnow().isoformat()
        conn.execute("""
            INSERT INTO atomic_runs
              (detection_id, technique_id, atomic_test, target_host, operator,
               status, notes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 'planned', ?, ?, ?)
        """, (
            body.detection_id,
            body.technique_id.upper(),
            body.atomic_test or "",
            body.target_host or "",
            body.operator or "",
            body.notes or "",
            now,
            now,
        ))
        conn.commit()
        run_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        return get_atomic_run(run_id)
    finally:
        conn.close()


@router.get("/runs")
def list_atomic_runs(limit: int = 100):
    conn = get_connection()
    try:
        _ensure_atomic_runs(conn)
        rows = conn.execute("""
            SELECT ar.*, d.title AS detection_title
            FROM atomic_runs ar
            LEFT JOIN detections d ON ar.detection_id = d.detection_id
            ORDER BY ar.run_id DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@router.get("/runs/{run_id}")
def get_atomic_run(run_id: int):
    conn = get_connection()
    try:
        _ensure_atomic_runs(conn)
        row = conn.execute("""
            SELECT ar.*, d.title AS detection_title
            FROM atomic_runs ar
            LEFT JOIN detections d ON ar.detection_id = d.detection_id
            WHERE ar.run_id = ?
        """, (run_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Atomic run not found")
        return dict(row)
    finally:
        conn.close()


@router.patch("/runs/{run_id}")
def update_atomic_run(run_id: int, body: AtomicRunUpdate):
    allowed = {"planned", "running", "completed", "failed", "cancelled"}
    conn = get_connection()
    try:
        _ensure_atomic_runs(conn)
        row = conn.execute("SELECT * FROM atomic_runs WHERE run_id = ?", (run_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Atomic run not found")
        updates = body.model_dump(exclude_unset=True)
        if "status" in updates and updates["status"] not in allowed:
            raise HTTPException(status_code=400, detail="Invalid run status")
        updates["updated_at"] = datetime.utcnow().isoformat()
        if updates.get("status") in ("completed", "failed", "cancelled"):
            updates["completed_at"] = updates["updated_at"]
        set_clause = ", ".join(f"{key}=?" for key in updates)
        conn.execute(
            f"UPDATE atomic_runs SET {set_clause} WHERE run_id=?",
            [*updates.values(), run_id],
        )
        conn.commit()
        return get_atomic_run(run_id)
    finally:
        conn.close()


@router.post("/runs/{run_id}/sample-log", status_code=201)
def attach_atomic_log(run_id: int, body: AtomicLogIngest):
    if body.expected_result not in {"fire", "no_fire"}:
        raise HTTPException(status_code=400, detail="expected_result must be fire or no_fire")
    if body.sample_type not in {"positive", "negative"}:
        raise HTTPException(status_code=400, detail="sample_type must be positive or negative")

    conn = get_connection()
    try:
        _ensure_atomic_runs(conn)
        run = conn.execute("""
            SELECT ar.*, d.title AS detection_title
            FROM atomic_runs ar
            LEFT JOIN detections d ON ar.detection_id = d.detection_id
            WHERE ar.run_id = ?
        """, (run_id,)).fetchone()
        if not run:
            raise HTTPException(status_code=404, detail="Atomic run not found")
        run = dict(run)
        attack_name = body.attack_name or f"Atomic {run['technique_id']} - {run['detection_title']}"
        conn.execute("""
            INSERT INTO validation_cases
              (detection_id, sample_event, expected_result, actual_result, status,
               tested_at, attack_name, detection_title, sample_type)
            VALUES (?, ?, ?, NULL, 'untested', NULL, ?, ?, ?)
        """, (
            run["detection_id"],
            body.sample_event,
            body.expected_result,
            attack_name,
            run["detection_title"],
            body.sample_type,
        ))
        conn.commit()
        case_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        return {
            "case_id": case_id,
            "run_id": run_id,
            "detection_id": run["detection_id"],
            "detection_title": run["detection_title"],
            "attack_name": attack_name,
            "expected_result": body.expected_result,
            "sample_type": body.sample_type,
        }
    finally:
        conn.close()
