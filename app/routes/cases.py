"""Case/alert triage workflow.

Analyst has full ownership here (create/assign/update status/notes/close) —
the one deliberate carve-out from "Analyst is read-only everywhere"
(see app/services/auth_service.py WRITE_ROLES). Every route below only
requires a signed-in session, not a write role.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional

from app.database import get_connection
from app.services.audit_service import log_audit
from app.services.auth_service import require_read_access

router = APIRouter(dependencies=[Depends(require_read_access)])

VALID_STATUSES = {"open", "investigating", "closed"}
VALID_DISPOSITIONS = {"true_positive", "false_positive", "benign", "duplicate", "other"}


# ── Models ───────────────────────────────────────────────────────────────────

class CaseCreate(BaseModel):
    title: str
    alert_id: Optional[str] = None
    alert_rule_id: Optional[str] = None
    alert_description: Optional[str] = None
    alert_agent_name: Optional[str] = None
    alert_timestamp: Optional[str] = None
    assign_to_self: bool = False


class CaseUpdate(BaseModel):
    title: Optional[str] = None
    status: Optional[str] = None
    disposition: Optional[str] = None


class AssignRequest(BaseModel):
    assignee: Optional[str] = None  # omitted/blank = assign to self


class CloseRequest(BaseModel):
    disposition: str


class NoteCreate(BaseModel):
    note: str


# ── Helpers ──────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _case_or_404(conn, case_id: int) -> dict:
    row = conn.execute("SELECT * FROM cases WHERE id = %s", (case_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Case not found")
    return dict(row)


def _with_notes(conn, case: dict) -> dict:
    notes = conn.execute(
        "SELECT id, author, note, created_at FROM case_notes WHERE case_id = %s ORDER BY id",
        (case["id"],),
    ).fetchall()
    case["notes"] = [dict(n) for n in notes]
    return case


# ── Routes ───────────────────────────────────────────────────────────────────

@router.get("/")
def list_cases(status: Optional[str] = None, assigned_to: Optional[str] = None,
               limit: int = 200, offset: int = 0):
    conn = get_connection()
    try:
        sql = "SELECT * FROM cases WHERE 1=1"
        params = []
        if status:
            sql += " AND status = %s"
            params.append(status)
        if assigned_to:
            sql += " AND assigned_to = %s"
            params.append(assigned_to)
        sql += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@router.get("/{case_id}")
def get_case(case_id: int):
    conn = get_connection()
    try:
        return _with_notes(conn, _case_or_404(conn, case_id))
    finally:
        conn.close()


@router.post("/", status_code=201)
def create_case(body: CaseCreate, actor=Depends(require_read_access)):
    now = _now()
    assigned_to = actor.email if body.assign_to_self else None
    conn = get_connection()
    try:
        cur = conn.execute(
            "INSERT INTO cases "
            "(title, status, assigned_to, created_by, alert_id, alert_rule_id, "
            " alert_description, alert_agent_name, alert_timestamp, created_at, updated_at) "
            "VALUES (%s, 'open', %s, %s, %s, %s, %s, %s, %s, %s, %s) "
            "RETURNING id",
            (body.title, assigned_to, actor.email, body.alert_id, body.alert_rule_id,
             body.alert_description, body.alert_agent_name, body.alert_timestamp, now, now),
        )
        case_id = cur.fetchone()[0]
        conn.commit()
        log_audit(actor, "create", "case", case_id, detail=body.title)
        return _with_notes(conn, _case_or_404(conn, case_id))
    finally:
        conn.close()


@router.put("/{case_id}")
def update_case(case_id: int, body: CaseUpdate, actor=Depends(require_read_access)):
    if body.status is not None and body.status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {sorted(VALID_STATUSES)}")
    if body.disposition is not None and body.disposition not in VALID_DISPOSITIONS:
        raise HTTPException(status_code=400, detail=f"disposition must be one of {sorted(VALID_DISPOSITIONS)}")

    conn = get_connection()
    try:
        case = _case_or_404(conn, case_id)
        title = body.title if body.title is not None else case["title"]
        status = body.status if body.status is not None else case["status"]
        disposition = body.disposition if body.disposition is not None else case["disposition"]
        closed_at = case["closed_at"]
        if status == "closed" and case["status"] != "closed":
            closed_at = _now()
        elif status != "closed":
            closed_at = None

        conn.execute(
            "UPDATE cases SET title=%s, status=%s, disposition=%s, closed_at=%s, updated_at=%s WHERE id=%s",
            (title, status, disposition, closed_at, _now(), case_id),
        )
        conn.commit()
        log_audit(actor, "update", "case", case_id, detail=f"status={status}")
        return _with_notes(conn, _case_or_404(conn, case_id))
    finally:
        conn.close()


@router.post("/{case_id}/assign")
def assign_case(case_id: int, body: AssignRequest, actor=Depends(require_read_access)):
    assignee = body.assignee or actor.email
    conn = get_connection()
    try:
        _case_or_404(conn, case_id)
        conn.execute(
            "UPDATE cases SET assigned_to=%s, updated_at=%s WHERE id=%s",
            (assignee, _now(), case_id),
        )
        conn.commit()
        log_audit(actor, "assign", "case", case_id, detail=f"assigned to {assignee}")
        return _with_notes(conn, _case_or_404(conn, case_id))
    finally:
        conn.close()


@router.post("/{case_id}/close")
def close_case(case_id: int, body: CloseRequest, actor=Depends(require_read_access)):
    if body.disposition not in VALID_DISPOSITIONS:
        raise HTTPException(status_code=400, detail=f"disposition must be one of {sorted(VALID_DISPOSITIONS)}")
    conn = get_connection()
    try:
        _case_or_404(conn, case_id)
        now = _now()
        conn.execute(
            "UPDATE cases SET status='closed', disposition=%s, closed_at=%s, updated_at=%s WHERE id=%s",
            (body.disposition, now, now, case_id),
        )
        conn.commit()
        log_audit(actor, "close", "case", case_id, detail=body.disposition)
        return _with_notes(conn, _case_or_404(conn, case_id))
    finally:
        conn.close()


@router.post("/{case_id}/notes", status_code=201)
def add_note(case_id: int, body: NoteCreate, actor=Depends(require_read_access)):
    if not body.note.strip():
        raise HTTPException(status_code=400, detail="note cannot be empty")
    conn = get_connection()
    try:
        _case_or_404(conn, case_id)
        now = _now()
        conn.execute(
            "INSERT INTO case_notes (case_id, author, note, created_at) VALUES (%s, %s, %s, %s)",
            (case_id, actor.email, body.note.strip(), now),
        )
        conn.execute("UPDATE cases SET updated_at=%s WHERE id=%s", (now, case_id))
        conn.commit()
        log_audit(actor, "add_note", "case", case_id)
        return _with_notes(conn, _case_or_404(conn, case_id))
    finally:
        conn.close()
