from fastapi import APIRouter, HTTPException
from app.database import get_connection

router = APIRouter()


@router.get("/")
def list_suggestions():
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT *
            FROM detection_suggestions
            ORDER BY created_at DESC
            LIMIT 200
        """).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@router.post("/")
def create_suggestion(payload: dict):
    conn = get_connection()
    try:
        conn.execute("""
            INSERT INTO detection_suggestions
              (technique_id, title, reason, suggested_sigma,
               required_telemetry, priority, status)
            VALUES (?, ?, ?, ?, ?, ?, 'open')
        """, (
            payload.get("technique_id", ""),
            payload.get("title", "Untitled suggestion"),
            payload.get("reason", ""),
            payload.get("suggested_sigma", ""),
            payload.get("required_telemetry", ""),
            payload.get("priority", "medium"),
        ))
        conn.commit()
        new_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        return {"message": "Suggestion created", "suggestion_id": new_id}
    finally:
        conn.close()


@router.post("/{suggestion_id}/approve")
def approve_suggestion(suggestion_id: int):
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM detection_suggestions WHERE suggestion_id = ?",
            (suggestion_id,)
        ).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Suggestion not found")

        s = dict(row)

        conn.execute("""
            INSERT INTO detections
              (title, description, severity, status, platform,
               author, falsepositives, raw_yaml, tags, updated_at)
            VALUES (?, ?, ?, 'testing', 'windows',
                    'AI Assistant', '', ?, ?, datetime('now'))
        """, (
            s.get("title", "AI Suggested Detection"),
            s.get("reason", ""),
            s.get("priority", "medium"),
            s.get("suggested_sigma", ""),
            s.get("technique_id", ""),
        ))

        detection_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        if s.get("technique_id"):
            conn.execute("""
                INSERT INTO detection_technique_mapping
                  (detection_id, technique_id)
                VALUES (?, ?)
            """, (detection_id, s["technique_id"]))

        conn.execute("""
            UPDATE detection_suggestions
            SET status = 'approved'
            WHERE suggestion_id = ?
        """, (suggestion_id,))

        conn.commit()

        return {
            "message": "Suggestion approved and saved as testing detection",
            "detection_id": detection_id
        }
    finally:
        conn.close()


@router.post("/{suggestion_id}/reject")
def reject_suggestion(suggestion_id: int):
    conn = get_connection()
    try:
        conn.execute("""
            UPDATE detection_suggestions
            SET status = 'rejected'
            WHERE suggestion_id = ?
        """, (suggestion_id,))
        conn.commit()
        return {"message": "Suggestion rejected"}
    finally:
        conn.close()
