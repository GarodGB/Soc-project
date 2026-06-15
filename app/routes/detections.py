from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional
from app.database import get_connection

router = APIRouter()


# ── Models ────────────────────────────────────────────────────────────────────

class Detection(BaseModel):
    id: Optional[str] = None          # auto-assigned on create if omitted
    title: str
    description: Optional[str] = None
    severity: str                      # critical / high / medium / low / informational
    status: str                        # stable / test / experimental
    category: Optional[str] = "windows"   # windows / linux / identity  (maps to platform)
    author: Optional[str] = None
    false_positives: Optional[str] = None  # maps to falsepositives
    rule_path: Optional[str] = None        # stored as-is (not in original schema; ignored)
    sigma_rule: Optional[str] = None       # maps to raw_yaml
    tags: Optional[str] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _row_to_dict(row) -> dict:
    """Map DB column names → frontend-expected field names."""
    d = dict(row)
    return {
        "id":             str(d.get("detection_id", "")),
        "title":          d.get("title", ""),
        "description":    d.get("description", ""),
        "severity":       d.get("severity", "medium"),
        "status":         d.get("status", "test"),
        "category":       d.get("platform", "windows") or "windows",
        "author":         d.get("author", ""),
        "false_positives": d.get("falsepositives", ""),
        "sigma_rule":     d.get("raw_yaml", ""),
        "tags":           d.get("tags", ""),
        "rule_logic":     d.get("rule_logic", ""),
        "logsource":      d.get("logsource", ""),
        "sigma_id":       d.get("sigma_id", ""),
        "modified":       d.get("modified", ""),
        "reference_urls": d.get("reference_urls", ""),
        "created_at":     d.get("created_at", ""),
        "updated_at":     d.get("updated_at", ""),
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/")
def get_detections(
    status:   Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    platform: Optional[str] = Query(None),
    search:   Optional[str] = Query(None),
    limit:    int            = Query(5000, le=50000),
    offset:   int            = Query(0),
):
    """Return all detections with optional filtering."""
    conn = get_connection()
    try:
        sql    = "SELECT * FROM detections WHERE 1=1"
        params = []
        if status:
            sql += " AND status = ?"
            params.append(status)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if platform:
            sql += " AND platform = ?"
            params.append(platform)
        if search:
            sql += " AND (title LIKE ? OR tags LIKE ? OR author LIKE ?)"
            like = f"%{search}%"
            params.extend([like, like, like])
        sql += " LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = conn.execute(sql, params).fetchall()
        return [_row_to_dict(r) for r in rows]
    finally:
        conn.close()


@router.get("/stats")
def get_detection_stats():
    """Summary counts used by the overview/dashboard panel."""
    conn = get_connection()
    try:
        total    = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
        by_sev   = {r[0]: r[1] for r in conn.execute(
            "SELECT severity, COUNT(*) FROM detections GROUP BY severity").fetchall()}
        by_stat  = {r[0]: r[1] for r in conn.execute(
            "SELECT status, COUNT(*) FROM detections GROUP BY status").fetchall()}
        by_plat  = {r[0]: r[1] for r in conn.execute(
            "SELECT platform, COUNT(*) FROM detections GROUP BY platform").fetchall()}
        return {
            "total":       total,
            "by_severity": by_sev,
            "by_status":   by_stat,
            "by_platform": by_plat,
        }
    finally:
        conn.close()


@router.get("/{detection_id}")
def get_detection(detection_id: str):
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM detections WHERE detection_id = ?", (detection_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Detection not found")
        return _row_to_dict(row)
    finally:
        conn.close()


@router.post("/", status_code=201)
def create_detection(detection: Detection):
    conn = get_connection()
    try:
        conn.execute("""
            INSERT INTO detections
              (title, description, severity, status, platform,
               author, falsepositives, raw_yaml, tags, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """, (
            detection.title,
            detection.description or "",
            detection.severity,
            detection.status,
            detection.category or "windows",
            detection.author or "",
            detection.false_positives or "",
            detection.sigma_rule or "",
            detection.tags or "",
        ))
        conn.commit()
        new_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        return {"message": "Detection created successfully", "id": new_id}
    finally:
        conn.close()


@router.put("/{detection_id}")
def update_detection(detection_id: str, detection: Detection):
    conn = get_connection()
    try:
        cur = conn.execute(
            "SELECT detection_id FROM detections WHERE detection_id = ?", (detection_id,)
        )
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="Detection not found")

        conn.execute("""
            UPDATE detections SET
              title=?, description=?, severity=?, status=?, platform=?,
              author=?, falsepositives=?, raw_yaml=?, tags=?,
              updated_at=datetime('now')
            WHERE detection_id=?
        """, (
            detection.title,
            detection.description or "",
            detection.severity,
            detection.status,
            detection.category or "windows",
            detection.author or "",
            detection.false_positives or "",
            detection.sigma_rule or "",
            detection.tags or "",
            detection_id,
        ))
        conn.commit()
        return {"message": "Detection updated successfully"}
    finally:
        conn.close()


@router.delete("/{detection_id}")
def delete_detection(detection_id: str):
    conn = get_connection()
    try:
        cur = conn.execute(
            "SELECT detection_id FROM detections WHERE detection_id = ?", (detection_id,)
        )
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="Detection not found")

        # Remove child rows first (FK-like cleanup)
        conn.execute("DELETE FROM detection_technique_mapping WHERE detection_id = ?", (detection_id,))
        conn.execute("DELETE FROM detection_telemetry WHERE detection_id = ?", (detection_id,))
        conn.execute("DELETE FROM validation_cases WHERE detection_id = ?", (detection_id,))
        conn.execute("DELETE FROM detections WHERE detection_id = ?", (detection_id,))
        conn.commit()
        return {"message": "Detection deleted successfully"}
    finally:
        conn.close()


# ── Technique mappings (bonus) ─────────────────────────────────────────────────

@router.get("/{detection_id}/techniques")
def get_detection_techniques(detection_id: str):
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT mt.technique_id, mt.name, mt.tactic, mt.description, mt.url
            FROM detection_technique_mapping dtm
            JOIN mitre_techniques mt ON dtm.technique_id = mt.technique_id
            WHERE dtm.detection_id = ?
        """, (detection_id,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()