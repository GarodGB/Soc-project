from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from app.database import get_connection

router = APIRouter()


# ── Models ────────────────────────────────────────────────────────────────────

class TelemetrySource(BaseModel):
    name:        str
    platform:    Optional[str] = None   # stored in category column
    description: Optional[str] = None  # not in schema, stored as coverage
    status:      str = "healthy"        # healthy / degraded / missing  (DB uses active)
    event_rate:  Optional[str] = None   # not in schema, stored for display
    coverage:    Optional[str] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

# Map frontend status terms ↔ DB values
_TO_DB   = {"healthy": "active", "degraded": "degraded", "missing": "inactive"}
_FROM_DB = {"active": "healthy", "degraded": "degraded", "inactive": "missing"}


def _row_to_dict(row) -> dict:
    d = dict(row)
    db_status = d.get("status", "active")
    return {
        "id":          d.get("source_id"),
        "name":        d.get("name", ""),
        "platform":    d.get("category", ""),      # category → platform
        "description": d.get("coverage", ""),      # coverage → description/coverage
        "status":      _FROM_DB.get(db_status, "healthy"),
        "event_rate":  d.get("event_rate", None),  # column may not exist — handled below
        "coverage":    d.get("coverage", ""),
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/")
def get_telemetry():
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM telemetry_sources").fetchall()
        return [_row_to_dict(r) for r in rows]
    finally:
        conn.close()


@router.get("/stats")
def get_telemetry_stats():
    conn = get_connection()
    try:
        total   = conn.execute("SELECT COUNT(*) FROM telemetry_sources").fetchone()[0]
        healthy = conn.execute(
            "SELECT COUNT(*) FROM telemetry_sources WHERE status = 'active'"
        ).fetchone()[0]
        return {"total": total, "healthy": healthy, "issues": total - healthy}
    finally:
        conn.close()


@router.get("/{telemetry_id}")
def get_telemetry_source(telemetry_id: int):
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM telemetry_sources WHERE source_id = ?", (telemetry_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Telemetry source not found")
        return _row_to_dict(row)
    finally:
        conn.close()


@router.post("/", status_code=201)
def create_telemetry(source: TelemetrySource):
    conn = get_connection()
    try:
        db_status = _TO_DB.get(source.status, "active")
        # event_rate column might not exist — add it if missing
        cols = {r[1] for r in conn.execute("PRAGMA table_info(telemetry_sources)").fetchall()}
        if "event_rate" not in cols:
            conn.execute("ALTER TABLE telemetry_sources ADD COLUMN event_rate TEXT")

        conn.execute("""
            INSERT INTO telemetry_sources (name, category, status, coverage, event_rate)
            VALUES (?, ?, ?, ?, ?)
        """, (
            source.name,
            source.platform or "",
            db_status,
            source.coverage or source.description or "",
            source.event_rate or "",
        ))
        conn.commit()
        new_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        return {"message": "Telemetry source created successfully", "id": new_id}
    finally:
        conn.close()


@router.put("/{telemetry_id}")
def update_telemetry(telemetry_id: int, source: TelemetrySource):
    conn = get_connection()
    try:
        if not conn.execute(
            "SELECT source_id FROM telemetry_sources WHERE source_id = ?", (telemetry_id,)
        ).fetchone():
            raise HTTPException(status_code=404, detail="Telemetry source not found")

        db_status = _TO_DB.get(source.status, "active")
        cols = {r[1] for r in conn.execute("PRAGMA table_info(telemetry_sources)").fetchall()}
        if "event_rate" not in cols:
            conn.execute("ALTER TABLE telemetry_sources ADD COLUMN event_rate TEXT")

        conn.execute("""
            UPDATE telemetry_sources SET
              name=?, category=?, status=?, coverage=?, event_rate=?
            WHERE source_id=?
        """, (
            source.name,
            source.platform or "",
            db_status,
            source.coverage or source.description or "",
            source.event_rate or "",
            telemetry_id,
        ))
        conn.commit()
        return {"message": "Telemetry source updated successfully"}
    finally:
        conn.close()


@router.delete("/{telemetry_id}")
def delete_telemetry(telemetry_id: int):
    conn = get_connection()
    try:
        if not conn.execute(
            "SELECT source_id FROM telemetry_sources WHERE source_id = ?", (telemetry_id,)
        ).fetchone():
            raise HTTPException(status_code=404, detail="Telemetry source not found")

        conn.execute("DELETE FROM detection_telemetry WHERE source_id = ?", (telemetry_id,))
        conn.execute("DELETE FROM telemetry_sources WHERE source_id = ?", (telemetry_id,))
        conn.commit()
        return {"message": "Telemetry source deleted successfully"}
    finally:
        conn.close()
