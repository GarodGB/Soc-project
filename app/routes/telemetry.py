from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from app.database import get_connection
from app.services.auth_service import require_read_access, require_write_access
from app.services.audit_service import log_audit
from app.wazuh_client import telemetry_live_status

router = APIRouter(dependencies=[Depends(require_read_access)])

# Categories backed by a real Wazuh event stream we can check the indexer for.
# Identity-provider sources (Okta, Azure AD, ...) aren't wired into this Wazuh
# deployment, so their status stays whatever was manually set.
_LIVE_CATEGORIES = {"windows_endpoint", "linux_endpoint"}


def _derive_live_status(count: int, last_seen: Optional[str]) -> tuple[str, str]:
    """Turn a 24h indexer count into (db_status, human event-rate string)."""
    if count == 0:
        return "inactive", "No events in last 24h"
    if count < 5:
        suffix = f" — last seen {last_seen}" if last_seen else ""
        return "degraded", f"{count} events / 24h (unusually thin){suffix}"
    suffix = f" · last seen {last_seen}" if last_seen else ""
    return "active", f"{count} events / 24h{suffix}"


def _apply_live_status(items: list) -> list:
    try:
        live = telemetry_live_status()
    except Exception:
        live = None
    if not live:
        return items
    for item in items:
        if item.get("platform") not in _LIVE_CATEGORIES:
            continue
        info = live.get(item.get("name"))
        if info is None:
            continue
        item["status"], item["event_rate"] = _derive_live_status(info["count"], info["last_seen"])
        item["live"] = True
    return items


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
    import json as _json
    details_raw = d.get("details", None)
    details = None
    if details_raw:
        try:
            details = _json.loads(details_raw)
        except Exception:
            details = None
    return {
        "id":          d.get("source_id"),
        "name":        d.get("name", ""),
        "platform":    d.get("category", ""),
        "description": d.get("coverage", ""),
        "status":      _FROM_DB.get(db_status, "healthy"),
        "event_rate":  d.get("event_rate", None),
        "coverage":    d.get("coverage", ""),
        "details":     details,
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/")
def get_telemetry():
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM telemetry_sources").fetchall()
        items = [_row_to_dict(r) for r in rows]
    finally:
        conn.close()
    return _apply_live_status(items)


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
            "SELECT * FROM telemetry_sources WHERE source_id = %s", (telemetry_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Telemetry source not found")
        return _apply_live_status([_row_to_dict(row)])[0]
    finally:
        conn.close()


@router.post("/", status_code=201)
def create_telemetry(source: TelemetrySource, actor=Depends(require_write_access)):
    conn = get_connection()
    try:
        db_status = _TO_DB.get(source.status, "active")
        # event_rate/coverage columns might not exist — add them if missing
        cols = {r[0] for r in conn.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name = 'telemetry_sources'"
        ).fetchall()}
        if "event_rate" not in cols:
            conn.execute("ALTER TABLE telemetry_sources ADD COLUMN event_rate TEXT")
        if "coverage" not in cols:
            conn.execute("ALTER TABLE telemetry_sources ADD COLUMN coverage TEXT")

        cur = conn.execute("""
            INSERT INTO telemetry_sources (name, category, status, coverage, event_rate)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING source_id
        """, (
            source.name,
            source.platform or "",
            db_status,
            source.coverage or source.description or "",
            source.event_rate or "",
        ))
        new_id = cur.fetchone()[0]
        conn.commit()
        log_audit(actor, "create", "telemetry_source", new_id, detail=source.name)
        return {"message": "Telemetry source created successfully", "id": new_id}
    finally:
        conn.close()


@router.put("/{telemetry_id}")
def update_telemetry(telemetry_id: int, source: TelemetrySource, actor=Depends(require_write_access)):
    conn = get_connection()
    try:
        if not conn.execute(
            "SELECT source_id FROM telemetry_sources WHERE source_id = %s", (telemetry_id,)
        ).fetchone():
            raise HTTPException(status_code=404, detail="Telemetry source not found")

        db_status = _TO_DB.get(source.status, "active")
        cols = {r[0] for r in conn.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name = 'telemetry_sources'"
        ).fetchall()}
        if "event_rate" not in cols:
            conn.execute("ALTER TABLE telemetry_sources ADD COLUMN event_rate TEXT")
        if "coverage" not in cols:
            conn.execute("ALTER TABLE telemetry_sources ADD COLUMN coverage TEXT")

        conn.execute("""
            UPDATE telemetry_sources SET
              name=%s, category=%s, status=%s, coverage=%s, event_rate=%s
            WHERE source_id=%s
        """, (
            source.name,
            source.platform or "",
            db_status,
            source.coverage or source.description or "",
            source.event_rate or "",
            telemetry_id,
        ))
        conn.commit()
        log_audit(actor, "update", "telemetry_source", telemetry_id, detail=source.name)
        return {"message": "Telemetry source updated successfully"}
    finally:
        conn.close()


@router.delete("/{telemetry_id}")
def delete_telemetry(telemetry_id: int, actor=Depends(require_write_access)):
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT source_id, name FROM telemetry_sources WHERE source_id = %s", (telemetry_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Telemetry source not found")

        conn.execute("DELETE FROM detection_telemetry WHERE source_id = %s", (telemetry_id,))
        conn.execute("DELETE FROM telemetry_sources WHERE source_id = %s", (telemetry_id,))
        conn.commit()
        log_audit(actor, "delete", "telemetry_source", telemetry_id, detail=dict(row).get("name"))
        return {"message": "Telemetry source deleted successfully"}
    finally:
        conn.close()