from fastapi import APIRouter, Depends, Query

from app.database import get_connection
from app.services.auth_service import require_admin

router = APIRouter(dependencies=[Depends(require_admin)])


@router.get("/")
def list_audit_log(
    actor:       str = Query(None, description="Filter by actor email (exact match)"),
    action:      str = Query(None, description="Filter by action (exact match)"),
    target_type: str = Query(None, description="Filter by target type (exact match)"),
    limit:       int = Query(100, le=1000),
    offset:      int = Query(0),
):
    """Admin-only: who did what to which resource, most recent first."""
    conn = get_connection()
    try:
        sql = "SELECT * FROM audit_log WHERE 1=1"
        params = []
        if actor:
            sql += " AND actor_email = %s"
            params.append(actor)
        if action:
            sql += " AND action = %s"
            params.append(action)
        if target_type:
            sql += " AND target_type = %s"
            params.append(target_type)
        sql += " ORDER BY id DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])

        rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
        total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        return {"items": rows, "total": total}
    finally:
        conn.close()
