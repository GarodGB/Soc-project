"""Audit trail for consequential platform actions.

Records who did what to which resource — approve/reject/deploy/save/delete —
so those actions carry real accountability. See
``database/migrations/007_audit_log.sql``.

Logging a failure here must never break the request it's attached to: a
missed audit row is bad, but turning every write into a 500 because the
audit insert failed would be worse.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from app.database import get_connection

logger = logging.getLogger(__name__)


def log_audit(actor, action: str, target_type: str, target_id=None, detail: str = None) -> None:
    """Record one audit entry. ``actor`` is an ``auth_service.Actor``."""
    try:
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO audit_log (actor_email, actor_role, action, target_type, target_id, detail, created_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (
                    actor.email, actor.role, action, target_type,
                    str(target_id) if target_id is not None else None,
                    detail, datetime.now(timezone.utc).isoformat(),
                ),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception:
        logger.exception("audit log insert failed (action=%s target=%s/%s)", action, target_type, target_id)
