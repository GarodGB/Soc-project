"""Server-side session and role enforcement.

The platform shipped with a demo credential store and a frontend-only session
(``sessionStorage``), which means *any* authorisation decision made in the
browser could be bypassed with a direct API call. The AI workflow can edit
detections and write rule files to the Wazuh Manager, so it enforces its own
checks on the server.

What this adds: ``POST /api/auth/login`` now issues an opaque bearer token that
is stored server-side (in the ``sessions`` table — see
``database/migrations/009_sessions.sql``) alongside the user's email and role.
The AI routes resolve the caller from that token and refuse privileged actions
for roles that are not permitted.

Sessions are stored in Postgres, not process memory — the app can restart or
redeploy without silently logging everyone out (this used to be an in-memory
dict, which meant a "remember me" login lost its persistence on the very
first restart).
"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import HTTPException, Request

from app.database import get_connection

#: Sessions expire after this many seconds of wall-clock time.
SESSION_TTL_SECONDS = 12 * 60 * 60
#: A "remember me" login gets a longer-lived session instead of the default.
REMEMBER_SESSION_TTL_SECONDS = 30 * 24 * 60 * 60

# Roles, normalised to lowercase.
ROLE_ADMIN = "admin"
ROLE_ENGINEER = "engineer"
ROLE_ANALYST = "analyst"

#: Roles allowed to change an AI draft's state (edit / approve / reject / save).
REVIEW_ROLES = {ROLE_ADMIN, ROLE_ENGINEER}
#: Roles allowed to write rules to the Wazuh Manager.
DEPLOY_ROLES = {ROLE_ADMIN, ROLE_ENGINEER}


@dataclass(frozen=True)
class Actor:
    email: str
    role: str
    authenticated: bool = True

    @property
    def name(self) -> str:
        return self.email

    def may_review(self) -> bool:
        return self.authenticated and self.role in REVIEW_ROLES

    def may_deploy(self) -> bool:
        return self.authenticated and self.role in DEPLOY_ROLES

    def to_dict(self) -> dict:
        return {"user": self.email, "role": self.role,
                "authenticated": self.authenticated,
                "may_review": self.may_review(), "may_deploy": self.may_deploy()}


ANONYMOUS = Actor(email="", role="", authenticated=False)


class _SessionStore:
    def issue(self, email: str, role: str, ttl_seconds: int = SESSION_TTL_SECONDS) -> str:
        token = secrets.token_urlsafe(32)
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO sessions (token, email, role, expires_at, created_at) "
                "VALUES (%s, %s, %s, %s, %s)",
                (token, email, role, time.time() + ttl_seconds, datetime.now(timezone.utc).isoformat()),
            )
            conn.commit()
        finally:
            conn.close()
        return token

    def resolve(self, token: str) -> Actor | None:
        if not token:
            return None
        conn = get_connection()
        try:
            row = conn.execute(
                "SELECT email, role, expires_at FROM sessions WHERE token = %s", (token,)
            ).fetchone()
            if row is None:
                return None
            if time.time() > row["expires_at"]:
                conn.execute("DELETE FROM sessions WHERE token = %s", (token,))
                conn.commit()
                return None
            return Actor(email=row["email"], role=_normalize_role(row["role"]))
        finally:
            conn.close()

    def revoke(self, token: str) -> None:
        conn = get_connection()
        try:
            conn.execute("DELETE FROM sessions WHERE token = %s", (token,))
            conn.commit()
        finally:
            conn.close()

    def clear(self) -> None:
        conn = get_connection()
        try:
            conn.execute("DELETE FROM sessions")
            conn.commit()
        finally:
            conn.close()


_store = _SessionStore()


def _normalize_role(role: str) -> str:
    value = (role or "").strip().lower()
    if value in ("admin", "administrator"):
        return ROLE_ADMIN
    if value in ("engineer", "detection engineer", "detection_engineer"):
        return ROLE_ENGINEER
    return ROLE_ANALYST


def issue_session(email: str, role: str, remember: bool = False) -> str:
    ttl = REMEMBER_SESSION_TTL_SECONDS if remember else SESSION_TTL_SECONDS
    return _store.issue(email, role, ttl)


def revoke_session(token: str) -> None:
    _store.revoke(token)


def clear_sessions() -> None:
    """Test helper."""
    _store.clear()


def _bearer_token(request: Request) -> str:
    header = request.headers.get("authorization") or ""
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return (request.headers.get("x-absega-token") or "").strip()


def current_actor(request: Request) -> Actor:
    """Resolve the caller from their bearer token, or ANONYMOUS."""
    return _store.resolve(_bearer_token(request)) or ANONYMOUS


def require_actor(request: Request) -> Actor:
    actor = current_actor(request)
    if not actor.authenticated:
        raise HTTPException(
            status_code=401,
            detail="Sign in to use the AI Detection Recommendation workflow.",
        )
    return actor


def require_reviewer(request: Request) -> Actor:
    """Editing, approving, rejecting and saving require a reviewer role."""
    actor = require_actor(request)
    if not actor.may_review():
        raise HTTPException(
            status_code=403,
            detail=("This action requires the Detection Engineer or Administrator "
                    f"role; your account has the '{actor.role}' role."),
        )
    return actor


def require_admin(request: Request) -> Actor:
    """Only an Administrator — e.g. the audit log."""
    actor = require_actor(request)
    if actor.role != ROLE_ADMIN:
        raise HTTPException(
            status_code=403,
            detail=("This action requires the Administrator role; your "
                    f"account has the '{actor.role}' role."),
        )
    return actor


def require_deployer(request: Request) -> Actor:
    """Only a Detection Engineer or Administrator may deploy to Wazuh."""
    actor = require_actor(request)
    if not actor.may_deploy():
        raise HTTPException(
            status_code=403,
            detail=("Deploying to the Wazuh Manager requires the Detection "
                    f"Engineer or Administrator role; your account has the "
                    f"'{actor.role}' role."),
        )
    return actor


#: Roles allowed to create, edit, delete, or trigger actions anywhere in the
#: app. Analyst is read-only project-wide.
WRITE_ROLES = {ROLE_ADMIN, ROLE_ENGINEER}


def require_read_access(request: Request) -> Actor:
    """Every route requires a signed-in session — analysts included."""
    return require_actor(request)


def require_write_access(request: Request) -> Actor:
    """Creating, editing, deleting, or triggering an action requires Engineer
    or Administrator; Analyst is read-only everywhere."""
    actor = require_actor(request)
    if actor.role not in WRITE_ROLES:
        raise HTTPException(
            status_code=403,
            detail=("This action requires the Detection Engineer or "
                    f"Administrator role; your account has the '{actor.role}' "
                    "role, which is read-only."),
        )
    return actor
