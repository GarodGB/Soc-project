from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.services.audit_service import log_audit
from app.services.auth_service import (
    current_actor,
    issue_session,
    require_admin,
    revoke_session,
)
from app.services.user_service import VALID_ROLES, create_user, get_user_by_email, verify_password
from app.database import get_connection

router = APIRouter()


class LoginRequest(BaseModel):
    email: str
    password: str
    remember: bool = False


class CreateUserRequest(BaseModel):
    email: str
    password: str
    role: str
    full_name: Optional[str] = None


@router.post("/login")
def login(req: LoginRequest):
    user = get_user_by_email(req.email)
    if not user or not user["is_active"] or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    # Issue a real server-side session token so the backend — not just the
    # browser — can enforce role checks on privileged actions.
    token = issue_session(user["email"], user["role"], remember=req.remember)
    display_name = user["full_name"] or user["email"]
    return {
        "success": True,
        "user":    user["email"],
        "role":    user["role"],
        "full_name": display_name,
        "access_token": token,
        "token_type": "bearer",
        "message": f"Welcome back, {display_name}",
    }


@router.post("/logout")
def logout(request: Request):
    """Invalidate the caller's server-side session."""
    header = request.headers.get("authorization") or ""
    token = header[7:].strip() if header.lower().startswith("bearer ") else \
        (request.headers.get("x-absega-token") or "").strip()
    if token:
        revoke_session(token)
    return {"success": True}


@router.get("/me")
def whoami(request: Request):
    """Who the backend thinks the caller is, and what they may do."""
    return current_actor(request).to_dict()


@router.get("/users")
def list_users():
    """Return active accounts (no password hashes)."""
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT id, email, role, full_name, created_at FROM users "
            "WHERE is_active = true ORDER BY email"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@router.post("/users", status_code=201)
def create_user_route(req: CreateUserRequest, actor=Depends(require_admin)):
    """Admin-only: create a new account with a role."""
    email = req.email.strip().lower()
    if "@" not in email or "." not in email.split("@")[-1]:
        raise HTTPException(status_code=400, detail="Enter a valid email address.")
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters.")
    role = req.role.strip().lower()
    if role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Role must be one of {list(VALID_ROLES)}.")

    try:
        user = create_user(email, req.password, role, (req.full_name or "").strip() or None)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    log_audit(actor, "create", "user", user["id"], detail=f"{email} ({role})")
    return user
