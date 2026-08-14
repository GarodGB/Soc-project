from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.services.auth_service import (
    current_actor,
    issue_session,
    revoke_session,
)

router = APIRouter()


class LoginRequest(BaseModel):
    email: str
    password: str


# Simple credential store — in production replace with hashed passwords in DB
VALID_USERS = {
    "admin@absega.local":    ("absega123",  "Admin"),
    "analyst@absega.local":  ("analyst123", "Analyst"),
    "engineer@absega.local": ("eng123",     "Engineer"),
}


@router.post("/login")
def login(req: LoginRequest):
    entry = VALID_USERS.get(req.email.lower())
    if not entry or entry[0] != req.password:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    # Issue a real server-side session token so the backend — not just the
    # browser — can enforce role checks on privileged actions.
    token = issue_session(req.email.lower(), entry[1])
    return {
        "success": True,
        "user":    req.email,
        "role":    entry[1],
        "full_name": entry[1],
        "access_token": token,
        "token_type": "bearer",
        "message": f"Welcome back, {entry[1]}",
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
    """Return available demo accounts (email only — no passwords)."""
    return [{"email": e, "role": r} for e, (_, r) in VALID_USERS.items()]
