from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.database import get_connection

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
    return {
        "success": True,
        "user":    req.email,
        "role":    entry[1],
        "message": f"Welcome back, {entry[1]}",
    }


@router.get("/users")
def list_users():
    """Return available demo accounts (email only — no passwords)."""
    return [{"email": e, "role": r} for e, (_, r) in VALID_USERS.items()]
