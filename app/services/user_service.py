"""Postgres-backed user accounts.

Replaces the old ``VALID_USERS`` dict in ``app/routes/auth.py`` (plaintext
passwords, in-process only) with hashed credentials in the ``users`` table
(see ``database/migrations/006_users.sql``).
"""
from __future__ import annotations

from datetime import datetime, timezone

import bcrypt

from app.database import get_connection

#: The 3 demo accounts the platform has always shipped with. Seeded once on
#: first boot (INSERT ... ON CONFLICT DO NOTHING) so a fresh checkout still
#: works out of the box; changing a password afterwards in the DB sticks.
_DEFAULT_ACCOUNTS = [
    ("admin@absega.local",    "absega123",  "admin",    "Admin"),
    ("analyst@absega.local",  "analyst123", "analyst",  "Analyst"),
    ("engineer@absega.local", "eng123",     "engineer", "Engineer"),
]


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        # Malformed/legacy hash — never let a bad row raise past a login attempt.
        return False


VALID_ROLES = ("admin", "engineer", "analyst")


def create_user(email: str, password: str, role: str, full_name: str | None = None) -> dict:
    """Admin-created account. Raises ValueError on a duplicate email."""
    now = datetime.now(timezone.utc).isoformat()
    conn = get_connection()
    try:
        existing = conn.execute(
            "SELECT id FROM users WHERE LOWER(email) = LOWER(%s)", (email,)
        ).fetchone()
        if existing:
            raise ValueError(f"An account with the email '{email}' already exists.")
        cur = conn.execute(
            "INSERT INTO users (email, password_hash, role, full_name, created_at, updated_at) "
            "VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
            (email, hash_password(password), role, full_name or email, now, now),
        )
        new_id = cur.fetchone()[0]
        conn.commit()
        return {"id": new_id, "email": email, "role": role, "full_name": full_name or email}
    finally:
        conn.close()


def get_user_by_email(email: str) -> dict | None:
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT id, email, password_hash, role, full_name, is_active "
            "FROM users WHERE LOWER(email) = LOWER(%s)",
            (email,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def seed_default_users() -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn = get_connection()
    try:
        for email, password, role, full_name in _DEFAULT_ACCOUNTS:
            conn.execute(
                "INSERT INTO users (email, password_hash, role, full_name, created_at, updated_at) "
                "VALUES (%s, %s, %s, %s, %s, %s) "
                "ON CONFLICT (email) DO NOTHING",
                (email, hash_password(password), role, full_name, now, now),
            )
        conn.commit()
    finally:
        conn.close()
