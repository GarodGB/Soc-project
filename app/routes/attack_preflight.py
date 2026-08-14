"""
Additive route: pre-flight reachability check for the Attack Lab.

Lets the frontend test a DVWA target BEFORE launching the full attack run,
so a dead/unreachable target shows a friendly diagnosis instead of a Python
traceback — and can be recorded as NOT_EXECUTED (never a telemetry gap).

Mount in app/main.py alongside the other routers:
    from app.routes import attack_preflight
    app.include_router(attack_preflight.router, prefix="/api/wazuh", tags=["wazuh"])
"""

import asyncio
import json as _json
import os
import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.services.auth_service import require_write_access

router = APIRouter()

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_STATUS_RE = re.compile(r"ABSEGA_STATUS=(\{.*\})")


def _script_python() -> str:
    """Prefer the project venv interpreter (has requests/httpx); fall back to
    this server's interpreter, then a bare 'python' on PATH."""
    import sys
    for p in (os.path.join(_PROJECT_ROOT, ".venv", "Scripts", "python.exe"),
              os.path.join(_PROJECT_ROOT, ".venv", "bin", "python3")):
        if os.path.exists(p):
            return p
    return sys.executable or "python"


class _PreflightReq(BaseModel):
    target: str = "http://127.0.0.1/dvwa"
    timeout: int = 8
    insecure: bool = False


def _parse_status(text: str) -> dict | None:
    m = None
    for line in text.splitlines():
        hit = _STATUS_RE.search(line)
        if hit:
            m = hit  # keep the last one
    if not m:
        return None
    try:
        return _json.loads(m.group(1))
    except Exception:
        return None


@router.post("/preflight", dependencies=[Depends(require_write_access)])
async def preflight_target(req: _PreflightReq):
    """Return {reachable, status, reason} for a DVWA target without attacking."""
    if not req.target.startswith(("http://", "https://")):
        raise HTTPException(400, "Target must be an HTTP(S) URL")

    script = os.path.join(_PROJECT_ROOT, "attack_dvwa.py")
    if not os.path.exists(script):
        raise HTTPException(404, "attack_dvwa.py not found in project root")

    cmd = [_script_python(), script, "--target", req.target,
           "--preflight", "--timeout", str(req.timeout)]
    if req.insecure:
        cmd.append("--insecure")

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=_PROJECT_ROOT,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=req.timeout + 15)
    except asyncio.TimeoutError:
        proc.kill()
        return {"reachable": False, "status": "UNREACHABLE",
                "reason": "Pre-flight timed out — target did not respond."}

    text = stdout.decode("utf-8", errors="replace") + "\n" + stderr.decode("utf-8", errors="replace")
    status = _parse_status(text)
    if not status:
        return {"reachable": False, "status": "ERROR",
                "reason": (text[-400:] or "Unknown pre-flight error").strip()}

    return {
        "reachable": status.get("status") == "OK",
        "status": status.get("status"),
        "reason": status.get("reason", ""),
    }
