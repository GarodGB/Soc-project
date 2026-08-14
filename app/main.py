from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os
from dotenv import load_dotenv

# Safely load .env; ignore files with non-UTF-8 encodings that break parsing on Windows
try:
    load_dotenv()
except UnicodeDecodeError:
    # If the .env file uses a different encoding (e.g. UTF-16), skip loading it.
    pass

from app.db_migrate import run_migrations

# Additive, idempotent schema migrations (creates the AI rule suggestion tables
# on first boot; a no-op on every boot after that).
run_migrations()

from app.routes import detections, telemetry, mitre, validation, auth, atomic, ai, wazuh
from app.routes import attack_preflight
from app.routes import ad_validation, ad_catalog
from app.routes import validation_runs
from app.routes import ai_rules

app = FastAPI(
    title="ABSEGA Detection Platform",
    description="Internal platform for detection engineering and telemetry validation",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routers
app.include_router(auth.router,        prefix="/api/auth",       tags=["Auth"])
app.include_router(detections.router,  prefix="/api/detections", tags=["Detections"])
app.include_router(telemetry.router,   prefix="/api/telemetry",  tags=["Telemetry"])
app.include_router(mitre.router,       prefix="/api/mitre",      tags=["MITRE ATT&CK"])
app.include_router(validation.router,  prefix="/api/validation", tags=["Validation"])
app.include_router(atomic.router,      prefix="/api/atomic",     tags=["Atomic Red Team"])
app.include_router(ai.router,          prefix="/api/ai",         tags=["AI Features"])
app.include_router(ai_rules.router,    prefix="/api/ai",         tags=["AI Rule Recommendations"])
app.include_router(wazuh.router,       prefix="/api/wazuh",      tags=["Wazuh"])
app.include_router(attack_preflight.router, prefix="/api/wazuh", tags=["Wazuh"])
app.include_router(validation_runs.router, prefix="/api/validation-runs", tags=["Validation Runs"])

# AD / Windows validation routers (self-prefixed)
app.include_router(ad_validation.router)
app.include_router(ad_catalog.router)

# Serve the frontend HTML files from the project root
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..")

# Plain FileResponse sends no Cache-Control header, so browsers fall back to
# heuristic caching (roughly 10% of the file's age) and will keep serving a
# stale copy of these pages after a normal navigation/redirect — a server
# restart doesn't change the file's mtime, so only a hard refresh (which
# bypasses the cache outright) picks up an edit. no-cache forces revalidation
# on every load while still allowing a cheap 304 when nothing changed.
_NO_CACHE_HEADERS = {"Cache-Control": "no-cache"}


def _serve(filename: str, media_type: str | None = None) -> FileResponse:
    return FileResponse(os.path.join(FRONTEND_DIR, filename),
                        media_type=media_type, headers=_NO_CACHE_HEADERS)


@app.get("/")
def serve_homepage():
    return _serve("homepage.html")

@app.get("/homepage.html")
def serve_homepage_explicit():
    return _serve("homepage.html")

@app.get("/login.html")
def serve_login():
    return _serve("login.html")

@app.get("/frontend.html")
def serve_frontend():
    return _serve("frontend.html")

@app.get("/absega-logo.png")
def serve_logo():
    return _serve("absega-logo.png")

@app.get("/ai_panel.js", include_in_schema=False)
def serve_ai_panel():
    """Reusable AI Detection Recommendation panel shared by all four surfaces."""
    return _serve("ai_panel.js", media_type="application/javascript")

@app.get("/auth_guard.js", include_in_schema=False)
def serve_auth_guard():
    """Login redirect + bearer-token fetch patch + role gating, shared by every dashboard page."""
    return _serve("auth_guard.js", media_type="application/javascript")

@app.get("/guide.html")
def serve_guide():
    return _serve("guide.html")

@app.get("/ad_dashboard.html", include_in_schema=False)
def serve_ad_dashboard():
    return _serve("ad_dashboard.html")

@app.get("/health")
def health():
    return {"status": "ok"}
