from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import os
from dotenv import load_dotenv

# Safely load .env; ignore files with non-UTF-8 encodings that break parsing on Windows
try:
    load_dotenv()
except UnicodeDecodeError:
    pass

from app.routes import detections, telemetry, mitre, validation, auth, atomic, ai, research

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
app.include_router(research.router,    prefix="/api/research",   tags=["Research"])

# Serve the frontend HTML files from the project root
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..")


@app.get("/")
def serve_homepage():
    return FileResponse(os.path.join(FRONTEND_DIR, "homepage.html"))


@app.get("/homepage.html")
def serve_homepage_explicit():
    return FileResponse(os.path.join(FRONTEND_DIR, "homepage.html"))


@app.get("/login.html")
def serve_login():
    return FileResponse(os.path.join(FRONTEND_DIR, "login.html"))


@app.get("/frontend.html")
def serve_frontend():
    return FileResponse(os.path.join(FRONTEND_DIR, "frontend.html"))


@app.get("/absega-logo.png")
def serve_logo():
    return FileResponse(os.path.join(FRONTEND_DIR, "absega-logo.png"))


@app.get("/health")
def health():
    return {"status": "ok"}