from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

from app.routes import detections, telemetry, mitre, validation, auth, atomic

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

@app.get("/health")
def health():
    return {"status": "ok"}
