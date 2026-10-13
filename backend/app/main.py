"""
FastAPI Main Application Entry Point
Mounts all REST APIs, initializes DB schemas, and starts background schedulers.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os

from .core.config import settings
from .db.session import engine, Base
from .db import models  # ensure models are registered
from .services.scheduler_service import start_scheduler
from .services.monitoring_scheduler import init_monitoring_scheduler

# Include routers
from .api.scans import router as scans_router
from .api.assets import router as assets_router
from .api.findings import router as findings_router
from .api.cost import router as cost_router
from .api.reports import router as reports_router
from .api.settings_api import router as settings_router
from .api.monitoring_api import router as monitoring_router
from .api.compliance_api import router as compliance_router
from .api.remediation_api import router as remediation_router
from .api.ip_rotator_api import router as ip_rotator_router
from .api.diff_api import router as diff_router
from .api.custom_rules_api import router as custom_rules_router
from .api.auth_api import router as auth_router
from .api.ai_playbook_api import router as ai_playbook_router
from .api.copilot_api import router as copilot_router
from .services.auth_service import seed_default_users

# Initialize tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="External attack-surface management and vulnerability audit platform with financial cost-of-risk modeling."
)

# CORS Configuration for local React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    start_scheduler()
    init_monitoring_scheduler()
    seed_default_users()
    os.makedirs(settings.OUTPUT_DIR, exist_ok=True)
    os.makedirs(settings.PLUGINS_DIR, exist_ok=True)

@app.get("/api/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION
    }

# Mount sub-routers
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(auth_router, prefix="/api")
app.include_router(ai_playbook_router, prefix=settings.API_V1_STR)
app.include_router(ai_playbook_router, prefix="/api")
app.include_router(copilot_router, prefix=settings.API_V1_STR)
app.include_router(copilot_router, prefix="/api")
app.include_router(scans_router, prefix=settings.API_V1_STR)
app.include_router(assets_router, prefix=settings.API_V1_STR)
app.include_router(findings_router, prefix=settings.API_V1_STR)
app.include_router(cost_router, prefix=settings.API_V1_STR)
app.include_router(reports_router, prefix=settings.API_V1_STR)
app.include_router(settings_router, prefix=settings.API_V1_STR)
app.include_router(monitoring_router, prefix=settings.API_V1_STR)
app.include_router(compliance_router, prefix=settings.API_V1_STR)
app.include_router(remediation_router, prefix=settings.API_V1_STR)
app.include_router(ip_rotator_router, prefix=settings.API_V1_STR)
app.include_router(diff_router)
app.include_router(custom_rules_router, prefix=settings.API_V1_STR)
app.include_router(custom_rules_router)
# Mount at root for drop-in compatibility with /get-ip, /headers, /generate-ips, /rank-and-transfer
app.include_router(ip_rotator_router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
