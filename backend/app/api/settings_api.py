"""
Settings & Audit Logs API Router
Manages API key configurations with 'missing key' UI indicators,
plugin registry, and audit logging.
"""
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from ..core.config import settings
from ..db.session import get_db
from ..db.models import AuditLog
from ..recon.adapter.plugin_loader import discover_plugins

router = APIRouter(tags=["Settings & Scope"])

class KeyUpdatePayload(BaseModel):
    key_name: str
    key_value: str

@router.get("/settings")
def get_system_settings():
    """
    Returns API key configuration state (masked) and active operational defaults.
    """
    def _key_status(val):
        if not val or val.strip() == "":
            return {"configured": False, "masked": "Not configured"}
        v = val.strip()
        masked = v[:4] + "*" * (max(0, len(v) - 8)) + v[-4:] if len(v) >= 8 else "***"
        return {"configured": True, "masked": masked}

    return {
        "api_keys": {
            "SHODAN_KEY": _key_status(settings.SHODAN_KEY),
            "SECURITYTRAILS_KEY": _key_status(settings.SECURITYTRAILS_KEY),
            "OTX_KEY": _key_status(settings.OTX_KEY),
            "VIRUSTOTAL_KEY": _key_status(settings.VIRUSTOTAL_KEY),
            "URLSCAN_KEY": _key_status(settings.URLSCAN_KEY),
            "NVD_KEY": _key_status(settings.NVD_KEY),
        },
        "rates": {
            "dev_rate": settings.DEFAULT_DEV_HOURLY_RATE,
            "tester_rate": settings.DEFAULT_TESTER_HOURLY_RATE,
            "currency": settings.DEFAULT_CURRENCY,
            "asset_value": settings.DEFAULT_ASSET_VALUE,
            "records_count": settings.DEFAULT_RECORDS_COUNT
        }
    }

@router.post("/settings/key")
def update_api_key(payload: KeyUpdatePayload):
    key_name = payload.key_name.upper().strip()
    key_val = payload.key_value.strip()

    valid_keys = [
        "SHODAN_KEY", "SECURITYTRAILS_KEY", "OTX_KEY", "VIRUSTOTAL_KEY",
        "URLSCAN_KEY", "NVD_KEY"
    ]
    if key_name not in valid_keys:
        raise HTTPException(status_code=400, detail=f"Invalid key name. Must be one of: {valid_keys}")

    setattr(settings, key_name, key_val)
    return {"message": f"Successfully updated {key_name} in memory."}

@router.get("/plugins")
def list_loaded_plugins():
    """
    Returns list of discovered drop-in plugins from plugins/ directory.
    """
    return discover_plugins()

@router.get("/audit-logs")
def get_audit_logs(
    limit: int = 50,
    db: Session = Depends(get_db)
):
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": l.id,
            "scan_id": l.scan_id,
            "action": l.action,
            "target": l.target,
            "details": l.details,
            "status_code": l.status_code,
            "timestamp": l.timestamp.isoformat() if l.timestamp else None
        }
        for l in logs
    ]
