"""
AI Remediation Playbook REST API
Endpoints for generating autonomous code patches, analytical playbooks,
and downloading the Pro Edition Patch Playbook PDF.
Role-gated to Pro users with standard tier paywall enforcement.
"""
from fastapi import APIRouter, Depends, HTTPException, Response, Query, Header
from sqlalchemy.orm import Session
from typing import Optional, Dict, Any

from ..db.session import get_db
from ..db.models import Scan, Finding, Asset, User
from ..services.auth_service import get_current_user_optional, require_pro_user
from ..services.ai_remediation_service import (
    build_complete_scan_ai_playbook,
    generate_ai_remediation_for_finding
)
from ..services.ai_patch_playbook_pdf import generate_ai_patch_playbook_pdf

router = APIRouter(prefix="/scans", tags=["AI Remediation Playbook"])

@router.get("/{scan_id}/ai-playbook")
async def get_ai_playbook(
    scan_id: str,
    authorization: Optional[str] = Header(None),
    role: Optional[str] = Query(None),
    token: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Fetches the full Autonomous AI Remediation Playbook with code diffs and CLI commands.
    Requires Pro Tier user account.
    Standard users receive 403 Forbidden with upgrade prompt.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    user = get_current_user_optional(authorization=authorization, role=role, token=token, db=db)
    
    # Check subscription tier
    if not user or user.role not in ("pro", "admin"):
        # Return 403 with detailed subscription requirement
        raise HTTPException(
            status_code=403,
            detail={
                "error": "PRO_SUBSCRIPTION_REQUIRED",
                "message": "Autonomous AI Remediation Playbooks and executable patches require an active Pro subscription.",
                "user_role": user.role if user else "unauthenticated",
                "target_domain": scan.target_domain,
                "total_findings": len(scan.findings),
                "upgrade_path": "/upgrade"
            }
        )

    # User is Pro: Build complete playbook
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).order_by(Finding.risk_score.desc()).all()
    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()

    playbook_data = await build_complete_scan_ai_playbook(scan, findings, assets)
    return playbook_data


@router.get("/{scan_id}/ai-playbook/preview")
def get_playbook_preview(
    scan_id: str,
    db: Session = Depends(get_db)
):
    """
    Public / Standard preview summarizing available patches, ROI, and sample code teaser
    to incentivize Pro subscription upgrade.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    crit_count = sum(1 for f in findings if f.severity == "Critical")
    high_count = sum(1 for f in findings if f.severity == "High")
    med_count = sum(1 for f in findings if f.severity == "Medium")

    return {
        "scan_id": scan_id,
        "domain": scan.target_domain,
        "pro_locked": True,
        "total_available_patches": len(findings),
        "critical_patches": crit_count,
        "high_patches": high_count,
        "medium_patches": med_count,
        "features_unlocked_with_pro": [
            "Autonomous unified git-diff generation for Nginx, Apache, and Application code",
            "Copy-paste bash CLI deployment commands",
            "Zero-trust curl verification test suites",
            "Emergency 1-click rollback procedures",
            "Publication-grade Analytical Patch Playbook PDF export"
        ],
        "sample_teaser_patch": {
            "title": "Missing Security Headers & Transport Hardening",
            "affected_component": "Nginx / Reverse Proxy",
            "diff_preview": "@@ -12,4 +12,10 @@\n+ add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains\" always;\n+ add_header X-Frame-Options \"SAMEORIGIN\" always;...",
            "unlock_message": "Subscribe to Pro to unlock all 100% executable patches and download the official PDF blueprint."
        }
    }


@router.get("/{scan_id}/ai-playbook/pdf")
async def download_ai_playbook_pdf(
    scan_id: str,
    authorization: Optional[str] = Header(None),
    role: Optional[str] = Query(None),
    token: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Generates and downloads the analytical Patch Playbook PDF.
    Exclusively permitted for Pro users.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    user = get_current_user_optional(authorization=authorization, role=role, token=token, db=db)
    if not user or user.role not in ("pro", "admin"):
        raise HTTPException(
            status_code=403,
            detail={
                "error": "PRO_SUBSCRIPTION_REQUIRED",
                "message": "Downloading the Analytical AI Patch Playbook PDF requires a Pro subscription.",
                "user_role": user.role if user else "unauthenticated"
            }
        )

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).order_by(Finding.risk_score.desc()).all()
    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()

    playbook_data = await build_complete_scan_ai_playbook(scan, findings, assets)

    meta = {
        "id": scan.id,
        "target_domain": scan.target_domain,
        "company_name": scan.company_name or scan.target_domain,
        "mode": scan.mode,
        "risk_score": scan.risk_score
    }

    pdf_bytes = generate_ai_patch_playbook_pdf(meta, playbook_data)
    filename = f"AI_Patch_Playbook_{scan.target_domain}_{scan.id[:8]}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
