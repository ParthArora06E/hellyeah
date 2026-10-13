"""
Remediation Patches, 'Verify Fix' Re-Tests, Issue Tracker Sync & SBOM API Router
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from ..db.session import get_db
from ..db.models import Finding
from ..remediation.patch_generator import generate_remediation_patch
from ..remediation.verifier import verify_finding_fix
from ..integrations.issue_tracker import sync_finding_to_issue_tracker
from ..vuln.sbom_engine import generate_sbom_for_scan, export_cyclonedx_json, export_spdx_json

router = APIRouter(tags=["Remediation, Verify Fix & SBOM"])

@router.get("/findings/{finding_id}/remediation-patch")
def get_finding_remediation_patch(finding_id: int, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding_dict = {
        "id": finding.id,
        "title": finding.title,
        "description": finding.description,
        "cve_ids": finding.cve_ids or [],
        "fix_hours_dev": finding.fix_hours_dev or 3.0
    }
    return generate_remediation_patch(finding_dict)

@router.post("/findings/{finding_id}/verify-fix")
def run_verify_fix(finding_id: int, db: Session = Depends(get_db)):
    res = verify_finding_fix(finding_id, db, simulated_pass=True)
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("message", "Verification failed"))
    return res

@router.post("/findings/{finding_id}/sync-issue")
def sync_issue(
    finding_id: int,
    provider: str = Query(default="github"),
    target_repo: str = Query(default="company/security-backlog"),
    db: Session = Depends(get_db)
):
    res = sync_finding_to_issue_tracker(finding_id, provider, target_repo, db)
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error", "Sync failed"))
    return res

@router.get("/scans/{scan_id}/sbom")
def get_scan_sbom(scan_id: str, db: Session = Depends(get_db)):
    return generate_sbom_for_scan(scan_id, db)

@router.get("/scans/{scan_id}/sbom/cyclonedx")
def get_cyclonedx_sbom(scan_id: str, db: Session = Depends(get_db)):
    return export_cyclonedx_json(scan_id, db)

@router.get("/scans/{scan_id}/sbom/spdx")
def get_spdx_sbom(scan_id: str, db: Session = Depends(get_db)):
    return export_spdx_json(scan_id, db)
