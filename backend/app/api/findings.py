"""
Findings API Router
Handles vulnerability findings query, severity/status filtering, and status progression.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..db.session import get_db
from ..db.models import Finding
from ..schemas.schemas import FindingResponse, FindingStatusUpdate

router = APIRouter(tags=["Findings"])

@router.get("/scans/{scan_id}/findings", response_model=List[FindingResponse])
def get_scan_findings(
    scan_id: str,
    severity: Optional[str] = Query(None, description="Filter Critical, High, Medium, Low"),
    status: Optional[str] = Query(None, description="Filter Open, Fixed, Accepted Risk"),
    is_kev: Optional[bool] = Query(None, description="Filter CISA KEV active exploits only"),
    search: Optional[str] = Query(None, description="Search title, description, or CVE"),
    db: Session = Depends(get_db)
):
    query = db.query(Finding).filter(Finding.scan_id == scan_id)

    if severity:
        query = query.filter(Finding.severity == severity)
    if status:
        query = query.filter(Finding.status == status)
    if is_kev is not None:
        query = query.filter(Finding.is_kev == is_kev)
    if search:
        s = f"%{search.strip()}%"
        query = query.filter(
            (Finding.title.ilike(s)) | (Finding.description.ilike(s)) | (Finding.cpe.ilike(s))
        )

    # Order by KEV first, then risk score descending
    return query.order_by(Finding.is_kev.desc(), Finding.risk_score.desc()).all()

@router.patch("/findings/{finding_id}/status", response_model=FindingResponse)
def update_finding_status(
    finding_id: int,
    payload: FindingStatusUpdate,
    db: Session = Depends(get_db)
):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    valid_statuses = ["Open", "Fixed", "Accepted Risk"]
    if payload.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")

    finding.status = payload.status
    db.commit()
    db.refresh(finding)
    return finding
