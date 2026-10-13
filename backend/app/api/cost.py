"""
Cost-of-Risk Analytics API Router
Provides interactive calculation of remediation costs, breach losses, and scenario modeling.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db.session import get_db
from ..db.models import Scan
from ..schemas.schemas import CostCalculationRequest, CostSummaryResponse
from ..analytics.cost_analyzer import calculate_costs

router = APIRouter(tags=["Cost Analytics"])

@router.post("/scans/{scan_id}/cost", response_model=CostSummaryResponse)
def compute_scan_cost_analytics(
    scan_id: str,
    payload: CostCalculationRequest,
    db: Session = Depends(get_db)
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = scan.findings

    result = calculate_costs(
        findings=findings,
        dev_rate=payload.dev_rate,
        tester_rate=payload.tester_rate,
        currency=payload.currency,
        asset_value=payload.asset_value,
        records_count=payload.records_count,
        scenario=payload.scenario
    )

    return result
