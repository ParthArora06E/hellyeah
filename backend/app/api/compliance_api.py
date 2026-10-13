"""
Compliance, DPDP Act 2023, Cyber Insurance, and Attack Graph API Router
Endpoints:
- GET /api/scans/{id}/compliance (DPDP, SOC2, PCI-DSS, HIPAA, ISO27001)
- GET /api/scans/{id}/compliance/dpdp (Detailed India DPDP Act 2023 evaluation)
- GET /api/scans/{id}/insurance (Cyber Insurability Index & Underwriter Warranties)
- GET /api/scans/{id}/attack-graph (Topological Attack Graph)
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..db.session import get_db
from ..compliance.dpdp_engine import evaluate_dpdp_compliance
from ..compliance.compliance_mapper import map_all_compliance_frameworks
from ..analytics.insurance_engine import evaluate_cyber_insurability
from ..analytics.attack_path_engine import generate_attack_path_graph

router = APIRouter(prefix="/scans", tags=["Compliance, DPDP & Insurance"])

@router.get("/{scan_id}/compliance")
def get_all_compliance_frameworks(scan_id: str, db: Session = Depends(get_db)):
    result = map_all_compliance_frameworks(scan_id, db)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result

@router.get("/{scan_id}/compliance/dpdp")
def get_dpdp_compliance(scan_id: str, db: Session = Depends(get_db)):
    result = evaluate_dpdp_compliance(scan_id, db)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result

@router.get("/{scan_id}/insurance")
def get_cyber_insurance_readiness(scan_id: str, db: Session = Depends(get_db)):
    result = evaluate_cyber_insurability(scan_id, db)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result

@router.get("/{scan_id}/attack-graph")
@router.get("/{scan_id}/attack-path")
def get_attack_path_graph(scan_id: str, db: Session = Depends(get_db)):
    result = generate_attack_path_graph(scan_id, db)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result
