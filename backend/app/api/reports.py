"""
Reports & Multi-Format Export API Router
Generates downloadable PDF, CSV, Excel XLSX, and JSON reports with compliance tags.
"""
from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
import io

from ..db.session import get_db
from ..db.models import Scan
from ..analytics.cost_analyzer import calculate_costs
from ..services.reporter import (
    normalize_report_data, generate_csv_export, generate_xlsx_export,
    generate_executive_summary_text
)
from ..services.pdf_generator import generate_pdf_report

router = APIRouter(tags=["Reports"])

@router.get("/scans/{scan_id}/report/summary")
async def get_scan_executive_summary(
    scan_id: str,
    db: Session = Depends(get_db)
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    cost_summary = calculate_costs(scan.findings)
    norm = normalize_report_data(scan, scan.assets, scan.findings, cost_summary)
    
    meta = {
        "target_domain": scan.target_domain,
        "company_name": scan.company_name,
        "mode": scan.mode,
        "risk_score": scan.risk_score
    }
    
    summary_text = await generate_executive_summary_text(meta, norm, cost_summary)
    return {"summary": summary_text}

@router.get("/scans/{scan_id}/report/pdf")
async def download_pdf_report(
    scan_id: str,
    db: Session = Depends(get_db)
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    cost_summary = calculate_costs(scan.findings)
    norm_findings = normalize_report_data(scan, scan.assets, scan.findings, cost_summary)
    norm_assets = [{"value": a.value, "type": a.type, "owner": a.owner, "criticality": a.criticality} for a in scan.assets]

    meta = {
        "target_domain": scan.target_domain,
        "company_name": scan.company_name,
        "mode": scan.mode,
        "risk_score": scan.risk_score
    }

    summary_text = await generate_executive_summary_text(meta, norm_findings, cost_summary)
    pdf_bytes = generate_pdf_report(meta, norm_findings, norm_assets, cost_summary, summary_text)

    filename = f"Auditor_Report_{scan.target_domain}_{scan.id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.get("/scans/{scan_id}/report/csv")
def download_csv_report(
    scan_id: str,
    db: Session = Depends(get_db)
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    cost_summary = calculate_costs(scan.findings)
    norm = normalize_report_data(scan, scan.assets, scan.findings, cost_summary)
    csv_text = generate_csv_export(norm)

    filename = f"Auditor_Findings_{scan.target_domain}_{scan.id[:8]}.csv"
    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.get("/scans/{scan_id}/report/xlsx")
def download_xlsx_report(
    scan_id: str,
    db: Session = Depends(get_db)
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    cost_summary = calculate_costs(scan.findings)
    norm = normalize_report_data(scan, scan.assets, scan.findings, cost_summary)
    
    meta = {"target_domain": scan.target_domain}
    xlsx_bytes = generate_xlsx_export(norm, meta)

    filename = f"Auditor_Findings_{scan.target_domain}_{scan.id[:8]}.xlsx"
    return Response(
        content=xlsx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.get("/scans/{scan_id}/report/json")
def download_json_report(
    scan_id: str,
    db: Session = Depends(get_db)
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    cost_summary = calculate_costs(scan.findings)
    norm = normalize_report_data(scan, scan.assets, scan.findings, cost_summary)
    
    # Structured Executive Audit Feasibility & Budget Decision
    crit_count = sum(1 for f in scan.findings if f.severity == "Critical")
    high_count = sum(1 for f in scan.findings if f.severity == "High")
    risk_score = scan.risk_score or 0.0
    total_assets = len(scan.assets) or 1
    total_loss = cost_summary.get("total_potential_breach_loss", 0.0)
    total_fix = cost_summary.get("total_fix_cost_both", 0.0)
    roi = cost_summary.get("roi_both", 0.0)

    risk_assets_count = max(1, min(total_assets, int(crit_count * 1.0 + high_count * 0.7 + 0.5)))
    scoped_fix = total_fix * 0.38
    scoped_loss = total_loss * 0.88
    scoped_savings = max(0.0, total_fix - scoped_fix)
    scoped_savings_pct = int(round((scoped_savings / total_fix) * 100)) if total_fix > 0 else 0
    scoped_roi = int(round(((scoped_loss - scoped_fix) / scoped_fix) * 100)) if scoped_fix > 0 else int(roi * 1.5)

    if risk_score < 35 and crit_count == 0 and (high_count == 0 or total_loss < 20000 or roi <= 80):
        verdict = "SKIP"
        verdict_label = "SAFE TO DEFER / SKIP AUDIT (CAPITAL PRESERVATION)"
    elif (crit_count > 0 or high_count > 0) and (total_assets >= 3 or (35 <= risk_score <= 75)):
        verdict = "SCOPE_DOWN"
        verdict_label = f"SCOPE DOWN BUDGET (TARGET {risk_assets_count} HIGH-RISK ASSETS)"
    else:
        verdict = "PROCEED"
        verdict_label = "PROCEED WITH COMPREHENSIVE AUDIT"

    decision_dict = {
        "verdict": verdict,
        "verdict_label": verdict_label,
        "risk_score": risk_score,
        "full_audit": {
            "budget_required": total_fix,
            "breach_loss_at_risk": total_loss,
            "projected_roi_pct": roi
        },
        "scoped_down": {
            "target_assets_count": risk_assets_count,
            "total_assets_count": total_assets,
            "budget_required": scoped_fix,
            "capital_saved": scoped_savings,
            "capital_saved_pct": scoped_savings_pct,
            "loss_neutralized": scoped_loss,
            "targeted_roi_pct": scoped_roi
        }
    }
    
    report_dict = {
        "scan": {
            "id": scan.id,
            "target": scan.target_domain,
            "company": scan.company_name,
            "mode": scan.mode,
            "risk_score": scan.risk_score,
            "created_at": scan.created_at.isoformat() if scan.created_at else None
        },
        "executive_audit_decision": decision_dict,
        "financial_summary": cost_summary,
        "assets_count": len(scan.assets),
        "findings": norm
    }

    return report_dict
