"""
Scan Comparison & Asset Drift Differential Analytics Engine
Computes delta between two scans:
- New vs. Resolved vs. Persistent findings
- New vs. Decommissioned vs. Persistent assets
- Risk score, breach loss, and DPDP compliance trajectory
- Historical target scan timeline
"""
from typing import Dict, Any, List, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import desc
from ..db.models import Scan, Asset, Finding


def compute_scan_diff(
    current_scan: Scan,
    previous_scan: Optional[Scan]
) -> Dict[str, Any]:
    """
    Computes deep differential analytics between current_scan and previous_scan.
    """
    if not previous_scan:
        return {
            "has_previous_scan": False,
            "message": "No previous scan available for comparison.",
            "current_scan_id": current_scan.id,
            "target_domain": current_scan.target_domain,
            "timeline": []
        }

    # -------------------------------------------------------------------------
    # 1. Asset Drift Analysis
    # -------------------------------------------------------------------------
    curr_assets = {f"{a.type}:{a.value.lower()}": a for a in (current_scan.assets or [])}
    prev_assets = {f"{a.type}:{a.value.lower()}": a for a in (previous_scan.assets or [])}

    curr_keys = set(curr_assets.keys())
    prev_keys = set(prev_assets.keys())

    new_asset_keys = curr_keys - prev_keys
    decommissioned_asset_keys = prev_keys - curr_keys
    persistent_asset_keys = curr_keys & prev_keys

    new_assets = [
        {
            "id": curr_assets[k].id,
            "type": curr_assets[k].type,
            "value": curr_assets[k].value,
            "ip_address": curr_assets[k].ip_address,
            "technologies": curr_assets[k].technologies or []
        }
        for k in new_asset_keys
    ]

    decommissioned_assets = [
        {
            "id": prev_assets[k].id,
            "type": prev_assets[k].type,
            "value": prev_assets[k].value,
            "ip_address": prev_assets[k].ip_address,
            "technologies": prev_assets[k].technologies or []
        }
        for k in decommissioned_asset_keys
    ]

    # -------------------------------------------------------------------------
    # 2. Finding / Vulnerability Drift Analysis
    # -------------------------------------------------------------------------
    # Generate canonical fingerprint for findings: primary CVE if present, or normalized title
    def finding_key(f: Finding) -> str:
        cve_list = f.cve_ids or []
        if isinstance(cve_list, list) and len(cve_list) > 0:
            return f"cve:{cve_list[0].upper()}"
        return f"title:{f.title.strip().lower()}"

    curr_findings_map = {}
    for f in (current_scan.findings or []):
        curr_findings_map[finding_key(f)] = f

    prev_findings_map = {}
    for f in (previous_scan.findings or []):
        prev_findings_map[finding_key(f)] = f

    curr_f_keys = set(curr_findings_map.keys())
    prev_f_keys = set(prev_findings_map.keys())

    new_f_keys = curr_f_keys - prev_f_keys
    resolved_f_keys = prev_f_keys - curr_f_keys
    persistent_f_keys = curr_f_keys & prev_f_keys

    def serialize_finding(f: Finding) -> Dict[str, Any]:
        return {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "cvss_score": f.cvss_score,
            "epss_score": f.epss_score,
            "is_kev": f.is_kev,
            "cve_ids": f.cve_ids or [],
            "source": f.source,
            "estimated_fix_cost": f.estimated_fix_cost or 0.0,
            "remediation_text": f.remediation_text or ""
        }

    new_findings = [serialize_finding(curr_findings_map[k]) for k in new_f_keys]
    resolved_findings = [serialize_finding(prev_findings_map[k]) for k in resolved_f_keys]
    persistent_findings = [serialize_finding(curr_findings_map[k]) for k in persistent_f_keys]

    # -------------------------------------------------------------------------
    # 3. Posture, Score & Financial Delta Calculation
    # -------------------------------------------------------------------------
    curr_risk = float(current_scan.risk_score or 0.0)
    prev_risk = float(previous_scan.risk_score or 0.0)
    risk_delta = round(curr_risk - prev_risk, 2)

    curr_loss = float(current_scan.potential_breach_loss or 0.0)
    prev_loss = float(previous_scan.potential_breach_loss or 0.0)
    loss_delta = round(curr_loss - prev_loss, 2)

    curr_cost = float(current_scan.total_fix_cost or 0.0)
    prev_cost = float(previous_scan.total_fix_cost or 0.0)
    cost_delta = round(curr_cost - prev_cost, 2)

    resolved_potential_loss = sum(
        f.get("cvss_score", 5.0) * 12500.0 for f in resolved_findings
    )

    if risk_delta < -2.0:
        posture_status = "Improved"
        posture_verdict = f"Security posture improved! Risk score decreased by {abs(risk_delta)} points."
    elif risk_delta > 2.0:
        posture_status = "Degraded"
        posture_verdict = f"Security posture degraded. Risk score increased by {risk_delta} points due to new findings."
    else:
        posture_status = "Stable"
        posture_verdict = "Security posture is stable relative to previous scan."

    return {
        "has_previous_scan": True,
        "current_scan": {
            "id": current_scan.id,
            "created_at": current_scan.created_at.isoformat() if current_scan.created_at else None,
            "risk_score": curr_risk,
            "total_assets": len(curr_assets),
            "total_findings": len(curr_findings_map),
            "potential_breach_loss": curr_loss,
            "total_fix_cost": curr_cost
        },
        "previous_scan": {
            "id": previous_scan.id,
            "created_at": previous_scan.created_at.isoformat() if previous_scan.created_at else None,
            "risk_score": prev_risk,
            "total_assets": len(prev_assets),
            "total_findings": len(prev_findings_map),
            "potential_breach_loss": prev_loss,
            "total_fix_cost": prev_cost
        },
        "deltas": {
            "risk_score_delta": risk_delta,
            "loss_delta": loss_delta,
            "fix_cost_delta": cost_delta,
            "assets_delta": len(curr_assets) - len(prev_assets),
            "findings_delta": len(curr_findings_map) - len(prev_findings_map),
            "posture_status": posture_status,
            "posture_verdict": posture_verdict,
            "resolved_potential_loss_saved": resolved_potential_loss
        },
        "asset_drift": {
            "new_count": len(new_assets),
            "decommissioned_count": len(decommissioned_assets),
            "persistent_count": len(persistent_asset_keys),
            "new_assets": new_assets,
            "decommissioned_assets": decommissioned_assets
        },
        "finding_drift": {
            "new_count": len(new_findings),
            "resolved_count": len(resolved_findings),
            "persistent_count": len(persistent_findings),
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
            "persistent_findings": persistent_findings
        }
    }


def get_target_scan_timeline(db: Session, target_domain: str) -> List[Dict[str, Any]]:
    """
    Returns historical timeline of all completed scans for a target domain.
    """
    scans = (
        db.query(Scan)
        .filter(Scan.target_domain == target_domain)
        .order_by(Scan.created_at.asc())
        .all()
    )

    timeline = []
    for s in scans:
        timeline.append({
            "id": s.id,
            "date": s.created_at.strftime("%Y-%m-%d %H:%M") if s.created_at else "Unknown",
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "status": s.status,
            "risk_score": round(float(s.risk_score or 0.0), 1),
            "total_assets": s.total_assets or len(s.assets or []),
            "total_findings": s.total_findings or len(s.findings or []),
            "potential_breach_loss": float(s.potential_breach_loss or 0.0),
            "total_fix_cost": float(s.total_fix_cost or 0.0)
        })
    return timeline
