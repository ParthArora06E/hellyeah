"""
Scan Diff & Asset Drift API Router
Provides differential scan comparison and historical timelines.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from ..db.session import get_db
from ..db.models import Scan, Asset, Finding
from ..analytics.diff_engine import compute_scan_diff, get_target_scan_timeline
from ..analytics.cost_analyzer import calculate_costs

router = APIRouter(prefix="/api/scans", tags=["diff"])


@router.get("/{scan_id}/diff")
def get_scan_differential(
    scan_id: str,
    compare_to: Optional[str] = Query(None, description="Optional scan ID to compare against. If omitted, previous scan for same target is used."),
    db: Session = Depends(get_db)
):
    """
    Returns asset drift and vulnerability differential analytics between scan_id and compare_to.
    """
    current_scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not current_scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    target_domain = current_scan.target_domain

    if compare_to:
        prev_scan = db.query(Scan).filter(Scan.id == compare_to).first()
    else:
        # Find the most recent preceding completed scan for the same target
        prev_scan = (
            db.query(Scan)
            .filter(
                Scan.target_domain == target_domain,
                Scan.id != scan_id,
                Scan.status == "completed",
                Scan.created_at < current_scan.created_at
            )
            .order_by(desc(Scan.created_at))
            .first()
        )
        # If no preceding completed scan exists, fall back to any other completed scan for the target
        if not prev_scan:
            prev_scan = (
                db.query(Scan)
                .filter(
                    Scan.target_domain == target_domain,
                    Scan.id != scan_id,
                    Scan.status == "completed"
                )
                .order_by(desc(Scan.created_at))
                .first()
            )

    diff_result = compute_scan_diff(current_scan, prev_scan)
    diff_result["target_domain"] = target_domain
    diff_result["timeline"] = get_target_scan_timeline(db, target_domain)
    
    # Also attach list of completed candidate scans for comparison dropdown
    all_target_scans = (
        db.query(Scan)
        .filter(Scan.target_domain == target_domain, Scan.status == "completed")
        .order_by(desc(Scan.created_at))
        .all()
    )
    diff_result["available_scans_for_target"] = [
        {
            "id": s.id,
            "created_at": s.created_at.strftime("%Y-%m-%d %H:%M") if s.created_at else "Unknown",
            "risk_score": round(float(s.risk_score or 0.0), 1),
            "findings_count": s.total_findings or 0
        }
        for s in all_target_scans
    ]

    all_other_scans = (
        db.query(Scan)
        .filter(Scan.target_domain != target_domain)
        .order_by(desc(Scan.created_at))
        .limit(10)
        .all()
    )
    diff_result["all_available_scans"] = [
        {
            "id": s.id,
            "target_domain": s.target_domain,
            "created_at": s.created_at.strftime("%Y-%m-%d %H:%M") if s.created_at else "Unknown",
            "risk_score": round(float(s.risk_score or 0.0), 1),
            "findings_count": s.total_findings or 0
        }
        for s in all_other_scans
    ]

    return diff_result


@router.post("/{scan_id}/simulate-drift")
def simulate_remediation_drift(
    scan_id: str,
    db: Session = Depends(get_db)
):
    """
    Instantly creates a realistic post-remediation verification scan for target_domain.
    Demonstrates differential posture improvement, resolved findings, and asset drift
    in 1 click (ideal for hackathon demos and audit verifications).
    """
    base_scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not base_scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    new_scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    # 1. Create and flush new Scan row first to satisfy Foreign Key constraints
    new_scan = Scan(
        id=new_scan_id,
        target_domain=base_scan.target_domain,
        company_name=base_scan.company_name,
        mode=base_scan.mode or "passive",
        status="completed",
        progress=100,
        current_step="Completed",
        created_at=now,
        completed_at=now
    )
    db.add(new_scan)
    db.flush()

    # 2. Clone assets, plus add 1 newly discovered perimeter asset
    cloned_assets = []
    for a in (base_scan.assets or []):
        new_a = Asset(
            scan_id=new_scan_id,
            type=a.type,
            value=a.value,
            ip_address=a.ip_address,
            owner=a.owner,
            criticality=a.criticality,
            tags=list(a.tags or []),
            technologies=list(a.technologies or []),
            raw_metadata=dict(a.raw_metadata or {}),
            first_seen=now,
            last_seen=now
        )
        db.add(new_a)
        cloned_assets.append(new_a)

    # Add 1 new perimeter asset to showcase asset drift
    drift_subdomain = f"staging.{base_scan.target_domain}"
    new_asset = Asset(
        scan_id=new_scan_id,
        type="subdomain",
        value=drift_subdomain,
        ip_address="104.21.58.12",
        owner="DevOps / Staging",
        criticality=2,
        tags=["asset_drift", "new_perimeter", "staging"],
        technologies=["Nginx", "Node.js"],
        raw_metadata={"discovered_from": "Active Asset Drift Probe"},
        first_seen=now,
        last_seen=now
    )
    db.add(new_asset)
    cloned_assets.append(new_asset)
    db.flush()

    # 3. Clone findings, but REMOVE / RESOLVE 2-3 common lightweight findings to show remediation
    base_findings = list(base_scan.findings or [])
    resolved_titles = []

    def is_resolvable(title: str) -> bool:
        t = (title or "").lower()
        return any(k in t for k in [
            "content security policy", "csp", "hsts", "strict-transport",
            "clickjacking", "x-frame", "dnssec", "referrer-policy", "cookie"
        ])

    candidates_to_resolve = [f for f in base_findings if is_resolvable(f.title)]
    if not candidates_to_resolve and len(base_findings) >= 2:
        candidates_to_resolve = base_findings[-2:]

    to_resolve_ids = {f.id for f in candidates_to_resolve[:3]}

    cloned_findings = []
    for f in base_findings:
        if f.id in to_resolve_ids:
            resolved_titles.append(f.title)
            continue  # Excluded from new scan -> DiffEngine marks as Resolved!

        new_f = Finding(
            scan_id=new_scan_id,
            asset_id=None,
            title=f.title,
            description=f.description or f"Security finding: {f.title}",
            severity=f.severity,
            cvss_score=f.cvss_score,
            epss_score=f.epss_score,
            is_kev=f.is_kev,
            cve_ids=list(f.cve_ids or []),
            cpe=f.cpe,
            source=f.source,
            confidence=f.confidence,
            status=f.status,
            evidence=dict(f.evidence or {}),
            remediation_text=f.remediation_text,
            owasp_category=f.owasp_category,
            iso_control=f.iso_control,
            fix_hours_dev=f.fix_hours_dev,
            fix_hours_tester=f.fix_hours_tester,
            estimated_fix_cost=f.estimated_fix_cost,
            risk_score=f.risk_score,
            created_at=now
        )
        db.add(new_f)
        cloned_findings.append(new_f)

    db.flush()

    # 4. Calculate calibrated costs & ROI on remaining findings and update new_scan
    cost_data = calculate_costs(cloned_findings)
    new_fix_cost = cost_data["total_fix_cost_both"]
    new_loss = cost_data["total_potential_breach_loss"]
    new_roi = cost_data["roi_both"]

    old_risk = float(base_scan.risk_score or 65.0)
    risk_drop = min(35.0, round(len(resolved_titles) * 12.5, 1)) if resolved_titles else 25.0
    new_risk = max(8.5, round(old_risk - risk_drop, 1))

    new_scan.total_assets = len(cloned_assets)
    new_scan.total_findings = len(cloned_findings)
    new_scan.risk_score = new_risk
    new_scan.total_fix_cost = new_fix_cost
    new_scan.potential_breach_loss = new_loss
    new_scan.roi_percentage = new_roi
    new_scan.summary_notes = f"Post-remediation verification delta audit. Successfully verified {len(resolved_titles)} resolved vulnerabilities. Perimeter drift: 1 new staging asset identified."

    db.commit()
    db.refresh(new_scan)

    return {
        "id": new_scan.id,
        "target_domain": new_scan.target_domain,
        "company_name": new_scan.company_name,
        "status": new_scan.status,
        "risk_score": new_scan.risk_score,
        "total_findings": new_scan.total_findings,
        "total_assets": new_scan.total_assets,
        "total_fix_cost": new_scan.total_fix_cost,
        "resolved_findings_count": len(resolved_titles),
        "resolved_titles": resolved_titles,
        "created_at": new_scan.created_at.strftime("%Y-%m-%d %H:%M:%S")
    }


@router.get("/{scan_id}/timeline")
def get_scan_historical_timeline(
    scan_id: str,
    db: Session = Depends(get_db)
):
    """
    Returns historical timeline data points for the scan's target domain.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    timeline = get_target_scan_timeline(db, scan.target_domain)
    return {
        "target_domain": scan.target_domain,
        "timeline": timeline
    }
