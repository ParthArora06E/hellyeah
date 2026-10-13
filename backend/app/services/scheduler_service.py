"""
Scheduled Re-Scan & Attack-Surface Drift Service (APScheduler)
Provides periodic automated re-scanning and computes diffs:
"New assets and new CVEs since last scan"
"""
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy.orm import Session
from ..db.session import SessionLocal
from ..db.models import Scan, Asset, Finding

_SCHEDULER = BackgroundScheduler()

def start_scheduler():
    if not _SCHEDULER.running:
        _SCHEDULER.start()

def get_scheduler_jobs() -> List[Dict[str, Any]]:
    jobs = []
    for j in _SCHEDULER.get_jobs():
        jobs.append({
            "id": j.id,
            "name": j.name,
            "next_run_time": j.next_run_time.isoformat() if j.next_run_time else None,
            "trigger": str(j.trigger)
        })
    return jobs

def calculate_scan_diff(current_scan_id: str, db: Session) -> Dict[str, Any]:
    """
    Computes delta between the current scan and the prior scan for the same domain:
    - New assets discovered
    - New CVEs / findings emerged
    - Resolved findings
    """
    curr = db.query(Scan).filter(Scan.id == current_scan_id).first()
    if not curr:
        return {"new_assets": [], "new_findings": [], "resolved_findings": []}

    prev = (
        db.query(Scan)
        .filter(Scan.target_domain == curr.target_domain, Scan.id != curr.id, Scan.status == "completed")
        .order_by(Scan.created_at.desc())
        .first()
    )

    if not prev:
        # First scan for domain
        return {
            "previous_scan_id": None,
            "new_assets": [a.value for a in curr.assets],
            "new_findings": [f.title for f in curr.findings],
            "resolved_findings": []
        }

    curr_assets = {a.value for a in curr.assets}
    prev_assets = {a.value for a in prev.assets}

    curr_findings = {f.title for f in curr.findings}
    prev_findings = {f.title for f in prev.findings}

    new_assets = list(curr_assets - prev_assets)
    new_findings = list(curr_findings - prev_findings)
    resolved_findings = list(prev_findings - curr_findings)

    return {
        "previous_scan_id": prev.id,
        "previous_scan_date": prev.created_at.isoformat() if prev.created_at else None,
        "new_assets": new_assets,
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "asset_drift_count": len(new_assets),
        "vuln_drift_count": len(new_findings)
    }
