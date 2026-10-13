"""
Scans API Router
Handles scan creation, listing, status querying, live SSE progress events, and drift diffing.
"""
import uuid
import json
import asyncio
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ..db.session import get_db, SessionLocal
from ..db.models import Scan, AuditLog
from ..schemas.schemas import ScanCreateRequest, ScanResponse
from ..services.scanner_pipeline import run_scan_pipeline, SCAN_EVENT_STREAMS, SCAN_EVENT_HISTORY
from ..services.scheduler_service import calculate_scan_diff

router = APIRouter(prefix="/scans", tags=["Scans"])

@router.post("", response_model=ScanResponse)
def create_scan(
    payload: ScanCreateRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    scan_id = str(uuid.uuid4())
    domain_clean = payload.target_domain.strip().lower()
    
    # Strip protocol if supplied by user
    if "://" in domain_clean:
        domain_clean = domain_clean.split("://")[1].split("/")[0]

    scan = Scan(
        id=scan_id,
        target_domain=domain_clean,
        company_name=payload.company_name or domain_clean,
        mode=payload.mode.lower(),
        status="queued",
        progress=0,
        current_step="Queued"
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Launch pipeline in background task
    background_tasks.add_task(
        run_scan_pipeline,
        scan_id=scan_id,
        db_factory=SessionLocal,
        manual_assets=payload.manual_assets,
        run_plugins=payload.run_plugins
    )

    return scan

@router.get("", response_model=List[ScanResponse])
def list_scans(db: Session = Depends(get_db)):
    return db.query(Scan).order_by(Scan.created_at.desc()).all()

@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@router.post("/{scan_id}/rescan", response_model=ScanResponse)
def trigger_rescan(
    scan_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Triggers a live re-scan for the same target domain in the background.
    """
    base_scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not base_scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    new_scan_id = str(uuid.uuid4())
    new_scan = Scan(
        id=new_scan_id,
        target_domain=base_scan.target_domain,
        company_name=base_scan.company_name,
        mode=base_scan.mode or "passive",
        status="queued",
        progress=0,
        current_step="Queued for Rescan"
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    background_tasks.add_task(
        run_scan_pipeline,
        scan_id=new_scan_id,
        db_factory=SessionLocal,
        manual_assets=[],
        run_plugins=True
    )

    return new_scan

@router.get("/{scan_id}/diff")
def get_scan_drift(
    scan_id: str,
    compare_to: Optional[str] = None,
    db: Session = Depends(get_db)
):
    from .diff_api import get_scan_differential
    return get_scan_differential(scan_id=scan_id, compare_to=compare_to, db=db)

@router.get("/{scan_id}/logs")
def get_scan_logs(scan_id: str, db: Session = Depends(get_db)):
    """
    Returns full chronological log events for a scan (either currently running or past).
    """
    if scan_id in SCAN_EVENT_HISTORY and len(SCAN_EVENT_HISTORY[scan_id]) > 0:
        return SCAN_EVENT_HISTORY[scan_id]

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    synthetic_logs = []
    created_time = scan.created_at.strftime("%H:%M:%S") if scan.created_at else "00:00:00"
    completed_time = scan.completed_at.strftime("%H:%M:%S") if scan.completed_at else created_time

    synthetic_logs.append({
        "timestamp": created_time,
        "level": "info",
        "message": f"Auditor scan initialized for target: {scan.target_domain} (Mode: {scan.mode.title()}).",
        "progress": 5,
        "step": "Target & Policy Validation"
    })

    audit_logs = db.query(AuditLog).filter(AuditLog.scan_id == scan_id).order_by(AuditLog.timestamp.asc()).all()
    for al in audit_logs:
        al_time = al.timestamp.strftime("%H:%M:%S") if al.timestamp else created_time
        synthetic_logs.append({
            "timestamp": al_time,
            "level": "good" if (al.status_code and al.status_code < 400) else "info",
            "message": f"[{al.action}] {al.target} {f'- {al.details}' if al.details else ''}",
            "progress": 50,
            "step": al.action
        })

    synthetic_logs.append({
        "timestamp": completed_time,
        "level": "good" if scan.status == "completed" else ("error" if scan.status == "failed" else "info"),
        "message": f"Audit {scan.status}. Discovered {scan.total_assets} assets and {scan.total_findings} vulnerabilities. Risk Score: {scan.risk_score}/100.",
        "progress": scan.progress,
        "step": scan.current_step or scan.status
    })

    return synthetic_logs

@router.get("/{scan_id}/events")
async def stream_scan_events(scan_id: str, db: Session = Depends(get_db)):
    """
    Server-Sent Events (SSE) endpoint for real-time progress and logs.
    Replays all past buffered events upon connection so clients navigating
    between pages never lose their audit progress.
    """
    q = asyncio.Queue()
    if scan_id not in SCAN_EVENT_STREAMS:
        SCAN_EVENT_STREAMS[scan_id] = []
    SCAN_EVENT_STREAMS[scan_id].append(q)

    # Check current status in DB
    scan_record = db.query(Scan).filter(Scan.id == scan_id).first()
    is_already_terminal = scan_record and scan_record.status in ["completed", "failed"]

    async def event_generator():
        try:
            # 1. Send initial connection ping
            yield f"data: {json.dumps({'message': f'Connected to live audit event stream ({scan_id[:8]})', 'level': 'info', 'progress': scan_record.progress if scan_record else 0, 'step': scan_record.current_step if scan_record else 'Initializing'})}\n\n"

            # 2. Replay all buffered past events so reconnecting clients see the complete history
            buffered = SCAN_EVENT_HISTORY.get(scan_id, [])
            for past_evt in buffered:
                yield f"data: {json.dumps(past_evt)}\n\n"

            # If scan already finished before client connected, exit cleanly
            if is_already_terminal and len(buffered) > 0 and buffered[-1].get("progress") == 100:
                return

            # 3. Stream live events
            while True:
                data = await q.get()
                yield f"data: {json.dumps(data)}\n\n"
                if data.get("progress") == 100 or data.get("level") == "error":
                    break
        except asyncio.CancelledError:
            pass
        finally:
            if scan_id in SCAN_EVENT_STREAMS and q in SCAN_EVENT_STREAMS[scan_id]:
                SCAN_EVENT_STREAMS[scan_id].remove(q)

    return StreamingResponse(event_generator(), media_type="text/event-stream")
