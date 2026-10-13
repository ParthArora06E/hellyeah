"""
Scheduled Monitoring, Alert Rules & Notifications API Router
Implements:
- /monitor/jobs (CRUD, pause, resume, run-now)
- /monitor/jobs/{id}/runs & /trend (time series with limit reference)
- /monitor/rules & /monitor/channels (channel configuration and test dispatches)
- /notifications (in-app notifications, mark-read, outbox review)
- RBAC validation: CISO & Finance can modify; Auditor is read-only.
- /monitor/demo/seed: Instant hackathon demo setup.
"""
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Header, BackgroundTasks
from sqlalchemy.orm import Session

from ..core.config import settings
from ..core.scope import check_scan_permission
from ..db.session import get_db, SessionLocal
from ..db.models import (
    MonitorJob, AlertRule, ScanRun, Notification, ChannelConfig, LocalOutboxMessage, AuditLog
)
from ..schemas.schemas import (
    MonitorJobCreate, MonitorJobUpdate, MonitorJobResponse,
    AlertRuleCreate, AlertRuleResponse,
    ScanRunResponse,
    NotificationResponse,
    ChannelConfigCreate, ChannelConfigResponse
)
from ..services.monitoring_scheduler import (
    register_or_update_scheduler_job,
    pause_scheduler_job,
    resume_scheduler_job,
    remove_scheduler_job,
    execute_scheduled_job
)
from ..services.notification_dispatcher import dispatch_all_channels

router = APIRouter(tags=["Scheduled Monitoring & Alerts"])

def verify_role(x_user_role: Optional[str] = Header(default="CISO"), require_write: bool = False):
    """
    RBAC Gatekeeper:
    - CISO and Finance can configure jobs, limits, and channels.
    - Auditor is read-only.
    """
    role = (x_user_role or "CISO").strip().upper()
    if require_write and role == "AUDITOR":
        raise HTTPException(
            status_code=403,
            detail="Permission denied: Role 'Auditor' has read-only access. Only 'CISO' or 'Finance' can modify monitoring jobs and alert thresholds."
        )
    return role

# =============================================================================
# Monitor Jobs Endpoints
# =============================================================================

@router.get("/monitor/jobs", response_model=List[MonitorJobResponse])
def list_monitor_jobs(db: Session = Depends(get_db)):
    jobs = db.query(MonitorJob).order_by(MonitorJob.created_at.desc()).all()
    results = []
    for j in jobs:
        latest = db.query(ScanRun).filter(ScanRun.job_id == j.id).order_by(ScanRun.started_at.desc()).first()
        j_dict = {
            "id": j.id,
            "name": j.name,
            "target_domain": j.target_domain,
            "scope": j.scope or [],
            "schedule_type": j.schedule_type,
            "schedule_value": j.schedule_value,
            "timezone": j.timezone,
            "enabled": j.enabled,
            "next_run": j.next_run,
            "last_run": j.last_run,
            "last_status": j.last_status,
            "scan_mode": j.scan_mode,
            "created_by": j.created_by,
            "created_at": j.created_at,
            "rules": j.rules,
            "latest_run": latest
        }
        results.append(j_dict)
    return results

@router.post("/monitor/jobs", response_model=MonitorJobResponse)
def create_monitor_job(
    payload: MonitorJobCreate,
    db: Session = Depends(get_db),
    role: str = Depends(lambda r=Header(default="CISO"): verify_role(r, require_write=True))
):
    target = payload.target_domain.strip().lower()
    if "://" in target:
        target = target.split("://")[1].split("/")[0]

    # Validate target permission
    allowed, reason = check_scan_permission(target, payload.scan_mode, db)
    if not allowed:
        raise HTTPException(status_code=400, detail=f"Target refusal: {reason}")

    job_id = str(uuid.uuid4())
    job = MonitorJob(
        id=job_id,
        name=payload.name.strip(),
        target_domain=target,
        scope=payload.scope or [],
        schedule_type=payload.schedule_type,
        schedule_value=payload.schedule_value,
        timezone=payload.timezone,
        scan_mode=payload.scan_mode,
        created_by=role,
        enabled=True,
        last_status="idle"
    )
    db.add(job)
    db.commit()

    # Automatically add initial alert rule if threshold provided
    if payload.threshold is not None:
        rule = AlertRule(
            job_id=job.id,
            metric=payload.metric or "estimated_audit_cost",
            operator="gte",
            threshold=float(payload.threshold),
            channels=payload.channels or ["in_app", "email", "slack"],
            cooldown_minutes=60,
            rearm_ratio=0.9,
            is_armed=True,
            enabled=True
        )
        db.add(rule)
        db.commit()

    db.refresh(job)

    # Register into scheduler
    register_or_update_scheduler_job(job)

    return {
        "id": job.id,
        "name": job.name,
        "target_domain": job.target_domain,
        "scope": job.scope or [],
        "schedule_type": job.schedule_type,
        "schedule_value": job.schedule_value,
        "timezone": job.timezone,
        "enabled": job.enabled,
        "next_run": job.next_run,
        "last_run": job.last_run,
        "last_status": job.last_status,
        "scan_mode": job.scan_mode,
        "created_by": job.created_by,
        "created_at": job.created_at,
        "rules": job.rules,
        "latest_run": None
    }

@router.get("/monitor/jobs/{job_id}", response_model=MonitorJobResponse)
def get_monitor_job(job_id: str, db: Session = Depends(get_db)):
    job = db.query(MonitorJob).filter(MonitorJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Monitoring job not found.")
    latest = db.query(ScanRun).filter(ScanRun.job_id == job.id).order_by(ScanRun.started_at.desc()).first()
    return {
        "id": job.id,
        "name": job.name,
        "target_domain": job.target_domain,
        "scope": job.scope or [],
        "schedule_type": job.schedule_type,
        "schedule_value": job.schedule_value,
        "timezone": job.timezone,
        "enabled": job.enabled,
        "next_run": job.next_run,
        "last_run": job.last_run,
        "last_status": job.last_status,
        "scan_mode": job.scan_mode,
        "created_by": job.created_by,
        "created_at": job.created_at,
        "rules": job.rules,
        "latest_run": latest
    }

@router.patch("/monitor/jobs/{job_id}", response_model=MonitorJobResponse)
def update_monitor_job(
    job_id: str,
    payload: MonitorJobUpdate,
    db: Session = Depends(get_db),
    role: str = Depends(lambda r=Header(default="CISO"): verify_role(r, require_write=True))
):
    job = db.query(MonitorJob).filter(MonitorJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Monitoring job not found.")

    if payload.name is not None: job.name = payload.name.strip()
    if payload.schedule_type is not None: job.schedule_type = payload.schedule_type
    if payload.schedule_value is not None: job.schedule_value = payload.schedule_value
    if payload.timezone is not None: job.timezone = payload.timezone
    if payload.enabled is not None: job.enabled = payload.enabled
    if payload.scan_mode is not None: job.scan_mode = payload.scan_mode
    if payload.scope is not None: job.scope = payload.scope

    db.commit()
    db.refresh(job)

    # Reschedule in APScheduler
    register_or_update_scheduler_job(job)

    latest = db.query(ScanRun).filter(ScanRun.job_id == job.id).order_by(ScanRun.started_at.desc()).first()
    return {
        "id": job.id,
        "name": job.name,
        "target_domain": job.target_domain,
        "scope": job.scope or [],
        "schedule_type": job.schedule_type,
        "schedule_value": job.schedule_value,
        "timezone": job.timezone,
        "enabled": job.enabled,
        "next_run": job.next_run,
        "last_run": job.last_run,
        "last_status": job.last_status,
        "scan_mode": job.scan_mode,
        "created_by": job.created_by,
        "created_at": job.created_at,
        "rules": job.rules,
        "latest_run": latest
    }

@router.delete("/monitor/jobs/{job_id}")
def delete_monitor_job(
    job_id: str,
    db: Session = Depends(get_db),
    role: str = Depends(lambda r=Header(default="CISO"): verify_role(r, require_write=True))
):
    job = db.query(MonitorJob).filter(MonitorJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Monitoring job not found.")

    remove_scheduler_job(job.id)
    db.delete(job)
    db.commit()
    return {"message": f"Successfully deleted monitoring job '{job.name}' ({job_id})."}

@router.post("/monitor/jobs/{job_id}/run")
async def run_monitor_job_now(
    job_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Manually triggers 'Run Now' execution asynchronously in the background.
    """
    job = db.query(MonitorJob).filter(MonitorJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Monitoring job not found.")

    # Schedule immediate execution
    background_tasks.add_task(execute_scheduled_job, job_id)
    return {"message": f"Execution triggered for '{job.name}'. Monitor progress in run history.", "job_id": job_id}

@router.post("/monitor/jobs/{job_id}/pause")
def pause_monitor_job(
    job_id: str,
    db: Session = Depends(get_db),
    role: str = Depends(lambda r=Header(default="CISO"): verify_role(r, require_write=True))
):
    job = db.query(MonitorJob).filter(MonitorJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Monitoring job not found.")

    job.enabled = False
    job.last_status = "paused"
    db.commit()
    pause_scheduler_job(job_id)
    return {"message": f"Paused scheduled monitoring for '{job.name}'."}

@router.post("/monitor/jobs/{job_id}/resume")
def resume_monitor_job(
    job_id: str,
    db: Session = Depends(get_db),
    role: str = Depends(lambda r=Header(default="CISO"): verify_role(r, require_write=True))
):
    job = db.query(MonitorJob).filter(MonitorJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Monitoring job not found.")

    job.enabled = True
    job.last_status = "idle"
    db.commit()
    register_or_update_scheduler_job(job)
    return {"message": f"Resumed scheduled monitoring for '{job.name}'."}

# =============================================================================
# Runs & Trend Chart Data Endpoints
# =============================================================================

@router.get("/monitor/jobs/{job_id}/runs", response_model=List[ScanRunResponse])
def get_job_runs(job_id: str, limit: int = 50, db: Session = Depends(get_db)):
    runs = (
        db.query(ScanRun)
        .filter(ScanRun.job_id == job_id)
        .order_by(ScanRun.started_at.desc())
        .limit(limit)
        .all()
    )
    return runs

@router.get("/monitor/jobs/{job_id}/trend")
def get_job_trend(job_id: str, db: Session = Depends(get_db)):
    """
    Returns time series historical data for the Recharts trend chart:
    [
      { "run_id": "...", "timestamp": "...", "date": "10/12 14:00",
        "estimated_audit_cost": 27500, "expected_annual_loss": 310000,
        "risk_score": 82, "limit": 25000, "exceeded": true, "verdict": "Audit Recommended" }
    ]
    """
    job = db.query(MonitorJob).filter(MonitorJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    rule = db.query(AlertRule).filter(AlertRule.job_id == job_id).first()
    threshold = float(rule.threshold) if rule else 25000.0

    runs = (
        db.query(ScanRun)
        .filter(ScanRun.job_id == job_id, ScanRun.status == "completed")
        .order_by(ScanRun.started_at.asc())
        .all()
    )

    points = []
    for r in runs:
        cost = float(r.estimated_audit_cost or 0.0)
        ts = r.started_at
        date_label = ts.strftime("%m/%d %H:%M") if ts else "N/A"
        points.append({
            "run_id": r.id,
            "timestamp": ts.isoformat() if ts else None,
            "date": date_label,
            "estimated_audit_cost": round(cost, 2),
            "expected_annual_loss": round(float(r.expected_annual_loss or 0.0), 2),
            "risk_score": round(float(r.risk_score or 0.0), 1),
            "limit": threshold,
            "exceeded": cost >= threshold,
            "verdict": r.verdict,
            "assets_count": r.assets_count
        })

    return {
        "job_id": job.id,
        "job_name": job.name,
        "target_domain": job.target_domain,
        "threshold": threshold,
        "points": points
    }

# =============================================================================
# Alert Rules Endpoints
# =============================================================================

@router.get("/monitor/rules", response_model=List[AlertRuleResponse])
def list_alert_rules(job_id: Optional[str] = None, db: Session = Depends(get_db)):
    q = db.query(AlertRule)
    if job_id:
        q = q.filter(AlertRule.job_id == job_id)
    return q.all()

@router.post("/monitor/rules", response_model=AlertRuleResponse)
def create_alert_rule(
    payload: AlertRuleCreate,
    db: Session = Depends(get_db),
    role: str = Depends(lambda r=Header(default="CISO"): verify_role(r, require_write=True))
):
    job = db.query(MonitorJob).filter(MonitorJob.id == payload.job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Associated monitor job not found.")

    rule = AlertRule(
        job_id=payload.job_id,
        metric=payload.metric,
        operator=payload.operator,
        threshold=float(payload.threshold),
        currency=payload.currency,
        cooldown_minutes=payload.cooldown_minutes,
        rearm_ratio=payload.rearm_ratio,
        channels=payload.channels,
        enabled=payload.enabled,
        is_armed=True
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule

# =============================================================================
# Notification Channels Endpoints
# =============================================================================

@router.get("/monitor/channels", response_model=List[ChannelConfigResponse])
def list_channel_configs(db: Session = Depends(get_db)):
    return db.query(ChannelConfig).order_by(ChannelConfig.created_at.desc()).all()

@router.post("/monitor/channels", response_model=ChannelConfigResponse)
def create_channel_config(
    payload: ChannelConfigCreate,
    db: Session = Depends(get_db),
    role: str = Depends(lambda r=Header(default="CISO"): verify_role(r, require_write=True))
):
    ch = ChannelConfig(
        name=payload.name.strip(),
        type=payload.type.strip().lower(),
        config=payload.config,
        enabled=payload.enabled,
        verified=False
    )
    db.add(ch)
    db.commit()
    db.refresh(ch)
    return ch

@router.post("/monitor/channels/{channel_id}/test")
async def test_notification_channel(
    channel_id: int,
    db: Session = Depends(get_db)
):
    """
    Sends a test notification payload to verify channel delivery.
    """
    ch = db.query(ChannelConfig).filter(ChannelConfig.id == channel_id).first()
    if not ch:
        raise HTTPException(status_code=404, detail="Channel configuration not found.")

    test_payload = {
        "title": "Audit Recommended (Test Verification)",
        "target_domain": "auditor-verification.test",
        "job_name": "Channel Test Dispatch",
        "metric_label": "Estimated Audit Cost",
        "metric_value": 32500.0,
        "metric_value_formatted": "$32,500.00",
        "threshold": 25000.0,
        "threshold_formatted": "$25,000.00",
        "verdict": "Audit Recommended",
        "drivers": [
            "Channel integration test verification ping",
            "Simulated CISA KEV critical asset flag"
        ],
        "report_link": "http://localhost:5173",
        "is_test": True
    }

    notifs = await dispatch_all_channels("test-job", None, None, [ch.type], test_payload, db)
    ch.verified = True
    db.commit()

    return {
        "message": f"Test notification dispatched to '{ch.name}' ({ch.type}). Check destination or local outbox.",
        "success": True
    }

# =============================================================================
# In-App Notifications & Outbox Review Endpoints
# =============================================================================

@router.get("/notifications")
def get_notifications(unread_only: bool = False, limit: int = 50, db: Session = Depends(get_db)):
    q = db.query(Notification).filter(Notification.channel == "in_app")
    if unread_only:
        q = q.filter(Notification.read_at.is_(None))
    notifs = q.order_by(Notification.sent_at.desc()).limit(limit).all()
    unread_count = db.query(Notification).filter(Notification.channel == "in_app", Notification.read_at.is_(None)).count()
    return {
        "unread_count": unread_count,
        "notifications": [
            {
                "id": n.id,
                "job_id": n.job_id,
                "run_id": n.run_id,
                "rule_id": n.rule_id,
                "channel": n.channel,
                "status": n.status,
                "payload": n.payload,
                "sent_at": n.sent_at.isoformat() if n.sent_at else None,
                "read_at": n.read_at.isoformat() if n.read_at else None
            }
            for n in notifs
        ]
    }

@router.post("/notifications/{notification_id}/read")
def mark_notification_read(notification_id: int, db: Session = Depends(get_db)):
    n = db.query(Notification).filter(Notification.id == notification_id).first()
    if not n:
        raise HTTPException(status_code=404, detail="Notification not found.")
    n.read_at = datetime.now(timezone.utc)
    db.commit()
    return {"message": f"Notification {notification_id} marked as read."}

@router.post("/notifications/read-all")
def mark_all_notifications_read(db: Session = Depends(get_db)):
    db.query(Notification).filter(Notification.read_at.is_(None)).update(
        {"read_at": datetime.now(timezone.utc)}
    )
    db.commit()
    return {"message": "All notifications marked as read."}

@router.get("/notifications/outbox")
def get_local_outbox_messages(limit: int = 30, db: Session = Depends(get_db)):
    """
    Returns captured email and Slack messages for demo mode inspection.
    """
    msgs = db.query(LocalOutboxMessage).order_by(LocalOutboxMessage.created_at.desc()).limit(limit).all()
    return [
        {
            "id": m.id,
            "channel": m.channel,
            "recipient": m.recipient,
            "subject": m.subject,
            "body": m.body,
            "payload": m.payload,
            "created_at": m.created_at.isoformat() if m.created_at else None
        }
        for m in msgs
    ]

# =============================================================================
# Demo Mode Drift Simulator Endpoint
# =============================================================================

@router.post("/monitor/demo/seed")
async def seed_demo_monitoring_scenario(db: Session = Depends(get_db)):
    """
    Seeds a high-value demonstration scenario:
    1. Creates/replaces a demo MonitorJob ('Production Core Web') for target 'demo-corp.internal'.
    2. Sets schedule to 'demo_30s' (every 30 seconds) and limit to $25,000.
    3. Synthesizes 3 historical runs showing upward cost drift:
       - Run 1 (2 mins ago): $14,200 (Below limit, Compliant)
       - Run 2 (1 min ago):  $21,500 (Below limit, Review Suggested)
       - Run 3 (Now):         $29,800 (CROSSES limit -> triggers 'Audit Recommended' alert!)
    4. Automatically dispatches the edge-triggered alert into in-app & outbox.
    """
    target = "demo-corp.internal"
    job_id = "demo-monitor-job-001"

    # Clean existing demo job if present
    existing_job = db.query(MonitorJob).filter(MonitorJob.id == job_id).first()
    if existing_job:
        db.delete(existing_job)
        db.commit()

    job = MonitorJob(
        id=job_id,
        name="Production Web & Cloud Infrastructure",
        target_domain=target,
        schedule_type="preset",
        schedule_value="demo_30s",
        timezone="UTC",
        enabled=True,
        scan_mode="passive",
        created_by="CISO",
        last_status="completed",
        last_run=datetime.now(timezone.utc)
    )
    db.add(job)
    db.commit()

    rule = AlertRule(
        job_id=job.id,
        metric="estimated_audit_cost",
        operator="gte",
        threshold=25000.0,
        currency="USD",
        cooldown_minutes=60,
        rearm_ratio=0.9,
        channels=["in_app", "email", "slack"],
        is_armed=False,  # Disarmed because it just crossed!
        last_fired_at=datetime.now(timezone.utc),
        last_value=29800.0,
        enabled=True
    )
    db.add(rule)
    db.commit()

    # Synthetic historical runs for trend visualization
    t0 = datetime.now(timezone.utc) - timedelta(minutes=2)
    t1 = datetime.now(timezone.utc) - timedelta(minutes=1)
    t2 = datetime.now(timezone.utc)

    run1 = ScanRun(
        id="demo-run-001",
        job_id=job.id,
        started_at=t0,
        finished_at=t0 + timedelta(seconds=12),
        status="completed",
        assets_count=12,
        findings_summary={"critical": 0, "high": 2, "medium": 5, "kev": 0},
        estimated_audit_cost=14200.0,
        expected_annual_loss=115000.0,
        risk_score=42.0,
        verdict="Compliant",
        diff_vs_previous={"new_assets": 0, "new_cves": 0}
    )
    run2 = ScanRun(
        id="demo-run-002",
        job_id=job.id,
        started_at=t1,
        finished_at=t1 + timedelta(seconds=14),
        status="completed",
        assets_count=15,
        findings_summary={"critical": 1, "high": 4, "medium": 6, "kev": 0},
        estimated_audit_cost=21500.0,
        expected_annual_loss=198000.0,
        risk_score=64.0,
        verdict="Elevated Risk",
        diff_vs_previous={"new_assets": 3, "new_cves": 2}
    )
    run3 = ScanRun(
        id="demo-run-003",
        job_id=job.id,
        started_at=t2,
        finished_at=t2 + timedelta(seconds=15),
        status="completed",
        assets_count=19,
        findings_summary={"critical": 2, "high": 6, "medium": 8, "kev": 1},
        estimated_audit_cost=29800.0,
        expected_annual_loss=385000.0,
        risk_score=88.5,
        verdict="Audit Recommended",
        diff_vs_previous={"new_assets": 4, "new_cves": 3}
    )
    db.add_all([run1, run2, run3])
    db.commit()

    # Dispatch alert for run 3
    payload = {
        "title": "Audit Recommended",
        "target_domain": target,
        "job_name": job.name,
        "job_id": job.id,
        "run_id": run3.id,
        "rule_id": rule.id,
        "metric_label": "Estimated Audit Cost",
        "metric_value": 29800.0,
        "metric_value_formatted": "$29,800.00",
        "threshold": 25000.0,
        "threshold_formatted": "$25,000.00",
        "verdict": "Audit Recommended",
        "drivers": [
            "1 CISA KEV weaponized vulnerability active on public API perimeter",
            "4 newly emerged CVEs discovered in external Apache/Nginx web services",
            "Estimated engineering remediation cost escalated past $25,000 threshold"
        ],
        "report_link": "http://localhost:5173",
        "triggered_at": t2.isoformat()
    }
    await dispatch_all_channels(job.id, run3.id, rule.id, ["in_app", "email", "slack"], payload, db)

    # Register into scheduler
    register_or_update_scheduler_job(job)

    return {
        "message": "Demo monitoring scenario initialized successfully! Cost threshold crossed at $29,800 > $25,000.",
        "job_id": job.id,
        "runs_created": 3
    }

@router.post("/monitor/demo/reset")
def reset_demo_monitoring_scenario(db: Session = Depends(get_db)):
    """
    Cleans up the demo scenario: removes demo jobs, demo runs, demo notifications, and resets outbox.
    """
    job_id = "demo-monitor-job-001"
    remove_scheduler_job(job_id)

    # Delete notifications, outbox, runs, rules, and job
    db.query(Notification).filter(Notification.job_id == job_id).delete()
    db.query(LocalOutboxMessage).delete()
    db.query(ScanRun).filter(ScanRun.job_id == job_id).delete()
    db.query(AlertRule).filter(AlertRule.job_id == job_id).delete()
    db.query(MonitorJob).filter(MonitorJob.id == job_id).delete()
    db.commit()

    return {"message": "Demo scenario reset successfully. Ready for a clean demonstration run."}

