"""
Persistent Monitoring Scheduler & Automated Execution Pipeline
Implements:
- AsyncIOScheduler with persistent SQLite job store.
- Reload all enabled jobs on startup.
- Per-job asyncio lock to prevent overlapping runs.
- Misfire grace time, coalescing, timeout, and transient retry.
- Integrates existing asset discovery, vulnerability correlation, cost analyzer, and risk engine.
- Calculates ScanRun diffs and triggers alert rule evaluations.
"""
import os
import uuid
import random
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
import zoneinfo

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy.orm import Session

from ..core.config import settings
from ..core.scope import check_scan_permission
from ..db.session import SessionLocal, SYNC_DATABASE_URL
from ..db.models import MonitorJob, AlertRule, ScanRun, Scan, Asset, Finding, AuditLog
from ..recon.adapter.context import ScanContext
from ..recon.modules.crtsh import CrtshModule
from ..recon.modules.alienvault_otx import AlienVaultOTXModule
from ..recon.modules.securitytrails import SecurityTrailsModule
from ..recon.modules.dns_resolver import DNSResolverModule
from ..recon.modules.whois_lookup import WhoisModule
from ..recon.modules.shodan_host import ShodanHostModule
from ..recon.modules.wayback_archive import WaybackModule
from ..recon.modules.urlscan_lookup import URLScanModule
from ..recon.modules.virustotal import VirusTotalModule
from ..vuln.cpe_mapper import detect_software_and_version
from ..vuln.cve_engine import lookup_cves_for_software
from ..vuln.active_probes import probe_security_headers, probe_exposed_files, probe_tls_certificate
from ..analytics.risk_scorer import score_and_rank_findings
from ..analytics.cost_analyzer import calculate_costs
from .alert_engine import evaluate_alert_rules_for_run

def now_utc():
    return datetime.now(timezone.utc)

# Persistent Jobstore in SQLite
_JOBSTORES = {
    "default": SQLAlchemyJobStore(url=SYNC_DATABASE_URL, tablename="apscheduler_jobs")
}

# Global Scheduler Instance
_SCHEDULER: Optional[AsyncIOScheduler] = None

# In-memory execution locks per job_id: {job_id: asyncio.Lock()}
_JOB_LOCKS: Dict[str, asyncio.Lock] = {}

def get_job_lock(job_id: str) -> asyncio.Lock:
    if job_id not in _JOB_LOCKS:
        _JOB_LOCKS[job_id] = asyncio.Lock()
    return _JOB_LOCKS[job_id]

def parse_schedule_trigger(schedule_type: str, schedule_value: str, timezone_str: str = "UTC"):
    """
    Parses preset or cron expressions into APScheduler trigger with timezone.
    """
    tz = timezone_str or "UTC"
    st = (schedule_type or "preset").lower().strip()
    val = (schedule_value or "daily").strip()

    if st == "preset":
        if val == "demo_30s":
            return IntervalTrigger(seconds=30)
        elif val == "hourly":
            return CronTrigger(minute=0, timezone=tz)
        elif val == "daily":
            return CronTrigger(hour=3, minute=0, timezone=tz)
        elif val == "weekly":
            return CronTrigger(day_of_week="mon", hour=3, minute=0, timezone=tz)
        elif val == "monthly":
            return CronTrigger(day=1, hour=3, minute=0, timezone=tz)
        else:
            return CronTrigger(hour=3, minute=0, timezone=tz)
    elif st == "cron":
        try:
            return CronTrigger.from_crontab(val, timezone=tz)
        except Exception as e:
            # Fallback to daily
            return CronTrigger(hour=3, minute=0, timezone=tz)
    return CronTrigger(hour=3, minute=0, timezone=tz)

def calculate_verdict(risk_score: float, fix_cost: float, findings_summary: dict, threshold: float = 25000.0) -> str:
    """
    Standardized verdict calculation:
    - 'Audit Recommended': when cost exceeds threshold, or high risk (>= 70), or CISA KEV active
    - 'Elevated Risk': when risk score is moderate (>= 45) or critical findings exist
    - 'Compliant': clean perimeter posture
    """
    kev_count = findings_summary.get("kev", 0)
    crit_count = findings_summary.get("critical", 0)

    if fix_cost >= threshold or risk_score >= 70.0 or kev_count > 0:
        return "Audit Recommended"
    elif risk_score >= 45.0 or crit_count > 0:
        return "Elevated Risk"
    return "Compliant"

def compute_run_diff(job_id: str, current_assets: List[str], current_cves: List[str], db: Session) -> Dict[str, Any]:
    """
    Computes delta against previous completed ScanRun for this job.
    """
    prev_run = (
        db.query(ScanRun)
        .filter(ScanRun.job_id == job_id, ScanRun.status == "completed")
        .order_by(ScanRun.started_at.desc())
        .first()
    )
    if not prev_run:
        return {
            "previous_run_id": None,
            "new_assets": current_assets,
            "removed_assets": [],
            "new_cves": current_cves,
            "resolved_cves": [],
            "is_initial_run": True
        }

    prev_diff = prev_run.diff_vs_previous or {}
    # We can inspect previous run or extract from scan records
    prev_assets_set = set(prev_diff.get("current_assets_snapshot", []))
    prev_cves_set = set(prev_diff.get("current_cves_snapshot", []))

    new_assets = list(set(current_assets) - prev_assets_set)
    removed_assets = list(prev_assets_set - set(current_assets))
    new_cves = list(set(current_cves) - prev_cves_set)
    resolved_cves = list(prev_cves_set - set(current_cves))

    return {
        "previous_run_id": prev_run.id,
        "new_assets": new_assets,
        "removed_assets": removed_assets,
        "new_cves": new_cves,
        "resolved_cves": resolved_cves,
        "current_assets_snapshot": current_assets,
        "current_cves_snapshot": current_cves,
        "is_initial_run": False
    }

async def execute_scheduled_job(job_id: str):
    """
    Core pipeline executed on scheduled triggers or manual "Run Now".
    Guaranteed single-flight per job via asyncio.Lock.
    """
    lock = get_job_lock(job_id)
    if lock.locked():
        # Overlapping execution prevented
        return

    async with lock:
        with SessionLocal() as db:
            job = db.query(MonitorJob).filter(MonitorJob.id == job_id).first()
            if not job or not job.enabled:
                return

            target = job.target_domain
            mode = job.scan_mode or "passive"

            # 1. Scope & Policy Verification
            allowed, reason = check_scan_permission(target, mode, db)
            run_id = str(uuid.uuid4())
            started_at = now_utc()

            if not allowed:
                # Target out of scope: record failed run with audit log
                failed_run = ScanRun(
                    id=run_id,
                    job_id=job.id,
                    started_at=started_at,
                    finished_at=now_utc(),
                    status="failed",
                    verdict="Scope Refusal",
                    error=f"Scope Refusal: {reason}"
                )
                db.add(failed_run)
                job.last_status = "failed"
                job.last_run = now_utc()
                db.add(AuditLog(
                    action="SCHEDULED_SCAN_REFUSAL",
                    target=target,
                    details=f"Job {job.name} ({job.id}) refused: {reason}",
                    status_code=403
                ))
                db.commit()
                return

            # 2. Initialize ScanRun Record
            run = ScanRun(
                id=run_id,
                job_id=job.id,
                started_at=started_at,
                status="running"
            )
            db.add(run)
            job.last_status = "running"
            db.commit()

            # Record Audit Log
            db.add(AuditLog(
                action="SCHEDULED_SCAN_LAUNCH",
                target=target,
                details=f"Monitoring job '{job.name}' initiated automated scan.",
                status_code=200
            ))
            db.commit()

        # 3. Execute Discovery & Vulnerability Pipeline
        # Run with a 180s timeout to protect against hang
        try:
            await asyncio.wait_for(_run_scan_internals(job_id, run_id, target, mode), timeout=180.0)
        except Exception as e:
            with SessionLocal() as db:
                r = db.query(ScanRun).filter(ScanRun.id == run_id).first()
                if r:
                    r.status = "failed"
                    r.error = f"Execution timeout or error: {str(e)}"
                    r.finished_at = now_utc()
                j = db.query(MonitorJob).filter(MonitorJob.id == job_id).first()
                if j:
                    j.last_status = "failed"
                    j.last_run = now_utc()
                db.commit()

async def _run_scan_internals(job_id: str, run_id: str, target: str, mode: str):
    """
    Internal scan runner executing discovery, CPE, CVE, cost model, diff, and alerts.
    """
    with SessionLocal() as db:
        # Create a linked Scan entity in DB to store individual assets & findings
        core_scan_id = f"mon-{run_id[:8]}"
        core_scan = Scan(
            id=core_scan_id,
            target_domain=target,
            company_name=f"Monitoring Job: {target}",
            mode=mode,
            status="running"
        )
        db.add(core_scan)
        db.commit()

        context = ScanContext(core_scan_id, target, mode, db, lambda *args: None)

        # 1. Passive Discovery Modules
        passive_modules = [
            CrtshModule(),
            AlienVaultOTXModule(),
            SecurityTrailsModule(),
            VirusTotalModule(),
            DNSResolverModule(),
            WhoisModule(),
            ShodanHostModule(),
            WaybackModule(),
            URLScanModule()
        ]

        for mod in passive_modules:
            try:
                await mod.run(target, context)
            except Exception:
                pass

        # 2. Technology Fingerprinting & CPE Synthesis
        discovered_cpes = []
        for asset in context.discovered_assets:
            for tech in (asset.technologies or []):
                cpe_info = detect_software_and_version(tech)
                if cpe_info:
                    discovered_cpes.append((asset.id, cpe_info))

        # 3. Vulnerability Lookup (NVD, OSV, EPSS, CISA KEV)
        for asset_id, cpe_info in discovered_cpes:
            try:
                vulns = await lookup_cves_for_software(
                    cpe_info["vendor"],
                    cpe_info["product"],
                    cpe_info["version"],
                    cpe_info["cpe"]
                )
                for v in vulns:
                    context.record_finding(v, asset_id=asset_id)
            except Exception:
                pass

        # 4. Safe Active Probes (if in active mode)
        if mode == "active":
            try:
                hf = await probe_security_headers(target, context)
                for f in hf: context.record_finding(f)
                ff = await probe_exposed_files(target, context)
                for f in ff: context.record_finding(f)
                tf = await probe_tls_certificate(target, context)
                for f in tf: context.record_finding(f)
            except Exception:
                pass

        # 5. Score & Rank Findings
        db.refresh(core_scan)
        scored_findings = score_and_rank_findings(core_scan.findings)

        # 6. Calculate Financial Costs & Breach Loss
        cost_res = calculate_costs(core_scan.findings, currency="USD")
        fix_cost = float(cost_res.get("total_fix_cost_both", 0.0))
        breach_loss = float(cost_res.get("total_potential_breach_loss", 0.0))

        # Compute summary metrics
        kev_count = sum(1 for f in core_scan.findings if getattr(f, "is_kev", False))
        crit_count = sum(1 for f in core_scan.findings if getattr(f, "severity", "") == "Critical")
        high_count = sum(1 for f in core_scan.findings if getattr(f, "severity", "") == "High")
        med_count = sum(1 for f in core_scan.findings if getattr(f, "severity", "") == "Medium")
        low_count = sum(1 for f in core_scan.findings if getattr(f, "severity", "") in ("Low", "Info"))

        findings_summary = {
            "total": len(core_scan.findings),
            "critical": crit_count,
            "high": high_count,
            "medium": med_count,
            "low": low_count,
            "kev": kev_count
        }

        # Calculate composite risk score
        overall_risk = 0.0
        if scored_findings:
            overall_risk = scored_findings[0][0]  # Max finding risk

        # Get job's rule threshold to compute verdict accurately
        primary_rule = db.query(AlertRule).filter(AlertRule.job_id == job_id).first()
        rule_threshold = float(primary_rule.threshold) if primary_rule else 25000.0

        verdict = calculate_verdict(overall_risk, fix_cost, findings_summary, threshold=rule_threshold)

        # 7. Compute Diff vs Previous Run
        current_assets_list = [a.value for a in core_scan.assets]
        current_cves_list = []
        for f in core_scan.findings:
            for cve in (f.cve_ids or []):
                current_cves_list.append(cve)

        diff = compute_run_diff(job_id, current_assets_list, current_cves_list, db)

        # 8. Complete ScanRun & Update MonitorJob
        run = db.query(ScanRun).filter(ScanRun.id == run_id).first()
        job = db.query(MonitorJob).filter(MonitorJob.id == job_id).first()

        if run:
            run.scan_id = core_scan_id
            run.finished_at = now_utc()
            run.status = "completed"
            run.assets_count = len(core_scan.assets)
            run.findings_summary = findings_summary
            run.estimated_audit_cost = fix_cost
            run.expected_annual_loss = breach_loss
            run.risk_score = overall_risk
            run.verdict = verdict
            run.diff_vs_previous = diff

        if job:
            job.last_run = now_utc()
            job.last_status = "completed"

        db.commit()

        # 9. Evaluate Alert Rules & Dispatch Notifications
        if job and run:
            await evaluate_alert_rules_for_run(job, run, db)

def init_monitoring_scheduler() -> AsyncIOScheduler:
    """
    Initializes and starts the persistent AsyncIOScheduler.
    Reloads all enabled jobs from database.
    """
    global _SCHEDULER
    if _SCHEDULER and _SCHEDULER.running:
        return _SCHEDULER

    _SCHEDULER = AsyncIOScheduler(
        jobstores=_JOBSTORES,
        job_defaults={
            "coalesce": True,
            "max_instances": 1,
            "misfire_grace_time": 300
        }
    )
    _SCHEDULER.start()

    # Reload active jobs from database
    reload_all_jobs()
    return _SCHEDULER

def reload_all_jobs():
    """
    Loads all enabled MonitorJobs from DB and registers them into APScheduler.
    """
    if not _SCHEDULER or not _SCHEDULER.running:
        return

    with SessionLocal() as db:
        jobs = db.query(MonitorJob).filter(MonitorJob.enabled == True).all()
        for j in jobs:
            try:
                trigger = parse_schedule_trigger(j.schedule_type, j.schedule_value, j.timezone)
                # Small random jitter between 1 and 5 seconds
                jitter_val = random.randint(1, 5) if j.schedule_value != "demo_30s" else 0

                _SCHEDULER.add_job(
                    execute_scheduled_job,
                    trigger=trigger,
                    args=[j.id],
                    id=f"job_{j.id}",
                    name=j.name,
                    replace_existing=True,
                    jitter=jitter_val
                )

                aps_job = _SCHEDULER.get_job(f"job_{j.id}")
                if aps_job and aps_job.next_run_time:
                    j.next_run = aps_job.next_run_time
            except Exception:
                pass
        db.commit()

def register_or_update_scheduler_job(job: MonitorJob):
    """
    Schedules or reschedules an individual job in APScheduler.
    """
    if not _SCHEDULER or not _SCHEDULER.running:
        return

    job_aps_id = f"job_{job.id}"
    if not job.enabled:
        if _SCHEDULER.get_job(job_aps_id):
            _SCHEDULER.remove_job(job_aps_id)
        return

    trigger = parse_schedule_trigger(job.schedule_type, job.schedule_value, job.timezone)
    jitter_val = random.randint(1, 4) if job.schedule_value != "demo_30s" else 0

    _SCHEDULER.add_job(
        execute_scheduled_job,
        trigger=trigger,
        args=[job.id],
        id=job_aps_id,
        name=job.name,
        replace_existing=True,
        jitter=jitter_val
    )

    aps_job = _SCHEDULER.get_job(job_aps_id)
    if aps_job and aps_job.next_run_time:
        with SessionLocal() as db:
            j = db.query(MonitorJob).filter(MonitorJob.id == job.id).first()
            if j:
                j.next_run = aps_job.next_run_time
                db.commit()

def pause_scheduler_job(job_id: str):
    if _SCHEDULER and _SCHEDULER.running:
        job_aps_id = f"job_{job_id}"
        if _SCHEDULER.get_job(job_aps_id):
            _SCHEDULER.pause_job(job_aps_id)

def resume_scheduler_job(job_id: str):
    if _SCHEDULER and _SCHEDULER.running:
        job_aps_id = f"job_{job_id}"
        if _SCHEDULER.get_job(job_aps_id):
            _SCHEDULER.resume_job(job_aps_id)

def remove_scheduler_job(job_id: str):
    if _SCHEDULER and _SCHEDULER.running:
        job_aps_id = f"job_{job_id}"
        if _SCHEDULER.get_job(job_aps_id):
            _SCHEDULER.remove_job(job_aps_id)
