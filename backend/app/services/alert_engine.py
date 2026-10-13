"""
Edge-Triggered Alert Rules Engine with Hysteresis & Cooldown
Evaluates ScanRun metrics against user-defined AlertRules.
Enforces:
1. Edge-triggered state: Only triggers when crossing the threshold upward.
2. Hysteresis re-arming: Re-arms only after dropping below threshold * rearm_ratio.
3. Cooldown window: Suppresses alerts if triggered recently.
4. Idempotency: Never produces duplicate alerts for the same run.
"""
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session

from ..db.models import MonitorJob, AlertRule, ScanRun, Notification
from .notification_dispatcher import dispatch_all_channels

def now_utc():
    return datetime.now(timezone.utc)

def evaluate_operator(curr_val: float, threshold: float, operator: str) -> bool:
    op = (operator or "gte").lower().strip()
    if op == "gte":
        return curr_val >= threshold
    elif op == "gt":
        return curr_val > threshold
    elif op == "lte":
        return curr_val <= threshold
    elif op == "lt":
        return curr_val < threshold
    elif op == "eq":
        return abs(curr_val - threshold) < 0.001
    elif op == "ne":
        return abs(curr_val - threshold) >= 0.001
    return curr_val >= threshold

def extract_metric_value(metric: str, run: ScanRun) -> Tuple[float, str, str]:
    """
    Returns (numeric_value, formatted_string, display_label)
    """
    m = (metric or "estimated_audit_cost").lower().strip()
    if m == "estimated_audit_cost":
        val = float(run.estimated_audit_cost or 0.0)
        return val, f"${val:,.2f}", "Estimated Audit Fix Cost"
    elif m == "expected_annual_loss":
        val = float(run.expected_annual_loss or 0.0)
        return val, f"${val:,.2f}", "Potential Breach Exposure"
    elif m == "risk_score":
        val = float(run.risk_score or 0.0)
        return val, f"{val:.1f}/100", "Composite Risk Score"
    elif m == "new_critical_findings":
        summary = run.findings_summary or {}
        crit = int(summary.get("critical", 0)) + int(summary.get("kev", 0))
        return float(crit), f"{crit} Critical/KEV findings", "Critical Security Findings"
    else:
        val = float(run.estimated_audit_cost or 0.0)
        return val, f"${val:,.2f}", "Estimated Audit Cost"

def extract_drivers(run: ScanRun) -> List[str]:
    """
    Builds the top 3 contributing drivers for the alert notification payload.
    """
    drivers = []
    diff = run.diff_vs_previous or {}
    new_cves = diff.get("new_cves", [])
    new_assets = diff.get("new_assets", [])
    summary = run.findings_summary or {}
    kev_count = int(summary.get("kev", 0))
    crit_count = int(summary.get("critical", 0))

    if kev_count > 0:
        drivers.append(f"{kev_count} CISA KEV weaponized vulnerabilities active on perimeter")
    if new_cves:
        drivers.append(f"{len(new_cves)} newly emerged CVE(s) identified since last run")
    if crit_count > 0:
        drivers.append(f"{crit_count} Critical severity vulnerability findings needing engineering patch")
    if new_assets:
        drivers.append(f"{len(new_assets)} new external asset(s) discovered in attack surface")

    if not drivers:
        drivers.append(f"Aggregate risk metric exceeded threshold: ${run.estimated_audit_cost:,.2f}")

    return drivers[:3]

async def evaluate_alert_rules_for_run(
    job: Any,
    run: Any,
    db: Session
) -> List[Notification]:
    """
    Evaluates all rules configured for a MonitorJob against the latest completed ScanRun.
    Accepts either MonitorJob/ScanRun model instances or their string IDs.
    """
    if isinstance(job, str):
        job = db.query(MonitorJob).filter(MonitorJob.id == job).first()
    if isinstance(run, str):
        run = db.query(ScanRun).filter(ScanRun.id == run).first()

    if not job or not run:
        return []

    created_notifications = []
    rules = db.query(AlertRule).filter(AlertRule.job_id == job.id, AlertRule.enabled == True).all()
    if not rules:
        return created_notifications

    now = now_utc()

    for rule in rules:
        # Idempotency check: Ensure rule hasn't already produced a notification for this run
        existing = (
            db.query(Notification)
            .filter(Notification.run_id == run.id, Notification.rule_id == rule.id)
            .first()
        )
        if existing:
            continue

        curr_val, curr_formatted, label = extract_metric_value(rule.metric, run)
        threshold = float(rule.threshold)
        rearm_floor = threshold * float(rule.rearm_ratio or 0.9)

        condition_met = evaluate_operator(curr_val, threshold, rule.operator)

        # 1. Hysteresis Reset Check:
        # If the metric drops below threshold * rearm_ratio, re-arm the trigger
        if curr_val < rearm_floor and not rule.is_armed:
            rule.is_armed = True
            rule.last_value = curr_val
            db.commit()

        # 2. Edge-Triggered Condition Check:
        # Fires only when condition is met AND rule is armed (preventing repeated spam while staying high)
        if condition_met and rule.is_armed:
            # 3. Cooldown Check:
            cooldown_min = int(rule.cooldown_minutes or 60)
            if rule.last_fired_at:
                elapsed = now - rule.last_fired_at.replace(tzinfo=timezone.utc if rule.last_fired_at.tzinfo is None else rule.last_fired_at.tzinfo)
                if elapsed < timedelta(minutes=cooldown_min):
                    # In cooldown period; skip alert
                    rule.last_value = curr_val
                    db.commit()
                    continue

            # Build rich payload
            drivers = extract_drivers(run)
            thresh_fmt = f"${threshold:,.2f}" if "cost" in rule.metric or "loss" in rule.metric else f"{threshold:,.0f}"

            payload = {
                "title": "Audit Recommended",
                "target_domain": job.target_domain,
                "job_name": job.name,
                "job_id": job.id,
                "run_id": run.id,
                "rule_id": rule.id,
                "metric_label": label,
                "metric_value": curr_val,
                "metric_value_formatted": curr_formatted,
                "threshold": threshold,
                "threshold_formatted": thresh_fmt,
                "verdict": run.verdict,
                "drivers": drivers,
                "report_link": f"http://localhost:5173",
                "triggered_at": now.isoformat()
            }

            channels = rule.channels or ["in_app", "email", "slack"]
            notifs = await dispatch_all_channels(job.id, run.id, rule.id, channels, payload, db)
            created_notifications.extend(notifs)

            # Disarm rule until metric drops below hysteresis limit
            rule.is_armed = False
            rule.last_fired_at = now
            rule.last_value = curr_val
            db.commit()
        else:
            # Update last tracked value
            rule.last_value = curr_val
            db.commit()

    return created_notifications
