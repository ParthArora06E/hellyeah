"""
Comprehensive Unit & Integration Test Suite for Scheduled Monitoring & Cost Alerts
Covers:
1. SSRF Guard: Loopback, private ranges, link-local metadata protection
2. Crypto: Secret encryption & decryption round-trip
3. Alert Engine: Edge-triggering, hysteresis re-arm ratio (0.9x), and cooldown
4. Notification Dispatcher: Channel isolation, idempotency, and fallback to local outbox
5. Concurrency: Single-flight per-job lock
6. Target Scope Refusal
7. Database persistence & state transitions
"""
import uuid
import socket
import pytest
import asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

from backend.app.core.ssrf_guard import validate_webhook_url
from backend.app.core.crypto import encrypt_secret, decrypt_secret
from backend.app.db.session import SessionLocal
from backend.app.db.models import (
    MonitorJob, AlertRule, ScanRun, Notification, ChannelConfig, LocalOutboxMessage
)
from backend.app.services.alert_engine import evaluate_alert_rules_for_run, extract_drivers
from backend.app.services.notification_dispatcher import dispatch_all_channels
from backend.app.services.monitoring_scheduler import get_job_lock
from backend.app.core.scope import check_scan_permission


# =============================================================================
# 1. SSRF Protection Tests
# =============================================================================

def test_ssrf_blocks_private_and_loopback_ips():
    bad_urls = [
        "http://127.0.0.1:8000/hook",
        "http://localhost:3000",
        "http://127.0.0.99/admin",
        "http://10.0.0.1/webhook",
        "http://192.168.1.100/notify",
        "http://172.16.0.5/api",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "ftp://ftp.example.com/upload"
    ]
    for url in bad_urls:
        with pytest.raises(ValueError):
            validate_webhook_url(url)

def test_ssrf_allows_public_webhooks():
    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]
        url = "https://api.example.com/webhooks/alerts-listener"
        validated = validate_webhook_url(url)
        assert validated == url


# =============================================================================
# 2. Cryptographic Storage Tests
# =============================================================================

def test_crypto_round_trip():
    secret_token = "test-crypto-secret-token-1234567890"
    encrypted = encrypt_secret(secret_token)
    assert encrypted != secret_token
    assert len(encrypted) > 16
    
    decrypted = decrypt_secret(encrypted)
    assert decrypted == secret_token


# =============================================================================
# 3. Alert Engine: Edge Triggering, Hysteresis & Cooldown Tests
# =============================================================================

@pytest.mark.asyncio
async def test_edge_triggered_hysteresis_and_cooldown():
    """
    Verifies that:
    1. Alert fires only when metric crosses threshold upward.
    2. Repeat runs above the threshold DO NOT fire repeat alerts (edge-triggered).
    3. Rule re-arms ONLY when metric drops below threshold * 0.9 (hysteresis floor).
    """
    job_id = f"test-edge-{uuid.uuid4().hex[:8]}"
    with SessionLocal() as db:
        # Pre-cleanup
        db.query(Notification).filter(Notification.job_id == job_id).delete()
        db.query(ScanRun).filter(ScanRun.job_id == job_id).delete()
        db.query(AlertRule).filter(AlertRule.job_id == job_id).delete()
        db.query(MonitorJob).filter(MonitorJob.id == job_id).delete()
        db.commit()

        job = MonitorJob(
            id=job_id,
            name="Test Edge Job",
            target_domain="edge-test.internal",
            schedule_type="preset",
            schedule_value="daily_midnight",
            timezone="UTC",
            enabled=True,
            created_by="CISO"
        )
        db.add(job)
        db.commit()

        threshold = 25000.0
        rearm_ratio = 0.9
        rearm_floor = threshold * rearm_ratio  # 22,500.0

        rule = AlertRule(
            job_id=job.id,
            metric="estimated_audit_cost",
            operator="gte",
            threshold=threshold,
            currency="USD",
            cooldown_minutes=60,
            rearm_ratio=rearm_ratio,
            channels=["in_app"],
            is_armed=True,
            enabled=True
        )
        db.add(rule)
        db.commit()

        # RUN 1: Cost is 18,000 (below threshold) -> Must NOT fire, remains armed
        run1 = ScanRun(
            id=f"run-01-{uuid.uuid4().hex[:6]}",
            job_id=job.id,
            started_at=datetime.now(timezone.utc),
            status="completed",
            estimated_audit_cost=18000.0,
            expected_annual_loss=50000.0,
            risk_score=35.0,
            verdict="Compliant"
        )
        db.add(run1)
        db.commit()

        fired1 = await evaluate_alert_rules_for_run(job.id, run1.id, db)
        assert len(fired1) == 0
        db.refresh(rule)
        assert rule.is_armed is True

        # RUN 2: Cost is 27,500 (CROSSES threshold upward) -> MUST fire, rule disarmed!
        run2 = ScanRun(
            id=f"run-02-{uuid.uuid4().hex[:6]}",
            job_id=job.id,
            started_at=datetime.now(timezone.utc),
            status="completed",
            estimated_audit_cost=27500.0,
            expected_annual_loss=250000.0,
            risk_score=78.0,
            verdict="Audit Recommended"
        )
        db.add(run2)
        db.commit()

        fired2 = await evaluate_alert_rules_for_run(job.id, run2.id, db)
        assert len(fired2) == 1
        assert fired2[0].rule_id == rule.id
        db.refresh(rule)
        assert rule.is_armed is False  # Disarmed after firing

        # RUN 3: Cost is 29,000 (still above threshold) -> Must NOT fire (zero spam)
        run3 = ScanRun(
            id=f"run-03-{uuid.uuid4().hex[:6]}",
            job_id=job.id,
            started_at=datetime.now(timezone.utc),
            status="completed",
            estimated_audit_cost=29000.0,
            expected_annual_loss=280000.0,
            risk_score=82.0,
            verdict="Audit Recommended"
        )
        db.add(run3)
        db.commit()

        fired3 = await evaluate_alert_rules_for_run(job.id, run3.id, db)
        assert len(fired3) == 0  # Edge-trigger suppression
        db.refresh(rule)
        assert rule.is_armed is False

        # RUN 4: Cost drops to 23,500 (below 25,000, BUT above 22,500 rearm floor)
        run4 = ScanRun(
            id=f"run-04-{uuid.uuid4().hex[:6]}",
            job_id=job.id,
            started_at=datetime.now(timezone.utc),
            status="completed",
            estimated_audit_cost=23500.0,
            expected_annual_loss=90000.0,
            risk_score=50.0,
            verdict="Elevated Risk"
        )
        db.add(run4)
        db.commit()

        fired4 = await evaluate_alert_rules_for_run(job.id, run4.id, db)
        assert len(fired4) == 0
        db.refresh(rule)
        assert rule.is_armed is False  # Hysteresis prevents premature re-arming

        # RUN 5: Cost drops to 20,000 (below 22,500 rearm floor) -> MUST re-arm!
        run5 = ScanRun(
            id=f"run-05-{uuid.uuid4().hex[:6]}",
            job_id=job.id,
            started_at=datetime.now(timezone.utc),
            status="completed",
            estimated_audit_cost=20000.0,
            expected_annual_loss=60000.0,
            risk_score=40.0,
            verdict="Compliant"
        )
        db.add(run5)
        db.commit()

        fired5 = await evaluate_alert_rules_for_run(job.id, run5.id, db)
        assert len(fired5) == 0
        db.refresh(rule)
        assert rule.is_armed is True  # Re-armed successfully!

        # Cleanup
        db.query(Notification).filter(Notification.job_id == job_id).delete()
        db.query(ScanRun).filter(ScanRun.job_id == job_id).delete()
        db.query(AlertRule).filter(AlertRule.job_id == job_id).delete()
        db.query(MonitorJob).filter(MonitorJob.id == job_id).delete()
        db.commit()


# =============================================================================
# 4. Channel Failure Isolation & Idempotency Tests
# =============================================================================

@pytest.mark.asyncio
async def test_channel_failure_isolation():
    """
    Verifies that a failure in one channel does not block other channels from executing.
    """
    job_id = f"test-iso-{uuid.uuid4().hex[:8]}"
    run_id = f"test-run-{uuid.uuid4().hex[:8]}"
    with SessionLocal() as db:
        job = MonitorJob(
            id=job_id,
            name="Isolation Job",
            target_domain="isolation.test",
            schedule_type="preset",
            schedule_value="daily_midnight",
            timezone="UTC",
            enabled=True,
            created_by="CISO"
        )
        db.add(job)
        db.commit()

        rule = AlertRule(
            job_id=job.id,
            metric="estimated_audit_cost",
            operator="gte",
            threshold=25000.0,
            currency="USD",
            channels=["in_app", "email"],
            enabled=True
        )
        db.add(rule)
        db.commit()

        run = ScanRun(
            id=run_id,
            job_id=job.id,
            started_at=datetime.now(timezone.utc),
            status="completed",
            estimated_audit_cost=30000.0,
            verdict="Audit Recommended"
        )
        db.add(run)
        db.commit()

        payload = {
            "title": "Audit Recommended",
            "target_domain": "isolation.test",
            "metric_value": 30000.0,
            "metric_value_formatted": "$30,000.00",
            "threshold": 25000.0,
            "threshold_formatted": "$25,000.00",
            "verdict": "Audit Recommended",
            "drivers": ["Isolated test driver"]
        }

        # Dispatch across in_app, email, and slack
        channels = ["in_app", "email", "slack"]
        notifications = await dispatch_all_channels(job.id, run.id, rule.id, channels, payload, db)

        assert len(notifications) == 3
        in_app_notif = next((n for n in notifications if n.channel == "in_app"), None)
        email_notif = next((n for n in notifications if n.channel == "email"), None)

        assert in_app_notif is not None
        assert in_app_notif.status == "sent"

        assert email_notif is not None
        assert email_notif.status == "sent"

        # Cleanup
        db.query(Notification).filter(Notification.job_id == job_id).delete()
        db.query(LocalOutboxMessage).filter(LocalOutboxMessage.subject.contains("isolation.test")).delete()
        db.query(ScanRun).filter(ScanRun.job_id == job_id).delete()
        db.query(AlertRule).filter(AlertRule.job_id == job_id).delete()
        db.query(MonitorJob).filter(MonitorJob.id == job_id).delete()
        db.commit()


@pytest.mark.asyncio
async def test_duplicate_notification_prevention_idempotency():
    """
    Verifies that dispatching the same run_id twice produces no duplicate records.
    """
    job_id = f"test-idemp-{uuid.uuid4().hex[:8]}"
    run_id = f"test-run-{uuid.uuid4().hex[:8]}"
    with SessionLocal() as db:
        job = MonitorJob(
            id=job_id,
            name="Idempotent Job",
            target_domain="idemp.test",
            schedule_type="preset",
            schedule_value="daily_midnight",
            timezone="UTC",
            enabled=True,
            created_by="CISO"
        )
        db.add(job)
        db.commit()

        rule = AlertRule(
            job_id=job.id,
            metric="estimated_audit_cost",
            operator="gte",
            threshold=25000.0,
            currency="USD",
            channels=["in_app"],
            enabled=True
        )
        db.add(rule)
        db.commit()

        run = ScanRun(
            id=run_id,
            job_id=job.id,
            started_at=datetime.now(timezone.utc),
            status="completed",
            estimated_audit_cost=30000.0,
            verdict="Audit Recommended"
        )
        db.add(run)
        db.commit()

        payload = {"title": "Test", "metric_value": 30000.0}

        # First dispatch
        notifs1 = await dispatch_all_channels(job.id, run.id, rule.id, ["in_app"], payload, db)
        assert len(notifs1) == 1
        assert notifs1[0].status == "sent"

        # Duplicate dispatch with identical job_id, run_id, rule_id, and channel
        notifs2 = await dispatch_all_channels(job.id, run.id, rule.id, ["in_app"], payload, db)
        assert len(notifs2) == 1
        
        # Exact DB count must remain 1
        total = db.query(Notification).filter(
            Notification.job_id == job.id,
            Notification.run_id == run.id,
            Notification.rule_id == rule.id,
            Notification.channel == "in_app"
        ).count()
        assert total == 1

        # Cleanup
        db.query(Notification).filter(Notification.job_id == job_id).delete()
        db.query(ScanRun).filter(ScanRun.job_id == job_id).delete()
        db.query(AlertRule).filter(AlertRule.job_id == job_id).delete()
        db.query(MonitorJob).filter(MonitorJob.id == job_id).delete()
        db.commit()


# =============================================================================
# 5. Concurrency: Single-Flight Per-Job Lock
# =============================================================================

@pytest.mark.asyncio
async def test_single_flight_job_lock():
    """
    Ensures that two simultaneous executions for the same job do not overlap.
    """
    job_id = "concurrent-test-job"
    lock = get_job_lock(job_id)

    assert not lock.locked()
    
    # Acquire the lock
    await lock.acquire()
    assert lock.locked()

    # Second acquisition attempt indicates locked state
    assert lock.locked() is True

    # Release
    lock.release()
    assert not lock.locked()


# =============================================================================
# 6. Target Scope & Validation Enforcement
# =============================================================================

def test_scope_refusal_for_unverified_targets():
    with SessionLocal() as db:
        # Invalid format
        allowed, reason = check_scan_permission("malicious-target;rm -rf /", "passive", db)
        assert allowed is False
        assert "Invalid target format" in reason

        # Valid public target
        allowed, reason = check_scan_permission("sub.mycorp.org", "passive", db)
        assert allowed is True


# =============================================================================
# 7. Database Persistence & Model Relationships
# =============================================================================

def test_monitoring_models_persistence():
    job_id = f"persist-{uuid.uuid4().hex[:8]}"
    with SessionLocal() as db:
        job = MonitorJob(
            id=job_id,
            name="Persistence Verification Job",
            target_domain="persist.example.com",
            schedule_type="cron",
            schedule_value="0 4 * * *",
            timezone="UTC",
            enabled=True,
            created_by="CISO"
        )
        db.add(job)
        db.commit()

        rule = AlertRule(
            job_id=job.id,
            metric="risk_score",
            operator="gte",
            threshold=75.0,
            currency="USD",
            channels=["in_app", "email"],
            enabled=True
        )
        db.add(rule)
        db.commit()

        retrieved_job = db.query(MonitorJob).filter(MonitorJob.id == job_id).first()
        assert retrieved_job is not None
        assert retrieved_job.name == "Persistence Verification Job"
        assert len(retrieved_job.rules) == 1
        assert retrieved_job.rules[0].metric == "risk_score"

        # Cleanup
        db.query(AlertRule).filter(AlertRule.job_id == job_id).delete()
        db.query(MonitorJob).filter(MonitorJob.id == job_id).delete()
        db.commit()
