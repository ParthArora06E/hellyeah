"""
Database Models for Auditor Platform
Entities: Scan, Asset, Finding, AuditLog, CostConfig
"""
from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, Text, DateTime, ForeignKey, JSON
)
from sqlalchemy.orm import relationship
from .session import Base

def now_utc():
    return datetime.now(timezone.utc)

class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, index=True)
    target_domain = Column(String(255), nullable=False, index=True)
    company_name = Column(String(255), nullable=True)
    mode = Column(String(50), default="passive")  # passive, active
    status = Column(String(50), default="queued")  # queued, running, completed, failed
    progress = Column(Integer, default=0)
    current_step = Column(String(255), default="Initialized")
    total_assets = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)
    total_fix_cost = Column(Float, default=0.0)
    potential_breach_loss = Column(Float, default=0.0)
    roi_percentage = Column(Float, default=0.0)
    summary_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=now_utc)
    completed_at = Column(DateTime, nullable=True)

    assets = relationship("Asset", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    logs = relationship("AuditLog", back_populates="scan", cascade="all, delete-orphan")

class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    type = Column(String(50), nullable=False)  # domain, subdomain, ip, service, bucket, endpoint
    value = Column(String(512), nullable=False, index=True)
    source = Column(String(100), default="unknown")
    owner = Column(String(255), default="Unassigned")
    criticality = Column(Integer, default=3)  # 1 to 5
    ip_address = Column(String(100), nullable=True)
    asn = Column(String(100), nullable=True)
    technologies = Column(JSON, default=list)  # e.g. ["Nginx 1.18.0", "PHP 7.4.3"]
    ports = Column(JSON, default=list)  # e.g. [80, 443]
    tags = Column(JSON, default=list)
    raw_metadata = Column(JSON, default=dict)
    first_seen = Column(DateTime, default=now_utc)
    last_seen = Column(DateTime, default=now_utc)

    scan = relationship("Scan", back_populates="assets")
    findings = relationship("Finding", back_populates="asset", cascade="all, delete-orphan")

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(50), nullable=False)  # Critical, High, Medium, Low, Info
    cvss_score = Column(Float, nullable=True)
    epss_score = Column(Float, nullable=True)
    is_kev = Column(Boolean, default=False)
    cve_ids = Column(JSON, default=list)
    cpe = Column(String(255), nullable=True)
    source = Column(String(100), default="automated")
    confidence = Column(String(50), default="High")  # Confirmed, High, Medium, Low
    status = Column(String(50), default="Open")  # Open, Fixed, Accepted Risk
    evidence = Column(JSON, default=dict)
    remediation_text = Column(Text, nullable=True)
    remediation_patch = Column(Text, nullable=True)
    verified_at = Column(DateTime, nullable=True)
    verification_notes = Column(Text, nullable=True)
    synced_issue_url = Column(String(512), nullable=True)
    synced_issue_id = Column(String(100), nullable=True)
    references = Column(JSON, default=list)
    owasp_category = Column(String(100), nullable=True)
    iso_control = Column(String(100), nullable=True)
    fix_hours_dev = Column(Float, default=0.5)
    fix_hours_tester = Column(Float, default=0.25)
    estimated_fix_cost = Column(Float, default=58.75)
    risk_score = Column(Float, default=0.0)
    created_at = Column(DateTime, default=now_utc)

    scan = relationship("Scan", back_populates="findings")
    asset = relationship("Asset", back_populates="findings")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=True, index=True)
    action = Column(String(100), nullable=False)  # DNS_LOOKUP, HTTP_GET, SHODAN_QUERY
    target = Column(String(512), nullable=False)
    details = Column(Text, nullable=True)
    status_code = Column(Integer, nullable=True)
    timestamp = Column(DateTime, default=now_utc)

    scan = relationship("Scan", back_populates="logs")


class CostConfig(Base):
    __tablename__ = "cost_configs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    dev_rate = Column(Float, default=85.0)
    tester_rate = Column(Float, default=65.0)
    currency = Column(String(10), default="USD")
    industry = Column(String(100), default="Technology / SaaS")
    asset_value = Column(Float, default=250000.0)
    records_count = Column(Integer, default=50000)
    updated_at = Column(DateTime, default=now_utc)


# =============================================================================
# Scheduled Monitoring & Cost-Threshold Alert Entities
# =============================================================================

class MonitorJob(Base):
    __tablename__ = "monitor_jobs"

    id = Column(String(36), primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    target_domain = Column(String(255), nullable=False, index=True)
    scope = Column(JSON, default=list)  # Additional subdomains, IPs, or assets in scope
    schedule_type = Column(String(50), default="preset")  # preset | cron
    schedule_value = Column(String(100), default="daily")  # daily, weekly, monthly, demo_30s, or "0 3 * * *"
    timezone = Column(String(100), default="UTC")
    enabled = Column(Boolean, default=True)
    next_run = Column(DateTime, nullable=True)
    last_run = Column(DateTime, nullable=True)
    last_status = Column(String(50), default="idle")  # idle, running, completed, failed, paused
    scan_mode = Column(String(50), default="passive")  # passive (default) | active
    created_by = Column(String(100), default="CISO")
    created_at = Column(DateTime, default=now_utc)

    rules = relationship("AlertRule", back_populates="job", cascade="all, delete-orphan")
    runs = relationship("ScanRun", back_populates="job", cascade="all, delete-orphan")
    notifications = relationship("Notification", back_populates="job", cascade="all, delete-orphan")


class AlertRule(Base):
    __tablename__ = "alert_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String(36), ForeignKey("monitor_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    metric = Column(String(100), default="estimated_audit_cost")  # estimated_audit_cost | expected_annual_loss | risk_score | new_critical_findings | verdict_change
    operator = Column(String(20), default="gte")  # gt, gte, lt, lte, eq, ne
    threshold = Column(Float, nullable=False, default=25000.0)
    currency = Column(String(10), default="USD")
    cooldown_minutes = Column(Integer, default=60)
    rearm_ratio = Column(Float, default=0.9)  # Hysteresis threshold factor
    channels = Column(JSON, default=lambda: ["in_app", "email", "slack"])
    is_armed = Column(Boolean, default=True)  # True if armed to fire on next upward crossing
    last_fired_at = Column(DateTime, nullable=True)
    last_value = Column(Float, nullable=True)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=now_utc)

    job = relationship("MonitorJob", back_populates="rules")
    notifications = relationship("Notification", back_populates="rule")


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(String(36), primary_key=True, index=True)
    job_id = Column(String(36), ForeignKey("monitor_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(String(36), nullable=True)  # Associated core scan id if generated
    started_at = Column(DateTime, default=now_utc)
    finished_at = Column(DateTime, nullable=True)
    status = Column(String(50), default="running")  # running, completed, failed
    assets_count = Column(Integer, default=0)
    findings_summary = Column(JSON, default=dict)  # {"critical": 1, "high": 2, "medium": 3, "kev": 1}
    estimated_audit_cost = Column(Float, default=0.0)
    expected_annual_loss = Column(Float, default=0.0)
    risk_score = Column(Float, default=0.0)
    verdict = Column(String(100), default="Compliant")  # "Audit Recommended", "Elevated Risk", "Compliant"
    diff_vs_previous = Column(JSON, default=dict)  # {"new_assets": [...], "removed_assets": [...], "new_cves": [...]}
    error = Column(Text, nullable=True)

    job = relationship("MonitorJob", back_populates="runs")
    notifications = relationship("Notification", back_populates="run", cascade="all, delete-orphan")


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String(36), ForeignKey("monitor_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    run_id = Column(String(36), ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=True, index=True)
    rule_id = Column(Integer, ForeignKey("alert_rules.id", ondelete="SET NULL"), nullable=True, index=True)
    channel = Column(String(50), nullable=False)  # in_app | email | slack | telegram | webhook
    status = Column(String(50), default="queued")  # queued | sent | failed
    payload = Column(JSON, default=dict)  # {title, metric, limit, verdict, drivers, report_link}
    sent_at = Column(DateTime, default=now_utc)
    read_at = Column(DateTime, nullable=True)
    error = Column(Text, nullable=True)
    retry_count = Column(Integer, default=0)

    job = relationship("MonitorJob", back_populates="notifications")
    run = relationship("ScanRun", back_populates="notifications")
    rule = relationship("AlertRule", back_populates="notifications")


class ChannelConfig(Base):
    __tablename__ = "channel_configs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    owner_id = Column(String(100), default="default")
    name = Column(String(255), nullable=False)
    type = Column(String(50), nullable=False)  # email | slack | telegram | webhook | in_app
    config = Column(JSON, default=dict)  # recipients, webhook_url, chat_id, auth_token (encrypted)
    verified = Column(Boolean, default=False)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=now_utc)


class LocalOutboxMessage(Base):
    """
    Local outbox for offline demo and verification:
    Captures emails and Slack webhooks when running in demo mode or without live credentials.
    """
    __tablename__ = "local_outbox_messages"

    id = Column(Integer, primary_key=True, autoincrement=True)
    channel = Column(String(50), nullable=False)  # email | slack | webhook
    recipient = Column(String(512), nullable=False)
    subject = Column(String(255), nullable=True)
    body = Column(Text, nullable=False)
    payload = Column(JSON, default=dict)
    created_at = Column(DateTime, default=now_utc)


class IssueSyncConfig(Base):
    __tablename__ = "issue_sync_configs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    provider = Column(String(50), nullable=False)  # github | jira
    repo_or_project = Column(String(255), nullable=False)
    api_token_encrypted = Column(Text, nullable=True)
    base_url = Column(String(512), nullable=True)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=now_utc)


class User(Base):
    """
    User Account model supporting Standard vs Pro role tiers
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=False, default="Analyst")
    role = Column(String(50), default="standard", nullable=False)  # "standard" | "pro" | "admin"
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=now_utc)
    last_login = Column(DateTime, nullable=True)


