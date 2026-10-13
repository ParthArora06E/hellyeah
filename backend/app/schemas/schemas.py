"""
Pydantic Schemas for Request/Response validation across Auditor platform.
"""
from datetime import datetime
from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field

# --- Scan Schemas ---
class ScanCreateRequest(BaseModel):
    target_domain: str = Field(..., description="Target domain or hostname e.g. example.com")
    company_name: Optional[str] = Field(None, description="Optional company name for reporting")
    mode: str = Field("passive", description="Scan mode: 'passive' or 'active'")
    manual_assets: Optional[List[str]] = Field(default=[], description="List of manually added domains or IPs")
    run_plugins: bool = Field(True, description="Whether to execute drop-in plugins from plugins/")

class ScanResponse(BaseModel):
    id: str
    target_domain: str
    company_name: Optional[str]
    mode: str
    status: str
    progress: int
    current_step: str
    total_assets: int
    total_findings: int
    risk_score: float
    total_fix_cost: float
    potential_breach_loss: float
    roi_percentage: float
    summary_notes: Optional[str]
    created_at: datetime
    completed_at: Optional[datetime]

    class Config:
        from_attributes = True

# --- Asset Schemas ---
class AssetBase(BaseModel):
    type: str = Field(..., description="subdomain, ip, service, bucket, endpoint")
    value: str
    source: str = "automated"
    owner: str = "Unassigned"
    criticality: int = Field(3, ge=1, le=5)
    ip_address: Optional[str] = None
    asn: Optional[str] = None
    technologies: List[str] = []
    ports: List[int] = []
    tags: List[str] = []
    raw_metadata: Dict[str, Any] = {}

class AssetCreate(AssetBase):
    scan_id: str

class AssetUpdate(BaseModel):
    owner: Optional[str] = None
    criticality: Optional[int] = Field(None, ge=1, le=5)
    tags: Optional[List[str]] = None

class AssetResponse(AssetBase):
    id: int
    scan_id: str
    first_seen: datetime
    last_seen: datetime

    class Config:
        from_attributes = True

# --- Finding Schemas ---
class FindingBase(BaseModel):
    title: str
    description: str
    severity: str  # Critical, High, Medium, Low, Info
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    is_kev: bool = False
    cve_ids: List[str] = []
    cpe: Optional[str] = None
    source: str = "automated"
    confidence: str = "High"
    status: str = "Open"
    evidence: Dict[str, Any] = {}
    remediation_text: Optional[str] = None
    references: List[str] = []
    owasp_category: Optional[str] = None
    iso_control: Optional[str] = None
    fix_hours_dev: float = 0.5
    fix_hours_tester: float = 0.25
    estimated_fix_cost: float = 58.75
    risk_score: float = 0.0

class FindingCreate(FindingBase):
    scan_id: str
    asset_id: Optional[int] = None

class FindingStatusUpdate(BaseModel):
    status: str = Field(..., description="Open, Fixed, or Accepted Risk")

class FindingResponse(FindingBase):
    id: int
    scan_id: str
    asset_id: Optional[int]
    created_at: datetime

    class Config:
        from_attributes = True

# --- Cost & Analytics Schemas ---
class CostCalculationRequest(BaseModel):
    dev_rate: float = Field(85.0, description="Developer hourly rate ($/hr)")
    tester_rate: float = Field(65.0, description="QA Tester hourly rate ($/hr)")
    currency: str = Field("USD", description="Currency code")
    asset_value: float = Field(250000.0, description="Estimated commercial value of asset/application")
    records_count: int = Field(50000, description="Customer or sensitive records stored")
    scenario: str = Field("both", description="'dev_only' or 'both'")

class CostSummaryResponse(BaseModel):
    total_fix_cost_dev_only: float
    total_fix_cost_both: float
    total_potential_breach_loss: float
    roi_dev_only: float
    roi_both: float
    currency: str
    severity_breakdown: Dict[str, Dict[str, float]]
    top_cost_findings: List[Dict[str, Any]]
    explanation: str
    damage_breakdown: Optional[Dict[str, float]] = None
    active_fix_cost: Optional[float] = None
    active_roi: Optional[float] = None
    total_dev_hours: Optional[float] = None
    total_tester_hours: Optional[float] = None


# --- SSE Event Schema ---
class ScanLogEvent(BaseModel):
    scan_id: str
    timestamp: str
    level: str  # info, good, warn, error
    message: str
    step: Optional[str] = None
    progress: Optional[int] = None


# --- Scheduled Monitoring & Alert Schemas ---

class AlertRuleBase(BaseModel):
    metric: str = Field("estimated_audit_cost", description="estimated_audit_cost, expected_annual_loss, risk_score, new_critical_findings, verdict_change")
    operator: str = Field("gte", description="gt, gte, lt, lte, eq, ne")
    threshold: float = Field(25000.0, description="Threshold limit value")
    currency: str = Field("USD", description="Currency code")
    cooldown_minutes: int = Field(60, description="Cooldown interval in minutes")
    rearm_ratio: float = Field(0.9, description="Hysteresis factor to re-arm (default 0.9 * threshold)")
    channels: List[str] = Field(default=["in_app", "email", "slack"], description="Notification channels")
    enabled: bool = Field(True, description="Rule active toggle")

class AlertRuleCreate(AlertRuleBase):
    job_id: str

class AlertRuleResponse(AlertRuleBase):
    id: int
    job_id: str
    is_armed: bool = True
    last_fired_at: Optional[datetime] = None
    last_value: Optional[float] = None
    created_at: datetime

    class Config:
        from_attributes = True

class MonitorJobCreate(BaseModel):
    name: str = Field(..., description="Job title, e.g. Production Perimeter Daily")
    target_domain: str = Field(..., description="Apex domain or target host")
    scope: Optional[List[str]] = Field(default=[], description="Extra domains or IPs in scope")
    schedule_type: str = Field("preset", description="preset | cron")
    schedule_value: str = Field("daily", description="daily, weekly, monthly, demo_30s, or cron expression e.g. '0 3 * * *'")
    timezone: str = Field("UTC", description="Target timezone e.g. UTC, America/New_York")
    scan_mode: str = Field("passive", description="passive (default) | active")
    created_by: str = Field("CISO", description="Creator identity or role")
    # Quick inline threshold & channels setup
    threshold: Optional[float] = Field(25000.0, description="Initial cost threshold limit")
    metric: Optional[str] = Field("estimated_audit_cost", description="Primary threshold metric")
    channels: Optional[List[str]] = Field(default=["in_app", "email", "slack"], description="Active channels")

class MonitorJobUpdate(BaseModel):
    name: Optional[str] = None
    schedule_type: Optional[str] = None
    schedule_value: Optional[str] = None
    timezone: Optional[str] = None
    enabled: Optional[bool] = None
    scan_mode: Optional[str] = None
    scope: Optional[List[str]] = None

class ScanRunResponse(BaseModel):
    id: str
    job_id: str
    scan_id: Optional[str] = None
    started_at: datetime
    finished_at: Optional[datetime] = None
    status: str
    assets_count: int = 0
    findings_summary: Dict[str, Any] = {}
    estimated_audit_cost: float = 0.0
    expected_annual_loss: float = 0.0
    risk_score: float = 0.0
    verdict: str = "Compliant"
    diff_vs_previous: Dict[str, Any] = {}
    error: Optional[str] = None

    class Config:
        from_attributes = True

class MonitorJobResponse(BaseModel):
    id: str
    name: str
    target_domain: str
    scope: List[str] = []
    schedule_type: str
    schedule_value: str
    timezone: str
    enabled: bool
    next_run: Optional[datetime] = None
    last_run: Optional[datetime] = None
    last_status: str
    scan_mode: str
    created_by: str
    created_at: datetime
    rules: List[AlertRuleResponse] = []
    latest_run: Optional[ScanRunResponse] = None

    class Config:
        from_attributes = True

class NotificationResponse(BaseModel):
    id: int
    job_id: str
    run_id: Optional[str] = None
    rule_id: Optional[int] = None
    channel: str
    status: str
    payload: Dict[str, Any] = {}
    sent_at: datetime
    read_at: Optional[datetime] = None
    error: Optional[str] = None
    retry_count: int = 0

    class Config:
        from_attributes = True

class ChannelConfigCreate(BaseModel):
    name: str
    type: str  # email, slack, telegram, webhook, in_app
    config: Dict[str, Any] = {}
    enabled: bool = True

class ChannelConfigResponse(BaseModel):
    id: int
    owner_id: str
    name: str
    type: str
    config: Dict[str, Any] = {}
    verified: bool = False
    enabled: bool = True
    created_at: datetime

    class Config:
        from_attributes = True

