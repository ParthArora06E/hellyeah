"""
ScanContext: Runtime environment passed to modules during execution.
Handles live SSE event emitting, database persistence, and audit logging.
"""
from typing import Callable, Optional, List, Dict, Any
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from ...schemas.schemas import AssetBase, FindingBase
from ...db.models import Asset, Finding, AuditLog
from .http_client import AsyncHttpClient

class ScanContext:
    def __init__(
        self,
        scan_id: str,
        target_domain: str,
        mode: str,
        db: Session,
        event_callback: Optional[Callable[[str, str, Optional[int], Optional[str]], None]] = None
    ):
        self.scan_id = scan_id
        self.target_domain = target_domain
        self.mode = mode
        self.db = db
        self.event_callback = event_callback
        self.http = AsyncHttpClient()
        self.discovered_assets: List[Asset] = []
        self.discovered_findings: List[Finding] = []

    def emit_log(self, level: str, message: str, progress: Optional[int] = None, step: Optional[str] = None):
        """
        Emits a log event to connected SSE clients.
        levels: info, good, warn, error
        """
        if self.event_callback:
            self.event_callback(level, message, progress, step)

    def log_audit(self, action: str, target: str, details: Optional[str] = None, status_code: Optional[int] = None):
        """
        Records an outbound probe or external query in the immutable audit log table.
        """
        try:
            entry = AuditLog(
                scan_id=self.scan_id,
                action=action,
                target=target,
                details=details,
                status_code=status_code,
                timestamp=datetime.now(timezone.utc)
            )
            self.db.add(entry)
            self.db.commit()
        except Exception:
            self.db.rollback()

    def record_asset(self, asset_data: AssetBase) -> Optional[Asset]:
        """
        Inserts or merges an asset in the database.
        """
        try:
            # Check existing asset for this scan
            existing = self.db.query(Asset).filter(
                Asset.scan_id == self.scan_id,
                Asset.value == asset_data.value
            ).first()

            if existing:
                # Merge technologies and ports
                existing.technologies = list(set(existing.technologies + asset_data.technologies))
                existing.ports = list(set(existing.ports + asset_data.ports))
                existing.tags = list(set(existing.tags + asset_data.tags))
                existing.last_seen = datetime.now(timezone.utc)
                if asset_data.ip_address:
                    existing.ip_address = asset_data.ip_address
                if asset_data.asn:
                    existing.asn = asset_data.asn
                self.db.commit()
                self.db.refresh(existing)
                return existing
            else:
                new_asset = Asset(
                    scan_id=self.scan_id,
                    type=asset_data.type,
                    value=asset_data.value,
                    source=asset_data.source,
                    owner=asset_data.owner,
                    criticality=asset_data.criticality,
                    ip_address=asset_data.ip_address,
                    asn=asset_data.asn,
                    technologies=asset_data.technologies,
                    ports=asset_data.ports,
                    tags=asset_data.tags,
                    raw_metadata=asset_data.raw_metadata,
                    first_seen=datetime.now(timezone.utc),
                    last_seen=datetime.now(timezone.utc)
                )
                self.db.add(new_asset)
                self.db.commit()
                self.db.refresh(new_asset)
                self.discovered_assets.append(new_asset)
                return new_asset
        except Exception as e:
            self.db.rollback()
            self.emit_log("warn", f"Failed to persist asset {asset_data.value}: {e}")
            return None

    def record_finding(self, finding_data: FindingBase, asset_id: Optional[int] = None) -> Optional[Finding]:
        """
        Inserts or merges a vulnerability finding.
        """
        try:
            existing = self.db.query(Finding).filter(
                Finding.scan_id == self.scan_id,
                Finding.title == finding_data.title
            ).first()
            if existing:
                return existing

            new_finding = Finding(
                scan_id=self.scan_id,
                asset_id=asset_id,
                title=finding_data.title,
                description=finding_data.description,
                severity=finding_data.severity,
                cvss_score=finding_data.cvss_score,
                epss_score=finding_data.epss_score,
                is_kev=finding_data.is_kev,
                cve_ids=finding_data.cve_ids,
                cpe=finding_data.cpe,
                source=finding_data.source,
                confidence=finding_data.confidence,
                status=finding_data.status,
                evidence=finding_data.evidence,
                remediation_text=finding_data.remediation_text,
                references=finding_data.references,
                owasp_category=finding_data.owasp_category,
                iso_control=finding_data.iso_control,
                fix_hours_dev=finding_data.fix_hours_dev,
                fix_hours_tester=finding_data.fix_hours_tester,
                estimated_fix_cost=finding_data.estimated_fix_cost,
                risk_score=finding_data.risk_score,
                created_at=datetime.now(timezone.utc)
            )
            self.db.add(new_finding)
            self.db.commit()
            self.db.refresh(new_finding)
            self.discovered_findings.append(new_finding)
            return new_finding
        except Exception as e:
            self.db.rollback()
            self.emit_log("warn", f"Failed to persist finding {finding_data.title}: {e}")
            return None
