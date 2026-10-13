"""
Unit Tests for:
1. Scan Differential & Asset Drift Engine (Feature 4)
2. CMS & Modern Framework Detection Module (Feature 5)
3. Reverse IP & Shared Hosting Inspector (Feature 5)
4. Custom Declarative Detection Rules Engine (Feature 5)
"""
import pytest
from datetime import datetime, timezone
from backend.app.db.models import Scan, Asset, Finding
from backend.app.analytics.diff_engine import compute_scan_diff
from backend.app.vuln.custom_rules_engine import (
    CustomRule, execute_custom_rules, get_all_custom_rules, add_custom_rule
)


def test_scan_diff_calculation():
    # Setup Mock Scan 1 (Earlier)
    scan_prev = Scan(
        id="scan-001",
        target_domain="example.com",
        created_at=datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc),
        risk_score=75.0,
        potential_breach_loss=500000.0,
        total_fix_cost=1200.0
    )
    asset_p1 = Asset(id=1, type="subdomain", value="api.example.com", ip_address="1.2.3.4", technologies=["Nginx 1.18.0"])
    asset_p2 = Asset(id=2, type="subdomain", value="legacy.example.com", ip_address="1.2.3.5", technologies=[])
    scan_prev.assets = [asset_p1, asset_p2]

    finding_p1 = Finding(id=101, title="Apache RCE", severity="Critical", cvss_score=9.8, cve_ids=["CVE-2021-41773"])
    finding_p2 = Finding(id=102, title="Missing HSTS", severity="Medium", cvss_score=5.4, cve_ids=[])
    scan_prev.findings = [finding_p1, finding_p2]

    # Setup Mock Scan 2 (Current, after remediation and adding new app)
    scan_curr = Scan(
        id="scan-002",
        target_domain="example.com",
        created_at=datetime(2026, 10, 10, 10, 0, tzinfo=timezone.utc),
        risk_score=45.0,  # Improved!
        potential_breach_loss=150000.0,  # Dropped!
        total_fix_cost=600.0
    )
    asset_c1 = Asset(id=10, type="subdomain", value="api.example.com", ip_address="1.2.3.4", technologies=["Nginx 1.24.0"])
    asset_c3 = Asset(id=11, type="subdomain", value="portal.example.com", ip_address="1.2.3.6", technologies=["Next.js", "React"])
    # legacy.example.com decommissioned, portal.example.com added!
    scan_curr.assets = [asset_c1, asset_c3]

    # CVE-2021-41773 patched! But new weak CORS finding introduced.
    finding_c2 = Finding(id=201, title="Missing HSTS", severity="Medium", cvss_score=5.4, cve_ids=[])
    finding_c3 = Finding(id=202, title="Permissive CORS Policy", severity="Low", cvss_score=3.7, cve_ids=[])
    scan_curr.findings = [finding_c2, finding_c3]

    diff = compute_scan_diff(scan_curr, scan_prev)

    assert diff["has_previous_scan"] is True
    # Deltas
    assert diff["deltas"]["risk_score_delta"] == -30.0
    assert diff["deltas"]["loss_delta"] == -350000.0
    assert diff["deltas"]["posture_status"] == "Improved"
    assert "improved" in diff["deltas"]["posture_verdict"].lower()

    # Asset drift
    assert diff["asset_drift"]["new_count"] == 1
    assert diff["asset_drift"]["new_assets"][0]["value"] == "portal.example.com"
    assert diff["asset_drift"]["decommissioned_count"] == 1
    assert diff["asset_drift"]["decommissioned_assets"][0]["value"] == "legacy.example.com"
    assert diff["asset_drift"]["persistent_count"] == 1

    # Finding drift
    # Resolved: Apache RCE (CVE-2021-41773)
    assert diff["finding_drift"]["resolved_count"] == 1
    assert diff["finding_drift"]["resolved_findings"][0]["cve_ids"] == ["CVE-2021-41773"]
    # New: Permissive CORS
    assert diff["finding_drift"]["new_count"] == 1
    assert "CORS" in diff["finding_drift"]["new_findings"][0]["title"]
    # Persistent: Missing HSTS
    assert diff["finding_drift"]["persistent_count"] == 1
    assert "HSTS" in diff["finding_drift"]["persistent_findings"][0]["title"]


def test_custom_rule_engine_catalog():
    rules = get_all_custom_rules()
    assert len(rules) >= 5
    rule_ids = [r["id"] for r in rules]
    assert "sec-txt-rfc9116" in rule_ids
    assert "prometheus-metrics-exposed" in rule_ids
    assert "minio-storage-console" in rule_ids

    # Add custom rule
    new_rule_payload = {
        "id": "custom-test-rule",
        "name": "Test Internal Admin Header",
        "severity": "High",
        "cvss": 7.0,
        "path": "/admin",
        "matcher_type": "status_code",
        "matcher_pattern": "200",
        "description": "Admin portal open without basic auth",
        "remediation": "Restrict /admin with IP allowlist"
    }
    added = add_custom_rule(new_rule_payload)
    assert added["id"] == "custom-test-rule"
    assert added["severity"] == "High"


def test_api_rescan_and_simulate_drift(monkeypatch):
    from fastapi.testclient import TestClient
    from backend.app.main import app
    from backend.app.db.session import SessionLocal
    from backend.app.db.models import Scan, Asset, Finding
    import uuid

    # Mock background scan pipeline to complete instantly in unit test
    monkeypatch.setattr("backend.app.api.scans.run_scan_pipeline", lambda **kw: None)

    client = TestClient(app)
    db = SessionLocal()

    # Create baseline scan
    base_id = str(uuid.uuid4())
    base_scan = Scan(
        id=base_id,
        target_domain="drift-test.org",
        company_name="Drift Test Org",
        mode="passive",
        status="completed",
        risk_score=78.0,
        total_findings=2,
        total_assets=1
    )
    db.add(base_scan)
    db.commit()

    asset1 = Asset(scan_id=base_id, type="domain", value="drift-test.org")
    db.add(asset1)
    f1 = Finding(scan_id=base_id, title="Missing Content Security Policy (CSP)", description="CSP header missing", severity="Medium", cvss_score=5.0)
    f2 = Finding(scan_id=base_id, title="Open SSH Port 22", description="SSH port exposed publicly", severity="High", cvss_score=7.5)
    db.add(f1)
    db.add(f2)
    db.commit()

    try:
        # Test 1: POST /api/scans/{id}/rescan
        res_rescan = client.post(f"/api/scans/{base_id}/rescan")
        assert res_rescan.status_code == 200
        rescan_data = res_rescan.json()
        assert rescan_data["target_domain"] == "drift-test.org"
        assert rescan_data["status"] == "queued"
        assert rescan_data["id"] != base_id

        # Test 2: POST /api/scans/{id}/simulate-drift
        res_drift = client.post(f"/api/scans/{base_id}/simulate-drift")
        assert res_drift.status_code == 200
        drift_data = res_drift.json()
        assert drift_data["target_domain"] == "drift-test.org"
        assert drift_data["status"] == "completed"
        assert drift_data["resolved_findings_count"] >= 1
        assert drift_data["risk_score"] < base_scan.risk_score
        drift_scan_id = drift_data["id"]

        # Test 3: GET /api/scans/{drift_scan_id}/diff
        res_diff = client.get(f"/api/scans/{drift_scan_id}/diff")
        assert res_diff.status_code == 200
        diff_payload = res_diff.json()
        assert diff_payload["has_previous_scan"] is True
        assert diff_payload["deltas"]["posture_status"] == "Improved"
        assert diff_payload["finding_drift"]["resolved_count"] >= 1
        assert diff_payload["asset_drift"]["new_count"] >= 1
    finally:
        db.close()
