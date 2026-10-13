import uuid
import pytest
from datetime import datetime, timezone

from backend.app.db.session import SessionLocal
from backend.app.db.models import Scan, Asset, Finding
from backend.app.compliance.dpdp_engine import evaluate_dpdp_compliance
from backend.app.compliance.compliance_mapper import map_all_compliance_frameworks
from backend.app.analytics.insurance_engine import evaluate_cyber_insurability
from backend.app.analytics.attack_path_engine import generate_attack_path_graph
from backend.app.remediation.patch_generator import generate_remediation_patch
from backend.app.remediation.verifier import verify_finding_fix
from backend.app.vuln.sbom_engine import (
    generate_sbom_for_scan,
    export_cyclonedx_json,
    export_spdx_json
)
from backend.app.integrations.issue_tracker import sync_finding_to_issue_tracker


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def test_scan_with_data(db_session):
    scan_id = str(uuid.uuid4())
    scan = Scan(
        id=scan_id,
        target_domain="test-compliance.example.com",
        company_name="Acme Corp Test",
        status="completed",
        mode="passive",
        total_assets=2,
        total_findings=2,
        created_at=datetime.now(timezone.utc)
    )
    db_session.add(scan)
    db_session.commit()

    asset1 = Asset(
        scan_id=scan_id,
        type="subdomain",
        value="api.test-compliance.example.com",
        ip_address="104.21.45.67",
        ports=[80, 443],
        technologies=["nginx/1.24.0", "OpenSSL 3.0.2", "React 18.2.0"],
        source="dns_recon",
        first_seen=datetime.now(timezone.utc)
    )
    asset2 = Asset(
        scan_id=scan_id,
        type="subdomain",
        value="db.test-compliance.example.com",
        ip_address="104.21.45.68",
        ports=[3306],  # exposed database
        technologies=["MySQL 8.0"],
        source="port_scanner",
        first_seen=datetime.now(timezone.utc)
    )
    db_session.add_all([asset1, asset2])
    db_session.commit()

    finding1 = Finding(
        scan_id=scan_id,
        asset_id=asset1.id,
        title="Apache HTTP Server Path Traversal & RCE",
        description="Critical weaponized vulnerability allowing arbitrary command execution.",
        severity="Critical",
        cvss_score=9.8,
        epss_score=0.94,
        is_kev=True,
        cve_ids=["CVE-2021-41773"],
        confidence="High",
        fix_hours_dev=4.0,
        fix_hours_tester=2.0,
        estimated_fix_cost=470.0,
        status="Open",
        created_at=datetime.now(timezone.utc)
    )
    finding2 = Finding(
        scan_id=scan_id,
        asset_id=asset1.id,
        title="Missing Strict-Transport-Security Header",
        description="HSTS header missing from perimeter web endpoints.",
        severity="Medium",
        cvss_score=5.3,
        epss_score=0.04,
        is_kev=False,
        cve_ids=[],
        confidence="High",
        fix_hours_dev=1.0,
        fix_hours_tester=0.5,
        estimated_fix_cost=115.0,
        status="Open",
        created_at=datetime.now(timezone.utc)
    )
    db_session.add_all([finding1, finding2])
    db_session.commit()

    yield {
        "scan_id": scan_id,
        "finding1_id": finding1.id,
        "finding2_id": finding2.id
    }

    # Cleanup
    db_session.query(Finding).filter(Finding.scan_id == scan_id).delete()
    db_session.query(Asset).filter(Asset.scan_id == scan_id).delete()
    db_session.query(Scan).filter(Scan.id == scan_id).delete()
    db_session.commit()


def test_remediation_patch_generator():
    finding_dict = {
        "title": "Missing Strict-Transport-Security and CSP Header",
        "description": "Perimeter web server lacks HSTS headers.",
        "cve_ids": []
    }
    patch = generate_remediation_patch(finding_dict)
    assert "nginx_config" in patch
    assert "add_header Strict-Transport-Security" in patch["nginx_config"]
    assert "diff_patch" in patch
    assert "--- nginx.conf.orig" in patch["diff_patch"]
    assert "implementation_guidance" in patch


def test_dpdp_compliance_engine(db_session, test_scan_with_data):
    scan_id = test_scan_with_data["scan_id"]
    result = evaluate_dpdp_compliance(scan_id, db_session)

    assert result["framework"] == "DPDP Act 2023 (Digital Personal Data Protection Act, India)"
    assert "NON-COMPLIANT" in result["compliance_verdict"]
    assert "₹250 Crore" in result["max_statutory_cap_inr"]
    assert "₹" in result["penalty_exposure_inr_formatted"]
    assert "$" in result["penalty_exposure_usd_formatted"]
    assert len(result["controls"]) >= 4

    # Check Section 8(5) safeguard control
    sec_8_5 = next(c for c in result["controls"] if "Section 8(5)" in c.get("statutory_ref", ""))
    assert sec_8_5["status"] == "FAILED"


def test_multi_framework_mapping(db_session, test_scan_with_data):
    scan_id = test_scan_with_data["scan_id"]
    result = map_all_compliance_frameworks(scan_id, db_session)

    assert "frameworks" in result
    frameworks = result["frameworks"]
    assert "dpdp_act_2023" in frameworks
    assert "soc2_type_2" in frameworks
    assert "pci_dss_4" in frameworks
    assert "hipaa" in frameworks
    assert "iso27001" in frameworks

    # Exposed DB port 3306 should cause SOC2 perimeter access boundary control to fail
    soc2 = frameworks["soc2_type_2"]
    assert any(c["control_id"] == "SOC2-CC6.1" and c["status"] == "FAILED" for c in soc2["controls"])


def test_cyber_insurance_readiness(db_session, test_scan_with_data):
    scan_id = test_scan_with_data["scan_id"]
    result = evaluate_cyber_insurability(scan_id, db_session)

    assert "insurability_score" in result
    assert result["insurability_score"] < 70  # Low score due to KEV + Exposed DB
    assert any(term in result["disposition"] for term in ["Conditional", "Substandard", "Decline"])
    assert result["estimated_premium_surcharge_pct"] > 0
    assert len(result["underwriter_warranties"]) >= 4


def test_attack_path_graph(db_session, test_scan_with_data):
    scan_id = test_scan_with_data["scan_id"]
    graph = generate_attack_path_graph(scan_id, db_session)

    assert "nodes" in graph
    assert "edges" in graph
    assert graph["metrics"]["critical_attack_paths"] >= 1
    assert graph["metrics"]["has_weaponized_conduit"] is True

    # Verify node levels
    levels = {n["level"] for n in graph["nodes"]}
    assert 0 in levels  # Apex
    assert 1 in levels  # Subdomain
    assert 3 in levels  # Vulnerability


def test_remediation_verifier(db_session, test_scan_with_data):
    finding_id = test_scan_with_data["finding1_id"]
    res = verify_finding_fix(finding_id, db_session, simulated_pass=True)

    assert res["success"] is True
    assert res["status"] == "Remediated"
    assert "certificate" in res
    assert res["certificate"]["certificate_id"].startswith("CERT-REM-")
    assert len(res["certificate"]["verification_hash"]) == 32

    # Verify DB update persisted
    finding = db_session.query(Finding).filter(Finding.id == finding_id).first()
    assert finding.status == "Remediated"
    assert finding.verified_at is not None


def test_sbom_cyclonedx_and_spdx(db_session, test_scan_with_data):
    scan_id = test_scan_with_data["scan_id"]

    cdx = export_cyclonedx_json(scan_id, db_session)
    assert cdx["bomFormat"] == "CycloneDX"
    assert cdx["specVersion"] == "1.5"
    assert len(cdx["components"]) >= 3

    spdx = export_spdx_json(scan_id, db_session)
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert len(spdx["packages"]) >= 3


def test_issue_sync_github_and_jira(db_session, test_scan_with_data):
    finding_id = test_scan_with_data["finding1_id"]

    gh_res = sync_finding_to_issue_tracker(
        finding_id=finding_id,
        provider="github",
        repository_or_project="org/security-repo",
        db=db_session
    )
    assert gh_res["success"] is True
    assert "github.com/org/security-repo" in gh_res["issue_url"]
    assert gh_res["issue_id"].startswith("#")

    jira_res = sync_finding_to_issue_tracker(
        finding_id=finding_id,
        provider="jira",
        repository_or_project="SEC",
        db=db_session
    )
    assert jira_res["success"] is True
    assert "jira.atlassian.net" in jira_res["issue_url"]
    assert jira_res["issue_id"].startswith("SEC-")


def test_scan_logs_and_event_buffering(db_session, test_scan_with_data):
    from backend.app.services.scanner_pipeline import broadcast_event, SCAN_EVENT_HISTORY
    from backend.app.api.scans import get_scan_logs

    test_scan_id = test_scan_with_data["scan_id"]

    # 1. Test in-memory event broadcast & buffering
    broadcast_event(test_scan_id, "info", "Starting test probe", 15, "Recon Phase")
    assert test_scan_id in SCAN_EVENT_HISTORY
    assert any(e["message"] == "Starting test probe" for e in SCAN_EVENT_HISTORY[test_scan_id])

    # 2. Test get_scan_logs returns buffered events
    logs = get_scan_logs(test_scan_id, db=db_session)
    assert len(logs) >= 1
    assert any("Starting test probe" in l["message"] for l in logs)

    # 3. Test synthetic logs when no in-memory buffer exists
    fake_scan_id = "synthetic-scan-id"
    scan = Scan(
        id=fake_scan_id,
        target_domain="synthetic.example.com",
        mode="passive",
        status="completed",
        progress=100,
        current_step="Completed",
        total_assets=5,
        total_findings=2,
        risk_score=15.0,
        created_at=datetime.now(timezone.utc)
    )
    db_session.add(scan)
    db_session.commit()

    synth_logs = get_scan_logs(fake_scan_id, db=db_session)
    assert len(synth_logs) >= 2
    assert "synthetic.example.com" in synth_logs[0]["message"]
    assert "Discovered 5 assets" in synth_logs[-1]["message"]

    db_session.delete(scan)
    db_session.commit()


def test_dpdp_clean_target_has_zero_penalty(db_session):
    """
    Ensure clean targets with no failed Section 8(5) controls receive ₹0.00 penalty
    exposure and >= 95% compliance score (preventing static ₹5 Crore / 90% trap).
    """
    clean_scan_id = str(uuid.uuid4())
    scan = Scan(
        id=clean_scan_id,
        target_domain="clean-hardened.example.com",
        status="completed",
        mode="passive",
        total_assets=1,
        total_findings=0,
        created_at=datetime.now(timezone.utc)
    )
    db_session.add(scan)
    db_session.commit()

    asset = Asset(
        scan_id=clean_scan_id,
        type="domain",
        value="clean-hardened.example.com",
        ip_address="104.21.10.10",
        ports=[443],
        source="dns",
        first_seen=datetime.now(timezone.utc)
    )
    db_session.add(asset)
    db_session.commit()

    result = evaluate_dpdp_compliance(clean_scan_id, db_session)

    assert result["penalty_exposure_inr"] == 0.0
    assert result["penalty_exposure_inr_formatted"] == "₹0.00"
    assert result["penalty_exposure_usd"] == 0.0
    assert result["compliance_score"] >= 95
    assert "COMPLIANT" in result["compliance_verdict"]

    db_session.delete(asset)
    db_session.delete(scan)
    db_session.commit()


def test_damage_breakdown_quantification():
    """
    Ensure calculate_costs computes dynamic damage breakdown across all 4 cost centers.
    """
    from backend.app.analytics.cost_analyzer import calculate_costs
    from backend.app.schemas.schemas import FindingBase

    findings = [
        FindingBase(
            title="Vulnerability A",
            description="Test vulnerability description A",
            severity="High",
            cvss_score=8.0,
            epss_score=0.45,
            is_kev=False,
            fix_hours_dev=4.0,
            fix_hours_tester=2.0
        ),
        FindingBase(
            title="Vulnerability B",
            description="Test vulnerability description B",
            severity="Critical",
            cvss_score=9.8,
            epss_score=0.90,
            is_kev=True,
            fix_hours_dev=6.0,
            fix_hours_tester=3.0
        )
    ]

    res = calculate_costs(findings, currency="USD")
    assert "damage_breakdown" in res
    db = res["damage_breakdown"]
    assert "incident_response_forensics" in db
    assert "business_downtime_disruption" in db
    assert "regulatory_penalties_fines" in db
    assert "customer_notification_pr" in db
    assert db["business_downtime_disruption"] > 0
    assert sum(db.values()) > 0

