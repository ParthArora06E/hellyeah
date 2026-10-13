"""
Tests for Cost-of-Risk and Remediation Financial Model
"""
from backend.app.analytics.cost_analyzer import calculate_costs
from backend.app.schemas.schemas import FindingBase

def test_cost_calculation_scenarios():
    dummy_findings = [
        FindingBase(
            title="Log4Shell RCE",
            description="Critical RCE",
            severity="Critical",
            cvss_score=10.0,
            epss_score=0.97,
            is_kev=True,
            fix_hours_dev=6.0,
            fix_hours_tester=4.0
        ),
        FindingBase(
            title="Missing HSTS",
            description="Medium config",
            severity="Medium",
            cvss_score=5.0,
            epss_score=0.02,
            is_kev=False,
            fix_hours_dev=1.0,
            fix_hours_tester=0.5
        )
    ]

    res = calculate_costs(
        findings=dummy_findings,
        dev_rate=100.0,
        tester_rate=50.0,
        currency="USD",
        asset_value=500000.0,
        scenario="both"
    )

    # Dev only = (6*100) + (0.25*100) = 625.0
    # Both = 625 + (4*50) + (0.25*50) = 625 + 200 + 12.5 = 837.5
    assert res["total_fix_cost_dev_only"] == 625.0
    assert res["total_fix_cost_both"] == 837.5
    assert res["total_potential_breach_loss"] > 0
    assert res["roi_both"] > 0
