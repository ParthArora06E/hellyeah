"""
Tests for Risk Scoring Engine and Ranking
"""
from backend.app.analytics.risk_scorer import calculate_finding_risk, score_and_rank_findings

def test_risk_calculation_kev_bump():
    # KEV=True must yield high score (>=88) and Critical severity
    score, sev, explanation = calculate_finding_risk(
        cvss=9.8,
        epss=0.95,
        is_kev=True,
        asset_criticality=4,
        is_public_facing=True
    )
    assert score >= 88.0
    assert sev == "Critical"
    assert "CISA Known Exploited Vulnerabilities" in explanation

def test_risk_calculation_low_severity():
    score, sev, explanation = calculate_finding_risk(
        cvss=4.0,
        epss=0.01,
        is_kev=False,
        asset_criticality=2,
        is_public_facing=False
    )
    assert score < 50.0
    assert sev in ("Low", "Medium")
