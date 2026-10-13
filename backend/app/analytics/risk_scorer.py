"""
Composite Risk Scoring Engine
Calculates transparent 0-100 risk score and human-readable explanation based on:
risk = f(CVSS, EPSS, KEV flag, asset criticality, exposure)
"""
from typing import Dict, Any, Tuple
from ..schemas.schemas import FindingBase

def calculate_finding_risk(
    cvss: float,
    epss: float,
    is_kev: bool,
    asset_criticality: int = 3,
    is_public_facing: bool = True
) -> Tuple[float, str, str]:
    """
    Computes (risk_score_0_100, severity_level, explanation).
    Guarantees KEV findings are prioritized to the top.
    """
    cvss_val = max(0.0, min(10.0, cvss or 5.0))
    epss_val = max(0.0, min(1.0, epss or 0.02))
    crit_val = max(1, min(5, asset_criticality))

    # Base contribution from technical severity (0 to 50 pts)
    cvss_component = cvss_val * 5.0

    # Likelihood contribution from EPSS real-world exploit prediction (0 to 30 pts)
    epss_component = epss_val * 30.0

    # Criticality and Exposure multipliers
    crit_multiplier = 0.8 + (crit_val * 0.1)  # 0.9 for crit=1 up to 1.3 for crit=5
    exposure_multiplier = 1.15 if is_public_facing else 0.95

    # Compute raw composite score
    raw_score = (cvss_component + epss_component) * crit_multiplier * exposure_multiplier

    # CISA KEV active exploitation boost
    if is_kev:
        raw_score = max(88.0, raw_score + 25.0)

    final_score = round(min(100.0, max(0.0, raw_score)), 1)

    # Severity tier
    if final_score >= 85.0:
        severity = "Critical"
    elif final_score >= 70.0:
        severity = "High"
    elif final_score >= 40.0:
        severity = "Medium"
    else:
        severity = "Low"

    # Human-readable explanation
    reasons = []
    if is_kev:
        reasons.append("Flagged on CISA Known Exploited Vulnerabilities (KEV) catalog with confirmed in-the-wild weaponization")
    if epss_val > 0.5:
        reasons.append(f"High EPSS likelihood ({round(epss_val * 100, 1)}% chance of exploitation within 30 days)")
    elif epss_val > 0.1:
        reasons.append(f"Moderate EPSS likelihood ({round(epss_val * 100, 1)}%)")
    reasons.append(f"CVSS base metric of {cvss_val}/10.0")
    reasons.append(f"Asset criticality level {crit_val}/5")
    if is_public_facing:
        reasons.append("Directly accessible via public external perimeter")

    explanation = f"Score {final_score}/100 ({severity}): " + "; ".join(reasons) + "."

    return final_score, severity, explanation

def score_and_rank_findings(findings: list, asset_map: Dict[int, Any] = None) -> list:
    """
    Ranks findings descending with KEV=True always prioritized.
    """
    asset_map = asset_map or {}
    scored = []
    for f in findings:
        asset_crit = 3
        is_pub = True
        if hasattr(f, 'asset_id') and f.asset_id in asset_map:
            asset = asset_map[f.asset_id]
            asset_crit = getattr(asset, 'criticality', 3)
        
        cvss = getattr(f, 'cvss_score', 5.0) or 5.0
        epss = getattr(f, 'epss_score', 0.02) or 0.02
        kev = getattr(f, 'is_kev', False) or False

        score, sev, exp = calculate_finding_risk(cvss, epss, kev, asset_crit, is_pub)
        if hasattr(f, 'risk_score'):
            f.risk_score = score
        scored.append((score, kev, f, exp))

    # Sort key: KEV first (1 if true, 0 if false), then risk score descending
    scored.sort(key=lambda x: (1 if x[1] else 0, x[0]), reverse=True)
    return scored
