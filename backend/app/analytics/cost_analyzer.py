"""
Cost-of-Risk & Remediation Financial Analyzer
Computes:
1. Fix cost under Developer-Only vs Developer + QA Tester scenarios.
2. Potential breach loss based on Asset Valuation, EPSS/KEV likelihood, and Severity Impact.
3. Return on Security Investment (ROSI).
"""
from typing import List, Dict, Any, Optional
from ..schemas.schemas import CostSummaryResponse

# Default benchmark rates
DEFAULT_DEV_RATE = 85.0
DEFAULT_TESTER_RATE = 65.0
DEFAULT_ASSET_VALUE = 250000.0
RECORD_BREACH_COST_BENCHMARK = 165.0  # IBM Cost of a Data Breach ($/record)

# Severity impact factors
SEVERITY_IMPACT = {
    "Critical": 0.85,
    "High": 0.50,
    "Medium": 0.20,
    "Low": 0.05,
    "Info": 0.01
}

def calibrate_remediation_effort(title: str, severity: str, dev_hrs: Optional[float] = None, tester_hrs: Optional[float] = None) -> tuple[float, float]:
    """
    Calibrates remediation engineering hours to realistic, defensible benchmarks.
    Prevents simple configuration items (CSP, HSTS, DNS records, headers) from being exaggerated.
    """
    t_lower = (title or "").lower()

    # 1. Very lightweight headers & DNS records (15 mins dev, 15 mins test = $37.50)
    if any(k in t_lower for k in [
        "hsts", "strict-transport-security",
        "clickjacking", "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "server banner", "server-status",
        "security.txt", "crossdomain.xml",
        "caa", "spf"
    ]):
        max_dev = 0.5 if ("exceeds 10 dns" in t_lower or "multiple spf" in t_lower) else 0.25
        max_test = 0.25
        cur_dev = dev_hrs if dev_hrs is not None and dev_hrs > 0 else max_dev
        cur_test = tester_hrs if tester_hrs is not None and tester_hrs > 0 else max_test
        return (min(cur_dev, max_dev), min(cur_test, max_test))

    # 2. Content Security Policy (CSP), DNSSEC, DMARC, SSL protocol/ciphers (30 mins dev, 15 mins test = $58.75)
    if any(k in t_lower for k in [
        "content security policy", "content-security-policy", "csp",
        "dnssec", "dmarc", "coop", "corp", "cookie",
        "tls 1.0", "tls 1.1", "tls certificate", "ssl certificate",
        "cipher suite", "robots.txt"
    ]):
        max_dev = 0.5
        max_test = 0.25
        cur_dev = dev_hrs if dev_hrs is not None and dev_hrs > 0 else max_dev
        cur_test = tester_hrs if tester_hrs is not None and tester_hrs > 0 else max_test
        return (min(cur_dev, max_dev), min(cur_test, max_test))

    # 3. Moderate configuration / CORS / Subdomain Takeover
    if any(k in t_lower for k in ["cors", "takeover", "subresource integrity", "sri", "trace"]):
        max_dev = 1.0
        max_test = 0.5
        cur_dev = dev_hrs if dev_hrs is not None and dev_hrs > 0 else max_dev
        cur_test = tester_hrs if tester_hrs is not None and tester_hrs > 0 else max_test
        return (min(cur_dev, max_dev), min(cur_test, max_test))

    # 4. If already explicitly provided and non-zero, respect it
    if dev_hrs is not None and dev_hrs > 0:
        return (float(dev_hrs), float(tester_hrs if (tester_hrs is not None and tester_hrs > 0) else dev_hrs * 0.5))

    # 5. Default by severity
    defaults_by_sev = {
        "Critical": (3.0, 1.5),
        "High": (2.0, 1.0),
        "Medium": (1.0, 0.5),
        "Low": (0.5, 0.25),
        "Info": (0.25, 0.25),
    }
    return defaults_by_sev.get(severity, (1.0, 0.5))

def calculate_costs(
    findings: List[Any],
    dev_rate: float = DEFAULT_DEV_RATE,
    tester_rate: float = DEFAULT_TESTER_RATE,
    currency: str = "USD",
    asset_value: float = DEFAULT_ASSET_VALUE,
    records_count: int = 50000,
    scenario: str = "both"
) -> Dict[str, Any]:
    """
    Computes total fix costs, expected breach loss, and ROI breakdown.
    """
    dev_rate = float(dev_rate or DEFAULT_DEV_RATE)
    tester_rate = float(tester_rate or DEFAULT_TESTER_RATE)
    asset_value = float(asset_value or DEFAULT_ASSET_VALUE)
    
    # Check data valuation based on records
    effective_asset_value = max(asset_value, (records_count * RECORD_BREACH_COST_BENCHMARK * 0.05))

    total_dev_hours = 0.0
    total_tester_hours = 0.0
    total_fix_dev_only = 0.0
    total_fix_both = 0.0
    total_breach_loss = 0.0

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    severity_fix_cost = {"Critical": 0.0, "High": 0.0, "Medium": 0.0, "Low": 0.0, "Info": 0.0}
    severity_loss = {"Critical": 0.0, "High": 0.0, "Medium": 0.0, "Low": 0.0, "Info": 0.0}

    top_cost_findings = []

    for f in findings:
        sev = getattr(f, 'severity', 'Medium') or 'Medium'
        if sev not in severity_counts:
            sev = 'Medium'
        severity_counts[sev] += 1

        raw_dev = getattr(f, 'fix_hours_dev', None)
        raw_tester = getattr(f, 'fix_hours_tester', None)
        f_title = getattr(f, 'title', '')

        dev_hrs, tester_hrs = calibrate_remediation_effort(f_title, sev, raw_dev, raw_tester)

        total_dev_hours += dev_hrs
        total_tester_hours += tester_hrs

        cost_dev = dev_hrs * dev_rate
        cost_both = cost_dev + (tester_hrs * tester_rate)

        total_fix_dev_only += cost_dev
        total_fix_both += cost_both
        severity_fix_cost[sev] += cost_both

        # Compute Likelihood and Breach Loss for finding
        epss = float(getattr(f, 'epss_score', 0.02) or 0.02)
        is_kev = bool(getattr(f, 'is_kev', False))
        
        if is_kev:
            likelihood = max(0.70, min(0.99, epss * 1.25))
        else:
            likelihood = max(0.02, min(0.95, epss))

        impact = SEVERITY_IMPACT.get(sev, 0.20)
        finding_loss = round(effective_asset_value * likelihood * impact, 2)
        total_breach_loss += finding_loss
        severity_loss[sev] += finding_loss

        # Attach item to top findings
        top_cost_findings.append({
            "id": getattr(f, 'id', None),
            "title": getattr(f, 'title', 'Finding'),
            "severity": sev,
            "fix_cost_both": round(cost_both, 2),
            "fix_cost_dev": round(cost_dev, 2),
            "potential_loss": finding_loss,
            "dev_hours": dev_hrs,
            "tester_hours": tester_hrs,
            "epss": epss,
            "is_kev": is_kev
        })

    # Sort top findings by potential loss descending
    top_cost_findings.sort(key=lambda x: x["potential_loss"], reverse=True)

    # Compute ROIs
    roi_dev = 0.0
    if total_fix_dev_only > 0:
        roi_dev = round(((total_breach_loss - total_fix_dev_only) / total_fix_dev_only) * 100, 1)

    roi_both = 0.0
    if total_fix_both > 0:
        roi_both = round(((total_breach_loss - total_fix_both) / total_fix_both) * 100, 1)

    severity_breakdown = {}
    for k in ["Critical", "High", "Medium", "Low", "Info"]:
        severity_breakdown[k] = {
            "count": severity_counts[k],
            "fix_cost": round(severity_fix_cost[k], 2),
            "potential_loss": round(severity_loss[k], 2)
        }

    active_fix_cost = total_fix_both if scenario == "both" else total_fix_dev_only
    active_roi = roi_both if scenario == "both" else roi_dev

    explanation = (
        f"Remediating all {len(findings)} identified issues requires an estimated {round(total_dev_hours, 1)} dev hours "
        f"and {round(total_tester_hours, 1)} QA hours ({currency} {round(active_fix_cost, 2):,}). "
        f"In contrast, the annualized risk-adjusted breach loss is {currency} {round(total_breach_loss, 2):,}, "
        f"yielding a {active_roi:,}% Return on Security Investment."
    )

    damage_breakdown = {
        "incident_response_forensics": round(total_breach_loss * 0.30, 2),
        "business_downtime_disruption": round(total_breach_loss * 0.35, 2),
        "regulatory_penalties_fines": round(total_breach_loss * 0.20, 2),
        "customer_notification_pr": round(total_breach_loss * 0.15, 2)
    }

    return {
        "dev_rate": dev_rate,
        "tester_rate": tester_rate,
        "currency": currency,
        "asset_value": asset_value,
        "records_count": records_count,
        "total_dev_hours": round(total_dev_hours, 1),
        "total_tester_hours": round(total_tester_hours, 1),
        "total_fix_cost_dev_only": round(total_fix_dev_only, 2),
        "total_fix_cost_both": round(total_fix_both, 2),
        "active_fix_cost": round(active_fix_cost, 2),
        "total_potential_breach_loss": round(total_breach_loss, 2),
        "damage_breakdown": damage_breakdown,
        "roi_dev_only": roi_dev,
        "roi_both": roi_both,
        "active_roi": active_roi,
        "severity_breakdown": severity_breakdown,
        "top_cost_findings": top_cost_findings[:10],
        "explanation": explanation
    }
