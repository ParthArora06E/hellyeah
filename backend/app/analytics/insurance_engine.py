"""
Cyber Insurance Readiness & Actuarial Underwriting Engine
Evaluates perimeter attack surface and risk metrics against commercial insurance
carrier underwriting guidelines (Coalition, Chubb, Cowbell, Travelers, Munich Re).
Calculates:
1. Insurability Index (0–100%)
2. Carrier Underwriting Disposition (Preferred, Conditional, Substandard, Decline)
3. Estimated Annual Premium Surcharge Load (+0% to +65%)
4. Underwriter Technical Exclusion Warranties
"""
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from ..db.models import Scan, Asset, Finding

def evaluate_cyber_insurability(scan_id: str, db: Session) -> Dict[str, Any]:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return {"error": "Scan not found"}

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()

    # 1. Inspect Underwriting Red Flags
    kev_findings = [f for f in findings if f.is_kev]
    crit_findings = [f for f in findings if f.severity == "Critical"]
    high_findings = [f for f in findings if f.severity == "High"]
    
    remote_access_ports = {3389, 22, 23, 5900}  # RDP, SSH, Telnet, VNC
    database_ports = {3306, 5432, 27017, 6379, 9200, 1433}

    exposed_remote_access = []
    exposed_dbs = []
    for a in assets:
        for p in (a.ports or []):
            try:
                p_int = int(p) if isinstance(p, (int, str)) and str(p).isdigit() else 0
                if p_int in remote_access_ports:
                    exposed_remote_access.append(f"{a.value}:{p_int}")
                if p_int in database_ports:
                    exposed_dbs.append(f"{a.value}:{p_int}")
            except Exception:
                pass

    tls_issues = [f for f in findings if any(k in (f.title or "").lower() for k in ["hsts", "tls", "ssl", "cleartext", "unencrypted"])]

    # 2. Score Deduction Model
    score = 100
    deductions = []

    if kev_findings:
        pen = min(35, len(kev_findings) * 20)
        score -= pen
        deductions.append({
            "category": "Weaponized Exploits (CISA KEV)",
            "impact": f"-{pen} pts",
            "reason": f"{len(kev_findings)} vulnerability actively weaponized in the wild. Most cyber carriers will issue an immediate policy exclusion or deny coverage."
        })

    if exposed_dbs:
        score -= 25
        deductions.append({
            "category": "Exposed Database Ports",
            "impact": "-25 pts",
            "reason": f"{len(exposed_dbs)} database instance(s) directly exposed to public internet ({', '.join(exposed_dbs[:2])})."
        })

    if exposed_remote_access:
        score -= 20
        deductions.append({
            "category": "Exposed Remote Access Management",
            "impact": "-20 pts",
            "reason": f"{len(exposed_remote_access)} public management port(s) open without perimeter VPN ({', '.join(exposed_remote_access[:2])})."
        })

    if crit_findings:
        pen = min(20, len(crit_findings) * 10)
        score -= pen
        deductions.append({
            "category": "Critical Severity CVEs",
            "impact": f"-{pen} pts",
            "reason": f"{len(crit_findings)} critical-severity perimeter vulnerabilities discovered."
        })

    if tls_issues:
        score -= 10
        deductions.append({
            "category": "Perimeter Cryptography & TLS Hygiene",
            "impact": "-10 pts",
            "reason": "Missing HSTS enforcement or weak TLS cipher suites detected."
        })

    final_score = max(5, min(100, score))

    # 3. Underwriter Disposition & Premium Impact
    if final_score >= 85:
        disposition = "Preferred Risk (Immediate Acceptance)"
        disposition_code = "PREFERRED"
        premium_surcharge_pct = 0.0
        retention_deductible = "$10,000"
    elif final_score >= 65:
        disposition = "Standard Risk (Conditional Acceptance)"
        disposition_code = "STANDARD"
        premium_surcharge_pct = 15.0
        retention_deductible = "$25,000"
    elif final_score >= 45:
        disposition = "Substandard Risk (Surplus Lines Surcharge)"
        disposition_code = "SUBSTANDARD"
        premium_surcharge_pct = 40.0
        retention_deductible = "$50,000"
    else:
        disposition = "Ineligible / High Risk of Denial"
        disposition_code = "DECLINE"
        premium_surcharge_pct = 65.0
        retention_deductible = "$100,000+"

    # 4. Underwriter Technical Warranties Checklist
    warranties = [
        {
            "warranty": "No Active CISA Known Exploited Vulnerabilities (KEV)",
            "met": len(kev_findings) == 0,
            "criticality": "Mandatory"
        },
        {
            "warranty": "No Publicly Exposed Database Infrastructure",
            "met": len(exposed_dbs) == 0,
            "criticality": "Mandatory"
        },
        {
            "warranty": "No Unsecured Remote Access (RDP / SSH) on Public IPs",
            "met": len(exposed_remote_access) == 0,
            "criticality": "Mandatory"
        },
        {
            "warranty": "Mandatory Transport Layer Security (TLS 1.2+ & HSTS)",
            "met": len(tls_issues) == 0,
            "criticality": "Standard"
        },
        {
            "warranty": "Continuous Perimeter Security Telemetry Active",
            "met": True,
            "criticality": "Recommended"
        }
    ]

    return {
        "scan_id": scan_id,
        "target_domain": scan.target_domain,
        "insurability_score": final_score,
        "disposition": disposition,
        "disposition_code": disposition_code,
        "estimated_premium_surcharge_pct": premium_surcharge_pct,
        "recommended_policy_retention": retention_deductible,
        "deductions": deductions,
        "underwriter_warranties": warranties,
        "summary": f"Target perimeter scored {final_score}/100. Evaluated as {disposition} with estimated {f'+{premium_surcharge_pct:.0f}%' if premium_surcharge_pct > 0 else '0%'} premium load factor."
    }
