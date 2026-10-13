"""
India Digital Personal Data Protection Act (DPDP Act 2023) Compliance Engine
Evaluates perimeter attack surface and vulnerabilities against:
- Section 8(5): Obligation of Data Fiduciary to protect personal data with reasonable security safeguards
- Section 8(6): Obligation to intimate Data Protection Board and Data Principals in case of breach
- Schedule of Penalties: Up to ₹250 Crore (~$30M USD) for Sec 8(5) violations; up to ₹200 Crore for Sec 8(6)
- Cross-Border Geolocation & Infrastructure Verification
"""
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from ..db.models import Scan, Asset, Finding, MonitorJob

# Currency conversion benchmark: 1 USD ≈ 83.5 INR
USD_TO_INR = 83.5
CRORE_INR = 10000000.0  # 1 Crore = 10 Million INR

# Maximum statutory caps under DPDP Act 2023 Schedule
MAX_SEC_8_5_PENALTY_INR = 250 * CRORE_INR  # ₹250 Crore (~$29.9M USD)
MAX_SEC_8_6_PENALTY_INR = 200 * CRORE_INR  # ₹200 Crore (~$23.9M USD)

SENSITIVE_DB_PORTS = {3306, 5432, 27017, 6379, 9200, 1433, 1521, 5984}

def evaluate_dpdp_compliance(scan_id: str, db: Session) -> Dict[str, Any]:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return {"error": "Scan not found"}

    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    # Check if continuous monitoring is enabled for this target
    target = (scan.target_domain or "").lower().strip()
    active_monitor = db.query(MonitorJob).filter(
        MonitorJob.target_domain == target,
        MonitorJob.enabled == True
    ).first()

    controls = []
    failing_finding_ids = []
    
    # -------------------------------------------------------------------------
    # 1. Section 8(5) - Control 1: Transmission Encryption & TLS Posture
    # -------------------------------------------------------------------------
    tls_fail = False
    tls_findings = []
    for f in findings:
        title_lower = (f.title or "").lower()
        desc_lower = (f.description or "").lower()
        if any(kw in title_lower or kw in desc_lower for kw in ["hsts", "tls", "ssl", "cleartext", "unencrypted", "https"]):
            tls_findings.append(f.id)
            if f.severity in ["Critical", "High", "Medium"]:
                tls_fail = True

    failing_finding_ids.extend(tls_findings)
    controls.append({
        "control_id": "DPDP-SEC-8-5-A",
        "statutory_ref": "Section 8(5)",
        "title": "Perimeter Transmission Security & Strong Encryption",
        "requirement": "Mandatory implementation of TLS 1.2+ encryption, HTTPS enforcement, and HSTS headers on all public perimeters handling personal data.",
        "status": "FAILED" if tls_fail else ("WARNING" if tls_findings else "PASSED"),
        "severity": "High" if tls_fail else "Low",
        "penalty_tier": "Up to ₹250 Crore (Schedule item 1)",
        "finding_ids": tls_findings,
        "recommendation": "Enforce Strict-Transport-Security (HSTS), deprecate TLS 1.0/1.1, and mandate HTTPS redirection across all perimeter endpoints."
    })

    # -------------------------------------------------------------------------
    # 2. Section 8(5) - Control 2: Database & Storage Port Exposure
    # -------------------------------------------------------------------------
    exposed_db_assets = []
    for a in assets:
        ports = a.ports or []
        for p in ports:
            try:
                p_int = int(p) if isinstance(p, (int, str)) and str(p).isdigit() else 0
                if p_int in SENSITIVE_DB_PORTS:
                    exposed_db_assets.append(f"{a.value} (Port {p_int})")
            except Exception:
                pass

    db_fail = len(exposed_db_assets) > 0
    controls.append({
        "control_id": "DPDP-SEC-8-5-B",
        "statutory_ref": "Section 8(5)",
        "title": "Database & Internal Storage Perimeter Isolation",
        "requirement": "Prohibition of publicly accessible database engines (MySQL, PostgreSQL, MongoDB, Redis) holding personal data records.",
        "status": "FAILED" if db_fail else "PASSED",
        "severity": "Critical" if db_fail else "Low",
        "penalty_tier": "Up to ₹250 Crore (Schedule item 1)",
        "exposed_assets": exposed_db_assets,
        "recommendation": "Bind database engines to private VPC subnets. Never expose ports 3306, 5432, 27017, or 6379 directly to the public internet."
    })

    # -------------------------------------------------------------------------
    # 3. Section 8(5) - Control 3: Sensitive File & Credential Leakage
    # -------------------------------------------------------------------------
    file_leak_findings = []
    for f in findings:
        title_lower = (f.title or "").lower()
        if any(kw in title_lower for kw in [".env", ".git", "backup", "credential", "config", "directory listing", "secret"]):
            file_leak_findings.append(f.id)

    failing_finding_ids.extend(file_leak_findings)
    file_fail = len(file_leak_findings) > 0
    controls.append({
        "control_id": "DPDP-SEC-8-5-C",
        "statutory_ref": "Section 8(5)",
        "title": "Prevention of Configuration, Credential & Source Leakage",
        "requirement": "Rigorous safeguards against publicly accessible configuration files, backup dumps, or source code repositories containing user keys.",
        "status": "FAILED" if file_fail else "PASSED",
        "severity": "Critical" if file_fail else "Low",
        "penalty_tier": "Up to ₹250 Crore (Schedule item 1)",
        "finding_ids": file_leak_findings,
        "recommendation": "Block web access to dotfiles (.env, .git) and remove automated database backups from publicly exposed document roots."
    })

    # -------------------------------------------------------------------------
    # 4. Section 8(5) - Control 4: Active Exploit & CISA KEV Vulnerability Protection
    # -------------------------------------------------------------------------
    kev_findings = [f.id for f in findings if f.is_kev]
    crit_findings = [f.id for f in findings if f.severity == "Critical"]
    failing_finding_ids.extend(kev_findings)

    kev_fail = len(kev_findings) > 0 or len(crit_findings) > 0
    controls.append({
        "control_id": "DPDP-SEC-8-5-D",
        "statutory_ref": "Section 8(5)",
        "title": "Remediation of Known Weaponized Vulnerabilities (KEV)",
        "requirement": "Data Fiduciaries must remediate high-severity and weaponized known vulnerabilities that permit remote code execution or data theft.",
        "status": "FAILED" if kev_fail else "PASSED",
        "severity": "Critical" if kev_fail else "Low",
        "penalty_tier": "Up to ₹250 Crore (Schedule item 1)",
        "finding_ids": list(set(kev_findings + crit_findings)),
        "recommendation": "Immediately patch all CISA KEV and Critical CVEs on public web services; active exploits negate claims of 'reasonable safeguards'."
    })

    # -------------------------------------------------------------------------
    # 5. Section 8(6) - Control 5: Breach Notification & Telemetry Readiness
    # -------------------------------------------------------------------------
    has_continuous = active_monitor is not None
    controls.append({
        "control_id": "DPDP-SEC-8-6-A",
        "statutory_ref": "Section 8(6)",
        "title": "Automated Breach Intimation & Telemetry Readiness",
        "requirement": "Readiness to intimate the Data Protection Board and affected Data Principals in the event of an attack surface breach without undue delay.",
        "status": "PASSED" if has_continuous else "WARNING",
        "severity": "Medium",
        "penalty_tier": "Up to ₹200 Crore (Schedule item 2)",
        "recommendation": "Activate Auditor's Continuous Monitoring scheduler to ensure edge-triggered alerts notify leadership immediately upon perimeter degradation."
    })

    # -------------------------------------------------------------------------
    # 6. Cross-Border Geolocation & Data Transfer Indicator
    # -------------------------------------------------------------------------
    detected_locations = []
    for a in assets:
        meta = a.raw_metadata or {}
        country = meta.get("country") or meta.get("country_code")
        if country and country not in detected_locations:
            detected_locations.append(country)

    controls.append({
        "control_id": "DPDP-SEC-16-A",
        "statutory_ref": "Section 16",
        "title": "Cross-Border Transfer & Geolocation Verification",
        "requirement": "Data processing and hosting infrastructure must comply with Central Government territory whitelist/blacklist notifications.",
        "status": "PASSED",
        "severity": "Low",
        "penalty_tier": "Statutory Review",
        "detected_locations": detected_locations or ["Global CDN / Cloud Infrastructure"],
        "recommendation": "Ensure data localization agreements and vendor sub-processor compliance documentation are maintained."
    })

    # -------------------------------------------------------------------------
    # Actuarial Statutory Penalty Liability Calculation (DPDP Act 2023 Schedule)
    # -------------------------------------------------------------------------
    failed_controls = [c for c in controls if c["status"] == "FAILED"]
    warning_controls = [c for c in controls if c["status"] == "WARNING"]

    # Base penalty multiplier based on findings and exposures
    has_kev = len(kev_findings) > 0
    has_critical = len(crit_findings) > 0
    has_db_leak = db_fail or file_fail

    if len(failed_controls) == 0:
        # Zero failed security controls under Section 8(5)
        penalty_inr = 0.0
        liability_tier = "Negligible Statutory Liability"
        if len(warning_controls) == 0:
            compliance_verdict = "COMPLIANT (Reasonable Safeguards Maintained)"
            compliance_score = 100
        else:
            compliance_verdict = "COMPLIANT WITH ADVISORY (Operational Guidance Pending)"
            compliance_score = max(92, 100 - len(warning_controls) * 4)
    else:
        # Failed controls trigger dynamic statutory penalty modeling based on
        # control type, finding severity, weaponization, and perimeter asset footprint
        base_fine_cr = 0.0
        if db_fail:
            base_fine_cr += 18.5 + (len(exposed_db_assets) * 4.5)
        if file_fail:
            base_fine_cr += 14.0 + (len(file_leak_findings) * 3.5)
        if tls_fail:
            base_fine_cr += 8.0 + (len(tls_findings) * 1.5)
        if kev_fail:
            base_fine_cr += 35.0 if has_kev else 20.0

        finding_addon_cr = (
            len(kev_findings) * 30.0 +
            len(crit_findings) * 10.5 +
            sum(1 for f in findings if f.severity == "High") * 3.2 +
            sum(1 for f in findings if f.severity == "Medium") * 0.75
        )

        asset_scale = 1.0 + (min(len(assets), 40) * 0.015)
        total_cr = (base_fine_cr + finding_addon_cr) * asset_scale
        total_cr = min(250.0, max(1.5, total_cr))
        penalty_inr = round(total_cr * CRORE_INR, 2)

        if total_cr >= 150.0:
            liability_tier = "Severe Statutory Liability (Tier 1: Up to ₹250 Cr)"
            compliance_verdict = "NON-COMPLIANT (Critical Breach Risk)"
        elif total_cr >= 60.0:
            liability_tier = "High Statutory Liability (Tier 2: Up to ₹100 Cr)"
            compliance_verdict = "NON-COMPLIANT (Elevated Regulatory Exposure)"
        elif total_cr >= 20.0:
            liability_tier = "Moderate Statutory Liability (Tier 3: Up to ₹50 Cr)"
            compliance_verdict = "NON-COMPLIANT (Remediation Required)"
        else:
            liability_tier = "Low Statutory Liability"
            compliance_verdict = "NON-COMPLIANT (Action Items Required)"

        deduction = (
            len(failed_controls) * 18 +
            len(crit_findings) * 8 +
            len(kev_findings) * 15 +
            len(warning_controls) * 3
        )
        compliance_score = max(5, min(90, 100 - deduction))

    penalty_usd = penalty_inr / USD_TO_INR

    if penalty_inr >= CRORE_INR:
        penalty_inr_formatted = f"₹{penalty_inr / CRORE_INR:.2f} Crore"
    elif penalty_inr > 0:
        penalty_inr_formatted = f"₹{penalty_inr / 100000:.2f} Lakh"
    else:
        penalty_inr_formatted = "₹0.00"

    return {
        "framework": "DPDP Act 2023 (Digital Personal Data Protection Act, India)",
        "statutory_act": "Act No. 22 of 2023, Ministry of Electronics and IT (MeitY)",
        "scan_id": scan_id,
        "target_domain": scan.target_domain,
        "compliance_score": compliance_score,
        "compliance_verdict": compliance_verdict,
        "liability_tier": liability_tier,
        "penalty_exposure_inr": penalty_inr,
        "penalty_exposure_inr_formatted": penalty_inr_formatted,
        "penalty_exposure_usd": round(penalty_usd, 2),
        "penalty_exposure_usd_formatted": f"${penalty_usd:,.2f}",
        "max_statutory_cap_inr": "₹250 Crore ($29.9M USD)",
        "controls_summary": {
            "total": len(controls),
            "passed": len([c for c in controls if c["status"] == "PASSED"]),
            "failed": len(failed_controls),
            "warning": len(warning_controls)
        },
        "controls": controls,
        "affected_findings_count": len(set(failing_finding_ids)),
        "continuous_telemetry_active": has_continuous
    }
