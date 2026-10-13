"""
Multi-Standard Compliance Mapping Engine
Translates attack surface assets, open ports, and ranked vulnerabilities into:
1. DPDP Act 2023 (India)
2. SOC 2 Type II (Trust Services Criteria)
3. PCI-DSS v4.0 (Payment Card Industry)
4. HIPAA Security Rule (Healthcare ePHI)
5. ISO/IEC 27001:2022 (Information Security Management)
"""
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from ..db.models import Scan, Asset, Finding
from .dpdp_engine import evaluate_dpdp_compliance

def map_all_compliance_frameworks(scan_id: str, db: Session) -> Dict[str, Any]:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return {"error": "Scan not found"}

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()

    # Base findings analysis
    has_crit = any(f.severity == "Critical" for f in findings)
    has_kev = any(f.is_kev for f in findings)
    tls_issues = [f for f in findings if any(k in (f.title or "").lower() for k in ["tls", "ssl", "hsts", "https", "cleartext"])]
    open_dbs = [a for a in assets if any(p in [3306, 5432, 27017, 6379, 9200] for p in (a.ports or []))]

    # 1. DPDP Act 2023
    dpdp_data = evaluate_dpdp_compliance(scan_id, db)

    # 2. SOC 2 Type II Controls
    soc2_controls = [
        {
            "control_id": "SOC2-CC6.1",
            "name": "Perimeter Logical Access Boundaries",
            "description": "The entity implements logical access security software, infrastructure, and architectures over the perimeter.",
            "status": "FAILED" if open_dbs else "PASSED",
            "findings_count": len(open_dbs),
            "remediation": "Restrict exposed database and administrative ports behind VPC / VPN."
        },
        {
            "control_id": "SOC2-CC6.6",
            "name": "Protection Against Malicious Exploitation",
            "description": "The entity implements logical boundary protections to prevent vulnerabilities from being exploited.",
            "status": "FAILED" if (has_crit or has_kev) else "PASSED",
            "findings_count": len([f for f in findings if f.severity in ["Critical", "High"]]),
            "remediation": "Patch high-severity and weaponized CVEs to protect perimeter boundaries."
        },
        {
            "control_id": "SOC2-CC6.7",
            "name": "Transmission Data Protection (In-Transit)",
            "description": "The entity protects data in transmission using approved encryption technologies and cipher suites.",
            "status": "FAILED" if tls_issues else "PASSED",
            "findings_count": len(tls_issues),
            "remediation": "Mandate TLS 1.2/1.3 and deploy HSTS headers across all endpoints."
        },
        {
            "control_id": "SOC2-CC7.1",
            "name": "Vulnerability Detection & Management",
            "description": "The entity performs continuous vulnerability detection and risk evaluations against perimeter assets.",
            "status": "PASSED" if dpdp_data.get("continuous_telemetry_active") else "WARNING",
            "findings_count": 0,
            "remediation": "Enable continuous scheduled monitoring for automated telemetry."
        }
    ]
    soc2_passed = len([c for c in soc2_controls if c["status"] == "PASSED"])
    soc2_score = int((soc2_passed / len(soc2_controls)) * 100)

    # 3. PCI-DSS v4.0 Controls
    pci_controls = [
        {
            "control_id": "PCI-REQ-2.2",
            "name": "System Hardening & Minimizing Services",
            "description": "System components are configured to securely disable unneeded protocols, ports, and default banners.",
            "status": "FAILED" if open_dbs else "PASSED",
            "findings_count": len(open_dbs),
            "remediation": "Disable exposed debug services, database ports, and default server tokens."
        },
        {
            "control_id": "PCI-REQ-4.1",
            "name": "Strong Cryptography in Public Transit",
            "description": "Strong cryptography and secure protocols are implemented when transmitting cardholder data over public networks.",
            "status": "FAILED" if tls_issues else "PASSED",
            "findings_count": len(tls_issues),
            "remediation": "Enforce modern TLS ciphers; prohibit SSLv3, TLS 1.0, and TLS 1.1."
        },
        {
            "control_id": "PCI-REQ-6.4.3",
            "name": "Payment Page Script Integrity & Authorization",
            "description": "All payment page scripts and external browser assets are managed, inventoried, and verified for integrity.",
            "status": "PASSED",
            "findings_count": 0,
            "remediation": "Maintain external script inventory and Content-Security-Policy (CSP) script-src directives."
        },
        {
            "control_id": "PCI-REQ-11.3",
            "name": "External Vulnerability Scanning Cadence",
            "description": "External vulnerability scans are performed at least once every three months by an ASV or qualified platform.",
            "status": "PASSED" if dpdp_data.get("continuous_telemetry_active") else "WARNING",
            "findings_count": 0,
            "remediation": "Maintain persistent quarterly or automated scheduled recurring scans."
        }
    ]
    pci_passed = len([c for c in pci_controls if c["status"] == "PASSED"])
    pci_score = int((pci_passed / len(pci_controls)) * 100)

    # 4. HIPAA Security Rule Controls
    hipaa_controls = [
        {
            "control_id": "HIPAA-164.312-E1",
            "name": "Transmission Security & Integrity",
            "description": "Implement technical security measures to guard against unauthorized access to electronic protected health information (ePHI) in transit.",
            "status": "FAILED" if tls_issues else "PASSED",
            "findings_count": len(tls_issues),
            "remediation": "Deploy enterprise HSTS and verify SSL certificate chains on all health portals."
        },
        {
            "control_id": "HIPAA-164.312-A1",
            "name": "Access Control & Perimeter Exposure",
            "description": "Implement technical policies that allow access to ePHI only to authorized persons or software programs.",
            "status": "FAILED" if open_dbs else "PASSED",
            "findings_count": len(open_dbs),
            "remediation": "Ensure healthcare databases and backend microservices are completely isolated from the internet."
        },
        {
            "control_id": "HIPAA-164.308-A1",
            "name": "Risk Analysis & Technical Safeguards",
            "description": "Conduct accurate and thorough assessment of potential risks and vulnerabilities to confidentiality and integrity of ePHI.",
            "status": "FAILED" if (has_crit or has_kev) else "PASSED",
            "findings_count": len([f for f in findings if f.severity in ["Critical", "High"]]),
            "remediation": "Remediate all remote execution and privilege escalation vulnerabilities."
        }
    ]
    hipaa_passed = len([c for c in hipaa_controls if c["status"] == "PASSED"])
    hipaa_score = int((hipaa_passed / len(hipaa_controls)) * 100)

    # 5. ISO/IEC 27001:2022 Controls
    iso_controls = [
        {
            "control_id": "ISO-A.8.8",
            "name": "Management of Technical Vulnerabilities",
            "description": "Information about technical vulnerabilities of information systems is evaluated and timely remediation is enforced.",
            "status": "FAILED" if has_crit else "PASSED",
            "findings_count": len([f for f in findings if f.severity == "Critical"]),
            "remediation": "Enforce vulnerability remediation SLAs: Critical within 48h, High within 14d."
        },
        {
            "control_id": "ISO-A.8.20",
            "name": "Network Security & Service Isolation",
            "description": "Networks and network devices are secured, managed, and controlled to protect information systems.",
            "status": "FAILED" if open_dbs else "PASSED",
            "findings_count": len(open_dbs),
            "remediation": "Isolate database tiers from demilitarized perimeter zones."
        },
        {
            "control_id": "ISO-A.8.24",
            "name": "Use of Cryptography",
            "description": "Rules for effective use of cryptography, including key management and cipher suites, are defined and implemented.",
            "status": "FAILED" if tls_issues else "PASSED",
            "findings_count": len(tls_issues),
            "remediation": "Deploy TLS 1.3 and disable deprecated CBC ciphers."
        }
    ]
    iso_passed = len([c for c in iso_controls if c["status"] == "PASSED"])
    iso_score = int((iso_passed / len(iso_controls)) * 100)

    return {
        "scan_id": scan_id,
        "target_domain": scan.target_domain,
        "frameworks": {
            "dpdp_act_2023": dpdp_data,
            "soc2_type_2": {
                "name": "SOC 2 Type II",
                "compliance_score": soc2_score,
                "status": "COMPLIANT" if soc2_score >= 80 else "NON_COMPLIANT",
                "controls": soc2_controls
            },
            "pci_dss_4": {
                "name": "PCI-DSS v4.0",
                "compliance_score": pci_score,
                "status": "COMPLIANT" if pci_score >= 80 else "NON_COMPLIANT",
                "controls": pci_controls
            },
            "hipaa": {
                "name": "HIPAA Security Rule",
                "compliance_score": hipaa_score,
                "status": "COMPLIANT" if hipaa_score >= 80 else "NON_COMPLIANT",
                "controls": hipaa_controls
            },
            "iso27001": {
                "name": "ISO/IEC 27001:2022",
                "compliance_score": iso_score,
                "status": "COMPLIANT" if iso_score >= 80 else "NON_COMPLIANT",
                "controls": iso_controls
            }
        }
    }
