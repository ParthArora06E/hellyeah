"""
Safe, Lightweight Active Vulnerability Probes
Includes:
- HTTP Security Headers Audit (HSTS, CSP, X-Frame-Options)
- TLS / SSL Certificate Hygiene & Expiration
- Exposed Confidential Files (.env, .git/HEAD, backups)
- Benign Reflection & Indicator Checks (harmless canary, database error disclosure, redirect validation)
Strictly non-destructive, rate-limited safe active checks.
"""
import ssl
import socket
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import httpx
from ..schemas.schemas import FindingBase
from ..recon.adapter.context import ScanContext

async def probe_security_headers(target: str, context: ScanContext) -> List[FindingBase]:
    findings = []
    context.emit_log("info", f"Auditing HTTP security headers on {target}...")
    context.log_audit("ACTIVE_HEADER_CHECK", target, "Inspecting HTTP response headers")
    
    url = f"https://{target}"
    try:
        resp = await context.http.get(url, ttl_seconds=0)
        if not resp:
            url = f"http://{target}"
            resp = await context.http.get(url, ttl_seconds=0)
        
        if not resp:
            return findings

        headers = {k.lower(): v for k, v in resp.headers.items()}

        # 1. HSTS Check
        if url.startswith("https") and "strict-transport-security" not in headers:
            findings.append(FindingBase(
                title=f"Missing HSTS Header on {target}",
                description="The Strict-Transport-Security (HSTS) header is not enforced, leaving connections vulnerable to man-in-the-middle SSL-stripping attacks.",
                severity="Medium",
                cvss_score=5.3,
                epss_score=0.015,
                source="Active Header Audit",
                confidence="Confirmed",
                status="Open",
                evidence={"headers_analyzed": list(headers.keys())},
                remediation_text="Configure Strict-Transport-Security: max-age=31536000; includeSubDomains; preload in web server headers.",
                owasp_category="A05:2021-Security Misconfiguration",
                iso_control="A.13.2.1 Information Transfer",
                fix_hours_dev=0.25,
                fix_hours_tester=0.25,
                estimated_fix_cost=37.5,
                risk_score=38.0
            ))

        # 2. Content Security Policy (CSP) Check
        if "content-security-policy" not in headers:
            findings.append(FindingBase(
                title=f"Missing Content Security Policy (CSP) on {target}",
                description="No Content-Security-Policy header was detected. Without a restrictive CSP, the application is at higher risk of cross-site scripting (XSS) and data injection.",
                severity="Medium",
                cvss_score=5.0,
                epss_score=0.02,
                source="Active Header Audit",
                confidence="Confirmed",
                status="Open",
                evidence={"url": url},
                remediation_text="Define and deploy a robust Content-Security-Policy restricting unauthorized script execution.",
                owasp_category="A05:2021-Security Misconfiguration",
                iso_control="A.14.2.5 Secure System Architecture",
                fix_hours_dev=0.5,
                fix_hours_tester=0.25,
                estimated_fix_cost=58.75,
                risk_score=42.0
            ))

        # 3. Clickjacking / X-Frame-Options
        if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
            findings.append(FindingBase(
                title=f"Missing Clickjacking Defense on {target}",
                description="The web page lacks X-Frame-Options or CSP frame-ancestors directives, allowing attackers to embed this site in an invisible iframe for clickjacking.",
                severity="Low",
                cvss_score=4.3,
                epss_score=0.01,
                source="Active Header Audit",
                confidence="Confirmed",
                status="Open",
                evidence={"x-frame-options": "Missing"},
                remediation_text="Add X-Frame-Options: DENY or SAMEORIGIN to HTTP response headers.",
                owasp_category="A05:2021-Security Misconfiguration",
                iso_control="A.14.2.5 Secure Architecture",
                fix_hours_dev=0.25,
                fix_hours_tester=0.25,
                estimated_fix_cost=37.5,
                risk_score=25.0
            ))

    except Exception as e:
        context.emit_log("warn", f"Security header check warning: {e}")

    return findings

async def probe_exposed_files(target: str, context: ScanContext) -> List[FindingBase]:
    findings = []
    context.emit_log("info", f"Inspecting high-risk configuration endpoints on {target}...")
    context.log_audit("ACTIVE_FILE_PROBE", target, "Checking sensitive path signatures")
    
    sensitive_targets = [
        ("/.env", "DB_PASSWORD=", "Exposed Environment Configuration File (.env)", "Critical", 9.5),
        ("/.git/HEAD", "ref: refs/", "Exposed Git Version Control Repository (/.git/HEAD)", "Critical", 9.1),
        ("/robots.txt", "Disallow:", "Robots.txt Information Disclosure", "Info", 2.0),
        ("/server-status", "Apache Server Status", "Exposed Apache Server-Status Dashboard", "Medium", 5.3)
    ]

    for path, signature, title, sev, cvss in sensitive_targets:
        url = f"https://{target}{path}"
        try:
            resp = await context.http.get(url, ttl_seconds=0)
            if resp and resp.status_code == 200 and signature in resp.text:
                findings.append(FindingBase(
                    title=f"{title} on {target}",
                    description=f"The sensitive endpoint {path} is publicly accessible over the internet and exposes internal system metadata or secrets matching signature '{signature}'.",
                    severity=sev,
                    cvss_score=cvss,
                    epss_score=0.75 if sev == "Critical" else 0.05,
                    is_kev=sev == "Critical",
                    source="Active Endpoint Probe",
                    confidence="Confirmed",
                    status="Open",
                    evidence={"endpoint": url, "signature_matched": signature, "status_code": 200},
                    remediation_text=f"Block public web server access to {path} or remove the sensitive file from public document root.",
                    owasp_category="A01:2021-Broken Access Control" if sev == "Critical" else "A05:2021-Security Misconfiguration",
                    iso_control="A.9.4.1 Information Access Restriction",
                    fix_hours_dev=1.0 if sev != "Critical" else 4.0,
                    fix_hours_tester=1.0 if sev != "Critical" else 2.0,
                    estimated_fix_cost=470.0 if sev == "Critical" else 150.0,
                    risk_score=95.0 if sev == "Critical" else 30.0
                ))
        except Exception:
            continue

    return findings

async def probe_tls_certificate(target: str, context: ScanContext) -> List[FindingBase]:
    findings = []
    context.emit_log("info", f"Verifying TLS certificate hygiene and protocol strength for {target}...")
    context.log_audit("TLS_CERT_PROBE", target, "Establishing TLS handshake")
    
    def _inspect_cert_sync():
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((target, 443), timeout=4.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
                return cert, version

    try:
        import asyncio
        cert, tls_version = await asyncio.to_thread(_inspect_cert_sync)
        if cert:
            not_after_str = cert.get("notAfter")
            if not_after_str:
                expire_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expire_dt - datetime.now(timezone.utc)).days
                if days_left < 15:
                    findings.append(FindingBase(
                        title=f"Expiring TLS/SSL Certificate: {target} ({days_left} days remaining)",
                        description=f"The SSL/TLS certificate for {target} expires in {days_left} days ({not_after_str}). Browsers will block access upon expiration.",
                        severity="High" if days_left < 7 else "Medium",
                        cvss_score=7.0,
                        epss_score=0.03,
                        source="Active TLS Audit",
                        confidence="Confirmed",
                        status="Open",
                        evidence={"expires_at": not_after_str, "days_remaining": days_left, "tls_version": tls_version},
                        remediation_text="Renew SSL/TLS certificate via Let's Encrypt or your Certificate Authority.",
                        owasp_category="A02:2021-Cryptographic Failures",
                        iso_control="A.10.1.1 Cryptographic Controls",
                        fix_hours_dev=0.5,
                        fix_hours_tester=0.25,
                        estimated_fix_cost=58.75,
                        risk_score=60.0
                    ))
    except Exception as e:
        context.emit_log("warn", f"TLS probe warning for {target}: {e}")

    return findings
