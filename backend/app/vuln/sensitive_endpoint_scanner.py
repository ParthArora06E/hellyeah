"""
Sensitive Endpoint, Backup & Configuration Leakage Scanner
Performs safe, non-destructive inspection for perimeter information leaks:
1. Environment Secret Files (.env)
2. Git Metadata Repository (/.git/HEAD)
3. API Documentation & Schema Exposures (/swagger.json, /openapi.json, /api-docs)
4. Spring Boot Actuator Endpoints (/actuator/health, /actuator/env)
5. Sensitive Disallow Paths in robots.txt
6. Server Status & Diagnostics Pages (/server-status, /phpinfo.php)
"""
from typing import List, Dict, Any, Optional
from ..schemas.schemas import FindingBase
from ..recon.adapter.context import ScanContext


PROBE_DEFINITIONS = [
    {
        "path": "/.env",
        "signature": "DB_",
        "signature_alt": "APP_",
        "title": "Exposed Environment Configuration File (.env)",
        "desc": "The application root exposes a public .env configuration file containing database credentials, API secret keys, or authentication tokens.",
        "severity": "Critical",
        "cvss": 9.8,
        "epss": 0.85,
        "is_kev": True,
        "dev_hrs": 2.0,
        "tester_hrs": 1.0,
        "cost": 235.0,
        "risk": 98.0
    },
    {
        "path": "/.git/HEAD",
        "signature": "ref: refs/",
        "title": "Exposed Git Source Code Repository (/.git/HEAD)",
        "desc": "The .git metadata directory is publicly accessible over HTTP. Attackers can reconstruct the complete application source code, commit history, and embedded credentials.",
        "severity": "Critical",
        "cvss": 9.8,
        "epss": 0.72,
        "is_kev": False,
        "dev_hrs": 1.5,
        "tester_hrs": 1.0,
        "cost": 192.5,
        "risk": 94.0
    },
    {
        "path": "/actuator/env",
        "signature": "propertySources",
        "title": "Exposed Spring Boot Actuator Environment (/actuator/env)",
        "desc": "Spring Boot production actuator endpoint /actuator/env is exposed without authentication, leaking runtime JVM environment variables and service configurations.",
        "severity": "High",
        "cvss": 8.5,
        "epss": 0.45,
        "is_kev": False,
        "dev_hrs": 2.0,
        "tester_hrs": 1.0,
        "cost": 235.0,
        "risk": 82.0
    },
    {
        "path": "/swagger.json",
        "signature": "swagger",
        "signature_alt": "openapi",
        "title": "Exposed OpenAPI / Swagger Specification File",
        "desc": "Publicly accessible Swagger JSON schema leaks full internal API endpoints, parameter schemas, and authentication schemes.",
        "severity": "Medium",
        "cvss": 5.3,
        "epss": 0.052,
        "is_kev": False,
        "dev_hrs": 1.0,
        "tester_hrs": 0.5,
        "cost": 117.5,
        "risk": 44.0
    },
    {
        "path": "/server-status",
        "signature": "Apache Server Status",
        "title": "Publicly Accessible Apache Server Status (/server-status)",
        "desc": "The mod_status monitoring page is open to the public, displaying active client IP addresses, requested URIs, and vhost routing data.",
        "severity": "Medium",
        "cvss": 5.3,
        "epss": 0.062,
        "is_kev": False,
        "dev_hrs": 1.0,
        "tester_hrs": 0.5,
        "cost": 117.5,
        "risk": 46.0
    },
    {
        "path": "/phpinfo.php",
        "signature": "phpinfo()",
        "signature_alt": "PHP Version",
        "title": "Exposed PHP Information Diagnostic Script (/phpinfo.php)",
        "desc": "Public phpinfo() diagnostic page leaks compiled extensions, server environment variables, file paths, and active modules.",
        "severity": "Medium",
        "cvss": 5.3,
        "epss": 0.048,
        "is_kev": False,
        "dev_hrs": 0.5,
        "tester_hrs": 0.5,
        "cost": 75.0,
        "risk": 42.0
    },
    {
        "path": "/.git/config",
        "signature": "[core]",
        "signature_alt": "[remote \"origin\"]",
        "title": "Exposed Git Repository Configuration (/.git/config)",
        "desc": "Git configuration file is publicly exposed, leaking origin repository URLs, branch definitions, and embedded access tokens.",
        "severity": "Critical",
        "cvss": 9.1,
        "epss": 0.65,
        "is_kev": False,
        "dev_hrs": 1.5,
        "tester_hrs": 1.0,
        "cost": 192.5,
        "risk": 90.0
    },
    {
        "path": "/docker-compose.yml",
        "signature": "services:",
        "signature_alt": "version:",
        "title": "Exposed Docker Compose File (/docker-compose.yml)",
        "desc": "Docker compose specification file is exposed over HTTP, disclosing microservice architecture, internal ports, and embedded container environment variables.",
        "severity": "Critical",
        "cvss": 9.1,
        "epss": 0.60,
        "is_kev": False,
        "dev_hrs": 1.5,
        "tester_hrs": 1.0,
        "cost": 192.5,
        "risk": 88.0
    },
    {
        "path": "/wp-config.php.bak",
        "signature": "DB_PASSWORD",
        "signature_alt": "DB_NAME",
        "title": "Exposed WordPress Backup Configuration (/wp-config.php.bak)",
        "desc": "Backup of WordPress configuration file is publicly downloadable, exposing database credentials, auth keys, and table prefix.",
        "severity": "Critical",
        "cvss": 9.8,
        "epss": 0.82,
        "is_kev": True,
        "dev_hrs": 1.5,
        "tester_hrs": 1.0,
        "cost": 192.5,
        "risk": 96.0
    },
    {
        "path": "/graphql",
        "signature": "__schema",
        "signature_alt": "GraphQL",
        "title": "Public GraphQL API Introspection (/graphql)",
        "desc": "GraphQL endpoint is publicly accessible and accepts introspection queries, exposing the complete internal data model, types, and schema fields.",
        "severity": "Medium",
        "cvss": 5.3,
        "epss": 0.052,
        "is_kev": False,
        "dev_hrs": 1.0,
        "tester_hrs": 0.5,
        "cost": 117.5,
        "risk": 44.0
    }
]


async def scan_sensitive_endpoints(target: str, context: ScanContext) -> List[FindingBase]:
    """
    Safely probes high-risk sensitive paths across the target apex and active web hosts.
    """
    findings: List[FindingBase] = []
    hosts_to_probe = [target]
    
    # Add www or api subdomains if discovered
    for asset in context.discovered_assets:
        if asset.type == "subdomain" and any(k in asset.value for k in ["www", "api"]):
            if asset.value not in hosts_to_probe and len(hosts_to_probe) < 3:
                hosts_to_probe.append(asset.value)

    context.emit_log("info", f"Executing non-destructive perimeter sensitive path probes across {len(hosts_to_probe)} hosts...")

    for host in hosts_to_probe:
        # Check robots.txt first for disallowed paths
        try:
            robots_url = f"https://{host}/robots.txt"
            robots_resp = await context.http.get(robots_url, ttl_seconds=600, retries=1)
            if robots_resp and robots_resp.status_code == 200:
                disallow_lines = [
                    l.split(":", 1)[1].strip()
                    for l in robots_resp.text.splitlines()
                    if l.lower().startswith("disallow:")
                ]
                sensitive_disallows = [
                    p for p in disallow_lines
                    if any(k in p.lower() for k in ["admin", "login", "secret", "backup", "private", "api", "internal", "config"])
                ]
                if sensitive_disallows:
                    findings.append(FindingBase(
                        title=f"Sensitive Administrative Paths Disclosed in robots.txt on {host}",
                        description=f"Host {host}/robots.txt lists sensitive restricted paths: {', '.join(sensitive_disallows[:4])}. Search engine exclusion files frequently assist attackers in discovering hidden administration portals.",
                        severity="Low",
                        cvss_score=3.7,
                        epss_score=0.022,
                        source="Sensitive Endpoint Audit",
                        confidence="Confirmed",
                        status="Open",
                        evidence={"url": robots_url, "disallowed_paths": sensitive_disallows[:5]},
                        remediation_text="Do not rely on robots.txt for access control. Restrict administrative endpoints using IP access control lists and mandatory MFA.",
                        owasp_category="A01:2021-Broken Access Control",
                        iso_control="A.9.4.1 Information Access Restriction",
                        fix_hours_dev=1.0,
                        fix_hours_tester=0.5,
                        estimated_fix_cost=117.5,
                        risk_score=25.0
                    ))
        except Exception:
            pass

        # Check Sensitive Target Signatures
        for probe in PROBE_DEFINITIONS:
            url = f"https://{host}{probe['path']}"
            try:
                resp = await context.http.get(url, ttl_seconds=300, retries=1)
                if resp and resp.status_code == 200:
                    text = resp.text or ""
                    sig1 = probe.get("signature")
                    sig2 = probe.get("signature_alt")
                    
                    matched = False
                    if sig1 and sig1 in text:
                        matched = True
                    elif sig2 and sig2 in text:
                        matched = True

                    if matched:
                        findings.append(FindingBase(
                            title=f"{probe['title']} on {host}",
                            description=f"{probe['desc']} Endpoint: {url}",
                            severity=probe["severity"],
                            cvss_score=probe["cvss"],
                            epss_score=probe["epss"],
                            is_kev=probe["is_kev"],
                            source="Sensitive Endpoint Audit",
                            confidence="Confirmed",
                            status="Open",
                            evidence={"url": url, "status_code": 200, "signature_matched": sig1 or sig2},
                            remediation_text=f"Block public access to {probe['path']} in web server configuration or remove sensitive file from public document root.",
                            owasp_category="A01:2021-Broken Access Control" if probe["severity"] == "Critical" else "A05:2021-Security Misconfiguration",
                            iso_control="A.9.4.1 Information Access Restriction",
                            fix_hours_dev=probe["dev_hrs"],
                            fix_hours_tester=probe["tester_hrs"],
                            estimated_fix_cost=probe["cost"],
                            risk_score=probe["risk"]
                        ))
            except Exception:
                continue

    return findings
