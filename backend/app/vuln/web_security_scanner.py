"""
Web Security & HTTP Misconfiguration Scanner
Analyzes perimeter web applications for:
1. Missing HTTP Security Headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
2. Insecure Cookie Flags (Missing Secure, HttpOnly, SameSite)
3. Information Disclosure & Verbose Headers (Server, X-Powered-By, X-AspNet-Version)
4. Cross-Origin Resource Sharing (CORS) Misconfigurations
5. Open Directory Listing
"""
from typing import List, Dict, Any, Optional
import urllib.parse
from ..schemas.schemas import FindingBase
from ..recon.adapter.context import ScanContext


async def scan_web_security_posture(target: str, context: ScanContext) -> List[FindingBase]:
    """
    Performs comprehensive, safe web security checks against target and discovered web hosts.
    """
    findings: List[FindingBase] = []
    hosts_to_probe = [target]
    
    # Also include high-value discovered web subdomains (up to 4)
    for asset in context.discovered_assets:
        if asset.type == "subdomain" and any(k in asset.value for k in ["www", "api", "portal", "app", "admin", "login"]):
            if asset.value not in hosts_to_probe and len(hosts_to_probe) < 5:
                hosts_to_probe.append(asset.value)

    context.emit_log("info", f"Executing web application security and misconfiguration scan across {len(hosts_to_probe)} perimeter hosts...")

    for host in hosts_to_probe:
        url = f"https://{host}"
        resp = await context.http.get(url, ttl_seconds=300, retries=1)
        
        # Fallback to HTTP if HTTPS fails
        if not resp:
            url = f"http://{host}"
            resp = await context.http.get(url, ttl_seconds=300, retries=1)

        if not resp:
            continue

        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text or ""

        # ---------------------------------------------------------------------
        # 1. Missing HTTP Strict Transport Security (HSTS)
        # ---------------------------------------------------------------------
        if "strict-transport-security" not in headers:
            findings.append(FindingBase(
                title=f"Missing HTTP Strict Transport Security (HSTS) on {host}",
                description=f"Host {host} does not enforce the 'Strict-Transport-Security' header. This exposes communications to SSL-stripping and man-in-the-middle (MitM) downgrade attacks.",
                severity="Medium",
                cvss_score=5.4,
                epss_score=0.045,
                source="Web Security Audit",
                confidence="Confirmed",
                status="Open",
                evidence={"url": url, "headers_missing": ["Strict-Transport-Security"]},
                remediation_text="Configure the web server or reverse proxy to send: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                owasp_category="A05:2021-Security Misconfiguration",
                iso_control="A.13.2.1 Information Transfer",
                fix_hours_dev=0.25,
                fix_hours_tester=0.25,
                estimated_fix_cost=37.5,
                risk_score=42.0
            ))

        # ---------------------------------------------------------------------
        # 2. Missing or Weak Content-Security-Policy (CSP)
        # ---------------------------------------------------------------------
        csp = headers.get("content-security-policy", "")
        if not csp:
            findings.append(FindingBase(
                title=f"Missing Content Security Policy (CSP) Header on {host}",
                description=f"Host {host} does not implement a Content-Security-Policy header, leaving the perimeter application vulnerable to Cross-Site Scripting (XSS) and malicious script injection.",
                severity="Medium",
                cvss_score=6.1,
                epss_score=0.065,
                source="Web Security Audit",
                confidence="Confirmed",
                status="Open",
                evidence={"url": url, "headers_missing": ["Content-Security-Policy"]},
                remediation_text="Define a robust CSP policy restricting script, style, and frame sources: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';",
                owasp_category="A03:2021-Injection",
                iso_control="A.14.2.5 Secure System Architecture",
                fix_hours_dev=0.5,
                fix_hours_tester=0.25,
                estimated_fix_cost=58.75,
                risk_score=55.0
            ))
        elif "unsafe-inline" in csp and "nonce" not in csp:
            findings.append(FindingBase(
                title=f"Weak Content Security Policy ('unsafe-inline') on {host}",
                description=f"The CSP header on {host} permits 'unsafe-inline' without cryptographic nonces or hashes, significantly reducing protection against inline XSS payloads.",
                severity="Low",
                cvss_score=4.3,
                epss_score=0.021,
                source="Web Security Audit",
                confidence="High",
                status="Open",
                evidence={"url": url, "csp_policy": csp},
                remediation_text="Refactor inline scripts to external bundles or adopt cryptographic nonces ('nonce-...') in the script-src directive.",
                owasp_category="A05:2021-Security Misconfiguration",
                iso_control="A.14.2.5 Secure System Architecture",
                fix_hours_dev=0.5,
                fix_hours_tester=0.25,
                estimated_fix_cost=58.75,
                risk_score=30.0
            ))

        # ---------------------------------------------------------------------
        # 3. Missing Clickjacking Protection (X-Frame-Options)
        # ---------------------------------------------------------------------
        x_frame = headers.get("x-frame-options", "").lower()
        if not x_frame and "frame-ancestors" not in csp:
            findings.append(FindingBase(
                title=f"Clickjacking Vulnerability (Missing X-Frame-Options) on {host}",
                description=f"Host {host} omits the X-Frame-Options header and CSP frame-ancestors directive. Attackers can embed this portal inside malicious iframes to hijack user clicks.",
                severity="Medium",
                cvss_score=5.3,
                epss_score=0.038,
                source="Web Security Audit",
                confidence="Confirmed",
                status="Open",
                evidence={"url": url, "headers_missing": ["X-Frame-Options"]},
                remediation_text="Add header: X-Frame-Options: SAMEORIGIN or DENY to prevent unauthorized framing.",
                owasp_category="A05:2021-Security Misconfiguration",
                iso_control="A.14.2.5 Secure System Architecture",
                fix_hours_dev=0.25,
                fix_hours_tester=0.25,
                estimated_fix_cost=37.5,
                risk_score=38.0
            ))

        # ---------------------------------------------------------------------
        # 4. Missing MIME-Type Sniffing Protection (X-Content-Type-Options)
        # ---------------------------------------------------------------------
        if "x-content-type-options" not in headers:
            findings.append(FindingBase(
                title=f"Missing X-Content-Type-Options Header on {host}",
                description=f"The 'X-Content-Type-Options: nosniff' header is missing on {host}, allowing browsers to MIME-sniff responses away from the declared content-type.",
                severity="Low",
                cvss_score=3.7,
                epss_score=0.015,
                source="Web Security Audit",
                confidence="Confirmed",
                status="Open",
                evidence={"url": url, "headers_missing": ["X-Content-Type-Options"]},
                remediation_text="Configure web server to return: X-Content-Type-Options: nosniff on all responses.",
                owasp_category="A05:2021-Security Misconfiguration",
                iso_control="A.14.2.5 Secure System Architecture",
                fix_hours_dev=0.25,
                fix_hours_tester=0.25,
                estimated_fix_cost=37.5,
                risk_score=22.0
            ))


        # ---------------------------------------------------------------------
        # 5. Overly Permissive Cross-Origin Resource Sharing (CORS)
        # ---------------------------------------------------------------------
        cors_origin = headers.get("access-control-allow-origin", "")
        cors_creds = headers.get("access-control-allow-credentials", "").lower()
        if cors_origin == "*" or (cors_origin and cors_creds == "true"):
            findings.append(FindingBase(
                title=f"Overly Permissive CORS Policy on {host}",
                description=f"Host {host} configures 'Access-Control-Allow-Origin: {cors_origin}' with allow-credentials: '{cors_creds}'. Unauthorized third-party origins can read authenticated API responses.",
                severity="Medium" if cors_origin == "*" else "High",
                cvss_score=6.5 if cors_creds == "true" else 5.3,
                epss_score=0.082,
                source="Web Security Audit",
                confidence="Confirmed",
                status="Open",
                evidence={"url": url, "access-control-allow-origin": cors_origin, "allow-credentials": cors_creds},
                remediation_text="Restrict Access-Control-Allow-Origin to trusted corporate origin domains only, never wildcard '*' with credentials.",
                owasp_category="A01:2021-Broken Access Control",
                iso_control="A.13.1 Network Security",
                fix_hours_dev=1.0,
                fix_hours_tester=0.5,
                estimated_fix_cost=117.5,
                risk_score=58.0
            ))

        # ---------------------------------------------------------------------
        # 6. Detailed Server & Technology Information Disclosure
        # ---------------------------------------------------------------------
        server_val = headers.get("server", "")
        powered_val = headers.get("x-powered-by", "")
        aspnet_val = headers.get("x-aspnet-version", "")
        
        verbose_tokens = []
        if any(c in server_val for c in ["/", "Ubuntu", "Debian", "CentOS", "Win32"]):
            verbose_tokens.append(f"Server: {server_val}")
        if powered_val:
            verbose_tokens.append(f"X-Powered-By: {powered_val}")
        if aspnet_val:
            verbose_tokens.append(f"X-AspNet-Version: {aspnet_val}")

        if verbose_tokens:
            findings.append(FindingBase(
                title=f"Server Banner Information Disclosure on {host}",
                description=f"Host {host} reveals detailed backend infrastructure and framework version banners in HTTP headers: {', '.join(verbose_tokens)}. This assists threat actors in vulnerability targeting.",
                severity="Low",
                cvss_score=4.0,
                epss_score=0.024,
                source="Web Security Audit",
                confidence="Confirmed",
                status="Open",
                evidence={"url": url, "disclosed_headers": verbose_tokens},
                remediation_text="Disable verbose banners in web server configuration (e.g. ServerTokens Prod, expose_php = Off).",
                owasp_category="A05:2021-Security Misconfiguration",
                iso_control="A.12.1.2 Change Management",
                fix_hours_dev=0.25,
                fix_hours_tester=0.25,
                estimated_fix_cost=37.5,
                risk_score=25.0
            ))

        # ---------------------------------------------------------------------
        # 7. Insecure Cookie Flags (Missing HttpOnly / Secure / SameSite)
        # ---------------------------------------------------------------------
        set_cookie_raw = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [headers.get("set-cookie")]
        for sc in set_cookie_raw:
            if not sc:
                continue
            sc_lower = sc.lower()
            cookie_name = sc.split("=")[0].strip()
            issues = []
            if "secure" not in sc_lower and url.startswith("https://"):
                issues.append("Missing 'Secure' flag")
            if "httponly" not in sc_lower:
                issues.append("Missing 'HttpOnly' flag")
            if "samesite" not in sc_lower:
                issues.append("Missing 'SameSite' flag")

            if issues:
                findings.append(FindingBase(
                    title=f"Insecure Cookie Configuration ('{cookie_name}') on {host}",
                    description=f"Cookie '{cookie_name}' issued by {host} has insecure flags: {', '.join(issues)}. This increases risk of session hijacking via XSS or CSRF.",
                    severity="Medium" if "HttpOnly" in issues else "Low",
                    cvss_score=5.0 if "HttpOnly" in issues else 3.8,
                    epss_score=0.031,
                    source="Web Security Audit",
                    confidence="Confirmed",
                    status="Open",
                    evidence={"cookie": cookie_name, "issues": issues},
                    remediation_text=f"Set 'Secure; HttpOnly; SameSite=Lax' (or Strict) on cookie '{cookie_name}'.",
                    owasp_category="A05:2021-Security Misconfiguration",
                    iso_control="A.14.2.5 Secure System Architecture",
                    fix_hours_dev=0.5,
                    fix_hours_tester=0.25,
                    estimated_fix_cost=58.75,
                    risk_score=36.0
                ))

        # ---------------------------------------------------------------------
        # 8. Directory Listing Enabled Detection
        # ---------------------------------------------------------------------
        if "index of /" in body.lower() or "<title>index of" in body.lower():
            findings.append(FindingBase(
                title=f"Open Directory Listing Enabled on {host}",
                description=f"Web server at {url} permits public directory indexing ('Index of /'), exposing internal file hierarchies and unlinked documents.",
                severity="Medium",
                cvss_score=5.3,
                epss_score=0.042,
                source="Web Security Audit",
                confidence="Confirmed",
                status="Open",
                evidence={"url": url, "signature": "Index of / in HTML body"},
                remediation_text="Disable directory indexing in server config: Options -Indexes in Apache, or autoindex off in Nginx.",
                owasp_category="A01:2021-Broken Access Control",
                iso_control="A.9.4.1 Information Access Restriction",
                fix_hours_dev=0.25,
                fix_hours_tester=0.25,
                estimated_fix_cost=37.5,
                risk_score=45.0
            ))

        # ---------------------------------------------------------------------
        # 9. Missing Permissions-Policy Header
        # ---------------------------------------------------------------------
        if "permissions-policy" not in headers and "feature-policy" not in headers:
            findings.append(FindingBase(
                title=f"Missing Permissions-Policy Header on {host}",
                description=f"Host {host} does not configure the 'Permissions-Policy' header (the modern successor to Feature-Policy). Browser capabilities like geolocation, camera, microphone, and payment APIs remain unrestricted for embedded iframes.",
                severity="Low",
                cvss_score=3.5,
                epss_score=0.019,
                source="Web Security Audit",
                confidence="Confirmed",
                status="Open",
                evidence={"url": url, "headers_missing": ["Permissions-Policy"]},
                remediation_text="Configure Permissions-Policy to explicitly disable unused hardware and browser APIs: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()",
                owasp_category="A05:2021-Security Misconfiguration",
                iso_control="A.14.2.5 Secure System Architecture",
                fix_hours_dev=0.25,
                fix_hours_tester=0.25,
                estimated_fix_cost=37.5,
                risk_score=20.0
            ))

        # ---------------------------------------------------------------------
        # 10. Missing or Weak Referrer-Policy
        # ---------------------------------------------------------------------
        ref_policy = headers.get("referrer-policy", "").lower()
        if not ref_policy or ref_policy in ("unsafe-url", "no-referrer-when-downgrade"):
            findings.append(FindingBase(
                title=f"Missing or Insecure Referrer-Policy ({ref_policy or 'None'}) on {host}",
                description=f"Host {host} does not specify a protective Referrer-Policy header. Browsers may leak sensitive internal URL paths, session query parameters, and tokens in Referer headers when navigating to third-party domains.",
                severity="Low",
                cvss_score=3.7,
                epss_score=0.022,
                source="Web Security Audit",
                confidence="Confirmed",
                status="Open",
                evidence={"url": url, "referrer_policy": ref_policy or "missing"},
                remediation_text="Set a restrictive Referrer-Policy: Referrer-Policy: strict-origin-when-cross-origin or no-referrer",
                owasp_category="A05:2021-Security Misconfiguration",
                iso_control="A.13.2.1 Information Transfer",
                fix_hours_dev=0.25,
                fix_hours_tester=0.25,
                estimated_fix_cost=37.5,
                risk_score=24.0
            ))

        # ---------------------------------------------------------------------
        # 11. Missing Cross-Origin Isolation (COOP / CORP)
        # ---------------------------------------------------------------------
        coop = headers.get("cross-origin-opener-policy", "").lower()
        corp = headers.get("cross-origin-resource-policy", "").lower()
        if not coop and not corp:
            findings.append(FindingBase(
                title=f"Missing Cross-Origin Isolation (COOP / CORP) on {host}",
                description=f"Host {host} does not set Cross-Origin-Opener-Policy (COOP) or Cross-Origin-Resource-Policy (CORP). Leaves the web window vulnerable to cross-origin side-channel attacks (Spectre) and window.opener tampering.",
                severity="Low",
                cvss_score=3.3,
                epss_score=0.015,
                source="Web Security Audit",
                confidence="Confirmed",
                status="Open",
                evidence={"url": url, "headers_missing": ["Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy"]},
                remediation_text="Set Cross-Origin-Opener-Policy: same-origin and Cross-Origin-Resource-Policy: same-origin on public endpoints.",
                owasp_category="A05:2021-Security Misconfiguration",
                iso_control="A.14.2.5 Secure System Architecture",
                fix_hours_dev=0.5,
                fix_hours_tester=0.25,
                estimated_fix_cost=58.75,
                risk_score=18.0
            ))

        # ---------------------------------------------------------------------
        # 12. Missing Subresource Integrity (SRI) on External Scripts
        # ---------------------------------------------------------------------
        if ("<script" in body.lower()) and ("src=\"http" in body or "src='http" in body):
            if "integrity=" not in body.lower():
                findings.append(FindingBase(
                    title=f"Missing Subresource Integrity (SRI) on Third-Party Scripts on {host}",
                    description=f"Web application at {url} loads external JavaScript assets without cryptographic Subresource Integrity (integrity='sha384-...') attributes. A compromised CDN can inject malicious code into client browsers.",
                    severity="Medium",
                    cvss_score=5.5,
                    epss_score=0.048,
                    source="Web Security Audit",
                    confidence="Confirmed",
                    status="Open",
                    evidence={"url": url, "missing_attribute": "integrity"},
                    remediation_text="Add cryptographic sha384 or sha512 hashes to all external script and stylesheet tags using the 'integrity' attribute.",
                    owasp_category="A08:2021-Software and Data Integrity Failures",
                    iso_control="A.14.2.5 Secure System Architecture",
                    fix_hours_dev=0.75,
                    fix_hours_tester=0.5,
                    estimated_fix_cost=96.25,
                    risk_score=48.0
                ))


    return findings
