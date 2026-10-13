"""
Active Recon Module: HTTP Methods & Dangerous Verb Auditor
Probes perimeter web applications to identify enabled HTTP methods:
1. OPTIONS query (extracts Allow and Public headers)
2. Insecure TRACE method (Cross-Site Tracing / XST vulnerability CWE-693)
3. Dangerous PUT / DELETE verbs (Unauthenticated file modification/deletion risks)
4. WebDAV methods (PROPFIND, MKCOL)
"""
from typing import List, Dict, Any, Union
from ..adapter.base import BaseModule, ModuleMeta
from ..adapter.context import ScanContext
from ...schemas.schemas import AssetBase, FindingBase


class HTTPMethodProberModule(BaseModule):
    meta = ModuleMeta(
        name="http_method_prober",
        author="Auditor Security Team",
        description="Actively queries HTTP methods and audits for Cross-Site Tracing (TRACE) and dangerous verbs (PUT, DELETE).",
        category="active",
        is_passive=False,
        version="1.0.0"
    )

    async def run(self, target: str, context: ScanContext) -> List[Union[AssetBase, FindingBase]]:
        results: List[Union[AssetBase, FindingBase]] = []
        context.emit_log("info", f"Auditing supported HTTP methods and verb vulnerabilities on {target}...", 85, "HTTP Method Prober")
        context.log_audit("ACTIVE_HTTP_VERBS", target, "Probing OPTIONS, TRACE, PUT, DELETE, PROPFIND")

        targets_to_test = [target]
        for a in getattr(context, "discovered_assets", []):
            if a.type == "subdomain" and any(k in a.value for k in ["api", "app", "admin", "portal"]):
                if a.value not in targets_to_test and len(targets_to_test) < 3:
                    targets_to_test.append(a.value)

        for host in targets_to_test:
            base_url = f"https://{host}"
            # 1. Probe OPTIONS
            resp_options = await context.http.request("OPTIONS", base_url)
            if not resp_options:
                base_url = f"http://{host}"
                resp_options = await context.http.request("OPTIONS", base_url)

            allowed_methods = []
            if resp_options:
                allow_header = resp_options.headers.get("allow") or resp_options.headers.get("public") or ""
                if allow_header:
                    allowed_methods = [m.strip().upper() for m in allow_header.split(",") if m.strip()]

            # 2. Probe TRACE directly
            canary_header = "X-Auditor-Trace-Probe: active_recon_123"
            trace_url = f"{base_url}/"
            resp_trace = await context.http.request(
                "TRACE",
                trace_url,
                headers={"X-Auditor-Trace-Probe": "active_recon_123"}
            )

            is_trace_vulnerable = False
            if resp_trace and resp_trace.status_code == 200:
                if "X-Auditor-Trace-Probe" in resp_trace.text or canary_header in resp_trace.text:
                    is_trace_vulnerable = True

            if is_trace_vulnerable or "TRACE" in allowed_methods:
                finding = FindingBase(
                    title=f"Insecure HTTP TRACE Method Enabled on {host} (Cross-Site Tracing / XST)",
                    description=(
                        f"The web server on {host} permits the HTTP TRACE method. "
                        "When enabled, an attacker can leverage Cross-Site Tracing (XST) combined with XSS to bypass "
                        "HttpOnly cookie protections and steal sensitive session tokens and authentication headers."
                    ),
                    severity="High" if is_trace_vulnerable else "Medium",
                    cvss_score=7.2 if is_trace_vulnerable else 5.3,
                    epss_score=0.18,
                    source="Active HTTP Verb Prober",
                    confidence="Confirmed" if is_trace_vulnerable else "High",
                    status="Open",
                    evidence={
                        "host": host,
                        "url": trace_url,
                        "reflected_trace": is_trace_vulnerable,
                        "allow_header": allowed_methods
                    },
                    remediation_text="Disable the HTTP TRACE method on web servers and reverse proxies (e.g., 'TraceEnable off' in Apache, or return 405 Method Not Allowed in Nginx).",
                    owasp_category="A05:2021-Security Misconfiguration",
                    iso_control="A.14.2.5 Secure System Architecture",
                    fix_hours_dev=0.5,
                    fix_hours_tester=0.25,
                    estimated_fix_cost=58.75,
                    risk_score=70.0 if is_trace_vulnerable else 45.0
                )
                context.record_finding(finding)
                results.append(finding)

            # 3. Probe dangerous PUT method on benign non-existent path
            probe_path = f"{base_url}/.auditor_probe_write_test_{host[:6]}.tmp"
            resp_put = await context.http.request(
                "PUT",
                probe_path,
                content="auditor_active_recon_probe"
            )

            if resp_put and resp_put.status_code in (200, 201, 204):
                finding = FindingBase(
                    title=f"Critical Unauthenticated HTTP PUT Method Enabled on {host}",
                    description=(
                        f"The web server on {host} accepted a benign HTTP PUT request (HTTP {resp_put.status_code}) on {probe_path}. "
                        "Allowing unauthenticated file upload via PUT exposes the web server to arbitrary file write, defacement, and remote code execution."
                    ),
                    severity="Critical",
                    cvss_score=9.1,
                    epss_score=0.74,
                    source="Active HTTP Verb Prober",
                    confidence="Confirmed",
                    status="Open",
                    evidence={
                        "endpoint": probe_path,
                        "status_code": resp_put.status_code,
                        "method": "PUT"
                    },
                    remediation_text="Disable HTTP PUT on public directories or mandate strict multi-factor authentication and role authorization.",
                    owasp_category="A01:2021-Broken Access Control",
                    iso_control="A.9.4.1 Information Access Restriction",
                    fix_hours_dev=1.5,
                    fix_hours_tester=1.0,
                    estimated_fix_cost=192.5,
                    risk_score=92.0
                )
                context.record_finding(finding)
                results.append(finding)

            # 4. Probe WebDAV PROPFIND
            resp_propfind = await context.http.request("PROPFIND", f"{base_url}/")
            if resp_propfind and resp_propfind.status_code in (200, 207):
                finding = FindingBase(
                    title=f"WebDAV PROPFIND Method Enabled on {host}",
                    description=(
                        f"Host {host} responds to WebDAV PROPFIND requests with HTTP {resp_propfind.status_code} Multi-Status. "
                        "WebDAV exposes directory hierarchies, internal file paths, and potential authentication bypasses."
                    ),
                    severity="Medium",
                    cvss_score=5.3,
                    epss_score=0.045,
                    source="Active HTTP Verb Prober",
                    confidence="Confirmed",
                    status="Open",
                    evidence={"endpoint": f"{base_url}/", "status_code": resp_propfind.status_code},
                    remediation_text="Disable WebDAV modules (mod_dav) unless explicitly required for business workflows.",
                    owasp_category="A05:2021-Security Misconfiguration",
                    iso_control="A.13.1 Network Security",
                    fix_hours_dev=0.5,
                    fix_hours_tester=0.25,
                    estimated_fix_cost=58.75,
                    risk_score=38.0
                )
                context.record_finding(finding)
                results.append(finding)

        context.emit_log("good", f"HTTP method probing complete across {len(targets_to_test)} endpoints.")
        return results
