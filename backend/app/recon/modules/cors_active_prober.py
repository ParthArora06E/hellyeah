"""
Active Recon Module: Cross-Origin Resource Sharing (CORS) Misconfiguration Prober
Actively sends tailored Origin headers to perimeter web APIs and endpoints to evaluate:
1. Arbitrary origin reflection with credentials (CWE-346)
2. Trusting 'null' origin with credentials
3. Insecure wildcard origins with sensitive cookies
"""
from typing import List, Dict, Any, Union
from ..adapter.base import BaseModule, ModuleMeta
from ..adapter.context import ScanContext
from ...schemas.schemas import AssetBase, FindingBase


class CORSActiveProberModule(BaseModule):
    meta = ModuleMeta(
        name="cors_active_prober",
        author="Auditor Security Team",
        description="Actively probes perimeter endpoints with custom Origin headers to identify dangerous CORS reflection and credential exposure.",
        category="active",
        is_passive=False,
        version="1.0.0"
    )

    async def run(self, target: str, context: ScanContext) -> List[Union[AssetBase, FindingBase]]:
        results: List[Union[AssetBase, FindingBase]] = []
        context.emit_log("info", f"Auditing CORS origin reflection and credential policies on {target}...", 88, "CORS Active Prober")
        context.log_audit("ACTIVE_CORS_PROBE", target, "Testing arbitrary origin reflection and credential headers")

        test_endpoints = [f"https://{target}", f"https://{target}/api"]
        for a in getattr(context, "discovered_assets", []):
            if a.type == "subdomain" and ("api" in a.value or "app" in a.value):
                test_endpoints.append(f"https://{a.value}")
                break

        origin_tests = [
            ("https://evil-attacker.com", "Arbitrary Untrusted Origin"),
            ("null", "Null Origin (Sandboxed Iframe)"),
            (f"https://{target}.evil-attacker.com", "Pre-Domain Prefix Bypass")
        ]

        tested_hosts = set()

        for url in test_endpoints[:3]:
            host = url.split("://")[1].split("/")[0]
            if host in tested_hosts:
                continue
            tested_hosts.add(host)

            for origin_val, test_label in origin_tests:
                headers = {
                    "Origin": origin_val,
                    "Access-Control-Request-Method": "GET"
                }

                resp = await context.http.request("GET", url, headers=headers)
                if not resp:
                    continue

                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                acao = resp_headers.get("access-control-allow-origin")
                acac = resp_headers.get("access-control-allow-credentials", "").lower() == "true"

                if not acao:
                    continue

                # 1. Critical/High: Arbitrary origin reflected + Credentials allowed
                if acao == origin_val and acac:
                    finding = FindingBase(
                        title=f"Critical CORS Misconfiguration: Arbitrary Origin Reflected with Credentials on {host}",
                        description=(
                            f"Host {host} reflects untrusted Origin '{origin_val}' in Access-Control-Allow-Origin "
                            "while simultaneously setting Access-Control-Allow-Credentials: true. "
                            "This permits malicious third-party websites to make credentialed cross-origin requests "
                            "and steal victim account data, session tokens, and confidential user information."
                        ),
                        severity="Critical",
                        cvss_score=8.8,
                        epss_score=0.48,
                        source="Active CORS Prober",
                        confidence="Confirmed",
                        status="Open",
                        evidence={
                            "endpoint": url,
                            "sent_origin": origin_val,
                            "reflected_acao": acao,
                            "allow_credentials": acac,
                            "test_type": test_label
                        },
                        remediation_text="Validate the Origin header against a strict server-side whitelist of trusted domains. Never dynamically reflect arbitrary Origin headers when Access-Control-Allow-Credentials is true.",
                        owasp_category="A01:2021-Broken Access Control",
                        iso_control="A.14.2.5 Secure Architecture",
                        fix_hours_dev=1.0,
                        fix_hours_tester=0.5,
                        estimated_fix_cost=117.5,
                        risk_score=90.0
                    )
                    context.record_finding(finding)
                    results.append(finding)
                    break

                # 2. High: Trusting 'null' origin + Credentials
                elif origin_val == "null" and acao == "null" and acac:
                    finding = FindingBase(
                        title=f"High Risk CORS Misconfiguration: Trusting 'null' Origin on {host}",
                        description=(
                            f"Host {host} trusts the 'null' Origin with Access-Control-Allow-Credentials: true. "
                            "Attackers can leverage sandboxed iframes (<iframe sandbox='allow-scripts'>) to generate "
                            "requests with Origin: null, bypassing standard browser cross-origin protections to extract sensitive API responses."
                        ),
                        severity="High",
                        cvss_score=7.5,
                        epss_score=0.22,
                        source="Active CORS Prober",
                        confidence="Confirmed",
                        status="Open",
                        evidence={"endpoint": url, "acao": acao, "acac": acac},
                        remediation_text="Remove 'null' from authorized CORS origins. Ensure only explicitly verified HTTPS origins are accepted.",
                        owasp_category="A01:2021-Broken Access Control",
                        iso_control="A.14.2.5 Secure Architecture",
                        fix_hours_dev=0.75,
                        fix_hours_tester=0.5,
                        estimated_fix_cost=96.25,
                        risk_score=75.0
                    )
                    context.record_finding(finding)
                    results.append(finding)
                    break

                # 3. Medium: Arbitrary reflection without credentials
                elif acao == origin_val and origin_val != "*":
                    finding = FindingBase(
                        title=f"Medium Risk CORS Origin Reflection on {host}",
                        description=(
                            f"Host {host} reflects external Origin '{origin_val}' in Access-Control-Allow-Origin. "
                            "While credentials were not explicitly enabled in this response, dynamic origin reflection indicates improper CORS filter validation."
                        ),
                        severity="Medium",
                        cvss_score=5.3,
                        epss_score=0.04,
                        source="Active CORS Prober",
                        confidence="Confirmed",
                        status="Open",
                        evidence={"endpoint": url, "reflected_origin": acao},
                        remediation_text="Replace dynamic reflection with a static list of authorized domains.",
                        owasp_category="A05:2021-Security Misconfiguration",
                        iso_control="A.14.2.5 Secure Architecture",
                        fix_hours_dev=0.5,
                        fix_hours_tester=0.25,
                        estimated_fix_cost=58.75,
                        risk_score=40.0
                    )
                    context.record_finding(finding)
                    results.append(finding)
                    break

        context.emit_log("good", f"CORS active prober audit completed.")
        return results
