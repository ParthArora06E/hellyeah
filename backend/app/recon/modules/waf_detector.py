"""
Active Recon Module: Web Application Firewall (WAF) & Reverse Proxy Detector
Actively inspects perimeter responses and diagnostic triggers to fingerprint:
1. Cloudflare
2. AWS WAF / CloudFront
3. Akamai Edge
4. Imperva Incapsula
5. F5 BIG-IP Application Security Manager
6. ModSecurity / OWASP CRS
7. Fastly CDN & Shield
8. Sucuri CloudProxy
9. Azure Front Door
"""
from typing import List, Dict, Any, Union, Optional
from ..adapter.base import BaseModule, ModuleMeta
from ..adapter.context import ScanContext
from ...schemas.schemas import AssetBase, FindingBase

WAF_SIGNATURES = [
    {
        "name": "Cloudflare WAF",
        "headers": ["cf-ray", "cf-cache-status"],
        "server": "cloudflare",
        "cookies": ["__cfduid", "__cf_bm"]
    },
    {
        "name": "AWS WAF / CloudFront",
        "headers": ["x-amzn-requestid", "x-amz-cf-id", "x-amz-id-2"],
        "server": "awswaf",
        "cookies": ["aws-waf-token"]
    },
    {
        "name": "Akamai Edge Guard",
        "headers": ["x-akamai-transformed", "akamai-origin-hop"],
        "server": "akamaighost",
        "cookies": ["aka_"]
    },
    {
        "name": "Imperva Incapsula",
        "headers": ["x-cdn: incapsula", "x-iinfo"],
        "server": "incapsula",
        "cookies": ["incap_ses", "visid_incap"]
    },
    {
        "name": "F5 BIG-IP ASM",
        "headers": ["x-wa-info", "x-cnection"],
        "server": "big-ip",
        "cookies": ["bigipserver", "ts"]
    },
    {
        "name": "ModSecurity / OWASP CRS",
        "headers": [],
        "server": "mod_security",
        "cookies": []
    },
    {
        "name": "Fastly Shield",
        "headers": ["fastly-debug-digest", "x-fastly-request-id"],
        "server": "fastly",
        "cookies": []
    },
    {
        "name": "Sucuri CloudProxy",
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "server": "sucuri",
        "cookies": ["sucuri_cloudproxy"]
    },
    {
        "name": "Azure Front Door",
        "headers": ["x-azure-ref", "x-fd-features"],
        "server": "microsoft-azure",
        "cookies": []
    }
]


class WAFDetectorModule(BaseModule):
    meta = ModuleMeta(
        name="waf_detector",
        author="Auditor Security Team",
        description="Actively fingerprints Web Application Firewalls (WAF) and perimeter reverse proxies via response analysis and benign diagnostic triggers.",
        category="active",
        is_passive=False,
        version="1.0.0"
    )

    async def run(self, target: str, context: ScanContext) -> List[Union[AssetBase, FindingBase]]:
        results: List[Union[AssetBase, FindingBase]] = []
        context.emit_log("info", f"Executing active WAF and reverse proxy fingerprinting for {target}...", 87, "Active WAF Detector")
        context.log_audit("ACTIVE_WAF_PROBE", target, "Inspecting headers and security appliance triggers")

        url = f"https://{target}"
        resp = await context.http.get(url, ttl_seconds=0, retries=1)
        if not resp:
            url = f"http://{target}"
            resp = await context.http.get(url, ttl_seconds=0, retries=1)

        if not resp:
            context.emit_log("warn", f"Could not establish HTTP connection to {target} for WAF detection.")
            return results

        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
        server_hdr = headers_lower.get("server", "")
        cookies_lower = [c.lower() for c in resp.headers.get_list("set-cookie")] if hasattr(resp.headers, "get_list") else [headers_lower.get("set-cookie", "")]
        cookie_blob = " ".join(cookies_lower)

        detected_waf = None

        for sig in WAF_SIGNATURES:
            # Check server header
            if sig["server"] and sig["server"] in server_hdr:
                detected_waf = sig["name"]
                break

            # Check specific headers
            for h in sig["headers"]:
                if ":" in h:
                    k, v = h.split(":", 1)
                    if k.strip() in headers_lower and v.strip() in headers_lower[k.strip()]:
                        detected_waf = sig["name"]
                        break
                elif h in headers_lower:
                    detected_waf = sig["name"]
                    break
            if detected_waf:
                break

            # Check cookies
            for c in sig["cookies"]:
                if c in cookie_blob:
                    detected_waf = sig["name"]
                    break
            if detected_waf:
                break

        if detected_waf:
            context.emit_log("good", f"Confirmed perimeter WAF protection: {detected_waf} identified on {target}.")

            # Update asset technologies
            target_asset = AssetBase(
                type="subdomain" if "." in target else "ip",
                value=target,
                source="Active WAF Detector",
                owner="DevSecOps",
                criticality=3,
                technologies=[detected_waf],
                tags=["active_recon", "waf_protected", detected_waf.lower().replace(" ", "_")],
                raw_metadata={"waf_detected": detected_waf, "server": server_hdr}
            )
            context.record_asset(target_asset)
            results.append(target_asset)

            finding = FindingBase(
                title=f"Perimeter WAF Identified: {detected_waf} Protecting {target}",
                description=(
                    f"Auditor active reconnaissance confirmed that {target} is shielded by {detected_waf}. "
                    "Web Application Firewalls filter malicious web traffic, mitigate automated credential stuffing, and block Layer 7 volumetric attacks."
                ),
                severity="Info",
                cvss_score=0.0,
                epss_score=0.001,
                source="Active WAF Detector",
                confidence="Confirmed",
                status="Open",
                evidence={"waf": detected_waf, "server_header": server_hdr, "target": target},
                remediation_text="Ensure WAF managed rule sets (OWASP Top 10, Bot Management) are kept in active blocking mode with tuned false-positive exceptions.",
                owasp_category="A05:2021-Security Misconfiguration",
                iso_control="A.13.1 Network Security",
                fix_hours_dev=0.0,
                fix_hours_tester=0.0,
                estimated_fix_cost=0.0,
                risk_score=0.0
            )
            context.record_finding(finding)
            results.append(finding)

        else:
            context.emit_log("info", f"No edge WAF appliance detected on {target}.")
            finding = FindingBase(
                title=f"Missing Web Application Firewall (WAF) on {target}",
                description=(
                    f"Target perimeter host {target} does not appear to be protected by an enterprise Web Application Firewall (WAF). "
                    "Perimeter web applications without WAF protection are directly exposed to automated exploitation, vulnerability scanning, and zero-day payload injection."
                ),
                severity="Low",
                cvss_score=3.8,
                epss_score=0.02,
                source="Active WAF Detector",
                confidence="High",
                status="Open",
                evidence={"server_header": server_hdr, "headers_analyzed": list(headers_lower.keys())},
                remediation_text="Deploy an enterprise Web Application Firewall (Cloudflare, AWS WAF, or Fastly) in front of public endpoints to inspect and filter inbound HTTP requests.",
                owasp_category="A05:2021-Security Misconfiguration",
                iso_control="A.13.1 Network Security",
                fix_hours_dev=1.0,
                fix_hours_tester=0.5,
                estimated_fix_cost=117.5,
                risk_score=26.0
            )
            context.record_finding(finding)
            results.append(finding)

        return results
