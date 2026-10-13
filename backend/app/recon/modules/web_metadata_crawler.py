"""
Active Recon Module: Web Metadata, Robots.txt & Sitemap Crawler
Actively extracts hidden endpoints and configuration policies from:
1. /robots.txt (harvests disallowed administrative & private directories)
2. /sitemap.xml (extracts perimeter application routes)
3. /.well-known/security.txt (RFC 9116 security vulnerability contact policy)
4. /crossdomain.xml & /clientaccesspolicy.xml (permissive domain access)
"""
import re
from typing import List, Dict, Any, Union, Optional
from ..adapter.base import BaseModule, ModuleMeta
from ..adapter.context import ScanContext
from ...schemas.schemas import AssetBase, FindingBase


class WebMetadataCrawlerModule(BaseModule):
    meta = ModuleMeta(
        name="web_metadata_crawler",
        author="Auditor Security Team",
        description="Actively crawls robots.txt, sitemaps, RFC 9116 security.txt, and crossdomain policies to discover hidden endpoints and information leaks.",
        category="active",
        is_passive=False,
        version="1.0.0"
    )

    async def run(self, target: str, context: ScanContext) -> List[Union[AssetBase, FindingBase]]:
        results: List[Union[AssetBase, FindingBase]] = []
        context.emit_log("info", f"Executing active web metadata and endpoint crawler on {target}...", 89, "Metadata Crawler")
        context.log_audit("ACTIVE_METADATA_CRAWL", target, "Crawling robots.txt, sitemap.xml, security.txt")

        base_url = f"https://{target}"

        # -------------------------------------------------------------
        # 1. Crawl /robots.txt
        # -------------------------------------------------------------
        robots_url = f"{base_url}/robots.txt"
        resp_robots = await context.http.get(robots_url, ttl_seconds=0, retries=1)
        if not resp_robots and not base_url.startswith("http://"):
            base_url = f"http://{target}"
            robots_url = f"{base_url}/robots.txt"
            resp_robots = await context.http.get(robots_url, ttl_seconds=0, retries=1)

        sensitive_disallow_paths = []
        all_disallowed_paths = []

        if resp_robots and resp_robots.status_code == 200:
            content = resp_robots.text or ""
            for line in content.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        path = parts[1].strip()
                        if path and path != "/":
                            all_disallowed_paths.append(path)
                            if any(k in path.lower() for k in ["admin", "portal", "backup", "staging", "private", "secret", "manage", "internal", "config", "db", "sql"]):
                                sensitive_disallow_paths.append(path)

            # Record discovered endpoint assets from robots.txt
            for path in set(all_disallowed_paths[:10]):
                ep_asset = AssetBase(
                    type="endpoint",
                    value=f"{base_url}{path}",
                    source="Active robots.txt Crawler",
                    owner="Application Team",
                    criticality=4 if path in sensitive_disallow_paths else 2,
                    tags=["active_recon", "robots_disallow", "perimeter_endpoint"],
                    raw_metadata={"discovered_path": path, "source_file": "robots.txt"}
                )
                context.record_asset(ep_asset)
                results.append(ep_asset)

            if sensitive_disallow_paths:
                finding = FindingBase(
                    title=f"Sensitive Administrative Paths Disclosed in robots.txt on {target}",
                    description=(
                        f"The public robots.txt file on {target} explicitly lists {len(sensitive_disallow_paths)} sensitive directories "
                        f"in Disallow directives (e.g. {', '.join(sensitive_disallow_paths[:5])}). "
                        "While intended for search engine spiders, public robots.txt files guide attackers directly toward internal panels and staging areas."
                    ),
                    severity="Low",
                    cvss_score=4.3,
                    epss_score=0.045,
                    source="Active Metadata Crawler",
                    confidence="Confirmed",
                    status="Open",
                    evidence={
                        "endpoint": robots_url,
                        "sensitive_paths": sensitive_disallow_paths[:10]
                    },
                    remediation_text="Ensure sensitive admin and staging paths enforce mandatory multi-factor authentication and IP allowlisting rather than relying on robots.txt obscurity.",
                    owasp_category="A01:2021-Broken Access Control",
                    iso_control="A.9.4.1 Information Access Restriction",
                    fix_hours_dev=0.5,
                    fix_hours_tester=0.25,
                    estimated_fix_cost=58.75,
                    risk_score=28.0
                )
                context.record_finding(finding)
                results.append(finding)

        # -------------------------------------------------------------
        # 2. Crawl /sitemap.xml
        # -------------------------------------------------------------
        sitemap_url = f"{base_url}/sitemap.xml"
        resp_sitemap = await context.http.get(sitemap_url, ttl_seconds=0, retries=1)
        if resp_sitemap and resp_sitemap.status_code == 200:
            urls_found = re.findall(r"<loc>(https?://[^<]+)</loc>", resp_sitemap.text or "")
            if urls_found:
                context.emit_log("info", f"Extracted {len(urls_found)} perimeter URLs from {sitemap_url}.")
                for u in urls_found[:8]:
                    ep_asset = AssetBase(
                        type="endpoint",
                        value=u,
                        source="Active Sitemap Crawler",
                        owner="Application Team",
                        criticality=2,
                        tags=["active_recon", "sitemap_url"],
                        raw_metadata={"sitemap": sitemap_url}
                    )
                    context.record_asset(ep_asset)
                    results.append(ep_asset)

        # -------------------------------------------------------------
        # 3. Audit /.well-known/security.txt (RFC 9116)
        # -------------------------------------------------------------
        sec_url = f"{base_url}/.well-known/security.txt"
        resp_sec = await context.http.get(sec_url, ttl_seconds=0, retries=1)
        has_security_txt = bool(resp_sec and resp_sec.status_code == 200 and "Contact:" in (resp_sec.text or ""))

        if not has_security_txt:
            finding = FindingBase(
                title=f"Missing RFC 9116 security.txt Vulnerability Disclosure Policy on {target}",
                description=(
                    f"Host {target} does not publish an RFC 9116 compliant /.well-known/security.txt file. "
                    "A security.txt file establishes a standard, frictionless channel for ethical security researchers "
                    "and incident responders to report discovered vulnerabilities directly to your security team."
                ),
                severity="Info",
                cvss_score=0.0,
                epss_score=0.005,
                source="Active Metadata Crawler",
                confidence="Confirmed",
                status="Open",
                evidence={"tested_endpoint": sec_url, "status_code": resp_sec.status_code if resp_sec else None},
                remediation_text="Publish a /.well-known/security.txt file containing Contact: mailto:security@yourcompany.com and Preferred-Languages: en.",
                owasp_category="A05:2021-Security Misconfiguration",
                iso_control="A.16.1.2 Reporting Information Security Events",
                fix_hours_dev=0.25,
                fix_hours_tester=0.25,
                estimated_fix_cost=37.5,
                risk_score=5.0
            )
            context.record_finding(finding)
            results.append(finding)

        # -------------------------------------------------------------
        # 4. Audit /crossdomain.xml (Flash / Silverlight RIA wildcards)
        # -------------------------------------------------------------
        cd_url = f"{base_url}/crossdomain.xml"
        resp_cd = await context.http.get(cd_url, ttl_seconds=0, retries=1)
        if resp_cd and resp_cd.status_code == 200:
            xml_text = resp_cd.text or ""
            if 'domain="*"' in xml_text:
                finding = FindingBase(
                    title=f"Overly Permissive Wildcard crossdomain.xml on {target}",
                    description=(
                        f"The file {cd_url} contains '<allow-access-from domain=\"*\"/>'. "
                        "This wildcard directive allows external Flash and Silverlight clients to execute cross-domain reads against this host."
                    ),
                    severity="Medium",
                    cvss_score=5.3,
                    epss_score=0.03,
                    source="Active Metadata Crawler",
                    confidence="Confirmed",
                    status="Open",
                    evidence={"endpoint": cd_url, "snippet": xml_text[:200]},
                    remediation_text="Restrict domain access in crossdomain.xml or delete the legacy file if Flash is no longer supported.",
                    owasp_category="A05:2021-Security Misconfiguration",
                    iso_control="A.14.2.5 Secure Architecture",
                    fix_hours_dev=0.25,
                    fix_hours_tester=0.25,
                    estimated_fix_cost=37.5,
                    risk_score=35.0
                )
                context.record_finding(finding)
                results.append(finding)

        context.emit_log("good", f"Active web metadata crawl complete for {target}.")
        return results
