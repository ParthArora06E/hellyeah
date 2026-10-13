"""
Wayback Machine Archive Intelligence Module
Ported & Adapted from Recon-ng / Preconng core/wayback.py
Licensed under GNU General Public License v3.0 (GPL-3.0)
"""
import re
from typing import List, Union
from urllib.parse import urlparse
from ..adapter.base import BaseModule, ModuleMeta
from ..adapter.context import ScanContext
from ...schemas.schemas import AssetBase, FindingBase

class WaybackModule(BaseModule):
    meta = ModuleMeta(
        name="wayback_archive",
        author="Auditor Security Team (Adapted from Recon-ng)",
        description="Queries Internet Archive (Wayback CDX API) to discover historical endpoints, subdomains, and exposed sensitive path patterns.",
        category="discovery",
        is_passive=True,
        version="1.0.0"
    )
    required_keys = []

    async def run(self, target: str, context: ScanContext) -> List[Union[AssetBase, FindingBase]]:
        context.emit_log("info", f"Harvesting historical endpoints from Wayback Machine for {target}...")
        context.log_audit("WAYBACK_CDX_QUERY", target, "Fetching CDX archive URLs")
        
        results: List[Union[AssetBase, FindingBase]] = []
        cdx_url = f"http://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&collapse=urlkey&limit=500"
        
        try:
            data = await context.http.get_json(cdx_url, ttl_seconds=3600)
            if not data or len(data) <= 1:
                context.emit_log("info", f"Wayback CDX yielded no historical archives for {target}.")
                return results

            # data[0] is header: ["urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"]
            rows = data[1:]
            discovered_hosts = set()
            sensitive_endpoints = []

            sensitive_patterns = [
                r"\.env", r"\.git", r"\.config", r"backup", r"dump\.sql",
                r"phpinfo\.php", r"/api/v1/user", r"/graphql", r"/admin/login",
                r"id_rsa", r"secrets", r"\.bak"
            ]

            for row in rows:
                if not row or len(row) < 3:
                    continue
                orig_url = row[2]
                try:
                    parsed = urlparse(orig_url)
                    host = parsed.netloc.split(":")[0].lower()
                    if host and host.endswith(target) and host not in discovered_hosts:
                        discovered_hosts.add(host)
                        asset = AssetBase(
                            type="subdomain" if host != target else "domain",
                            value=host,
                            source="Wayback Machine CDX",
                            owner="Unassigned",
                            criticality=3,
                            tags=["wayback_archive", "historical_host"]
                        )
                        context.record_asset(asset)
                        results.append(asset)

                    # Check sensitive endpoint pattern
                    path = parsed.path.lower()
                    for pattern in sensitive_patterns:
                        if re.search(pattern, path):
                            sensitive_endpoints.append(orig_url)
                            break
                except Exception:
                    continue

            # If sensitive historical URLs were indexed, record as informational finding
            if sensitive_endpoints:
                finding = FindingBase(
                    title=f"Historical Sensitive Endpoints Indexed in Wayback for {target}",
                    description=f"Internet Archive historical snapshots contain {len(sensitive_endpoints)} potentially sensitive URLs (e.g., config files, admin paths, or backups) that may remain exposed or reveal internal architecture.",
                    severity="Medium",
                    cvss_score=5.0,
                    epss_score=0.04,
                    source="Wayback Machine CDX Archive",
                    confidence="Medium",
                    status="Open",
                    evidence={"sample_urls": sensitive_endpoints[:10], "total_matches": len(sensitive_endpoints)},
                    remediation_text="Verify that historical configuration files, backups, or legacy admin endpoints are completely decommissioned and return HTTP 404.",
                    owasp_category="A01:2021-Broken Access Control",
                    iso_control="A.12.1.2 Change Management",
                    fix_hours_dev=1.0,
                    fix_hours_tester=0.5,
                    estimated_fix_cost=117.5,
                    risk_score=45.0
                )
                context.record_finding(finding)
                results.append(finding)

            context.emit_log("good", f"Wayback CDX extracted {len(discovered_hosts)} historical subdomains and {len(sensitive_endpoints)} sensitive paths.")
        except Exception as e:
            context.emit_log("warn", f"Wayback CDX error: {e}")

        return results
