"""
Shodan Host Intelligence Module
Ported & Adapted from Recon-ng / Preconng parsers/shodan_parser.py
Licensed under GNU General Public License v3.0 (GPL-3.0)
"""
import socket
from typing import List, Union
from ..adapter.base import BaseModule, ModuleMeta
from ..adapter.context import ScanContext
from ...schemas.schemas import AssetBase, FindingBase

class ShodanHostModule(BaseModule):
    meta = ModuleMeta(
        name="shodan_host",
        author="Auditor Security Team (Adapted from Recon-ng)",
        description="Extracts passive service banners, open ports, operating system fingerprints, and known CVEs from Shodan database.",
        category="discovery",
        is_passive=True,
        version="1.0.0"
    )
    required_keys = ["SHODAN_KEY"]

    async def run(self, target: str, context: ScanContext) -> List[Union[AssetBase, FindingBase]]:
        results: List[Union[AssetBase, FindingBase]] = []
        api_key = self.get_api_key("SHODAN_KEY")
        if not api_key:
            context.emit_log("info", "Shodan API key not configured. Skipping passive Shodan intelligence.")
            return results

        # Resolve IP for target
        try:
            ip_addr = socket.gethostbyname(target)
        except Exception:
            context.emit_log("warn", f"Could not resolve IP for {target} to query Shodan.")
            return results

        context.emit_log("info", f"Querying Shodan intelligence for IP {ip_addr} ({target})...")
        context.log_audit("SHODAN_HOST_QUERY", ip_addr, "Querying Shodan host profile")
        
        url = f"https://api.shodan.io/shodan/host/{ip_addr}?key={api_key}"
        try:
            data = await context.http.get_json(url, ttl_seconds=1800)
            if not data or "error" in data:
                context.emit_log("warn", f"Shodan response: {data.get('error', 'No host record') if data else 'Empty'}")
                return results

            ports = data.get("ports", [])
            os_name = data.get("os")
            org = data.get("org")
            isp = data.get("isp")
            hostnames = data.get("hostnames", [])
            vulns = list(data.get("vulns", {}).keys()) if isinstance(data.get("vulns"), dict) else []

            # Extract banners and product names
            tech_stack = []
            for item in data.get("data", []):
                product = item.get("product")
                version = item.get("version")
                port = item.get("port")
                if product:
                    tech_str = f"{product} {version}".strip() if version else product
                    tech_stack.append(f"{tech_str} (port {port})")

            asset = AssetBase(
                type="ip",
                value=ip_addr,
                source="Shodan Intelligence",
                owner=org or "Network Infrastructure",
                criticality=4 if any(p in [22, 3389, 445, 1433, 3306, 5432] for p in ports) else 3,
                ip_address=ip_addr,
                technologies=list(set(tech_stack)),
                ports=ports,
                tags=["shodan_indexed", f"org:{org or 'unknown'}"],
                raw_metadata={
                    "os": os_name,
                    "isp": isp,
                    "hostnames": hostnames,
                    "shodan_vulns": vulns
                }
            )
            created_asset = context.record_asset(asset)
            results.append(asset)

            # If Shodan directly recorded CVEs for this host, record them as Findings
            asset_db_id = created_asset.id if created_asset else None
            for cve in vulns[:5]:  # limit to top 5 from Shodan
                finding = FindingBase(
                    title=f"Shodan Flagged CVE: {cve} on {ip_addr}",
                    description=f"Shodan search engine indexed known vulnerability {cve} on host {ip_addr} (ports {ports}).",
                    severity="High",
                    cvss_score=7.5,
                    epss_score=0.15,
                    cve_ids=[cve],
                    source="Shodan Host Vulnerability Feed",
                    confidence="Confirmed",
                    status="Open",
                    evidence={"shodan_cve": cve, "ports": ports, "ip": ip_addr},
                    remediation_text=f"Patch the vulnerable service on {ip_addr} or restrict network ingress via security group/firewall.",
                    owasp_category="A06:2021-Vulnerable and Outdated Components",
                    iso_control="A.12.6.1 Management of Technical Vulnerabilities",
                    fix_hours_dev=4.0,
                    fix_hours_tester=2.0,
                    estimated_fix_cost=470.0,
                    risk_score=75.0
                )
                context.record_finding(finding, asset_id=asset_db_id)
                results.append(finding)

            context.emit_log("good", f"Shodan enriched {ip_addr}: {len(ports)} open ports, {len(vulns)} indexed CVEs.")
        except Exception as e:
            context.emit_log("warn", f"Shodan module error: {e}")

        return results
