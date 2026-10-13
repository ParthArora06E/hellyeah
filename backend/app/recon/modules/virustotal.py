"""
VirusTotal v3 Subdomain Enumeration Module
Harvests historically observed subdomains and DNS records via VirusTotal API v3.
"""
from typing import List, Union
from ..adapter.base import BaseModule, ModuleMeta
from ..adapter.context import ScanContext
from ...schemas.schemas import AssetBase, FindingBase

class VirusTotalModule(BaseModule):
    meta = ModuleMeta(
        name="virustotal_subdomains",
        author="Auditor Security Team",
        description="Retrieves known subdomains from VirusTotal API v3.",
        category="discovery",
        is_passive=True,
        version="1.0.0"
    )
    required_keys = ["VIRUSTOTAL_KEY"]

    async def run(self, target: str, context: ScanContext) -> List[Union[AssetBase, FindingBase]]:
        results: List[Union[AssetBase, FindingBase]] = []
        api_key = self.get_api_key("VIRUSTOTAL_KEY")
        if not api_key:
            context.emit_log("info", "VirusTotal API key not configured. Skipping module gracefully.")
            return results

        context.emit_log("info", f"Querying VirusTotal v3 for subdomains of {target}...")
        context.log_audit("VIRUSTOTAL_QUERY", target, "Fetching subdomains via VT API v3")

        headers = {"x-apikey": api_key}
        url = f"https://www.virustotal.com/api/v3/domains/{target}/subdomains?limit=40"

        try:
            data = await context.http.get_json(url, headers=headers, ttl_seconds=600)
            if not data or "data" not in data:
                context.emit_log("warn", "VirusTotal returned no subdomain records or empty dataset.")
                return results

            items = data.get("data", [])
            discovered_count = 0
            for item in items:
                sub_id = item.get("id", "").strip().lower()
                if not sub_id:
                    continue
                if sub_id.endswith(target) or sub_id == target:
                    discovered_count += 1
                    asset = AssetBase(
                        type="subdomain" if sub_id != target else "domain",
                        value=sub_id,
                        source="VirusTotal API v3",
                        owner="Unassigned",
                        criticality=4 if any(k in sub_id for k in ["admin", "api", "auth", "vpn", "cpanel", "webmail"]) else 3,
                        tags=["virustotal", "subdomain", "dns_record"],
                        raw_metadata={
                            "last_analysis_stats": item.get("attributes", {}).get("last_analysis_stats", {}),
                            "last_update_date": item.get("attributes", {}).get("last_update_date")
                        }
                    )
                    context.record_asset(asset)
                    results.append(asset)

            context.emit_log("good", f"VirusTotal discovered {discovered_count} subdomains for {target}.")
        except Exception as e:
            context.emit_log("warn", f"VirusTotal query encountered an error: {e}")

        return results
