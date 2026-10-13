"""
URLScan.io Visual & Technology Profiling Module
Ported & Adapted from Recon-ng / Preconng parsers/urlscan_parser.py
Licensed under GNU General Public License v3.0 (GPL-3.0)
"""
from typing import List, Union
from ..adapter.base import BaseModule, ModuleMeta
from ..adapter.context import ScanContext
from ...schemas.schemas import AssetBase, FindingBase

class URLScanModule(BaseModule):
    meta = ModuleMeta(
        name="urlscan_lookup",
        author="Auditor Security Team (Adapted from Recon-ng)",
        description="Gathers visual screenshots, web server headers, and domain links from URLScan.io index.",
        category="discovery",
        is_passive=True,
        version="1.0.0"
    )
    required_keys = ["URLSCAN_KEY"]

    async def run(self, target: str, context: ScanContext) -> List[Union[AssetBase, FindingBase]]:
        results: List[Union[AssetBase, FindingBase]] = []
        api_key = self.get_api_key("URLSCAN_KEY")
        if not api_key:
            context.emit_log("info", "URLScan API key not configured. Skipping module gracefully.")
            return results

        context.emit_log("info", f"Searching URLScan.io historical indices for {target}...")
        context.log_audit("URLSCAN_SEARCH", target, "Searching public scan history")
        
        headers = {"API-Key": api_key, "Content-Type": "application/json"}
        search_url = f"https://urlscan.io/api/v1/search/?q=domain:{target}"
        
        try:
            data = await context.http.get_json(search_url, headers=headers, ttl_seconds=1800)
            if not data or not data.get("results"):
                context.emit_log("info", f"URLScan found no indexed pages for {target}.")
                return results

            latest = data["results"][0]
            page_meta = latest.get("page", {})
            server_header = page_meta.get("server")
            country = page_meta.get("country")
            screenshot_url = latest.get("screenshot")
            domains_linked = latest.get("lists", {}).get("domains", [])

            techs = []
            if server_header:
                techs.append(f"Server:{server_header}")

            asset = AssetBase(
                type="endpoint",
                value=f"https://{target}",
                source="URLScan.io",
                owner="Web Team",
                criticality=3,
                technologies=techs,
                tags=["urlscan_snapshot", f"country:{country or 'unknown'}"],
                raw_metadata={
                    "screenshot": screenshot_url,
                    "server": server_header,
                    "country": country,
                    "linked_domains_count": len(domains_linked)
                }
            )
            context.record_asset(asset)
            results.append(asset)
            context.emit_log("good", f"URLScan matched snapshot. Server: {server_header or 'Hidden'}.")
        except Exception as e:
            context.emit_log("warn", f"URLScan module error: {e}")

        return results
