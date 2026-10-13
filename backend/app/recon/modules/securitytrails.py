"""
SecurityTrails Subdomain Enumeration Module
Ported & Adapted from Recon-ng / Preconng enrichment.py
Licensed under GNU General Public License v3.0 (GPL-3.0)
"""
from typing import List, Union
from ..adapter.base import BaseModule, ModuleMeta
from ..adapter.context import ScanContext
from ...schemas.schemas import AssetBase, FindingBase

class SecurityTrailsModule(BaseModule):
    meta = ModuleMeta(
        name="securitytrails_subdomains",
        author="Auditor Security Team (Adapted from Recon-ng)",
        description="Retrieves known subdomains from SecurityTrails API.",
        category="discovery",
        is_passive=True,
        version="1.0.0"
    )
    required_keys = ["SECURITYTRAILS_KEY"]

    async def run(self, target: str, context: ScanContext) -> List[Union[AssetBase, FindingBase]]:
        results: List[Union[AssetBase, FindingBase]] = []
        api_key = self.get_api_key("SECURITYTRAILS_KEY")
        if not api_key:
            context.emit_log("info", "SecurityTrails API key not configured. Skipping module gracefully.")
            return results

        context.emit_log("info", f"Querying SecurityTrails API for subdomains of {target}...")
        context.log_audit("SECURITYTRAILS_QUERY", target, "Fetching subdomains list")
        
        headers = {"APIKEY": api_key}
        url = f"https://api.securitytrails.com/v1/domain/{target}/subdomains"
        
        try:
            data = await context.http.get_json(url, headers=headers, ttl_seconds=600)
            if not data or "subdomains" not in data:
                context.emit_log("warn", "SecurityTrails returned no subdomains.")
                return results

            subs = data.get("subdomains", [])
            for s in subs:
                fqdn = f"{s.strip().lower()}.{target}"
                asset = AssetBase(
                    type="subdomain",
                    value=fqdn,
                    source="SecurityTrails API",
                    owner="Unassigned",
                    criticality=3,
                    tags=["securitytrails", "subdomain"]
                )
                context.record_asset(asset)
                results.append(asset)

            context.emit_log("good", f"SecurityTrails discovered {len(subs)} subdomains.")
        except Exception as e:
            context.emit_log("warn", f"SecurityTrails error: {e}")

        return results
