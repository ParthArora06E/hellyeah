"""
AlienVault OTX Passive DNS Module
Ported & Adapted from Recon-ng / Preconng enrichment.py
Licensed under GNU General Public License v3.0 (GPL-3.0)
"""
from typing import List, Union
from ..adapter.base import BaseModule, ModuleMeta
from ..adapter.context import ScanContext
from ...schemas.schemas import AssetBase, FindingBase

class AlienVaultOTXModule(BaseModule):
    meta = ModuleMeta(
        name="alienvault_otx",
        author="Auditor Security Team (Adapted from Recon-ng)",
        description="Extracts passive DNS records and subdomains from AlienVault OTX indicator database.",
        category="discovery",
        is_passive=True,
        version="1.0.0"
    )
    required_keys = ["OTX_KEY"]

    async def run(self, target: str, context: ScanContext) -> List[Union[AssetBase, FindingBase]]:
        results: List[Union[AssetBase, FindingBase]] = []
        api_key = self.get_api_key("OTX_KEY")
        if not api_key:
            context.emit_log("info", "AlienVault OTX API key not configured. Skipping module gracefully.")
            return results

        context.emit_log("info", f"Querying AlienVault OTX passive DNS for {target}...")
        context.log_audit("OTX_QUERY", target, "Querying passive_dns indicators")
        
        headers = {"X-OTX-API-KEY": api_key}
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns"
        
        try:
            data = await context.http.get_json(url, headers=headers, ttl_seconds=600)
            if not data or "passive_dns" not in data:
                context.emit_log("warn", "OTX passive DNS returned no data.")
                return results

            discovered = set()
            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname", "").strip().lower()
                ip_addr = entry.get("address")
                asn = entry.get("asn")
                if hostname and hostname.endswith(target) and hostname not in discovered:
                    discovered.add(hostname)
                    asset = AssetBase(
                        type="subdomain" if hostname != target else "domain",
                        value=hostname,
                        source="AlienVault OTX",
                        owner="Unassigned",
                        criticality=3,
                        ip_address=ip_addr,
                        asn=asn,
                        tags=["passive_dns", "otx_indicator"],
                        raw_metadata={"first": entry.get("first"), "last": entry.get("last")}
                    )
                    context.record_asset(asset)
                    results.append(asset)

            context.emit_log("good", f"AlienVault OTX yielded {len(discovered)} assets.")
        except Exception as e:
            context.emit_log("warn", f"AlienVault OTX error: {e}")

        return results
