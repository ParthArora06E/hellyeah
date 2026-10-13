"""
crt.sh Certificate Transparency Subdomain Enumeration Module
Ported & Adapted from Recon-ng / Preconng enrichment.py
Licensed under GNU General Public License v3.0 (GPL-3.0)
"""
import re
from typing import List, Union
from ..adapter.base import BaseModule, ModuleMeta
from ..adapter.context import ScanContext
from ...schemas.schemas import AssetBase, FindingBase

class CrtshModule(BaseModule):
    meta = ModuleMeta(
        name="crtsh_subdomains",
        author="Auditor Security Team (Adapted from Recon-ng)",
        description="Harvests subdomains via public Certificate Transparency logs (crt.sh).",
        category="discovery",
        is_passive=True,
        version="1.0.0"
    )
    required_keys = []

    async def run(self, target: str, context: ScanContext) -> List[Union[AssetBase, FindingBase]]:
        context.emit_log("info", f"Querying Certificate Transparency logs for {target} via crt.sh...")
        context.log_audit("CRT_SH_QUERY", target, "Fetching CT logs")
        url = f"https://crt.sh/?q=%25.{target}&output=json"
        
        results: List[Union[AssetBase, FindingBase]] = []
        try:
            data = await context.http.get_json(url, ttl_seconds=600)
            if not data or not isinstance(data, list):
                context.emit_log("warn", f"crt.sh returned no records or timed out for {target}.")
                return results

            discovered = set()
            for entry in data:
                name_value = entry.get("name_value", "")
                if not name_value:
                    continue
                # May contain multiple domains separated by newline
                for sub in name_value.split("\n"):
                    sub_clean = sub.strip().lower()
                    # Strip wildcard prefixes like *.example.com
                    if sub_clean.startswith("*."):
                        sub_clean = sub_clean[2:]
                    if sub_clean.endswith(target) and sub_clean not in discovered:
                        discovered.add(sub_clean)
                        asset = AssetBase(
                            type="subdomain" if sub_clean != target else "domain",
                            value=sub_clean,
                            source="crt.sh (Certificate Transparency)",
                            owner="Unassigned",
                            criticality=4 if any(k in sub_clean for k in ["admin", "api", "auth", "vpn", "stage"]) else 3,
                            tags=["public_facing", "tls_cert"],
                            raw_metadata={"issuer": entry.get("issuer_name"), "logged_at": entry.get("entry_timestamp")}
                        )
                        context.record_asset(asset)
                        results.append(asset)

            context.emit_log("good", f"crt.sh discovered {len(discovered)} unique domain/subdomain assets.")
        except Exception as e:
            context.emit_log("warn", f"crt.sh parsing encountered an error: {e}")

        return results
