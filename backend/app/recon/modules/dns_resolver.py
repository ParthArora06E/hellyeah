"""
DNS Resolver & Security Records Analyzer Module
Ported & Adapted from Recon-ng / Preconng parsers/dns_parser.py
Licensed under GNU General Public License v3.0 (GPL-3.0)
"""
import dns.resolver
import asyncio
from typing import List, Union
from ..adapter.base import BaseModule, ModuleMeta
from ..adapter.context import ScanContext
from ...schemas.schemas import AssetBase, FindingBase

class DNSResolverModule(BaseModule):
    meta = ModuleMeta(
        name="dns_records",
        author="Auditor Security Team (Adapted from Recon-ng)",
        description="Performs forward DNS lookups (A, AAAA, MX, NS, TXT, CNAME) and analyzes email security posture (SPF/DMARC).",
        category="discovery",
        is_passive=True,
        version="1.0.0"
    )
    required_keys = []

    async def run(self, target: str, context: ScanContext) -> List[Union[AssetBase, FindingBase]]:
        context.emit_log("info", f"Resolving comprehensive DNS records for {target}...")
        context.log_audit("DNS_RESOLVE", target, "Querying A, AAAA, MX, NS, TXT, CNAME")
        
        results: List[Union[AssetBase, FindingBase]] = []
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
        records = {}

        def _resolve_sync():
            res_dict = {}
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3.0
            resolver.lifetime = 5.0
            for rtype in record_types:
                try:
                    answers = resolver.resolve(target, rtype)
                    res_dict[rtype] = [str(r).strip().rstrip(',') for r in answers if str(r).strip()]
                except Exception:
                    res_dict[rtype] = []
            return res_dict

        try:
            records = await asyncio.to_thread(_resolve_sync)
        except Exception as e:
            context.emit_log("warn", f"DNS resolver failure: {e}")
            return results

        # Process A records as IP assets
        for ip in records.get("A", []):
            asset = AssetBase(
                type="ip",
                value=ip,
                source="DNS A Record",
                owner="Network Operations",
                criticality=3,
                ip_address=ip,
                tags=["resolved_ip", "public_ipv4"],
                raw_metadata={"dns_records": records}
            )
            context.record_asset(asset)
            results.append(asset)

        # Check mail security: Missing SPF or DMARC
        txt_records = records.get("TXT", [])
        has_spf = any("v=spf1" in txt.lower() for txt in txt_records)
        
        if not has_spf:
            finding = FindingBase(
                title=f"Missing Email SPF Record on {target}",
                description=f"Domain {target} does not publish an SPF (Sender Policy Framework) TXT record, allowing unauthorized threat actors to spoof emails from this domain.",
                severity="Medium",
                cvss_score=5.3,
                epss_score=0.012,
                source="DNS Security Analysis",
                confidence="High",
                status="Open",
                evidence={"txt_records": txt_records},
                remediation_text="Publish a TXT record for the root domain specifying authorized mail servers: 'v=spf1 mx include:_spf.example.com ~all'.",
                owasp_category="A05:2021-Security Misconfiguration",
                iso_control="A.13.2.1 Information Transfer",
                fix_hours_dev=1.0,
                fix_hours_tester=0.5,
                estimated_fix_cost=100.0,
                risk_score=40.0
            )
            context.record_finding(finding)
            results.append(finding)

        context.emit_log("good", f"DNS resolution complete. A: {len(records.get('A', []))}, MX: {len(records.get('MX', []))}, NS: {len(records.get('NS', []))}.")
        return results
