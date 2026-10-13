"""
Recon Module: Shared IP & Reverse DNS Hosting Neighbor Inspector
Inspects perimeter IP addresses to uncover:
1. Reverse DNS (PTR) hostname resolution
2. Co-hosted domain neighbors on the same IP infrastructure (Shared Hosting Risk)
3. Infrastructure classification: Dedicated IP vs. Multi-Tenant Shared Host
"""
import socket
import asyncio
from typing import List, Dict, Any, Union
from ..adapter.base import BaseModule, ModuleMeta
from ...schemas.schemas import AssetBase, FindingBase


class ReverseIPReconModule(BaseModule):
    meta = ModuleMeta(
        name="reverse_ip_recon",
        author="Auditor Security Team",
        description="Inspects perimeter IP reverse DNS records and co-hosted domain neighbors",
        category="discovery",
        is_passive=True,
        version="1.0.0"
    )

    async def run(self, target: str, context: Any) -> List[Union[AssetBase, FindingBase]]:
        results: List[Union[AssetBase, FindingBase]] = []
        ip_assets = [
            a for a in getattr(context, "discovered_assets", [])
            if a.type == "ip" and a.value
        ]

        # If no explicit IP asset yet, resolve the apex target IP
        if not ip_assets:
            try:
                loop = asyncio.get_running_loop()
                ip_val = await loop.run_in_executor(None, socket.gethostbyname, target)
                if ip_val:
                    ip_assets = [AssetBase(type="ip", value=ip_val, source="DNS Apex Resolution")]
            except Exception:
                pass

        if not ip_assets:
            return results

        context.emit_log("info", f"Executing Reverse IP and shared hosting inspection for {len(ip_assets)} perimeter IPs...")

        for ip_asset in ip_assets[:10]:
            ip = ip_asset.value.strip()
            # 1. Reverse DNS PTR lookup
            ptr_hostname = None
            try:
                loop = asyncio.get_running_loop()
                ptr_info = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
                if ptr_info and ptr_info[0]:
                    ptr_hostname = ptr_info[0]
            except Exception:
                pass

            # 2. Query free HackerTarget Reverse IP API
            co_hosted_domains = []
            try:
                url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
                resp = await context.http.get(url, ttl_seconds=86400, retries=1)
                if resp and resp.status_code == 200 and "API count exceeded" not in resp.text:
                    lines = [l.strip() for l in resp.text.splitlines() if l.strip() and "." in l]
                    # Filter out error strings
                    co_hosted_domains = [d for d in lines if not d.lower().startswith("no records") and " " not in d]
            except Exception:
                pass

            # 3. Analyze multi-tenancy & tag asset
            is_shared = len(co_hosted_domains) > 1
            ip_tags = ["shared-hosting" if is_shared else "dedicated-ip"]
            if is_shared:
                ip_tags.append("multi-tenant")

            context.emit_log("info", f"IP {ip} PTR: {ptr_hostname or 'None'} | Co-hosted domains: {len(co_hosted_domains)}")

            # Update asset tags and metadata
            for a in getattr(context, "discovered_assets", []):
                if a.type == "ip" and a.value == ip:
                    current_tags = set(a.tags or [])
                    current_tags.update(ip_tags)
                    a.tags = list(current_tags)
                    raw_meta = a.raw_metadata or {}
                    raw_meta["ptr_record"] = ptr_hostname
                    raw_meta["co_hosted_count"] = len(co_hosted_domains)
                    raw_meta["co_hosted_sample"] = co_hosted_domains[:8]
                    a.raw_metadata = raw_meta
                    break

            # 4. If high density co-hosting is detected (> 10 neighbor domains), flag informational finding
            if len(co_hosted_domains) >= 10:
                results.append(FindingBase(
                    title=f"High-Density Multi-Tenant Shared Hosting on {ip}",
                    description=f"Perimeter IP {ip} co-hosts {len(co_hosted_domains)} separate domains ({', '.join(co_hosted_domains[:5])}...). Multi-tenant shared hosting exposes perimeter assets to noisy neighbor attacks, shared IP reputation blacklisting, and cross-tenant resource contention.",
                    severity="Low",
                    cvss_score=3.8,
                    epss_score=0.024,
                    source="Reverse IP Intelligence",
                    confidence="Confirmed",
                    status="Open",
                    evidence={
                        "ip": ip,
                        "ptr": ptr_hostname,
                        "co_hosted_count": len(co_hosted_domains),
                        "sample_neighbors": co_hosted_domains[:10]
                    },
                    remediation_text="Migrate business-critical and customer-facing assets to dedicated IP addresses or isolated Virtual Private Cloud (VPC) ingress.",
                    owasp_category="A05:2021-Security Misconfiguration",
                    iso_control="A.13.1 Network Security",
                    fix_hours_dev=1.0,
                    fix_hours_tester=0.5,
                    estimated_fix_cost=117.5,
                    risk_score=26.0
                ))

        return results
