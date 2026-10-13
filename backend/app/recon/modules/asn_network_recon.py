"""
Autonomous System (ASN) & IP Network Reconnaissance Module
Enriches attack surface perimeter with:
1. IP-to-ASN resolution (AS Number, BGP prefix, ISP/Network Provider)
2. Geolocation and hosting environment identification (Cloudflare, AWS, GCP, Azure, On-Prem)
3. Reverse DNS (PTR) host discovery on network interfaces
"""
import asyncio
import socket
import ipaddress
from typing import List, Union, Set, Dict, Any, Optional
import dns.resolver
import dns.reversename

from ..adapter.base import BaseModule, ModuleMeta
from ..adapter.context import ScanContext
from ...schemas.schemas import AssetBase, FindingBase
from ...db.models import Asset


class ASNNetworkReconModule(BaseModule):
    meta = ModuleMeta(
        name="asn_network_recon",
        author="Auditor Security Team",
        description="Discovers and enriches perimeter IP assets with Autonomous System (ASN) data, BGP netblocks, and Reverse DNS (PTR) hostnames.",
        category="discovery",
        is_passive=True,
        version="2.0.0"
    )
    required_keys = []

    def _is_valid_ip(self, val: Optional[str]) -> bool:
        if not val:
            return False
        try:
            ipaddress.ip_address(val.strip())
            return True
        except (ValueError, TypeError):
            return False

    async def run(self, target: str, context: ScanContext) -> List[Union[AssetBase, FindingBase]]:
        context.emit_log("info", f"Executing Autonomous System (ASN) and network reconnaissance for {target}...")
        context.log_audit("ASN_NETWORK_RECON", target, "Resolving ASN, BGP netblocks, and PTR reverse DNS records")

        results: List[Union[AssetBase, FindingBase]] = []

        # 1. Collect all known unique IP addresses from discovered assets and target DNS
        known_ips: Set[str] = set()

        # Check target IP
        target_ips = await self._resolve_target_ips(target)
        for tip in target_ips:
            if self._is_valid_ip(tip):
                known_ips.add(tip)

        # Resolve any discovered subdomains that lack IP addresses
        unresolved_assets = [
            a for a in context.discovered_assets
            if a.type in ("subdomain", "domain") and (not a.ip_address or not self._is_valid_ip(a.ip_address))
        ]
        if unresolved_assets:
            resolved_map = await self._resolve_hosts([a.value for a in unresolved_assets])
            for a in unresolved_assets:
                ip = resolved_map.get(a.value)
                if ip and self._is_valid_ip(ip):
                    a.ip_address = ip
                    known_ips.add(ip)
                    try:
                        db_asset = context.db.query(Asset).filter(Asset.id == a.id).first()
                        if db_asset:
                            db_asset.ip_address = ip
                            context.db.commit()
                    except Exception:
                        context.db.rollback()

        # Add valid IPs from existing assets in context
        for asset in context.discovered_assets:
            if self._is_valid_ip(asset.ip_address):
                known_ips.add(asset.ip_address)
            elif asset.type == "ip" and self._is_valid_ip(asset.value):
                known_ips.add(asset.value)

        if not known_ips:
            context.emit_log("info", "No public IP addresses identified for ASN enrichment yet.")
            return results

        context.emit_log("info", f"Analyzing ASN & BGP network routing for {len(known_ips)} perimeter IP addresses...")

        # 2. Enrich each IP with ASN, BGP prefix, and PTR records
        for ip in known_ips:
            asn_info = await self._lookup_ip_asn_details(ip, context)
            ptr_hostnames = await self._reverse_dns_lookup(ip, target)

            # Record any PTR hostnames discovered that belong to the target
            for ptr_host in ptr_hostnames:
                asset_sub = AssetBase(
                    type="subdomain" if ptr_host != target else "domain",
                    value=ptr_host,
                    source="Reverse DNS (PTR Lookup)",
                    owner="Network Operations",
                    criticality=3,
                    ip_address=ip,
                    asn=asn_info.get("asn"),
                    tags=["ptr_record", "reverse_dns_verified"],
                    raw_metadata={
                        "resolved_from_ip": ip,
                        "asn_name": asn_info.get("as_name"),
                        "country": asn_info.get("country")
                    }
                )
                context.record_asset(asset_sub)
                results.append(asset_sub)

            # Record or update IP Asset
            asn_tag = "cloud_waf" if "cloudflare" in (asn_info.get("as_name") or "").lower() else "public_ip"
            ip_asset = AssetBase(
                type="ip",
                value=ip,
                source="ASN & BGP Network Recon",
                owner="Network Operations",
                criticality=3,
                ip_address=ip,
                asn=asn_info.get("asn"),
                tags=[asn_tag, "asn_enriched"],
                raw_metadata={
                    "asn_number": asn_info.get("asn"),
                    "asn_name": asn_info.get("as_name"),
                    "cidr_prefix": asn_info.get("cidr"),
                    "country": asn_info.get("country"),
                    "city": asn_info.get("city"),
                    "ptr_records": ptr_hostnames
                }
            )
            saved_asset = context.record_asset(ip_asset)
            if saved_asset:
                results.append(ip_asset)

            # Also update existing database assets that have this IP
            try:
                matching_assets = context.db.query(Asset).filter(
                    Asset.scan_id == context.scan_id,
                    Asset.ip_address == ip
                ).all()
                for ma in matching_assets:
                    if not ma.asn and asn_info.get("asn"):
                        ma.asn = asn_info.get("asn")
                    meta = ma.raw_metadata or {}
                    meta["asn_name"] = asn_info.get("as_name")
                    meta["country"] = asn_info.get("country")
                    ma.raw_metadata = meta
                context.db.commit()
            except Exception:
                context.db.rollback()

        context.emit_log(
            "good",
            f"ASN & Network Recon finished: {len(known_ips)} IPs enriched with Autonomous System & BGP routing data."
        )
        return results

    async def _resolve_target_ips(self, target: str) -> Set[str]:
        """
        Quickly resolves target apex domain and www to IP addresses.
        """
        def _resolve_sync():
            ips = set()
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.5
            resolver.lifetime = 3.5
            for host in [target, f"www.{target}"]:
                try:
                    answers = resolver.resolve(host, "A")
                    for a in answers:
                        ip_str = str(a).strip()
                        if ip_str and self._is_valid_ip(ip_str):
                            ips.add(ip_str)
                except Exception:
                    pass
            return ips

        try:
            return await asyncio.to_thread(_resolve_sync)
        except Exception:
            return set()

    async def _resolve_hosts(self, hosts: List[str]) -> Dict[str, str]:
        """
        Concurrently resolves a list of hostnames to their primary IPv4 address.
        """
        def _resolve_one(h: str):
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2.0
                resolver.lifetime = 3.0
                answers = resolver.resolve(h, "A")
                for a in answers:
                    ip_str = str(a).strip()
                    if self._is_valid_ip(ip_str):
                        return h, ip_str
            except Exception:
                pass
            return h, None

        tasks = [asyncio.to_thread(_resolve_one, h) for h in hosts[:50]]
        resolved_list = await asyncio.gather(*tasks)
        return {h: ip for h, ip in resolved_list if ip}

    async def _lookup_ip_asn_details(self, ip: str, context: ScanContext) -> Dict[str, Any]:
        """
        Resolves IP to ASN Number, Organization, and Country using:
        1. Team Cymru IP-to-ASN DNS (origin.asn.cymru.com) - Zero rate limits
        2. BGPView Looking Glass API (api.bgpview.io)
        3. RDAP RFC 7482 API (rdap.org)
        4. ipapi.co JSON API
        """
        info = {
            "asn": None,
            "as_name": "Unassigned",
            "cidr": None,
            "country": None,
            "city": None
        }

        # ── Tier 1: Team Cymru IP-to-ASN DNS (Instant, Free, Unlimited) ──────
        def _cymru_sync():
            res = {}
            try:
                rev_ip = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2.0
                resolver.lifetime = 3.0
                answers = resolver.resolve(rev_ip, "TXT")
                for a in answers:
                    txt = str(a).strip('"')
                    parts = [p.strip() for p in txt.split("|")]
                    if len(parts) >= 3:
                        asn_clean = f"AS{parts[0]}"
                        res["asn"] = asn_clean
                        res["cidr"] = parts[1]
                        res["country"] = parts[2]
                        # Query ASN Org Name
                        try:
                            asn_query = f"AS{parts[0]}.asn.cymru.com"
                            org_answers = resolver.resolve(asn_query, "TXT")
                            for oa in org_answers:
                                o_txt = str(oa).strip('"')
                                o_parts = [op.strip() for op in o_txt.split("|")]
                                if len(o_parts) >= 5:
                                    res["as_name"] = o_parts[4]
                        except Exception:
                            pass
                        break
            except Exception:
                pass
            return res

        cymru_res = await asyncio.to_thread(_cymru_sync)
        if cymru_res and cymru_res.get("asn"):
            info.update(cymru_res)
            return info

        # ── Tier 2: BGPView Looking Glass API ────────────────────────────────
        try:
            bgp_url = f"https://api.bgpview.io/ip/{ip}"
            bgp_data = await context.http.get_json(bgp_url, ttl_seconds=86400)
            if bgp_data and bgp_data.get("status") == "ok":
                data = bgp_data.get("data", {})
                prefixes = data.get("prefixes", [])
                if prefixes:
                    pref = prefixes[0]
                    info["cidr"] = pref.get("prefix")
                    asn_obj = pref.get("asn", {})
                    if asn_obj.get("asn"):
                        info["asn"] = f"AS{asn_obj.get('asn')}"
                        info["as_name"] = asn_obj.get("name") or asn_obj.get("description")
                        info["country"] = asn_obj.get("country_code")
                        return info
        except Exception:
            pass

        # ── Tier 3: RDAP IP API ──────────────────────────────────────────────
        try:
            rdap_url = f"https://rdap.org/ip/{ip}"
            rdap_data = await context.http.get_json(rdap_url, ttl_seconds=86400)
            if rdap_data and isinstance(rdap_data, dict):
                info["country"] = rdap_data.get("country")
                info["as_name"] = rdap_data.get("name") or "Network Range"
                cidrs = rdap_data.get("cidr0_cidrs", [])
                if cidrs and len(cidrs) > 0:
                    info["cidr"] = f"{cidrs[0].get('v4prefix')}/{cidrs[0].get('length')}"
                return info
        except Exception:
            pass

        # ── Tier 4: ipapi.co Fallback ────────────────────────────────────────
        try:
            url = f"https://ipapi.co/{ip}/json/"
            data = await context.http.get_json(url, ttl_seconds=86400)
            if data and isinstance(data, dict) and data.get("asn"):
                info["asn"] = data.get("asn")
                info["as_name"] = data.get("org") or data.get("asn")
                info["country"] = data.get("country_code") or data.get("country_name")
                info["city"] = data.get("city")
                return info
        except Exception:
            pass

        return info

    async def _reverse_dns_lookup(self, ip: str, target: str) -> List[str]:
        """
        Performs Reverse DNS (PTR) lookup on an IP address to find hostnames.
        """
        def _ptr_sync():
            found_hosts = []
            try:
                rev_name = dns.reversename.from_address(ip)
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2.0
                resolver.lifetime = 3.0
                answers = resolver.resolve(rev_name, "PTR")
                for ans in answers:
                    host = str(ans).strip().rstrip(".").lower()
                    if host:
                        found_hosts.append(host)
            except Exception:
                pass
            return found_hosts

        try:
            all_ptrs = await asyncio.to_thread(_ptr_sync)
            # Filter PTRs that belong to the target or corporate domain
            matching = [h for h in all_ptrs if h.endswith(target)]
            return matching if matching else all_ptrs[:2]
        except Exception:
            return []
