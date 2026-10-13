"""
Advanced Domain & Subdomain Enumeration Module
Discovers perimeter assets using:
1. High-speed concurrent DNS resolution against high-value enterprise prefix wordlists
2. DNS Service Record (SRV) service discovery (SIP, Autodiscover, CalDAV, XMPP)
3. DNS Name Server (NS) Zone Transfer (AXFR) auditing
"""
import asyncio
from typing import List, Union, Set, Dict, Any
import dns.resolver
import dns.query
import dns.zone

from ..adapter.base import BaseModule, ModuleMeta
from ..adapter.context import ScanContext
from ...schemas.schemas import AssetBase, FindingBase


ENTERPRISE_SUBDOMAIN_PREFIXES = [
    "www", "mail", "api", "admin", "portal", "app", "dev", "stage", "staging",
    "vpn", "auth", "login", "secure", "remote", "gateway", "cpanel", "webmail",
    "autodiscover", "sip", "ftp", "corp", "cdn", "dashboard", "status", "monitor",
    "test", "beta", "sso", "docs", "git", "internal", "mx", "ns1", "ns2",
    "shop", "store", "blog", "support", "help", "billing", "cloud", "connect",
    "server", "db", "backend", "ws", "m", "mobile", "static", "assets", "email"
]

SRV_SERVICE_PREFIXES = [
    "_sip._tcp",
    "_sips._tcp",
    "_autodiscover._tcp",
    "_caldav._tcp",
    "_carddav._tcp",
    "_xmpp-server._tcp"
]


class DomainNameReconModule(BaseModule):
    meta = ModuleMeta(
        name="domain_name_recon",
        author="Auditor Security Team",
        description="High-speed concurrent DNS enumeration of enterprise subdomains, SRV service discovery, and AXFR zone audit.",
        category="discovery",
        is_passive=True,
        version="2.0.0"
    )
    required_keys = []

    async def run(self, target: str, context: ScanContext) -> List[Union[AssetBase, FindingBase]]:
        context.emit_log("info", f"Executing enterprise domain & DNS enumeration for {target}...")
        context.log_audit("DOMAIN_NAME_RECON", target, "Probing enterprise subdomains, SRV services, and NS posture")

        results: List[Union[AssetBase, FindingBase]] = []
        discovered_subs: Set[str] = set()

        # ─────────────────────────────────────────────────────────────────────
        # 1. High-Speed Concurrent DNS Subdomain Probing
        # ─────────────────────────────────────────────────────────────────────
        context.emit_log("info", f"Probing top {len(ENTERPRISE_SUBDOMAIN_PREFIXES)} enterprise service subdomains for {target}...")
        resolved_map = await self._probe_subdomain_wordlist(target)

        for sub, ip_list in resolved_map.items():
            discovered_subs.add(sub)
            primary_ip = ip_list[0] if ip_list else None
            asset = AssetBase(
                type="subdomain" if sub != target else "domain",
                value=sub,
                source="Enterprise DNS Enumeration",
                owner="Corporate Infrastructure",
                criticality=4 if any(k in sub for k in ["admin", "api", "auth", "vpn", "cpanel", "corp"]) else 3,
                ip_address=primary_ip,
                tags=["dns_resolved", "active_host"],
                raw_metadata={"resolved_ips": ip_list}
            )
            context.record_asset(asset)
            results.append(asset)

        if resolved_map:
            context.emit_log("good", f"Enterprise DNS probing uncovered {len(resolved_map)} active subdomains for {target}.")

        # ─────────────────────────────────────────────────────────────────────
        # 2. DNS Service Record (SRV) Discovery
        # ─────────────────────────────────────────────────────────────────────
        srv_hosts = await self._probe_srv_records(target)
        for srv_host in srv_hosts:
            if srv_host.endswith(target) and srv_host not in discovered_subs:
                discovered_subs.add(srv_host)
                asset = AssetBase(
                    type="subdomain",
                    value=srv_host,
                    source="DNS SRV Service Record",
                    owner="Voice / Communications Team",
                    criticality=4,
                    tags=["srv_service", "voip_or_directory"],
                    raw_metadata={"discovered_via": "dns_srv_lookup"}
                )
                context.record_asset(asset)
                results.append(asset)

        if srv_hosts:
            context.emit_log("good", f"DNS SRV inspection revealed {len(srv_hosts)} service endpoints.")

        # ─────────────────────────────────────────────────────────────────────
        # 3. Authoritative Name Server AXFR Zone Transfer Check
        # ─────────────────────────────────────────────────────────────────────
        axfr_findings = await self._test_zone_transfer(target, context)
        results.extend(axfr_findings)

        context.emit_log("good", f"Domain name reconnaissance completed: {len(discovered_subs)} unique subdomains validated.")
        return results

    async def _probe_subdomain_wordlist(self, target: str) -> Dict[str, List[str]]:
        """
        Concurrently tests common enterprise subdomains via DNS resolver.
        """
        def _resolve_candidate(candidate: str):
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 1.5
                resolver.lifetime = 2.0
                answers = resolver.resolve(candidate, "A")
                ips = [str(r).strip() for r in answers if str(r).strip()]
                return candidate, ips
            except Exception:
                return candidate, []

        candidates = [f"{prefix}.{target}" for prefix in ENTERPRISE_SUBDOMAIN_PREFIXES]
        tasks = [asyncio.to_thread(_resolve_candidate, c) for c in candidates]
        resolved_results = await asyncio.gather(*tasks)

        valid_map = {}
        for cand, ips in resolved_results:
            if ips:
                valid_map[cand] = ips
        return valid_map

    async def _probe_srv_records(self, target: str) -> Set[str]:
        """
        Queries common enterprise SRV records for hidden communication endpoints.
        """
        def _resolve_srv_sync():
            found = set()
            resolver = dns.resolver.Resolver()
            resolver.timeout = 1.5
            resolver.lifetime = 2.0
            for prefix in SRV_SERVICE_PREFIXES:
                query_name = f"{prefix}.{target}"
                try:
                    answers = resolver.resolve(query_name, "SRV")
                    for a in answers:
                        target_host = str(a.target).strip().rstrip(".").lower()
                        if target_host:
                            found.add(target_host)
                except Exception:
                    pass
            return found

        try:
            return await asyncio.to_thread(_resolve_srv_sync)
        except Exception:
            return set()

    async def _test_zone_transfer(self, target: str, context: ScanContext) -> List[FindingBase]:
        """
        Tests whether authoritative Name Servers permit unauthenticated DNS Zone Transfers (AXFR).
        """
        def _axfr_sync():
            findings = []
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2.0
                resolver.lifetime = 3.0
                ns_answers = resolver.resolve(target, "NS")
                ns_servers = [str(ns).strip().rstrip(".") for ns in ns_answers]

                for ns_host in ns_servers[:2]:
                    try:
                        # Attempt AXFR query
                        ns_ips = [str(a) for a in resolver.resolve(ns_host, "A")]
                        for ns_ip in ns_ips:
                            try:
                                z = dns.zone.from_xfr(dns.query.xfr(ns_ip, target, timeout=2.0))
                                if z and len(z.nodes) > 1:
                                    findings.append(FindingBase(
                                        title=f"Critical DNS Zone Transfer (AXFR) Allowed on {ns_host}",
                                        description=f"Authoritative Name Server {ns_host} ({ns_ip}) allows unrestricted zone transfer for {target}, exposing internal DNS topology.",
                                        severity="Critical",
                                        cvss_score=9.1,
                                        epss_score=0.85,
                                        is_kev=False,
                                        source="DNS Zone Audit",
                                        confidence="Confirmed",
                                        status="Open",
                                        evidence={"nameserver": ns_host, "ip": ns_ip, "records_count": len(z.nodes)},
                                        remediation_text="Restrict zone transfers on authoritative BIND/DNS servers to authorized secondary nameserver IPs only ('allow-transfer { none; };').",
                                        owasp_category="A05:2021-Security Misconfiguration",
                                        iso_control="A.13.1 Network Security",
                                        fix_hours_dev=1.0,
                                        fix_hours_tester=0.5,
                                        estimated_fix_cost=117.5,
                                        risk_score=90.0
                                    ))
                                    break
                            except Exception:
                                pass
                    except Exception:
                        pass
            except Exception:
                pass
            return findings

        try:
            return await asyncio.to_thread(_axfr_sync)
        except Exception:
            return []
