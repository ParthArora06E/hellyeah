"""
Active Recon Module: DNS Zone Transfer (AXFR) & Open Resolver Auditor
Actively tests authoritative nameservers for:
1. Full DNS Zone Transfer (AXFR) misconfiguration (catastrophic perimeter data leak)
2. Discovered internal subdomains from transferred zone
3. Open DNS Recursive Resolver posture (DDoS amplification risk)
"""
import dns.resolver
import dns.query
import dns.zone
import dns.message
import asyncio
from typing import List, Dict, Any, Union, Optional
from ..adapter.base import BaseModule, ModuleMeta
from ..adapter.context import ScanContext
from ...schemas.schemas import AssetBase, FindingBase


class DNSAXFRModule(BaseModule):
    meta = ModuleMeta(
        name="dns_axfr_prober",
        author="Auditor Security Team",
        description="Actively queries authoritative nameservers for unauthorized DNS Zone Transfers (AXFR) and open recursive resolvers.",
        category="active",
        is_passive=False,
        version="1.0.0"
    )

    async def run(self, target: str, context: ScanContext) -> List[Union[AssetBase, FindingBase]]:
        results: List[Union[AssetBase, FindingBase]] = []
        context.emit_log("info", f"Auditing authoritative DNS nameservers for AXFR zone transfer posture on {target}...", 86, "DNS AXFR Prober")
        context.log_audit("ACTIVE_DNS_AXFR", target, "Attempting AXFR zone transfer on authoritative nameservers")

        def _sync_axfr_audit():
            discovered_assets = []
            findings = []
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.5
            resolver.lifetime = 4.0

            # 1. Resolve NS records
            ns_servers = []
            try:
                ns_answers = resolver.resolve(target, "NS")
                for ns in ns_answers:
                    ns_host = str(ns.target).rstrip(".")
                    try:
                        ip_ans = resolver.resolve(ns_host, "A")
                        for ip in ip_ans:
                            ns_servers.append((ns_host, str(ip)))
                    except Exception:
                        pass
            except Exception:
                return discovered_assets, findings

            for ns_host, ns_ip in ns_servers[:4]:
                # 2. Attempt AXFR
                zone_transferred = False
                transferred_records = []
                try:
                    xfr_query = dns.query.xfr(ns_ip, target, timeout=3.0, lifetime=4.0)
                    zone = dns.zone.from_xfr(xfr_query)
                    zone_transferred = True
                    for name, node in zone.nodes.items():
                        node_str = str(name).strip()
                        if node_str and node_str != "@":
                            full_subdomain = f"{node_str}.{target}"
                        else:
                            full_subdomain = target
                        transferred_records.append(full_subdomain)
                except Exception:
                    zone_transferred = False

                if zone_transferred and transferred_records:
                    # Huge discovery: Full Zone Transfer!
                    finding = FindingBase(
                        title=f"Critical DNS Zone Transfer (AXFR) Permitted on {ns_host}",
                        description=(
                            f"Authoritative nameserver {ns_host} ({ns_ip}) allows unrestricted DNS zone transfers (AXFR) for domain {target}. "
                            f"Threat actors can download the entire DNS zone file, revealing all internal subdomains, network architecture, and confidential hosts."
                        ),
                        severity="Critical",
                        cvss_score=9.3,
                        epss_score=0.72,
                        source="Active DNS AXFR Prober",
                        confidence="Confirmed",
                        status="Open",
                        evidence={
                            "nameserver": ns_host,
                            "nameserver_ip": ns_ip,
                            "records_leaked_count": len(transferred_records),
                            "sample_records": transferred_records[:15]
                        },
                        remediation_text="Restrict AXFR zone transfers to authorized secondary nameservers only via 'allow-transfer { authorized_ips; };' in BIND/named or equivalent DNS configuration.",
                        owasp_category="A05:2021-Security Misconfiguration",
                        iso_control="A.13.1 Network Security",
                        fix_hours_dev=1.0,
                        fix_hours_tester=0.5,
                        estimated_fix_cost=117.5,
                        risk_score=95.0
                    )
                    findings.append(finding)

                    # Register all discovered subdomains from AXFR as assets!
                    for sub in set(transferred_records):
                        asset = AssetBase(
                            type="subdomain",
                            value=sub,
                            source="DNS AXFR Zone Transfer",
                            owner="Network Operations",
                            criticality=3,
                            tags=["active_recon", "axfr_discovery"],
                            raw_metadata={"discovered_from_ns": ns_host}
                        )
                        discovered_assets.append(asset)

                # 3. Check for Open DNS Recursion
                try:
                    q = dns.message.make_query("example.com", dns.rdatatype.A)
                    resp = dns.query.udp(q, ns_ip, timeout=2.0)
                    # If RA (Recursion Available) bit is set and answers returned
                    if resp and (resp.flags & dns.flags.RA) and resp.answer:
                        findings.append(FindingBase(
                            title=f"Open DNS Recursive Resolver Exposed on {ns_host} ({ns_ip})",
                            description=(
                                f"Authoritative nameserver {ns_host} ({ns_ip}) is configured as an open recursive DNS resolver for external clients. "
                                "Open recursive resolvers are weaponized in DNS amplification Distributed Denial-of-Service (DDoS) reflection attacks."
                            ),
                            severity="Medium",
                            cvss_score=5.8,
                            epss_score=0.12,
                            source="Active DNS Resolver Prober",
                            confidence="Confirmed",
                            status="Open",
                            evidence={"nameserver": ns_host, "nameserver_ip": ns_ip, "recursion_available": True},
                            remediation_text="Disable recursive querying for external clients ('recursion no;' or 'allow-recursion { trusted_nets; };').",
                            owasp_category="A05:2021-Security Misconfiguration",
                            iso_control="A.13.1 Network Security",
                            fix_hours_dev=1.0,
                            fix_hours_tester=0.5,
                            estimated_fix_cost=117.5,
                            risk_score=50.0
                        ))
                except Exception:
                    pass

            return discovered_assets, findings

        try:
            discovered_assets, findings = await asyncio.to_thread(_sync_axfr_audit)
            for a in discovered_assets:
                context.record_asset(a)
                results.append(a)
            for f in findings:
                context.record_finding(f)
                results.append(f)
        except Exception as e:
            context.emit_log("warn", f"DNS AXFR prober notice: {e}")

        context.emit_log("good", f"DNS AXFR and recursive nameserver audit completed.")
        return results
