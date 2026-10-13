"""
Active Recon Module: Subdomain Takeover & Dangling Cloud Prober
Actively queries DNS CNAME records and performs HTTP response verification
against known dangling third-party cloud provider error signatures.
"""
import asyncio
import dns.resolver
from typing import List, Dict, Any, Union, Optional
from ..adapter.base import BaseModule, ModuleMeta
from ..adapter.context import ScanContext
from ...schemas.schemas import AssetBase, FindingBase

TAKEOVER_SIGNATURES = [
    ("github.io", "There isn't a GitHub Pages site here", "GitHub Pages"),
    ("herokuapp.com", "There's nothing here, yet", "Heroku"),
    ("s3.amazonaws.com", "The specified bucket does not exist", "AWS S3"),
    ("myshopify.com", "Sorry, this shop is currently unavailable", "Shopify"),
    ("zendesk.com", "Help Center Closed", "Zendesk"),
    ("unbouncepages.com", "The requested URL was not found on this server", "Unbounce"),
    ("bitbucket.io", "Repository not found", "Bitbucket"),
    ("ghost.io", "The thing you were looking for is no longer here", "Ghost"),
    ("pantheonsite.io", "404 error unknown site", "Pantheon"),
    ("readme.io", "Project doesnt exist", "Readme.io"),
    ("surge.sh", "project not found", "Surge.sh"),
    ("cname.vercel-dns.com", "404: NOT_FOUND", "Vercel"),
    ("azurewebsites.net", "404 Web Site not found", "Azure App Service")
]


class ActiveTakeoverProberModule(BaseModule):
    meta = ModuleMeta(
        name="active_takeover_prober",
        author="Auditor Security Team",
        description="Actively resolves DNS CNAMEs and verifies dangling third-party cloud service pointers across perimeter subdomains.",
        category="active",
        is_passive=False,
        version="1.0.0"
    )

    async def run(self, target: str, context: ScanContext) -> List[Union[AssetBase, FindingBase]]:
        results: List[Union[AssetBase, FindingBase]] = []
        context.emit_log("info", f"Auditing perimeter subdomains for dangling CNAME takeover vulnerabilities on {target}...", 92, "Active Takeover Prober")
        context.log_audit("ACTIVE_TAKEOVER_PROBE", target, "Checking CNAMEs and HTTP response fingerprints")

        subdomain_assets = [
            a.value for a in getattr(context, "discovered_assets", [])
            if a.type == "subdomain" and a.value != target
        ]

        if not subdomain_assets:
            subdomain_assets = [f"www.{target}", f"api.{target}", f"blog.{target}"]

        def _check_cnames_sync():
            cname_map = {}
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.0
            resolver.lifetime = 3.0
            for sub in subdomain_assets[:20]:
                try:
                    answers = resolver.resolve(sub, "CNAME")
                    for a in answers:
                        cname_str = str(a.target).strip().rstrip(".")
                        cname_map[sub] = cname_str
                except Exception:
                    pass
            return cname_map

        cname_map = await asyncio.to_thread(_check_cnames_sync)

        for host, cname_target in cname_map.items():
            for provider_domain, signature, provider_name in TAKEOVER_SIGNATURES:
                if provider_domain in cname_target.lower():
                    try:
                        resp = await context.http.get(f"https://{host}", ttl_seconds=0, retries=1)
                        if not resp:
                            resp = await context.http.get(f"http://{host}", ttl_seconds=0, retries=1)

                        if resp and signature in (resp.text or ""):
                            finding = FindingBase(
                                title=f"Critical Subdomain Takeover Confirmed on {host} ({provider_name})",
                                description=(
                                    f"Subdomain {host} points via CNAME to an unclaimed {provider_name} resource ({cname_target}). "
                                    f"Response matched signature '{signature}'. Threat actors can register the dangling resource "
                                    "to hijack the subdomain, steal session cookies, and stage credible phishing campaigns."
                                ),
                                severity="Critical",
                                cvss_score=8.8,
                                epss_score=0.68,
                                is_kev=True,
                                source="Active Takeover Prober",
                                confidence="Confirmed",
                                status="Open",
                                evidence={"subdomain": host, "cname": cname_target, "signature_matched": signature},
                                remediation_text=f"Remove dangling DNS CNAME record for {host} or re-claim the resource in {provider_name}.",
                                owasp_category="A05:2021-Security Misconfiguration",
                                iso_control="A.13.1 Network Security",
                                fix_hours_dev=1.0,
                                fix_hours_tester=0.5,
                                estimated_fix_cost=117.5,
                                risk_score=92.0
                            )
                            context.record_finding(finding)
                            results.append(finding)
                    except Exception:
                        pass

        context.emit_log("good", f"Subdomain takeover verification completed.")
        return results
