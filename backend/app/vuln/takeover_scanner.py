"""
Subdomain Takeover & Dangling CNAME Pointer Scanner
Inspects discovered perimeter assets for unclaimed third-party pointers:
1. GitHub Pages (There isn't a GitHub Pages site here.)
2. Heroku (No such app / heroku-warning)
3. AWS S3 / CloudFront (The specified bucket does not exist)
4. Shopify, Zendesk, Fastly, Azure Traffic Manager
"""
import dns.resolver
import asyncio
from typing import List, Dict, Any, Optional
from ..schemas.schemas import FindingBase
from ..recon.adapter.context import ScanContext

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


async def scan_subdomain_takeovers(target: str, context: ScanContext) -> List[FindingBase]:
    """
    Checks CNAME targets of all discovered subdomains for dangling takeover vulnerabilities.
    """
    findings: List[FindingBase] = []
    
    subdomain_assets = [
        a.value for a in context.discovered_assets 
        if a.type == "subdomain" and a.value != target
    ]

    if not subdomain_assets:
        return findings

    context.emit_log("info", f"Auditing {len(subdomain_assets)} subdomains for dangling CNAME takeover vulnerabilities...")

    def _check_cnames_sync():
        cname_map = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 3.0
        for sub in subdomain_assets[:25]:
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
                # Query HTTP to verify if it's dangling
                try:
                    resp = await context.http.get(f"https://{host}", ttl_seconds=600, retries=1)
                    if resp and signature in (resp.text or ""):
                        findings.append(FindingBase(
                            title=f"Critical Subdomain Takeover on {host} ({provider_name})",
                            description=f"Subdomain {host} points via CNAME to unclaimed {provider_name} resource ({cname_target}). Threat actors can register the dangling resource to hijack the entire subdomain and its cookies.",
                            severity="Critical",
                            cvss_score=8.6,
                            epss_score=0.62,
                            is_kev=False,
                            source="Subdomain Takeover Audit",
                            confidence="Confirmed",
                            status="Open",
                            evidence={"subdomain": host, "cname": cname_target, "signature_matched": signature},
                            remediation_text=f"Remove dangling DNS CNAME record for {host} or claim the corresponding resource in {provider_name}.",
                            owasp_category="A05:2021-Security Misconfiguration",
                            iso_control="A.13.1 Network Security",
                            fix_hours_dev=1.0,
                            fix_hours_tester=0.5,
                            estimated_fix_cost=117.5,
                            risk_score=88.0
                        ))
                except Exception:
                    pass

    return findings
