"""
Master Scan Pipeline Orchestrator
Coordinates target validation, discovery, CPE mapping, CVE correlation, active checks,
risk scoring, and financial cost modeling. Emits real-time SSE progress events.
"""
import asyncio
from datetime import datetime, timezone
from typing import Callable, Optional, Dict, Any
from sqlalchemy.orm import Session

from ..core.config import settings
from ..core.scope import check_scan_permission
from ..db.models import Scan, Asset, Finding
from ..schemas.schemas import AssetBase, FindingBase
from ..recon.adapter.context import ScanContext
from ..recon.adapter.plugin_loader import execute_all_plugins
from ..recon.modules.crtsh import CrtshModule
from ..recon.modules.alienvault_otx import AlienVaultOTXModule
from ..recon.modules.securitytrails import SecurityTrailsModule
from ..recon.modules.dns_resolver import DNSResolverModule
from ..recon.modules.whois_lookup import WhoisModule
from ..recon.modules.shodan_host import ShodanHostModule
from ..recon.modules.urlscan_lookup import URLScanModule
from ..recon.modules.wayback_archive import WaybackModule
from ..recon.modules.ssl_cert_recon import SSLCertReconModule
from ..recon.modules.asn_network_recon import ASNNetworkReconModule
from ..recon.modules.domain_name_recon import DomainNameReconModule
from ..recon.modules.cms_detector import CMSDetectorModule
from ..recon.modules.reverse_ip_recon import ReverseIPReconModule
from ..recon.modules.virustotal import VirusTotalModule
from ..recon.modules import (
    ActivePortScannerModule,
    HTTPMethodProberModule,
    DNSAXFRModule,
    WAFDetectorModule,
    CORSActiveProberModule,
    WebMetadataCrawlerModule,
    VirtualHostProberModule,
    ActiveTLSProberModule,
    ActiveTakeoverProberModule,
)
from ..vuln.cpe_mapper import detect_software_and_version
from ..vuln.cve_engine import lookup_cves_for_software
from ..vuln.custom_rules_engine import execute_custom_rules
from ..vuln.active_probes import probe_security_headers, probe_exposed_files, probe_tls_certificate
from ..vuln.web_security_scanner import scan_web_security_posture
from ..vuln.ssl_security_scanner import scan_ssl_security_posture
from ..vuln.dns_security_scanner import scan_dns_security_posture
from ..vuln.sensitive_endpoint_scanner import scan_sensitive_endpoints
from ..vuln.cloud_storage_scanner import scan_cloud_storage_buckets
from ..vuln.takeover_scanner import scan_subdomain_takeovers
from ..analytics.risk_scorer import score_and_rank_findings
from ..analytics.cost_analyzer import calculate_costs

# Global in-memory broadcast queues for SSE clients: {scan_id: [asyncio.Queue, ...]}
SCAN_EVENT_STREAMS: Dict[str, list] = {}
# Global in-memory log history per scan for reconnecting clients: {scan_id: [event_payload, ...]}
SCAN_EVENT_HISTORY: Dict[str, list] = {}

def broadcast_event(scan_id: str, level: str, message: str, progress: Optional[int] = None, step: Optional[str] = None):
    event_payload = {
        "scan_id": scan_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "message": message,
        "progress": progress,
        "step": step
    }
    # Buffer event in scan history
    if scan_id not in SCAN_EVENT_HISTORY:
        SCAN_EVENT_HISTORY[scan_id] = []
    SCAN_EVENT_HISTORY[scan_id].append(event_payload)
    if len(SCAN_EVENT_HISTORY[scan_id]) > 500:
        SCAN_EVENT_HISTORY[scan_id].pop(0)

    queues = SCAN_EVENT_STREAMS.get(scan_id, [])
    for q in queues:
        try:
            q.put_nowait(event_payload)
        except Exception:
            pass

async def run_scan_pipeline(
    scan_id: str,
    db_factory: Callable[[], Session],
    manual_assets: Optional[list] = None,
    run_plugins: bool = True
):
    """
    Executes the full end-to-end vulnerability and attack-surface audit.
    """
    with db_factory() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        target = scan.target_domain
        mode = scan.mode
        company = scan.company_name or target

        # Initialize event callback
        def event_cb(level: str, msg: str, prog: Optional[int] = None, st: Optional[str] = None):
            broadcast_event(scan_id, level, msg, prog, st)
            if prog is not None:
                scan.progress = prog
            if st is not None:
                scan.current_step = st
            db.commit()

        context = ScanContext(scan_id, target, mode, db, event_cb)

        # ─────────────────────────────────────────────────────────────
        # Step 1: Scope & Permission Gatekeeper Check
        # ─────────────────────────────────────────────────────────────
        event_cb("info", f"Auditor scanner initialized for target: {target} (mode: {mode})", 5, "Target & Policy Validation")
        allowed, reason = check_scan_permission(target, mode, db)
        
        if not allowed:
            event_cb("error", reason, 100, "Scope Refusal")
            scan.status = "failed"
            scan.summary_notes = reason
            db.commit()
            return

        event_cb("good", f"Scope verified: {reason}", 10, "Target Verified")
        scan.status = "running"
        db.commit()

        # ─────────────────────────────────────────────────────────────
        # LIVE AUDIT PIPELINE
        # ─────────────────────────────────────────────────────────────
        # 1. Add manual assets if supplied
        if manual_assets:
            for ma in manual_assets:
                context.record_asset(AssetBase(
                    type="subdomain" if "." in ma else "ip",
                    value=ma,
                    source="Manual Entry",
                    owner="Security Team",
                    criticality=3,
                    tags=["manual_asset"]
                ))

        # 2. Passive Discovery Modules
        event_cb("info", f"Executing passive OSINT asset discovery for {target}...", 15, "Passive Discovery")
        passive_modules = [
            SSLCertReconModule(),
            CrtshModule(),
            DomainNameReconModule(),
            DNSResolverModule(),
            WhoisModule(),
            ASNNetworkReconModule(),
            ReverseIPReconModule(),
            AlienVaultOTXModule(),
            SecurityTrailsModule(),
            VirusTotalModule(),
            ShodanHostModule(),
            WaybackModule(),
            URLScanModule()
        ]

        for mod in passive_modules:
            try:
                await mod.run(target, context)
            except Exception as e:
                event_cb("warn", f"Module {mod.meta.name} warning: {e}")

        event_cb("good", f"Passive discovery finished. Discovered {len(context.discovered_assets)} assets.", 45, "Asset Fingerprinting")

        # 3. Deep CMS, Framework & Technology Fingerprinting & CPE Synthesis
        event_cb("info", "Executing deep CMS and framework stack detection...", 48, "CMS & Framework Analysis")
        try:
            await CMSDetectorModule().run(target, context)
        except Exception as e:
            event_cb("warn", f"CMS detector warning: {e}")

        event_cb("info", "Synthesizing software banners and frameworks for CPE 2.3 identification...", 52, "CPE Synthesis")
        discovered_cpes = []
        for asset in context.discovered_assets:
            for tech in (asset.technologies or []):
                cpe_info = detect_software_and_version(tech)
                if cpe_info:
                    discovered_cpes.append((asset.id, cpe_info))

        # 4. Vulnerability Lookup (NVD, OSV, EPSS, CISA KEV)
        event_cb("info", f"Querying NVD, OSV.dev, EPSS, and CISA KEV for {len(discovered_cpes)} identified software stacks...", 60, "CVE Correlation")
        for asset_id, cpe_info in discovered_cpes:
            try:
                vulns = await lookup_cves_for_software(
                    cpe_info["vendor"],
                    cpe_info["product"],
                    cpe_info["version"],
                    cpe_info["cpe"]
                )
                for v in vulns:
                    context.record_finding(v, asset_id=asset_id)
            except Exception as e:
                event_cb("warn", f"Vulnerability lookup error for {cpe_info['product']}: {e}")

        # 5. Comprehensive Web, Cryptographic, DNS & Cloud Security Scanners
        # These non-destructive posture audits run safely across discovered hosts
        event_cb("info", "Executing web security posture, header misconfiguration, and cookie flags audit...", 62, "Web Security Scans")
        try:
            web_findings = await scan_web_security_posture(target, context)
            for wf in web_findings:
                context.record_finding(wf)
        except Exception as e:
            event_cb("warn", f"Web security scanner warning: {e}")

        event_cb("info", "Auditing SSL/TLS certificate validity, protocol deprecation, and weak ciphers...", 68, "SSL/TLS Cryptography")
        try:
            ssl_findings = await scan_ssl_security_posture(target, context)
            for sf in ssl_findings:
                context.record_finding(sf)
        except Exception as e:
            event_cb("warn", f"SSL/TLS security scanner warning: {e}")

        event_cb("info", "Auditing DNS, SPF, DMARC email spoofing, and DNSSEC posture...", 72, "DNS & Email Security")
        try:
            dns_findings = await scan_dns_security_posture(target, context)
            for df in dns_findings:
                context.record_finding(df)
        except Exception as e:
            event_cb("warn", f"DNS security scanner warning: {e}")

        event_cb("info", "Checking subdomain CNAME records for dangling takeover pointers...", 76, "Subdomain Takeovers")
        try:
            takeover_findings = await scan_subdomain_takeovers(target, context)
            for tf in takeover_findings:
                context.record_finding(tf)
        except Exception as e:
            event_cb("warn", f"Subdomain takeover scanner warning: {e}")

        event_cb("info", "Inspecting cloud storage bucket permutations (AWS S3)...", 80, "Cloud Storage Exposure")
        try:
            bucket_findings = await scan_cloud_storage_buckets(target, context)
            for bf in bucket_findings:
                context.record_finding(bf)
        except Exception as e:
            event_cb("warn", f"Cloud storage scanner warning: {e}")

        event_cb("info", "Evaluating custom security detection rules...", 82, "Custom Rules Engine")
        try:
            custom_findings = await execute_custom_rules(target, context)
            for cf in custom_findings:
                context.record_finding(cf)
        except Exception as e:
            event_cb("warn", f"Custom rules engine warning: {e}")

        # 6. Active Reconnaissance Suite & Sensitive Probes (if in active mode and authorized)
        if mode == "active":
            event_cb("info", "Scope authorized for active audit. Launching Comprehensive Active Reconnaissance Suite...", 83, "Active Recon Suite")
            
            active_modules = [
                (ActivePortScannerModule(), "TCP Port & Banner Scanner", 84),
                (HTTPMethodProberModule(), "HTTP Verbs & WebDAV Audit", 85),
                (DNSAXFRModule(), "DNS Zone Transfer (AXFR) Audit", 86),
                (WAFDetectorModule(), "WAF & Reverse Proxy Fingerprinting", 87),
                (CORSActiveProberModule(), "CORS Origin Reflection & Credential Audit", 88),
                (WebMetadataCrawlerModule(), "Web Metadata & Endpoint Crawler", 89),
                (VirtualHostProberModule(), "Virtual Host (VHost) Header Probing", 90),
                (ActiveTLSProberModule(), "Active TLS Protocol & SAN Discovery", 91),
                (ActiveTakeoverProberModule(), "Active Subdomain Takeover Verification", 92),
            ]

            for active_mod, mod_title, step_progress in active_modules:
                event_cb("info", f"Executing active recon: {mod_title} on {target}...", step_progress, mod_title)
                try:
                    await active_mod.run(target, context)
                except Exception as e:
                    event_cb("warn", f"Active module {active_mod.meta.name} notice: {e}")

            # Also execute active sensitive endpoints and file probes
            try:
                endpoint_findings = await scan_sensitive_endpoints(target, context)
                for ef in endpoint_findings:
                    context.record_finding(ef)

                header_findings = await probe_security_headers(target, context)
                for hf in header_findings:
                    context.record_finding(hf)

                file_findings = await probe_exposed_files(target, context)
                for ff in file_findings:
                    context.record_finding(ff)

                tls_findings = await probe_tls_certificate(target, context)
                for tf in tls_findings:
                    context.record_finding(tf)
            except Exception as e:
                event_cb("warn", f"Active checks error: {e}")

        # 7. Drop-in Plugins Execution (from plugins/)
        if run_plugins:
            event_cb("info", "Executing drop-in plugins from plugins/ directory...", 94, "Executing Plugins")
            try:
                await execute_all_plugins(target, context)
            except Exception as e:

                event_cb("warn", f"Plugin execution warning: {e}")

        # 8. Risk Scoring & Financial Model Calculation
        event_cb("info", "Synthesizing composite risk scoring and financial breach loss metrics...", 96, "Financial Risk Modeling")
        db.refresh(scan)
        findings_list = scan.findings
        assets_list = scan.assets

        # Compute Risk Ranking
        asset_map = {a.id: a for a in assets_list}
        scored_findings = score_and_rank_findings(findings_list, asset_map)
        
        # Calculate overall scan risk score (weighted top 5 findings)
        overall_score = 0.0
        if scored_findings:
            top_scores = [sf[0] for sf in scored_findings[:5]]
            overall_score = round(sum(top_scores) / len(top_scores), 1)

        # Financial cost calculation
        cost_res = calculate_costs(findings_list, currency="USD")

        # 8. Finalize Scan
        scan.total_assets = len(assets_list)
        scan.total_findings = len(findings_list)
        scan.risk_score = overall_score
        scan.total_fix_cost = cost_res["total_fix_cost_both"]
        scan.potential_breach_loss = cost_res["total_potential_breach_loss"]
        scan.roi_percentage = cost_res["roi_both"]
        scan.progress = 100
        scan.current_step = "Completed"
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.summary_notes = cost_res["explanation"]
        db.commit()

        event_cb("good", f"Audit completed successfully! Discovered {scan.total_assets} assets and {scan.total_findings} findings.", 100, "Completed")
