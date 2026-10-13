"""
WHOIS Domain Registration & Expiry Analysis Module
Ported & Adapted from Recon-ng / Preconng parsers/whois_parser.py
Licensed under GNU General Public License v3.0 (GPL-3.0)
"""
import asyncio
from datetime import datetime, timezone
from typing import List, Union
from ..adapter.base import BaseModule, ModuleMeta
from ..adapter.context import ScanContext
from ...schemas.schemas import AssetBase, FindingBase

class WhoisModule(BaseModule):
    meta = ModuleMeta(
        name="whois_lookup",
        author="Auditor Security Team (Adapted from Recon-ng)",
        description="Inspects WHOIS registrar, creation and expiration metadata, alerting on imminent domain expiration risks.",
        category="discovery",
        is_passive=True,
        version="1.0.0"
    )
    required_keys = []

    async def run(self, target: str, context: ScanContext) -> List[Union[AssetBase, FindingBase]]:
        context.emit_log("info", f"Executing WHOIS registration query for {target}...")
        context.log_audit("WHOIS_QUERY", target, "Fetching domain registration details")
        
        results: List[Union[AssetBase, FindingBase]] = []

        # Use an RDAP HTTP lookup or whois package query
        # RDAP (Registration Data Access Protocol) is modern, clean, JSON-based, no binary dependency required!
        rdap_url = f"https://rdap.org/domain/{target}"
        try:
            data = await context.http.get_json(rdap_url, ttl_seconds=86400)
            if data and isinstance(data, dict):
                registrar = ""
                for entity in data.get("entities", []):
                    if "registrar" in entity.get("roles", []):
                        vcard = entity.get("vcardArray", [])
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if item[0] == "fn":
                                    registrar = item[3]
                                    break

                # Extract events (registration, expiration)
                exp_date_str = None
                for ev in data.get("events", []):
                    if ev.get("eventAction") == "expiration":
                        exp_date_str = ev.get("eventDate")

                asset = AssetBase(
                    type="domain",
                    value=target,
                    source="WHOIS / RDAP",
                    owner="Domain Administrator",
                    criticality=5,
                    tags=["apex_domain", "rdap_registered"],
                    raw_metadata={
                        "registrar": registrar or "Identified via RDAP",
                        "expiration": exp_date_str,
                        "status": data.get("status", [])
                    }
                )
                context.record_asset(asset)
                results.append(asset)

                # Check if expiration date is within 30 days
                if exp_date_str:
                    try:
                        # Clean ISO format
                        clean_str = exp_date_str.replace("Z", "+00:00")
                        exp_dt = datetime.fromisoformat(clean_str)
                        days_left = (exp_dt - datetime.now(timezone.utc)).days
                        if 0 <= days_left <= 30:
                            finding = FindingBase(
                                title=f"Imminent Domain Expiration: {target} ({days_left} days left)",
                                description=f"The domain {target} expires in {days_left} days ({exp_date_str}). Unrenewed domains risk domain hijacking and catastrophic business interruption.",
                                severity="High",
                                cvss_score=7.5,
                                epss_score=0.05,
                                source="WHOIS Registration Audit",
                                confidence="Confirmed",
                                status="Open",
                                evidence={"expiration_date": exp_date_str, "days_remaining": days_left},
                                remediation_text="Enable auto-renewal with registrar immediately or manually renew domain for at least 1-3 years.",
                                owasp_category="A05:2021-Security Misconfiguration",
                                iso_control="A.12.1.2 Change Management",
                                fix_hours_dev=0.5,
                                fix_hours_tester=0.2,
                                estimated_fix_cost=50.0,
                                risk_score=70.0
                            )
                            context.record_finding(finding)
                            results.append(finding)
                    except Exception:
                        pass

                context.emit_log("good", f"WHOIS data retrieved successfully for {target}.")
            else:
                context.emit_log("info", "RDAP/WHOIS query yielded basic records.")
        except Exception as e:
            context.emit_log("warn", f"WHOIS lookup warning: {e}")

        return results
