"""
Active Recon Module: Virtual Host (VHost) & Host Header Prober
Actively probes web servers with alternate Host headers to discover internal virtual hosts
hosted on the same IP infrastructure (e.g. admin.target, dev.target, internal.target, localhost).
"""
import socket
from typing import List, Dict, Any, Union, Optional
from ..adapter.base import BaseModule, ModuleMeta
from ..adapter.context import ScanContext
from ...schemas.schemas import AssetBase, FindingBase


class VirtualHostProberModule(BaseModule):
    meta = ModuleMeta(
        name="virtual_host_prober",
        author="Auditor Security Team",
        description="Actively audits web servers for internal virtual hosts and routing leaks by sending alternate Host headers.",
        category="active",
        is_passive=False,
        version="1.0.0"
    )

    async def run(self, target: str, context: ScanContext) -> List[Union[AssetBase, FindingBase]]:
        results: List[Union[AssetBase, FindingBase]] = []
        context.emit_log("info", f"Executing active Virtual Host (VHost) header probing on {target}...", 90, "Virtual Host Prober")
        context.log_audit("ACTIVE_VHOST_PROBE", target, "Testing alternate Host headers against IP")

        # Resolve target IP
        try:
            target_ip = socket.gethostbyname(target)
        except Exception:
            return results

        base_url = f"https://{target_ip}"
        # Baseline request with normal target host header
        baseline_resp = await context.http.get(
            base_url,
            headers={"Host": target},
            ttl_seconds=0,
            retries=1
        )
        if not baseline_resp:
            base_url = f"http://{target_ip}"
            baseline_resp = await context.http.get(
                base_url,
                headers={"Host": target},
                ttl_seconds=0,
                retries=1
            )

        if not baseline_resp:
            return results

        base_len = len(baseline_resp.content or b"")
        base_status = baseline_resp.status_code

        vhost_candidates = [
            f"admin.{target}",
            f"internal.{target}",
            f"dev.{target}",
            f"staging.{target}",
            f"portal.{target}",
            f"api.{target}",
            "localhost",
            "127.0.0.1"
        ]

        discovered_vhosts = []

        for candidate in vhost_candidates:
            resp = await context.http.get(
                base_url,
                headers={"Host": candidate},
                ttl_seconds=0,
                retries=1
            )
            if not resp:
                continue

            resp_len = len(resp.content or b"")
            resp_status = resp.status_code

            # Distinct virtual host detection:
            # 1. Status change (e.g. baseline is 404, candidate is 200 or 401/403)
            # 2. Or length changes significantly (> 30%) and status != 404
            status_changed = (resp_status != base_status and resp_status in (200, 301, 302, 401, 403))
            len_changed = abs(resp_len - base_len) > max(300, base_len * 0.3) and resp_status == 200

            if status_changed or len_changed:
                discovered_vhosts.append((candidate, resp_status, resp_len))

        if discovered_vhosts:
            context.emit_log("good", f"Identified {len(discovered_vhosts)} internal virtual hosts responding on {target_ip}.")

            for vhost, st, ln in discovered_vhosts:
                # Record as newly discovered asset
                vh_asset = AssetBase(
                    type="subdomain",
                    value=vhost if "." in vhost else f"{vhost}.{target}",
                    source="Active Virtual Host Prober",
                    owner="Infrastructure Team",
                    criticality=4 if "admin" in vhost or "internal" in vhost else 3,
                    ip_address=target_ip,
                    tags=["active_recon", "vhost_discovery"],
                    raw_metadata={"vhost": vhost, "status_code": st, "length": ln}
                )
                context.record_asset(vh_asset)
                results.append(vh_asset)

                finding = FindingBase(
                    title=f"Internal Virtual Host Discovered via Host Header: {vhost} on {target_ip}",
                    description=(
                        f"Web server at IP {target_ip} routes to distinct content or administrative services when presented with Host header '{vhost}' "
                        f"(HTTP {st}, content length {ln} bytes vs baseline HTTP {base_status}, {base_len} bytes). "
                        "Internal virtual hosts frequently expose unauthenticated administration dashboards or staging databases to external users."
                    ),
                    severity="High" if "admin" in vhost or "internal" in vhost or st in (200, 401) else "Medium",
                    cvss_score=7.5 if "admin" in vhost else 5.3,
                    epss_score=0.21,
                    source="Active Virtual Host Prober",
                    confidence="Confirmed",
                    status="Open",
                    evidence={"ip": target_ip, "vhost": vhost, "status_code": st, "length": ln, "baseline_status": base_status},
                    remediation_text="Configure web server default virtual host (e.g., default_server in Nginx) to drop or reject unknown Host headers with HTTP 444 or 400 Bad Request.",
                    owasp_category="A05:2021-Security Misconfiguration",
                    iso_control="A.13.1 Network Security",
                    fix_hours_dev=1.0,
                    fix_hours_tester=0.5,
                    estimated_fix_cost=117.5,
                    risk_score=72.0 if "admin" in vhost else 45.0
                )
                context.record_finding(finding)
                results.append(finding)

        return results
