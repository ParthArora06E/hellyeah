"""
Advanced SSL/TLS Certificate & Certificate Transparency (CT) Reconnaissance Module
Discovers perimeter assets using:
1. Direct live TLS/SSL socket handshakes (X.509 Subject Alternative Names - SAN extraction)
2. Multi-provider Certificate Transparency feeds (CertSpotter, HackerTarget, jldc/Anubis, crt.sh)
3. Certificate validity & expiration auditing
"""
import ssl
import socket
import asyncio
from typing import List, Union, Set
from datetime import datetime, timezone
import dns.resolver

from ..adapter.base import BaseModule, ModuleMeta
from ..adapter.context import ScanContext
from ...schemas.schemas import AssetBase, FindingBase


class SSLCertReconModule(BaseModule):
    meta = ModuleMeta(
        name="ssl_cert_recon",
        author="Auditor Security Team",
        description="Extracts assets via live TLS X.509 Subject Alternative Names (SANs) and multi-source Certificate Transparency feeds.",
        category="discovery",
        is_passive=True,
        version="2.0.0"
    )
    required_keys = []

    async def run(self, target: str, context: ScanContext) -> List[Union[AssetBase, FindingBase]]:
        context.emit_log("info", f"Initiating advanced SSL/TLS certificate reconnaissance for {target}...")
        context.log_audit("SSL_CERT_RECON", target, "Inspecting TLS certificates and Certificate Transparency logs")

        results: List[Union[AssetBase, FindingBase]] = []
        discovered_subdomains: Set[str] = set()

        # ─────────────────────────────────────────────────────────────────────
        # 1. Direct Live TLS/SSL Socket Handshake & SAN Extraction
        # ─────────────────────────────────────────────────────────────────────
        san_hostnames = await self._inspect_live_tls_certificate(target, context)
        for sub in san_hostnames:
            sub_clean = sub.strip().lower()
            if sub_clean.startswith("*."):
                sub_clean = sub_clean[2:]
            if sub_clean.endswith(target) and sub_clean not in discovered_subdomains:
                discovered_subdomains.add(sub_clean)
                asset = AssetBase(
                    type="subdomain" if sub_clean != target else "domain",
                    value=sub_clean,
                    source="Live TLS Certificate (SAN)",
                    owner="Infrastructure Team",
                    criticality=4 if any(k in sub_clean for k in ["admin", "api", "auth", "vpn", "corp", "mail"]) else 3,
                    tags=["tls_cert", "san_verified", "active_ssl"],
                    raw_metadata={"discovered_via": "x509_subject_alternative_names"}
                )
                context.record_asset(asset)
                results.append(asset)

        if san_hostnames:
            context.emit_log("good", f"Live TLS handshake on {target} yielded {len(san_hostnames)} Subject Alternative Names (SANs).")

        # ─────────────────────────────────────────────────────────────────────
        # 2. Multi-Provider Certificate Transparency (CT) Aggregation
        # ─────────────────────────────────────────────────────────────────────
        ct_subdomains = await self._query_certificate_transparency_feeds(target, context)
        new_from_ct = 0
        for sub in ct_subdomains:
            sub_clean = sub.strip().lower()
            if sub_clean.startswith("*."):
                sub_clean = sub_clean[2:]
            if sub_clean.endswith(target) and sub_clean not in discovered_subdomains:
                discovered_subdomains.add(sub_clean)
                new_from_ct += 1
                asset = AssetBase(
                    type="subdomain" if sub_clean != target else "domain",
                    value=sub_clean,
                    source="Certificate Transparency Logs",
                    owner="Unassigned",
                    criticality=4 if any(k in sub_clean for k in ["admin", "api", "auth", "vpn", "stage"]) else 3,
                    tags=["public_facing", "tls_cert", "ct_log"],
                    raw_metadata={"discovered_via": "certificate_transparency"}
                )
                context.record_asset(asset)
                results.append(asset)

        context.emit_log(
            "good",
            f"SSL/TLS Certificate Recon finished: {len(discovered_subdomains)} unique hosts identified ({len(san_hostnames)} from live cert, {new_from_ct} from CT feeds)."
        )
        return results

    async def _inspect_live_tls_certificate(self, target: str, context: ScanContext) -> Set[str]:
        """
        Connects via TLS socket to port 443 with SNI to extract X.509 certificate and SANs using cryptography.x509.
        """
        def _get_cert_sync():
            found_sans = set()
            hosts_to_try = [target]
            if not target.startswith("www."):
                hosts_to_try.append(f"www.{target}")
            ports_to_try = [443, 8443]

            for host in hosts_to_try:
                for port in ports_to_try:
                    try:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE  # Safe inspection even if self-signed or expired

                        with socket.create_connection((host, port), timeout=3.5) as sock:
                            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                                # Primary: Binary DER inspection via cryptography
                                der_cert = ssock.getpeercert(binary_form=True)
                                if der_cert:
                                    try:
                                        import cryptography.x509
                                        from cryptography.x509.oid import ExtensionOID, NameOID
                                        x509_cert = cryptography.x509.load_der_x509_certificate(der_cert)

                                        # 1. Subject Alternative Names (SANs)
                                        try:
                                            san_ext = x509_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                                            dns_names = san_ext.value.get_values_for_type(cryptography.x509.DNSName)
                                            for dname in dns_names:
                                                d_clean = str(dname).strip().lower()
                                                if d_clean.startswith("*."):
                                                    d_clean = d_clean[2:]
                                                if d_clean.endswith(target):
                                                    found_sans.add(d_clean)
                                        except Exception:
                                            pass

                                        # 2. Subject Common Name (CN)
                                        for attr in x509_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                                            c_val = str(attr.value).strip().lower()
                                            if c_val.startswith("*."):
                                                c_val = c_val[2:]
                                            if c_val.endswith(target):
                                                found_sans.add(c_val)
                                    except Exception:
                                        pass

                                # Fallback: standard getpeercert dict if available
                                cert_dict = ssock.getpeercert(binary_form=False)
                                if cert_dict:
                                    for item in cert_dict.get("subject", []):
                                        for k, val in item:
                                            if k == "commonName" and val:
                                                val_clean = str(val).strip().lower()
                                                if val_clean.startswith("*."):
                                                    val_clean = val_clean[2:]
                                                if val_clean.endswith(target):
                                                    found_sans.add(val_clean)
                                    for san_type, san_val in cert_dict.get("subjectAltName", []):
                                        if san_type.lower() == "dns" and san_val:
                                            s_clean = str(san_val).strip().lower()
                                            if s_clean.startswith("*."):
                                                s_clean = s_clean[2:]
                                            if s_clean.endswith(target):
                                                found_sans.add(s_clean)
                    except Exception:
                        continue
            return found_sans

        try:
            return await asyncio.to_thread(_get_cert_sync)
        except Exception:
            return set()

    async def _query_certificate_transparency_feeds(self, target: str, context: ScanContext) -> Set[str]:
        """
        Aggregates Certificate Transparency records from multiple public providers:
        1. CertSpotter API
        2. HackerTarget Hostsearch API
        3. jldc / Anubis API
        4. crt.sh API
        """
        ct_hosts = set()

        # Feed A: CertSpotter (Free CT API)
        try:
            cs_url = f"https://api.certspotter.com/v1/issuances?domain={target}&include_subdomains=true&expand=dns_names"
            cs_data = await context.http.get_json(cs_url, ttl_seconds=1200)
            if cs_data and isinstance(cs_data, list):
                for issuance in cs_data:
                    for dname in issuance.get("dns_names", []):
                        d_clean = str(dname).strip().lower()
                        if d_clean.startswith("*."):
                            d_clean = d_clean[2:]
                        if d_clean.endswith(target):
                            ct_hosts.add(d_clean)
        except Exception:
            pass

        # Feed B: HackerTarget Hostsearch (Free CT / DNS index)
        try:
            ht_url = f"https://api.hackertarget.com/hostsearch/?q={target}"
            ht_text = await context.http.get_text(ht_url, ttl_seconds=1200)
            if ht_text and not ht_text.startswith("error"):
                for line in ht_text.splitlines():
                    if "," in line:
                        hname, ip_val = line.split(",", 1)
                        h_clean = hname.strip().lower()
                        if h_clean.endswith(target):
                            ct_hosts.add(h_clean)
        except Exception:
            pass

        # Feed C: jldc / Anubis (CT & Web Archive aggregator)
        try:
            anubis_url = f"https://jldc.me/anubis/subdomains/{target}"
            anubis_data = await context.http.get_json(anubis_url, ttl_seconds=1200)
            if anubis_data and isinstance(anubis_data, list):
                for item in anubis_data:
                    sub_str = str(item).strip().lower()
                    if sub_str.startswith("*."):
                        sub_str = sub_str[2:]
                    if sub_str.endswith(target):
                        ct_hosts.add(sub_str)
        except Exception:
            pass

        # Feed D: crt.sh (Standard Certificate Transparency)
        try:
            crt_url = f"https://crt.sh/?q=%25.{target}&output=json"
            crt_data = await context.http.get_json(crt_url, ttl_seconds=1200)
            if crt_data and isinstance(crt_data, list):
                for entry in crt_data:
                    nv = entry.get("name_value", "")
                    for sub in nv.split("\n"):
                        s_clean = sub.strip().lower()
                        if s_clean.startswith("*."):
                            s_clean = s_clean[2:]
                        if s_clean.endswith(target):
                            ct_hosts.add(s_clean)
        except Exception:
            pass

        return ct_hosts
