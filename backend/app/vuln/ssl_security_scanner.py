"""
SSL/TLS Cryptographic Security & Protocol Posture Scanner
Audits perimeter TLS endpoints for:
1. Deprecated TLS 1.0 and TLS 1.1 support
2. Certificate expiration (expired or expiring in < 30 days)
3. Untrusted / Self-signed certificates
4. Hostname mismatches
5. Weak cipher suite configurations
"""
import ssl
import socket
import asyncio
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from ..schemas.schemas import FindingBase
from ..recon.adapter.context import ScanContext


async def scan_ssl_security_posture(target: str, context: ScanContext) -> List[FindingBase]:
    """
    Evaluates TLS protocol hygiene, cryptographic strength, and certificate validity.
    """
    findings: List[FindingBase] = []
    hosts_to_test = [target]
    if not target.startswith("www."):
        hosts_to_test.append(f"www.{target}")

    context.emit_log("info", f"Executing SSL/TLS cryptographic hygiene and protocol strength audit for {target}...")

    def _sync_ssl_audit(host: str) -> List[FindingBase]:
        sub_findings = []
        port = 443
        
        # 1. Primary Certificate & Protocol Check
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=3.5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    tls_version = ssock.version()
                    cipher_info = ssock.cipher()

                    if der_cert:
                        try:
                            import cryptography.x509
                            from cryptography.x509.oid import ExtensionOID
                            x509_cert = cryptography.x509.load_der_x509_certificate(der_cert)
                            
                            # Expiration check
                            not_after = x509_cert.not_valid_after_utc
                            now_utc = datetime.now(timezone.utc)
                            days_remaining = (not_after - now_utc).days

                            if days_remaining < 0:
                                sub_findings.append(FindingBase(
                                    title=f"Expired SSL/TLS Certificate on {host}",
                                    description=f"The SSL/TLS certificate for {host} expired on {not_after.strftime('%Y-%m-%d')} ({abs(days_remaining)} days ago). Browsers block user access with severe security warnings.",
                                    severity="High",
                                    cvss_score=7.5,
                                    epss_score=0.12,
                                    source="SSL/TLS Cryptographic Audit",
                                    confidence="Confirmed",
                                    status="Open",
                                    evidence={"host": host, "expired_date": not_after.isoformat(), "days_expired": abs(days_remaining)},
                                    remediation_text="Renew and deploy an active X.509 certificate immediately via Let's Encrypt or your commercial CA.",
                                    owasp_category="A02:2021-Cryptographic Failures",
                                    iso_control="A.10.1 Cryptographic Controls",
                                    fix_hours_dev=0.5,
                                    fix_hours_tester=0.25,
                                    estimated_fix_cost=58.75,
                                    risk_score=75.0
                                ))
                            elif days_remaining < 30:
                                sub_findings.append(FindingBase(
                                    title=f"SSL/TLS Certificate Expiring Soon ({days_remaining} Days) on {host}",
                                    description=f"The certificate on {host} expires in {days_remaining} days on {not_after.strftime('%Y-%m-%d')}. Automated renewal failure risk.",
                                    severity="Medium",
                                    cvss_score=5.3,
                                    epss_score=0.035,
                                    source="SSL/TLS Cryptographic Audit",
                                    confidence="Confirmed",
                                    status="Open",
                                    evidence={"host": host, "expires_in_days": days_remaining},
                                    remediation_text="Trigger automated ACME certificate renewal before the 30-day expiration window lapses.",
                                    owasp_category="A02:2021-Cryptographic Failures",
                                    iso_control="A.10.1 Cryptographic Controls",
                                    fix_hours_dev=0.25,
                                    fix_hours_tester=0.25,
                                    estimated_fix_cost=37.5,
                                    risk_score=35.0
                                ))

                            # Hostname match check
                            try:
                                san_ext = x509_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                                valid_dns_names = [str(d).strip().lower() for d in san_ext.value.get_values_for_type(cryptography.x509.DNSName)]
                                matches = any(
                                    h == host.lower() or (h.startswith("*.") and host.lower().endswith(h[2:]))
                                    for h in valid_dns_names
                                )
                                if not matches and valid_dns_names:
                                    sub_findings.append(FindingBase(
                                        title=f"SSL Certificate Hostname Mismatch on {host}",
                                        description=f"The certificate presented by {host} lists SANs for {', '.join(valid_dns_names[:3])}, which does not match requested host '{host}'. Causes browser warnings.",
                                        severity="Medium",
                                        cvss_score=6.0,
                                        epss_score=0.045,
                                        source="SSL/TLS Cryptographic Audit",
                                        confidence="Confirmed",
                                        status="Open",
                                        evidence={"host": host, "cert_sans": valid_dns_names[:5]},
                                        remediation_text=f"Re-issue certificate with {host} listed in Subject Alternative Names (SANs).",
                                        owasp_category="A02:2021-Cryptographic Failures",
                                        iso_control="A.10.1 Cryptographic Controls",
                                        fix_hours_dev=0.5,
                                        fix_hours_tester=0.25,
                                        estimated_fix_cost=58.75,
                                        risk_score=48.0
                                    ))
                            except Exception:
                                pass

                            # Self-signed certificate check
                            try:
                                if x509_cert.issuer == x509_cert.subject:
                                    issuer_str = x509_cert.issuer.rfc4514_string()
                                    sub_findings.append(FindingBase(
                                        title=f"Self-Signed SSL/TLS Certificate on {host}",
                                        description=f"The certificate on {host} is self-signed (Issuer and Subject are identical: '{issuer_str[:60]}'). It is not trusted by public root certificate authorities, triggering browser warning interstitials.",
                                        severity="High",
                                        cvss_score=7.4,
                                        epss_score=0.08,
                                        source="SSL/TLS Cryptographic Audit",
                                        confidence="Confirmed",
                                        status="Open",
                                        evidence={"host": host, "issuer": issuer_str},
                                        remediation_text="Replace self-signed certificate with an active certificate issued by a trusted public Certificate Authority (e.g., Let's Encrypt).",
                                        owasp_category="A02:2021-Cryptographic Failures",
                                        iso_control="A.10.1 Cryptographic Controls",
                                        fix_hours_dev=0.5,
                                        fix_hours_tester=0.25,
                                        estimated_fix_cost=58.75,
                                        risk_score=72.0
                                    ))
                            except Exception:
                                pass

                            # Deprecated Signature Algorithm check (SHA-1 / MD5)
                            try:
                                sig_hash = x509_cert.signature_hash_algorithm
                                if sig_hash and sig_hash.name.lower() in ("sha1", "md5"):
                                    sub_findings.append(FindingBase(
                                        title=f"Weak Certificate Signature Algorithm ({sig_hash.name.upper()}) on {host}",
                                        description=f"Certificate on {host} was signed using deprecated hash algorithm '{sig_hash.name.upper()}'. Susceptible to collision attacks and rejected by modern browsers.",
                                        severity="High",
                                        cvss_score=7.1,
                                        epss_score=0.065,
                                        source="SSL/TLS Cryptographic Audit",
                                        confidence="Confirmed",
                                        status="Open",
                                        evidence={"host": host, "signature_algorithm": sig_hash.name},
                                        remediation_text="Re-issue certificate with SHA-256 (or SHA-384) signature digest.",
                                        owasp_category="A02:2021-Cryptographic Failures",
                                        iso_control="A.10.1 Cryptographic Controls",
                                        fix_hours_dev=0.5,
                                        fix_hours_tester=0.25,
                                        estimated_fix_cost=58.75,
                                        risk_score=68.0
                                    ))
                            except Exception:
                                pass

                            # Inadequate Public Key Size check
                            try:
                                pub_key = x509_cert.public_key()
                                key_size = getattr(pub_key, "key_size", None)
                                if key_size and key_size < 2048:
                                    sub_findings.append(FindingBase(
                                        title=f"Inadequate Public Key Length ({key_size} bits) on {host}",
                                        description=f"Host {host} presents an RSA certificate with a key length of {key_size} bits. NIST and CA/Browser Forum require a minimum RSA key size of 2048 bits.",
                                        severity="Medium",
                                        cvss_score=6.2,
                                        epss_score=0.042,
                                        source="SSL/TLS Cryptographic Audit",
                                        confidence="Confirmed",
                                        status="Open",
                                        evidence={"host": host, "key_size": key_size},
                                        remediation_text="Generate a new private key with at least 2048-bit RSA (or 256-bit ECDSA) and re-issue the certificate.",
                                        owasp_category="A02:2021-Cryptographic Failures",
                                        iso_control="A.10.1 Cryptographic Controls",
                                        fix_hours_dev=0.5,
                                        fix_hours_tester=0.25,
                                        estimated_fix_cost=58.75,
                                        risk_score=50.0
                                    ))
                            except Exception:
                                pass

                        except Exception:
                            pass

                    # 2. Weak Cipher Check
                    if cipher_info:
                        cipher_name, proto, bits = cipher_info
                        if any(weak in cipher_name.upper() for weak in ["RC4", "3DES", "DES", "CBC", "MD5"]):
                            sub_findings.append(FindingBase(
                                title=f"Legacy / Weak Cipher Suite In Use ({cipher_name}) on {host}",
                                description=f"Host {host} negotiated cipher suite '{cipher_name}' ({proto}, {bits} bits). CBC and legacy ciphers are susceptible to POODLE and Lucky13 padding oracle attacks.",
                                severity="Medium",
                                cvss_score=5.9,
                                epss_score=0.052,
                                source="SSL/TLS Cryptographic Audit",
                                confidence="Confirmed",
                                status="Open",
                                evidence={"host": host, "cipher": cipher_name, "protocol": proto, "bits": bits},
                                remediation_text="Disable CBC, RC4, and 3DES ciphers. Enforce AEAD ciphers only (AES-GCM or CHACHA20-POLY1305).",
                                owasp_category="A02:2021-Cryptographic Failures",
                                iso_control="A.10.1 Cryptographic Controls",
                                fix_hours_dev=0.5,
                                fix_hours_tester=0.25,
                                estimated_fix_cost=58.75,
                                risk_score=46.0
                            ))
        except Exception:
            pass

        # 3. Test for Deprecated TLS 1.0 / TLS 1.1 Support
        for legacy_version, proto_name, cvss_val in [
            (ssl.TLSVersion.TLSv1, "TLS 1.0", 7.4),
            (ssl.TLSVersion.TLSv1_1, "TLS 1.1", 6.8)
        ]:
            try:
                legacy_ctx = ssl.create_default_context()
                legacy_ctx.check_hostname = False
                legacy_ctx.verify_mode = ssl.CERT_NONE
                legacy_ctx.minimum_version = legacy_version
                legacy_ctx.maximum_version = legacy_version

                with socket.create_connection((host, port), timeout=2.0) as sock:
                    with legacy_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        sub_findings.append(FindingBase(
                            title=f"Deprecated {proto_name} Protocol Supported on {host}",
                            description=f"Host {host} permits connections using {proto_name}. The IETF officially deprecated TLS 1.0/1.1 under RFC 8996 due to fundamental cryptographic flaws (BEAST, POODLE). Violates PCI-DSS 4.0 requirements.",
                            severity="High" if proto_name == "TLS 1.0" else "Medium",
                            cvss_score=cvss_val,
                            epss_score=0.088,
                            source="SSL/TLS Cryptographic Audit",
                            confidence="Confirmed",
                            status="Open",
                            evidence={"host": host, "negotiated_protocol": proto_name},
                            remediation_text=f"Disable {proto_name} in web server/load balancer. Enforce TLS 1.2 and TLS 1.3 as the minimum protocol versions.",
                            owasp_category="A02:2021-Cryptographic Failures",
                            iso_control="A.10.1 Cryptographic Controls",
                            fix_hours_dev=0.5,
                            fix_hours_tester=0.25,
                            estimated_fix_cost=58.75,
                            risk_score=68.0 if proto_name == "TLS 1.0" else 52.0
                        ))
            except Exception:
                # Connection refused or protocol rejected -> Good!
                pass

        return sub_findings

    for host in hosts_to_test:
        try:
            res = await asyncio.to_thread(_sync_ssl_audit, host)
            findings.extend(res)
        except Exception:
            pass

    return findings
