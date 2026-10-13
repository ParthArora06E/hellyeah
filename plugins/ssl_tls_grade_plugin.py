"""
Example Drop-in Plugin: SSL/TLS Protocol Hygiene & Grade Inspector
Audits SSL/TLS cipher suites and deprecated protocol versions.
"""
import ssl
import socket
from typing import List, Union
from backend.app.recon.adapter.base import BaseModule, ModuleMeta
from backend.app.recon.adapter.context import ScanContext
from backend.app.schemas.schemas import AssetBase, FindingBase

class SSLTLSGradePlugin(BaseModule):
    meta = ModuleMeta(
        name="ssl_tls_grade_plugin",
        author="Auditor Security Team",
        description="Inspects SSL/TLS handshake ciphers and flags deprecated protocols (TLS 1.0, TLS 1.1).",
        category="vulnerability",
        is_passive=False,
        version="1.0.0"
    )
    required_keys = []

    async def run(self, target: str, context: ScanContext) -> List[Union[AssetBase, FindingBase]]:
        results: List[Union[AssetBase, FindingBase]] = []
        context.emit_log("info", f"[Plugin:TLSGrade] Checking TLS cipher negotiation on {target}:443...")

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((target, 443), timeout=3.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                    cipher_info = ssock.cipher()
                    proto_version = ssock.version()
                    
                    if proto_version in ("TLSv1", "TLSv1.1"):
                        finding = FindingBase(
                            title=f"Deprecated TLS Protocol ({proto_version}) Supported on {target}",
                            description=f"Server {target} negotiates deprecated protocol {proto_version}. Legacy TLS protocols suffer from known cryptographic weaknesses (POODLE, BEAST) and fail PCI-DSS 4.0 compliance.",
                            severity="High",
                            cvss_score=7.4,
                            epss_score=0.04,
                            source="TLS Grade Plugin",
                            confidence="Confirmed",
                            status="Open",
                            evidence={"negotiated_protocol": proto_version, "cipher": cipher_info},
                            remediation_text="Disable TLS 1.0 and TLS 1.1 in web server configuration; enforce TLS 1.2 and TLS 1.3 only.",
                            owasp_category="A02:2021-Cryptographic Failures",
                            iso_control="A.10.1.1 Cryptographic Controls",
                            fix_hours_dev=1.0,
                            fix_hours_tester=1.0,
                            estimated_fix_cost=150.0,
                            risk_score=68.0
                        )
                        context.record_finding(finding)
                        results.append(finding)
        except Exception:
            pass

        return results
