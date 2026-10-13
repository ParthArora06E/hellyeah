"""
Active Recon Module: TCP Port Scanner & Service Banner Grabber
Performs safe, asynchronous port scanning and service banner identification
across critical perimeter TCP ports.
"""
import asyncio
import socket
from typing import List, Dict, Any, Union, Optional
from ..adapter.base import BaseModule, ModuleMeta
from ..adapter.context import ScanContext
from ...schemas.schemas import AssetBase, FindingBase

# Common perimeter ports to audit actively
TARGET_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS-TCP",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "Web-Admin",
    9200: "Elasticsearch",
    27017: "MongoDB"
}

class ActivePortScannerModule(BaseModule):
    meta = ModuleMeta(
        name="active_port_scanner",
        author="Auditor Security Team",
        description="Asynchronous TCP port scanner & banner grabber detecting active exposed network services and database listeners.",
        category="active",
        is_passive=False,
        version="1.0.0"
    )

    async def _probe_port(self, host: str, port: int, service_name: str) -> Optional[Dict[str, Any]]:
        """
        Attempts a TCP connection and banner grab with strict timeouts.
        """
        banner = ""
        is_open = False
        reader = None
        writer = None

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=1.2
            )
            is_open = True

            # Interactive probe for specific services
            if port in (80, 8080, 8888):
                probe_payload = b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n"
                writer.write(probe_payload)
                await writer.drain()
            elif port == 6379:
                writer.write(b"PING\r\n")
                await writer.drain()
            elif port in (21, 22, 25, 110, 143):
                # Service usually sends welcome banner immediately
                pass

            try:
                data = await asyncio.wait_for(reader.read(512), timeout=0.8)
                banner = data.decode("utf-8", errors="ignore").strip()
            except Exception:
                pass

        except Exception:
            is_open = False
        finally:
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        if is_open:
            return {
                "port": port,
                "service": service_name,
                "banner": banner[:200] if banner else ""
            }
        return None

    async def run(self, target: str, context: ScanContext) -> List[Union[AssetBase, FindingBase]]:
        results: List[Union[AssetBase, FindingBase]] = []
        context.emit_log("info", f"Executing active TCP port scan and service banner grabbing on {target}...", 84, "Active Port Scanner")
        context.log_audit("ACTIVE_PORT_SCAN", target, f"Probing {len(TARGET_PORTS)} perimeter TCP ports")

        # Resolve target to IP if possible
        target_host = target
        try:
            resolved_ip = socket.gethostbyname(target)
        except Exception:
            resolved_ip = None

        # Use semaphore to limit socket concurrency
        semaphore = asyncio.Semaphore(12)

        async def _bounded_probe(p: int, s: str):
            async with semaphore:
                return await self._probe_port(target_host, p, s)

        tasks = [_bounded_probe(p, s) for p, s in TARGET_PORTS.items()]
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)

        open_ports = []
        for res in scan_results:
            if isinstance(res, dict) and res:
                open_ports.append(res)

        context.emit_log("good", f"Active port scan completed. Identified {len(open_ports)} open TCP services on {target}.")

        for op in open_ports:
            port = op["port"]
            service = op["service"]
            banner = op["banner"]

            # 1. Record Discovered Service Asset
            service_asset = AssetBase(
                type="service",
                value=f"{target}:{port}",
                source="Active Port Scanner",
                owner="Infrastructure Team",
                criticality=4 if port in (22, 3389, 6379, 27017, 9200) else 3,
                ip_address=resolved_ip,
                ports=[port],
                technologies=[service] + ([banner] if banner and len(banner) < 50 else []),
                tags=["active_recon", "open_port", service.lower()],
                raw_metadata={
                    "port": port,
                    "service": service,
                    "banner": banner,
                    "target_host": target,
                    "ip_address": resolved_ip
                }
            )
            context.record_asset(service_asset)
            results.append(service_asset)

            # 2. Risk & Vulnerability Assessment for Dangerous Publicly Exposed Ports
            if port == 6379:
                is_unauth = "+PONG" in banner or "ERR" in banner or not banner
                finding = FindingBase(
                    title=f"Critical Exposed Redis In-Memory Database ({target}:6379)",
                    description="Redis database port 6379 is publicly exposed on the internet perimeter. Redis is designed for trusted internal networks; unauthenticated exposure allows remote threat actors to read/write all memory caches, execute arbitrary code, or write malicious SSH keys.",
                    severity="Critical",
                    cvss_score=9.8,
                    epss_score=0.82,
                    is_kev=True,
                    source="Active Port Scanner",
                    confidence="Confirmed",
                    status="Open",
                    evidence={"port": 6379, "service": "Redis", "banner": banner},
                    remediation_text="Bind Redis to localhost (127.0.0.1) or internal VPC interface, enable strong requirepass authentication, and block external TCP port 6379 at perimeter firewalls.",
                    owasp_category="A05:2021-Security Misconfiguration",
                    iso_control="A.13.1 Network Security",
                    fix_hours_dev=2.0,
                    fix_hours_tester=1.0,
                    estimated_fix_cost=235.0,
                    risk_score=98.0
                )
                context.record_finding(finding)
                results.append(finding)

            elif port == 27017:
                finding = FindingBase(
                    title=f"Critical Exposed MongoDB Database ({target}:27017)",
                    description="MongoDB listener port 27017 is directly accessible from the public internet. Internet-facing database instances are prime targets for automated ransomware attacks and catastrophic data breaches.",
                    severity="Critical",
                    cvss_score=9.8,
                    epss_score=0.78,
                    is_kev=True,
                    source="Active Port Scanner",
                    confidence="Confirmed",
                    status="Open",
                    evidence={"port": 27017, "service": "MongoDB", "banner": banner},
                    remediation_text="Ensure MongoDB bindIp is restricted to 127.0.0.1/private network, enable SCRAM authentication, and block port 27017 from external CIDR blocks.",
                    owasp_category="A05:2021-Security Misconfiguration",
                    iso_control="A.9.4.1 Information Access Restriction",
                    fix_hours_dev=2.0,
                    fix_hours_tester=1.0,
                    estimated_fix_cost=235.0,
                    risk_score=96.0
                )
                context.record_finding(finding)
                results.append(finding)

            elif port == 9200:
                finding = FindingBase(
                    title=f"High Risk Exposed Elasticsearch Cluster ({target}:9200)",
                    description="Elasticsearch HTTP REST API port 9200 is exposed to the public internet. Exposed clusters frequently leak internal application logs, PII, and sensitive business metrics.",
                    severity="High",
                    cvss_score=8.6,
                    epss_score=0.54,
                    source="Active Port Scanner",
                    confidence="Confirmed",
                    status="Open",
                    evidence={"port": 9200, "service": "Elasticsearch", "banner": banner},
                    remediation_text="Enable Elasticsearch Security features (xpack.security.enabled: true), mandate TLS/authentication, and place the cluster behind an internal API gateway or VPN.",
                    owasp_category="A01:2021-Broken Access Control",
                    iso_control="A.13.1 Network Security",
                    fix_hours_dev=3.0,
                    fix_hours_tester=1.5,
                    estimated_fix_cost=370.0,
                    risk_score=86.0
                )
                context.record_finding(finding)
                results.append(finding)

            elif port in (3389, 5900):
                svc_title = "RDP (Remote Desktop Protocol)" if port == 3389 else "VNC (Virtual Network Computing)"
                finding = FindingBase(
                    title=f"High Risk Exposed Remote GUI Desktop: {svc_title} ({target}:{port})",
                    description=f"{svc_title} is exposed to the public internet. Public remote desktop services are subjected to continuous brute-force credential stuffing and exploitation of zero-day vulnerabilities (e.g., BlueKeep CVE-2019-0708).",
                    severity="High",
                    cvss_score=8.1,
                    epss_score=0.61,
                    is_kev=True if port == 3389 else False,
                    source="Active Port Scanner",
                    confidence="Confirmed",
                    status="Open",
                    evidence={"port": port, "service": service, "banner": banner},
                    remediation_text=f"Place {svc_title} behind an enterprise Zero-Trust Network Access (ZTNA) or corporate VPN gateway with mandatory MFA.",
                    owasp_category="A07:2021-Identification and Authentication Failures",
                    iso_control="A.9.4.2 Secure Log-on Procedures",
                    fix_hours_dev=2.0,
                    fix_hours_tester=1.0,
                    estimated_fix_cost=235.0,
                    risk_score=82.0
                )
                context.record_finding(finding)
                results.append(finding)

            elif port == 23:
                finding = FindingBase(
                    title=f"Medium Risk Insecure Legacy Telnet Service ({target}:23)",
                    description="Unencrypted Telnet daemon port 23 is listening on the perimeter. Telnet transmits usernames, passwords, and commands in cleartext across the network without encryption.",
                    severity="Medium",
                    cvss_score=6.5,
                    epss_score=0.15,
                    source="Active Port Scanner",
                    confidence="Confirmed",
                    status="Open",
                    evidence={"port": 23, "service": "Telnet", "banner": banner},
                    remediation_text="Decommission Telnet immediately and migrate all administrative access to SSHv2 with key-based authentication.",
                    owasp_category="A02:2021-Cryptographic Failures",
                    iso_control="A.13.2.1 Information Transfer",
                    fix_hours_dev=1.0,
                    fix_hours_tester=0.5,
                    estimated_fix_cost=117.5,
                    risk_score=55.0
                )
                context.record_finding(finding)
                results.append(finding)

            elif port == 445:
                finding = FindingBase(
                    title=f"High Risk Exposed Microsoft SMB Service ({target}:445)",
                    description="Server Message Block (SMB) port 445 is publicly reachable. Public SMB services are historically targeted by wormable remote code execution vulnerabilities (e.g. EternalBlue MS17-010).",
                    severity="High",
                    cvss_score=8.5,
                    epss_score=0.72,
                    is_kev=True,
                    source="Active Port Scanner",
                    confidence="Confirmed",
                    status="Open",
                    evidence={"port": 445, "service": "SMB", "banner": banner},
                    remediation_text="Block external access to TCP port 445 at edge firewalls. SMB should never be exposed to the public internet.",
                    owasp_category="A05:2021-Security Misconfiguration",
                    iso_control="A.13.1 Network Security",
                    fix_hours_dev=1.0,
                    fix_hours_tester=0.5,
                    estimated_fix_cost=117.5,
                    risk_score=84.0
                )
                context.record_finding(finding)
                results.append(finding)

        return results
