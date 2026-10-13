"""
Custom Security Detection Rules Engine (Nuclei-Style Safe Probes)
Allows declarative inspection rules for perimeter HTTP endpoints, headers, and bodies.
Includes default rules for RFC 9116 security.txt, Prometheus metrics, and internal consoles.
"""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from ..schemas.schemas import FindingBase
from ..recon.adapter.context import ScanContext


class CustomRule(BaseModel):
    id: str
    name: str
    severity: str = "Medium"
    cvss: float = 5.3
    path: str
    matcher_type: str = "body_contains"  # body_contains, body_absent, header_contains, status_code
    matcher_pattern: str
    description: str
    remediation: str
    category: str = "A05:2021-Security Misconfiguration"
    iso_control: str = "A.12.6.1 Management of Technical Vulnerabilities"
    dev_hrs: float = 1.0
    tester_hrs: float = 0.5


# Default Curated Rule Catalog
DEFAULT_CUSTOM_RULES: List[CustomRule] = [
    CustomRule(
        id="sec-txt-rfc9116",
        name="Missing RFC 9116 Security.txt Policy",
        severity="Low",
        cvss=3.7,
        path="/.well-known/security.txt",
        matcher_type="body_absent",
        matcher_pattern="Contact:",
        description="The organization does not publish a security.txt file under /.well-known/security.txt per RFC 9116. Ethical vulnerability reporters have no established channel to disclose zero-day findings before public exposure.",
        remediation="Deploy a signed security.txt file at /.well-known/security.txt containing Contact, Encryption (PGP), and Policy URLs.",
        category="A05:2021-Security Misconfiguration",
        iso_control="A.16.1.2 Reporting Information Security Weaknesses",
        dev_hrs=0.5,
        tester_hrs=0.5
    ),
    CustomRule(
        id="prometheus-metrics-exposed",
        name="Exposed Prometheus Metrics Telemetry (/metrics)",
        severity="Medium",
        cvss=6.5,
        path="/metrics",
        matcher_type="body_contains",
        matcher_pattern="process_cpu_seconds",
        description="Publicly exposed Prometheus endpoint /metrics reveals detailed internal runtime stats, thread pools, and process memory architecture.",
        remediation="Restrict /metrics to internal scraping networks or require mTLS / Bearer token authentication.",
        category="A05:2021-Security Misconfiguration",
        iso_control="A.13.1 Network Security",
        dev_hrs=1.5,
        tester_hrs=1.0
    ),
    CustomRule(
        id="minio-storage-console",
        name="Exposed MinIO Object Storage Console",
        severity="High",
        cvss=7.5,
        path="/minio/login",
        matcher_type="body_contains",
        matcher_pattern="MinIO Console",
        description="MinIO object storage administrative console is exposed to the public internet, inviting credential stuffing and brute-force attacks.",
        remediation="Disable public internet exposure of MinIO console port (default 9001) using VPC security groups or reverse proxy ACLs.",
        category="A01:2021-Broken Access Control",
        iso_control="A.9.4.1 Information Access Restriction",
        dev_hrs=2.0,
        tester_hrs=1.0
    ),
    CustomRule(
        id="k8s-kubelet-healthz",
        name="Exposed Kubernetes Health & Diagnostic Endpoint (/healthz)",
        severity="Medium",
        cvss=5.3,
        path="/healthz",
        matcher_type="body_contains",
        matcher_pattern="ok",
        description="Perimeter host exposes internal cluster or container orchestration /healthz endpoint without access control.",
        remediation="Restrict cluster health check endpoints to internal load balancers and container kubelets.",
        category="A05:2021-Security Misconfiguration",
        iso_control="A.13.1 Network Security",
        dev_hrs=1.0,
        tester_hrs=0.5
    ),
    CustomRule(
        id="actuator-beans-leak",
        name="Exposed Spring Boot Actuator Application Beans (/actuator/beans)",
        severity="High",
        cvss=7.5,
        path="/actuator/beans",
        matcher_type="body_contains",
        matcher_pattern="contexts",
        description="Production Spring Boot application exposes /actuator/beans, revealing entire internal Spring component graph, datasource configurations, and service classes.",
        remediation="Set management.endpoints.web.exposure.exclude=beans in application.properties.",
        category="A05:2021-Security Misconfiguration",
        iso_control="A.12.6.1 Management of Technical Vulnerabilities",
        dev_hrs=1.0,
        tester_hrs=0.5
    )
]

# In-memory registry of custom rules (can be appended to by users via API)
CUSTOM_RULES_REGISTRY: List[CustomRule] = list(DEFAULT_CUSTOM_RULES)


def get_all_custom_rules() -> List[Dict[str, Any]]:
    return [r.model_dump() if hasattr(r, "model_dump") else r.dict() for r in CUSTOM_RULES_REGISTRY]


def add_custom_rule(rule_dict: Dict[str, Any]) -> Dict[str, Any]:
    new_rule = CustomRule(**rule_dict)
    # Check duplicate ID
    for idx, existing in enumerate(CUSTOM_RULES_REGISTRY):
        if existing.id == new_rule.id:
            CUSTOM_RULES_REGISTRY[idx] = new_rule
            return new_rule.model_dump() if hasattr(new_rule, "model_dump") else new_rule.dict()
    CUSTOM_RULES_REGISTRY.append(new_rule)
    return new_rule.model_dump() if hasattr(new_rule, "model_dump") else new_rule.dict()


async def execute_custom_rules(target: str, context: ScanContext) -> List[FindingBase]:
    """
    Executes active custom detection rules against target host.
    """
    findings: List[FindingBase] = []
    hosts_to_probe = [target]

    for asset in getattr(context, "discovered_assets", []):
        if asset.type == "subdomain" and any(k in asset.value for k in ["api", "app", "dev", "staging"]):
            if asset.value not in hosts_to_probe and len(hosts_to_probe) < 3:
                hosts_to_probe.append(asset.value)

    context.emit_log("info", f"Evaluating {len(CUSTOM_RULES_REGISTRY)} custom detection rules across {len(hosts_to_probe)} perimeter hosts...")

    for host in hosts_to_probe:
        for rule in CUSTOM_RULES_REGISTRY:
            url = f"https://{host}{rule.path}"
            try:
                resp = await context.http.get(url, ttl_seconds=300, retries=1)
                
                # Check status or content
                matched = False
                text = resp.text if resp else ""
                status_code = resp.status_code if resp else 0

                if rule.matcher_type == "body_contains":
                    if resp and status_code == 200 and rule.matcher_pattern in text:
                        matched = True
                elif rule.matcher_type == "body_absent":
                    # Triggers if endpoint returns 404 or pattern is absent on 200
                    if not resp or status_code == 404 or (status_code == 200 and rule.matcher_pattern not in text):
                        matched = True
                elif rule.matcher_type == "status_code":
                    if resp and str(status_code) == rule.matcher_pattern:
                        matched = True
                elif rule.matcher_type == "header_contains":
                    if resp:
                        headers_flat = " ".join([f"{k}: {v}" for k, v in resp.headers.items()])
                        if rule.matcher_pattern.lower() in headers_flat.lower():
                            matched = True

                if matched:
                    findings.append(FindingBase(
                        title=f"{rule.name} on {host}",
                        description=f"{rule.description} Endpoint probed: {url}",
                        severity=rule.severity,
                        cvss_score=rule.cvss,
                        epss_score=0.045,
                        is_kev=False,
                        source="Custom Detection Rules Engine",
                        confidence="Confirmed",
                        status="Open",
                        evidence={"url": url, "rule_id": rule.id, "matcher": rule.matcher_type},
                        remediation_text=rule.remediation,
                        owasp_category=rule.category,
                        iso_control=rule.iso_control,
                        fix_hours_dev=rule.dev_hrs,
                        fix_hours_tester=rule.tester_hrs,
                        estimated_fix_cost=(rule.dev_hrs * 85.0) + (rule.tester_hrs * 65.0),
                        risk_score=rule.cvss * 8.0
                    ))
            except Exception:
                continue

    return findings
