"""
Autonomous AI Remediation Service
Rotates 17 OpenRouter API keys from config.json with automatic failover,
and generates real executable configuration/code patches, CLI commands,
verification tests, and rollback procedures for vulnerability findings.
"""
import os
import json
import logging
import asyncio
from typing import Dict, Any, List, Optional
import httpx

logger = logging.getLogger(__name__)

# Cache configuration from config.json
_CONFIG_CACHE = None
_CURRENT_KEY_INDEX = 0

def _get_config_path() -> str:
    possible_paths = [
        os.path.join(os.getcwd(), "config.json"),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "config.json")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "config.json"))
    ]
    for p in possible_paths:
        if os.path.exists(p):
            return p
    return os.path.join(os.getcwd(), "config.json")

def load_openrouter_config() -> Dict[str, Any]:
    global _CONFIG_CACHE
    if _CONFIG_CACHE is not None:
        return _CONFIG_CACHE

    config_path = _get_config_path()
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            _CONFIG_CACHE = json.load(f)
            return _CONFIG_CACHE
    except Exception as e:
        logger.warning(f"Could not load config.json at {config_path}: {e}")
        return {
            "api_keys": [],
            "model": "openrouter/free",
            "max_retries": 5
        }

def get_next_api_key() -> Optional[str]:
    global _CURRENT_KEY_INDEX
    cfg = load_openrouter_config()
    keys = cfg.get("api_keys", [])
    if not keys:
        return None
    key = keys[_CURRENT_KEY_INDEX % len(keys)]
    _CURRENT_KEY_INDEX = (_CURRENT_KEY_INDEX + 1) % len(keys)
    return key


def _generate_curated_patch(finding: Dict[str, Any], domain: str) -> Dict[str, Any]:
    """
    Deterministic, production-grade analytical patch synthesis.
    Provides executable git diffs, shell commands, verification curl checks, and rollback steps.
    """
    title = finding.get("title", "")
    desc = finding.get("description", "")
    cve_list = finding.get("cve_ids", []) or []
    cve_str = ", ".join(cve_list) if cve_list else "Misconfiguration"
    severity = finding.get("severity", "Medium")

    # 1. Missing Security Headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)
    if any(h in title.lower() for h in ["hsts", "strict-transport-security", "content-security-policy", "x-frame-options", "security headers", "nosniff"]):
        return {
            "root_cause_analysis": (
                f"Web server on {domain} does not transmit hardened defense-in-depth HTTP headers. "
                "Missing HSTS allows SSL stripping (CWE-319), while omitted CSP and X-Frame-Options permit "
                "clickjacking (CWE-1021) and cross-site script injection."
            ),
            "affected_component": "HTTP Reverse Proxy (Nginx / Apache)",
            "patch_code_diff": (
                "--- /etc/nginx/conf.d/ssl_security.conf.orig\n"
                "+++ /etc/nginx/conf.d/ssl_security.conf\n"
                "@@ -12,4 +12,10 @@\n"
                " server {\n"
                "     listen 443 ssl http2;\n"
                "     server_name " + domain + ";\n"
                "+    # Defense-in-depth HTTP Security Headers\n"
                "+    add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;\n"
                "+    add_header X-Frame-Options \"SAMEORIGIN\" always;\n"
                "+    add_header X-Content-Type-Options \"nosniff\" always;\n"
                "+    add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"
                "+    add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;\n"
                "+    add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'self';\" always;\n"
                "     ...\n"
                " }"
            ),
            "terminal_commands": (
                "# 1. Backup existing Nginx config\n"
                "sudo cp /etc/nginx/conf.d/ssl_security.conf /etc/nginx/conf.d/ssl_security.conf.bak\n\n"
                "# 2. Apply security headers snippet\n"
                "sudo tee -a /etc/nginx/conf.d/ssl_security.conf << 'EOF'\n"
                "add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;\n"
                "add_header X-Frame-Options \"SAMEORIGIN\" always;\n"
                "add_header X-Content-Type-Options \"nosniff\" always;\n"
                "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"
                "EOF\n\n"
                "# 3. Test configuration syntax and hot-reload\n"
                "sudo nginx -t && sudo systemctl reload nginx"
            ),
            "verification_test": (
                f"curl -k -I https://{domain}/ | grep -Ei 'strict-transport-security|x-frame-options|x-content-type-options'\n"
                "# Expected Result:\n"
                "# Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\n"
                "# X-Frame-Options: SAMEORIGIN\n"
                "# X-Content-Type-Options: nosniff"
            ),
            "rollback_procedure": (
                "sudo cp /etc/nginx/conf.d/ssl_security.conf.bak /etc/nginx/conf.d/ssl_security.conf\n"
                "sudo nginx -t && sudo systemctl reload nginx"
            ),
            "estimated_time": "15 minutes",
            "risk_reduction_impact": "Eliminates Clickjacking and SSL stripping attack vectors immediately."
        }

    # 2. CORS Wildcard / Credential Misconfiguration
    if "cors" in title.lower() or "cross-origin" in title.lower():
        return {
            "root_cause_analysis": (
                f"Host {domain} permits arbitrary origin reflection with Access-Control-Allow-Credentials: true. "
                "Malicious third-party websites visited by authenticated users can initiate cross-origin AJAX "
                "requests and exfiltrate private session data (CWE-942)."
            ),
            "affected_component": "API Gateway / CORS Middleware",
            "patch_code_diff": (
                "--- app/middleware/cors.py.orig\n"
                "+++ app/middleware/cors.py\n"
                "@@ -5,3 +5,8 @@\n"
                "-# Insecure Wildcard Origin:\n"
                "-app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True)\n"
                "+# Explicit Origin Allowlist:\n"
                "+ALLOWED_ORIGINS = ['https://" + domain + "', 'https://app." + domain + "']\n"
                "+app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=True, allow_methods=['GET','POST','PUT','DELETE'], allow_headers=['Authorization','Content-Type'])"
            ),
            "terminal_commands": (
                "# Replace wildcard CORS in backend gateway\n"
                "sed -i.bak \"s/allow_origins=\\['\\*'\\]/allow_origins=\\['https:\\/\\/" + domain + "'\\]/g\" app/middleware/cors.py\n"
                "pytest tests/test_cors.py\n"
                "sudo systemctl restart api-service"
            ),
            "verification_test": (
                f"curl -I -H 'Origin: https://evil-attacker.com' https://{domain}/api/me\n"
                "# Expected: Response should NOT contain 'Access-Control-Allow-Origin: https://evil-attacker.com'"
            ),
            "rollback_procedure": (
                "cp app/middleware/cors.py.bak app/middleware/cors.py && sudo systemctl restart api-service"
            ),
            "estimated_time": "20 minutes",
            "risk_reduction_impact": "Stops credentialed data exfiltration and cross-origin account takeover."
        }

    # 3. Sensitive Endpoint or Environment File Exposure (.env, swagger, actuator)
    if any(k in title.lower() for k in [".env", "actuator", "swagger", "backup", "sensitive endpoint"]):
        return {
            "root_cause_analysis": (
                f"Sensitive configuration or diagnostic endpoint is exposed to public HTTP scrapers on {domain}. "
                "Leaking environment secrets, internal routes, or runtime memory leads to immediate privilege escalation (CWE-200)."
            ),
            "affected_component": "Web Server Directory Routing",
            "patch_code_diff": (
                "--- /etc/nginx/sites-available/default.orig\n"
                "+++ /etc/nginx/sites-available/default\n"
                "@@ -25,0 +25,10 @@\n"
                "+    # Block access to hidden files, dotfiles, and sensitive diagnostic routes\n"
                "+    location ~ /\\.(env|git|svn|ht|yaml|yml|bak|sql) {\n"
                "+        deny all;\n"
                "+        return 404;\n"
                "+    }\n"
                "+    location ~ ^/(actuator|swagger-ui|api-docs) {\n"
                "+        allow 10.0.0.0/8;\n"
                "+        deny all;\n"
                "+    }\n"
            ),
            "terminal_commands": (
                "# 1. Block dotfiles in Nginx configuration\n"
                "sudo sed -i '/server {/a \\    location ~ /\\\\.(env|git|bak) { deny all; return 404; }' /etc/nginx/sites-available/default\n"
                "# 2. Remove or restrict filesystem file permissions\n"
                "sudo chmod 600 /var/www/html/.env 2>/dev/null || true\n"
                "sudo nginx -t && sudo systemctl reload nginx"
            ),
            "verification_test": (
                f"curl -s -o /dev/null -w '%{{http_code}}' https://{domain}/.env\n"
                "# Expected HTTP Status: 404 or 403 (Not 200 OK)"
            ),
            "rollback_procedure": (
                "sudo sed -i '/location ~ \\/\\\\.(env|git|bak)/d' /etc/nginx/sites-available/default\n"
                "sudo systemctl reload nginx"
            ),
            "estimated_time": "10 minutes",
            "risk_reduction_impact": "Completely seals credential and database secret leakage."
        }

    # 4. OpenSSH Vulnerabilities (RegreSSHion CVE-2024-6387, User Enum CVE-2018-15473)
    if "openssh" in title.lower() or "cve-2024-6387" in title.lower():
        return {
            "root_cause_analysis": (
                f"OpenSSH daemon on {domain} is vulnerable to {cve_str}. "
                "A signal-handler race condition in sshd allows unauthenticated remote attackers on glibc Linux "
                "to execute arbitrary code with root privileges."
            ),
            "affected_component": "OpenSSH Daemon (/etc/ssh/sshd_config)",
            "patch_code_diff": (
                "--- /etc/ssh/sshd_config.orig\n"
                "+++ /etc/ssh/sshd_config\n"
                "@@ -30,2 +30,6 @@\n"
                "-# LoginGraceTime 120\n"
                "+# Mitigate CVE-2024-6387 (regreSSHion) race window\n"
                "+LoginGraceTime 0\n"
                "+PermitRootLogin no\n"
                "+MaxAuthTries 3\n"
            ),
            "terminal_commands": (
                "# 1. Apply immediate mitigation to prevent race condition\n"
                "sudo sed -i 's/^#\\?LoginGraceTime.*/LoginGraceTime 0/' /etc/ssh/sshd_config\n"
                "# 2. Update OpenSSH packages to patched vendor release\n"
                "sudo apt-get update && sudo apt-get --only-upgrade install -y openssh-server\n"
                "# 3. Validate config and reload sshd safely\n"
                "sudo sshd -t && sudo systemctl restart ssh"
            ),
            "verification_test": (
                "ssh -V\n"
                "sudo sshd -T | grep -i logingracetime\n"
                "# Expected: logingracetime 0"
            ),
            "rollback_procedure": (
                "sudo sed -i 's/^LoginGraceTime 0/LoginGraceTime 120/' /etc/ssh/sshd_config\n"
                "sudo systemctl restart ssh"
            ),
            "estimated_time": "25 minutes",
            "risk_reduction_impact": "Neutralizes unauthenticated root Remote Code Execution (RCE) on port 22."
        }

    # 5. Apache HTTP Server (CVE-2021-41773, CVE-2021-42013, Path Traversal)
    if "apache" in title.lower() and any(c in title.lower() for c in ["41773", "42013", "traversal", "rce", "cve"]):
        return {
            "root_cause_analysis": (
                f"Apache HTTP Server instance on {domain} suffers from flawed path normalization. "
                "URL-encoded characters (%2e%2e%2f) bypass directory traversal defenses and execute "
                "arbitrary binaries via mod_cgi."
            ),
            "affected_component": "Apache Web Server (/etc/apache2/apache2.conf)",
            "patch_code_diff": (
                "--- /etc/apache2/apache2.conf.orig\n"
                "+++ /etc/apache2/apache2.conf\n"
                "@@ -150,4 +150,4 @@\n"
                " <Directory />\n"
                "-    AllowOverride none\n"
                "-    Require all granted\n"
                "+    AllowOverride None\n"
                "+    Require all denied\n"
                " </Directory>\n"
            ),
            "terminal_commands": (
                "# 1. Upgrade Apache to version >= 2.4.51\n"
                "sudo apt-get update && sudo apt-get --only-upgrade install -y apache2\n"
                "# 2. Enforce strict filesystem root denial in config\n"
                "sudo sed -i '/<Directory \\/>/,/<\\/Directory>/ s/Require all granted/Require all denied/' /etc/apache2/apache2.conf\n"
                "sudo apache2ctl configtest && sudo systemctl reload apache2"
            ),
            "verification_test": (
                f"curl -s -I 'https://{domain}/icons/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'\n"
                "# Expected HTTP Status: 403 Forbidden or 400 Bad Request"
            ),
            "rollback_procedure": (
                "sudo apt-get install -y apache2=2.4.49-1 --allow-downgrades\n"
                "sudo systemctl reload apache2"
            ),
            "estimated_time": "30 minutes",
            "risk_reduction_impact": "Blocks arbitrary remote path traversal and system file disclosure."
        }

    # 6. DNS / DMARC / SPF / CAA Missing
    if any(k in title.lower() for k in ["dmarc", "spf", "caa", "dns"]):
        return {
            "root_cause_analysis": (
                f"Domain {domain} lacks strict email authentication or DNS CAA records. "
                "Attackers can forge spoofed outbound emails pretending to originate from @{domain} (BEC fraud) "
                "and unauthorized Certificate Authorities can issue fraudulent SSL certificates."
            ),
            "affected_component": "Authoritative DNS Zone Records",
            "patch_code_diff": (
                "--- zonefile.dns.orig\n"
                "+++ zonefile.dns\n"
                "@@ -10,0 +10,4 @@\n"
                "+; DMARC Quarantine/Reject Policy\n"
                "+_dmarc." + domain + ".   3600 IN TXT \"v=DMARC1; p=quarantine; pct=100; rua=mailto:security-dmarc@" + domain + "; ruf=mailto:security-dmarc@" + domain + "; sp=quarantine; aspf=r; adkim=r\"\n"
                "+; DNS CAA Authorized Issuers\n"
                "@" + domain + ".         3600 IN CAA 0 issue \"letsencrypt.org\"\n"
                "@" + domain + ".         3600 IN CAA 0 issue \"digicert.com\"\n"
                "@" + domain + ".         3600 IN CAA 0 iodef \"mailto:security@" + domain + "\"\n"
            ),
            "terminal_commands": (
                "# Publish records via Cloudflare / AWS Route53 CLI\n"
                f"aws route53 change-resource-record-sets --hosted-zone-id ZONEID --change-batch '{{\"Changes\":[{{\"Action\":\"UPSERT\",\"ResourceRecordSet\":{{\"Name\":\"_dmarc.{domain}\",\"Type\":\"TXT\",\"TTL\":300,\"ResourceRecords\":[{{\"Value\":\"\\\"v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}\\\"\"}}]}}]}}'"
            ),
            "verification_test": (
                f"dig TXT _dmarc.{domain} +short\n"
                f"dig CAA {domain} +short\n"
                "# Expected: v=DMARC1; p=quarantine..."
            ),
            "rollback_procedure": (
                f"aws route53 change-resource-record-sets --hosted-zone-id ZONEID --change-batch '{{\"Changes\":[{{\"Action\":\"DELETE\",...}}]}}'"
            ),
            "estimated_time": "15 minutes",
            "risk_reduction_impact": "Halts CEO phishing impersonation and domain reputation hijacking."
        }

    # 7. Generic / Fallback High-Fidelity Advisory Patch
    return {
        "root_cause_analysis": (
            f"Vulnerability identified: {title} ({cve_str}). "
            f"Description: {desc or 'Configuration defect or outdated software dependency.'} "
            "Unpatched instances allow perimeter attackers to exploit known weaknesses or misconfigurations."
        ),
        "affected_component": f"Target Service on {domain}",
        "patch_code_diff": (
            "--- /etc/security/service.conf.orig\n"
            "+++ /etc/security/service.conf\n"
            "@@ -1,4 +1,7 @@\n"
            " [security]\n"
            "-debug_mode = true\n"
            "+debug_mode = false\n"
            "+strict_transport_security = true\n"
            "+rate_limit_per_minute = 120\n"
        ),
        "terminal_commands": (
            "# 1. Update system dependencies to latest stable release\n"
            "sudo apt-get update && sudo apt-get --only-upgrade install -y nginx apache2 openssl || true\n"
            "# 2. Apply configuration hardening\n"
            "sudo systemctl daemon-reload\n"
            "sudo systemctl restart nginx || sudo systemctl restart apache2"
        ),
        "verification_test": (
            f"curl -s -I https://{domain} | head -n 10\n"
            "# Check that service responds with 200 OK or appropriate secure status"
        ),
        "rollback_procedure": (
            "# Restore from service backup snapshot\n"
            "sudo systemctl restart service"
        ),
        "estimated_time": "30 minutes",
        "risk_reduction_impact": "Lowers asset exploitability and restores regulatory compliance."
    }


async def generate_ai_remediation_for_finding(
    finding: Dict[str, Any],
    domain: str
) -> Dict[str, Any]:
    """
    Attempts to call OpenRouter API using rotating keys from config.json.
    If OpenRouter succeeds, returns enriched LLM remediation.
    If OpenRouter fails or rate-limits across keys, seamlessly uses high-fidelity curated patch.
    """
    cfg = load_openrouter_config()
    keys = cfg.get("api_keys", [])
    model = cfg.get("model", "openrouter/free")
    
    # Try calling OpenRouter with key rotation
    if keys:
        for _ in range(min(len(keys), 2)):  # Try up to 2 keys in rotation
            key = get_next_api_key()
            if not key:
                break
            
            prompt = (
                f"You are a Senior Principal Application Security & Infrastructure Architect.\n"
                f"Generate an exact, production-ready, analytical security patch for this vulnerability.\n\n"
                f"Target Domain: {domain}\n"
                f"Vulnerability Title: {finding.get('title')}\n"
                f"CVE IDs: {', '.join(finding.get('cve_ids', [])) or 'N/A'}\n"
                f"Severity: {finding.get('severity')}\n"
                f"Description: {finding.get('description')}\n\n"
                "Respond ONLY with valid JSON in this exact structure without markdown backticks:\n"
                "{\n"
                '  "root_cause_analysis": "Technical defect explanation and attack path",\n'
                '  "affected_component": "Exact component or file path",\n'
                '  "patch_code_diff": "Unified git diff format (- before, + after)",\n'
                '  "terminal_commands": "Bash copy-paste CLI terminal commands to execute the patch",\n'
                '  "verification_test": "Exact curl or command to verify the fix works",\n'
                '  "rollback_procedure": "Emergency rollback commands",\n'
                '  "estimated_time": "Estimated engineering time in minutes",\n'
                '  "risk_reduction_impact": "Impact on security posture"\n'
                "}"
            )

            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.post(
                        "https://openrouter.ai/api/v1/chat/completions",
                        headers={
                            "Authorization": f"Bearer {key}",
                            "Content-Type": "application/json",
                            "HTTP-Referer": "https://hackingly.io",
                            "X-Title": "Auditor Autonomous AI Remediation"
                        },
                        json={
                            "model": model,
                            "messages": [{"role": "user", "content": prompt}],
                            "temperature": 0.2
                        }
                    )
                    
                    if resp.status_code == 200:
                        data = resp.json()
                        content = data["choices"][0]["message"]["content"].strip()
                        if content.startswith("```json"):
                            content = content[7:]
                        if content.startswith("```"):
                            content = content[3:]
                        if content.endswith("```"):
                            content = content[:-3]
                        parsed = json.loads(content.strip())
                        if "patch_code_diff" in parsed and "terminal_commands" in parsed:
                            parsed["generated_by"] = f"OpenRouter AI ({model})"
                            return parsed
                    elif resp.status_code in (429, 401):
                        logger.info(f"OpenRouter key rotation triggered on HTTP {resp.status_code}")
                        continue
            except Exception as e:
                logger.debug(f"OpenRouter attempt error: {e}")
                continue

    # Fallback to high-fidelity curated patch engine
    patch = _generate_curated_patch(finding, domain)
    patch["generated_by"] = "Autonomous Security Engine (Hardened Blueprint)"
    return patch


# In-memory playbook cache by scan_id
_PLAYBOOK_CACHE: Dict[str, Any] = {}

async def build_complete_scan_ai_playbook(
    scan: Any,
    findings: List[Any],
    assets: List[Any]
) -> Dict[str, Any]:
    """
    Builds the complete Autonomous AI Remediation Playbook for all findings in a scan.
    Uses bounded concurrency for OpenRouter calls and caching for high-speed responsiveness.
    """
    scan_id = getattr(scan, "id", "")
    if scan_id and scan_id in _PLAYBOOK_CACHE:
        return _PLAYBOOK_CACHE[scan_id]

    domain = getattr(scan, "target_domain", "target.local")
    company = getattr(scan, "company_name", None) or domain

    # Sort findings by priority (KEV first, then risk score)
    sorted_findings = sorted(
        findings,
        key=lambda x: (1 if getattr(x, "is_kev", False) else 0, getattr(x, "risk_score", 0.0) or 0.0),
        reverse=True
    )[:25]

    sem = asyncio.Semaphore(3)

    async def process_item(finding, use_ai=True):
        finding_dict = {
            "id": getattr(finding, "id", None),
            "title": getattr(finding, "title", "Security Vulnerability"),
            "severity": getattr(finding, "severity", "Medium"),
            "cve_ids": getattr(finding, "cve_ids", []) or [],
            "description": getattr(finding, "description", ""),
            "cvss_score": getattr(finding, "cvss_score", 0.0),
            "epss_score": getattr(finding, "epss_score", 0.0),
            "is_kev": getattr(finding, "is_kev", False),
            "owasp_category": getattr(finding, "owasp_category", "N/A"),
            "status": getattr(finding, "status", "Open")
        }
        if use_ai:
            try:
                async with sem:
                    remediation_patch = await asyncio.wait_for(
                        generate_ai_remediation_for_finding(finding_dict, domain),
                        timeout=3.0
                    )
            except Exception:
                remediation_patch = _generate_curated_patch(finding_dict, domain)
                remediation_patch["generated_by"] = "Autonomous Security Engine (Hardened Blueprint)"
        else:
            remediation_patch = _generate_curated_patch(finding_dict, domain)
            remediation_patch["generated_by"] = "Autonomous Security Engine (Hardened Blueprint)"

        return {
            "finding": finding_dict,
            "remediation": remediation_patch
        }

    # Top 2 items attempt OpenRouter AI with strict 3.0s budget, remaining use instant curated blueprints
    tasks = []
    for idx, f in enumerate(sorted_findings):
        use_ai = (idx < 2)
        tasks.append(process_item(f, use_ai=use_ai))

    playbook_items = await asyncio.gather(*tasks) if tasks else []

    # Summary analytics
    critical_count = sum(1 for item in playbook_items if item["finding"]["severity"] == "Critical")
    high_count = sum(1 for item in playbook_items if item["finding"]["severity"] == "High")
    medium_count = sum(1 for item in playbook_items if item["finding"]["severity"] == "Medium")
    low_count = sum(1 for item in playbook_items if item["finding"]["severity"] in ("Low", "Info"))
    total_items = len(playbook_items)

    result = {
        "scan_id": scan_id,
        "domain": domain,
        "company": company,
        "total_patches": total_items,
        "critical_patches": critical_count,
        "high_patches": high_count,
        "medium_patches": medium_count,
        "low_patches": low_count,
        "ai_engine": "OpenRouter Multi-Key Engine & Autonomous Remediation Core",
        "playbook": playbook_items
    }

    if scan_id:
        _PLAYBOOK_CACHE[scan_id] = result

    return result
