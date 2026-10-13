"""
CISA Known Exploited Vulnerabilities (KEV) Catalog Service
Downloads and caches CISA's official feed to identify in-the-wild weaponized exploits.
"""
import time
import httpx
from typing import Set, Dict, Any, Optional

CISA_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# In-memory cache for CISA KEV CVE set and metadata
_KEV_SET: Set[str] = set()
_KEV_METADATA: Dict[str, Dict[str, Any]] = {}
_LAST_KEV_FETCH: float = 0.0
_CACHE_TTL = 86400  # 24 hours

# Seed common critical KEVs as instant fallback in offline/demo mode
_SEED_KEV_CVES = {
    "CVE-2021-44228": {"name": "Apache Log4j Remote Code Execution", "dateAdded": "2021-12-10"},
    "CVE-2021-41773": {"name": "Apache HTTP Server Path Traversal and RCE", "dateAdded": "2021-11-03"},
    "CVE-2021-42013": {"name": "Apache HTTP Server Path Traversal and RCE", "dateAdded": "2021-11-03"},
    "CVE-2023-44487": {"name": "HTTP/2 Rapid Reset Distributed Denial of Service", "dateAdded": "2023-10-10"},
    "CVE-2024-6387":  {"name": "OpenSSH regreSSHion Signal Handler RCE", "dateAdded": "2024-07-01"},
    "CVE-2023-38408": {"name": "OpenSSH PKCS#11 Provider Remote Code Execution", "dateAdded": "2023-07-20"},
    "CVE-2024-4577":  {"name": "PHP CGI Argument Injection Remote Code Execution", "dateAdded": "2024-06-12"},
    "CVE-2019-11043": {"name": "PHP-FPM Remote Code Execution", "dateAdded": "2021-11-03"},
    "CVE-2022-22965": {"name": "Spring Framework DataBinder RCE (Spring4Shell)", "dateAdded": "2022-04-04"},
    "CVE-2020-1938":  {"name": "Apache Tomcat AJP Protocol File Read / Inclusion (Ghostcat)", "dateAdded": "2021-11-03"},
    "CVE-2021-31166": {"name": "Microsoft HTTP Protocol Stack RCE", "dateAdded": "2021-11-03"},
    "CVE-2021-26855": {"name": "Microsoft Exchange Server SSRF (ProxyLogon)", "dateAdded": "2021-11-03"},
    "CVE-2021-34473": {"name": "Microsoft Exchange Remote Code Execution (ProxyShell)", "dateAdded": "2021-11-03"},
    "CVE-2022-26134": {"name": "Atlassian Confluence OGNL Injection RCE", "dateAdded": "2022-06-02"},
    "CVE-2023-22515": {"name": "Atlassian Confluence Broken Access Control Privilege Escalation", "dateAdded": "2023-10-04"},
    "CVE-2023-3519":  {"name": "Citrix ADC / NetScaler Unauthenticated Remote Code Execution", "dateAdded": "2023-07-19"},
    "CVE-2023-4966":  {"name": "Citrix NetScaler ADC Sensitive Information Disclosure (Citrix Bleed)", "dateAdded": "2023-10-18"},
    "CVE-2023-27997": {"name": "Fortinet FortiOS SSL-VPN Heap Buffer Overflow RCE", "dateAdded": "2023-06-13"},
    "CVE-2024-21762": {"name": "Fortinet FortiOS SSL-VPN Out-of-Bounds Write RCE", "dateAdded": "2024-02-09"},
    "CVE-2022-1388":  {"name": "F5 BIG-IP iControl REST Authentication Bypass RCE", "dateAdded": "2022-05-10"},
    "CVE-2020-5902":  {"name": "F5 BIG-IP Traffic Management Interface RCE", "dateAdded": "2021-11-03"},
    "CVE-2022-0543":  {"name": "Redis Lua Sandbox Escape Remote Code Execution", "dateAdded": "2022-03-25"},
    "CVE-2024-23897": {"name": "Jenkins CLI Arbitrary File Read leading to RCE", "dateAdded": "2024-01-29"},
    "CVE-2021-43798": {"name": "Grafana Directory Traversal Arbitrary File Read", "dateAdded": "2021-12-08"},
    "CVE-2017-5638":  {"name": "Apache Struts 2 Content-Type Parser RCE", "dateAdded": "2021-11-03"},
    "CVE-2019-19781": {"name": "Citrix ADC Directory Traversal", "dateAdded": "2021-11-03"},
    "CVE-2018-7600":  {"name": "Drupal Drupalgeddon2 RCE", "dateAdded": "2021-11-03"},
    "CVE-2019-11510": {"name": "Pulse Connect Secure Arbitrary File Read", "dateAdded": "2021-11-03"},
    "CVE-2020-14882": {"name": "Oracle WebLogic Server Console RCE", "dateAdded": "2021-11-03"},
    "CVE-2021-21985": {"name": "VMware vCenter Server RCE", "dateAdded": "2021-11-03"}
}

async def ensure_kev_catalog_loaded() -> Set[str]:
    """
    Ensures CISA KEV catalog is populated, fetching live feed if TTL expired.
    Falls back gracefully to offline catalog on network failure.
    """
    global _KEV_SET, _KEV_METADATA, _LAST_KEV_FETCH
    now = time.time()

    if _KEV_SET and (now - _LAST_KEV_FETCH < _CACHE_TTL):
        return _KEV_SET

    # Initialize with seeds first
    _KEV_SET.update(_SEED_KEV_CVES.keys())
    _KEV_METADATA.update(_SEED_KEV_CVES)

    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            resp = await client.get(CISA_KEV_FEED_URL)
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                for v in vulns:
                    cve_id = v.get("cveID")
                    if cve_id:
                        _KEV_SET.add(cve_id)
                        _KEV_METADATA[cve_id] = {
                            "name": v.get("vulnerabilityName"),
                            "dateAdded": v.get("dateAdded"),
                            "requiredAction": v.get("requiredAction")
                        }
                _LAST_KEV_FETCH = now
    except Exception:
        # Graceful fallback: maintain seeded KEV list
        pass

    return _KEV_SET

def is_cisa_kev(cve_id: str) -> bool:
    """
    Synchronously checks if a CVE is in the known CISA KEV catalog.
    """
    if not cve_id:
        return False
    return cve_id.upper().strip() in _KEV_SET or cve_id.upper().strip() in _SEED_KEV_CVES

def get_kev_details(cve_id: str) -> Optional[Dict[str, Any]]:
    return _KEV_METADATA.get(cve_id.upper().strip()) or _SEED_KEV_CVES.get(cve_id.upper().strip())
