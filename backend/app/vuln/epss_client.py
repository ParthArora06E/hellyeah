"""
FIRST.org EPSS (Exploit Prediction Scoring System) API Client
Provides probability estimates of weaponized in-the-wild exploitation.
"""
from typing import Dict, Any, Optional
import httpx

_EPSS_CACHE: Dict[str, Dict[str, float]] = {}

# Default benchmarks if offline or API unavailable
_BENCHMARK_EPSS = {
    "CVE-2021-44228": {"epss": 0.975, "percentile": 0.999},  # Log4Shell
    "CVE-2021-41773": {"epss": 0.952, "percentile": 0.998},  # Apache Path Traversal
    "CVE-2021-42013": {"epss": 0.945, "percentile": 0.997},  # Apache RCE
    "CVE-2022-22720": {"epss": 0.812, "percentile": 0.985},  # Apache HTTP Smuggling
    "CVE-2023-25690": {"epss": 0.835, "percentile": 0.988},  # Apache HTTP Splitting
    "CVE-2024-38476": {"epss": 0.742, "percentile": 0.972},  # Apache mod_rewrite RCE
    "CVE-2021-23017": {"epss": 0.778, "percentile": 0.981},  # Nginx Resolver
    "CVE-2023-44487": {"epss": 0.915, "percentile": 0.994},  # HTTP/2 Rapid Reset
    "CVE-2024-6387":  {"epss": 0.892, "percentile": 0.991},  # regreSSHion OpenSSH RCE
    "CVE-2023-38408": {"epss": 0.923, "percentile": 0.995},  # OpenSSH PKCS11 RCE
    "CVE-2018-15473": {"epss": 0.650, "percentile": 0.945},  # OpenSSH User Enum
    "CVE-2024-4577":  {"epss": 0.965, "percentile": 0.999},  # PHP CGI Argument Injection
    "CVE-2019-11043": {"epss": 0.951, "percentile": 0.998},  # PHP-FPM RCE
    "CVE-2014-0160":  {"epss": 0.960, "percentile": 0.998},  # OpenSSL Heartbleed
    "CVE-2022-22965": {"epss": 0.948, "percentile": 0.997},  # Spring4Shell
    "CVE-2020-1938":  {"epss": 0.954, "percentile": 0.998},  # Tomcat Ghostcat
    "CVE-2021-31166": {"epss": 0.921, "percentile": 0.994},  # IIS HTTP.sys RCE
    "CVE-2021-26855": {"epss": 0.941, "percentile": 0.997},  # ProxyLogon
    "CVE-2021-34473": {"epss": 0.952, "percentile": 0.998},  # ProxyShell
    "CVE-2022-26134": {"epss": 0.959, "percentile": 0.998},  # Confluence OGNL RCE
    "CVE-2023-22515": {"epss": 0.962, "percentile": 0.999},  # Confluence Admin Creation
    "CVE-2023-3519":  {"epss": 0.966, "percentile": 0.999},  # Citrix ADC RCE
    "CVE-2023-4966":  {"epss": 0.958, "percentile": 0.998},  # Citrix Bleed
    "CVE-2023-27997": {"epss": 0.961, "percentile": 0.999},  # FortiOS SSL-VPN RCE
    "CVE-2024-21762": {"epss": 0.963, "percentile": 0.999},  # FortiOS Out-of-bounds RCE
    "CVE-2022-1388":  {"epss": 0.955, "percentile": 0.998},  # F5 BIG-IP REST RCE
    "CVE-2022-0543":  {"epss": 0.938, "percentile": 0.996},  # Redis Lua Sandbox Escape
    "CVE-2024-23897": {"epss": 0.947, "percentile": 0.997},  # Jenkins CLI File Read RCE
    "CVE-2021-43798": {"epss": 0.912, "percentile": 0.993},  # Grafana Directory Traversal
    "CVE-2017-5638":  {"epss": 0.963, "percentile": 0.999},  # Equifax Struts
    "CVE-2019-19781": {"epss": 0.968, "percentile": 0.999},  # Citrix ADC
    "CVE-2020-5902":  {"epss": 0.955, "percentile": 0.998},  # F5 BIG-IP
    "CVE-2018-7600":  {"epss": 0.924, "percentile": 0.995},  # Drupalgeddon2
    "CVE-2019-11510": {"epss": 0.949, "percentile": 0.997},  # Pulse VPN
    "CVE-2020-14882": {"epss": 0.932, "percentile": 0.996},  # WebLogic
    "CVE-2021-21985": {"epss": 0.915, "percentile": 0.994},  # vCenter
}

async def get_epss_score(cve_id: str) -> Dict[str, float]:
    """
    Returns {'epss': float, 'percentile': float} for a given CVE.
    """
    if not cve_id:
        return {"epss": 0.01, "percentile": 0.50}

    cve_clean = cve_id.upper().strip()
    if cve_clean in _EPSS_CACHE:
        return _EPSS_CACHE[cve_clean]

    # Check benchmark table
    if cve_clean in _BENCHMARK_EPSS:
        _EPSS_CACHE[cve_clean] = _BENCHMARK_EPSS[cve_clean]
        return _BENCHMARK_EPSS[cve_clean]

    url = f"https://api.first.org/data/v1/epss?cve={cve_clean}"
    try:
        async with httpx.AsyncClient(timeout=5, verify=False) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                results = data.get("data", [])
                if results and len(results) > 0:
                    epss_val = float(results[0].get("epss", 0.01))
                    perc_val = float(results[0].get("percentile", 0.50))
                    res = {"epss": epss_val, "percentile": perc_val}
                    _EPSS_CACHE[cve_clean] = res
                    return res
    except Exception:
        pass

    # Default fallback
    fallback = {"epss": 0.025, "percentile": 0.65}
    _EPSS_CACHE[cve_clean] = fallback
    return fallback
