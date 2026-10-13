"""
CPE 2.3 Synthesis and Software Version Detection Engine
Converts banner tokens and detected technologies into official CPE 2.3 identifiers.
"""
import re
from typing import Optional, Dict, Any, Tuple

# Common software dictionary mapping keywords to (part, vendor, product)
# part: 'a' for application, 'o' for operating system, 'h' for hardware
SOFTWARE_MAP = {
    "apache": ("a", "apache", "http_server"),
    "http_server": ("a", "apache", "http_server"),
    "nginx": ("a", "f5", "nginx"),
    "openssh": ("a", "openbsd", "openssh"),
    "openssl": ("a", "openssl", "openssl"),
    "php": ("a", "php", "php"),
    "wordpress": ("a", "wordpress", "wordpress"),
    "tomcat": ("a", "apache", "tomcat"),
    "log4j": ("a", "apache", "log4j"),
    "mysql": ("a", "oracle", "mysql"),
    "mariadb": ("a", "mariadb", "mariadb"),
    "postgresql": ("a", "postgresql", "postgresql"),
    "redis": ("a", "redis", "redis"),
    "microsoft-iis": ("a", "microsoft", "iis"),
    "iis": ("a", "microsoft", "iis"),
    "exchange": ("a", "microsoft", "exchange_server"),
    "spring": ("a", "vmware", "spring_framework"),
    "spring-boot": ("a", "vmware", "spring_boot"),
    "fortios": ("o", "fortinet", "fortios"),
    "citrix": ("a", "citrix", "netscaler_adc"),
    "netscaler": ("a", "citrix", "netscaler_adc"),
    "confluence": ("a", "atlassian", "confluence"),
    "jira": ("a", "atlassian", "jira"),
    "big-ip": ("a", "f5", "big-ip_access_policy_manager"),
    "elasticsearch": ("a", "elastic", "elasticsearch"),
    "kibana": ("a", "elastic", "kibana"),
    "drupal": ("a", "drupal", "drupal"),
    "joomla": ("a", "joomla", "joomla"),
    "grafana": ("a", "grafana", "grafana"),
    "jenkins": ("a", "jenkins", "jenkins"),
    "gitlab": ("a", "gitlab", "gitlab"),
    "node.js": ("a", "nodejs", "node.js"),
    "express": ("a", "expressjs", "express"),
    "haproxy": ("a", "haproxy", "haproxy"),
    "envoy": ("a", "envoyproxy", "envoy"),
    "traefik": ("a", "traefik", "traefik"),
    "caddy": ("a", "caddyserver", "caddy"),
    "lighttpd": ("a", "lighttpd", "lighttpd"),
}

VERSION_REGEX = re.compile(r"([0-9]+(?:\.[0-9]+)+(?:[-_a-zA-Z0-9]+)?)")

def detect_software_and_version(banner_or_header: str) -> Optional[Dict[str, str]]:
    """
    Parses a raw server header or banner string into vendor, product, and version.
    Example: 'Apache/2.4.49 (Unix) OpenSSL/1.1.1' -> Apache 2.4.49
    """
    if not banner_or_header:
        return None

    cleaned = banner_or_header.strip()
    lowered = cleaned.lower()

    for key, (part, vendor, product) in SOFTWARE_MAP.items():
        if key in lowered:
            # Look for version near key
            # pattern: key[/ :v]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)
            pattern = rf"{key}[/ :v\-]*([0-9]+(?:\.[0-9]+)+(?:[a-zA-Z0-9\.\-]*)?)"
            match = re.search(pattern, lowered)
            version = match.group(1) if match else None
            
            # Fallback general version regex if not directly beside
            if not version:
                gen_match = VERSION_REGEX.search(cleaned)
                if gen_match:
                    version = gen_match.group(1)

            cpe_string = build_cpe_23(part, vendor, product, version or "*")
            return {
                "vendor": vendor,
                "product": product,
                "version": version or "unknown",
                "part": part,
                "cpe": cpe_string,
                "raw_banner": cleaned
            }

    return None

def build_cpe_23(part: str, vendor: str, product: str, version: str) -> str:
    """
    Formats tokens into official CPE 2.3 URI standard.
    Example: cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
    """
    clean_v = version.strip() if version and version != "unknown" else "*"
    return f"cpe:2.3:{part}:{vendor}:{product}:{clean_v}:*:*:*:*:*:*:*"
