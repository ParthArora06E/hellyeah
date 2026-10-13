"""
SSRF (Server-Side Request Forgery) Protection Module
Validates outbound webhook and notification URLs to prevent access
to loopback, private networks, cloud metadata services, and link-local ranges.
"""
import socket
import ipaddress
from urllib.parse import urlparse

# Private, loopback, and link-local IPv4/IPv6 networks to block
DISALLOWED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback IPv4
    ipaddress.ip_network("10.0.0.0/8"),       # RFC 1918 Private
    ipaddress.ip_network("172.16.0.0/12"),    # RFC 1918 Private
    ipaddress.ip_network("192.168.0.0/16"),   # RFC 1918 Private
    ipaddress.ip_network("169.254.0.0/16"),   # Link-Local / Cloud Metadata (AWS/GCP/Azure 169.254.169.254)
    ipaddress.ip_network("0.0.0.0/8"),        # Current network
    ipaddress.ip_network("224.0.0.0/4"),      # Multicast
    ipaddress.ip_network("240.0.0.0/4"),      # Reserved
    ipaddress.ip_network("::1/128"),          # Loopback IPv6
    ipaddress.ip_network("fc00::/7"),         # Unique Local IPv6
    ipaddress.ip_network("fe80::/10"),        # Link-Local IPv6
]

def validate_webhook_url(url: str, allow_local_for_testing: bool = False) -> str:
    """
    Validates that a URL is a safe external endpoint.
    Raises ValueError if URL is invalid, non-HTTP/HTTPS, or resolves to an internal network.
    """
    if not url or not isinstance(url, str):
        raise ValueError("Webhook URL cannot be empty.")

    clean_url = url.strip()
    parsed = urlparse(clean_url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Disallowed URL scheme '{parsed.scheme}'. Only http and https are allowed.")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL must have a valid hostname.")

    # Block common local domain names directly
    lower_host = hostname.lower()
    if lower_host in ("localhost", "127.0.0.1", "0.0.0.0", "metadata.google.internal") and not allow_local_for_testing:
        raise ValueError(f"SSRF Protection: Destination '{hostname}' is a reserved internal host.")

    # Resolve hostname to IP addresses
    try:
        resolved_ips = socket.getaddrinfo(hostname, parsed.port or 443)
    except Exception as e:
        raise ValueError(f"Could not resolve hostname '{hostname}': {e}")

    for item in resolved_ips:
        ip_str = item[4][0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        if not allow_local_for_testing:
            for net in DISALLOWED_NETWORKS:
                if ip_obj in net:
                    raise ValueError(
                        f"SSRF Protection: Webhook destination resolves to restricted IP range ({ip_str})."
                    )

    return clean_url
