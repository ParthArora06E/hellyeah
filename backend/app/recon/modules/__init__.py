"""
Reconnaissance Modules Registry
Exports all passive OSINT discovery modules and safe active reconnaissance modules.
"""
# Passive OSINT Modules
from .ssl_cert_recon import SSLCertReconModule
from .crtsh import CrtshModule
from .domain_name_recon import DomainNameReconModule
from .dns_resolver import DNSResolverModule
from .whois_lookup import WhoisModule
from .asn_network_recon import ASNNetworkReconModule
from .reverse_ip_recon import ReverseIPReconModule
from .alienvault_otx import AlienVaultOTXModule
from .securitytrails import SecurityTrailsModule
from .shodan_host import ShodanHostModule
from .wayback_archive import WaybackModule
from .urlscan_lookup import URLScanModule
from .virustotal import VirusTotalModule
from .cms_detector import CMSDetectorModule

# Active Reconnaissance Modules
from .active_port_scanner import ActivePortScannerModule
from .http_method_prober import HTTPMethodProberModule
from .dns_axfr_prober import DNSAXFRModule
from .waf_detector import WAFDetectorModule
from .cors_active_prober import CORSActiveProberModule
from .web_metadata_crawler import WebMetadataCrawlerModule
from .virtual_host_prober import VirtualHostProberModule
from .active_tls_prober import ActiveTLSProberModule
from .active_takeover_prober import ActiveTakeoverProberModule

PASSIVE_MODULES = [
    SSLCertReconModule,
    CrtshModule,
    DomainNameReconModule,
    DNSResolverModule,
    WhoisModule,
    ASNNetworkReconModule,
    ReverseIPReconModule,
    AlienVaultOTXModule,
    SecurityTrailsModule,
    ShodanHostModule,
    WaybackModule,
    URLScanModule,
    VirusTotalModule,
]

ACTIVE_RECON_MODULES = [
    ActivePortScannerModule,
    HTTPMethodProberModule,
    DNSAXFRModule,
    WAFDetectorModule,
    CORSActiveProberModule,
    WebMetadataCrawlerModule,
    VirtualHostProberModule,
    ActiveTLSProberModule,
    ActiveTakeoverProberModule,
]

__all__ = [
    "SSLCertReconModule",
    "CrtshModule",
    "DomainNameReconModule",
    "DNSResolverModule",
    "WhoisModule",
    "ASNNetworkReconModule",
    "ReverseIPReconModule",
    "AlienVaultOTXModule",
    "SecurityTrailsModule",
    "ShodanHostModule",
    "WaybackModule",
    "URLScanModule",
    "VirusTotalModule",
    "CMSDetectorModule",
    "ActivePortScannerModule",
    "HTTPMethodProberModule",
    "DNSAXFRModule",
    "WAFDetectorModule",
    "CORSActiveProberModule",
    "WebMetadataCrawlerModule",
    "VirtualHostProberModule",
    "ActiveTLSProberModule",
    "ActiveTakeoverProberModule",
    "PASSIVE_MODULES",
    "ACTIVE_RECON_MODULES",
]
