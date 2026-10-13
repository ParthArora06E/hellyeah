"""
Tests for CPE 2.3 Mapping and CVE Correlation Engine
"""
import pytest
from backend.app.vuln.cpe_mapper import detect_software_and_version, build_cpe_23
from backend.app.vuln.cve_engine import lookup_cves_for_software
from backend.app.vuln.kev_catalog import is_cisa_kev
from backend.app.vuln.epss_client import get_epss_score

def test_cpe_builder():
    cpe = build_cpe_23("a", "apache", "http_server", "2.4.49")
    assert cpe == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"

def test_detect_software_apache():
    info = detect_software_and_version("Apache/2.4.49 (Unix) OpenSSL/1.1.1")
    assert info is not None
    assert info["vendor"] == "apache"
    assert info["product"] == "http_server"
    assert info["version"] == "2.4.49"
    assert "cpe:2.3:a:apache:http_server:2.4.49" in info["cpe"]

def test_detect_software_nginx():
    info = detect_software_and_version("nginx/1.18.0")
    assert info is not None
    assert info["product"] == "nginx"
    assert info["version"] == "1.18.0"

@pytest.mark.asyncio
async def test_cve_correlation_apache_rce():
    cpe = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    vulns = await lookup_cves_for_software("apache", "http_server", "2.4.49", cpe)
    assert len(vulns) > 0
    cve_ids = [c for v in vulns for c in v.cve_ids]
    assert "CVE-2021-41773" in cve_ids
    # CVE-2021-41773 is on CISA KEV catalog
    matching = next(v for v in vulns if "CVE-2021-41773" in v.cve_ids)
    assert matching.is_kev is True
    assert matching.severity == "Critical"
    assert matching.epss_score > 0.5

@pytest.mark.asyncio
async def test_epss_and_kev():
    kev = is_cisa_kev("CVE-2021-44228")
    assert kev is True
    epss = await get_epss_score("CVE-2021-44228")
    assert epss["epss"] > 0.9

def test_version_range_evaluation():
    from backend.app.vuln.cve_engine import is_version_affected
    # Less-than checks
    assert is_version_affected("2.4.41", "< 2.4.51") is True
    assert is_version_affected("2.4.52", "< 2.4.51") is False
    # Less-than-or-equal checks
    assert is_version_affected("1.20.0", "<= 1.20.0") is True
    assert is_version_affected("1.21.0", "<= 1.20.0") is False
    # Range checks
    assert is_version_affected("8.9p1", "8.5p1..9.7p1") is True
    assert is_version_affected("9.8p1", "8.5p1..9.7p1") is False
    # Wildcards
    assert is_version_affected("*", "< 2.4.51") is True

@pytest.mark.asyncio
async def test_openssh_regresshion():
    cpe = "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"
    vulns = await lookup_cves_for_software("openbsd", "openssh", "8.9p1", cpe)
    assert len(vulns) > 0
    cve_ids = [c for v in vulns for c in v.cve_ids]
    assert "CVE-2024-6387" in cve_ids
    regresshion = next(v for v in vulns if "CVE-2024-6387" in v.cve_ids)
    assert regresshion.is_kev is True
    assert regresshion.severity == "Critical"
    assert "regreSSHion" in regresshion.title

@pytest.mark.asyncio
async def test_nginx_http2_rapid_reset():
    cpe = "cpe:2.3:a:f5:nginx:1.20.0:*:*:*:*:*:*:*"
    vulns = await lookup_cves_for_software("f5", "nginx", "1.20.0", cpe)
    cve_ids = [c for v in vulns for c in v.cve_ids]
    assert "CVE-2023-44487" in cve_ids  # Rapid Reset
    assert "CVE-2021-23017" in cve_ids  # 1-byte heap overwrite

@pytest.mark.asyncio
async def test_spring_and_php_cves():
    # Spring4Shell
    vulns_spring = await lookup_cves_for_software("vmware", "spring_framework", "5.3.10", "cpe:2.3:a:vmware:spring_framework:5.3.10:*:*:*:*:*:*:*")
    cve_ids_spring = [c for v in vulns_spring for c in v.cve_ids]
    assert "CVE-2022-22965" in cve_ids_spring

    # PHP CGI RCE
    vulns_php = await lookup_cves_for_software("php", "php", "8.2.10", "cpe:2.3:a:php:php:8.2.10:*:*:*:*:*:*:*")
    cve_ids_php = [c for v in vulns_php for c in v.cve_ids]
    assert "CVE-2024-4577" in cve_ids_php

