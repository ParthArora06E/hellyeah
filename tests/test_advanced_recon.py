import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

from backend.app.schemas.schemas import AssetBase
from backend.app.recon.modules.ssl_cert_recon import SSLCertReconModule
from backend.app.recon.modules.asn_network_recon import ASNNetworkReconModule
from backend.app.recon.modules.domain_name_recon import DomainNameReconModule
from backend.app.recon.adapter.context import ScanContext
from backend.app.db.session import SessionLocal
from backend.app.db.models import Scan, Asset


@pytest.fixture
def test_context():
    db = SessionLocal()
    scan_id = "test-recon-scan-id"
    scan = Scan(
        id=scan_id,
        target_domain="example.com",
        mode="passive"
    )
    db.add(scan)
    db.commit()

    logs = []
    def log_cb(level, msg, prog=None, step=None):
        logs.append({"level": level, "msg": msg})

    ctx = ScanContext(scan_id, "example.com", "passive", db, log_cb)
    yield ctx

    # Cleanup
    db.query(Asset).filter(Asset.scan_id == scan_id).delete()
    db.query(Scan).filter(Scan.id == scan_id).delete()
    db.commit()
    db.close()


@pytest.mark.asyncio
async def test_ssl_cert_recon_module(test_context):
    mod = SSLCertReconModule()
    assert mod.meta.name == "ssl_cert_recon"
    assert mod.meta.is_passive is True

    # Mock live TLS socket and CT feeds
    with patch.object(mod, "_inspect_live_tls_certificate", return_value={"mail.example.com", "api.example.com"}), \
         patch.object(mod, "_query_certificate_transparency_feeds", return_value={"admin.example.com", "vpn.example.com"}):
        
        results = await mod.run("example.com", test_context)
        assert len(results) == 4
        values = {r.value for r in results}
        assert "mail.example.com" in values
        assert "api.example.com" in values
        assert "admin.example.com" in values
        assert "vpn.example.com" in values

        # Verify assets saved in context
        assert len(test_context.discovered_assets) == 4
        first_asset = test_context.discovered_assets[0]
        assert "tls_cert" in first_asset.tags


@pytest.mark.asyncio
async def test_asn_network_recon_module(test_context):
    mod = ASNNetworkReconModule()
    assert mod.meta.name == "asn_network_recon"

    # Pre-populate an asset with IP
    test_context.record_asset(
        AssetBase(
            type="subdomain",
            value="api.example.com",
            ip_address="104.21.45.67",
            source="DNS"
        )
    )

    with patch.object(mod, "_resolve_target_ips", return_value={"104.21.45.67"}), \
         patch.object(mod, "_lookup_ip_asn_details", return_value={
             "asn": "AS13335",
             "as_name": "Cloudflare, Inc.",
             "cidr": "104.21.0.0/20",
             "country": "US",
             "city": "San Francisco"
         }), \
         patch.object(mod, "_reverse_dns_lookup", return_value=["edge-node1.example.com"]):

        results = await mod.run("example.com", test_context)
        assert len(results) >= 1
        
        # Check IP asset
        ip_assets = [r for r in results if r.type == "ip"]
        assert len(ip_assets) >= 1
        assert ip_assets[0].asn == "AS13335"
        assert ip_assets[0].raw_metadata["asn_name"] == "Cloudflare, Inc."

        # Check PTR hostname
        ptr_assets = [r for r in results if r.value == "edge-node1.example.com"]
        assert len(ptr_assets) == 1
        assert "ptr_record" in ptr_assets[0].tags


@pytest.mark.asyncio
async def test_domain_name_recon_module(test_context):
    mod = DomainNameReconModule()
    assert mod.meta.name == "domain_name_recon"

    with patch.object(mod, "_probe_subdomain_wordlist", return_value={
        "www.example.com": ["93.184.216.34"],
        "api.example.com": ["93.184.216.35"],
        "portal.example.com": ["93.184.216.36"]
    }), \
    patch.object(mod, "_probe_srv_records", return_value={"sip.example.com"}), \
    patch.object(mod, "_test_zone_transfer", return_value=[]):

        results = await mod.run("example.com", test_context)
        assert len(results) >= 4
        values = {r.value for r in results}
        assert "www.example.com" in values
        assert "api.example.com" in values
        assert "portal.example.com" in values
        assert "sip.example.com" in values
