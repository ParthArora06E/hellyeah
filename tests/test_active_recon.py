"""
Comprehensive Test Suite for Active Reconnaissance Modules
Validates metadata, execution logic, asset discovery, and finding emission
for all active recon methods:
1. ActivePortScannerModule (TCP ports & banner grabbing)
2. HTTPMethodProberModule (OPTIONS, TRACE, PUT, WebDAV)
3. DNSAXFRModule (AXFR Zone Transfer & open resolver)
4. WAFDetectorModule (WAF & reverse proxy fingerprinting)
5. CORSActiveProberModule (Origin reflection & credentials)
6. WebMetadataCrawlerModule (robots.txt, sitemaps, security.txt)
7. VirtualHostProberModule (Host header injection & internal vhosts)
8. ActiveTLSProberModule (TLS 1.0/1.1 deprecation & live SANs)
9. ActiveTakeoverProberModule (Dangling CNAME takeover)
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from backend.app.recon.modules import (
    ActivePortScannerModule,
    HTTPMethodProberModule,
    DNSAXFRModule,
    WAFDetectorModule,
    CORSActiveProberModule,
    WebMetadataCrawlerModule,
    VirtualHostProberModule,
    ActiveTLSProberModule,
    ActiveTakeoverProberModule,
    ACTIVE_RECON_MODULES
)
from backend.app.schemas.schemas import AssetBase, FindingBase


class MockScanContext:
    def __init__(self, target="example.com"):
        self.scan_id = "test-scan-123"
        self.target_domain = target
        self.mode = "active"
        self.discovered_assets = []
        self.discovered_findings = []
        self.logs = []
        self.audits = []
        self.http = MagicMock()

    def emit_log(self, level, message, progress=None, step=None):
        self.logs.append((level, message, progress, step))

    def log_audit(self, action, target, details=None, status_code=None):
        self.audits.append((action, target, details, status_code))

    def record_asset(self, asset):
        self.discovered_assets.append(asset)
        return asset

    def record_finding(self, finding, asset_id=None):
        self.discovered_findings.append(finding)
        return finding


def test_active_modules_registry():
    """Ensure all 9 active recon modules are properly registered and flagged as active."""
    assert len(ACTIVE_RECON_MODULES) == 9
    for mod_cls in ACTIVE_RECON_MODULES:
        mod = mod_cls()
        assert mod.meta.is_passive is False
        assert mod.meta.category == "active"
        assert len(mod.meta.name) > 0


@pytest.mark.asyncio
async def test_waf_detector_cloudflare():
    """Validates active WAF detection when Cloudflare headers are returned."""
    ctx = MockScanContext("target.com")
    mock_resp = MagicMock()
    mock_resp.headers = {
        "server": "cloudflare",
        "cf-ray": "84892789123-IAD",
        "cf-cache-status": "HIT"
    }
    ctx.http.get = AsyncMock(return_value=mock_resp)

    mod = WAFDetectorModule()
    results = await mod.run("target.com", ctx)

    assert any(a.type == "subdomain" and "Cloudflare WAF" in a.technologies for a in ctx.discovered_assets)
    assert any("Cloudflare WAF" in f.title for f in ctx.discovered_findings)


@pytest.mark.asyncio
async def test_cors_active_prober_critical():
    """Validates critical finding emitted when arbitrary origin is reflected with credentials."""
    ctx = MockScanContext("api.target.com")
    
    mock_resp = MagicMock()
    mock_resp.headers = {
        "access-control-allow-origin": "https://evil-attacker.com",
        "access-control-allow-credentials": "true"
    }
    ctx.http.request = AsyncMock(return_value=mock_resp)

    mod = CORSActiveProberModule()
    results = await mod.run("api.target.com", ctx)

    assert any(f.severity == "Critical" and "Arbitrary Origin Reflected" in f.title for f in ctx.discovered_findings)


@pytest.mark.asyncio
async def test_web_metadata_crawler_robots():
    """Validates that robots.txt disallow directives harvest endpoints and flag sensitive paths."""
    ctx = MockScanContext("app.target.com")
    
    robots_content = "User-agent: *\nDisallow: /admin\nDisallow: /staging/portal\nDisallow: /public-feed\n"
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = robots_content
    ctx.http.get = AsyncMock(return_value=mock_resp)

    mod = WebMetadataCrawlerModule()
    results = await mod.run("app.target.com", ctx)

    # Discovered endpoints
    endpoint_vals = [a.value for a in ctx.discovered_assets if a.type == "endpoint"]
    assert any("/admin" in ep for ep in endpoint_vals)
    assert any("Sensitive Administrative Paths Disclosed" in f.title for f in ctx.discovered_findings)


@pytest.mark.asyncio
async def test_http_method_prober_trace():
    """Validates HTTP TRACE vulnerability detection."""
    ctx = MockScanContext("target.com")

    # Options response
    resp_opt = MagicMock()
    resp_opt.headers = {"allow": "GET, POST, OPTIONS, TRACE"}
    
    # Trace response reflecting probe header
    resp_trace = MagicMock()
    resp_trace.status_code = 200
    resp_trace.text = "TRACE / HTTP/1.1\r\nX-Auditor-Trace-Probe: active_recon_123\r\n\r\n"

    async def mock_req(method, url, **kwargs):
        if method == "OPTIONS":
            return resp_opt
        elif method == "TRACE":
            return resp_trace
        return MagicMock(status_code=405)

    ctx.http.request = AsyncMock(side_effect=mock_req)

    mod = HTTPMethodProberModule()
    results = await mod.run("target.com", ctx)

    assert any("Cross-Site Tracing" in f.title for f in ctx.discovered_findings)


@pytest.mark.asyncio
async def test_active_port_scanner_redis_exposure():
    """Validates that open port 6379 emits Redis asset and Critical finding."""
    ctx = MockScanContext("redis-cache.target.com")

    mod = ActivePortScannerModule()
    # Mock _probe_port to simulate open Redis port
    async def mock_probe(host, port, service_name):
        if port == 6379:
            return {"port": 6379, "service": "Redis", "banner": "+PONG"}
        return None

    mod._probe_port = AsyncMock(side_effect=mock_probe)

    results = await mod.run("redis-cache.target.com", ctx)

    assert any(a.type == "service" and 6379 in a.ports for a in ctx.discovered_assets)
    assert any(f.severity == "Critical" and "Redis" in f.title for f in ctx.discovered_findings)
