"""
Tests for Drop-in Plugin Dynamic Discovery and Execution
"""
from backend.app.recon.adapter.plugin_loader import discover_plugins

def test_plugin_discovery():
    plugins = discover_plugins()
    assert len(plugins) >= 2
    # Check that our shipped plugins are discovered
    assert "cloud_bucket_checker" in plugins or "cloud_bucket_checker_plugin" in plugins
    assert "ssl_tls_grade_plugin" in plugins
