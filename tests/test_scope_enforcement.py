"""
Tests for Scope and Target Validation Gatekeeper
"""
from backend.app.core.scope import check_scan_permission, is_valid_target
from backend.app.db.session import SessionLocal

def test_scope_allowed_passive():
    with SessionLocal() as db:
        allowed, reason = check_scan_permission("target-site.com", "passive", db)
        assert allowed is True
        assert "approved for passive" in reason

def test_scope_allowed_active():
    with SessionLocal() as db:
        allowed, reason = check_scan_permission("target-site.com", "active", db)
        assert allowed is True
        assert "approved for active" in reason

def test_scope_refusal_invalid_format():
    with SessionLocal() as db:
        allowed, reason = check_scan_permission("invalid..domain!!!", "active", db)
        assert allowed is False
        assert "Invalid target format" in reason

def test_target_validation():
    assert is_valid_target("example.com") is True
    assert is_valid_target("api.sub.example.com") is True
    assert is_valid_target("192.168.1.1") is True
    assert is_valid_target("not a valid target") is False
