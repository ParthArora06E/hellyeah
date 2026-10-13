"""
Comprehensive Unit Tests for:
1. User Authentication, PBKDF2 Password Hashing & HS256 Token Verification
2. Default Seed Accounts: Pro (pro@hackingly.io) & Standard (user@hackingly.io)
3. Role Gating & Paywall: Standard user gets 403 Forbidden on Playbook & PDF download
4. Pro User full access to AI Remediation Playbook and Analytical PDF export
5. OpenRouter 17-Key rotation from config.json and high-fidelity fallback blueprints
"""
import pytest
from fastapi.testclient import TestClient
from datetime import datetime, timezone
import json

from backend.app.main import app
from backend.app.db.session import SessionLocal, Base, engine
from backend.app.db.models import User, Scan, Finding, Asset
from backend.app.services.auth_service import (
    hash_password,
    verify_password,
    create_access_token,
    verify_token,
    seed_default_users
)
from backend.app.services.ai_remediation_service import (
    load_openrouter_config,
    get_next_api_key,
    _generate_curated_patch
)
from backend.app.services.ai_patch_playbook_pdf import generate_ai_patch_playbook_pdf

client = TestClient(app)

@pytest.fixture(scope="module", autouse=True)
def setup_db_and_mock_data():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    seed_default_users(db)

    # Create a mock scan for testing playbook endpoints
    mock_scan = db.query(Scan).filter(Scan.id == "test-auth-scan-001").first()
    if not mock_scan:
        mock_scan = Scan(
            id="test-auth-scan-001",
            target_domain="secure-test.hackingly.io",
            company_name="Secure Test Corp",
            status="completed",
            risk_score=78.5
        )
        db.add(mock_scan)

        # Add mock findings
        f1 = Finding(
            scan_id=mock_scan.id,
            title="Missing Strict-Transport-Security (HSTS) Header",
            severity="High",
            cvss_score=7.5,
            cve_ids=[],
            description="The remote web server does not enforce HSTS response headers."
        )
        f2 = Finding(
            scan_id=mock_scan.id,
            title="OpenSSH regreSSHion Signal Handler RCE (CVE-2024-6387)",
            severity="Critical",
            cvss_score=9.8,
            cve_ids=["CVE-2024-6387"],
            is_kev=True,
            description="Signal handler race condition in sshd allows root RCE."
        )
        db.add_all([f1, f2])
        db.commit()

    db.close()
    yield

def test_password_hashing_and_verification():
    raw_pass = "Pro@123456"
    hashed = hash_password(raw_pass)
    assert hashed.startswith("pbkdf2_sha256$")
    assert verify_password(raw_pass, hashed) is True
    assert verify_password("IncorrectPassword", hashed) is False

def test_token_creation_and_payload_verification():
    payload = {"sub": "pro@hackingly.io", "role": "pro", "user_id": 1}
    token = create_access_token(payload, expires_delta_seconds=3600)
    assert token is not None
    assert len(token.split(".")) == 3

    decoded = verify_token(token)
    assert decoded is not None
    assert decoded["sub"] == "pro@hackingly.io"
    assert decoded["role"] == "pro"

def test_demo_accounts_endpoint():
    resp = client.get("/api/auth/demo-accounts")
    assert resp.status_code == 200
    accounts = resp.json()
    assert len(accounts) >= 2
    emails = [a["email"] for a in accounts]
    assert "pro@hackingly.io" in emails
    assert "user@hackingly.io" in emails

def test_pro_user_login():
    resp = client.post("/api/auth/login", json={
        "email": "pro@hackingly.io",
        "password": "Pro@123456"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["user"]["role"] == "pro"
    assert data["user"]["email"] == "pro@hackingly.io"

def test_standard_user_login():
    resp = client.post("/api/auth/login", json={
        "email": "user@hackingly.io",
        "password": "User@123456"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["user"]["role"] == "standard"

def test_invalid_login_rejected():
    resp = client.post("/api/auth/login", json={
        "email": "pro@hackingly.io",
        "password": "WrongPassword999"
    })
    assert resp.status_code == 401

def test_switch_account_endpoint():
    resp = client.post("/api/auth/switch-account", json={"role": "pro"})
    assert resp.status_code == 200
    assert resp.json()["user"]["role"] == "pro"

    resp_std = client.post("/api/auth/switch-account", json={"role": "standard"})
    assert resp_std.status_code == 200
    assert resp_std.json()["user"]["role"] == "standard"

def test_standard_user_pro_paywall_enforcement():
    """
    Standard user must receive 403 Forbidden when requesting full AI Playbook or PDF.
    """
    # Get standard user token
    login_resp = client.post("/api/auth/switch-account", json={"role": "standard"})
    std_token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {std_token}"}

    # 1. AI Playbook JSON endpoint must return 403
    resp_playbook = client.get("/api/scans/test-auth-scan-001/ai-playbook", headers=headers)
    assert resp_playbook.status_code == 403
    assert resp_playbook.json()["detail"]["error"] == "PRO_SUBSCRIPTION_REQUIRED"

    # 2. AI Playbook PDF endpoint must return 403
    resp_pdf = client.get("/api/scans/test-auth-scan-001/ai-playbook/pdf", headers=headers)
    assert resp_pdf.status_code == 403
    assert resp_pdf.json()["detail"]["error"] == "PRO_SUBSCRIPTION_REQUIRED"

def test_public_preview_teaser_accessible_by_anyone():
    """
    Public teaser returns summary and non-sensitive sample for standard users.
    """
    resp = client.get("/api/scans/test-auth-scan-001/ai-playbook/preview")
    assert resp.status_code == 200
    data = resp.json()
    assert data["pro_locked"] is True
    assert "sample_teaser_patch" in data
    assert data["total_available_patches"] >= 2

def test_pro_user_ai_playbook_access():
    """
    Pro user gets full access to executable code diffs and CLI commands.
    """
    login_resp = client.post("/api/auth/switch-account", json={"role": "pro"})
    pro_token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {pro_token}"}

    resp = client.get("/api/scans/test-auth-scan-001/ai-playbook", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["domain"] == "secure-test.hackingly.io"
    assert len(data["playbook"]) >= 2
    
    # Check that executable code diff and terminal commands exist
    first_item = data["playbook"][0]
    rem = first_item["remediation"]
    assert "patch_code_diff" in rem
    assert "terminal_commands" in rem
    assert "verification_test" in rem
    assert "rollback_procedure" in rem

def test_pro_user_ai_playbook_pdf_download():
    """
    Pro user successfully downloads the analytical PDF blueprint.
    """
    login_resp = client.post("/api/auth/switch-account", json={"role": "pro"})
    pro_token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {pro_token}"}

    resp = client.get("/api/scans/test-auth-scan-001/ai-playbook/pdf", headers=headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    # PDF Magic Bytes: %PDF
    assert resp.content.startswith(b"%PDF")
    assert len(resp.content) > 5000  # Non-trivial PDF size

def test_openrouter_config_and_key_rotation():
    """
    Verifies that config.json keys are loaded and rotation operates correctly.
    """
    cfg = load_openrouter_config()
    keys = cfg.get("api_keys", [])
    assert len(keys) == 17  # 17 keys from user config.json
    
    k1 = get_next_api_key()
    k2 = get_next_api_key()
    assert k1 is not None and k2 is not None
    # Key index advances
    assert k1 != k2 or len(keys) == 1

def test_curated_patch_generator_fidelity():
    """
    Verifies high-fidelity analytical templates for different vulnerability types.
    """
    # 1. HSTS patch
    hsts_finding = {"title": "Missing HSTS Header", "severity": "High", "cve_ids": []}
    p1 = _generate_curated_patch(hsts_finding, "app.domain.com")
    assert "add_header Strict-Transport-Security" in p1["patch_code_diff"]
    assert "nginx -t" in p1["terminal_commands"]

    # 2. OpenSSH regreSSHion patch
    ssh_finding = {"title": "OpenSSH regreSSHion RCE (CVE-2024-6387)", "severity": "Critical", "cve_ids": ["CVE-2024-6387"]}
    p2 = _generate_curated_patch(ssh_finding, "ssh.domain.com")
    assert "LoginGraceTime 0" in p2["patch_code_diff"]
    assert "openssh-server" in p2["terminal_commands"]
