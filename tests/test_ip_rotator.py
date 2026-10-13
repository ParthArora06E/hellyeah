"""
Unit tests for Fast IP Generation, Ranking, and the Integrated IP Rotator Engine
"""
import pytest
import os
import time
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.fast_json_transfer import (
    generate_random_ip_int,
    int_to_ip,
    ip_to_int,
    is_public_ip_int,
    generate_random_public_ip_int,
    generate_batch_ips,
    rank_and_transfer_ips
)
from backend.app.core.rotator import IPRotator, rotator


@pytest.fixture
def client():
    return TestClient(app)


def test_ip_integer_conversion():
    test_ip = "192.0.2.1"
    val = ip_to_int(test_ip)
    assert isinstance(val, int)
    assert int_to_ip(val) == test_ip

    raw_val = generate_random_ip_int()
    assert 0 <= raw_val <= 0xFFFFFFFF
    ip_str = int_to_ip(raw_val)
    assert len(ip_str.split(".")) == 4


def test_public_ip_filtering():
    # Private / bogon IPs should return False
    assert is_public_ip_int(ip_to_int("10.0.0.1")) is False
    assert is_public_ip_int(ip_to_int("127.0.0.1")) is False
    assert is_public_ip_int(ip_to_int("192.168.1.1")) is False
    assert is_public_ip_int(ip_to_int("172.16.5.10")) is False
    assert is_public_ip_int(ip_to_int("169.254.1.1")) is False
    assert is_public_ip_int(ip_to_int("224.0.0.1")) is False  # Multicast
    assert is_public_ip_int(ip_to_int("0.0.0.0")) is False

    # Real public IPs should return True
    assert is_public_ip_int(ip_to_int("8.8.8.8")) is True
    assert is_public_ip_int(ip_to_int("1.1.1.1")) is True
    assert is_public_ip_int(ip_to_int("104.21.45.67")) is True


def test_fast_batch_ip_generation():
    count = 1000
    t0 = time.perf_counter()
    ips = generate_batch_ips(count=count, only_public=True)
    duration_ms = (time.perf_counter() - t0) * 1000

    assert len(ips) == count
    # Check that all are valid public IPs
    for ip in ips[:50]:
        assert is_public_ip_int(ip_to_int(ip)) is True
    assert duration_ms < 500  # 1000 IPs generated in well under 500ms


def test_rank_and_transfer_ips(tmp_path):
    target_file = str(tmp_path / "test_ranked_ips.json")
    metrics = rank_and_transfer_ips(count=100, target_path=target_file)
    
    assert metrics["status"] == "success"
    assert metrics["saved_count"] >= 100
    assert os.path.exists(target_file)
    assert len(metrics["sample"]) == 5


def test_ip_rotator_engine():
    rot = IPRotator(rotation_interval=0.1, enabled=True)
    first_ip = rot.get_current_ip()
    assert first_ip is not None
    assert len(first_ip.split(".")) == 4

    headers = rot.get_headers()
    assert headers["X-Forwarded-For"] == first_ip
    assert headers["X-Real-IP"] == first_ip
    assert headers["CF-Connecting-IP"] == first_ip
    assert headers["Client-IP"] == first_ip

    # Wait for interval (0.1s) and check rotation
    time.sleep(0.12)
    next_ip = rot.get_current_ip()
    assert rot.rotations_count >= 1

    # Force rotation
    forced_ip = rot.rotate_now()
    assert rot.rotations_count >= 2


def test_rotator_endpoints_at_root(client):
    # Test Flask compatibility endpoints at root
    resp_ip = client.get("/get-ip")
    assert resp_ip.status_code == 200
    data_ip = resp_ip.json()
    assert data_ip["success"] is True
    assert "ip" in data_ip
    assert data_ip["rotation_interval"] == 0.6

    resp_headers = client.get("/headers")
    assert resp_headers.status_code == 200
    data_headers = resp_headers.json()
    assert "X-Forwarded-For" in data_headers
    assert "X-Real-IP" in data_headers

    # Test fast generator endpoints at root
    resp_gen = client.get("/generate-ips?count=50")
    assert resp_gen.status_code == 200
    data_gen = resp_gen.json()
    assert data_gen["count"] == 50
    assert len(data_gen["ips"]) == 50

    resp_rank = client.get("/rank-and-transfer?count=50")
    assert resp_rank.status_code == 200
    data_rank = resp_rank.json()
    assert "metrics" in data_rank


def test_rotator_api_prefix_endpoints(client):
    # Test prefixed endpoints under /api/
    resp = client.get("/api/rotator/get-ip")
    assert resp.status_code == 200
    assert resp.json()["success"] is True

    resp_stats = client.get("/api/rotator/stats")
    assert resp_stats.status_code == 200
    stats = resp_stats.json()
    assert stats["enabled"] is True
    assert stats["rotation_interval"] == 0.6

    # Test rotate-now
    resp_rot = client.post("/api/rotator/rotate-now")
    assert resp_rot.status_code == 200
    assert "new_ip" in resp_rot.json()

    # Test toggle
    resp_toggle = client.post("/api/rotator/toggle?enabled=false")
    assert resp_toggle.status_code == 200
    assert resp_toggle.json()["enabled"] is False

    # Re-enable
    client.post("/api/rotator/toggle?enabled=true")


def test_user_proxy_pool_and_meta(client):
    # Ensure rotator has the 100 user proxies loaded
    resp_pool = client.get("/api/rotator/pool")
    assert resp_pool.status_code == 200
    pool_data = resp_pool.json()
    assert pool_data["total_items"] == 100
    assert len(pool_data["items"]) == 100
    assert "protocol_breakdown" in pool_data
    assert "country_breakdown" in pool_data

    # Verify first proxy matches user's data (103.43.17.157, CN, https)
    first_item = pool_data["items"][0]
    assert first_item["ip"] == "103.43.17.157"
    assert first_item["country"] == "CN"
    assert first_item["protocol"] == "https"
    assert first_item["port"] == 11111

    # Verify get-ip returns enriched metadata
    resp_ip = client.get("/api/rotator/get-ip")
    assert resp_ip.status_code == 200
    ip_data = resp_ip.json()
    assert "country" in ip_data
    assert "protocol" in ip_data
    assert "port" in ip_data
    assert "proxy_url" in ip_data


def test_user_pool_reload_endpoint(client):
    # Test reloading the 100 user proxies via API
    resp_reload = client.post("/api/rotator/load-user-pool")
    assert resp_reload.status_code == 200
    reload_data = resp_reload.json()
    assert reload_data["success"] is True
    assert reload_data["loaded_ips_count"] == 100
    assert reload_data["mode"] == "pool"
    assert reload_data["current_ip"] == "103.43.17.157"

