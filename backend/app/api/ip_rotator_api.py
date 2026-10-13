"""
IP Rotator API Router
Provides high-speed IP generation, ranking, and real-time rotating IP/header endpoints.
Directly replaces the need for standalone Flask/FastAPI IP rotator services.
"""
from fastapi import APIRouter, Query, HTTPException, Body
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import time

from ..core.rotator import rotator
from ..core.fast_json_transfer import (
    generate_random_ip_int,
    int_to_ip,
    generate_batch_ips,
    rank_and_transfer_ips
)

router = APIRouter(tags=["IP Rotator & Obfuscation"])


class RotatorConfigPayload(BaseModel):
    interval: Optional[float] = None
    enabled: Optional[bool] = None
    mode: Optional[str] = None
    proxies: Optional[List[str]] = None


@router.get("/rotator/get-ip")
@router.get("/get-ip", include_in_schema=True)
def get_ip():
    """
    Returns the currently rotated IP address.
    Matches the Flask /get-ip API format.
    """
    ip = rotator.get_current_ip()
    current_meta = None
    if rotator.mode == "pool" and getattr(rotator, "proxy_items", None) and rotator._pool_index < len(rotator.proxy_items):
        current_meta = rotator.proxy_items[rotator._pool_index]

    res = {
        "success": True,
        "ip": ip,
        "rotation_interval": rotator.rotation_interval
    }
    if current_meta:
        res["country"] = current_meta.get("country", "")
        res["protocol"] = current_meta.get("protocol", "")
        res["port"] = current_meta.get("port", "")
        res["proxy_url"] = current_meta.get("proxy_url", "")
        res["anonymity"] = current_meta.get("anonymity", "")
        res["isp"] = current_meta.get("isp", "")
        res["latency_ms"] = current_meta.get("latency_ms", 0)
    return res


@router.get("/rotator/headers")
@router.get("/headers", include_in_schema=True)
def get_headers():
    """
    Returns current client spoofing / proxy headers (X-Forwarded-For, X-Real-IP, etc.).
    Matches the Flask /headers API format.
    """
    return rotator.get_headers()


@router.get("/rotator/generate-ips")
@router.get("/generate-ips", include_in_schema=True)
def generate_ips(count: int = Query(10000, description="Number of IPs to generate")):
    """
    Generates IPs extremely fast (within milliseconds) and returns them in memory.
    Matches the Fast Random IP Generator API format.
    """
    start_time = time.perf_counter()
    raw_ips = [generate_random_ip_int() for _ in range(count)]
    ips_strings = [int_to_ip(ip) for ip in raw_ips]
    duration_ms = (time.perf_counter() - start_time) * 1000

    return {
        "success": True,
        "count": count,
        "duration_ms": round(duration_ms, 4),
        "ips": ips_strings
    }


@router.get("/rotator/rank-and-transfer")
@router.get("/rank-and-transfer", include_in_schema=True)
def rank_and_transfer(count: int = Query(10000, description="Number of IPs to generate, rank, and save")):
    """
    Generates IPs, ranks them by public legitimacy/class diversity, and immediately saves them to ranked_ips.json.
    Matches the Fast Random IP Generator API format.
    """
    metrics = rank_and_transfer_ips(count)
    # Also load the generated pool into the live rotator
    rotator.load_ranked_file()
    
    return {
        "message": f"Successfully generated, ranked, and saved {count} IPs to ranked_ips.json",
        "metrics": metrics
    }


@router.get("/rotator/stats")
def get_rotator_stats():
    """Returns detailed real-time statistics of the active IP Rotator."""
    return rotator.get_stats()


@router.post("/rotator/rotate-now")
def rotate_now():
    """Forces immediate rotation to a new IP."""
    new_ip = rotator.rotate_now()
    return {
        "success": True,
        "new_ip": new_ip,
        "headers": rotator.get_headers()
    }


@router.post("/rotator/toggle")
def toggle_rotator(enabled: Optional[bool] = Query(None)):
    """Toggles or sets the IP Rotator enabled status."""
    is_active = rotator.toggle(enabled)
    return {
        "success": True,
        "enabled": is_active,
        "current_ip": rotator.get_current_ip()
    }


@router.post("/rotator/config")
def update_rotator_config(payload: RotatorConfigPayload):
    """Updates rotator interval, mode, proxies, or enabled state."""
    if payload.interval is not None:
        rotator.set_interval(payload.interval)
    if payload.enabled is not None:
        rotator.toggle(payload.enabled)
    if payload.mode in ("generated", "pool"):
        rotator.mode = payload.mode
    if payload.proxies is not None:
        rotator.set_proxies(payload.proxies)

    return rotator.get_stats()


@router.get("/rotator/pool")
@router.get("/api/rotator/pool", include_in_schema=True)
def get_rotator_pool():
    """
    Returns the loaded proxy/IP pool with rich metadata (country, protocol, latency).
    """
    items = getattr(rotator, "proxy_items", [])
    countries = {}
    protocols = {}
    for it in items:
        c = it.get("country") or "Unknown"
        countries[c] = countries.get(c, 0) + 1
        p = it.get("protocol") or "http"
        protocols[p] = protocols.get(p, 0) + 1

    count = len(items) if items else len(rotator.ip_pool)
    return {
        "success": True,
        "total_count": count,
        "total_items": count,
        "mode": rotator.mode,
        "active_ip": rotator.get_current_ip(),
        "active_proxy": rotator.get_current_proxy(),
        "countries_summary": countries,
        "country_breakdown": countries,
        "protocols_summary": protocols,
        "protocol_breakdown": protocols,
        "items": items
    }


@router.post("/rotator/reload-pool")
@router.post("/api/rotator/reload-pool", include_in_schema=True)
def reload_user_pool():
    """Reloads the user proxy pool from output/ranked_ips.json."""
    loaded = rotator.load_ranked_file()
    return {
        "success": loaded,
        "pool_size": len(rotator.ip_pool),
        "proxies_count": len(rotator.proxies),
        "stats": rotator.get_stats()
    }


@router.post("/rotator/load-user-pool")
@router.post("/api/rotator/load-user-pool", include_in_schema=True)
def load_user_proxy_pool():
    """Switches the rotator to use the curated 100 User Proxies."""
    loaded = rotator.load_user_pool()
    return {
        "success": loaded,
        "message": "Loaded 100 curated user proxies into active IP Rotator",
        "loaded_ips_count": len(rotator.ip_pool),
        "pool_size": len(rotator.ip_pool),
        "proxies_count": len(rotator.proxies),
        "mode": rotator.mode,
        "current_ip": rotator.get_current_ip(),
        "stats": rotator.get_stats()
    }
