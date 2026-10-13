"""
Core IP Rotator & Obfuscation Engine
Maintains an active rotating IP identity and header injection mapping.
Rotates on a configurable micro-interval (default 0.6s) or on demand.
"""
import time
import os
import json
from typing import List, Dict, Any, Optional

from .fast_json_transfer import (
    generate_random_public_ip_int,
    int_to_ip,
    generate_batch_ips,
    rank_and_transfer_ips
)


class IPRotator:
    def __init__(self, rotation_interval: float = 0.6, enabled: bool = True):
        self.rotation_interval: float = rotation_interval
        self.is_enabled: bool = enabled
        self.rotations_count: int = 0
        self.last_rotation_time: float = time.monotonic()
        
        # Initial IP
        self._current_ip: str = int_to_ip(generate_random_public_ip_int())
        
        # IP Pool management
        self.ip_pool: List[str] = []
        self._pool_index: int = 0
        self.mode: str = "generated"  # "generated" or "pool"
        
        # Optional HTTP/SOCKS proxy rotation
        self.proxies: List[str] = []
        self._proxy_index: int = 0
        self.proxy_items: List[Dict[str, Any]] = []

        # Auto-load curated user proxy pool on initialization
        if not self.load_user_pool():
            self.load_ranked_file()

    def load_user_pool(self) -> bool:
        """Loads the curated user proxy pool (100 verified proxies) into the active rotator."""
        try:
            from .user_proxies_data import get_user_proxies, get_user_ips, get_user_proxy_urls
            items = get_user_proxies()
            ips = get_user_ips()
            proxies = get_user_proxy_urls()
            if ips:
                self.load_pool(ips)
                self.set_proxies(proxies)
                self.proxy_items = items
                return True
        except Exception:
            pass
        return False

    def rotate_now(self) -> str:
        """Forces an immediate rotation to a new IP."""
        if self.mode == "pool" and self.ip_pool:
            self._pool_index = (self._pool_index + 1) % len(self.ip_pool)
            self._current_ip = self.ip_pool[self._pool_index]
            if self.proxies:
                self._proxy_index = self._pool_index % len(self.proxies)
        else:
            self._current_ip = int_to_ip(generate_random_public_ip_int())
        
        self.last_rotation_time = time.monotonic()
        self.rotations_count += 1
        return self._current_ip

    def get_current_ip(self) -> str:
        """
        Returns the currently active IP. Automatically rotates if rotation_interval has elapsed.
        """
        now = time.monotonic()
        if now - self.last_rotation_time >= self.rotation_interval:
            self.rotate_now()
        return self._current_ip

    def get_headers(self) -> Dict[str, str]:
        """
        Generates standard spoofed client IP headers for outbound HTTP requests.
        Bypasses standard client-IP rate limiting, WAF blocks, and source logging.
        """
        if not self.is_enabled:
            return {}

        ip = self.get_current_ip()
        return {
            "X-Forwarded-For": ip,
            "X-Real-IP": ip,
            "CF-Connecting-IP": ip,
            "Client-IP": ip,
            "True-Client-IP": ip,
            "X-Client-IP": ip,
            "X-Originating-IP": ip
        }

    def set_interval(self, seconds: float):
        """Sets the rotation frequency in seconds (e.g. 0.6s)."""
        self.rotation_interval = max(0.01, float(seconds))

    def toggle(self, enabled: Optional[bool] = None) -> bool:
        """Toggles or explicitly sets enabled status."""
        if enabled is not None:
            self.is_enabled = bool(enabled)
        else:
            self.is_enabled = not self.is_enabled
        return self.is_enabled

    def load_pool(self, ips: List[str]):
        """Sets a pre-generated pool of IPs."""
        valid = [ip.strip() for ip in ips if ip.strip()]
        if valid:
            self.ip_pool = valid
            self.mode = "pool"
            self._pool_index = 0
            self._current_ip = self.ip_pool[0]

    def load_ranked_file(self, target_path: Optional[str] = None) -> bool:
        """Loads IPs and proxies from a saved ranked_ips.json file."""
        if not target_path:
            out_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "output")
            target_path = os.path.join(out_dir, "ranked_ips.json")
            if not os.path.exists(target_path):
                target_path = os.path.join(os.getcwd(), "ranked_ips.json")

        if os.path.exists(target_path):
            try:
                with open(target_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    ips = data.get("ips", [])
                    proxies = data.get("proxies", [])
                    items = data.get("items", [])
                    if ips:
                        self.load_pool(ips)
                    if proxies:
                        self.set_proxies(proxies)
                    if items:
                        self.proxy_items = items
                    return True
            except Exception:
                pass
        return False

    def set_proxies(self, proxies: List[str]):
        """Sets an optional list of proxy URLs (http:// or socks5://)."""
        self.proxies = [p.strip() for p in proxies if p.strip()]
        self._proxy_index = 0

    def get_current_proxy(self) -> Optional[str]:
        """Returns the current proxy URL if configured, cycling with rotation."""
        if not self.proxies or not self.is_enabled:
            return None
        return self.proxies[self._proxy_index % len(self.proxies)]

    def get_stats(self) -> Dict[str, Any]:
        """Returns real-time status and operational metrics."""
        current_meta = None
        if self.mode == "pool" and self.proxy_items and self._pool_index < len(self.proxy_items):
            current_meta = self.proxy_items[self._pool_index]

        return {
            "success": True,
            "enabled": self.is_enabled,
            "ip": self.get_current_ip(),
            "rotation_interval": self.rotation_interval,
            "rotations_completed": self.rotations_count,
            "mode": self.mode,
            "pool_size": len(self.ip_pool),
            "proxies_count": len(self.proxies),
            "current_proxy": self.get_current_proxy(),
            "current_meta": current_meta,
            "items_preview": self.proxy_items[:25] if self.proxy_items else [],
            "uptime_seconds": round(time.monotonic(), 1)
        }


# Global application singleton
rotator = IPRotator(rotation_interval=0.6, enabled=True)
