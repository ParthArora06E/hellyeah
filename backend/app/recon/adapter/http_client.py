"""
Async HTTP Client with TTL Caching, Rate Limiting, Retries, and Audit Logging
"""
import asyncio
import time
from typing import Optional, Dict, Any, Tuple, Union
import httpx
from ...core.config import settings
from ...core.rotator import rotator

class AsyncHttpClient:
    def __init__(self, timeout: Optional[int] = None, rate_limit: Optional[float] = None):
        self.timeout = timeout or settings.REQUEST_TIMEOUT
        self.rate_limit_delay = 1.0 / (rate_limit or settings.RATE_LIMIT_PER_SEC)
        self.last_request_time = 0.0
        self._cache: Dict[str, Tuple[float, Any, int]] = {}
        self.default_headers = {
            "User-Agent": settings.USER_AGENT,
            "Accept": "application/json, text/html, */*"
        }

    async def _throttle(self):
        now = time.monotonic()
        elapsed = now - self.last_request_time
        if elapsed < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - elapsed)
        self.last_request_time = time.monotonic()

    async def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        ttl_seconds: int = 300,
        retries: int = 2
    ) -> Optional[httpx.Response]:
        cache_key = f"{url}?{sorted(params.items()) if params else ''}"
        now = time.time()
        
        # Check cache
        if ttl_seconds > 0 and cache_key in self._cache:
            cached_time, cached_resp, status = self._cache[cache_key]
            if now - cached_time < ttl_seconds:
                return cached_resp

        rotator_headers = rotator.get_headers() if rotator.is_enabled else {}
        merged_headers = {**self.default_headers, **rotator_headers, **(headers or {})}
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        is_osint_api = any(domain in host for domain in (
            "virustotal.com",
            "securitytrails.com",
            "alienvault.com",
            "shodan.io",
            "urlscan.io",
            "crt.sh",
            "nist.gov",
            "circl.lu",
            "osv.dev",
            "archive.org"
        ))

        effective_proxy = None if is_osint_api else proxy_url

        for attempt in range(retries + 1):
            try:
                await self._throttle()
                client_kwargs = {
                    "timeout": self.timeout,
                    "verify": False,
                    "follow_redirects": True
                }
                # Use proxy only for target asset probing, never for authenticated OSINT APIs
                if effective_proxy and attempt == 0:
                    client_kwargs["proxy"] = effective_proxy
                elif effective_proxy and attempt > 0:
                    # On retry, fallback to direct connection in case proxy failed
                    pass

                async with httpx.AsyncClient(**client_kwargs) as client:
                    resp = await client.get(url, headers=merged_headers, params=params)
                    if resp.status_code in (429, 502, 503, 504) and attempt < retries:
                        await asyncio.sleep(1.0 * (2 ** attempt))
                        continue
                    
                    if ttl_seconds > 0 and resp.status_code == 200:
                        self._cache[cache_key] = (now, resp, resp.status_code)
                    return resp
            except Exception:
                if attempt < retries:
                    # Switch to direct on retry
                    effective_proxy = None
                    await asyncio.sleep(0.5 * (2 ** attempt))
                else:
                    return None
        return None

    async def get_json(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        ttl_seconds: int = 300
    ) -> Optional[Any]:
        resp = await self.get(url, headers=headers, params=params, ttl_seconds=ttl_seconds)
        if resp and resp.status_code == 200:
            try:
                return resp.json()
            except Exception:
                return None
        return None

    async def head(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None
    ) -> Optional[httpx.Response]:
        rotator_headers = rotator.get_headers() if rotator.is_enabled else {}
        merged_headers = {**self.default_headers, **rotator_headers, **(headers or {})}
        proxy_url = rotator.get_current_proxy()
        try:
            await self._throttle()
            client_kwargs = {
                "timeout": self.timeout,
                "verify": False,
                "follow_redirects": True
            }
            if proxy_url:
                client_kwargs["proxy"] = proxy_url
            async with httpx.AsyncClient(**client_kwargs) as client:
                return await client.head(url, headers=merged_headers)
        except Exception:
            return None

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        content: Optional[Union[str, bytes]] = None,
        follow_redirects: bool = True,
        retries: int = 1
    ) -> Optional[httpx.Response]:
        """
        Executes an arbitrary HTTP request (OPTIONS, TRACE, PUT, DELETE, POST, etc.)
        with rate-limiting, proxy rotation, and timeout.
        """
        rotator_headers = rotator.get_headers() if rotator.is_enabled else {}
        merged_headers = {**self.default_headers, **rotator_headers, **(headers or {})}
        proxy_url = rotator.get_current_proxy()

        for attempt in range(retries + 1):
            try:
                await self._throttle()
                client_kwargs = {
                    "timeout": self.timeout,
                    "verify": False,
                    "follow_redirects": follow_redirects
                }
                if proxy_url:
                    client_kwargs["proxy"] = proxy_url

                async with httpx.AsyncClient(**client_kwargs) as client:
                    resp = await client.request(
                        method=method.upper(),
                        url=url,
                        headers=merged_headers,
                        content=content
                    )
                    return resp
            except Exception:
                if attempt < retries:
                    await asyncio.sleep(0.5)
                else:
                    return None
        return None

