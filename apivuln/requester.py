"""
HTTP Request handler with authentication, throttling, and retry logic.
"""

import asyncio
import aiohttp
import time
from typing import Optional, Any
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse
import json
import copy

from .config import ScanConfig


@dataclass
class Response:
    """Wrapper for HTTP response data."""
    status_code: int
    headers: dict
    body: str
    json_body: Optional[dict]
    elapsed: float
    url: str
    method: str
    
    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300
    
    @property
    def is_error(self) -> bool:
        return self.status_code >= 400
    
    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").lower()
    
    @property
    def is_json(self) -> bool:
        return "application/json" in self.content_type


class Requester:
    """
    Async HTTP client with built-in throttling, authentication, and retry logic.
    """
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.base_url = config.base_url.rstrip("/")
        self._last_request_time = 0
        self._request_count = 0
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        await self._create_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
    
    async def _create_session(self):
        """Create aiohttp session with configured settings."""
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        
        connector = aiohttp.TCPConnector(
            ssl=self.config.verify_ssl,
            limit=self.config.threads
        )
        
        self._session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector
        )
    
    async def close(self):
        """Close the HTTP session."""
        if self._session:
            await self._session.close()
            self._session = None
    
    def _build_headers(self, auth_level: str = "high") -> dict:
        """Build request headers with authentication."""
        headers = {
            "User-Agent": "APIVuln/1.0",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        
        # Add custom headers
        headers.update(self.config.headers)
        
        # Add authentication
        token = None
        if auth_level == "high" and self.config.auth_token:
            token = self.config.auth_token
        elif auth_level == "low" and self.config.auth_token_low:
            token = self.config.auth_token_low
        elif self.config.auth_token:
            token = self.config.auth_token
        
        if token:
            headers[self.config.auth_header] = token
        
        return headers
    
    def _build_url(self, path: str) -> str:
        """Build full URL from path."""
        if path.startswith("http"):
            return path
        return urljoin(self.base_url + "/", path.lstrip("/"))
    
    async def _throttle(self):
        """Apply request throttling."""
        if self.config.delay > 0:
            elapsed = time.time() - self._last_request_time
            if elapsed < self.config.delay:
                await asyncio.sleep(self.config.delay - elapsed)
        self._last_request_time = time.time()
    
    async def send(
        self,
        endpoint: dict,
        auth_level: str = "high",
        extra_headers: Optional[dict] = None,
        override_params: Optional[dict] = None,
        override_body: Optional[dict] = None,
    ) -> Response:
        """
        Send an HTTP request based on endpoint configuration.
        
        Args:
            endpoint: Endpoint configuration dict with path, method, params, body
            auth_level: "high" for normal token, "low" for lower privilege token
            extra_headers: Additional headers to include
            override_params: Override URL parameters
            override_body: Override request body
        
        Returns:
            Response object with status, headers, body, etc.
        """
        if not self._session:
            await self._create_session()
        
        await self._throttle()
        
        method = endpoint.get("method", "GET").upper()
        path = endpoint.get("path", "/")
        params = override_params or endpoint.get("params", {})
        body = override_body or endpoint.get("body")
        
        # Build URL with path parameters
        url = self._build_url(path)
        for key, value in params.items():
            url = url.replace(f"{{{key}}}", str(value))
        
        # Build headers
        headers = self._build_headers(auth_level)
        if extra_headers:
            headers.update(extra_headers)
        
        # Prepare request kwargs
        kwargs = {"headers": headers}
        
        if method in ["POST", "PUT", "PATCH"]:
            if body:
                kwargs["json"] = body
        elif params:
            # For GET requests, add remaining params as query string
            query_params = {k: v for k, v in params.items() if f"{{{k}}}" not in path}
            if query_params:
                kwargs["params"] = query_params
        
        # Send request with retry logic
        last_error = None
        for attempt in range(self.config.max_retries):
            try:
                start_time = time.time()
                async with self._session.request(method, url, **kwargs) as resp:
                    elapsed = time.time() - start_time
                    body_text = await resp.text()
                    
                    # Try to parse JSON
                    json_body = None
                    try:
                        json_body = json.loads(body_text)
                    except (json.JSONDecodeError, ValueError):
                        pass
                    
                    self._request_count += 1
                    
                    return Response(
                        status_code=resp.status,
                        headers=dict(resp.headers),
                        body=body_text,
                        json_body=json_body,
                        elapsed=elapsed,
                        url=str(resp.url),
                        method=method,
                    )
            
            except asyncio.TimeoutError:
                last_error = "Request timed out"
            except aiohttp.ClientError as e:
                last_error = str(e)
            
            if attempt < self.config.max_retries - 1:
                await asyncio.sleep(1 * (attempt + 1))
        
        # Return error response if all retries failed
        return Response(
            status_code=0,
            headers={},
            body=f"Request failed: {last_error}",
            json_body=None,
            elapsed=0,
            url=url,
            method=method,
        )
    
    async def send_raw(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        body: Optional[Any] = None,
        auth_level: str = "high",
    ) -> Response:
        """
        Send a raw HTTP request without endpoint configuration.
        
        Useful for custom requests in vulnerability modules.
        """
        endpoint = {
            "method": method,
            "path": url,
        }
        if body:
            endpoint["body"] = body
        
        return await self.send(
            endpoint,
            auth_level=auth_level,
            extra_headers=headers,
        )
    
    def clone_endpoint(self, endpoint: dict) -> dict:
        """Create a deep copy of an endpoint configuration."""
        return copy.deepcopy(endpoint)
    
    @property
    def request_count(self) -> int:
        """Return total number of requests made."""
        return self._request_count
