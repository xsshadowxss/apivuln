#!/usr/bin/env python3
"""
API Endpoint Discovery Module

Automatically discovers API endpoints from a target website by:
1. Crawling HTML/JS files for API references
2. Checking common API paths
3. Parsing JavaScript for fetch/axios calls
4. Checking robots.txt and sitemap.xml
5. Analyzing response headers for API hints
"""

import re
import asyncio
import aiohttp
from typing import List, Dict, Set, Optional
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field


@dataclass
class DiscoveredEndpoint:
    """Represents a discovered API endpoint."""
    path: str
    method: str = "GET"
    source: str = ""  # Where it was found
    params: Dict = field(default_factory=dict)
    body: Dict = field(default_factory=dict)
    confidence: int = 50  # How confident we are this is a real endpoint
    
    def to_dict(self) -> Dict:
        """Convert to endpoint dict format."""
        result = {
            "path": self.path,
            "method": self.method,
            "description": f"Auto-discovered from {self.source}"
        }
        if self.params:
            result["params"] = self.params
        if self.body:
            result["body"] = self.body
        return result


class APIDiscovery:
    """
    Discovers API endpoints from a target website.
    """
    
    # Common API path patterns to check
    COMMON_API_PATHS = [
        # Version patterns
        "/api",
        "/api/v1",
        "/api/v2",
        "/api/v3",
        "/v1",
        "/v2",
        "/v3",
        "/rest",
        "/rest/v1",
        "/graphql",
        "/graphiql",
        
        # Auth endpoints
        "/api/auth/login",
        "/api/auth/register",
        "/api/auth/logout",
        "/api/auth/refresh",
        "/api/auth/forgot-password",
        "/api/login",
        "/api/register",
        "/api/signup",
        "/auth/login",
        "/auth/register",
        "/login",
        "/signin",
        "/signup",
        "/oauth/token",
        "/oauth/authorize",
        "/token",
        "/jwt/auth",
        
        # User endpoints
        "/api/users",
        "/api/user",
        "/api/users/me",
        "/api/user/profile",
        "/api/profile",
        "/api/account",
        "/api/me",
        "/users",
        "/user",
        "/profile",
        "/account",
        
        # Common CRUD endpoints
        "/api/items",
        "/api/products",
        "/api/orders",
        "/api/posts",
        "/api/comments",
        "/api/messages",
        "/api/notifications",
        "/api/settings",
        "/api/config",
        "/api/data",
        
        # Admin endpoints
        "/api/admin",
        "/api/admin/users",
        "/api/admin/settings",
        "/api/admin/config",
        "/admin/api",
        "/admin",
        "/management",
        "/internal",
        
        # Documentation
        "/swagger",
        "/swagger.json",
        "/swagger.yaml",
        "/swagger/v1/swagger.json",
        "/api-docs",
        "/api/docs",
        "/docs",
        "/openapi.json",
        "/openapi.yaml",
        "/redoc",
        "/api/swagger",
        "/api/openapi",
        "/api/schema",
        
        # Health/Status
        "/api/health",
        "/api/status",
        "/api/ping",
        "/api/version",
        "/health",
        "/healthz",
        "/status",
        "/ping",
        "/version",
        "/info",
        "/actuator",
        "/actuator/health",
        "/actuator/info",
        
        # Search
        "/api/search",
        "/search",
        "/api/query",
        "/query",
        
        # Upload
        "/api/upload",
        "/api/files",
        "/upload",
        "/files",
        
        # Webhooks
        "/api/webhooks",
        "/api/webhook",
        "/webhooks",
        "/callback",
    ]
    
    # Patterns to find APIs in JavaScript/HTML
    JS_API_PATTERNS = [
        # Fetch calls
        r'fetch\s*\(\s*[\'"`]([^\'"` ]+)[\'"`]',
        r'fetch\s*\(\s*`([^`]+)`',
        
        # Axios calls
        r'axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"` ]+)[\'"`]',
        r'axios\s*\(\s*\{[^}]*url\s*:\s*[\'"`]([^\'"` ]+)[\'"`]',
        
        # XMLHttpRequest
        r'\.open\s*\(\s*[\'"`](?:GET|POST|PUT|DELETE|PATCH)[\'"`]\s*,\s*[\'"`]([^\'"` ]+)[\'"`]',
        
        # jQuery AJAX
        r'\$\.(?:ajax|get|post)\s*\(\s*[\'"`]([^\'"` ]+)[\'"`]',
        r'\$\.(?:ajax|get|post)\s*\(\s*\{[^}]*url\s*:\s*[\'"`]([^\'"` ]+)[\'"`]',
        
        # Generic API patterns
        r'[\'"`](/api/[^\'"` ]+)[\'"`]',
        r'[\'"`](/v[0-9]+/[^\'"` ]+)[\'"`]',
        r'apiUrl\s*[=:]\s*[\'"`]([^\'"` ]+)[\'"`]',
        r'baseUrl\s*[=:]\s*[\'"`]([^\'"` ]+)[\'"`]',
        r'endpoint\s*[=:]\s*[\'"`]([^\'"` ]+)[\'"`]',
        r'API_URL\s*[=:]\s*[\'"`]([^\'"` ]+)[\'"`]',
        r'BASE_URL\s*[=:]\s*[\'"`]([^\'"` ]+)[\'"`]',
    ]
    
    # Patterns to detect HTTP methods
    METHOD_PATTERNS = [
        (r'\.get\s*\(', 'GET'),
        (r'\.post\s*\(', 'POST'),
        (r'\.put\s*\(', 'PUT'),
        (r'\.patch\s*\(', 'PATCH'),
        (r'\.delete\s*\(', 'DELETE'),
        (r'method\s*:\s*[\'"`]GET[\'"`]', 'GET'),
        (r'method\s*:\s*[\'"`]POST[\'"`]', 'POST'),
        (r'method\s*:\s*[\'"`]PUT[\'"`]', 'PUT'),
        (r'method\s*:\s*[\'"`]PATCH[\'"`]', 'PATCH'),
        (r'method\s*:\s*[\'"`]DELETE[\'"`]', 'DELETE'),
    ]
    
    def __init__(self, base_url: str, timeout: int = 10, verbose: bool = False):
        """
        Initialize the API discovery.
        
        Args:
            base_url: Target website URL
            timeout: Request timeout in seconds
            verbose: Print verbose output
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.verbose = verbose
        self.discovered: Dict[str, DiscoveredEndpoint] = {}
        self.session: Optional[aiohttp.ClientSession] = None
        self.js_files: Set[str] = set()
        self.checked_paths: Set[str] = set()
    
    def log(self, message: str, level: str = "info"):
        """Print log message if verbose."""
        if self.verbose:
            prefix = {
                "info": "\033[94m[*]\033[0m",
                "success": "\033[92m[+]\033[0m",
                "warning": "\033[93m[!]\033[0m",
                "error": "\033[91m[-]\033[0m",
            }.get(level, "[*]")
            print(f"{prefix} {message}")
    
    async def discover(self, callback=None) -> List[DiscoveredEndpoint]:
        """
        Run the full discovery process.
        
        Args:
            callback: Optional callback function(message, discovered_count)
        
        Returns:
            List of discovered endpoints
        """
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(timeout=timeout) as self.session:
            # Step 1: Check common API paths
            if callback:
                callback("Checking common API paths...", len(self.discovered))
            await self._check_common_paths()
            
            # Step 2: Fetch and parse main page
            if callback:
                callback("Analyzing main page...", len(self.discovered))
            await self._analyze_main_page()
            
            # Step 3: Check robots.txt
            if callback:
                callback("Checking robots.txt...", len(self.discovered))
            await self._check_robots_txt()
            
            # Step 4: Check sitemap.xml
            if callback:
                callback("Checking sitemap.xml...", len(self.discovered))
            await self._check_sitemap()
            
            # Step 5: Parse JavaScript files
            if callback:
                callback("Analyzing JavaScript files...", len(self.discovered))
            await self._analyze_js_files()
            
            # Step 6: Check for OpenAPI/Swagger
            if callback:
                callback("Looking for API documentation...", len(self.discovered))
            await self._check_api_docs()
        
        return list(self.discovered.values())
    
    async def _make_request(self, url: str, method: str = "GET") -> Optional[aiohttp.ClientResponse]:
        """Make HTTP request and return response."""
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "application/json, text/html, */*",
            }
            
            async with self.session.request(method, url, headers=headers, ssl=False) as response:
                # Read body to ensure we can check content
                body = await response.text()
                response._body = body
                return response
        except Exception as e:
            self.log(f"Request failed for {url}: {e}", "error")
            return None
    
    async def _check_common_paths(self):
        """Check common API paths for existence."""
        tasks = []
        
        for path in self.COMMON_API_PATHS:
            url = urljoin(self.base_url, path)
            if url not in self.checked_paths:
                self.checked_paths.add(url)
                tasks.append(self._check_path(path))
        
        # Run in batches to avoid overwhelming the server
        batch_size = 10
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i+batch_size]
            await asyncio.gather(*batch, return_exceptions=True)
            await asyncio.sleep(0.1)  # Small delay between batches
    
    async def _check_path(self, path: str):
        """Check if a path exists and looks like an API."""
        url = urljoin(self.base_url, path)
        response = await self._make_request(url)
        
        if response is None:
            return
        
        # Determine if it looks like an API endpoint
        is_api = False
        confidence = 0
        
        content_type = response.headers.get("Content-Type", "").lower()
        body = getattr(response, '_body', '')
        
        # Check status code
        if response.status == 200:
            confidence += 30
            
            # Check content type
            if "application/json" in content_type:
                is_api = True
                confidence += 40
            elif "application/xml" in content_type:
                is_api = True
                confidence += 30
            
            # Check if body looks like JSON
            if body.strip().startswith('{') or body.strip().startswith('['):
                is_api = True
                confidence += 20
            
            # Check for API-like response headers
            if response.headers.get("X-RateLimit-Limit"):
                confidence += 10
            if response.headers.get("X-Request-Id"):
                confidence += 10
                
        elif response.status == 401:
            # Unauthorized usually means it's a real protected endpoint
            is_api = True
            confidence = 70
        elif response.status == 403:
            # Forbidden - endpoint exists but not accessible
            is_api = True
            confidence = 60
        elif response.status == 405:
            # Method not allowed - endpoint exists
            is_api = True
            confidence = 80
        
        if is_api and confidence >= 50:
            self._add_endpoint(path, "GET", "common_paths", confidence)
            self.log(f"Found: {path} (confidence: {confidence}%)", "success")
    
    async def _analyze_main_page(self):
        """Analyze the main page for API references."""
        response = await self._make_request(self.base_url)
        
        if response is None:
            return
        
        body = getattr(response, '_body', '')
        
        # Find JavaScript file references
        js_pattern = r'<script[^>]+src=[\'"]([^\'"]+\.js[^\'"]*)[\'"]'
        js_matches = re.findall(js_pattern, body, re.IGNORECASE)
        
        for js_url in js_matches:
            if js_url.startswith('//'):
                js_url = 'https:' + js_url
            elif not js_url.startswith('http'):
                js_url = urljoin(self.base_url, js_url)
            self.js_files.add(js_url)
        
        # Find API references in HTML
        self._extract_apis_from_content(body, "main_page")
        
        # Find links that might be API endpoints
        link_pattern = r'href=[\'"]([^\'"]*(?:api|v[0-9])[^\'"]*)[\'"]'
        link_matches = re.findall(link_pattern, body, re.IGNORECASE)
        
        for link in link_matches:
            if not link.startswith(('http', '//')):
                path = link if link.startswith('/') else '/' + link
                self._add_endpoint(path, "GET", "html_link", 40)
    
    async def _check_robots_txt(self):
        """Check robots.txt for API paths."""
        url = urljoin(self.base_url, "/robots.txt")
        response = await self._make_request(url)
        
        if response is None or response.status != 200:
            return
        
        body = getattr(response, '_body', '')
        
        # Look for disallowed paths that might be APIs
        for line in body.split('\n'):
            line = line.strip()
            if line.lower().startswith('disallow:'):
                path = line.split(':', 1)[1].strip()
                if any(api_hint in path.lower() for api_hint in ['api', 'admin', 'internal', 'v1', 'v2']):
                    self._add_endpoint(path, "GET", "robots.txt", 60)
    
    async def _check_sitemap(self):
        """Check sitemap.xml for API paths."""
        sitemap_urls = [
            "/sitemap.xml",
            "/sitemap_index.xml",
            "/sitemap/sitemap.xml",
        ]
        
        for sitemap_path in sitemap_urls:
            url = urljoin(self.base_url, sitemap_path)
            response = await self._make_request(url)
            
            if response and response.status == 200:
                body = getattr(response, '_body', '')
                
                # Extract URLs from sitemap
                url_pattern = r'<loc>([^<]+)</loc>'
                urls = re.findall(url_pattern, body)
                
                for found_url in urls:
                    parsed = urlparse(found_url)
                    if any(api_hint in parsed.path.lower() for api_hint in ['api', 'v1', 'v2', 'rest']):
                        self._add_endpoint(parsed.path, "GET", "sitemap.xml", 50)
    
    async def _analyze_js_files(self):
        """Analyze JavaScript files for API endpoints."""
        for js_url in list(self.js_files)[:20]:  # Limit to 20 JS files
            response = await self._make_request(js_url)
            
            if response and response.status == 200:
                body = getattr(response, '_body', '')
                self._extract_apis_from_content(body, f"js:{js_url.split('/')[-1]}")
    
    async def _check_api_docs(self):
        """Check for OpenAPI/Swagger documentation."""
        doc_paths = [
            "/swagger.json",
            "/openapi.json",
            "/api-docs",
            "/swagger/v1/swagger.json",
            "/v1/swagger.json",
            "/v2/swagger.json",
            "/api/swagger.json",
            "/api/openapi.json",
        ]
        
        for path in doc_paths:
            url = urljoin(self.base_url, path)
            response = await self._make_request(url)
            
            if response and response.status == 200:
                body = getattr(response, '_body', '')
                
                try:
                    import json
                    spec = json.loads(body)
                    
                    # Parse OpenAPI/Swagger spec
                    if "paths" in spec:
                        self.log(f"Found API spec at {path}", "success")
                        
                        for endpoint_path, methods in spec["paths"].items():
                            for method in methods:
                                if method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                                    self._add_endpoint(
                                        endpoint_path,
                                        method.upper(),
                                        f"openapi:{path}",
                                        95
                                    )
                except:
                    pass
    
    def _extract_apis_from_content(self, content: str, source: str):
        """Extract API endpoints from content using regex patterns."""
        for pattern in self.JS_API_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            
            for match in matches:
                # Clean up the match
                path = match.strip()
                
                # Skip external URLs
                if path.startswith(('http://', 'https://', '//')):
                    parsed = urlparse(path)
                    # Only include if it's the same domain
                    if parsed.netloc and parsed.netloc not in self.base_url:
                        continue
                    path = parsed.path
                
                # Skip non-API looking paths
                if not path or path == '/':
                    continue
                
                # Ensure path starts with /
                if not path.startswith('/'):
                    path = '/' + path
                
                # Determine method from context
                method = "GET"
                for method_pattern, http_method in self.METHOD_PATTERNS:
                    # Look for method pattern near the URL
                    context_start = max(0, content.find(match) - 100)
                    context = content[context_start:content.find(match) + len(match) + 50]
                    if re.search(method_pattern, context, re.IGNORECASE):
                        method = http_method
                        break
                
                self._add_endpoint(path, method, source, 60)
    
    def _add_endpoint(self, path: str, method: str, source: str, confidence: int):
        """Add a discovered endpoint."""
        # Normalize path
        path = path.split('?')[0]  # Remove query string
        path = path.split('#')[0]  # Remove fragment
        
        # Skip invalid paths
        if not path or len(path) > 200:
            return
        
        # Skip static files
        static_extensions = ['.css', '.js', '.png', '.jpg', '.gif', '.ico', '.svg', '.woff', '.ttf']
        if any(path.lower().endswith(ext) for ext in static_extensions):
            return
        
        # Create unique key
        key = f"{method}:{path}"
        
        # Update if higher confidence or new
        if key not in self.discovered or self.discovered[key].confidence < confidence:
            # Try to extract path parameters
            params = {}
            param_pattern = r'\{(\w+)\}'
            param_matches = re.findall(param_pattern, path)
            for param in param_matches:
                params[param] = "1"  # Default value
            
            # Also check for :param style
            colon_pattern = r':(\w+)'
            colon_matches = re.findall(colon_pattern, path)
            for param in colon_matches:
                params[param] = "1"
                # Convert :param to {param} format
                path = path.replace(f':{param}', f'{{{param}}}')
            
            self.discovered[key] = DiscoveredEndpoint(
                path=path,
                method=method,
                source=source,
                params=params,
                confidence=confidence
            )
    
    def get_endpoints_json(self) -> Dict:
        """Get discovered endpoints in JSON format."""
        endpoints = []
        
        # Sort by confidence (highest first)
        sorted_endpoints = sorted(
            self.discovered.values(),
            key=lambda x: x.confidence,
            reverse=True
        )
        
        for endpoint in sorted_endpoints:
            endpoints.append(endpoint.to_dict())
        
        return {"endpoints": endpoints}


async def discover_apis(base_url: str, verbose: bool = False, callback=None) -> List[Dict]:
    """
    Convenience function to discover APIs from a URL.
    
    Args:
        base_url: Target website URL
        verbose: Print verbose output
        callback: Optional callback function
    
    Returns:
        List of endpoint dictionaries
    """
    discovery = APIDiscovery(base_url, verbose=verbose)
    endpoints = await discovery.discover(callback=callback)
    return [e.to_dict() for e in endpoints]


def discover_apis_sync(base_url: str, verbose: bool = False) -> List[Dict]:
    """Synchronous wrapper for discover_apis."""
    return asyncio.run(discover_apis(base_url, verbose=verbose))


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python discovery.py <target_url>")
        sys.exit(1)
    
    target = sys.argv[1]
    print(f"\n[*] Discovering APIs on {target}...\n")
    
    endpoints = discover_apis_sync(target, verbose=True)
    
    print(f"\n[+] Found {len(endpoints)} endpoints:\n")
    for ep in endpoints:
        print(f"  {ep['method']:6} {ep['path']}")
    
    # Save to file
    import json
    with open("discovered_endpoints.json", "w") as f:
        json.dump({"endpoints": endpoints}, f, indent=2)
    
    print(f"\n[+] Saved to discovered_endpoints.json")
