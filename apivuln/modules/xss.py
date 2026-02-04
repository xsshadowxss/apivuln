"""
XSS (Cross-Site Scripting) Detection Module

Detects reflected XSS vulnerabilities in API responses.
While APIs typically return JSON, some may return HTML or
reflect user input in error messages.

CWE-79: Improper Neutralization of Input During Web Page Generation
"""

import re
import html
import copy
import urllib.parse
from typing import Optional, List
from .base import BaseModule, Finding, Severity


class XSSModule(BaseModule):
    """
    Detects Cross-Site Scripting vulnerabilities.
    
    Focuses on:
    - Reflected input in responses
    - Unescaped HTML in JSON values
    - XSS in error messages
    """
    
    name = "xss"
    description = "Cross-Site Scripting (XSS) Detection"
    version = "1.0"
    
    # Test payloads - simple ones for detection
    XSS_PAYLOADS = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '"><script>alert(1)</script>',
        "'-alert(1)-'",
        '<svg onload=alert(1)>',
        '{{7*7}}',  # Template injection
        '${7*7}',   # Template injection
        '<iframe src="javascript:alert(1)">',
    ]
    
    # Patterns indicating XSS reflection
    REFLECTION_PATTERNS = [
        r'<script[^>]*>.*?</script>',
        r'<img[^>]*onerror[^>]*>',
        r'<svg[^>]*onload[^>]*>',
        r'javascript:',
        r'on\w+\s*=',
    ]
    
    async def run(self, endpoint: dict) -> list[Finding]:
        """Test endpoint for XSS vulnerabilities."""
        findings = []
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        self.log(f"Testing {method} {path} for XSS", "info")
        
        # Get baseline
        baseline = await self.requester.send(endpoint)
        
        # Get injection points
        injection_points = self._get_injection_points(endpoint)
        
        if not injection_points:
            return findings
        
        for param_name, location in injection_points:
            for payload in self.XSS_PAYLOADS:
                finding = await self._test_xss(
                    endpoint, param_name, location, payload, baseline
                )
                if finding:
                    findings.append(finding)
                    break  # One finding per parameter is enough
        
        return findings
    
    def _get_injection_points(self, endpoint: dict) -> List[tuple]:
        """Extract injection points from endpoint."""
        points = []
        
        # Query/path params
        for param in endpoint.get("params", {}):
            points.append((param, "params"))
        
        # Body fields
        body = endpoint.get("body", {})
        if isinstance(body, dict):
            for field in body:
                points.append((field, "body"))
        
        return points
    
    async def _test_xss(
        self,
        endpoint: dict,
        param_name: str,
        location: str,
        payload: str,
        baseline
    ) -> Optional[Finding]:
        """Test a specific parameter for XSS."""
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        # Inject payload
        modified = copy.deepcopy(endpoint)
        
        if location == "params":
            modified["params"][param_name] = payload
        elif location == "body" and isinstance(modified.get("body"), dict):
            modified["body"][param_name] = payload
        
        response = await self.requester.send(modified)
        
        # Check if payload is reflected
        if self._is_reflected(payload, response.body):
            # Check if it's unescaped (potential XSS)
            if self._is_unescaped(payload, response.body):
                return self.create_finding(
                    severity=Severity.HIGH,
                    endpoint=path,
                    method=method,
                    title=f"Reflected XSS in '{param_name}'",
                    evidence=(
                        f"Payload '{payload[:50]}' was reflected unescaped in response. "
                        f"Response content-type: {response.content_type}"
                    ),
                    verification=(
                        f"1. Set {param_name} to: {payload}\n"
                        f"       2. Check if payload executes in browser\n"
                        f"       3. Verify response content-type allows script execution"
                    ),
                    confidence=75,
                    cwe_id="CWE-79",
                    references=[
                        "https://owasp.org/www-community/attacks/xss/",
                        "https://cwe.mitre.org/data/definitions/79.html",
                    ],
                )
            
            # Reflected but escaped - lower severity info
            return self.create_finding(
                severity=Severity.LOW,
                endpoint=path,
                method=method,
                title=f"Input Reflected in '{param_name}'",
                evidence=(
                    f"Input is reflected in response but appears escaped. "
                    f"Payload: {payload[:30]}..."
                ),
                verification=(
                    f"1. Test various encoding bypasses\n"
                    f"       2. Check if escaping is context-appropriate"
                ),
                confidence=40,
                cwe_id="CWE-79",
            )
        
        return None
    
    def _is_reflected(self, payload: str, response_body: str) -> bool:
        """Check if payload is reflected in response."""
        # Check for exact match
        if payload in response_body:
            return True
        
        # Check for URL-encoded version
        if urllib.parse.quote(payload) in response_body:
            return True
        
        # Check for HTML-encoded version
        if html.escape(payload) in response_body:
            return True
        
        return False
    
    def _is_unescaped(self, payload: str, response_body: str) -> bool:
        """Check if payload is reflected without proper escaping."""
        # If exact payload is in response, it's unescaped
        if payload in response_body:
            return True
        
        # Check for dangerous patterns
        for pattern in self.REFLECTION_PATTERNS:
            if re.search(pattern, response_body, re.IGNORECASE):
                return True
        
        return False
