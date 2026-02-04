"""
CORS (Cross-Origin Resource Sharing) Misconfiguration Detection Module

Detects insecure CORS configurations that could allow unauthorized
cross-origin access to sensitive data.

CWE-942: Overly Permissive Cross-domain Whitelist
"""

from typing import Optional
from .base import BaseModule, Finding, Severity


class CORSModule(BaseModule):
    """
    Detects CORS misconfiguration vulnerabilities.
    
    Tests for:
    - Wildcard origins (Access-Control-Allow-Origin: *)
    - Reflected origins without validation
    - Credentials allowed with wildcard
    - Null origin acceptance
    """
    
    name = "cors"
    description = "CORS Misconfiguration Detection"
    version = "1.0"
    
    # Test origins
    TEST_ORIGINS = [
        "https://evil.com",
        "https://attacker.com",
        "null",
        "https://test.evil.com",
    ]
    
    async def run(self, endpoint: dict) -> list[Finding]:
        """Test endpoint for CORS misconfigurations."""
        findings = []
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        self.log(f"Testing {method} {path} for CORS issues", "info")
        
        # Test 1: Check for wildcard origin
        wildcard_finding = await self._test_wildcard_origin(endpoint)
        if wildcard_finding:
            findings.append(wildcard_finding)
        
        # Test 2: Check for reflected origin
        reflected_finding = await self._test_reflected_origin(endpoint)
        if reflected_finding:
            findings.append(reflected_finding)
        
        # Test 3: Check for null origin acceptance
        null_finding = await self._test_null_origin(endpoint)
        if null_finding:
            findings.append(null_finding)
        
        return findings
    
    async def _test_wildcard_origin(self, endpoint: dict) -> Optional[Finding]:
        """Test for wildcard Access-Control-Allow-Origin."""
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        response = await self.requester.send(endpoint)
        
        acao = response.headers.get("Access-Control-Allow-Origin", "")
        acac = response.headers.get("Access-Control-Allow-Credentials", "")
        
        if acao == "*":
            severity = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
            
            return self.create_finding(
                severity=severity,
                endpoint=path,
                method=method,
                title="CORS Wildcard Origin",
                evidence=(
                    f"Access-Control-Allow-Origin: * is set. "
                    f"Allow-Credentials: {acac or 'not set'}. "
                    f"Any website can make requests to this endpoint."
                ),
                verification=(
                    f"1. Create a page on any domain\n"
                    f"       2. Make fetch/XHR request to {path}\n"
                    f"       3. Verify response is accessible cross-origin"
                ),
                confidence=95,
                cwe_id="CWE-942",
                references=[
                    "https://portswigger.net/web-security/cors",
                    "https://cwe.mitre.org/data/definitions/942.html",
                ],
            )
        
        return None
    
    async def _test_reflected_origin(self, endpoint: dict) -> Optional[Finding]:
        """Test if arbitrary origins are reflected."""
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        for test_origin in self.TEST_ORIGINS:
            if test_origin == "null":
                continue  # Test separately
            
            response = await self.requester.send(
                endpoint,
                extra_headers={"Origin": test_origin}
            )
            
            acao = response.headers.get("Access-Control-Allow-Origin", "")
            acac = response.headers.get("Access-Control-Allow-Credentials", "")
            
            if acao == test_origin:
                severity = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
                
                return self.create_finding(
                    severity=severity,
                    endpoint=path,
                    method=method,
                    title="CORS Origin Reflection",
                    evidence=(
                        f"Origin '{test_origin}' was reflected in Access-Control-Allow-Origin. "
                        f"Allow-Credentials: {acac or 'not set'}. "
                        f"Server may accept any origin."
                    ),
                    verification=(
                        f"1. Send request with Origin: {test_origin}\n"
                        f"       2. Check if ACAO header reflects the origin\n"
                        f"       3. Test with credentials to assess full impact"
                    ),
                    confidence=90,
                    cwe_id="CWE-942",
                )
        
        return None
    
    async def _test_null_origin(self, endpoint: dict) -> Optional[Finding]:
        """Test if null origin is accepted."""
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        response = await self.requester.send(
            endpoint,
            extra_headers={"Origin": "null"}
        )
        
        acao = response.headers.get("Access-Control-Allow-Origin", "")
        acac = response.headers.get("Access-Control-Allow-Credentials", "")
        
        if acao == "null":
            return self.create_finding(
                severity=Severity.HIGH,
                endpoint=path,
                method=method,
                title="CORS Accepts Null Origin",
                evidence=(
                    f"Server accepts 'null' origin. "
                    f"Allow-Credentials: {acac or 'not set'}. "
                    f"Sandboxed iframes and redirects can exploit this."
                ),
                verification=(
                    f"1. Create sandboxed iframe with srcdoc\n"
                    f"       2. Make request from iframe (sends null origin)\n"
                    f"       3. Verify cross-origin access is granted"
                ),
                confidence=90,
                cwe_id="CWE-942",
            )
        
        return None
