"""
BFLA (Broken Function Level Authorization) Detection Module

Detects when API endpoints allow lower-privileged users to access
administrative or higher-privilege functionality.

OWASP API Security Top 10: API5:2023
CWE-285: Improper Authorization
"""

import re
from .base import BaseModule, Finding, Severity


class BFLAModule(BaseModule):
    """
    Detects Broken Function Level Authorization vulnerabilities.
    
    Tests if endpoints meant for higher privileges are accessible
    with lower-privilege credentials.
    """
    
    name = "bfla"
    description = "Broken Function Level Authorization Detection"
    version = "1.0"
    
    # Patterns that indicate admin/privileged endpoints
    ADMIN_PATTERNS = [
        r"/admin",
        r"/administrator",
        r"/manage",
        r"/management",
        r"/internal",
        r"/private",
        r"/sudo",
        r"/superuser",
        r"/root",
        r"/system",
        r"/config",
        r"/settings",
        r"/users/all",
        r"/users/list",
        r"/audit",
        r"/logs",
        r"/debug",
        r"/console",
        r"/dashboard",
        r"/analytics",
        r"/reports",
        r"/export",
        r"/import",
        r"/bulk",
        r"/batch",
    ]
    
    # HTTP methods that modify data
    DANGEROUS_METHODS = ["POST", "PUT", "PATCH", "DELETE"]
    
    async def run(self, endpoint: dict) -> list[Finding]:
        """
        Test endpoint for BFLA vulnerabilities.
        """
        findings = []
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        # Check if we have both high and low privilege tokens
        if not self.config or not self.config.auth_token_low:
            self.log("No low-privilege token configured, skipping BFLA tests", "warning")
            return findings
        
        is_sensitive = self._is_sensitive_endpoint(path, method)
        
        if not is_sensitive:
            self.log(f"Endpoint {path} doesn't match sensitive patterns", "info")
            # Still test but with lower priority
        
        self.log(f"Testing {method} {path} for BFLA", "info")
        
        # First, make request with high-privilege token
        high_priv_response = await self.requester.send(endpoint, auth_level="high")
        
        # Then, make same request with low-privilege token
        low_priv_response = await self.requester.send(endpoint, auth_level="low")
        
        # Analyze the difference
        if self._indicates_authz_bypass(high_priv_response, low_priv_response):
            severity = Severity.HIGH if is_sensitive else Severity.MEDIUM
            confidence = self._calculate_confidence(
                high_priv_response, low_priv_response, is_sensitive
            )
            
            findings.append(self.create_finding(
                severity=severity,
                endpoint=path,
                method=method,
                title="Potential BFLA Vulnerability",
                evidence=(
                    f"Low-privilege token received successful response. "
                    f"High-priv status: {high_priv_response.status_code}, "
                    f"Low-priv status: {low_priv_response.status_code}. "
                    f"Both returned similar successful responses."
                ),
                verification=(
                    f"1. Authenticate as admin/high-privilege user\n"
                    f"       2. Access {method} {path} - should succeed\n"
                    f"       3. Authenticate as regular/low-privilege user\n"
                    f"       4. Access same endpoint - should fail but succeeds"
                ),
                confidence=confidence,
                cwe_id="CWE-285",
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
                    "https://cwe.mitre.org/data/definitions/285.html",
                ],
            ))
        
        # Also test without any authentication
        no_auth_response = await self.requester.send(
            endpoint,
            extra_headers={self.config.auth_header: ""}
        )
        
        if no_auth_response.is_success and high_priv_response.is_success:
            if self.analyzer.similarity(no_auth_response, high_priv_response) > 0.5:
                findings.append(self.create_finding(
                    severity=Severity.CRITICAL,
                    endpoint=path,
                    method=method,
                    title="Missing Authentication on Sensitive Endpoint",
                    evidence=(
                        f"Endpoint accessible without any authentication. "
                        f"Status: {no_auth_response.status_code}"
                    ),
                    verification=(
                        f"1. Remove all authentication headers\n"
                        f"       2. Access {method} {path}\n"
                        f"       3. Verify sensitive data/functionality is accessible"
                    ),
                    confidence=90,
                    cwe_id="CWE-306",
                    references=[
                        "https://cwe.mitre.org/data/definitions/306.html",
                    ],
                ))
        
        return findings
    
    def _is_sensitive_endpoint(self, path: str, method: str) -> bool:
        """Check if endpoint appears to be admin/privileged."""
        # Check path patterns
        for pattern in self.ADMIN_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                return True
        
        # Dangerous methods on user-related endpoints
        if method in self.DANGEROUS_METHODS:
            if re.search(r"/users?(/|$)", path, re.IGNORECASE):
                return True
        
        return False
    
    def _indicates_authz_bypass(self, high_priv, low_priv) -> bool:
        """Check if responses indicate authorization bypass."""
        # Low priv should fail (401/403) but doesn't
        if low_priv.is_success and high_priv.is_success:
            # Both succeed - check if they return similar data
            similarity = self.analyzer.similarity(low_priv, high_priv)
            if similarity > 0.5:
                return True
        
        return False
    
    def _calculate_confidence(self, high_priv, low_priv, is_sensitive) -> int:
        """Calculate confidence score."""
        confidence = 50
        
        # Higher confidence for sensitive endpoints
        if is_sensitive:
            confidence += 20
        
        # Higher confidence if responses are very similar
        similarity = self.analyzer.similarity(low_priv, high_priv)
        if similarity > 0.9:
            confidence += 20
        elif similarity > 0.7:
            confidence += 10
        
        # Higher confidence if JSON data is returned
        if low_priv.json_body:
            confidence += 10
        
        return min(100, confidence)
