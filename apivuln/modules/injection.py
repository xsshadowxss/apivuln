"""
Injection Vulnerability Detection Module

Detects potential SQL injection, NoSQL injection, and SSRF vulnerabilities
through error-based and time-based detection techniques.

OWASP API Security Top 10: API8:2023
CWE-89: SQL Injection
CWE-943: NoSQL Injection
CWE-918: Server-Side Request Forgery
"""

import copy
from typing import Optional
from .base import BaseModule, Finding, Severity
from ..config import SQLI_PAYLOADS, NOSQL_PAYLOADS, SSRF_PAYLOADS


class InjectionModule(BaseModule):
    """
    Detects injection vulnerabilities in API endpoints.
    """
    
    name = "injection"
    description = "SQL/NoSQL/SSRF Injection Detection"
    version = "1.0"
    
    async def run(self, endpoint: dict) -> list[Finding]:
        """
        Test endpoint for injection vulnerabilities.
        """
        findings = []
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        self.log(f"Testing {method} {path} for injection vulnerabilities", "info")
        
        # Get baseline response
        baseline = await self.requester.send(endpoint)
        
        # Get injection points (params and body fields)
        injection_points = self._get_injection_points(endpoint)
        
        if not injection_points:
            self.log(f"No injection points found in {path}", "info")
            return findings
        
        self.log(f"Found {len(injection_points)} injection points", "info")
        
        # Test each injection point
        for point_name, point_location in injection_points:
            # SQL Injection tests
            sqli_finding = await self._test_sqli(
                endpoint, point_name, point_location, baseline
            )
            if sqli_finding:
                findings.append(sqli_finding)
            
            # NoSQL Injection tests
            nosqli_finding = await self._test_nosqli(
                endpoint, point_name, point_location, baseline
            )
            if nosqli_finding:
                findings.append(nosqli_finding)
            
            # SSRF tests (only for URL-like parameters)
            if self._looks_like_url_param(point_name):
                ssrf_finding = await self._test_ssrf(
                    endpoint, point_name, point_location, baseline
                )
                if ssrf_finding:
                    findings.append(ssrf_finding)
        
        return findings
    
    def _get_injection_points(self, endpoint: dict) -> list[tuple[str, str]]:
        """
        Extract all potential injection points from endpoint.
        Returns list of (param_name, location) tuples.
        """
        points = []
        
        # URL/Query parameters
        params = endpoint.get("params", {})
        for param_name in params:
            points.append((param_name, "params"))
        
        # Body fields (for POST/PUT/PATCH)
        body = endpoint.get("body", {})
        if isinstance(body, dict):
            for field_name in body:
                points.append((field_name, "body"))
        
        return points
    
    def _inject_payload(
        self,
        endpoint: dict,
        param_name: str,
        location: str,
        payload: str
    ) -> dict:
        """Create a copy of endpoint with payload injected."""
        modified = copy.deepcopy(endpoint)
        
        if location == "params":
            if "params" not in modified:
                modified["params"] = {}
            original = str(modified["params"].get(param_name, ""))
            modified["params"][param_name] = original + payload
        
        elif location == "body":
            if "body" not in modified:
                modified["body"] = {}
            if isinstance(modified["body"], dict):
                original = str(modified["body"].get(param_name, ""))
                modified["body"][param_name] = original + payload
        
        return modified
    
    async def _test_sqli(
        self,
        endpoint: dict,
        param_name: str,
        location: str,
        baseline
    ) -> Optional[Finding]:
        """Test for SQL injection."""
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        for payload in SQLI_PAYLOADS:
            modified = self._inject_payload(endpoint, param_name, location, payload)
            response = await self.requester.send(modified)
            
            # Check for SQL error messages
            has_error, error_match = self.analyzer.has_sql_error(response)
            
            if has_error:
                return self.create_finding(
                    severity=Severity.HIGH,
                    endpoint=path,
                    method=method,
                    title=f"Potential SQL Injection in '{param_name}'",
                    evidence=(
                        f"SQL error detected with payload: {payload}\n"
                        f"       Error pattern matched: {error_match}\n"
                        f"       Response status: {response.status_code}"
                    ),
                    verification=(
                        f"1. Send request with {param_name}={payload}\n"
                        f"       2. Observe SQL error in response\n"
                        f"       3. Test further with UNION/time-based payloads"
                    ),
                    confidence=85,
                    cwe_id="CWE-89",
                    references=[
                        "https://owasp.org/www-community/attacks/SQL_Injection",
                        "https://cwe.mitre.org/data/definitions/89.html",
                    ],
                )
            
            # Check for time-based SQLi (if payload contains SLEEP)
            if "SLEEP" in payload.upper():
                if self.analyzer.response_time_anomaly(response, baseline, threshold=4.0):
                    return self.create_finding(
                        severity=Severity.HIGH,
                        endpoint=path,
                        method=method,
                        title=f"Time-Based SQL Injection in '{param_name}'",
                        evidence=(
                            f"Response delayed by {response.elapsed - baseline.elapsed:.1f}s "
                            f"with SLEEP payload: {payload}"
                        ),
                        verification=(
                            f"1. Send request with {param_name}=' AND SLEEP(5)--\n"
                            f"       2. Measure response time\n"
                            f"       3. Compare with normal response time"
                        ),
                        confidence=80,
                        cwe_id="CWE-89",
                    )
        
        return None
    
    async def _test_nosqli(
        self,
        endpoint: dict,
        param_name: str,
        location: str,
        baseline
    ) -> Optional[Finding]:
        """Test for NoSQL injection."""
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        for payload in NOSQL_PAYLOADS:
            # For NoSQL, we often need to replace the entire value
            modified = copy.deepcopy(endpoint)
            
            if location == "params":
                modified["params"][param_name] = payload
            elif location == "body" and isinstance(modified.get("body"), dict):
                # Try to inject NoSQL operators
                try:
                    if payload.startswith("{"):
                        import json
                        modified["body"][param_name] = json.loads(payload)
                    else:
                        modified["body"][param_name] = payload
                except:
                    modified["body"][param_name] = payload
            
            response = await self.requester.send(modified)
            
            # Check for NoSQL error messages
            has_error, error_match = self.analyzer.has_nosql_error(response)
            
            if has_error:
                return self.create_finding(
                    severity=Severity.HIGH,
                    endpoint=path,
                    method=method,
                    title=f"Potential NoSQL Injection in '{param_name}'",
                    evidence=(
                        f"NoSQL error detected with payload: {payload}\n"
                        f"       Error pattern matched: {error_match}"
                    ),
                    verification=(
                        f"1. Replace {param_name} with {payload}\n"
                        f"       2. Observe NoSQL error or behavior change\n"
                        f"       3. Test with $ne, $gt, $regex operators"
                    ),
                    confidence=80,
                    cwe_id="CWE-943",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
                    ],
                )
            
            # Check for auth bypass (NoSQL $ne operator)
            if "$ne" in payload and response.is_success:
                # If we get success with $ne operator, might be vulnerable
                if not baseline.is_success or len(response.body) > len(baseline.body) * 1.5:
                    return self.create_finding(
                        severity=Severity.HIGH,
                        endpoint=path,
                        method=method,
                        title=f"Potential NoSQL Auth Bypass in '{param_name}'",
                        evidence=(
                            f"$ne operator returned more data. "
                            f"Baseline: {len(baseline.body)} bytes, "
                            f"Payload response: {len(response.body)} bytes"
                        ),
                        verification=(
                            f"1. Replace {param_name} with {{\"$ne\": null}}\n"
                            f"       2. Check if more data is returned\n"
                            f"       3. Verify unauthorized data access"
                        ),
                        confidence=70,
                        cwe_id="CWE-943",
                    )
        
        return None
    
    async def _test_ssrf(
        self,
        endpoint: dict,
        param_name: str,
        location: str,
        baseline
    ) -> Optional[Finding]:
        """Test for Server-Side Request Forgery."""
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        for payload in SSRF_PAYLOADS:
            modified = copy.deepcopy(endpoint)
            
            if location == "params":
                modified["params"][param_name] = payload
            elif location == "body" and isinstance(modified.get("body"), dict):
                modified["body"][param_name] = payload
            
            response = await self.requester.send(modified)
            
            # Check for signs of SSRF
            ssrf_indicators = [
                "root:",  # /etc/passwd
                "localhost",
                "127.0.0.1",
                "ami-id",  # AWS metadata
                "instance-id",
                "Connection refused",
                "No route to host",
            ]
            
            for indicator in ssrf_indicators:
                if indicator.lower() in response.body.lower():
                    severity = Severity.CRITICAL if "ami-id" in response.body else Severity.HIGH
                    
                    return self.create_finding(
                        severity=severity,
                        endpoint=path,
                        method=method,
                        title=f"Potential SSRF in '{param_name}'",
                        evidence=(
                            f"SSRF indicator '{indicator}' found with payload: {payload}\n"
                            f"       This may allow access to internal services or cloud metadata."
                        ),
                        verification=(
                            f"1. Set {param_name} to {payload}\n"
                            f"       2. Check response for internal data\n"
                            f"       3. Try cloud metadata endpoints (169.254.169.254)"
                        ),
                        confidence=75,
                        cwe_id="CWE-918",
                        references=[
                            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                            "https://cwe.mitre.org/data/definitions/918.html",
                        ],
                    )
            
            # Check for different response indicating server-side fetch
            if response.status_code != baseline.status_code:
                if response.status_code in [500, 502, 503, 504]:
                    return self.create_finding(
                        severity=Severity.MEDIUM,
                        endpoint=path,
                        method=method,
                        title=f"SSRF Indicator in '{param_name}'",
                        evidence=(
                            f"Server error ({response.status_code}) with SSRF payload: {payload}\n"
                            f"       This suggests server-side URL fetching."
                        ),
                        verification=(
                            f"1. Set {param_name} to various internal URLs\n"
                            f"       2. Monitor for different error responses\n"
                            f"       3. Use out-of-band detection (Burp Collaborator, etc.)"
                        ),
                        confidence=50,
                        cwe_id="CWE-918",
                    )
        
        return None
    
    def _looks_like_url_param(self, param_name: str) -> bool:
        """Check if parameter name suggests it might accept URLs."""
        url_indicators = [
            "url", "uri", "link", "href", "src", "source",
            "redirect", "return", "next", "dest", "destination",
            "target", "path", "file", "image", "img", "load",
            "fetch", "callback", "webhook", "endpoint",
        ]
        
        param_lower = param_name.lower()
        return any(indicator in param_lower for indicator in url_indicators)
