"""
Information Disclosure Detection Module

Detects various forms of information leakage including:
- Verbose error messages
- Debug information
- Stack traces
- Excessive data exposure
- Sensitive data in responses

OWASP API Security Top 10: API3:2023
CWE-200: Exposure of Sensitive Information
"""

import re
from typing import Optional
from .base import BaseModule, Finding, Severity


class DisclosureModule(BaseModule):
    """
    Detects information disclosure vulnerabilities.
    """
    
    name = "disclosure"
    description = "Information Disclosure Detection"
    version = "1.0"
    
    # Patterns indicating debug/development mode
    DEBUG_ENDPOINTS = [
        "/debug",
        "/trace",
        "/actuator",
        "/health",
        "/metrics",
        "/env",
        "/configprops",
        "/heapdump",
        "/threaddump",
        "/mappings",
        "/.git",
        "/.env",
        "/phpinfo",
        "/server-status",
        "/elmah",
        "/swagger",
        "/api-docs",
        "/graphql",
    ]
    
    # Sensitive field patterns
    SENSITIVE_FIELD_PATTERNS = [
        r"password",
        r"passwd",
        r"secret",
        r"api_key",
        r"apikey",
        r"api-key",
        r"token",
        r"auth",
        r"credential",
        r"private",
        r"ssn",
        r"social_security",
        r"credit_card",
        r"creditcard",
        r"card_number",
        r"cvv",
        r"pin",
        r"bank_account",
        r"routing_number",
    ]
    
    # Error message patterns
    ERROR_PATTERNS = [
        (r"Exception in thread", "Java stack trace"),
        (r"Traceback \(most recent call last\)", "Python stack trace"),
        (r"at .+\.(java|py|js|rb|php):\d+", "Stack trace with line numbers"),
        (r"Fatal error:", "PHP fatal error"),
        (r"Warning:.*on line \d+", "PHP warning"),
        (r"<b>Fatal error</b>:", "PHP HTML error"),
        (r"Microsoft OLE DB Provider", "ASP/MSSQL error"),
        (r"ODBC.*Driver", "ODBC error"),
        (r"pg_query\(\):", "PostgreSQL error"),
        (r"mysql_fetch", "MySQL error"),
        (r"DEBUG\s*=\s*True", "Debug mode enabled"),
        (r"DJANGO_SETTINGS_MODULE", "Django settings exposed"),
        (r"Laravel", "Laravel framework error"),
        (r"Express|node_modules", "Node.js/Express error"),
    ]
    
    # Version disclosure patterns
    VERSION_PATTERNS = [
        (r"Apache/[\d.]+", "Apache version"),
        (r"nginx/[\d.]+", "Nginx version"),
        (r"PHP/[\d.]+", "PHP version"),
        (r"Python/[\d.]+", "Python version"),
        (r"Node\.js/[\d.]+", "Node.js version"),
        (r"Express/[\d.]+", "Express version"),
        (r"ASP\.NET[\s/][\d.]+", "ASP.NET version"),
        (r"X-Powered-By:\s*(.+)", "X-Powered-By header"),
    ]
    
    async def run(self, endpoint: dict) -> list[Finding]:
        """
        Test endpoint for information disclosure.
        """
        findings = []
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        self.log(f"Testing {method} {path} for information disclosure", "info")
        
        # Get normal response
        response = await self.requester.send(endpoint)
        
        # Test 1: Check for debug/error information in response
        debug_finding = self._check_debug_info(endpoint, response)
        if debug_finding:
            findings.append(debug_finding)
        
        # Test 2: Check for sensitive data in response
        sensitive_finding = self._check_sensitive_data(endpoint, response)
        if sensitive_finding:
            findings.append(sensitive_finding)
        
        # Test 3: Check for version disclosure in headers
        version_finding = self._check_version_headers(endpoint, response)
        if version_finding:
            findings.append(version_finding)
        
        # Test 4: Check for excessive data exposure
        excessive_finding = self._check_excessive_data(endpoint, response)
        if excessive_finding:
            findings.append(excessive_finding)
        
        # Test 5: Trigger error and check response
        error_finding = await self._trigger_error_response(endpoint)
        if error_finding:
            findings.append(error_finding)
        
        return findings
    
    def _check_debug_info(self, endpoint: dict, response) -> Optional[Finding]:
        """Check for debug information in response."""
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        found_patterns = []
        
        for pattern, description in self.ERROR_PATTERNS:
            if re.search(pattern, response.body, re.IGNORECASE):
                found_patterns.append(description)
        
        if found_patterns:
            return self.create_finding(
                severity=Severity.MEDIUM,
                endpoint=path,
                method=method,
                title="Debug/Error Information Disclosed",
                evidence=(
                    f"Response contains debug information: {', '.join(found_patterns[:3])}. "
                    f"This may reveal internal architecture and aid attackers."
                ),
                verification=(
                    f"1. Send request to {method} {path}\n"
                    f"       2. Examine response for stack traces or error details\n"
                    f"       3. Check if internal paths or versions are exposed"
                ),
                confidence=80,
                cwe_id="CWE-209",
                references=[
                    "https://cwe.mitre.org/data/definitions/209.html",
                ],
            )
        
        return None
    
    def _check_sensitive_data(self, endpoint: dict, response) -> Optional[Finding]:
        """Check for sensitive data fields in response."""
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        if not response.json_body:
            return None
        
        # Recursively search for sensitive field names
        sensitive_fields = []
        
        def search_fields(obj, prefix=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    full_key = f"{prefix}.{key}" if prefix else key
                    
                    for pattern in self.SENSITIVE_FIELD_PATTERNS:
                        if re.search(pattern, key, re.IGNORECASE):
                            # Check if value is non-empty and not masked
                            if value and not self._is_masked(value):
                                sensitive_fields.append((full_key, type(value).__name__))
                    
                    search_fields(value, full_key)
            elif isinstance(obj, list):
                for i, item in enumerate(obj[:3]):  # Check first 3 items
                    search_fields(item, f"{prefix}[{i}]")
        
        search_fields(response.json_body)
        
        if sensitive_fields:
            field_list = ", ".join([f[0] for f in sensitive_fields[:5]])
            return self.create_finding(
                severity=Severity.HIGH,
                endpoint=path,
                method=method,
                title="Sensitive Data Exposed in Response",
                evidence=(
                    f"Response contains potentially sensitive fields: {field_list}. "
                    f"Found {len(sensitive_fields)} sensitive field(s)."
                ),
                verification=(
                    f"1. Examine response JSON structure\n"
                    f"       2. Identify fields containing sensitive data\n"
                    f"       3. Verify if this data should be exposed"
                ),
                confidence=70,
                cwe_id="CWE-200",
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                    "https://cwe.mitre.org/data/definitions/200.html",
                ],
            )
        
        return None
    
    def _is_masked(self, value) -> bool:
        """Check if a value appears to be masked/redacted."""
        if not isinstance(value, str):
            return False
        
        # Common masking patterns
        masked_patterns = [
            r"^\*+$",           # All asterisks
            r"^x+$",            # All x's
            r"^\[REDACTED\]$",  # Redacted marker
            r"^\[HIDDEN\]$",    # Hidden marker
            r"^\.{3,}$",        # Dots
            r"^\*{4,}\d{4}$",   # Credit card mask (****1234)
        ]
        
        for pattern in masked_patterns:
            if re.match(pattern, value, re.IGNORECASE):
                return True
        
        return False
    
    def _check_version_headers(self, endpoint: dict, response) -> Optional[Finding]:
        """Check for version disclosure in headers."""
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        disclosed_versions = []
        headers_str = str(response.headers)
        
        # Check headers
        for header, value in response.headers.items():
            header_lower = header.lower()
            
            if header_lower == "x-powered-by":
                disclosed_versions.append(f"X-Powered-By: {value}")
            elif header_lower == "server":
                # Check if version number is included
                if re.search(r"[\d.]+", value):
                    disclosed_versions.append(f"Server: {value}")
        
        # Check body for version patterns
        for pattern, description in self.VERSION_PATTERNS:
            match = re.search(pattern, response.body)
            if match:
                disclosed_versions.append(f"{description}: {match.group()}")
        
        if disclosed_versions:
            return self.create_finding(
                severity=Severity.LOW,
                endpoint=path,
                method=method,
                title="Server Version Information Disclosed",
                evidence=(
                    f"Version information exposed: {'; '.join(disclosed_versions[:3])}. "
                    f"This helps attackers identify known vulnerabilities."
                ),
                verification=(
                    f"1. Check response headers for Server, X-Powered-By\n"
                    f"       2. Look for version numbers in error pages\n"
                    f"       3. Recommend removing version info in production"
                ),
                confidence=90,
                cwe_id="CWE-200",
            )
        
        return None
    
    def _check_excessive_data(self, endpoint: dict, response) -> Optional[Finding]:
        """Check for excessive data exposure."""
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        if not response.json_body:
            return None
        
        # Count fields in response
        field_count = 0
        
        def count_fields(obj):
            nonlocal field_count
            if isinstance(obj, dict):
                field_count += len(obj)
                for value in obj.values():
                    count_fields(value)
            elif isinstance(obj, list) and obj:
                count_fields(obj[0])
        
        count_fields(response.json_body)
        
        # Flag if response has many fields (potential over-exposure)
        if field_count > 30:
            return self.create_finding(
                severity=Severity.LOW,
                endpoint=path,
                method=method,
                title="Potentially Excessive Data Exposure",
                evidence=(
                    f"Response contains {field_count} fields. "
                    f"Large responses may expose unnecessary data."
                ),
                verification=(
                    f"1. Review all fields in the response\n"
                    f"       2. Identify fields not needed by the client\n"
                    f"       3. Consider implementing field filtering"
                ),
                confidence=40,
                cwe_id="CWE-213",
            )
        
        return None
    
    async def _trigger_error_response(self, endpoint: dict) -> Optional[Finding]:
        """Try to trigger an error response and check for verbose errors."""
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        # Try invalid input to trigger error
        import copy
        modified = copy.deepcopy(endpoint)
        
        # Add invalid parameter
        if "params" not in modified:
            modified["params"] = {}
        modified["params"]["__invalid__"] = "{{invalid}}"
        
        response = await self.requester.send(modified)
        
        # Check if error response is verbose
        if response.status_code >= 400:
            found_patterns = []
            
            for pattern, description in self.ERROR_PATTERNS:
                if re.search(pattern, response.body, re.IGNORECASE):
                    found_patterns.append(description)
            
            if found_patterns:
                return self.create_finding(
                    severity=Severity.MEDIUM,
                    endpoint=path,
                    method=method,
                    title="Verbose Error Messages on Invalid Input",
                    evidence=(
                        f"Error response ({response.status_code}) contains: "
                        f"{', '.join(found_patterns[:3])}. "
                        f"Verbose errors aid reconnaissance."
                    ),
                    verification=(
                        f"1. Send malformed request to trigger error\n"
                        f"       2. Check error response for stack traces\n"
                        f"       3. Look for internal paths or config details"
                    ),
                    confidence=75,
                    cwe_id="CWE-209",
                )
        
        return None
