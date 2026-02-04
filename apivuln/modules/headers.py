"""
Security Headers Detection Module

Detects missing or misconfigured security headers that could
leave the application vulnerable to various attacks.

References: OWASP Secure Headers Project
"""

from typing import Optional, List, Tuple
from .base import BaseModule, Finding, Severity


class HeadersModule(BaseModule):
    """
    Detects missing or misconfigured security headers.
    
    Checks for:
    - Content-Security-Policy
    - X-Content-Type-Options
    - X-Frame-Options
    - Strict-Transport-Security
    - X-XSS-Protection (legacy)
    - Cache-Control for sensitive endpoints
    - Cookie security attributes
    """
    
    name = "headers"
    description = "Security Headers Analysis"
    version = "1.0"
    
    # Required security headers and their descriptions
    SECURITY_HEADERS = {
        "Content-Security-Policy": {
            "description": "Prevents XSS and injection attacks",
            "severity": Severity.MEDIUM,
        },
        "X-Content-Type-Options": {
            "description": "Prevents MIME-type sniffing",
            "severity": Severity.LOW,
            "expected": "nosniff",
        },
        "X-Frame-Options": {
            "description": "Prevents clickjacking",
            "severity": Severity.MEDIUM,
            "expected": ["DENY", "SAMEORIGIN"],
        },
        "Strict-Transport-Security": {
            "description": "Enforces HTTPS connections",
            "severity": Severity.MEDIUM,
        },
        "Referrer-Policy": {
            "description": "Controls referrer information leakage",
            "severity": Severity.LOW,
        },
        "Permissions-Policy": {
            "description": "Controls browser features",
            "severity": Severity.LOW,
        },
    }
    
    # Headers that should NOT be present
    BAD_HEADERS = {
        "X-Powered-By": "Reveals technology stack",
        "Server": "May reveal version information",
        "X-AspNet-Version": "Reveals ASP.NET version",
        "X-AspNetMvc-Version": "Reveals ASP.NET MVC version",
    }
    
    async def run(self, endpoint: dict) -> list[Finding]:
        """Analyze security headers for endpoint."""
        findings = []
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        self.log(f"Analyzing headers for {method} {path}", "info")
        
        response = await self.requester.send(endpoint)
        
        # Check for missing security headers
        missing_findings = self._check_missing_headers(endpoint, response)
        findings.extend(missing_findings)
        
        # Check for dangerous headers
        bad_findings = self._check_bad_headers(endpoint, response)
        findings.extend(bad_findings)
        
        # Check cookie security
        cookie_findings = self._check_cookie_security(endpoint, response)
        findings.extend(cookie_findings)
        
        # Check cache headers for sensitive endpoints
        cache_findings = self._check_cache_headers(endpoint, response)
        findings.extend(cache_findings)
        
        return findings
    
    def _check_missing_headers(self, endpoint: dict, response) -> List[Finding]:
        """Check for missing security headers."""
        findings = []
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        missing = []
        
        for header, config in self.SECURITY_HEADERS.items():
            value = response.headers.get(header)
            
            if not value:
                missing.append((header, config["description"], config["severity"]))
            elif "expected" in config:
                expected = config["expected"]
                if isinstance(expected, list):
                    if value.upper() not in [e.upper() for e in expected]:
                        missing.append((
                            header,
                            f"{config['description']} (unexpected value: {value})",
                            config["severity"]
                        ))
                elif value.lower() != expected.lower():
                    missing.append((
                        header,
                        f"{config['description']} (expected: {expected}, got: {value})",
                        config["severity"]
                    ))
        
        if missing:
            # Group by severity
            high_missing = [m for m in missing if m[2] in [Severity.HIGH, Severity.CRITICAL]]
            medium_missing = [m for m in missing if m[2] == Severity.MEDIUM]
            low_missing = [m for m in missing if m[2] == Severity.LOW]
            
            if high_missing or medium_missing:
                severity = Severity.MEDIUM if medium_missing else Severity.LOW
                header_list = ", ".join([m[0] for m in (high_missing + medium_missing)[:5]])
                
                findings.append(self.create_finding(
                    severity=severity,
                    endpoint=path,
                    method=method,
                    title="Missing Security Headers",
                    evidence=(
                        f"Missing headers: {header_list}. "
                        f"Total missing: {len(missing)}"
                    ),
                    verification=(
                        f"1. Inspect response headers\n"
                        f"       2. Add missing security headers to server config\n"
                        f"       3. Test that headers are correctly applied"
                    ),
                    confidence=95,
                    cwe_id="CWE-693",
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                    ],
                ))
        
        return findings
    
    def _check_bad_headers(self, endpoint: dict, response) -> List[Finding]:
        """Check for headers that should not be present."""
        findings = []
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        present = []
        
        for header, reason in self.BAD_HEADERS.items():
            value = response.headers.get(header)
            if value:
                present.append((header, value, reason))
        
        if present:
            header_info = "; ".join([f"{h[0]}: {h[1]}" for h in present[:3]])
            
            findings.append(self.create_finding(
                severity=Severity.LOW,
                endpoint=path,
                method=method,
                title="Information Disclosure via Headers",
                evidence=(
                    f"Headers revealing server info: {header_info}. "
                    f"This aids attacker reconnaissance."
                ),
                verification=(
                    f"1. Check response headers\n"
                    f"       2. Configure server to remove these headers\n"
                    f"       3. Verify headers are no longer present"
                ),
                confidence=90,
                cwe_id="CWE-200",
            ))
        
        return findings
    
    def _check_cookie_security(self, endpoint: dict, response) -> List[Finding]:
        """Check for insecure cookie attributes."""
        findings = []
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        set_cookie = response.headers.get("Set-Cookie", "")
        
        if not set_cookie:
            return findings
        
        issues = []
        
        # Check for missing security attributes
        cookie_lower = set_cookie.lower()
        
        if "httponly" not in cookie_lower:
            issues.append("Missing HttpOnly flag")
        
        if "secure" not in cookie_lower:
            issues.append("Missing Secure flag")
        
        if "samesite" not in cookie_lower:
            issues.append("Missing SameSite attribute")
        elif "samesite=none" in cookie_lower and "secure" not in cookie_lower:
            issues.append("SameSite=None without Secure flag")
        
        if issues:
            findings.append(self.create_finding(
                severity=Severity.MEDIUM,
                endpoint=path,
                method=method,
                title="Insecure Cookie Configuration",
                evidence=(
                    f"Cookie security issues: {', '.join(issues)}. "
                    f"This may allow session hijacking or CSRF."
                ),
                verification=(
                    f"1. Inspect Set-Cookie header\n"
                    f"       2. Add missing security attributes\n"
                    f"       3. Verify cookies are properly protected"
                ),
                confidence=90,
                cwe_id="CWE-614",
            ))
        
        return findings
    
    def _check_cache_headers(self, endpoint: dict, response) -> List[Finding]:
        """Check cache headers for sensitive endpoints."""
        findings = []
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        # Check if this looks like a sensitive endpoint
        sensitive_patterns = [
            "/user", "/account", "/profile", "/admin",
            "/settings", "/password", "/auth", "/login",
            "/token", "/session", "/private"
        ]
        
        is_sensitive = any(p in path.lower() for p in sensitive_patterns)
        
        if not is_sensitive:
            return findings
        
        cache_control = response.headers.get("Cache-Control", "").lower()
        pragma = response.headers.get("Pragma", "").lower()
        
        # Check if caching is properly disabled
        if "no-store" not in cache_control and "no-cache" not in cache_control:
            findings.append(self.create_finding(
                severity=Severity.LOW,
                endpoint=path,
                method=method,
                title="Sensitive Endpoint May Be Cached",
                evidence=(
                    f"Cache-Control header does not prevent caching. "
                    f"Current value: '{cache_control or 'not set'}'. "
                    f"Sensitive data may be stored in browser/proxy cache."
                ),
                verification=(
                    f"1. Check Cache-Control and Pragma headers\n"
                    f"       2. Add 'Cache-Control: no-store, no-cache'\n"
                    f"       3. Verify caching is disabled for sensitive endpoints"
                ),
                confidence=70,
                cwe_id="CWE-525",
            ))
        
        return findings
