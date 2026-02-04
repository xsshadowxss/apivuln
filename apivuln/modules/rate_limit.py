"""
Rate Limiting Detection Module

Detects missing or inadequate rate limiting on API endpoints,
which can lead to brute force attacks, DoS, or resource exhaustion.

OWASP API Security Top 10: API4:2023
CWE-770: Allocation of Resources Without Limits
"""

import asyncio
import time
from .base import BaseModule, Finding, Severity


class RateLimitModule(BaseModule):
    """
    Detects missing or weak rate limiting on API endpoints.
    """
    
    name = "rate_limit"
    description = "Rate Limiting Detection"
    version = "1.0"
    
    # Endpoints that should definitely have rate limiting
    SENSITIVE_PATTERNS = [
        "/login",
        "/signin",
        "/auth",
        "/authenticate",
        "/register",
        "/signup",
        "/password",
        "/reset",
        "/forgot",
        "/verify",
        "/otp",
        "/2fa",
        "/mfa",
        "/token",
    ]
    
    async def run(self, endpoint: dict) -> list[Finding]:
        """
        Test endpoint for rate limiting.
        """
        findings = []
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        # Determine test parameters
        is_sensitive = self._is_sensitive_endpoint(path)
        
        # Use config values or defaults
        num_requests = 50 if is_sensitive else 30
        time_period = 5  # seconds
        
        if self.config:
            num_requests = self.config.rate_limit_requests
            time_period = self.config.rate_limit_period
        
        self.log(f"Testing rate limiting on {method} {path} ({num_requests} requests)", "info")
        
        # Send rapid requests
        results = await self._send_rapid_requests(endpoint, num_requests, time_period)
        
        # Analyze results
        finding = self._analyze_rate_limit_results(
            endpoint, results, num_requests, time_period, is_sensitive
        )
        
        if finding:
            findings.append(finding)
        
        return findings
    
    def _is_sensitive_endpoint(self, path: str) -> bool:
        """Check if endpoint is authentication-related."""
        path_lower = path.lower()
        return any(pattern in path_lower for pattern in self.SENSITIVE_PATTERNS)
    
    async def _send_rapid_requests(
        self,
        endpoint: dict,
        num_requests: int,
        time_period: int
    ) -> dict:
        """
        Send multiple requests rapidly and collect results.
        """
        results = {
            "total": num_requests,
            "success": 0,
            "rate_limited": 0,
            "errors": 0,
            "status_codes": {},
            "response_times": [],
            "start_time": time.time(),
        }
        
        # Send requests concurrently in batches
        batch_size = 10
        
        for i in range(0, num_requests, batch_size):
            batch = min(batch_size, num_requests - i)
            tasks = [
                self.requester.send(endpoint)
                for _ in range(batch)
            ]
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            for response in responses:
                if isinstance(response, Exception):
                    results["errors"] += 1
                    continue
                
                status = response.status_code
                results["status_codes"][status] = results["status_codes"].get(status, 0) + 1
                results["response_times"].append(response.elapsed)
                
                if response.is_success:
                    results["success"] += 1
                elif status == 429:
                    results["rate_limited"] += 1
                elif status in [401, 403]:
                    # Might be rate limiting via auth failure
                    pass
                else:
                    results["errors"] += 1
        
        results["end_time"] = time.time()
        results["duration"] = results["end_time"] - results["start_time"]
        
        return results
    
    def _analyze_rate_limit_results(
        self,
        endpoint: dict,
        results: dict,
        num_requests: int,
        time_period: int,
        is_sensitive: bool
    ) -> Finding:
        """
        Analyze rate limit test results and create finding if vulnerable.
        """
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        success_rate = results["success"] / results["total"] * 100
        rate_limited = results["rate_limited"]
        
        # Check for rate limit headers in responses
        has_rate_limit_headers = False  # Would need to track headers
        
        # Determine if rate limiting is missing
        if rate_limited == 0 and success_rate > 80:
            # No rate limiting detected
            severity = Severity.HIGH if is_sensitive else Severity.MEDIUM
            confidence = 85 if is_sensitive else 70
            
            avg_response_time = (
                sum(results["response_times"]) / len(results["response_times"])
                if results["response_times"] else 0
            )
            
            return self.create_finding(
                severity=severity,
                endpoint=path,
                method=method,
                title="Missing Rate Limiting",
                evidence=(
                    f"Sent {num_requests} requests in {results['duration']:.1f}s. "
                    f"Success rate: {success_rate:.0f}%. "
                    f"Rate limited: {rate_limited}. "
                    f"Avg response time: {avg_response_time*1000:.0f}ms. "
                    f"Status codes: {dict(results['status_codes'])}"
                ),
                verification=(
                    f"1. Send {num_requests}+ rapid requests to {method} {path}\n"
                    f"       2. Count successful responses\n"
                    f"       3. Verify no 429 responses or blocking occurs"
                ),
                confidence=confidence,
                cwe_id="CWE-770",
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
                    "https://cwe.mitre.org/data/definitions/770.html",
                ],
            )
        
        # Check for weak rate limiting (allows too many)
        if rate_limited > 0 and rate_limited < num_requests * 0.3:
            # Some rate limiting but may be too permissive
            requests_before_limit = num_requests - rate_limited
            
            if is_sensitive and requests_before_limit > 20:
                return self.create_finding(
                    severity=Severity.MEDIUM,
                    endpoint=path,
                    method=method,
                    title="Weak Rate Limiting",
                    evidence=(
                        f"Rate limiting triggered after ~{requests_before_limit} requests. "
                        f"This may be too permissive for authentication endpoints."
                    ),
                    verification=(
                        f"1. Send requests until rate limited\n"
                        f"       2. Count allowed requests\n"
                        f"       3. Evaluate if limit is appropriate for this endpoint"
                    ),
                    confidence=60,
                    cwe_id="CWE-770",
                )
        
        return None
