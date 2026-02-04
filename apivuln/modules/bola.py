"""
BOLA (Broken Object Level Authorization) / IDOR Detection Module

Detects when API endpoints allow access to objects belonging to other users
by manipulating object identifiers.

OWASP API Security Top 10: API1:2023
CWE-639: Authorization Bypass Through User-Controlled Key
"""

from .base import BaseModule, Finding, Severity


class BOLAModule(BaseModule):
    """
    Detects Broken Object Level Authorization vulnerabilities.
    
    Tests if changing ID parameters allows access to other users' data.
    """
    
    name = "bola"
    description = "Broken Object Level Authorization (IDOR) Detection"
    version = "1.0"
    
    # Test IDs to try
    TEST_IDS = [
        "1", "2", "0", "999", "9999",
        "00000000-0000-0000-0000-000000000001",  # UUID
        "00000000-0000-0000-0000-000000000002",
        "admin", "root", "test",
    ]
    
    async def run(self, endpoint: dict) -> list[Finding]:
        """
        Test endpoint for BOLA/IDOR vulnerabilities.
        """
        findings = []
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        # Get ID-like parameters
        id_params = self.get_id_params(endpoint)
        
        if not id_params:
            self.log(f"No ID parameters found in {path}", "info")
            return findings
        
        self.log(f"Testing {path} for BOLA with params: {id_params}", "info")
        
        # Get baseline response with original ID
        baseline = await self.requester.send(endpoint)
        
        if not baseline.is_success:
            self.log(f"Baseline request failed with status {baseline.status_code}", "warning")
            return findings
        
        # Test each ID parameter
        for param in id_params:
            original_value = endpoint.get("params", {}).get(param)
            
            for test_id in self.TEST_IDS:
                # Skip if same as original
                if str(test_id) == str(original_value):
                    continue
                
                # Create modified endpoint
                modified = self.swap_param(endpoint, param, test_id)
                
                # Send request
                response = await self.requester.send(modified)
                
                # Analyze response
                if self.analyzer.indicates_data_access(response, baseline):
                    confidence = self._calculate_confidence(response, baseline)
                    
                    findings.append(self.create_finding(
                        severity=Severity.HIGH,
                        endpoint=path,
                        method=method,
                        title="Potential BOLA/IDOR Vulnerability",
                        evidence=(
                            f"Changing {param} from '{original_value}' to '{test_id}' "
                            f"returned different data with same authentication. "
                            f"Response status: {response.status_code}, "
                            f"Body length: {len(response.body)} bytes"
                        ),
                        verification=(
                            f"1. Send request to {path} with {param}={original_value}\n"
                            f"       2. Send same request with {param}={test_id}\n"
                            f"       3. Verify the second request returns another user's data"
                        ),
                        confidence=confidence,
                        cwe_id="CWE-639",
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                            "https://cwe.mitre.org/data/definitions/639.html",
                        ],
                    ))
                    
                    # Found vulnerability, no need to test more IDs for this param
                    break
        
        return findings
    
    def _calculate_confidence(self, response, baseline) -> int:
        """Calculate confidence score based on response analysis."""
        confidence = 50  # Base confidence
        
        # Higher confidence if JSON response with different IDs
        if response.json_body and baseline.json_body:
            if self._has_different_id(response.json_body, baseline.json_body):
                confidence += 25
        
        # Higher confidence if similar response structure
        similarity = self.analyzer.similarity(response, baseline)
        if 0.3 < similarity < 0.9:
            confidence += 15
        
        # Lower confidence if response is error-like
        if self.analyzer.has_error_patterns(response):
            confidence -= 20
        
        return max(0, min(100, confidence))
    
    def _has_different_id(self, json1: dict, json2: dict) -> bool:
        """Check if JSON responses have different ID values."""
        id_fields = ["id", "_id", "user_id", "userId", "account_id", "uuid"]
        
        for field in id_fields:
            val1 = self._get_nested_value(json1, field)
            val2 = self._get_nested_value(json2, field)
            
            if val1 is not None and val2 is not None and val1 != val2:
                return True
        
        return False
    
    def _get_nested_value(self, obj, key):
        """Get value from nested dict/list structure."""
        if isinstance(obj, dict):
            if key in obj:
                return obj[key]
            for v in obj.values():
                result = self._get_nested_value(v, key)
                if result is not None:
                    return result
        elif isinstance(obj, list) and obj:
            return self._get_nested_value(obj[0], key)
        return None
