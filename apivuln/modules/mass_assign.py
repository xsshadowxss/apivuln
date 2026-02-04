"""
Mass Assignment Vulnerability Detection Module

Detects when API endpoints accept and process unexpected fields
that could allow privilege escalation or data manipulation.

OWASP API Security Top 10: API6:2023
CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
"""

import copy
from typing import Optional
from .base import BaseModule, Finding, Severity
from ..config import MASS_ASSIGNMENT_FIELDS


class MassAssignmentModule(BaseModule):
    """
    Detects mass assignment vulnerabilities in API endpoints.
    """
    
    name = "mass_assign"
    description = "Mass Assignment Vulnerability Detection"
    version = "1.0"
    
    async def run(self, endpoint: dict) -> list[Finding]:
        """
        Test endpoint for mass assignment vulnerabilities.
        """
        findings = []
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        # Only test endpoints that accept body data
        if method not in ["POST", "PUT", "PATCH"]:
            self.log(f"Skipping {method} {path} - no body expected", "info")
            return findings
        
        body = endpoint.get("body", {})
        if not isinstance(body, dict):
            return findings
        
        self.log(f"Testing {method} {path} for mass assignment", "info")
        
        # Get baseline response
        baseline = await self.requester.send(endpoint)
        
        if not baseline.is_success:
            self.log(f"Baseline failed: {baseline.status_code}", "warning")
            return findings
        
        # Test each potentially dangerous field
        for field in MASS_ASSIGNMENT_FIELDS:
            # Skip if field already exists in body
            if field in body:
                continue
            
            finding = await self._test_field(endpoint, field, baseline)
            if finding:
                findings.append(finding)
        
        # Also test for hidden fields in response that aren't in request
        response_finding = await self._test_response_fields(endpoint, baseline)
        if response_finding:
            findings.append(response_finding)
        
        return findings
    
    async def _test_field(
        self,
        endpoint: dict,
        field: str,
        baseline
    ) -> Optional[Finding]:
        """Test if a specific field is accepted."""
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        # Create modified request with extra field
        modified = copy.deepcopy(endpoint)
        
        # Try different values based on field name
        test_value = self._get_test_value(field)
        modified["body"][field] = test_value
        
        response = await self.requester.send(modified)
        
        # Check if the field was accepted
        if response.is_success:
            # Check if field appears in response
            if self._field_in_response(field, test_value, response):
                return self.create_finding(
                    severity=Severity.HIGH,
                    endpoint=path,
                    method=method,
                    title=f"Mass Assignment: '{field}' Field Accepted",
                    evidence=(
                        f"Field '{field}' with value '{test_value}' was accepted and "
                        f"appears in response. This could allow privilege escalation."
                    ),
                    verification=(
                        f"1. Add '{field}': {test_value} to request body\n"
                        f"       2. Send {method} request to {path}\n"
                        f"       3. Verify the field value is persisted"
                    ),
                    confidence=80,
                    cwe_id="CWE-915",
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
                        "https://cwe.mitre.org/data/definitions/915.html",
                    ],
                )
            
            # Field might be accepted but not returned
            # Check if response differs from baseline
            if self._response_indicates_acceptance(response, baseline, field):
                return self.create_finding(
                    severity=Severity.MEDIUM,
                    endpoint=path,
                    method=method,
                    title=f"Potential Mass Assignment: '{field}' May Be Accepted",
                    evidence=(
                        f"Response changed when '{field}' was added to request. "
                        f"The field may be processed server-side."
                    ),
                    verification=(
                        f"1. Add '{field}' to request body\n"
                        f"       2. Check if server behavior changes\n"
                        f"       3. Verify in database or via GET request"
                    ),
                    confidence=50,
                    cwe_id="CWE-915",
                )
        
        return None
    
    async def _test_response_fields(
        self,
        endpoint: dict,
        baseline
    ) -> Optional[Finding]:
        """Check for sensitive fields in response that could be mass-assigned."""
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        body = endpoint.get("body", {})
        
        if not baseline.json_body:
            return None
        
        # Extract fields from response
        response_fields = self._extract_fields(baseline.json_body)
        request_fields = set(body.keys()) if body else set()
        
        # Find sensitive fields in response that weren't in request
        hidden_sensitive = []
        for field in response_fields:
            if field not in request_fields:
                for sensitive in MASS_ASSIGNMENT_FIELDS:
                    if sensitive.lower() in field.lower():
                        hidden_sensitive.append(field)
                        break
        
        if hidden_sensitive:
            return self.create_finding(
                severity=Severity.LOW,
                endpoint=path,
                method=method,
                title="Sensitive Fields in Response",
                evidence=(
                    f"Response contains sensitive fields not in request: "
                    f"{', '.join(hidden_sensitive[:5])}. "
                    f"These may be vulnerable to mass assignment."
                ),
                verification=(
                    f"1. Note the sensitive fields in response\n"
                    f"       2. Try adding these fields to your request body\n"
                    f"       3. Check if values are accepted and persisted"
                ),
                confidence=40,
                cwe_id="CWE-915",
            )
        
        return None
    
    def _get_test_value(self, field: str):
        """Get an appropriate test value for a field."""
        field_lower = field.lower()
        
        if "admin" in field_lower or "role" in field_lower:
            return True
        if "privilege" in field_lower or "permission" in field_lower:
            return ["admin", "write", "delete"]
        if "balance" in field_lower or "credit" in field_lower:
            return 999999
        if "verified" in field_lower or "active" in field_lower:
            return True
        if "type" in field_lower:
            return "admin"
        if "plan" in field_lower or "subscription" in field_lower:
            return "premium"
        
        return True
    
    def _field_in_response(self, field: str, value, response) -> bool:
        """Check if field with value appears in response."""
        if not response.json_body:
            return False
        
        def search_json(obj, target_field, target_value):
            if isinstance(obj, dict):
                for key, val in obj.items():
                    if key.lower() == target_field.lower():
                        if val == target_value:
                            return True
                    if search_json(val, target_field, target_value):
                        return True
            elif isinstance(obj, list):
                for item in obj:
                    if search_json(item, target_field, target_value):
                        return True
            return False
        
        return search_json(response.json_body, field, value)
    
    def _response_indicates_acceptance(self, response, baseline, field: str) -> bool:
        """Check if response suggests the field was processed."""
        # Different response length might indicate processing
        len_diff = abs(len(response.body) - len(baseline.body))
        if len_diff > 10:
            return True
        
        # Check for field name in response
        if field.lower() in response.body.lower():
            return True
        
        return False
    
    def _extract_fields(self, obj, prefix="") -> set:
        """Extract all field names from JSON object."""
        fields = set()
        
        if isinstance(obj, dict):
            for key, value in obj.items():
                full_key = f"{prefix}.{key}" if prefix else key
                fields.add(full_key)
                fields.update(self._extract_fields(value, full_key))
        elif isinstance(obj, list) and obj:
            fields.update(self._extract_fields(obj[0], prefix))
        
        return fields
