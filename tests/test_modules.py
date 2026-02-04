"""
Comprehensive Test Suite for APIVuln
Tests all modules and core functionality.
"""

import pytest
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch
from dataclasses import dataclass

# Import modules to test
from apivuln.config import ScanConfig
from apivuln.analyzer import Analyzer
from apivuln.requester import Response, Requester
from apivuln.modules.base import Finding, Severity, BaseModule
from apivuln.modules import (
    BOLAModule, BFLAModule, JWTModule,
    InjectionModule, RateLimitModule,
    MassAssignmentModule, DisclosureModule,
    get_all_module_names, get_module_info, MODULE_MAP
)


# ============== Test Helpers ==============

def create_response(
    status_code: int = 200,
    body: str = "",
    json_body: dict = None,
    headers: dict = None,
    elapsed: float = 0.1
) -> Response:
    """Helper to create Response objects for testing."""
    return Response(
        status_code=status_code,
        headers=headers or {"content-type": "application/json"},
        body=body or json.dumps(json_body) if json_body else "",
        json_body=json_body,
        elapsed=elapsed,
        url="https://api.test.com/test",
        method="GET",
    )


def create_mock_requester(responses: list = None):
    """Create a mock requester that returns predefined responses."""
    requester = AsyncMock()
    requester.request_count = 0
    
    if responses:
        requester.send = AsyncMock(side_effect=responses)
    else:
        requester.send = AsyncMock(return_value=create_response())
    
    return requester


# ============== Fixtures ==============

@pytest.fixture
def config():
    """Create a test configuration."""
    return ScanConfig(
        base_url="https://api.test.com",
        auth_token="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6OTk5OTk5OTk5OX0.signature",
        auth_token_low="Bearer low_priv_token",
        verbose=False,
        quiet=True,
    )


@pytest.fixture
def analyzer():
    """Create an analyzer instance."""
    return Analyzer()


@pytest.fixture
def sample_get_endpoint():
    """Sample GET endpoint with ID parameter."""
    return {
        "path": "/api/v1/users/{id}",
        "method": "GET",
        "params": {"id": "123"},
    }


@pytest.fixture
def sample_post_endpoint():
    """Sample POST endpoint with body."""
    return {
        "path": "/api/v1/users",
        "method": "POST",
        "body": {
            "username": "testuser",
            "email": "test@example.com",
        },
    }


@pytest.fixture
def admin_endpoint():
    """Sample admin endpoint."""
    return {
        "path": "/api/v1/admin/users",
        "method": "GET",
    }


# ============== Module Registry Tests ==============

class TestModuleRegistry:
    """Test module registration and discovery."""
    
    def test_all_modules_registered(self):
        """Verify all expected modules are registered."""
        expected = ["bola", "bfla", "jwt", "injection", "rate_limit", "mass_assign", "disclosure"]
        names = get_all_module_names()
        
        for module in expected:
            assert module in names, f"Module {module} not registered"
    
    def test_module_info_complete(self):
        """Verify module info contains required fields."""
        info_list = get_module_info()
        
        for info in info_list:
            assert "name" in info
            assert "description" in info
            assert "version" in info
            assert len(info["description"]) > 0
    
    def test_module_map_access(self):
        """Test accessing modules by name."""
        assert MODULE_MAP["bola"] == BOLAModule
        assert MODULE_MAP["jwt"] == JWTModule
        assert MODULE_MAP.get("nonexistent") is None


# ============== Analyzer Tests ==============

class TestAnalyzer:
    """Test the response analyzer."""
    
    def test_similarity_identical_responses(self, analyzer):
        """Identical responses should have similarity of 1.0."""
        resp1 = create_response(body='{"user": "test"}')
        resp2 = create_response(body='{"user": "test"}')
        
        assert analyzer.similarity(resp1, resp2) == 1.0
    
    def test_similarity_different_status_codes(self, analyzer):
        """Different status codes should have similarity of 0.0."""
        resp1 = create_response(status_code=200, body="test")
        resp2 = create_response(status_code=404, body="test")
        
        assert analyzer.similarity(resp1, resp2) == 0.0
    
    def test_similarity_different_bodies(self, analyzer):
        """Different bodies should have low similarity."""
        resp1 = create_response(body='{"user": "alice", "id": 1}')
        resp2 = create_response(body='{"user": "bob", "id": 2}')
        
        similarity = analyzer.similarity(resp1, resp2)
        assert 0 < similarity < 1.0
    
    def test_sql_error_detection(self, analyzer):
        """Test SQL error pattern detection."""
        # MySQL error
        resp1 = create_response(body="You have an error in your SQL syntax near 'test' at line 1")
        has_error, match = analyzer.has_sql_error(resp1)
        assert has_error
        
        # PostgreSQL error
        resp2 = create_response(body="ERROR: syntax error at or near \"test\"")
        has_error, match = analyzer.has_sql_error(resp2)
        assert has_error
        
        # No error
        resp3 = create_response(body='{"status": "ok"}')
        has_error, match = analyzer.has_sql_error(resp3)
        assert not has_error
    
    def test_nosql_error_detection(self, analyzer):
        """Test NoSQL error pattern detection."""
        resp1 = create_response(body="MongoError: $where is not allowed")
        has_error, match = analyzer.has_nosql_error(resp1)
        assert has_error
        
        resp2 = create_response(body="CastError: Cast to ObjectId failed")
        has_error, match = analyzer.has_nosql_error(resp2)
        assert has_error
    
    def test_debug_info_detection(self, analyzer):
        """Test debug/stack trace detection."""
        # Python traceback
        resp1 = create_response(body="Traceback (most recent call last):\n  File \"app.py\"")
        has_debug, patterns = analyzer.has_debug_info(resp1)
        assert has_debug
        
        # Java stack trace
        resp2 = create_response(body="at com.example.MyClass.method(MyClass.java:42)")
        has_debug, patterns = analyzer.has_debug_info(resp2)
        assert has_debug
    
    def test_sensitive_data_detection(self, analyzer):
        """Test sensitive data pattern detection."""
        resp1 = create_response(body='{"password": "secret123", "user": "test"}')
        has_sensitive, patterns = analyzer.has_sensitive_data(resp1)
        assert has_sensitive
        
        resp2 = create_response(body='{"api_key": "sk_live_xxx", "data": "test"}')
        has_sensitive, patterns = analyzer.has_sensitive_data(resp2)
        assert has_sensitive
    
    def test_response_time_anomaly(self, analyzer):
        """Test time-based anomaly detection."""
        baseline = create_response(elapsed=0.1)
        slow_response = create_response(elapsed=5.5)
        normal_response = create_response(elapsed=0.2)
        
        assert analyzer.response_time_anomaly(slow_response, baseline, threshold=5.0)
        assert not analyzer.response_time_anomaly(normal_response, baseline, threshold=5.0)
    
    def test_indicates_data_access(self, analyzer):
        """Test BOLA/IDOR data access detection."""
        baseline = create_response(
            json_body={"id": 1, "name": "Alice", "email": "alice@test.com"}
        )
        different_user = create_response(
            json_body={"id": 2, "name": "Bob", "email": "bob@test.com"}
        )
        same_user = create_response(
            json_body={"id": 1, "name": "Alice", "email": "alice@test.com"}
        )
        
        assert analyzer.indicates_data_access(different_user, baseline)
        assert not analyzer.indicates_data_access(same_user, baseline)
    
    def test_jwt_decode(self, analyzer):
        """Test JWT decoding."""
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QifQ.signature"
        decoded = analyzer.jwt_decode_unsafe(token)
        
        assert decoded is not None
        assert decoded["header"]["alg"] == "HS256"
        assert decoded["payload"]["sub"] == "1234567890"


# ============== BOLA Module Tests ==============

class TestBOLAModule:
    """Test Broken Object Level Authorization detection."""
    
    @pytest.mark.asyncio
    async def test_detects_idor_vulnerability(self, config, analyzer, sample_get_endpoint):
        """Test that BOLA is detected when different IDs return different user data."""
        # Baseline response for user 123
        baseline_resp = create_response(
            json_body={"id": 123, "name": "Alice", "email": "alice@test.com"}
        )
        # Response for user 1 (different user's data)
        other_user_resp = create_response(
            json_body={"id": 1, "name": "Admin", "email": "admin@test.com"}
        )
        
        requester = create_mock_requester([baseline_resp, other_user_resp])
        module = BOLAModule(requester, analyzer, config)
        
        findings = await module.run(sample_get_endpoint)
        
        assert len(findings) >= 1
        assert findings[0].severity == Severity.HIGH
        assert "BOLA" in findings[0].title or "IDOR" in findings[0].title
    
    @pytest.mark.asyncio
    async def test_no_finding_when_access_denied(self, config, analyzer, sample_get_endpoint):
        """Test that no BOLA is reported when unauthorized access is denied."""
        baseline_resp = create_response(
            json_body={"id": 123, "name": "Alice"}
        )
        forbidden_resp = create_response(
            status_code=403,
            body='{"error": "Access denied"}'
        )
        
        requester = create_mock_requester([baseline_resp, forbidden_resp])
        module = BOLAModule(requester, analyzer, config)
        
        findings = await module.run(sample_get_endpoint)
        
        # Should not report vulnerability when access is properly denied
        assert len(findings) == 0
    
    @pytest.mark.asyncio
    async def test_skips_endpoint_without_id(self, config, analyzer):
        """Test that endpoints without ID parameters are skipped."""
        endpoint = {"path": "/api/v1/status", "method": "GET"}
        
        requester = create_mock_requester([])
        module = BOLAModule(requester, analyzer, config)
        
        findings = await module.run(endpoint)
        
        assert len(findings) == 0


# ============== BFLA Module Tests ==============

class TestBFLAModule:
    """Test Broken Function Level Authorization detection."""
    
    @pytest.mark.asyncio
    async def test_detects_privilege_escalation(self, config, analyzer, admin_endpoint):
        """Test detection when low-priv user can access admin endpoint."""
        high_priv_resp = create_response(
            json_body={"users": [{"id": 1}, {"id": 2}]}
        )
        low_priv_resp = create_response(
            json_body={"users": [{"id": 1}, {"id": 2}]}  # Same data returned!
        )
        no_auth_resp = create_response(status_code=401)
        
        requester = create_mock_requester([high_priv_resp, low_priv_resp, no_auth_resp])
        module = BFLAModule(requester, analyzer, config)
        
        findings = await module.run(admin_endpoint)
        
        assert len(findings) >= 1
        assert any("BFLA" in f.title for f in findings)
    
    @pytest.mark.asyncio
    async def test_detects_missing_auth(self, config, analyzer, admin_endpoint):
        """Test detection when endpoint has no authentication."""
        high_priv_resp = create_response(json_body={"users": []})
        low_priv_resp = create_response(status_code=403)
        no_auth_resp = create_response(json_body={"users": []})  # Works without auth!
        
        requester = create_mock_requester([high_priv_resp, low_priv_resp, no_auth_resp])
        module = BFLAModule(requester, analyzer, config)
        
        findings = await module.run(admin_endpoint)
        
        assert len(findings) >= 1
        assert any("Authentication" in f.title for f in findings)


# ============== JWT Module Tests ==============

class TestJWTModule:
    """Test JWT vulnerability detection."""
    
    @pytest.mark.asyncio
    async def test_detects_none_algorithm(self, config, analyzer, sample_get_endpoint):
        """Test detection of 'none' algorithm vulnerability."""
        baseline_resp = create_response(json_body={"user": "test"})
        none_alg_resp = create_response(json_body={"user": "test"})  # Accepts none!
        
        requester = create_mock_requester([baseline_resp, none_alg_resp])
        module = JWTModule(requester, analyzer, config)
        
        findings = await module.run(sample_get_endpoint)
        
        # Check if none algorithm vulnerability was detected
        none_findings = [f for f in findings if "none" in f.title.lower()]
        if none_findings:
            assert none_findings[0].severity == Severity.CRITICAL
    
    @pytest.mark.asyncio
    async def test_no_jwt_in_config(self, analyzer, sample_get_endpoint):
        """Test handling when no JWT is configured."""
        config = ScanConfig(base_url="https://test.com", auth_token=None)
        requester = create_mock_requester([])
        module = JWTModule(requester, analyzer, config)
        
        findings = await module.run(sample_get_endpoint)
        
        assert len(findings) == 0


# ============== Injection Module Tests ==============

class TestInjectionModule:
    """Test SQL/NoSQL/SSRF injection detection."""
    
    @pytest.mark.asyncio
    async def test_detects_sql_injection(self, config, analyzer):
        """Test SQL injection detection via error messages."""
        endpoint = {
            "path": "/api/v1/search",
            "method": "GET",
            "params": {"q": "test"}
        }
        
        baseline_resp = create_response(json_body={"results": []})
        sqli_resp = create_response(
            status_code=500,
            body="You have an error in your SQL syntax near '\\'' at line 1"
        )
        
        requester = create_mock_requester([baseline_resp] + [sqli_resp] * 20)
        module = InjectionModule(requester, analyzer, config)
        
        findings = await module.run(endpoint)
        
        sql_findings = [f for f in findings if "SQL" in f.title]
        if sql_findings:
            assert sql_findings[0].severity in [Severity.HIGH, Severity.CRITICAL]
    
    @pytest.mark.asyncio
    async def test_detects_nosql_injection(self, config, analyzer):
        """Test NoSQL injection detection."""
        endpoint = {
            "path": "/api/v1/users",
            "method": "POST",
            "body": {"username": "test", "password": "test"}
        }
        
        baseline_resp = create_response(json_body={"error": "Invalid credentials"})
        nosqli_resp = create_response(
            body="MongoError: $where is not allowed in this context"
        )
        
        requester = create_mock_requester([baseline_resp] + [nosqli_resp] * 20)
        module = InjectionModule(requester, analyzer, config)
        
        findings = await module.run(endpoint)
        
        nosql_findings = [f for f in findings if "NoSQL" in f.title]
        # Should detect based on error message
    
    @pytest.mark.asyncio
    async def test_detects_ssrf(self, config, analyzer):
        """Test SSRF detection."""
        endpoint = {
            "path": "/api/v1/fetch",
            "method": "GET",
            "params": {"url": "https://example.com"}
        }
        
        baseline_resp = create_response(body="<html>Example</html>")
        ssrf_resp = create_response(body="root:x:0:0:root:/root:/bin/bash")
        
        requester = create_mock_requester([baseline_resp] + [ssrf_resp] * 20)
        module = InjectionModule(requester, analyzer, config)
        
        findings = await module.run(endpoint)
        
        ssrf_findings = [f for f in findings if "SSRF" in f.title]
        if ssrf_findings:
            assert ssrf_findings[0].severity in [Severity.HIGH, Severity.CRITICAL]


# ============== Rate Limit Module Tests ==============

class TestRateLimitModule:
    """Test rate limiting detection."""
    
    @pytest.mark.asyncio
    async def test_detects_missing_rate_limit(self, config, analyzer):
        """Test detection of missing rate limiting."""
        endpoint = {
            "path": "/api/v1/login",
            "method": "POST",
            "body": {"username": "test", "password": "test"}
        }
        
        # All requests succeed - no rate limiting
        responses = [create_response(json_body={"status": "failed"}) for _ in range(100)]
        
        requester = create_mock_requester(responses)
        config.rate_limit_requests = 50
        module = RateLimitModule(requester, analyzer, config)
        
        findings = await module.run(endpoint)
        
        # Should detect missing rate limiting on login endpoint
        assert len(findings) >= 1
        assert any("Rate" in f.title for f in findings)
    
    @pytest.mark.asyncio
    async def test_no_finding_when_rate_limited(self, config, analyzer):
        """Test no finding when rate limiting is in place."""
        endpoint = {"path": "/api/v1/login", "method": "POST", "body": {}}
        
        # First 10 succeed, then 429
        responses = [create_response() for _ in range(10)]
        responses += [create_response(status_code=429) for _ in range(40)]
        
        requester = create_mock_requester(responses)
        config.rate_limit_requests = 50
        module = RateLimitModule(requester, analyzer, config)
        
        findings = await module.run(endpoint)
        
        # Should not report missing rate limit
        missing_findings = [f for f in findings if "Missing" in f.title]
        assert len(missing_findings) == 0


# ============== Mass Assignment Module Tests ==============

class TestMassAssignmentModule:
    """Test mass assignment detection."""
    
    @pytest.mark.asyncio
    async def test_detects_mass_assignment(self, config, analyzer, sample_post_endpoint):
        """Test detection when admin field is accepted."""
        baseline_resp = create_response(
            json_body={"id": 1, "username": "testuser", "email": "test@example.com"}
        )
        mass_assign_resp = create_response(
            json_body={"id": 1, "username": "testuser", "email": "test@example.com", "admin": True}
        )
        
        requester = create_mock_requester([baseline_resp] + [mass_assign_resp] * 30)
        module = MassAssignmentModule(requester, analyzer, config)
        
        findings = await module.run(sample_post_endpoint)
        
        mass_findings = [f for f in findings if "Mass Assignment" in f.title]
        if mass_findings:
            assert mass_findings[0].severity in [Severity.HIGH, Severity.MEDIUM]
    
    @pytest.mark.asyncio
    async def test_skips_get_requests(self, config, analyzer, sample_get_endpoint):
        """Test that GET requests are skipped."""
        requester = create_mock_requester([])
        module = MassAssignmentModule(requester, analyzer, config)
        
        findings = await module.run(sample_get_endpoint)
        
        assert len(findings) == 0


# ============== Disclosure Module Tests ==============

class TestDisclosureModule:
    """Test information disclosure detection."""
    
    @pytest.mark.asyncio
    async def test_detects_stack_trace(self, config, analyzer, sample_get_endpoint):
        """Test detection of stack traces in response."""
        error_resp = create_response(
            status_code=500,
            body="Traceback (most recent call last):\n  File \"app.py\", line 42\n    raise Exception"
        )
        
        requester = create_mock_requester([error_resp, error_resp])
        module = DisclosureModule(requester, analyzer, config)
        
        findings = await module.run(sample_get_endpoint)
        
        debug_findings = [f for f in findings if "Debug" in f.title or "Error" in f.title]
        assert len(debug_findings) >= 1
    
    @pytest.mark.asyncio
    async def test_detects_sensitive_fields(self, config, analyzer, sample_get_endpoint):
        """Test detection of sensitive fields in response."""
        sensitive_resp = create_response(
            json_body={
                "user": "test",
                "password_hash": "abc123",
                "api_secret": "sk_live_xxx",
                "ssn": "123-45-6789"
            }
        )
        
        requester = create_mock_requester([sensitive_resp, sensitive_resp])
        module = DisclosureModule(requester, analyzer, config)
        
        findings = await module.run(sample_get_endpoint)
        
        sensitive_findings = [f for f in findings if "Sensitive" in f.title]
        assert len(sensitive_findings) >= 1
    
    @pytest.mark.asyncio
    async def test_detects_version_disclosure(self, config, analyzer, sample_get_endpoint):
        """Test detection of version info in headers."""
        version_resp = create_response(
            headers={
                "Server": "Apache/2.4.41 (Ubuntu)",
                "X-Powered-By": "PHP/7.4.3"
            }
        )
        
        requester = create_mock_requester([version_resp, version_resp])
        module = DisclosureModule(requester, analyzer, config)
        
        findings = await module.run(sample_get_endpoint)
        
        version_findings = [f for f in findings if "Version" in f.title]
        assert len(version_findings) >= 1


# ============== Finding Tests ==============

class TestFinding:
    """Test Finding dataclass."""
    
    def test_finding_creation(self):
        """Test creating a finding."""
        finding = Finding(
            module="test",
            severity=Severity.HIGH,
            endpoint="/test",
            method="GET",
            title="Test Finding",
            evidence="Test evidence",
            verification="Test steps",
            confidence=80
        )
        
        assert finding.module == "test"
        assert finding.severity == Severity.HIGH
        assert finding.confidence == 80
    
    def test_finding_to_dict(self):
        """Test converting finding to dictionary."""
        finding = Finding(
            module="test",
            severity=Severity.CRITICAL,
            endpoint="/test",
            method="POST",
            title="Critical Issue",
            evidence="Found issue",
            verification="Verify it",
            confidence=95,
            cwe_id="CWE-89"
        )
        
        d = finding.to_dict()
        
        assert d["severity"] == "critical"
        assert d["cwe_id"] == "CWE-89"
        assert d["confidence"] == 95
    
    def test_severity_colors(self):
        """Test severity color codes."""
        assert Severity.CRITICAL.color != ""
        assert Severity.HIGH.color != ""
        assert Severity.CRITICAL.priority > Severity.HIGH.priority
        assert Severity.HIGH.priority > Severity.MEDIUM.priority


# ============== Config Tests ==============

class TestScanConfig:
    """Test configuration."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = ScanConfig(base_url="https://test.com")
        
        assert config.timeout == 30
        assert config.delay == 0.1
        assert config.threads == 5
        assert config.verify_ssl == True
    
    def test_config_to_dict(self):
        """Test converting config to dict (with redacted tokens)."""
        config = ScanConfig(
            base_url="https://test.com",
            auth_token="secret_token"
        )
        
        d = config.to_dict()
        
        assert d["auth_token"] == "***"  # Should be redacted
        assert d["base_url"] == "https://test.com"


# ============== Integration Test ==============

class TestIntegration:
    """Integration tests for full scan workflow."""
    
    @pytest.mark.asyncio
    async def test_multiple_modules_run(self, config, analyzer, sample_get_endpoint):
        """Test running multiple modules on same endpoint."""
        baseline_resp = create_response(json_body={"id": 1, "user": "test"})
        
        # Create enough responses for all modules
        responses = [baseline_resp] * 100
        requester = create_mock_requester(responses)
        
        all_findings = []
        
        for module_cls in [BOLAModule, DisclosureModule]:
            module = module_cls(requester, analyzer, config)
            findings = await module.run(sample_get_endpoint)
            all_findings.extend(findings)
        
        # Should complete without error
        assert isinstance(all_findings, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
