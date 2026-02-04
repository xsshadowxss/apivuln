"""
Response analysis utilities for detecting vulnerabilities.
"""

import re
import json
from typing import Optional
from difflib import SequenceMatcher

from .requester import Response


class Analyzer:
    """
    Analyzes HTTP responses to detect potential vulnerabilities.
    """
    
    # Error patterns that indicate potential issues
    SQL_ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_",
        r"ORA-\d{5}",
        r"Oracle.*Driver",
        r"SQLite.*error",
        r"sqlite3\.OperationalError",
        r"Microsoft SQL Server",
        r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver",
        r"Unclosed quotation mark",
        r"quoted string not properly terminated",
        r"syntax error at or near",
        r"unexpected end of SQL command",
    ]
    
    NOSQL_ERROR_PATTERNS = [
        r"MongoDB.*Error",
        r"Cannot convert.*to BSON",
        r"\$where.*not allowed",
        r"MongoError",
        r"CastError",
    ]
    
    DEBUG_PATTERNS = [
        r"Traceback \(most recent call last\)",
        r"at .+\.java:\d+",
        r"at .+\.py:\d+",
        r"at .+\.js:\d+",
        r"at .+\.rb:\d+",
        r"Exception in thread",
        r"stack trace:",
        r"DEBUG",
        r"FATAL ERROR",
        r"<title>Error</title>",
    ]
    
    SENSITIVE_DATA_PATTERNS = [
        r"password[\"']?\s*[:=]\s*[\"'][^\"']+[\"']",
        r"api[_-]?key[\"']?\s*[:=]\s*[\"'][^\"']+[\"']",
        r"secret[\"']?\s*[:=]\s*[\"'][^\"']+[\"']",
        r"token[\"']?\s*[:=]\s*[\"'][^\"']+[\"']",
        r"private[_-]?key",
        r"-----BEGIN.*PRIVATE KEY-----",
        r"aws_access_key_id",
        r"aws_secret_access_key",
    ]
    
    def __init__(self):
        self._compiled_patterns = {}
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Pre-compile regex patterns for performance."""
        self._compiled_patterns["sql"] = [
            re.compile(p, re.IGNORECASE) for p in self.SQL_ERROR_PATTERNS
        ]
        self._compiled_patterns["nosql"] = [
            re.compile(p, re.IGNORECASE) for p in self.NOSQL_ERROR_PATTERNS
        ]
        self._compiled_patterns["debug"] = [
            re.compile(p, re.IGNORECASE) for p in self.DEBUG_PATTERNS
        ]
        self._compiled_patterns["sensitive"] = [
            re.compile(p, re.IGNORECASE) for p in self.SENSITIVE_DATA_PATTERNS
        ]
    
    def similarity(self, response1: Response, response2: Response) -> float:
        """
        Calculate similarity between two responses (0.0 to 1.0).
        """
        # Compare status codes
        if response1.status_code != response2.status_code:
            return 0.0
        
        # Compare body content
        return SequenceMatcher(
            None,
            response1.body,
            response2.body
        ).ratio()
    
    def indicates_data_access(
        self,
        response: Response,
        baseline: Response,
        threshold: float = 0.3
    ) -> bool:
        """
        Check if response indicates access to different data than baseline.
        Used for BOLA/IDOR detection.
        """
        # Both should be successful
        if not response.is_success or not baseline.is_success:
            return False
        
        # Check if responses are different enough
        similarity = self.similarity(response, baseline)
        
        # If very similar, likely same data or error
        if similarity > 0.95:
            return False
        
        # If completely different, might be error page
        if similarity < threshold:
            # Check if it looks like an error
            if self.has_error_patterns(response):
                return False
            # Different data returned
            return True
        
        # Check for different data in JSON responses
        if response.json_body and baseline.json_body:
            return self._json_differs(response.json_body, baseline.json_body)
        
        return similarity < 0.8
    
    def _json_differs(self, json1: dict, json2: dict) -> bool:
        """Check if two JSON objects contain different data."""
        try:
            # Compare specific fields that indicate different data
            id_fields = ["id", "_id", "user_id", "userId", "account_id"]
            for field in id_fields:
                if field in json1 and field in json2:
                    if json1[field] != json2[field]:
                        return True
            
            # Check for different data in nested structures
            if isinstance(json1, dict) and isinstance(json2, dict):
                for key in json1:
                    if key in json2:
                        if json1[key] != json2[key]:
                            return True
            
            return False
        except (TypeError, KeyError):
            return False
    
    def has_sql_error(self, response: Response) -> tuple[bool, Optional[str]]:
        """Check if response contains SQL error messages."""
        for pattern in self._compiled_patterns["sql"]:
            match = pattern.search(response.body)
            if match:
                return True, match.group()
        return False, None
    
    def has_nosql_error(self, response: Response) -> tuple[bool, Optional[str]]:
        """Check if response contains NoSQL error messages."""
        for pattern in self._compiled_patterns["nosql"]:
            match = pattern.search(response.body)
            if match:
                return True, match.group()
        return False, None
    
    def has_error_patterns(self, response: Response) -> bool:
        """Check if response contains generic error patterns."""
        for pattern in self._compiled_patterns["debug"]:
            if pattern.search(response.body):
                return True
        return False
    
    def has_debug_info(self, response: Response) -> tuple[bool, list[str]]:
        """Check if response contains debug/stack trace information."""
        findings = []
        for pattern in self._compiled_patterns["debug"]:
            match = pattern.search(response.body)
            if match:
                findings.append(match.group())
        return bool(findings), findings
    
    def has_sensitive_data(self, response: Response) -> tuple[bool, list[str]]:
        """Check if response contains sensitive data patterns."""
        findings = []
        for pattern in self._compiled_patterns["sensitive"]:
            match = pattern.search(response.body)
            if match:
                # Redact the actual value
                findings.append(pattern.pattern)
        return bool(findings), findings
    
    def response_time_anomaly(
        self,
        response: Response,
        baseline: Response,
        threshold: float = 5.0
    ) -> bool:
        """
        Check if response time is significantly longer than baseline.
        Used for time-based injection detection.
        """
        return response.elapsed > baseline.elapsed + threshold
    
    def status_code_indicates_authz_bypass(
        self,
        normal_response: Response,
        test_response: Response
    ) -> bool:
        """
        Check if status codes indicate authorization bypass.
        """
        # If normal request is forbidden but test succeeds
        if normal_response.status_code in [401, 403] and test_response.is_success:
            return True
        
        # If both succeed but different privilege levels
        if normal_response.is_success and test_response.is_success:
            return True
        
        return False
    
    def extract_json_fields(self, response: Response) -> set[str]:
        """Extract all field names from JSON response."""
        fields = set()
        
        def extract_keys(obj, prefix=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    full_key = f"{prefix}.{key}" if prefix else key
                    fields.add(full_key)
                    extract_keys(value, full_key)
            elif isinstance(obj, list) and obj:
                extract_keys(obj[0], prefix)
        
        if response.json_body:
            extract_keys(response.json_body)
        
        return fields
    
    def check_excessive_data(
        self,
        response: Response,
        expected_fields: Optional[set[str]] = None
    ) -> tuple[bool, set[str]]:
        """
        Check if response contains more data than expected.
        Used for excessive data exposure detection.
        """
        if not response.json_body:
            return False, set()
        
        actual_fields = self.extract_json_fields(response)
        
        if expected_fields:
            extra_fields = actual_fields - expected_fields
            return bool(extra_fields), extra_fields
        
        # Check for potentially sensitive field names
        sensitive_patterns = [
            r"password", r"secret", r"token", r"key", r"hash",
            r"salt", r"private", r"internal", r"ssn", r"credit",
        ]
        
        suspicious_fields = set()
        for field in actual_fields:
            for pattern in sensitive_patterns:
                if re.search(pattern, field, re.IGNORECASE):
                    suspicious_fields.add(field)
        
        return bool(suspicious_fields), suspicious_fields
    
    def jwt_decode_unsafe(self, token: str) -> Optional[dict]:
        """
        Decode JWT without verification (for analysis only).
        """
        try:
            import base64
            
            parts = token.replace("Bearer ", "").split(".")
            if len(parts) != 3:
                return None
            
            # Decode header and payload
            def decode_part(part):
                # Add padding if needed
                padding = 4 - len(part) % 4
                if padding != 4:
                    part += "=" * padding
                decoded = base64.urlsafe_b64decode(part)
                return json.loads(decoded)
            
            return {
                "header": decode_part(parts[0]),
                "payload": decode_part(parts[1]),
            }
        except Exception:
            return None
