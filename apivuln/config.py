"""
Configuration management for APIVuln scanner.
"""

from dataclasses import dataclass, field
from typing import Optional
import json


@dataclass
class ScanConfig:
    """Configuration for a scan session."""
    
    # Target configuration
    base_url: str = ""
    endpoints_file: str = ""
    
    # Authentication
    auth_token: Optional[str] = None
    auth_token_low: Optional[str] = None  # Lower privilege token for authz tests
    auth_header: str = "Authorization"
    
    # Request settings
    timeout: int = 30
    delay: float = 0.1  # Delay between requests in seconds
    max_retries: int = 3
    verify_ssl: bool = True
    
    # Proxy settings
    proxy: Optional[str] = None
    
    # Scan settings
    modules: list = field(default_factory=list)
    threads: int = 5
    verbose: bool = False
    quiet: bool = False
    
    # Output settings
    output_file: Optional[str] = None
    output_format: str = "terminal"  # terminal, json, html
    
    # Rate limiting test settings
    rate_limit_requests: int = 100
    rate_limit_period: int = 5
    
    # Custom headers
    headers: dict = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.modules:
            self.modules = []
    
    @classmethod
    def from_file(cls, filepath: str) -> "ScanConfig":
        """Load configuration from a JSON file."""
        with open(filepath, "r") as f:
            data = json.load(f)
        return cls(**data)
    
    def to_dict(self) -> dict:
        """Convert configuration to dictionary."""
        return {
            "base_url": self.base_url,
            "endpoints_file": self.endpoints_file,
            "auth_token": "***" if self.auth_token else None,
            "auth_token_low": "***" if self.auth_token_low else None,
            "timeout": self.timeout,
            "delay": self.delay,
            "modules": self.modules,
            "threads": self.threads,
            "output_format": self.output_format,
        }


# Default payloads for various tests
SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR '1'='1' --",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "1' AND '1'='1",
    "1 AND 1=1",
    "' AND SLEEP(5)--",
]

NOSQL_PAYLOADS = [
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$regex": ".*"}',
    '{"$where": "1==1"}',
    "[$ne]=1",
    "[$gt]=",
    "[$regex]=.*",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "http://169.254.169.254",  # AWS metadata
    "http://metadata.google.internal",  # GCP metadata
    "file:///etc/passwd",
]

MASS_ASSIGNMENT_FIELDS = [
    "admin",
    "is_admin",
    "isAdmin",
    "role",
    "roles",
    "privilege",
    "privileges",
    "permission",
    "permissions",
    "verified",
    "is_verified",
    "active",
    "is_active",
    "balance",
    "credits",
    "user_type",
    "userType",
    "account_type",
    "plan",
    "subscription",
]
