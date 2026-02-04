"""
Base class for all vulnerability detection modules.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from datetime import datetime


class Severity(Enum):
    """Vulnerability severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    @property
    def color(self) -> str:
        """ANSI color code for terminal output."""
        colors = {
            "info": "\033[94m",      # Blue
            "low": "\033[92m",       # Green
            "medium": "\033[93m",    # Yellow
            "high": "\033[91m",      # Red
            "critical": "\033[95m",  # Magenta
        }
        return colors.get(self.value, "\033[0m")
    
    @property
    def priority(self) -> int:
        """Numeric priority for sorting."""
        priorities = {
            "info": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }
        return priorities.get(self.value, 0)


@dataclass
class Finding:
    """
    Represents a discovered vulnerability or security issue.
    """
    module: str
    severity: Severity
    endpoint: str
    method: str
    title: str
    evidence: str
    verification: str
    confidence: int  # 0-100
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    request_details: Optional[dict] = None
    response_details: Optional[dict] = None
    cwe_id: Optional[str] = None
    references: list = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert finding to dictionary for JSON serialization."""
        return {
            "module": self.module,
            "severity": self.severity.value,
            "endpoint": self.endpoint,
            "method": self.method,
            "title": self.title,
            "evidence": self.evidence,
            "verification": self.verification,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "cwe_id": self.cwe_id,
            "references": self.references,
        }
    
    def __str__(self) -> str:
        reset = "\033[0m"
        return (
            f"{self.severity.color}[{self.severity.value.upper()}]{reset} "
            f"{self.title} on {self.method} {self.endpoint}\n"
            f"       Evidence: {self.evidence}\n"
            f"       Confidence: {self.confidence}%\n"
            f"       → Verify: {self.verification}"
        )


class BaseModule(ABC):
    """
    Abstract base class for vulnerability detection modules.
    
    All modules must implement the `run` method which performs
    the actual vulnerability checks.
    """
    
    name: str = "base"
    description: str = "Base module"
    author: str = "APIVuln"
    version: str = "1.0"
    
    def __init__(self, requester, analyzer, config=None):
        """
        Initialize the module.
        
        Args:
            requester: Requester instance for making HTTP requests
            analyzer: Analyzer instance for response analysis
            config: Optional ScanConfig for module-specific settings
        """
        self.requester = requester
        self.analyzer = analyzer
        self.config = config
        self.findings: list[Finding] = []
    
    @abstractmethod
    async def run(self, endpoint: dict) -> list[Finding]:
        """
        Run vulnerability checks against an endpoint.
        
        Args:
            endpoint: Endpoint configuration dict with:
                - path: URL path (may contain {param} placeholders)
                - method: HTTP method
                - params: URL/path parameters
                - body: Request body (for POST/PUT/PATCH)
                - headers: Additional headers
        
        Returns:
            List of Finding objects for any discovered issues
        """
        pass
    
    def create_finding(
        self,
        severity: Severity,
        endpoint: str,
        method: str,
        title: str,
        evidence: str,
        verification: str,
        confidence: int,
        cwe_id: Optional[str] = None,
        references: Optional[list] = None,
    ) -> Finding:
        """
        Helper method to create a Finding with module info pre-filled.
        """
        return Finding(
            module=self.name,
            severity=severity,
            endpoint=endpoint,
            method=method,
            title=title,
            evidence=evidence,
            verification=verification,
            confidence=confidence,
            cwe_id=cwe_id,
            references=references or [],
        )
    
    def log(self, message: str, level: str = "info"):
        """
        Log a message (if verbose mode is enabled).
        """
        if self.config and self.config.verbose:
            prefix = {
                "info": "\033[94m[*]\033[0m",
                "success": "\033[92m[+]\033[0m",
                "warning": "\033[93m[!]\033[0m",
                "error": "\033[91m[-]\033[0m",
            }.get(level, "[*]")
            print(f"{prefix} [{self.name}] {message}")
    
    @staticmethod
    def has_path_param(endpoint: dict, param_names: list[str]) -> bool:
        """Check if endpoint has any of the specified path parameters."""
        path = endpoint.get("path", "")
        params = endpoint.get("params", {})
        
        for name in param_names:
            if f"{{{name}}}" in path or name in params:
                return True
        return False
    
    @staticmethod
    def get_id_params(endpoint: dict) -> list[str]:
        """Extract ID-like parameters from endpoint."""
        id_patterns = ["id", "user_id", "userId", "account_id", "accountId", 
                       "order_id", "orderId", "item_id", "itemId", "record_id"]
        
        found = []
        path = endpoint.get("path", "")
        params = endpoint.get("params", {})
        
        for pattern in id_patterns:
            if f"{{{pattern}}}" in path or pattern in params:
                found.append(pattern)
        
        return found
    
    def swap_param(self, endpoint: dict, param_name: str, new_value) -> dict:
        """
        Create a copy of endpoint with a parameter value changed.
        """
        import copy
        modified = copy.deepcopy(endpoint)
        
        if "params" in modified and param_name in modified["params"]:
            modified["params"][param_name] = new_value
        
        if "body" in modified and isinstance(modified["body"], dict):
            if param_name in modified["body"]:
                modified["body"][param_name] = new_value
        
        return modified
