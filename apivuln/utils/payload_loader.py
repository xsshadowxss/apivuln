"""
Payload Loader Utility

Loads and manages payload files for different attack types.
"""

import os
import json
from pathlib import Path
from typing import List, Dict, Any, Optional


class PayloadLoader:
    """
    Loads payloads from files for use in vulnerability testing.
    """
    
    def __init__(self, payload_dir: Optional[str] = None):
        """
        Initialize the payload loader.
        
        Args:
            payload_dir: Directory containing payload files.
                        Defaults to the payloads directory in the package.
        """
        if payload_dir:
            self.payload_dir = Path(payload_dir)
        else:
            # Default to payloads directory relative to this file
            self.payload_dir = Path(__file__).parent.parent / "payloads"
        
        self._cache: Dict[str, Any] = {}
    
    def load_text_payloads(self, filename: str) -> List[str]:
        """
        Load payloads from a text file (one per line).
        Comments starting with # are ignored.
        
        Args:
            filename: Name of the payload file (e.g., "sqli.txt")
        
        Returns:
            List of payload strings
        """
        cache_key = f"txt:{filename}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        filepath = self.payload_dir / filename
        payloads = []
        
        if filepath.exists():
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if line and not line.startswith("#"):
                        payloads.append(line)
        
        self._cache[cache_key] = payloads
        return payloads
    
    def load_json_payloads(self, filename: str) -> Dict[str, Any]:
        """
        Load payloads from a JSON file.
        
        Args:
            filename: Name of the JSON file (e.g., "nosql.json")
        
        Returns:
            Dictionary containing payload data
        """
        cache_key = f"json:{filename}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        filepath = self.payload_dir / filename
        data = {}
        
        if filepath.exists():
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        
        self._cache[cache_key] = data
        return data
    
    def get_sqli_payloads(self, category: Optional[str] = None) -> List[str]:
        """
        Get SQL injection payloads.
        
        Args:
            category: Optional category filter (e.g., "time_based", "union")
        
        Returns:
            List of SQL injection payloads
        """
        payloads = self.load_text_payloads("sqli.txt")
        
        if category:
            # Filter by category based on payload characteristics
            if category == "time_based":
                payloads = [p for p in payloads if "SLEEP" in p.upper() or "WAITFOR" in p.upper() or "PG_SLEEP" in p.upper()]
            elif category == "union":
                payloads = [p for p in payloads if "UNION" in p.upper()]
            elif category == "error_based":
                payloads = [p for p in payloads if "CONVERT" in p.upper() or "EXTRACTVALUE" in p.upper()]
            elif category == "auth_bypass":
                payloads = [p for p in payloads if "admin" in p.lower() or "or 1=1" in p.lower() or "or '1'='1" in p.lower()]
            elif category == "basic":
                payloads = [p for p in payloads if len(p) < 10]
        
        return payloads
    
    def get_nosqli_payloads(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get NoSQL injection payloads.
        
        Args:
            category: Optional category (e.g., "operators", "auth_bypass")
        
        Returns:
            List of NoSQL injection payloads
        """
        data = self.load_json_payloads("nosql.json")
        
        if category == "operators":
            return data.get("mongodb_operators", {}).get("comparison", []) + \
                   data.get("mongodb_operators", {}).get("evaluation", [])
        elif category == "auth_bypass":
            return data.get("auth_bypass", [])
        elif category == "query_string":
            return data.get("query_string_payloads", [])
        
        # Return all operator payloads by default
        payloads = []
        for cat in data.get("mongodb_operators", {}).values():
            if isinstance(cat, list):
                payloads.extend(cat)
        return payloads
    
    def get_ssrf_payloads(self, category: Optional[str] = None) -> List[str]:
        """
        Get SSRF payloads.
        
        Args:
            category: Optional category (e.g., "localhost", "aws", "gcp", "internal")
        
        Returns:
            List of SSRF payloads
        """
        payloads = self.load_text_payloads("ssrf.txt")
        
        if category:
            if category == "localhost":
                payloads = [p for p in payloads if "127.0.0.1" in p or "localhost" in p or "0.0.0.0" in p]
            elif category == "aws":
                payloads = [p for p in payloads if "169.254.169.254" in p]
            elif category == "gcp":
                payloads = [p for p in payloads if "metadata.google.internal" in p]
            elif category == "azure":
                payloads = [p for p in payloads if "169.254.169.254" in p and "metadata" in p]
            elif category == "internal":
                payloads = [p for p in payloads if "192.168." in p or "10.0." in p or "172.16." in p]
            elif category == "file":
                payloads = [p for p in payloads if p.startswith("file:")]
        
        return payloads
    
    def get_xss_payloads(self, category: Optional[str] = None) -> List[str]:
        """
        Get XSS payloads.
        
        Args:
            category: Optional category (e.g., "basic", "event", "encoded")
        
        Returns:
            List of XSS payloads
        """
        payloads = self.load_text_payloads("xss.txt")
        
        if category:
            if category == "basic":
                payloads = [p for p in payloads if "<script>" in p.lower()]
            elif category == "event":
                payloads = [p for p in payloads if "onerror" in p.lower() or "onload" in p.lower()]
            elif category == "encoded":
                payloads = [p for p in payloads if "&#" in p or "\\u" in p]
        
        return payloads
    
    def get_command_injection_payloads(self, category: Optional[str] = None) -> List[str]:
        """
        Get command injection payloads.
        
        Args:
            category: Optional category (e.g., "unix", "windows", "blind")
        
        Returns:
            List of command injection payloads
        """
        payloads = self.load_text_payloads("command_injection.txt")
        
        if category:
            if category == "unix":
                payloads = [p for p in payloads if "/etc/passwd" in p or "ls" in p or "cat" in p]
            elif category == "windows":
                payloads = [p for p in payloads if "dir" in p.lower() or "type" in p.lower() or "C:\\" in p]
            elif category == "blind" or category == "time_based":
                payloads = [p for p in payloads if "sleep" in p.lower() or "ping" in p.lower() or "timeout" in p.lower()]
        
        return payloads
    
    def get_path_traversal_payloads(self, category: Optional[str] = None) -> List[str]:
        """
        Get path traversal payloads.
        
        Args:
            category: Optional category (e.g., "unix", "windows", "encoded")
        
        Returns:
            List of path traversal payloads
        """
        payloads = self.load_text_payloads("path_traversal.txt")
        
        if category:
            if category == "unix":
                payloads = [p for p in payloads if "/etc/" in p or not "\\" in p]
            elif category == "windows":
                payloads = [p for p in payloads if "\\" in p or "windows" in p.lower()]
            elif category == "encoded":
                payloads = [p for p in payloads if "%" in p or "%2f" in p.lower()]
        
        return payloads
    
    def get_jwt_weak_secrets(self) -> List[str]:
        """
        Get list of weak JWT secrets to test.
        
        Returns:
            List of weak secret strings
        """
        data = self.load_json_payloads("jwt.json")
        return data.get("weak_secrets", [])
    
    def get_jwt_none_algorithms(self) -> List[str]:
        """
        Get variations of 'none' algorithm for JWT attacks.
        
        Returns:
            List of none algorithm variations
        """
        data = self.load_json_payloads("jwt.json")
        return data.get("algorithm_confusion", {}).get("none_variants", ["none", "None", "NONE"])
    
    def clear_cache(self):
        """Clear the payload cache."""
        self._cache.clear()
    
    def list_available_payloads(self) -> List[str]:
        """
        List all available payload files.
        
        Returns:
            List of payload filenames
        """
        if not self.payload_dir.exists():
            return []
        
        return [f.name for f in self.payload_dir.iterdir() if f.is_file()]


# Global loader instance
_loader: Optional[PayloadLoader] = None


def get_payload_loader() -> PayloadLoader:
    """Get or create the global payload loader instance."""
    global _loader
    if _loader is None:
        _loader = PayloadLoader()
    return _loader


# Convenience functions
def get_sqli_payloads(category: Optional[str] = None) -> List[str]:
    """Convenience function to get SQL injection payloads."""
    return get_payload_loader().get_sqli_payloads(category)


def get_nosqli_payloads(category: Optional[str] = None) -> List[Dict[str, Any]]:
    """Convenience function to get NoSQL injection payloads."""
    return get_payload_loader().get_nosqli_payloads(category)


def get_ssrf_payloads(category: Optional[str] = None) -> List[str]:
    """Convenience function to get SSRF payloads."""
    return get_payload_loader().get_ssrf_payloads(category)


def get_xss_payloads(category: Optional[str] = None) -> List[str]:
    """Convenience function to get XSS payloads."""
    return get_payload_loader().get_xss_payloads(category)


def get_command_injection_payloads(category: Optional[str] = None) -> List[str]:
    """Convenience function to get command injection payloads."""
    return get_payload_loader().get_command_injection_payloads(category)


def get_path_traversal_payloads(category: Optional[str] = None) -> List[str]:
    """Convenience function to get path traversal payloads."""
    return get_payload_loader().get_path_traversal_payloads(category)
