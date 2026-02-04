"""
Reporter Module

Handles formatting and output of scan results in various formats.
"""

import json
from datetime import datetime
from typing import TextIO
import sys

from .modules import Finding, Severity


class Reporter:
    """
    Formats and outputs scan results.
    """
    
    # ANSI color codes
    COLORS = {
        "reset": "\033[0m",
        "bold": "\033[1m",
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
    }
    
    SEVERITY_COLORS = {
        Severity.CRITICAL: "magenta",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "green",
        Severity.INFO: "blue",
    }
    
    def __init__(self, use_color: bool = True, output: TextIO = None):
        """
        Initialize reporter.
        
        Args:
            use_color: Whether to use ANSI colors in output
            output: Output stream (defaults to stdout)
        """
        self.use_color = use_color
        self.output = output or sys.stdout
    
    def _color(self, text: str, color: str) -> str:
        """Apply color to text if colors are enabled."""
        if not self.use_color:
            return text
        return f"{self.COLORS.get(color, '')}{text}{self.COLORS['reset']}"
    
    def _severity_color(self, severity: Severity) -> str:
        """Get color for severity level."""
        return self.SEVERITY_COLORS.get(severity, "reset")
    
    def print_banner(self):
        """Print the tool banner."""
        banner = """
    ___    ____  ____     __      __     
   /   |  / __ \\/  _/    / /___  / /____ 
  / /| | / /_/ // /_____/ / __ \\/ __/ _ \\
 / ___ |/ ____// /_____/ / / / / /_/  __/
/_/  |_/_/   /___/    /_/_/ /_/\\__/\\___/ 
                                         
        API Vulnerability Scanner v1.0
"""
        print(self._color(banner, "cyan"), file=self.output)
    
    def print_config(self, config):
        """Print scan configuration."""
        print(self._color("[*]", "blue") + f" Target: {config.base_url}", file=self.output)
        print(self._color("[*]", "blue") + f" Auth: {'Configured' if config.auth_token else 'None'}", file=self.output)
        if config.auth_token_low:
            print(self._color("[*]", "blue") + " Low-priv token: Configured", file=self.output)
    
    def print_finding(self, finding: Finding):
        """Print a single finding."""
        color = self._severity_color(finding.severity)
        
        print(file=self.output)
        print(
            self._color(f"[{finding.severity.value.upper()}]", color) +
            f" {finding.title} on {finding.method} {finding.endpoint}",
            file=self.output
        )
        print(f"       Evidence: {finding.evidence}", file=self.output)
        print(f"       Confidence: {finding.confidence}%", file=self.output)
        print(f"       → Verify: {finding.verification}", file=self.output)
        
        if finding.cwe_id:
            print(f"       CWE: {finding.cwe_id}", file=self.output)
    
    def print_progress(self, endpoint: dict, current: int, total: int):
        """Print scan progress."""
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        progress = f"[{current}/{total}]"
        print(
            f"\r{self._color('[scanning]', 'blue')} {progress} {method} {path}",
            end="",
            flush=True,
            file=self.output
        )
    
    def print_summary(self, findings: list[Finding], scan_time: float, requests: int):
        """Print scan summary."""
        print(file=self.output)
        print(
            self._color("[*]", "green") +
            f" Scan complete in {scan_time:.1f}s",
            file=self.output
        )
        print(
            self._color("[*]", "blue") +
            f" Total requests: {requests}",
            file=self.output
        )
        print(
            self._color("[*]", "blue") +
            f" Findings: {len(findings)}",
            file=self.output
        )
        
        if findings:
            print(file=self.output)
            print(self._color("[*]", "blue") + " Summary by severity:", file=self.output)
            
            severity_counts = {}
            for finding in findings:
                sev = finding.severity
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    color = self._severity_color(severity)
                    print(
                        f"    {self._color(severity.value.upper(), color)}: {count}",
                        file=self.output
                    )
    
    def print_modules(self, modules: list):
        """Print available modules."""
        print(self._color("[*]", "blue") + " Available modules:", file=self.output)
        print(file=self.output)
        
        for module in modules:
            print(f"  {self._color(module.name, 'cyan')}", file=self.output)
            print(f"    {module.description}", file=self.output)
            print(file=self.output)
    
    def format_json(self, results: dict) -> str:
        """Format results as JSON."""
        return json.dumps(results, indent=2)
    
    def format_csv(self, findings: list[Finding]) -> str:
        """Format findings as CSV."""
        lines = [
            "severity,module,endpoint,method,title,confidence,cwe_id"
        ]
        
        for f in findings:
            # Escape commas and quotes
            title = f.title.replace('"', '""')
            lines.append(
                f'{f.severity.value},{f.module},{f.endpoint},{f.method},"{title}",{f.confidence},{f.cwe_id or ""}'
            )
        
        return "\n".join(lines)
    
    def export_json(self, results: dict, filepath: str):
        """Export results to JSON file."""
        with open(filepath, "w") as f:
            json.dump(results, f, indent=2)
        print(self._color("[*]", "green") + f" Results saved to {filepath}", file=self.output)
    
    def export_html(self, results: dict, filepath: str):
        """Export results to HTML file."""
        html = self._generate_html(results)
        with open(filepath, "w") as f:
            f.write(html)
        print(self._color("[*]", "green") + f" Report saved to {filepath}", file=self.output)
    
    def _generate_html(self, results: dict) -> str:
        """Generate HTML report."""
        # Reuse scanner's HTML generation
        from .scanner import Scanner
        scanner = Scanner.__new__(Scanner)
        scanner.findings = []
        return scanner._generate_html_report(results)


def print_error(message: str):
    """Print error message."""
    print(f"\033[91m[-]\033[0m {message}", file=sys.stderr)


def print_warning(message: str):
    """Print warning message."""
    print(f"\033[93m[!]\033[0m {message}", file=sys.stderr)


def print_info(message: str):
    """Print info message."""
    print(f"\033[94m[*]\033[0m {message}")


def print_success(message: str):
    """Print success message."""
    print(f"\033[92m[+]\033[0m {message}")
