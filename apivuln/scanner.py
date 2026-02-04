"""
Main Scanner Module

Orchestrates the vulnerability scanning process by loading endpoints,
initializing modules, running scans, and collecting results.
"""

import asyncio
import json
from datetime import datetime
from typing import Optional

from .config import ScanConfig
from .requester import Requester
from .analyzer import Analyzer
from .modules import MODULES, MODULE_MAP, Finding


class Scanner:
    """
    Main scanner class that orchestrates vulnerability detection.
    """
    
    def __init__(self, config: ScanConfig):
        """
        Initialize the scanner with configuration.
        
        Args:
            config: ScanConfig instance with scan parameters
        """
        self.config = config
        self.requester: Optional[Requester] = None
        self.analyzer = Analyzer()
        self.findings: list[Finding] = []
        self.endpoints: list[dict] = []
        self.scan_start: Optional[datetime] = None
        self.scan_end: Optional[datetime] = None
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.requester = Requester(self.config)
        await self.requester.__aenter__()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.requester:
            await self.requester.__aexit__(exc_type, exc_val, exc_tb)
    
    def load_endpoints(self, filepath: str) -> list[dict]:
        """
        Load endpoints from a JSON file.
        
        Args:
            filepath: Path to endpoints JSON file
        
        Returns:
            List of endpoint configurations
        """
        with open(filepath, "r") as f:
            data = json.load(f)
        
        # Support both direct list and {"endpoints": [...]} format
        if isinstance(data, list):
            self.endpoints = data
        elif isinstance(data, dict) and "endpoints" in data:
            self.endpoints = data["endpoints"]
        else:
            raise ValueError("Invalid endpoints file format")
        
        # Validate endpoints
        for i, endpoint in enumerate(self.endpoints):
            if "path" not in endpoint:
                raise ValueError(f"Endpoint {i} missing 'path' field")
            if "method" not in endpoint:
                endpoint["method"] = "GET"
        
        return self.endpoints
    
    def load_modules(self, module_names: Optional[list[str]] = None) -> list:
        """
        Load vulnerability detection modules.
        
        Args:
            module_names: List of module names to load, or None for all
        
        Returns:
            List of module classes
        """
        if module_names:
            modules = []
            for name in module_names:
                if name in MODULE_MAP:
                    modules.append(MODULE_MAP[name])
                else:
                    print(f"\033[93m[!]\033[0m Unknown module: {name}")
            return modules
        
        return MODULES
    
    async def scan(
        self,
        endpoints: Optional[list[dict]] = None,
        module_names: Optional[list[str]] = None
    ) -> list[Finding]:
        """
        Run vulnerability scan on endpoints.
        
        Args:
            endpoints: List of endpoints to scan (uses loaded endpoints if None)
            module_names: List of module names to use (uses all if None)
        
        Returns:
            List of Finding objects for discovered vulnerabilities
        """
        self.scan_start = datetime.utcnow()
        self.findings = []
        
        # Use provided endpoints or loaded ones
        scan_endpoints = endpoints or self.endpoints
        if not scan_endpoints:
            raise ValueError("No endpoints to scan")
        
        # Load modules
        modules = self.load_modules(module_names or self.config.modules or None)
        
        if not self.config.quiet:
            print(f"\033[94m[*]\033[0m Starting scan on {len(scan_endpoints)} endpoints")
            print(f"\033[94m[*]\033[0m Modules: {', '.join(m.name for m in modules)}")
        
        # Scan each endpoint with each module
        total_tests = len(scan_endpoints) * len(modules)
        completed = 0
        
        for endpoint in scan_endpoints:
            path = endpoint.get("path", "")
            method = endpoint.get("method", "GET")
            
            if not self.config.quiet:
                print(f"\n\033[94m[scanning]\033[0m {method} {path}")
            
            for module_cls in modules:
                try:
                    # Initialize module
                    module = module_cls(
                        self.requester,
                        self.analyzer,
                        self.config
                    )
                    
                    # Run module
                    module_findings = await module.run(endpoint)
                    
                    # Collect findings
                    for finding in module_findings:
                        self.findings.append(finding)
                        if not self.config.quiet:
                            print(f"\n{finding}")
                
                except Exception as e:
                    if self.config.verbose:
                        print(f"\033[91m[-]\033[0m Error in {module_cls.name}: {e}")
                
                completed += 1
                
                # Progress indicator
                if not self.config.quiet and not self.config.verbose:
                    progress = "." * (completed % 10)
                    print(f"\r\033[94m[scanning]\033[0m {method} {path} {progress}", end="", flush=True)
        
        self.scan_end = datetime.utcnow()
        
        if not self.config.quiet:
            print(f"\n\n\033[92m[*]\033[0m Scan complete: {len(self.findings)} findings")
            self._print_summary()
        
        return self.findings
    
    def _print_summary(self):
        """Print scan summary."""
        if not self.findings:
            return
        
        # Count by severity
        severity_counts = {}
        for finding in self.findings:
            sev = finding.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        print("\n\033[94m[*]\033[0m Summary by severity:")
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                print(f"    {severity.upper()}: {count}")
    
    def get_results(self) -> dict:
        """
        Get scan results as a dictionary.
        
        Returns:
            Dictionary with scan metadata and findings
        """
        return {
            "scan_info": {
                "target": self.config.base_url,
                "start_time": self.scan_start.isoformat() if self.scan_start else None,
                "end_time": self.scan_end.isoformat() if self.scan_end else None,
                "endpoints_scanned": len(self.endpoints),
                "total_findings": len(self.findings),
                "requests_made": self.requester.request_count if self.requester else 0,
            },
            "findings": [f.to_dict() for f in self.findings],
            "summary": self._get_summary(),
        }
    
    def _get_summary(self) -> dict:
        """Get findings summary."""
        severity_counts = {}
        module_counts = {}
        
        for finding in self.findings:
            # Count by severity
            sev = finding.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            # Count by module
            mod = finding.module
            module_counts[mod] = module_counts.get(mod, 0) + 1
        
        return {
            "by_severity": severity_counts,
            "by_module": module_counts,
        }
    
    def export_json(self, filepath: str):
        """Export results to JSON file."""
        results = self.get_results()
        with open(filepath, "w") as f:
            json.dump(results, f, indent=2)
    
    def export_html(self, filepath: str):
        """Export results to HTML report."""
        results = self.get_results()
        
        html = self._generate_html_report(results)
        with open(filepath, "w") as f:
            f.write(html)
    
    def _generate_html_report(self, results: dict) -> str:
        """Generate HTML report content."""
        findings_html = ""
        
        # Sort findings by severity
        sorted_findings = sorted(
            results["findings"],
            key=lambda x: ["critical", "high", "medium", "low", "info"].index(x["severity"]),
        )
        
        for finding in sorted_findings:
            severity_class = finding["severity"]
            findings_html += f"""
            <div class="finding {severity_class}">
                <div class="finding-header">
                    <span class="severity {severity_class}">{finding['severity'].upper()}</span>
                    <span class="title">{finding['title']}</span>
                </div>
                <div class="finding-details">
                    <p><strong>Endpoint:</strong> {finding['method']} {finding['endpoint']}</p>
                    <p><strong>Module:</strong> {finding['module']}</p>
                    <p><strong>Confidence:</strong> {finding['confidence']}%</p>
                    <p><strong>Evidence:</strong><br>{finding['evidence']}</p>
                    <p><strong>Verification:</strong><br><pre>{finding['verification']}</pre></p>
                    {f"<p><strong>CWE:</strong> {finding['cwe_id']}</p>" if finding.get('cwe_id') else ""}
                </div>
            </div>
            """
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>APIVuln Scan Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #eee; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }}
        h2 {{ color: #00d4ff; margin-top: 30px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }}
        .summary-card {{ background: #16213e; padding: 20px; border-radius: 8px; text-align: center; }}
        .summary-card .number {{ font-size: 2em; font-weight: bold; }}
        .summary-card.critical .number {{ color: #ff6b6b; }}
        .summary-card.high .number {{ color: #ffa502; }}
        .summary-card.medium .number {{ color: #ffd43b; }}
        .summary-card.low .number {{ color: #69db7c; }}
        .finding {{ background: #16213e; margin: 15px 0; border-radius: 8px; overflow: hidden; }}
        .finding-header {{ padding: 15px; display: flex; align-items: center; gap: 15px; }}
        .finding-details {{ padding: 0 15px 15px; }}
        .severity {{ padding: 5px 12px; border-radius: 4px; font-weight: bold; font-size: 0.85em; }}
        .severity.critical {{ background: #ff6b6b; color: #000; }}
        .severity.high {{ background: #ffa502; color: #000; }}
        .severity.medium {{ background: #ffd43b; color: #000; }}
        .severity.low {{ background: #69db7c; color: #000; }}
        .severity.info {{ background: #74c0fc; color: #000; }}
        .title {{ font-weight: 600; font-size: 1.1em; }}
        pre {{ background: #0f0f1a; padding: 10px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; }}
        .meta {{ color: #888; font-size: 0.9em; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 APIVuln Scan Report</h1>
        <div class="meta">
            <p>Target: {results['scan_info']['target']}</p>
            <p>Scan Time: {results['scan_info']['start_time']}</p>
            <p>Endpoints Scanned: {results['scan_info']['endpoints_scanned']}</p>
            <p>Total Requests: {results['scan_info']['requests_made']}</p>
        </div>
        
        <h2>Summary</h2>
        <div class="summary">
            <div class="summary-card critical">
                <div class="number">{results['summary']['by_severity'].get('critical', 0)}</div>
                <div>Critical</div>
            </div>
            <div class="summary-card high">
                <div class="number">{results['summary']['by_severity'].get('high', 0)}</div>
                <div>High</div>
            </div>
            <div class="summary-card medium">
                <div class="number">{results['summary']['by_severity'].get('medium', 0)}</div>
                <div>Medium</div>
            </div>
            <div class="summary-card low">
                <div class="number">{results['summary']['by_severity'].get('low', 0)}</div>
                <div>Low</div>
            </div>
        </div>
        
        <h2>Findings ({len(results['findings'])})</h2>
        {findings_html if findings_html else "<p>No vulnerabilities found.</p>"}
    </div>
</body>
</html>"""
        
        return html
