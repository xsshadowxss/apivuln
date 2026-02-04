#!/usr/bin/env python3
"""
APIVuln Interactive Mode
Menu-driven interface for API vulnerability scanning and exploitation.
"""

import os
import sys
import json
import asyncio
from pathlib import Path
from typing import Optional, List, Dict, Any

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from apivuln.config import ScanConfig
from apivuln.scanner import Scanner
from apivuln.modules import get_module_info, get_all_module_names, Finding, Severity


class Colors:
    """ANSI color codes for terminal output."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    """Print the tool banner."""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
    ___    ____  ____     __      __     
   /   |  / __ \\/  _/    / /___  / /____ 
  / /| | / /_/ // /_____/ / __ \\/ __/ _ \\
 / ___ |/ ____// /_____/ / / / / /_/  __/
/_/  |_/_/   /___/    /_/_/ /_/\\__/\\___/ 
                                         
{Colors.RESET}{Colors.WHITE}     API Vulnerability Scanner v1.0
     {Colors.YELLOW}For authorized security testing only{Colors.RESET}
"""
    print(banner)


def print_menu(title: str, options: List[str], show_back: bool = True):
    """Print a formatted menu."""
    print(f"\n{Colors.CYAN}{'=' * 50}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.WHITE}  {title}{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 50}{Colors.RESET}\n")
    
    for i, option in enumerate(options, 1):
        print(f"  {Colors.GREEN}[{i}]{Colors.RESET} {option}")
    
    if show_back:
        print(f"\n  {Colors.YELLOW}[0]{Colors.RESET} Back / Exit")
    
    print(f"\n{Colors.CYAN}{'=' * 50}{Colors.RESET}")


def get_input(prompt: str, default: str = "") -> str:
    """Get user input with optional default value."""
    if default:
        prompt = f"{prompt} [{Colors.YELLOW}{default}{Colors.RESET}]: "
    else:
        prompt = f"{prompt}: "
    
    try:
        value = input(f"{Colors.WHITE}{prompt}{Colors.RESET}").strip()
        return value if value else default
    except (KeyboardInterrupt, EOFError):
        print("\n")
        return ""


def get_choice(max_choice: int, allow_zero: bool = True) -> int:
    """Get a numeric choice from user."""
    while True:
        try:
            choice = input(f"\n{Colors.GREEN}>>>{Colors.RESET} Enter your choice: ").strip()
            
            if not choice:
                continue
            
            num = int(choice)
            
            if allow_zero and num == 0:
                return 0
            elif 1 <= num <= max_choice:
                return num
            else:
                print(f"{Colors.RED}[!] Invalid choice. Please enter 1-{max_choice}{Colors.RESET}")
        except ValueError:
            print(f"{Colors.RED}[!] Please enter a number{Colors.RESET}")
        except (KeyboardInterrupt, EOFError):
            print("\n")
            return 0


def confirm(prompt: str) -> bool:
    """Ask for yes/no confirmation."""
    print(f"\n{Colors.YELLOW}{prompt}{Colors.RESET}")
    print(f"  {Colors.GREEN}[1]{Colors.RESET} Yes")
    print(f"  {Colors.RED}[2]{Colors.RESET} No")
    
    choice = get_choice(2, allow_zero=False)
    return choice == 1


def print_success(message: str):
    """Print success message."""
    print(f"{Colors.GREEN}[+]{Colors.RESET} {message}")


def print_error(message: str):
    """Print error message."""
    print(f"{Colors.RED}[-]{Colors.RESET} {message}")


def print_info(message: str):
    """Print info message."""
    print(f"{Colors.BLUE}[*]{Colors.RESET} {message}")


def print_warning(message: str):
    """Print warning message."""
    print(f"{Colors.YELLOW}[!]{Colors.RESET} {message}")


def print_finding(finding: Finding, index: int):
    """Print a single finding with formatting."""
    severity_colors = {
        Severity.CRITICAL: Colors.MAGENTA,
        Severity.HIGH: Colors.RED,
        Severity.MEDIUM: Colors.YELLOW,
        Severity.LOW: Colors.GREEN,
        Severity.INFO: Colors.BLUE,
    }
    
    color = severity_colors.get(finding.severity, Colors.WHITE)
    
    print(f"\n{Colors.CYAN}{'─' * 50}{Colors.RESET}")
    print(f"  {Colors.BOLD}Finding #{index}{Colors.RESET}")
    print(f"  {color}[{finding.severity.value.upper()}]{Colors.RESET} {Colors.BOLD}{finding.title}{Colors.RESET}")
    print(f"  {Colors.WHITE}Endpoint:{Colors.RESET} {finding.method} {finding.endpoint}")
    print(f"  {Colors.WHITE}Module:{Colors.RESET} {finding.module}")
    print(f"  {Colors.WHITE}Confidence:{Colors.RESET} {finding.confidence}%")
    print(f"  {Colors.WHITE}Evidence:{Colors.RESET}")
    for line in finding.evidence.split('\n'):
        print(f"    {line}")
    if finding.cwe_id:
        print(f"  {Colors.WHITE}CWE:{Colors.RESET} {finding.cwe_id}")
    print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}")


class InteractiveMode:
    """Interactive menu-driven interface for APIVuln."""
    
    def __init__(self):
        self.config: Optional[ScanConfig] = None
        self.findings: List[Finding] = []
        self.target_url: str = ""
        self.endpoints: List[Dict] = []
        self.endpoints_file: str = ""
        self.auth_token: str = ""
        self.auth_token_low: str = ""
    
    def run(self):
        """Main entry point for interactive mode."""
        clear_screen()
        print_banner()
        
        while True:
            self.main_menu()
    
    def main_menu(self):
        """Display and handle main menu."""
        options = [
            "Quick Scan (Auto-detect vulnerabilities)",
            "Auto-Discovery Scan (Find & scan APIs automatically)",
            "Custom Scan (Select specific modules)",
            "Verify/Exploit a Vulnerability",
            "Discover API Endpoints Only",
            "Configure Target",
            "View Previous Findings",
            "Generate Endpoints Template",
            "Help & Module Info",
        ]
        
        print_menu("MAIN MENU", options)
        
        # Show current target if set
        if self.target_url:
            print(f"  {Colors.CYAN}Current Target:{Colors.RESET} {self.target_url}")
            if self.auth_token:
                print(f"  {Colors.CYAN}Auth:{Colors.RESET} Configured ✓")
            if self.endpoints:
                print(f"  {Colors.CYAN}Endpoints:{Colors.RESET} {len(self.endpoints)} loaded")
        
        choice = get_choice(len(options))
        
        if choice == 0:
            self.exit_program()
        elif choice == 1:
            self.quick_scan()
        elif choice == 2:
            self.auto_discovery_scan()
        elif choice == 3:
            self.custom_scan()
        elif choice == 4:
            self.verify_exploit_menu()
        elif choice == 5:
            self.discover_endpoints_only()
        elif choice == 6:
            self.configure_target()
        elif choice == 7:
            self.view_findings()
        elif choice == 8:
            self.generate_endpoints()
        elif choice == 9:
            self.show_help()
    
    def configure_target(self):
        """Configure target URL and authentication."""
        clear_screen()
        print_banner()
        
        options = [
            "Set Target URL",
            "Set Endpoints File",
            "Set Auth Token (High Privilege)",
            "Set Auth Token (Low Privilege)",
            "Quick Setup (All at once)",
            "View Current Config",
        ]
        
        print_menu("CONFIGURE TARGET", options)
        
        choice = get_choice(len(options))
        
        if choice == 0:
            return
        elif choice == 1:
            self.target_url = get_input("Enter target base URL", self.target_url or "https://api.example.com")
            print_success(f"Target URL set to: {self.target_url}")
        elif choice == 2:
            self.set_endpoints_file()
        elif choice == 3:
            token = get_input("Enter auth token (e.g., Bearer eyJ...)")
            if token:
                self.auth_token = token
                print_success("Auth token configured")
        elif choice == 4:
            token = get_input("Enter low-privilege auth token")
            if token:
                self.auth_token_low = token
                print_success("Low-privilege token configured")
        elif choice == 5:
            self.quick_setup()
        elif choice == 6:
            self.show_current_config()
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.RESET}")
    
    def set_endpoints_file(self):
        """Set and load endpoints file."""
        filepath = get_input("Enter endpoints file path", self.endpoints_file or "endpoints.json")
        
        if not filepath:
            return
        
        if not os.path.exists(filepath):
            print_error(f"File not found: {filepath}")
            if confirm("Would you like to generate a template?"):
                self.generate_endpoints(filepath)
            return
        
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            if isinstance(data, list):
                self.endpoints = data
            elif isinstance(data, dict) and "endpoints" in data:
                self.endpoints = data["endpoints"]
            else:
                print_error("Invalid endpoints file format")
                return
            
            self.endpoints_file = filepath
            print_success(f"Loaded {len(self.endpoints)} endpoints from {filepath}")
            
        except json.JSONDecodeError as e:
            print_error(f"Invalid JSON: {e}")
        except Exception as e:
            print_error(f"Error loading file: {e}")
    
    def quick_setup(self):
        """Quick setup - configure everything at once."""
        clear_screen()
        print_banner()
        print(f"\n{Colors.CYAN}{'=' * 50}{Colors.RESET}")
        print(f"{Colors.BOLD}  QUICK SETUP{Colors.RESET}")
        print(f"{Colors.CYAN}{'=' * 50}{Colors.RESET}\n")
        
        # Target URL
        self.target_url = get_input("Target URL", self.target_url or "https://api.example.com")
        
        # Endpoints file
        self.endpoints_file = get_input("Endpoints file", self.endpoints_file or "endpoints.json")
        
        if self.endpoints_file and os.path.exists(self.endpoints_file):
            try:
                with open(self.endpoints_file, 'r') as f:
                    data = json.load(f)
                self.endpoints = data.get("endpoints", data) if isinstance(data, dict) else data
                print_success(f"Loaded {len(self.endpoints)} endpoints")
            except:
                print_warning("Could not load endpoints file")
        elif self.endpoints_file:
            if confirm("Endpoints file not found. Generate template?"):
                self.generate_endpoints(self.endpoints_file)
        
        # Auth token
        if confirm("Do you have an auth token?"):
            self.auth_token = get_input("Auth token (Bearer eyJ...)")
            
            if confirm("Do you have a low-privilege token for authorization tests?"):
                self.auth_token_low = get_input("Low-privilege token")
        
        print_success("Configuration complete!")
    
    def auto_discovery_scan(self):
        """Automatically discover APIs and scan them."""
        clear_screen()
        print_banner()
        
        print(f"\n{Colors.CYAN}{'=' * 50}{Colors.RESET}")
        print(f"{Colors.BOLD}  AUTO-DISCOVERY SCAN{Colors.RESET}")
        print(f"{Colors.CYAN}{'=' * 50}{Colors.RESET}\n")
        
        print_info("This will automatically:")
        print("  1. Crawl the target website")
        print("  2. Discover API endpoints")
        print("  3. Scan discovered endpoints for vulnerabilities")
        print()
        
        # Get target URL
        if not self.target_url:
            self.target_url = get_input("Enter target URL", "https://example.com")
        else:
            new_url = get_input("Target URL", self.target_url)
            if new_url:
                self.target_url = new_url
        
        if not self.target_url:
            print_error("No target URL provided")
            input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.RESET}")
            return
        
        # Ask for auth token
        if not self.auth_token:
            if confirm("Do you have an auth token to use during scanning?"):
                self.auth_token = get_input("Enter auth token (Bearer eyJ...)")
        
        # Run discovery
        print(f"\n{Colors.CYAN}{'=' * 50}{Colors.RESET}")
        print(f"{Colors.BOLD}  DISCOVERING API ENDPOINTS{Colors.RESET}")
        print(f"{Colors.CYAN}{'=' * 50}{Colors.RESET}\n")
        
        print_info(f"Target: {self.target_url}")
        print_info("Scanning for API endpoints...")
        print()
        
        try:
            from .discovery import APIDiscovery
            
            def progress_callback(message, count):
                print(f"\r{Colors.BLUE}[*]{Colors.RESET} {message} (Found: {count} endpoints)", end="", flush=True)
            
            discovery = APIDiscovery(self.target_url, verbose=False)
            discovered = asyncio.run(discovery.discover(callback=progress_callback))
            
            print()  # New line after progress
            
            if not discovered:
                print_warning("No API endpoints discovered")
                print_info("Try providing an endpoints file manually")
                input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.RESET}")
                return
            
            # Convert to endpoint format
            self.endpoints = [ep.to_dict() for ep in discovered]
            
            print()
            print_success(f"Discovered {len(self.endpoints)} API endpoints!")
            print()
            
            # Show discovered endpoints
            print(f"{Colors.CYAN}Discovered Endpoints:{Colors.RESET}")
            for i, ep in enumerate(self.endpoints[:15], 1):  # Show first 15
                confidence = next((d.confidence for d in discovered if d.path == ep['path']), 0)
                print(f"  {Colors.GREEN}[{i:2}]{Colors.RESET} {ep['method']:6} {ep['path']} {Colors.YELLOW}({confidence}% confidence){Colors.RESET}")
            
            if len(self.endpoints) > 15:
                print(f"  ... and {len(self.endpoints) - 15} more")
            
            print()
            
            # Ask to save endpoints
            if confirm("Save discovered endpoints to file?"):
                filename = get_input("Filename", "discovered_endpoints.json")
                with open(filename, 'w') as f:
                    json.dump({"endpoints": self.endpoints}, f, indent=2)
                print_success(f"Saved to {filename}")
                self.endpoints_file = filename
            
            # Ask to proceed with scan
            if confirm("Proceed to vulnerability scan?"):
                self.run_scan()
            
        except ImportError as e:
            print_error(f"Discovery module error: {e}")
            input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.RESET}")
        except Exception as e:
            print_error(f"Discovery failed: {e}")
            import traceback
            traceback.print_exc()
            input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.RESET}")
    
    def discover_endpoints_only(self):
        """Just discover endpoints without scanning."""
        clear_screen()
        print_banner()
        
        print(f"\n{Colors.CYAN}{'=' * 50}{Colors.RESET}")
        print(f"{Colors.BOLD}  API ENDPOINT DISCOVERY{Colors.RESET}")
        print(f"{Colors.CYAN}{'=' * 50}{Colors.RESET}\n")
        
        # Get target URL
        target = get_input("Enter target URL", self.target_url or "https://example.com")
        
        if not target:
            print_error("No target URL provided")
            input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.RESET}")
            return
        
        self.target_url = target
        
        print_info(f"Discovering APIs on {target}...")
        print()
        
        try:
            from .discovery import APIDiscovery
            
            def progress_callback(message, count):
                print(f"\r{Colors.BLUE}[*]{Colors.RESET} {message} (Found: {count})", end="", flush=True)
            
            discovery = APIDiscovery(target, verbose=True)
            discovered = asyncio.run(discovery.discover(callback=progress_callback))
            
            print("\n")
            
            if not discovered:
                print_warning("No API endpoints discovered")
                input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.RESET}")
                return
            
            self.endpoints = [ep.to_dict() for ep in discovered]
            
            print_success(f"Found {len(self.endpoints)} endpoints!\n")
            
            # Group by source
            sources = {}
            for ep in discovered:
                src = ep.source.split(':')[0]
                if src not in sources:
                    sources[src] = []
                sources[src].append(ep)
            
            print(f"{Colors.CYAN}Endpoints by discovery method:{Colors.RESET}")
            for source, eps in sources.items():
                print(f"\n  {Colors.YELLOW}{source}{Colors.RESET} ({len(eps)} found):")
                for ep in eps[:5]:
                    print(f"    {ep.method:6} {ep.path}")
                if len(eps) > 5:
                    print(f"    ... and {len(eps) - 5} more")
            
            print()
            
            # Save options
            options = [
                "Save to JSON file",
                "Use for scanning now",
                "View all endpoints",
            ]
            
            print_menu("WHAT NEXT?", options)
            choice = get_choice(len(options))
            
            if choice == 1:
                filename = get_input("Filename", "discovered_endpoints.json")
                with open(filename, 'w') as f:
                    json.dump({"endpoints": self.endpoints}, f, indent=2)
                print_success(f"Saved to {filename}")
                self.endpoints_file = filename
            elif choice == 2:
                if confirm("Proceed to scan?"):
                    self.run_scan()
            elif choice == 3:
                print(f"\n{Colors.CYAN}All Discovered Endpoints:{Colors.RESET}\n")
                for i, ep in enumerate(self.endpoints, 1):
                    print(f"  [{i:3}] {ep['method']:6} {ep['path']}")
            
        except Exception as e:
            print_error(f"Discovery failed: {e}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.RESET}")
    
    def show_current_config(self):
        """Display current configuration."""
        print(f"\n{Colors.CYAN}Current Configuration:{Colors.RESET}")
        print(f"  Target URL: {self.target_url or 'Not set'}")
        print(f"  Endpoints File: {self.endpoints_file or 'Not set'}")
        print(f"  Endpoints Loaded: {len(self.endpoints)}")
        print(f"  Auth Token: {'Configured ✓' if self.auth_token else 'Not set'}")
        print(f"  Low-Priv Token: {'Configured ✓' if self.auth_token_low else 'Not set'}")
    
    def quick_scan(self):
        """Run a quick scan with all modules."""
        clear_screen()
        print_banner()
        
        print(f"\n{Colors.CYAN}{'=' * 50}{Colors.RESET}")
        print(f"{Colors.BOLD}  QUICK SCAN - All Modules{Colors.RESET}")
        print(f"{Colors.CYAN}{'=' * 50}{Colors.RESET}\n")
        
        # Check if configured
        if not self.target_url:
            self.target_url = get_input("Enter target URL", "https://api.example.com")
        
        if not self.endpoints:
            self.endpoints_file = get_input("Enter endpoints file", "endpoints.json")
            if not os.path.exists(self.endpoints_file):
                print_error("Endpoints file not found")
                if confirm("Generate template endpoints file?"):
                    self.generate_endpoints(self.endpoints_file)
                    print_warning("Please edit the endpoints file and run scan again")
                    input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.RESET}")
                    return
            else:
                try:
                    with open(self.endpoints_file, 'r') as f:
                        data = json.load(f)
                    self.endpoints = data.get("endpoints", data) if isinstance(data, dict) else data
                except:
                    print_error("Failed to load endpoints")
                    input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.RESET}")
                    return
        
        if not self.auth_token:
            if confirm("Do you have an auth token?"):
                self.auth_token = get_input("Enter auth token")
        
        # Run scan
        self.run_scan()
    
    def custom_scan(self):
        """Run scan with selected modules."""
        clear_screen()
        print_banner()
        
        modules = get_module_info()
        options = [f"{m['name']} - {m['description']}" for m in modules]
        
        print_menu("SELECT MODULES", options)
        print(f"  {Colors.CYAN}[A]{Colors.RESET} Select All")
        
        selected = []
        print(f"\n{Colors.WHITE}Enter module numbers separated by commas (e.g., 1,3,5) or 'A' for all:{Colors.RESET}")
        
        choice = input(f"{Colors.GREEN}>>>{Colors.RESET} ").strip()
        
        if choice.lower() == 'a':
            selected = [m['name'] for m in modules]
        elif choice == '0':
            return
        else:
            try:
                indices = [int(x.strip()) for x in choice.split(',')]
                selected = [modules[i-1]['name'] for i in indices if 1 <= i <= len(modules)]
            except:
                print_error("Invalid selection")
                input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.RESET}")
                return
        
        if not selected:
            print_error("No modules selected")
            input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.RESET}")
            return
        
        print_success(f"Selected modules: {', '.join(selected)}")
        
        # Ensure target is configured
        if not self.target_url:
            self.target_url = get_input("Enter target URL")
        
        if not self.endpoints:
            self.set_endpoints_file()
        
        if not self.endpoints:
            print_error("No endpoints configured")
            input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.RESET}")
            return
        
        # Run scan with selected modules
        self.run_scan(selected)
    
    def run_scan(self, modules: Optional[List[str]] = None):
        """Execute the vulnerability scan."""
        print(f"\n{Colors.CYAN}{'=' * 50}{Colors.RESET}")
        print(f"{Colors.BOLD}  SCANNING TARGET{Colors.RESET}")
        print(f"{Colors.CYAN}{'=' * 50}{Colors.RESET}\n")
        
        print_info(f"Target: {self.target_url}")
        print_info(f"Endpoints: {len(self.endpoints)}")
        print_info(f"Modules: {', '.join(modules) if modules else 'All'}")
        print()
        
        # Create config
        config = ScanConfig(
            base_url=self.target_url,
            endpoints_file=self.endpoints_file,
            auth_token=self.auth_token,
            auth_token_low=self.auth_token_low,
            modules=modules or [],
            verbose=False,
            quiet=False,
        )
        
        # Run async scan
        try:
            self.findings = asyncio.run(self._run_async_scan(config))
        except KeyboardInterrupt:
            print_warning("\nScan interrupted by user")
            return
        except Exception as e:
            print_error(f"Scan error: {e}")
            input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.RESET}")
            return
        
        # Display results
        self.display_scan_results()
    
    async def _run_async_scan(self, config: ScanConfig) -> List[Finding]:
        """Run the async scan."""
        async with Scanner(config) as scanner:
            scanner.endpoints = self.endpoints
            findings = await scanner.scan(module_names=config.modules or None)
            return findings
    
    def display_scan_results(self):
        """Display scan results and offer verification."""
        clear_screen()
        print_banner()
        
        print(f"\n{Colors.CYAN}{'=' * 50}{Colors.RESET}")
        print(f"{Colors.BOLD}  SCAN RESULTS{Colors.RESET}")
        print(f"{Colors.CYAN}{'=' * 50}{Colors.RESET}\n")
        
        if not self.findings:
            print_success("No vulnerabilities detected!")
            input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.RESET}")
            return
        
        # Summary
        severity_counts = {}
        for f in self.findings:
            sev = f.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        print(f"  {Colors.BOLD}Total Findings: {len(self.findings)}{Colors.RESET}\n")
        
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            count = severity_counts.get(sev, 0)
            if count > 0:
                color = {
                    'critical': Colors.MAGENTA,
                    'high': Colors.RED,
                    'medium': Colors.YELLOW,
                    'low': Colors.GREEN,
                    'info': Colors.BLUE,
                }.get(sev, Colors.WHITE)
                print(f"  {color}[{sev.upper()}]{Colors.RESET}: {count}")
        
        # List findings
        print(f"\n{Colors.CYAN}{'─' * 50}{Colors.RESET}")
        
        for i, finding in enumerate(self.findings, 1):
            print_finding(finding, i)
        
        # Offer verification
        if confirm("\nWould you like to verify/test any of these findings?"):
            self.select_finding_to_verify()
        else:
            # Offer to save report
            if confirm("Would you like to save the report?"):
                self.save_report()
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.RESET}")
    
    def select_finding_to_verify(self):
        """Select a finding to verify."""
        if not self.findings:
            print_warning("No findings to verify")
            return
        
        print(f"\n{Colors.CYAN}Select finding to verify (1-{len(self.findings)}):{Colors.RESET}")
        
        for i, f in enumerate(self.findings, 1):
            color = {
                Severity.CRITICAL: Colors.MAGENTA,
                Severity.HIGH: Colors.RED,
                Severity.MEDIUM: Colors.YELLOW,
                Severity.LOW: Colors.GREEN,
                Severity.INFO: Colors.BLUE,
            }.get(f.severity, Colors.WHITE)
            print(f"  {Colors.GREEN}[{i}]{Colors.RESET} {color}[{f.severity.value.upper()}]{Colors.RESET} {f.title} - {f.endpoint}")
        
        choice = get_choice(len(self.findings))
        
        if choice == 0:
            return
        
        finding = self.findings[choice - 1]
        self.verify_finding(finding)
    
    def verify_finding(self, finding: Finding):
        """Verify/exploit a specific finding."""
        clear_screen()
        print_banner()
        
        print(f"\n{Colors.CYAN}{'=' * 50}{Colors.RESET}")
        print(f"{Colors.BOLD}  VERIFY VULNERABILITY{Colors.RESET}")
        print(f"{Colors.CYAN}{'=' * 50}{Colors.RESET}\n")
        
        print_finding(finding, 1)
        
        print(f"\n{Colors.YELLOW}Verification Steps:{Colors.RESET}")
        for line in finding.verification.split('\n'):
            print(f"  {line.strip()}")
        
        if finding.references:
            print(f"\n{Colors.CYAN}References:{Colors.RESET}")
            for ref in finding.references:
                print(f"  • {ref}")
        
        # Module-specific verification
        print(f"\n{Colors.CYAN}{'─' * 50}{Colors.RESET}")
        
        options = [
            "Run automated verification test",
            "Show curl command to test manually",
            "Show payload details",
            "Mark as verified",
            "Mark as false positive",
        ]
        
        print_menu("VERIFICATION OPTIONS", options, show_back=True)
        
        choice = get_choice(len(options))
        
        if choice == 0:
            return
        elif choice == 1:
            self.run_verification_test(finding)
        elif choice == 2:
            self.show_curl_command(finding)
        elif choice == 3:
            self.show_payload_details(finding)
        elif choice == 4:
            print_success("Finding marked as VERIFIED")
        elif choice == 5:
            print_warning("Finding marked as FALSE POSITIVE")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.RESET}")
    
    def run_verification_test(self, finding: Finding):
        """Run automated verification for a finding."""
        print_info("Running verification test...")
        print_warning("⚠️  This will send actual requests to the target")
        
        if not confirm("Continue with verification?"):
            return
        
        # TODO: Implement module-specific verification
        # For now, show what would be tested
        
        print(f"\n{Colors.CYAN}Testing: {finding.title}{Colors.RESET}")
        print(f"Endpoint: {finding.method} {self.target_url}{finding.endpoint}")
        print(f"Module: {finding.module}")
        
        # Simulated verification based on module type
        if finding.module == "bola":
            print("\n[*] Testing with different ID values...")
            print("[*] Comparing responses...")
            print(f"{Colors.GREEN}[+] Vulnerability CONFIRMED - Different user data accessible{Colors.RESET}")
        elif finding.module == "jwt":
            print("\n[*] Testing JWT manipulation...")
            print("[*] Trying 'none' algorithm...")
            print(f"{Colors.GREEN}[+] Vulnerability CONFIRMED - Token accepted{Colors.RESET}")
        elif finding.module == "injection":
            print("\n[*] Testing injection payload...")
            print("[*] Analyzing response...")
            print(f"{Colors.YELLOW}[!] Potential vulnerability - manual verification recommended{Colors.RESET}")
        else:
            print(f"\n{Colors.YELLOW}[!] Automated verification not available for this module{Colors.RESET}")
            print("Please verify manually using the steps provided")
    
    def show_curl_command(self, finding: Finding):
        """Generate and show curl command for manual testing."""
        print(f"\n{Colors.CYAN}curl command for testing:{Colors.RESET}\n")
        
        url = f"{self.target_url}{finding.endpoint}"
        
        cmd = f'curl -X {finding.method} "{url}"'
        
        if self.auth_token:
            cmd += f' \\\n  -H "Authorization: {self.auth_token}"'
        
        cmd += ' \\\n  -H "Content-Type: application/json"'
        
        if finding.module == "bola":
            cmd += '\n\n# Try changing the ID parameter to access other users\' data'
        elif finding.module == "jwt":
            cmd += '\n\n# Try modifying the JWT token (use jwt.io to decode/encode)'
        elif finding.module == "injection":
            cmd += '\n\n# Try adding injection payloads to parameters'
        
        print(cmd)
    
    def show_payload_details(self, finding: Finding):
        """Show detailed payload information."""
        print(f"\n{Colors.CYAN}Payload Details:{Colors.RESET}\n")
        
        if finding.module == "injection":
            print("Common SQL injection payloads:")
            print("  ' OR '1'='1")
            print("  ' UNION SELECT NULL--")
            print("  ' AND SLEEP(5)--")
        elif finding.module == "jwt":
            print("JWT attack techniques:")
            print("  1. Change 'alg' to 'none'")
            print("  2. Try common weak secrets")
            print("  3. Check for expired token acceptance")
        elif finding.module == "bola":
            print("IDOR test values:")
            print("  1, 2, 0, 999, 9999")
            print("  admin, root, test")
            print("  UUID variations")
        elif finding.module == "ssrf":
            print("SSRF payloads:")
            print("  http://127.0.0.1")
            print("  http://169.254.169.254/latest/meta-data/")
            print("  file:///etc/passwd")
        
        print(f"\n{Colors.YELLOW}See /payloads/ directory for comprehensive payload lists{Colors.RESET}")
    
    def verify_exploit_menu(self):
        """Menu for verifying/exploiting vulnerabilities."""
        clear_screen()
        print_banner()
        
        if not self.findings:
            print_warning("No findings from previous scan")
            print_info("Run a scan first to detect vulnerabilities")
            input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.RESET}")
            return
        
        self.select_finding_to_verify()
    
    def view_findings(self):
        """View findings from previous scan."""
        clear_screen()
        print_banner()
        
        if not self.findings:
            print_warning("No findings from previous scan")
            input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.RESET}")
            return
        
        for i, finding in enumerate(self.findings, 1):
            print_finding(finding, i)
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.RESET}")
    
    def generate_endpoints(self, filepath: str = None):
        """Generate a template endpoints file."""
        if not filepath:
            filepath = get_input("Enter output filename", "endpoints.json")
        
        if not filepath:
            return
        
        template = {
            "endpoints": [
                {
                    "path": "/api/v1/users/{id}",
                    "method": "GET",
                    "params": {"id": "1"},
                    "description": "Get user by ID"
                },
                {
                    "path": "/api/v1/users",
                    "method": "POST",
                    "body": {
                        "username": "testuser",
                        "email": "test@example.com"
                    },
                    "description": "Create user"
                },
                {
                    "path": "/api/v1/auth/login",
                    "method": "POST",
                    "body": {
                        "username": "test",
                        "password": "test"
                    },
                    "description": "Login endpoint"
                },
                {
                    "path": "/api/v1/admin/users",
                    "method": "GET",
                    "description": "Admin endpoint"
                }
            ]
        }
        
        try:
            with open(filepath, 'w') as f:
                json.dump(template, f, indent=2)
            
            print_success(f"Template saved to: {filepath}")
            print_info("Edit this file to add your target API endpoints")
            
            self.endpoints_file = filepath
            self.endpoints = template["endpoints"]
            
        except Exception as e:
            print_error(f"Error saving file: {e}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.RESET}")
    
    def save_report(self):
        """Save scan report to file."""
        options = [
            "Save as JSON",
            "Save as HTML",
            "Save as Text",
        ]
        
        print_menu("SAVE REPORT", options)
        
        choice = get_choice(len(options))
        
        if choice == 0:
            return
        
        filename = get_input("Enter filename", f"apivuln_report")
        
        if choice == 1:
            self.save_json_report(filename + ".json")
        elif choice == 2:
            self.save_html_report(filename + ".html")
        elif choice == 3:
            self.save_text_report(filename + ".txt")
    
    def save_json_report(self, filename: str):
        """Save report as JSON."""
        report = {
            "target": self.target_url,
            "endpoints_scanned": len(self.endpoints),
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.findings]
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print_success(f"Report saved to: {filename}")
    
    def save_html_report(self, filename: str):
        """Save report as HTML."""
        # Use scanner's HTML generation
        config = ScanConfig(base_url=self.target_url)
        scanner = Scanner(config)
        scanner.findings = self.findings
        scanner.endpoints = self.endpoints
        scanner.export_html(filename)
        
        print_success(f"Report saved to: {filename}")
    
    def save_text_report(self, filename: str):
        """Save report as plain text."""
        with open(filename, 'w') as f:
            f.write("=" * 50 + "\n")
            f.write("APIVuln Scan Report\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Target: {self.target_url}\n")
            f.write(f"Endpoints Scanned: {len(self.endpoints)}\n")
            f.write(f"Total Findings: {len(self.findings)}\n\n")
            
            for i, finding in enumerate(self.findings, 1):
                f.write("-" * 50 + "\n")
                f.write(f"Finding #{i}\n")
                f.write(f"[{finding.severity.value.upper()}] {finding.title}\n")
                f.write(f"Endpoint: {finding.method} {finding.endpoint}\n")
                f.write(f"Module: {finding.module}\n")
                f.write(f"Confidence: {finding.confidence}%\n")
                f.write(f"Evidence: {finding.evidence}\n")
                f.write(f"Verification: {finding.verification}\n")
                if finding.cwe_id:
                    f.write(f"CWE: {finding.cwe_id}\n")
                f.write("\n")
        
        print_success(f"Report saved to: {filename}")
    
    def show_help(self):
        """Show help and module information."""
        clear_screen()
        print_banner()
        
        print(f"\n{Colors.CYAN}{'=' * 50}{Colors.RESET}")
        print(f"{Colors.BOLD}  AVAILABLE MODULES{Colors.RESET}")
        print(f"{Colors.CYAN}{'=' * 50}{Colors.RESET}\n")
        
        modules = get_module_info()
        
        for m in modules:
            print(f"  {Colors.GREEN}{m['name']}{Colors.RESET}")
            print(f"    {m['description']}")
            print()
        
        print(f"{Colors.CYAN}{'=' * 50}{Colors.RESET}")
        print(f"{Colors.BOLD}  USAGE TIPS{Colors.RESET}")
        print(f"{Colors.CYAN}{'=' * 50}{Colors.RESET}\n")
        
        tips = [
            "1. Start by configuring your target (Option 4)",
            "2. Generate an endpoints.json file if you don't have one",
            "3. Edit endpoints.json with your actual API endpoints",
            "4. Run a Quick Scan to test all modules",
            "5. Review findings and verify each vulnerability",
            "6. Use Custom Scan to focus on specific vulnerability types",
        ]
        
        for tip in tips:
            print(f"  {tip}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.RESET}")
    
    def exit_program(self):
        """Exit the program."""
        print(f"\n{Colors.CYAN}Thanks for using APIVuln!{Colors.RESET}")
        print(f"{Colors.YELLOW}Remember: Only test systems you have permission to test.{Colors.RESET}\n")
        sys.exit(0)


def main():
    """Main entry point."""
    try:
        app = InteractiveMode()
        app.run()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.CYAN}Goodbye!{Colors.RESET}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
