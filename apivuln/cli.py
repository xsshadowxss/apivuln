#!/usr/bin/env python3
"""
APIVuln CLI - Command Line Interface

Main entry point for the API vulnerability scanner.
"""

import argparse
import asyncio
import sys
import json
from pathlib import Path

from . import __version__, __description__
from .config import ScanConfig
from .scanner import Scanner
from .reporter import Reporter, print_error, print_warning, print_info
from .modules import get_all_module_names, get_module_info


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="apivuln",
        description=__description__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  apivuln scan --url https://api.example.com --endpoints endpoints.json
  apivuln scan --url https://api.example.com --endpoints endpoints.json --auth-token "Bearer eyJ..."
  apivuln scan --url https://api.example.com --endpoints endpoints.json --modules bola,jwt,injection
  apivuln scan --url https://api.example.com --endpoints endpoints.json --output report.html --format html
  apivuln modules
  apivuln init --output endpoints.json
        """
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run vulnerability scan")
    
    # Required arguments
    scan_parser.add_argument(
        "--url", "-u",
        required=True,
        help="Base URL of the target API (e.g., https://api.example.com)"
    )
    scan_parser.add_argument(
        "--endpoints", "-e",
        required=True,
        help="Path to endpoints JSON file"
    )
    
    # Authentication
    auth_group = scan_parser.add_argument_group("Authentication")
    auth_group.add_argument(
        "--auth-token", "-t",
        help="Authorization token (e.g., 'Bearer eyJ...')"
    )
    auth_group.add_argument(
        "--auth-token-low",
        help="Lower privilege token for authorization tests"
    )
    auth_group.add_argument(
        "--auth-header",
        default="Authorization",
        help="Header name for auth token (default: Authorization)"
    )
    
    # Scan options
    scan_group = scan_parser.add_argument_group("Scan Options")
    scan_group.add_argument(
        "--modules", "-m",
        help="Comma-separated list of modules to run (default: all)"
    )
    scan_group.add_argument(
        "--threads",
        type=int,
        default=5,
        help="Number of concurrent threads (default: 5)"
    )
    scan_group.add_argument(
        "--delay",
        type=float,
        default=0.1,
        help="Delay between requests in seconds (default: 0.1)"
    )
    scan_group.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Request timeout in seconds (default: 30)"
    )
    scan_group.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL certificate verification"
    )
    
    # Output options
    output_group = scan_parser.add_argument_group("Output Options")
    output_group.add_argument(
        "--output", "-o",
        help="Output file path"
    )
    output_group.add_argument(
        "--format", "-f",
        choices=["terminal", "json", "html", "csv"],
        default="terminal",
        help="Output format (default: terminal)"
    )
    output_group.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Minimal output (only findings)"
    )
    output_group.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output (show all requests)"
    )
    output_group.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )
    
    # Request options
    request_group = scan_parser.add_argument_group("Request Options")
    request_group.add_argument(
        "--header", "-H",
        action="append",
        help="Custom header (can be used multiple times, format: 'Name: Value')"
    )
    request_group.add_argument(
        "--proxy",
        help="Proxy URL (e.g., http://127.0.0.1:8080)"
    )
    
    # Rate limit test options
    rate_group = scan_parser.add_argument_group("Rate Limit Test Options")
    rate_group.add_argument(
        "--rate-limit-requests",
        type=int,
        default=100,
        help="Number of requests for rate limit testing (default: 100)"
    )
    rate_group.add_argument(
        "--rate-limit-period",
        type=int,
        default=5,
        help="Time period for rate limit testing in seconds (default: 5)"
    )
    
    # Modules command
    modules_parser = subparsers.add_parser("modules", help="List available modules")
    
    # Init command
    init_parser = subparsers.add_parser("init", help="Generate template endpoints file")
    init_parser.add_argument(
        "--output", "-o",
        default="endpoints.json",
        help="Output file path (default: endpoints.json)"
    )
    
    # Validate command
    validate_parser = subparsers.add_parser("validate", help="Validate endpoints file")
    validate_parser.add_argument(
        "file",
        help="Endpoints file to validate"
    )
    
    # Interactive command
    interactive_parser = subparsers.add_parser("interactive", help="Launch interactive menu mode")
    
    return parser


def parse_headers(header_list: list) -> dict:
    """Parse header arguments into dict."""
    headers = {}
    if header_list:
        for header in header_list:
            if ":" in header:
                name, value = header.split(":", 1)
                headers[name.strip()] = value.strip()
    return headers


async def run_scan(args) -> int:
    """Run the vulnerability scan."""
    reporter = Reporter(use_color=not args.no_color)
    
    if not args.quiet:
        reporter.print_banner()
    
    # Build configuration
    config = ScanConfig(
        base_url=args.url,
        endpoints_file=args.endpoints,
        auth_token=args.auth_token,
        auth_token_low=args.auth_token_low,
        auth_header=args.auth_header,
        timeout=args.timeout,
        delay=args.delay,
        verify_ssl=not args.no_verify_ssl,
        proxy=args.proxy,
        modules=args.modules.split(",") if args.modules else [],
        threads=args.threads,
        verbose=args.verbose,
        quiet=args.quiet,
        output_file=args.output,
        output_format=args.format,
        rate_limit_requests=args.rate_limit_requests,
        rate_limit_period=args.rate_limit_period,
        headers=parse_headers(args.header),
    )
    
    if not args.quiet:
        reporter.print_config(config)
    
    # Check endpoints file exists
    if not Path(args.endpoints).exists():
        print_error(f"Endpoints file not found: {args.endpoints}")
        return 1
    
    try:
        async with Scanner(config) as scanner:
            # Load endpoints
            scanner.load_endpoints(args.endpoints)
            
            if not args.quiet:
                print_info(f"Loaded {len(scanner.endpoints)} endpoints")
            
            # Run scan
            findings = await scanner.scan()
            
            # Output results
            if args.output:
                results = scanner.get_results()
                
                if args.format == "json":
                    scanner.export_json(args.output)
                    if not args.quiet:
                        print_info(f"Results saved to {args.output}")
                
                elif args.format == "html":
                    scanner.export_html(args.output)
                    if not args.quiet:
                        print_info(f"Report saved to {args.output}")
                
                elif args.format == "csv":
                    csv_content = reporter.format_csv(findings)
                    with open(args.output, "w") as f:
                        f.write(csv_content)
                    if not args.quiet:
                        print_info(f"CSV saved to {args.output}")
            
            # Return code based on findings
            if any(f.severity.value in ["critical", "high"] for f in findings):
                return 2  # Critical/High findings
            elif findings:
                return 1  # Some findings
            return 0  # No findings
    
    except KeyboardInterrupt:
        print_warning("\nScan interrupted by user")
        return 130
    except Exception as e:
        print_error(f"Scan failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def list_modules(args) -> int:
    """List available modules."""
    reporter = Reporter()
    reporter.print_banner()
    
    print_info("Available vulnerability detection modules:\n")
    
    for info in get_module_info():
        print(f"  \033[96m{info['name']}\033[0m (v{info['version']})")
        print(f"    {info['description']}")
        print()
    
    return 0


def init_endpoints(args) -> int:
    """Generate template endpoints file."""
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
                "description": "Create new user"
            },
            {
                "path": "/api/v1/users/{id}",
                "method": "PUT",
                "params": {"id": "1"},
                "body": {
                    "username": "updateduser"
                },
                "description": "Update user"
            },
            {
                "path": "/api/v1/login",
                "method": "POST",
                "body": {
                    "username": "testuser",
                    "password": "testpass"
                },
                "description": "User login endpoint"
            },
            {
                "path": "/api/v1/admin/users",
                "method": "GET",
                "description": "Admin endpoint - list all users"
            }
        ]
    }
    
    output_path = Path(args.output)
    
    if output_path.exists():
        print_warning(f"File {args.output} already exists. Overwrite? [y/N] ", )
        response = input()
        if response.lower() != "y":
            print_info("Aborted")
            return 0
    
    with open(output_path, "w") as f:
        json.dump(template, f, indent=2)
    
    print_info(f"Template endpoints file created: {args.output}")
    print_info("Edit this file to add your API endpoints, then run:")
    print(f"  apivuln scan --url https://your-api.com --endpoints {args.output}")
    
    return 0


def validate_endpoints(args) -> int:
    """Validate endpoints file."""
    filepath = Path(args.file)
    
    if not filepath.exists():
        print_error(f"File not found: {args.file}")
        return 1
    
    try:
        with open(filepath) as f:
            data = json.load(f)
        
        # Check structure
        if isinstance(data, list):
            endpoints = data
        elif isinstance(data, dict) and "endpoints" in data:
            endpoints = data["endpoints"]
        else:
            print_error("Invalid format: expected list or {\"endpoints\": [...]}")
            return 1
        
        # Validate each endpoint
        errors = []
        warnings = []
        
        for i, endpoint in enumerate(endpoints):
            if "path" not in endpoint:
                errors.append(f"Endpoint {i}: missing 'path' field")
            
            if "method" not in endpoint:
                warnings.append(f"Endpoint {i}: missing 'method', will default to GET")
            elif endpoint["method"] not in ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]:
                warnings.append(f"Endpoint {i}: unusual method '{endpoint['method']}'")
            
            if endpoint.get("method") in ["POST", "PUT", "PATCH"] and "body" not in endpoint:
                warnings.append(f"Endpoint {i}: {endpoint['method']} without body")
        
        # Report results
        if errors:
            for error in errors:
                print_error(error)
            return 1
        
        if warnings:
            for warning in warnings:
                print_warning(warning)
        
        print_info(f"✓ Valid endpoints file with {len(endpoints)} endpoints")
        return 0
    
    except json.JSONDecodeError as e:
        print_error(f"Invalid JSON: {e}")
        return 1


def run_interactive():
    """Launch interactive mode."""
    from .interactive import main as interactive_main
    interactive_main()


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    if args.command is None:
        # No command given - launch interactive mode
        run_interactive()
        sys.exit(0)
    
    if args.command == "scan":
        exit_code = asyncio.run(run_scan(args))
    elif args.command == "modules":
        exit_code = list_modules(args)
    elif args.command == "init":
        exit_code = init_endpoints(args)
    elif args.command == "validate":
        exit_code = validate_endpoints(args)
    elif args.command == "interactive":
        run_interactive()
        exit_code = 0
    else:
        parser.print_help()
        exit_code = 0
    
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
