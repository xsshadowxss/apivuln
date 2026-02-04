# 🔍 APIVuln

**API Vulnerability Scanner for Security Professionals and Bug Hunters**

APIVuln is a comprehensive, modular API security scanner that detects common vulnerabilities in REST APIs. It's designed to help security professionals and bug bounty hunters identify potential security issues that require manual verification.

![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## ✨ Features

- **🎯 Modular Architecture** - Enable/disable specific vulnerability checks
- **🔐 Authentication Support** - Test with different privilege levels
- **📊 Multiple Output Formats** - Terminal, JSON, HTML, CSV reports
- **⚡ Async & Fast** - Concurrent scanning with rate limiting
- **🛡️ OWASP Coverage** - Covers OWASP API Security Top 10

## 🔬 Vulnerability Detection Modules

| Module | Description | OWASP |
|--------|-------------|-------|
| `bola` | Broken Object Level Authorization (IDOR) | API1:2023 |
| `bfla` | Broken Function Level Authorization | API5:2023 |
| `jwt` | JWT vulnerabilities (none alg, weak secrets, expired tokens) | API2:2023 |
| `injection` | SQL, NoSQL, and SSRF injection | API8:2023 |
| `rate_limit` | Missing or weak rate limiting | API4:2023 |
| `mass_assign` | Mass assignment vulnerabilities | API6:2023 |
| `disclosure` | Information disclosure, verbose errors | API3:2023 |

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/apivuln.git
cd apivuln

# Install in development mode
pip install -e .

# Or install dependencies directly
pip install -r requirements.txt
```

## 📖 Usage

### Quick Start

```bash
# Generate a template endpoints file
apivuln init --output endpoints.json

# Edit endpoints.json with your target API endpoints

# Run a scan
apivuln scan --url https://api.target.com --endpoints endpoints.json
```

### Full Scan with Authentication

```bash
apivuln scan \
  --url https://api.target.com \
  --endpoints endpoints.json \
  --auth-token "Bearer eyJhbGciOiJIUzI1NiIs..." \
  --auth-token-low "Bearer eyJhbGciOiJIUzI1NiIs..." \
  --output report.html \
  --format html
```

### Run Specific Modules

```bash
apivuln scan \
  --url https://api.target.com \
  --endpoints endpoints.json \
  --modules bola,jwt,injection
```

### List Available Modules

```bash
apivuln modules
```

## 📝 Endpoints File Format

Create a JSON file defining your API endpoints:

```json
{
  "endpoints": [
    {
      "path": "/api/v1/users/{id}",
      "method": "GET",
      "params": {"id": "123"},
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
      "path": "/api/v1/admin/users",
      "method": "GET",
      "description": "Admin endpoint"
    }
  ]
}
```

### Endpoint Fields

| Field | Required | Description |
|-------|----------|-------------|
| `path` | Yes | API endpoint path (supports `{param}` placeholders) |
| `method` | No | HTTP method (default: GET) |
| `params` | No | URL/path parameters |
| `body` | No | Request body (for POST/PUT/PATCH) |
| `headers` | No | Additional headers for this endpoint |
| `description` | No | Description for reports |

## 🎛️ CLI Options

```
apivuln scan [OPTIONS]

Required:
  --url, -u          Base URL of the target API
  --endpoints, -e    Path to endpoints JSON file

Authentication:
  --auth-token, -t   Authorization token (e.g., 'Bearer eyJ...')
  --auth-token-low   Lower privilege token for authz tests
  --auth-header      Header name for auth (default: Authorization)

Scan Options:
  --modules, -m      Comma-separated list of modules
  --threads          Concurrent threads (default: 5)
  --delay            Delay between requests in seconds (default: 0.1)
  --timeout          Request timeout in seconds (default: 30)
  --no-verify-ssl    Disable SSL verification

Output:
  --output, -o       Output file path
  --format, -f       Output format: terminal, json, html, csv
  --quiet, -q        Minimal output
  --verbose, -v      Verbose output
  --no-color         Disable colors

Request Options:
  --header, -H       Custom header (format: 'Name: Value')
  --proxy            Proxy URL (e.g., http://127.0.0.1:8080)
```

## 📊 Sample Output

### Terminal Output

```
    ___    ____  ____     __      __     
   /   |  / __ \/  _/    / /___  / /____ 
  / /| | / /_/ // /_____/ / __ \/ __/ _ \
 / ___ |/ ____// /_____/ / / / / /_/  __/
/_/  |_/_/   /___/    /_/_/ /_/\__/\___/ 
                                         
[*] Target: https://api.target.com
[*] Endpoints: 12
[*] Modules: bola, bfla, jwt, injection, rate_limit, mass_assign, disclosure

[scanning] GET /api/v1/users/{id} 

[HIGH] Potential BOLA/IDOR Vulnerability on GET /api/v1/users/{id}
       Evidence: Changing id from '123' to '1' returned different data with same auth
       Confidence: 75%
       → Verify: Send request with different ID values and compare responses

[CRITICAL] JWT 'none' Algorithm Accepted on GET /api/v1/profile
       Evidence: Server accepted JWT with alg:none
       Confidence: 95%
       → Verify: Modify token header to {"alg":"none"} and remove signature

[*] Scan complete: 2 findings (1 critical, 1 high)
```

### HTML Report

The HTML report includes:
- Scan metadata and statistics
- Findings sorted by severity
- Evidence and verification steps
- CWE references and links

## ⚠️ Important Notes

1. **Authorization Required** - Only scan APIs you have permission to test
2. **Verification Needed** - Findings indicate *potential* vulnerabilities that require manual verification
3. **Rate Limiting** - Use `--delay` to avoid overwhelming targets
4. **False Positives** - Some findings may be false positives; always verify manually

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

### Adding New Modules

1. Create a new file in `apivuln/modules/`
2. Inherit from `BaseModule`
3. Implement the `run()` method
4. Register in `apivuln/modules/__init__.py`

```python
from .base import BaseModule, Finding, Severity

class MyModule(BaseModule):
    name = "mymodule"
    description = "My custom vulnerability check"
    
    async def run(self, endpoint: dict) -> list[Finding]:
        findings = []
        # Your detection logic here
        return findings
```

## 📜 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- [OWASP API Security Project](https://owasp.org/www-project-api-security/)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)

---

**Disclaimer**: This tool is for authorized security testing only. Always obtain proper authorization before testing any API. The authors are not responsible for misuse of this tool.
