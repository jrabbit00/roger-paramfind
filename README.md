# Roger ParamFind 🐰

[![Python 3.7+](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**Hidden parameter discovery tool for bug bounty hunting.**

Finds unlinked HTTP parameters that can lead to IDOR, XSS, debug features, and other vulnerabilities.

Part of the [Roger Toolkit](https://github.com/jrabbit00/roger-recon) - 14 free security tools for bug bounty hunters.

🔥 **[Get the complete toolkit on Gumroad](https://jrabbit00.gumroad.com)**

## Why Parameter Discovery?

Many endpoints have hidden parameters that aren't linked in the UI:
- `?admin=1` - Access control bypass
- `?debug=true` - Debug features
- `?id=123` - IDOR vulnerabilities
- `?format=json` - API endpoints
- `?preview=true` - Unpublished content

## Features

- Multiple parameter wordlists (short, medium, large)
- Multi-threaded scanning for speed
- Response analysis (detects interesting differences)
- HTTP method support (GET/POST)
- Custom headers and cookies
- Rate limiting awareness
- Verbose and quiet modes

## Installation

```bash
git clone https://github.com/jrabbit00/roger-paramfind.git
cd roger-paramfind
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python3 paramfind.py https://target.com/login

# With wordlist
python3 paramfind.py target.com/page -w params.txt

# Custom threads
python3 paramfind.py target.com -t 20

# POST requests
python3 paramfind.py target.com/api --method POST
```

## Options

| Flag | Description |
|------|-------------|
| `-w, --wordlist` | Parameter wordlist (default: medium) |
| `-t, --threads` | Number of threads (default: 10) |
| `-m, --method` | HTTP method (GET/POST) |
| `-d, --data` | POST data |
| `-H, --headers` | Custom headers |
| `-c, --cookie` | Cookies |
| `-q, --quiet` | Quiet mode |
| `-o, --output` | Output results |

## Wordlists Included

- **mini** - ~50 common params
- **medium** - ~300 params (default)
- **large** - ~2000 params

## Examples

```bash
# Find admin parameters
python3 paramfind.py https://target.com -w wordlists/admin.txt

# Save results
python3 paramfind.py target.com -o findings.txt

# With auth
python3 paramfind.py target.com -c "session=abc123"
```

## 🐰 Part of the Roger Toolkit

| Tool | Purpose |
|------|---------|
| [roger-recon](https://github.com/jrabbit00/roger-recon) | All-in-one recon suite |
| [roger-direnum](https://github.com/jrabbit00/roger-direnum) | Directory enumeration |
| [roger-jsgrab](https://github.com/jrabbit00/roger-jsgrab) | JavaScript analysis |
| [roger-sourcemap](https://github.com/jrabbit00/roger-sourcemap) | Source map extraction |
| [roger-paramfind](https://github.com/jrabbit00/roger-paramfind) | Parameter discovery |
| [roger-wayback](https://github.com/jrabbit00/roger-wayback) | Wayback URL enumeration |
| [roger-cors](https://github.com/jrabbit00/roger-cors) | CORS misconfigurations |
| [roger-jwt](https://github.com/jrabbit00/roger-jwt) | JWT security testing |
| [roger-headers](https://github.com/jrabbit00/roger-headers) | Security header scanner |
| [roger-xss](https://github.com/jrabbit00/roger-xss) | XSS vulnerability scanner |
| [roger-sqli](https://github.com/jrabbit00/roger-sqli) | SQL injection scanner |
| [roger-redirect](https://github.com/jrabbit00/roger-redirect) | Open redirect finder |
| [roger-idor](https://github.com/jrabbit00/roger-idor) | IDOR detection |
| [roger-ssrf](https://github.com/jrabbit00/roger-ssrf) | SSRF vulnerability scanner |

## ☕ Support

If Roger ParamFind helps you find vulnerabilities, consider [supporting the project](https://github.com/sponsors/jrabbit00)!

## License

MIT License - Created by [J Rabbit](https://github.com/jrabbit00)