# Roger ParamFind 🐰

Hidden parameter discovery tool for bug bounty hunting. Finds unlinked HTTP parameters that can lead to IDOR, XSS, and other vulnerabilities.

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

## License

MIT License