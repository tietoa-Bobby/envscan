[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://www.python.org/downloads/)

# envscan

A Python CLI tool that scans `.env` files for sensitive information and security misconfigurations.

## Features

- 🔍 **Comprehensive Scanning**: Detects API keys, secrets, tokens, and database URLs
- 🎯 **Severity Levels**: Categorizes findings as HIGH, MEDIUM, or LOW risk
- 🏠 **Recursive Scanning**: Scan entire directory trees for `.env` files
- 🧠 **Smart Validation**: Distinguishes between real secrets and placeholder values
- 🎨 **Beautiful Output**: Color-coded results with emojis and summaries
- ⚡ **Fast & Lightweight**: No external dependencies

## Installation

### From Source
```bash
git clone https://github.com/tietoa-Bobby/envscan.git
cd envscan
pip3 install -e .
```

### From PyPI (when published)
```bash
pip3 install envscan
```

## Usage

### Basic Usage
```bash
# Scan default .env file in current directory
envscan

# Scan a specific file
envscan myfile.env

# Scan a directory recursively
envscan /path/to/project

# Scan directory non-recursively
envscan /path/to/project --no-recursive
```

### Advanced Options
```bash
# Only show high severity issues
envscan --min-severity HIGH

# Include likely placeholder values
envscan --show-placeholders

# Only show real secrets (exclude placeholders)
envscan --validate-only

# Combine options
envscan . --recursive --min-severity MEDIUM --validate-only
```

## What It Detects

### High Severity
- AWS Access Keys (`AKIA...`)
- GitHub Personal Access Tokens (`ghp_...`)
- Stripe Live Secret Keys (`sk_live_...`)
- Private Key Blocks (`-----BEGIN PRIVATE KEY-----`)

### Medium Severity
- Database URLs (PostgreSQL, MySQL, MongoDB, Redis)
- Slack Tokens (`xoxb-...`)
- JWT Tokens
- Google/Firebase API Keys
- Twilio Account SIDs

### Low Severity
- Debug mode enabled
- Generic hex strings
- Common placeholder patterns

## Examples

### Sample Output
```
🔍 Scanning .env...

📁 .env:
  🔴 Line 3: HIGH - Pattern match: GitHub Personal Access Token
    GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef12345678
  🟡 Line 5: MEDIUM - Pattern match: PostgreSQL URL
    DATABASE_URL=postgres://user:pass@localhost:5432/db

📊 Summary:
   Files scanned: 1
   Total warnings: 2
   🔴 High: 1
   🟡 Medium: 1
   🟢 Low: 0
```

## Exit Codes

- `0`: No issues found
- `1`: Issues found (low/medium severity or placeholders)
- `2`: High severity issues found

## Development

### Setup
```bash
git clone https://github.com/tietoa-Bobby/envscan.git
cd envscan
pip3 install -e .
```

### Project Structure
```
envscan/
├── envscan/
│   ├── __init__.py
│   ├── cli.py          # Command-line interface
│   ├── scanner.py      # Core scanning logic
│   └── patterns.py     # Regex patterns and severity levels
├── setup.py            # Package configuration
├── README.md           # This file
├── LICENSE             # MIT License
└── .gitignore          # Git ignore rules
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Adding New Patterns

To add new detection patterns, edit `envscan/patterns.py`:

```python
# Add to PATTERNS list
(re.compile(r'your_pattern'), Severity.HIGH, "Description"),
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security

This tool is designed to help identify potential security issues in your environment files. However, it's not a substitute for proper security practices:

- Always use environment variables for secrets in production
- Never commit real secrets to version control
- Regularly rotate your API keys and tokens
- Use secret management services when possible

 