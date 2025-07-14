"""
Pattern definitions for envscan.

This module contains all the regex patterns and configuration used to detect
sensitive information in .env files.
"""

import re
from enum import Enum


class Severity(Enum):
    """Severity levels for detected security issues."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

# Environment variable keys that commonly contain sensitive information
RISKY_KEYS = [
    'API_KEY', 'SECRET', 'PASSWORD', 'TOKEN', 'ACCESS_KEY', 'PRIVATE_KEY', 
    'CLIENT_SECRET', 'DB_PASSWORD', 'AWS_SECRET', 'GCP_KEY', 'SLACK_TOKEN', 
    'SESSION_SECRET', 'ENCRYPTION_KEY', 'SECRET_KEY', 'AUTH_TOKEN', 'JWT', 'OAUTH', 
    'SSH_KEY', 'PGPASSWORD', 'MYSQL_PWD', 'MONGO_URI', 'REDIS_URL', 'DATABASE_URL',
    'GITHUB_TOKEN', 'DOCKER_SECRET', 'KUBERNETES_SECRET', 'AZURE_KEY', 'FIREBASE_KEY',
    'STRIPE_KEY', 'TWILIO_TOKEN', 'SENDGRID_KEY', 'MAILGUN_KEY', 'ALGOLIA_KEY',
    'CLOUDFLARE_TOKEN', 'DIGITALOCEAN_TOKEN', 'HEROKU_API_KEY', 'VERCEL_TOKEN',
    'NETLIFY_TOKEN', 'RAILWAY_TOKEN', 'RENDER_API_KEY', 'FLY_API_TOKEN'
]

# Regex patterns for detecting specific types of sensitive information
# Each pattern is a tuple of (regex, severity, description)
PATTERNS = [
    # High severity patterns
    (re.compile(r'AKIA[0-9A-Z]{16}'), Severity.HIGH, "AWS Access Key"),
    (re.compile(r'(?i)aws_secret_access_key\s*=\s*[^\s#]+'), Severity.HIGH, "AWS Secret Key"),
    (re.compile(r'ghp_[0-9a-zA-Z]{36}'), Severity.HIGH, "GitHub Personal Access Token"),
    (re.compile(r'gho_[0-9a-zA-Z]{36}'), Severity.HIGH, "GitHub OAuth Token"),
    (re.compile(r'ghu_[0-9a-zA-Z]{36}'), Severity.HIGH, "GitHub User-to-Server Token"),
    (re.compile(r'ghs_[0-9a-zA-Z]{36}'), Severity.HIGH, "GitHub Server-to-Server Token"),
    (re.compile(r'ghr_[0-9a-zA-Z]{36}'), Severity.HIGH, "GitHub Refresh Token"),
    (re.compile(r'sk_live_[0-9a-zA-Z]{24}'), Severity.HIGH, "Stripe Live Secret Key"),
    (re.compile(r'pk_live_[0-9a-zA-Z]{24}'), Severity.MEDIUM, "Stripe Live Publishable Key"),
    (re.compile(r'-----BEGIN (RSA|DSA|EC|OPENSSH|PRIVATE) KEY-----'), Severity.HIGH, "Private Key Block"),
    
    # Medium severity patterns
    (re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}'), Severity.MEDIUM, "Slack Token"),
    (re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+'), Severity.MEDIUM, "JWT Token"),
    (re.compile(r'AIza[0-9A-Za-z\-_]{35}'), Severity.MEDIUM, "Google/Firebase API Key"),
    (re.compile(r'1//[0-9A-Za-z\-_]{35}'), Severity.MEDIUM, "Google OAuth Token"),
    (re.compile(r'ya29\.[0-9A-Za-z\-_]+'), Severity.MEDIUM, "Google OAuth Access Token"),
    (re.compile(r'AC[0-9a-fA-F]{32}'), Severity.MEDIUM, "Twilio Account SID"),
    (re.compile(r'[0-9a-fA-F]{32}'), Severity.LOW, "Generic 32-character hex string"),
    
    # Database URLs
    (re.compile(r'postgres://[^\s]+'), Severity.MEDIUM, "PostgreSQL URL"),
    (re.compile(r'mysql://[^\s]+'), Severity.MEDIUM, "MySQL URL"),
    (re.compile(r'mongodb://[^\s]+'), Severity.MEDIUM, "MongoDB URL"),
    (re.compile(r'redis://[^\s]+'), Severity.MEDIUM, "Redis URL"),
    (re.compile(r'neo4j://[^\s]+'), Severity.MEDIUM, "Neo4j URL"),
    (re.compile(r'cassandra://[^\s]+'), Severity.MEDIUM, "Cassandra URL"),
    
    # Generic patterns
    (re.compile(r'(?i)password\s*=\s*[^\s#]+'), Severity.MEDIUM, "Generic Password"),
    (re.compile(r'(?i)debug\s*=\s*true'), Severity.LOW, "Debug Mode Enabled"),
    (re.compile(r'(?i)secret\s*=\s*[^\s#]+'), Severity.MEDIUM, "Generic Secret"),
    (re.compile(r'(?i)token\s*=\s*[^\s#]+'), Severity.MEDIUM, "Generic Token"),
]

# Patterns that indicate a value is likely a placeholder rather than a real secret
PLACEHOLDER_PATTERNS = [
    re.compile(r'(?i)(placeholder|example|test|demo|sample|dummy|fake|mock)'),
    re.compile(r'(?i)(your_|my_|the_)'),
    re.compile(r'(?i)(123|abc)'),
    re.compile(r'[a-z]{3,10}_[a-z]{3,10}'),  # Simple word_word patterns
] 