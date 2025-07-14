import re
import os
from pathlib import Path
from .patterns import RISKY_KEYS, PATTERNS, PLACEHOLDER_PATTERNS, Severity

class Warning:
    def __init__(self, line_number, line, reason, severity, pattern_name=None):
        self.line_number = line_number
        self.line = line
        self.reason = reason
        self.severity = severity
        self.pattern_name = pattern_name
        self.is_placeholder = self._check_placeholder()
    
    def _check_placeholder(self):
        """Check if the value is likely a placeholder rather than a real secret."""
        value = self.line.split('=', 1)[1].strip() if '=' in self.line else ''
        for pattern in PLACEHOLDER_PATTERNS:
            if pattern.search(value):
                return True
        return False
    
    def __repr__(self):
        """Return string representation of the warning."""
        placeholder_note = " (PLACEHOLDER)" if self.is_placeholder else ""
        return f"Warning(line {self.line_number}: {self.severity.value} - {self.reason}{placeholder_note})"
    
    def __str__(self):
        """Return formatted string representation of the warning."""
        placeholder_note = " (likely placeholder)" if self.is_placeholder else ""
        severity_colour = {
            Severity.HIGH: "🔴",
            Severity.MEDIUM: "🟡", 
            Severity.LOW: "🟢"
        }
        return f"{severity_colour[self.severity]} Line {self.line_number}: {self.severity.value} - {self.reason}{placeholder_note}\n    {self.line.strip()}"

def scan_env_file(filepath):
    """Scan a single .env file for sensitive information."""
    warnings = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                
                # Check for risky keys
                for key in RISKY_KEYS:
                    if re.search(rf'(?i)\b{re.escape(key)}\b', line):
                        warnings.append(Warning(i, line, f"Found risky key: {key}", Severity.MEDIUM))
                        break
                
                # Check for pattern matches
                for pattern, severity, pattern_name in PATTERNS:
                    if pattern.search(line):
                        warnings.append(Warning(i, line, f"Pattern match: {pattern_name}", severity, pattern_name))
                        break
                        
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {filepath}")
    except UnicodeDecodeError:
        raise Exception(f"Error reading file {filepath}: File contains invalid UTF-8 characters")
    except PermissionError:
        raise Exception(f"Error reading file {filepath}: Permission denied")
    except Exception as e:
        raise Exception(f"Error reading file {filepath}: {e}")
    
    return warnings

def scan_directory(directory_path, recursive=True):
    """Scan a directory for .env files."""
    directory = Path(directory_path)
    if not directory.exists():
        raise FileNotFoundError(f"Directory not found: {directory_path}")
    
    env_files = []
    if recursive:
        env_files = list(directory.rglob('.env'))
    else:
        env_files = list(directory.glob('.env'))
    
    all_warnings = {}
    for env_file in env_files:
        try:
            warnings = scan_env_file(str(env_file))
            if warnings:
                all_warnings[str(env_file)] = warnings
        except Exception as e:
            print(f"Error scanning {env_file}: {e}")
    
    return all_warnings

def validate_secrets(warnings):
    """Validate if warnings are likely real secrets or placeholders."""
    validated_warnings = []
    for warning in warnings:
        if not warning.is_placeholder:
            validated_warnings.append(warning)
    return validated_warnings 