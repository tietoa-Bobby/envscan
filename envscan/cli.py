import argparse
import os
from pathlib import Path
from .scanner import scan_env_file, scan_directory, validate_secrets
from .patterns import Severity

def print_summary(all_warnings, show_placeholders=False):
    """Print a summary of all warnings found."""
    total_files = len(all_warnings)
    total_warnings = sum(len(warnings) for warnings in all_warnings.values())
    
    if total_warnings == 0:
        print("✅ No security issues found!")
        return
    
    print(f"\n📊 Summary:")
    print(f"   Files scanned: {total_files}")
    print(f"   Total warnings: {total_warnings}")
    
    # Count by severity
    severity_counts = {Severity.HIGH: 0, Severity.MEDIUM: 0, Severity.LOW: 0}
    for warnings in all_warnings.values():
        for warning in warnings:
            if show_placeholders or not warning.is_placeholder:
                severity_counts[warning.severity] += 1
    
    print(f"   🔴 High: {severity_counts[Severity.HIGH]}")
    print(f"   🟡 Medium: {severity_counts[Severity.MEDIUM]}")
    print(f"   🟢 Low: {severity_counts[Severity.LOW]}")

def main():
    parser = argparse.ArgumentParser(
        description='Scan .env files for sensitive information or misconfigurations.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  envscan                    # Scan .env in current directory
  envscan myfile.env         # Scan specific file
  envscan /path/to/dir       # Scan directory recursively
  envscan /path/to/dir --no-recursive  # Scan directory non-recursively
  envscan --min-severity HIGH  # Only show high severity issues
  envscan --show-placeholders  # Include likely placeholder values
        """
    )
    
    parser.add_argument('path', nargs='?', default='.env', 
                       help='Path to .env file or directory (default: .env)')
    parser.add_argument('--recursive', '-r', action='store_true', default=True,
                       help='Scan directories recursively (default: True)')
    parser.add_argument('--no-recursive', dest='recursive', action='store_false',
                       help='Do not scan directories recursively')
    parser.add_argument('--min-severity', choices=['LOW', 'MEDIUM', 'HIGH'], 
                       default='LOW', help='Minimum severity to report (default: LOW)')
    parser.add_argument('--show-placeholders', action='store_true',
                       help='Show warnings for likely placeholder values')
    parser.add_argument('--validate-only', action='store_true',
                       help='Only show warnings for likely real secrets (exclude placeholders)')
    
    args = parser.parse_args()
    
    try:
        path = Path(args.path)
        
        if path.is_file():
            # Scan single file
            warnings = scan_env_file(str(path))
            if warnings:
                all_warnings = {str(path): warnings}
            else:
                all_warnings = {}
                
        elif path.is_dir():
            # Scan directory
            all_warnings = scan_directory(str(path), recursive=args.recursive)
            
        else:
            print(f"❌ Error: {args.path} is not a file or directory")
            return 1
        
        if not all_warnings:
            print(f"✅ No issues found in {args.path}")
            return 0
        
        # Filter by severity
        min_severity_level = Severity[args.min_severity]
        filtered_warnings = {}
        
        for file_path, warnings in all_warnings.items():
            filtered = []
            for warning in warnings:
                if warning.severity.value >= min_severity_level.value:
                    if args.validate_only and warning.is_placeholder:
                        continue
                    if not args.show_placeholders and warning.is_placeholder:
                        continue
                    filtered.append(warning)
            
            if filtered:
                filtered_warnings[file_path] = filtered
        
        if not filtered_warnings:
            print(f"✅ No issues found matching your criteria in {args.path}")
            return 0
        
        # Print results
        print(f"🔍 Scanning {args.path}...")
        
        for file_path, warnings in filtered_warnings.items():
            print(f"\n📁 {file_path}:")
            for warning in warnings:
                print(f"  {warning}")
        
        print_summary(filtered_warnings, args.show_placeholders)
        
        # Return appropriate exit code
        high_severity_count = sum(
            1 for warnings in filtered_warnings.values() 
            for warning in warnings 
            if warning.severity == Severity.HIGH and not warning.is_placeholder
        )
        
        return 2 if high_severity_count > 0 else 1
        
    except FileNotFoundError as e:
        print(f"❌ {e}")
        return 1
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1

if __name__ == '__main__':
    exit(main()) 