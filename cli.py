#!/usr/bin/env python3
"""
CyberSec Analyst Tool - Command Line Interface
Simple CLI wrapper for core security tools
"""

import argparse
import sys
from datetime import datetime

# Import core tools
try:
    from network_scanner import NetworkScanner
    from vulnerability_scanner import VulnerabilityScanner
    from password_analyzer import PasswordAnalyzer
    from hash_utils import HashUtils
    from ip_analyzer import IPAnalyzer
    from whois_analyzer import WhoisAnalyzer
    from email_analyzer import EmailAnalyzer
    print("✅ Core tools imported successfully")
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("💡 For full functionality, use the web interface: python3 start.py")
    sys.exit(1)

def scan_network(target, scan_type='quick'):
    """Network scanning via CLI"""
    print(f"🌐 Scanning network target: {target}")
    scanner = NetworkScanner()
    
    if scan_type == 'quick':
        results = scanner.scan_target(target, 'quick_scan')
    elif scan_type == 'full':
        results = scanner.scan_target(target, 'full_scan')
    else:
        results = scanner.scan_target(target, 'port_scan')
    
    print(f"📊 Scan completed:")
    print(f"   Target: {results.get('target', 'N/A')}")
    print(f"   Status: {results.get('status', 'N/A')}")
    print(f"   Open Ports: {len(results.get('open_ports', []))}")
    
    return results

def analyze_password(password):
    """Password analysis via CLI"""
    print("🔐 Analyzing password strength...")
    analyzer = PasswordAnalyzer()
    results = analyzer.analyze_password(password)
    
    print(f"📊 Password Analysis:")
    print(f"   Strength: {results.get('strength_score', 0)}/100")
    print(f"   Entropy: {results.get('entropy', 0):.2f} bits")
    print(f"   Status: {results.get('strength_level', 'Unknown')}")
    
    return results

def analyze_ip(ip_address):
    """IP analysis via CLI"""
    print(f"📍 Analyzing IP address: {ip_address}")
    analyzer = IPAnalyzer()
    results = analyzer.analyze_ip(ip_address)
    
    print(f"📊 IP Analysis:")
    print(f"   Location: {results.get('location', 'Unknown')}")
    print(f"   ISP: {results.get('isp', 'Unknown')}")
    print(f"   Risk Score: {results.get('risk_score', 0)}")
    
    return results

def generate_hash(data, algorithm='sha256'):
    """Hash generation via CLI"""
    print(f"🔑 Generating {algorithm.upper()} hash...")
    hasher = HashUtils()
    result = hasher.generate_hash(data, algorithm)
    
    print(f"📊 Hash Result:")
    print(f"   Algorithm: {algorithm.upper()}")
    print(f"   Hash: {result}")
    
    return result

def main():
    parser = argparse.ArgumentParser(
        description="CyberSec Analyst Tool - Command Line Interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --scan 192.168.1.1 --type quick
  %(prog)s --password "mypassword123"
  %(prog)s --ip 8.8.8.8
  %(prog)s --hash "test data" --algorithm sha256
  %(prog)s --web  # Launch web interface
        """
    )
    
    # Tool selection arguments
    parser.add_argument('--scan', help='Network scan target (IP/hostname)')
    parser.add_argument('--type', choices=['quick', 'full', 'port'], default='quick', help='Scan type')
    parser.add_argument('--password', help='Password to analyze')
    parser.add_argument('--ip', help='IP address to analyze')
    parser.add_argument('--hash', help='Data to hash')
    parser.add_argument('--algorithm', choices=['md5', 'sha1', 'sha256', 'sha512'], default='sha256', help='Hash algorithm')
    parser.add_argument('--web', action='store_true', help='Launch web interface')
    
    args = parser.parse_args()
    
    # Header
    print("=" * 60)
    print("🔒 CyberSec Analyst Tool - CLI Mode")
    print(f"   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    # Web interface launch
    if args.web:
        print("🚀 Launching web interface...")
        import subprocess
        subprocess.run([sys.executable, "start.py"])
        return
    
    # Tool execution
    if args.scan:
        scan_network(args.scan, args.type)
    elif args.password:
        analyze_password(args.password)
    elif args.ip:
        analyze_ip(args.ip)
    elif args.hash:
        generate_hash(args.hash, args.algorithm)
    else:
        print("❌ No action specified")
        print("💡 Use --help for usage information")
        print("🌐 For full interface: python3 cli.py --web")
        parser.print_help()

if __name__ == "__main__":
    main()
