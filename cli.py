#!/usr/bin/env python3
"""
CyberSec Analyst Tool - Command Line Interface
Modernized CLI wrapper for core security tools.
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime


def _load_tool(module_name, class_name):
    try:
        module = __import__(module_name, fromlist=[class_name])
        return getattr(module, class_name)
    except Exception as exc:
        raise RuntimeError(
            'Unable to load {} from {}: {}'.format(class_name, module_name, exc)
        )


def _print_json(data):
    print(json.dumps(data, indent=2, sort_keys=True, default=str))


def scan_network(target, scan_type='quick', ports=None, as_json=False):
    """Network scanning via CLI."""
    scanner = _load_tool('network_scanner', 'NetworkScanner')()

    scan_map = {
        'quick': 'quick_scan',
        'full': 'full_scan',
        'port': 'custom_ports',
    }
    internal_scan_type = scan_map.get(scan_type, 'quick_scan')
    custom_ports = ports if internal_scan_type == 'custom_ports' else None

    result = scanner.scan_target(
        target,
        scan_type=internal_scan_type,
        custom_ports=custom_ports,
        grab_banners=bool(custom_ports),
    )

    if as_json:
        _print_json(result)
        return result

    print('🌐 Network Scan')
    print('   Target: {}'.format(result.get('target', 'N/A')))
    print('   Status: {}'.format(result.get('status', 'unknown')))

    if result.get('status') != 'completed':
        print('   Error: {}'.format(result.get('error', 'unknown error')))
        return result

    print('   Target IP: {}'.format(result.get('target_ip', 'N/A')))
    print('   Scan Type: {}'.format(result.get('scan_type', 'N/A')))
    print('   Open Ports: {}'.format(result.get('open_port_count', 0)))
    print('   Duration: {}s'.format(result.get('scan_duration_seconds', 0)))

    risk_summary = result.get('risk_summary', {})
    print('   Risk Level: {}'.format(risk_summary.get('risk_level', 'unknown')))

    for port_info in result.get('open_ports', []):
        banner = port_info.get('banner')
        row = '     - {:>5}/tcp {} ({})'.format(
            port_info.get('port', '?'),
            port_info.get('service', 'Unknown'),
            port_info.get('state', 'open'),
        )
        if banner:
            row += ' | {}'.format(banner)
        print(row)

    return result


def scan_vulnerabilities(target, assessment='web', aggressive=False, as_json=False):
    """Vulnerability assessment via CLI."""
    scanner = _load_tool('vulnerability_scanner', 'VulnerabilityScanner')()
    report = scanner.assess_target(target, assessment_type=assessment, aggressive=aggressive)

    if as_json:
        _print_json(report)
        return report

    print('🔍 Vulnerability Assessment')
    print('   Target: {}'.format(report.get('target', target)))
    print('   Assessment: {}'.format(report.get('assessment_type', assessment)))
    print('   Status: {}'.format(report.get('status', 'unknown')))

    if report.get('status') != 'completed':
        print('   Error: {}'.format(report.get('error', 'unknown error')))
        return report

    print('   Risk Level: {}'.format(report.get('risk_level', 'unknown')))
    counts = report.get('severity_counts', {})
    print(
        '   Severity Counts: critical={critical}, high={high}, medium={medium}, low={low}, info={info}'.format(
            critical=counts.get('critical', 0),
            high=counts.get('high', 0),
            medium=counts.get('medium', 0),
            low=counts.get('low', 0),
            info=counts.get('info', 0),
        )
    )

    for vuln in report.get('vulnerabilities', []):
        print(
            '     - [{severity}] {name}: {description}'.format(
                severity=vuln.get('severity', 'low').upper(),
                name=vuln.get('name', 'Unnamed finding'),
                description=vuln.get('description', 'No details'),
            )
        )

    return report


def scan_tls(target, port=443, as_json=False):
    """TLS security analysis via CLI."""
    analyzer = _load_tool('tls_security_analyzer', 'TLSSecurityAnalyzer')()
    report = analyzer.analyze_target(target, port=port)

    if as_json:
        _print_json(report)
        return report

    print('🔐 TLS Security Analysis')
    print('   Target: {}'.format(target))
    print('   Host: {}'.format(report.get('hostname', 'N/A')))
    print('   Port: {}'.format(report.get('port', port)))
    print('   Status: {}'.format(report.get('status', 'unknown')))

    if report.get('status') != 'completed':
        print('   Error: {}'.format(report.get('error', 'unknown error')))
        return report

    certificate = report.get('certificate', {})
    print('   Risk Level: {}'.format(report.get('risk_level', 'unknown')))
    print('   Certificate Subject: {}'.format(certificate.get('subject', 'N/A')))
    print('   Certificate Issuer: {}'.format(certificate.get('issuer', 'N/A')))
    print('   Days Until Expiry: {}'.format(certificate.get('days_until_expiry', 'N/A')))

    protocol_support = report.get('protocol_support', {})
    if protocol_support:
        print('   Protocol Support:')
        for protocol, enabled in protocol_support.items():
            state = 'enabled' if enabled else 'disabled'
            if enabled is None:
                state = 'unknown'
            print('     - {}: {}'.format(protocol, state))

    for finding in report.get('findings', []):
        print(
            '     - [{severity}] {name}: {description}'.format(
                severity=finding.get('severity', 'low').upper(),
                name=finding.get('name', 'Unnamed finding'),
                description=finding.get('description', 'No details'),
            )
        )

    return report


def analyze_password(password, as_json=False):
    """Password analysis via CLI."""
    analyzer = _load_tool('password_analyzer', 'PasswordAnalyzer')()
    result = analyzer.analyze_password(password)

    if as_json:
        _print_json(result)
        return result

    print('🔐 Password Analysis')
    print('   Strength: {}/100'.format(result.get('strength_score', 0)))
    print('   Entropy: {:.2f} bits'.format(result.get('entropy', 0)))
    print('   Status: {}'.format(result.get('strength_level', 'Unknown')))

    return result


def analyze_ip(ip_address, as_json=False):
    """IP analysis via CLI."""
    analyzer = _load_tool('ip_analyzer', 'IPAnalyzer')()
    result = analyzer.analyze_ip(ip_address)

    if as_json:
        _print_json(result)
        return result

    print('📍 IP Analysis')
    print('   Target: {}'.format(ip_address))
    print('   Location: {}'.format(result.get('location', 'Unknown')))
    print('   ISP: {}'.format(result.get('isp', 'Unknown')))
    print('   Risk Score: {}'.format(result.get('risk_score', 0)))

    return result


def generate_hash(data, algorithm='sha256', as_json=False):
    """Hash generation via CLI."""
    hasher = _load_tool('hash_utils', 'HashUtils')()
    digest = hasher.generate_hash(data, algorithm)

    if as_json:
        _print_json({'algorithm': algorithm, 'hash': digest})
        return digest

    print('🔑 Hash Result')
    print('   Algorithm: {}'.format(algorithm.upper()))
    print('   Hash: {}'.format(digest))

    return digest


def main():
    parser = argparse.ArgumentParser(
        description='CyberSec Analyst Tool - Command Line Interface',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --scan 192.168.1.1 --type quick
  %(prog)s --scan 192.168.1.1 --type port --ports 22,80,443
  %(prog)s --vuln https://example.com --assessment web --aggressive
  %(prog)s --tls example.com --tls-port 443
  %(prog)s --password "mypassword123"
  %(prog)s --ip 8.8.8.8
  %(prog)s --hash "test data" --algorithm sha256
  %(prog)s --json --vuln https://example.com
  %(prog)s --web
        """,
    )

    parser.add_argument('--scan', help='Network scan target (IP/hostname)')
    parser.add_argument('--type', choices=['quick', 'full', 'port'], default='quick', help='Scan type')
    parser.add_argument('--ports', help='Custom port list/range (e.g. 22,80,443 or 1-1024)')

    parser.add_argument('--vuln', help='Vulnerability scan target')
    parser.add_argument(
        '--assessment',
        choices=['web', 'network', 'ssl'],
        default='web',
        help='Vulnerability assessment mode',
    )
    parser.add_argument('--aggressive', action='store_true', help='Enable active payload checks for web assessments')

    parser.add_argument('--tls', help='TLS analysis target (host, host:port, or URL)')
    parser.add_argument('--tls-port', type=int, default=443, help='TLS port (default: 443)')

    parser.add_argument('--password', help='Password to analyze')
    parser.add_argument('--ip', help='IP address to analyze')
    parser.add_argument('--hash', dest='hash_data', help='Data to hash')
    parser.add_argument(
        '--algorithm',
        choices=['md5', 'sha1', 'sha256', 'sha512'],
        default='sha256',
        help='Hash algorithm',
    )

    parser.add_argument('--json', action='store_true', help='Output structured JSON')
    parser.add_argument('--web', action='store_true', help='Launch web terminal interface')

    args = parser.parse_args()

    if not args.json:
        print('=' * 60)
        print('🔒 CyberSec Analyst Tool - CLI Mode')
        print('   {}'.format(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        print('=' * 60)

    if args.web:
        if not args.json:
            print('🚀 Launching web terminal...')
        subprocess.run([sys.executable, 'terminal_web.py'])
        return

    try:
        if args.scan:
            scan_network(args.scan, scan_type=args.type, ports=args.ports, as_json=args.json)
            return

        if args.vuln:
            scan_vulnerabilities(
                args.vuln,
                assessment=args.assessment,
                aggressive=args.aggressive,
                as_json=args.json,
            )
            return

        if args.tls:
            scan_tls(args.tls, port=args.tls_port, as_json=args.json)
            return

        if args.password:
            analyze_password(args.password, as_json=args.json)
            return

        if args.ip:
            analyze_ip(args.ip, as_json=args.json)
            return

        if args.hash_data:
            generate_hash(args.hash_data, args.algorithm, as_json=args.json)
            return
    except RuntimeError as exc:
        if args.json:
            _print_json({'status': 'failed', 'error': str(exc)})
        else:
            print('❌ {}'.format(exc))
            print('💡 Install project dependencies with: pip install -r requirements.txt')
        sys.exit(1)

    if not args.json:
        print('❌ No action specified')
        print('💡 Use --help for usage information')
        print('🌐 For full interface: python3 cli.py --web')
    parser.print_help()


if __name__ == '__main__':
    main()
