#!/usr/bin/env python3
"""
CSS-styled web terminal for CyberSec tools.
Real scanner-backed command handlers for network and vulnerability workflows.
"""

import hashlib
import os
import secrets
import shlex
import threading
import time
import uuid
from datetime import datetime
from html import escape

from flask import Flask, jsonify, render_template, request, session

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

TOOL_IMPORT_ERRORS = {}

NETWORK_SCANNER = None
try:  # pragma: no cover - runtime dependency path
    from network_scanner import NetworkScanner

    NETWORK_SCANNER = NetworkScanner()
except Exception as exc:
    TOOL_IMPORT_ERRORS['network'] = str(exc)

VULN_SCANNER = None
try:  # pragma: no cover - runtime dependency path
    from vulnerability_scanner import VulnerabilityScanner

    VULN_SCANNER = VulnerabilityScanner()
except Exception as exc:
    TOOL_IMPORT_ERRORS['vulnerability'] = str(exc)

TLS_ANALYZER = None
try:  # pragma: no cover - runtime dependency path
    from tls_security_analyzer import TLSSecurityAnalyzer

    TLS_ANALYZER = TLSSecurityAnalyzer()
except Exception as exc:
    TOOL_IMPORT_ERRORS['tls'] = str(exc)

IP_ANALYZER = None
try:  # pragma: no cover - runtime dependency path
    from ip_analyzer import IPAnalyzer

    IP_ANALYZER = IPAnalyzer()
except Exception as exc:
    TOOL_IMPORT_ERRORS['ip'] = str(exc)

DOMAIN_ANALYZER = None
try:  # pragma: no cover - runtime dependency path
    from whois_analyzer import WhoisAnalyzer

    DOMAIN_ANALYZER = WhoisAnalyzer()
except Exception as exc:
    TOOL_IMPORT_ERRORS['domain'] = str(exc)

EMAIL_ANALYZER = None
try:  # pragma: no cover - runtime dependency path
    from email_analyzer import EmailAnalyzer

    EMAIL_ANALYZER = EmailAnalyzer()
except Exception as exc:
    TOOL_IMPORT_ERRORS['email'] = str(exc)

LOG_ANALYZER = None
try:  # pragma: no cover - runtime dependency path
    from log_analyzer import LogAnalyzer

    LOG_ANALYZER = LogAnalyzer()
except Exception as exc:
    TOOL_IMPORT_ERRORS['logs'] = str(exc)

REPORT_GENERATOR = None
try:  # pragma: no cover - runtime dependency path
    from report_generator import ReportGenerator

    REPORT_GENERATOR = ReportGenerator()
except Exception as exc:
    TOOL_IMPORT_ERRORS['report'] = str(exc)


class TerminalSession:
    def __init__(self):
        self.session_id = str(uuid.uuid4())[:8]
        self.start_time = datetime.now()
        self.command_history = []
        self.current_directory = '~'
        self.username = 'cybersec'
        self.hostname = 'security-terminal'

    def add_command(self, command, output):
        self.command_history.append(
            {
                'timestamp': datetime.now().isoformat(),
                'command': command,
                'output': output,
            }
        )


terminal_sessions = {}


def get_session():
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())[:8]
        terminal_sessions[session['session_id']] = TerminalSession()

    return terminal_sessions.get(session['session_id'])


@app.route('/')
def terminal():
    return render_template('terminal.html')


@app.route('/execute', methods=['POST'])
def execute_command():
    payload = request.get_json(silent=True) or {}
    command = str(payload.get('command', '')).strip()

    terminal_session = get_session()
    output = process_command(command, terminal_session)
    terminal_session.add_command(command, output)

    return jsonify(
        {
            'output': output,
            'prompt': '{}@{}:~$ '.format(terminal_session.username, terminal_session.hostname),
        }
    )


def process_command(command, user_session):
    """Process terminal commands and return formatted output."""
    if not command:
        return ''

    try:
        cmd_parts = shlex.split(command)
    except ValueError as exc:
        return '<span class="error">Command parsing error: {}</span>'.format(_safe_text(str(exc)))

    if not cmd_parts:
        return ''

    cmd = cmd_parts[0].lower()
    args = cmd_parts[1:]

    # System commands
    if cmd == 'help':
        return get_help_text()
    if cmd == 'clear':
        return 'CLEAR_SCREEN'
    if cmd == 'whoami':
        return user_session.username
    if cmd == 'pwd':
        return user_session.current_directory
    if cmd == 'date':
        return datetime.now().strftime('%a %b %d %H:%M:%S %Z %Y')
    if cmd == 'uptime':
        uptime = datetime.now() - user_session.start_time
        return 'up {}h {}m'.format(uptime.seconds // 3600, (uptime.seconds % 3600) // 60)
    if cmd == 'id':
        return 'uid=1000({0}) gid=1000(cybersec) groups=1000(cybersec),27(sudo)'.format(user_session.username)
    if cmd == 'uname':
        return 'CyberSec-Terminal 5.4.0-cybersec #1 SMP x86_64 GNU/Linux'

    # CyberSec commands
    if cmd in ('01', 'netscan', 'network-scan'):
        return run_network_scanner(args)
    if cmd in ('02', 'vulnscan', 'vuln-scan'):
        return run_vulnerability_scanner(args)
    if cmd in ('03', 'passcheck', 'password-check'):
        return run_password_analyzer(args)
    if cmd in ('04', 'hash'):
        return run_hash_utilities(args)
    if cmd in ('05', 'ipinfo', 'ip-info'):
        return run_ip_analyzer(args)
    if cmd in ('06', 'domain', 'whois'):
        return run_domain_analyzer(args)
    if cmd in ('07', 'email'):
        return run_email_analyzer(args)
    if cmd in ('08', 'logs', 'log-analyzer'):
        return run_log_analyzer(args)
    if cmd in ('09', 'report'):
        return run_report_generator(args)
    if cmd in ('10', 'tlscheck', 'tls-scan'):
        return run_tls_analyzer(args)
    if cmd == 'menu':
        return get_menu_text()
    if cmd == 'status':
        return get_status_text(user_session)
    if cmd == 'exit':
        return 'Session terminated. Thank you for using CyberSec Terminal.'

    # Filesystem simulation
    if cmd == 'ls':
        return get_directory_listing()
    if cmd == 'cat':
        if args:
            return get_file_content(args[0])
        return 'cat: missing file operand'

    return 'cybersec-terminal: command not found: {}\nType \"help\" for available commands'.format(
        _safe_text(command)
    )


def _safe_text(value):
    return escape(str(value), quote=False)


def _core_tools_unavailable_message(tool_name):
    reason = TOOL_IMPORT_ERRORS.get(tool_name, 'unknown')
    return (
        '<span class="error">Requested scanning tool is unavailable in this runtime.</span>\n'
        'Reason: {}\n'
        'Run from the project root or install package modules.'.format(_safe_text(reason))
    )


def _severity_css(severity):
    mapping = {
        'critical': 'vuln-high',
        'high': 'vuln-high',
        'medium': 'vuln-medium',
        'low': 'vuln-low',
        'info': 'status-info',
    }
    return mapping.get(str(severity).lower(), 'vuln-low')


def get_help_text():
    return """<span class="help-header">CyberSec Terminal - Command Reference</span>

<span class="help-section">SYSTEM COMMANDS:</span>
  help           - Show this help message
  clear          - Clear the terminal screen
  menu           - Show security modules menu
  status         - Show system status
  whoami         - Display current user
  pwd            - Print working directory
  ls             - List directory contents
  date           - Display current date/time
  exit           - Exit terminal

<span class="help-section">CYBERSECURITY TOOLS:</span>
  01, netscan    - Network Scanner
  02, vulnscan   - Vulnerability Scanner
  03, passcheck  - Password Analyzer
  04, hash       - Hash Utilities
  05, ipinfo     - IP Intelligence
  06, domain     - Domain Analysis
  07, email      - Email Security
  08, logs       - Log Analyzer
  09, report     - Report Generator
  10, tlscheck   - TLS security analyzer

<span class="help-section">EXAMPLES:</span>
  netscan 192.168.1.1 quick
  netscan 192.168.1.1 port 22,80,443
  vulnscan https://example.com web --aggressive
  vulnscan 10.0.0.5 network
  tlscheck example.com 443
    email security@example.com --content "urgent verify your account"
    logs --type apache_common "203.0.113.9 - - [31/Jul/2026:12:00:00 +0000] \"GET /admin HTTP/1.1\" 401 721"
    report comprehensive --title "Weekly Snapshot"

<span class="help-footer">Use 'menu' to see all available security modules</span>"""


def get_menu_text():
    return """<span class="menu-header">CYBERSEC TERMINAL - SECURITY MODULES</span>

┌─────────────────────────────────────────────────────────────┐
│  <span class="menu-item">[01]</span> <span class="tool-name">Network Scanner</span>      │ Port scanning & discovery       │
│  <span class="menu-item">[02]</span> <span class="tool-name">Vulnerability Scan</span>   │ Web and service assessment      │
│  <span class="menu-item">[03]</span> <span class="tool-name">Password Analyzer</span>    │ Password strength evaluation    │
│  <span class="menu-item">[04]</span> <span class="tool-name">Hash Utilities</span>       │ Generate & verify hashes        │
│  <span class="menu-item">[05]</span> <span class="tool-name">IP Intelligence</span>      │ Geolocation & reputation        │
│  <span class="menu-item">[06]</span> <span class="tool-name">Domain Analysis</span>      │ WHOIS & DNS investigation       │
│  <span class="menu-item">[07]</span> <span class="tool-name">Email Security</span>       │ Email threat analysis           │
│  <span class="menu-item">[08]</span> <span class="tool-name">Log Analyzer</span>         │ Security log investigation      │
│  <span class="menu-item">[09]</span> <span class="tool-name">Report Generator</span>     │ Security reporting              │
│  <span class="menu-item">[10]</span> <span class="tool-name">TLS Analyzer</span>         │ Certificate and protocol check  │
└─────────────────────────────────────────────────────────────┘

Type the number or command name to access any module."""


def get_status_text(user_session):
    available_scanners = sum(
        [
            NETWORK_SCANNER is not None,
            VULN_SCANNER is not None,
            TLS_ANALYZER is not None,
            IP_ANALYZER is not None,
            DOMAIN_ANALYZER is not None,
            EMAIL_ANALYZER is not None,
            LOG_ANALYZER is not None,
            REPORT_GENERATOR is not None,
        ]
    )

    return """<span class="status-header">SYSTEM STATUS</span>

<span class="status-good">✓ Terminal Interface:</span> OPERATIONAL
<span class="status-good">✓ Security Modules:</span> 10 AVAILABLE
<span class="status-good">✓ Session Tracking:</span> ACTIVE
<span class="status-info">ℹ Session ID:</span> {session_id}
<span class="status-info">ℹ Started:</span> {started}
<span class="status-info">ℹ Commands Run:</span> {commands}
<span class="status-info">ℹ Core Tools:</span> {tools}
<span class="status-info">ℹ Platform:</span> CyberSec Terminal v2.1""".format(
        session_id=_safe_text(user_session.session_id),
        started=_safe_text(user_session.start_time.strftime('%Y-%m-%d %H:%M:%S')),
        commands=len(user_session.command_history),
    tools='{} of 8 analyzer engines loaded'.format(available_scanners),
    )


def get_directory_listing():
    return """total 172
drwxr-xr-x  2 cybersec cybersec  4096 Jul 31 2026  bin/
drwxr-xr-x  3 cybersec cybersec  4096 Jul 31 2026  config/
drwxr-xr-x  2 cybersec cybersec  4096 Jul 31 2026  logs/
drwxr-xr-x  5 cybersec cybersec  4096 Jul 31 2026  modules/
-rw-r--r--  1 cybersec cybersec  1820 Jul 31 2026  README.txt
drwxr-xr-x  3 cybersec cybersec  4096 Jul 31 2026  reports/
drwxr-xr-x  2 cybersec cybersec  4096 Jul 31 2026  scripts/
-rw-r--r--  1 cybersec cybersec   294 Jul 31 2026  version.info"""


def run_network_scanner(args):
    if NETWORK_SCANNER is None:
        return _core_tools_unavailable_message('network')

    if not args:
        return """<span class="tool-header">NETWORK SCANNER</span>

Usage: netscan <target> [quick|full|port <port-range>]
  target       Target IP address or hostname
  quick        Scan common ports (default)
  full         Scan ports 1-1024
  port         Custom ports like 22,80,443 or 1-1024

Examples:
  netscan 192.168.1.1
  netscan scanme.nmap.org full
  netscan 10.0.0.5 port 22,80,443

<span class="error">Error: No target specified</span>"""

    target = args[0]
    mode = args[1].lower() if len(args) > 1 else 'quick'
    custom_ports = None

    if mode == 'quick':
        scan_type = 'quick_scan'
    elif mode == 'full':
        scan_type = 'full_scan'
    elif mode in ('port', 'custom'):
        scan_type = 'custom_ports'
        if len(args) < 3:
            return '<span class="error">Error: Custom port mode requires a port list/range.</span>'
        custom_ports = args[2]
    else:
        return '<span class="error">Unknown scan mode: {}. Use quick, full, or port.</span>'.format(_safe_text(mode))

    results = NETWORK_SCANNER.scan_target(
        target,
        scan_type=scan_type,
        custom_ports=custom_ports,
        grab_banners=(scan_type == 'custom_ports'),
    )

    if results.get('status') != 'completed':
        return (
            '<span class="tool-header">NETWORK SCANNER</span>\n\n'
            '<span class="error">Scan failed: {}</span>'.format(_safe_text(results.get('error', 'unknown error')))
        )

    lines = [
        '<span class="tool-header">NETWORK SCANNER</span>',
        '',
        'Target: {}'.format(_safe_text(results.get('target', target))),
        'Resolved IP: {}'.format(_safe_text(results.get('target_ip', 'N/A'))),
        'Scan Type: {}'.format(_safe_text(results.get('scan_type', 'quick_scan'))),
        'Scanned Ports: {}'.format(results.get('total_ports_scanned', 0)),
        'Duration: {}s'.format(_safe_text(results.get('scan_duration_seconds', 0))),
        '',
        '<span class="results-header">OPEN PORTS</span>',
    ]

    open_ports = results.get('open_ports', [])
    if not open_ports:
        lines.append('<span class="scan-complete">✓ No open ports detected in the scanned range</span>')
    else:
        lines.append('PORT     STATE      SERVICE      BANNER')
        for item in open_ports:
            port = _safe_text(item.get('port', '?'))
            state = _safe_text(item.get('state', 'open')).upper()
            service = _safe_text(item.get('service', 'Unknown'))
            banner = _safe_text(item.get('banner', '-'))
            lines.append('{:<8} {:<10} {:<12} {}'.format(port, state, service, banner))

    summary = results.get('risk_summary', {})
    risk_level = summary.get('risk_level', 'unknown')
    lines.append('')
    lines.append(
        'Exposure Risk: <span class="{}">{}</span>'.format(_severity_css(risk_level), _safe_text(str(risk_level).upper()))
    )

    recommendations = summary.get('recommendations', [])
    if recommendations:
        lines.append('<span class="help-section">Recommendations:</span>')
        for rec in recommendations:
            lines.append('- {}'.format(_safe_text(rec)))

    lines.append('')
    lines.append(
        '<span class="scan-complete">✓ Scan completed - Found {} open ports</span>'.format(
            len(open_ports)
        )
    )

    return '\n'.join(lines)


def run_vulnerability_scanner(args):
    if VULN_SCANNER is None:
        return _core_tools_unavailable_message('vulnerability')

    if not args:
        return """<span class="tool-header">VULNERABILITY SCANNER</span>

Usage: vulnscan <target> [web|network|ssl] [--aggressive]
  target       Target URL, host, or IP
  web          Web configuration assessment (default)
  network      Network service exposure assessment
  ssl          TLS/certificate assessment
  --aggressive Enables active payload checks for web scans

Examples:
  vulnscan https://example.com
  vulnscan https://example.com web --aggressive
  vulnscan 10.0.0.5 network
  vulnscan example.com ssl

<span class="error">Error: No target specified</span>"""

    target = args[0]
    assessment = 'web'
    aggressive = False

    for arg in args[1:]:
        lowered = arg.lower()
        if lowered in ('web', 'network', 'ssl'):
            assessment = lowered
        elif lowered == '--aggressive':
            aggressive = True

    report = VULN_SCANNER.assess_target(target, assessment_type=assessment, aggressive=aggressive)

    if report.get('status') != 'completed':
        return (
            '<span class="tool-header">VULNERABILITY SCANNER</span>\n\n'
            '<span class="error">Assessment failed: {}</span>'.format(_safe_text(report.get('error', 'unknown error')))
        )

    counts = report.get('severity_counts', {})
    risk_level = report.get('risk_level', 'low')

    lines = [
        '<span class="tool-header">VULNERABILITY SCANNER</span>',
        '',
        'Target: {}'.format(_safe_text(report.get('target', target))),
        'Assessment Type: {}'.format(_safe_text(report.get('assessment_type', assessment))),
        'Aggressive Checks: {}'.format('enabled' if aggressive else 'disabled'),
        'Risk Level: <span class="{}">{}</span>'.format(_severity_css(risk_level), _safe_text(str(risk_level).upper())),
        '',
        '<span class="results-header">SEVERITY SUMMARY</span>',
        'Critical: {} | High: {} | Medium: {} | Low: {} | Info: {}'.format(
            counts.get('critical', 0),
            counts.get('high', 0),
            counts.get('medium', 0),
            counts.get('low', 0),
            counts.get('info', 0),
        ),
        '',
        '<span class="results-header">FINDINGS</span>',
    ]

    findings = report.get('vulnerabilities', [])
    if not findings:
        lines.append('<span class="status-good">✓ No findings detected for this assessment mode.</span>')
    else:
        for finding in findings:
            severity = str(finding.get('severity', 'low')).lower()
            lines.append(
                '<span class="{}">[{}]</span> {} - {}'.format(
                    _severity_css(severity),
                    _safe_text(severity.upper()),
                    _safe_text(finding.get('name', 'Unnamed finding')),
                    _safe_text(finding.get('description', 'No details provided')),
                )
            )
            recommendation = finding.get('recommendation')
            if recommendation:
                lines.append('  Recommendation: {}'.format(_safe_text(recommendation)))

    lines.append('')
    lines.append(
        '<span class="scan-complete">✓ Assessment completed - {} findings</span>'.format(len(findings))
    )

    return '\n'.join(lines)


def run_tls_analyzer(args):
    if TLS_ANALYZER is None:
        return _core_tools_unavailable_message('tls')

    if not args:
        return """<span class="tool-header">TLS SECURITY ANALYZER</span>

Usage: tlscheck <target> [port]
  target       Hostname, host:port, or URL
  port         Optional TLS port (default: 443)

Examples:
  tlscheck example.com
  tlscheck example.com 8443
  tlscheck https://example.com

<span class="error">Error: No target specified</span>"""

    target = args[0]
    port = 443
    if len(args) > 1:
        if args[1].isdigit():
            port = int(args[1])
        else:
            return '<span class="error">Port must be numeric.</span>'

    report = TLS_ANALYZER.analyze_target(target, port=port)
    if report.get('status') != 'completed':
        return (
            '<span class="tool-header">TLS SECURITY ANALYZER</span>\n\n'
            '<span class="error">TLS analysis failed: {}</span>'.format(_safe_text(report.get('error', 'unknown error')))
        )

    certificate = report.get('certificate', {})
    protocol_support = report.get('protocol_support', {})
    cipher = report.get('cipher', {})
    risk_level = report.get('risk_level', 'low')

    lines = [
        '<span class="tool-header">TLS SECURITY ANALYZER</span>',
        '',
        'Target: {}'.format(_safe_text(target)),
        'Host: {}'.format(_safe_text(report.get('hostname', 'N/A'))),
        'Port: {}'.format(_safe_text(report.get('port', port))),
        'Risk Level: <span class="{}">{}</span>'.format(_severity_css(risk_level), _safe_text(str(risk_level).upper())),
        '',
        '<span class="results-header">CERTIFICATE</span>',
        'Subject: {}'.format(_safe_text(certificate.get('subject', 'N/A'))),
        'Issuer: {}'.format(_safe_text(certificate.get('issuer', 'N/A'))),
        'Expires: {}'.format(_safe_text(certificate.get('not_after', 'N/A'))),
        'Days Until Expiry: {}'.format(_safe_text(certificate.get('days_until_expiry', 'N/A'))),
        '',
        '<span class="results-header">PROTOCOL SUPPORT</span>',
    ]

    for protocol, enabled in protocol_support.items():
        if enabled is None:
            state = 'unknown'
            css_class = 'status-info'
        elif enabled:
            state = 'enabled'
            css_class = 'status-good'
        else:
            state = 'disabled'
            css_class = 'status-info'
        lines.append('{}: <span class="{}">{}</span>'.format(_safe_text(protocol), css_class, _safe_text(state)))

    lines.extend(
        [
            '',
            '<span class="results-header">NEGOTIATED CIPHER</span>',
            'Name: {}'.format(_safe_text(cipher.get('name', 'N/A'))),
            'Protocol: {}'.format(_safe_text(cipher.get('protocol', 'N/A'))),
            'Bits: {}'.format(_safe_text(cipher.get('bits', 'N/A'))),
            '',
            '<span class="results-header">FINDINGS</span>',
        ]
    )

    findings = report.get('findings', [])
    if findings:
        for finding in findings:
            severity = str(finding.get('severity', 'low')).lower()
            lines.append(
                '<span class="{}">[{}]</span> {} - {}'.format(
                    _severity_css(severity),
                    _safe_text(severity.upper()),
                    _safe_text(finding.get('name', 'Unnamed finding')),
                    _safe_text(finding.get('description', 'No details provided')),
                )
            )
    else:
        lines.append('<span class="status-good">✓ No TLS findings detected.</span>')

    lines.append('')
    lines.append('<span class="scan-complete">✓ TLS analysis completed</span>')
    return '\n'.join(lines)


def run_password_analyzer(args):
    if not args:
        return """<span class="tool-header">PASSWORD ANALYZER</span>

Usage: passcheck <password>
  password    Password to analyze

Example: passcheck "MySecurePass123!"

<span class="error">Error: No password provided</span>"""

    password = ' '.join(args)

    length = len(password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_special = any(char in '!@#$%^&*()_+-=' for char in password)

    score = 0
    if length >= 8:
        score += 20
    if length >= 12:
        score += 20
    if has_upper:
        score += 15
    if has_lower:
        score += 15
    if has_digit:
        score += 15
    if has_special:
        score += 15

    strength = 'WEAK'
    strength_class = 'strength-weak'
    if score >= 80:
        strength = 'STRONG'
        strength_class = 'strength-strong'
    elif score >= 60:
        strength = 'MODERATE'
        strength_class = 'strength-moderate'

    return """<span class="tool-header">PASSWORD ANALYZER</span>

<span class="scan-progress">[*] Analyzing password strength...</span>

<span class="results-header">PASSWORD ANALYSIS:</span>
Length: {length} characters
Uppercase: {has_upper}
Lowercase: {has_lower}
Numbers: {has_digit}
Special Characters: {has_special}

<span class="{strength_class}">Password Strength: {strength} ({score}%)</span>""".format(
        length=length,
        has_upper='✓' if has_upper else '✗',
        has_lower='✓' if has_lower else '✗',
        has_digit='✓' if has_digit else '✗',
        has_special='✓' if has_special else '✗',
        strength_class=strength_class,
        strength=strength,
        score=score,
    )


def run_hash_utilities(args):
    if len(args) < 2:
        return """<span class="tool-header">HASH UTILITIES</span>

Usage: hash <algorithm> <text>
  algorithm    Hash algorithm (md5, sha1, sha256, sha512)
  text         Text to hash

Example: hash md5 "hello world"

<span class="error">Error: Missing algorithm or text</span>"""

    algorithm = args[0].lower()
    text = ' '.join(args[1:]).strip('"')

    if algorithm == 'md5':
        hash_obj = hashlib.md5(text.encode('utf-8'))
    elif algorithm == 'sha1':
        hash_obj = hashlib.sha1(text.encode('utf-8'))
    elif algorithm == 'sha256':
        hash_obj = hashlib.sha256(text.encode('utf-8'))
    elif algorithm == 'sha512':
        hash_obj = hashlib.sha512(text.encode('utf-8'))
    else:
        return '<span class="error">Unsupported algorithm: {}. Supported: md5, sha1, sha256, sha512</span>'.format(
            _safe_text(algorithm)
        )

    return """<span class="tool-header">HASH UTILITIES</span>

Algorithm: {algorithm}
Input: {text}

<span class="hash-result">{digest}</span>""".format(
        algorithm=_safe_text(algorithm.upper()),
        text=_safe_text(text),
        digest=_safe_text(hash_obj.hexdigest()),
    )


def _valid_record_count(records):
    if not isinstance(records, list):
        return 0

    return len(
        [
            record
            for record in records
            if not str(record).lower().startswith(('error:', 'no records found', 'domain not found'))
        ]
    )


def _yes_no(value):
    return 'YES' if bool(value) else 'NO'


def run_ip_analyzer(args):
    if IP_ANALYZER is None:
        return _core_tools_unavailable_message('ip')

    if not args:
        return """<span class="tool-header">IP INTELLIGENCE</span>

Usage: ipinfo <ip_address>
  ip_address    IP address to analyze

Example: ipinfo 8.8.8.8

<span class="error">Error: No IP address specified</span>"""

    target_ip = args[0]
    report = IP_ANALYZER.analyze_ip(target_ip)
    if report.get('error'):
        return (
            '<span class="tool-header">IP INTELLIGENCE</span>\n\n'
            '<span class="error">Analysis failed: {}</span>'.format(_safe_text(report.get('error')))
        )

    network = report.get('network_info', {})
    reputation = report.get('reputation', {})
    security = report.get('security', {})
    geolocation = report.get('geolocation', {})
    threats = reputation.get('threats', [])

    lines = [
        '<span class="tool-header">IP INTELLIGENCE</span>',
        '',
        'Target: {}'.format(_safe_text(report.get('ip_address', target_ip))),
        'IP Version: IPv{}'.format(_safe_text(report.get('ip_version', '?'))),
        'Private: {} | Loopback: {} | Reserved: {}'.format(
            _safe_text(_yes_no(report.get('is_private'))),
            _safe_text(_yes_no(report.get('is_loopback'))),
            _safe_text(_yes_no(report.get('is_reserved'))),
        ),
        '',
        '<span class="results-header">NETWORK CONTEXT</span>',
        'Hostname: {}'.format(_safe_text(network.get('hostname', 'N/A'))),
        'Global Reachability: {}'.format(_safe_text(_yes_no(network.get('is_global')))),
        'Compressed: {}'.format(_safe_text(network.get('compressed', 'N/A'))),
    ]

    if geolocation:
        lines.extend(
            [
                '',
                '<span class="results-header">GEOLOCATION</span>',
                'Country: {}'.format(_safe_text(geolocation.get('country', geolocation.get('status', 'N/A')))),
                'City: {}'.format(_safe_text(geolocation.get('city', 'N/A'))),
                'Organization: {}'.format(_safe_text(geolocation.get('org', 'N/A'))),
            ]
        )

    lines.extend(
        [
            '',
            '<span class="results-header">REPUTATION</span>',
            'Score: {}'.format(_safe_text(reputation.get('score', 'N/A'))),
            'Status: {}'.format(_safe_text(reputation.get('reputation', reputation.get('status', 'Unknown')))),
        ]
    )

    if threats:
        lines.append('Threat Indicators:')
        for threat in threats[:5]:
            lines.append('- {}'.format(_safe_text(threat)))

    if security:
        lines.extend(
            [
                '',
                '<span class="results-header">SECURITY SOURCES</span>',
                'VirusTotal: {}'.format(_safe_text(security.get('virustotal_status', 'N/A'))),
                'AbuseIPDB: {}'.format(_safe_text(security.get('abuseipdb_status', 'N/A'))),
            ]
        )

    lines.append('')
    lines.append('<span class="scan-complete">✓ IP analysis completed</span>')
    return '\n'.join(lines)


def run_domain_analyzer(args):
    if DOMAIN_ANALYZER is None:
        return _core_tools_unavailable_message('domain')

    if not args:
        return """<span class="tool-header">DOMAIN ANALYSIS</span>

Usage: domain <domain_name>
  domain_name    Domain to analyze

Example: domain google.com

<span class="error">Error: No domain specified</span>"""

    domain = args[0]
    report = DOMAIN_ANALYZER.analyze_domain(domain)
    if report.get('error'):
        return (
            '<span class="tool-header">DOMAIN ANALYSIS</span>\n\n'
            '<span class="error">Analysis failed: {}</span>'.format(_safe_text(report.get('error')))
        )

    whois_data = report.get('whois', {})
    dns_records = report.get('dns_records', {})
    security = report.get('security_assessment', {})

    lines = [
        '<span class="tool-header">DOMAIN ANALYSIS</span>',
        '',
        'Target: {}'.format(_safe_text(report.get('domain', domain))),
        'Status: {}'.format(_safe_text(report.get('status', 'Unknown'))),
        '',
        '<span class="results-header">WHOIS</span>',
        'Registrar: {}'.format(_safe_text(whois_data.get('registrar', 'Unknown'))),
        'Created: {}'.format(_safe_text(whois_data.get('creation_date', 'Unknown'))),
        'Expires: {}'.format(_safe_text(whois_data.get('expiration_date', 'Unknown'))),
        '',
        '<span class="results-header">DNS SUMMARY</span>',
        'A: {} | AAAA: {} | MX: {} | TXT: {} | NS: {}'.format(
            _safe_text(_valid_record_count(dns_records.get('a', []))),
            _safe_text(_valid_record_count(dns_records.get('aaaa', []))),
            _safe_text(_valid_record_count(dns_records.get('mx', []))),
            _safe_text(_valid_record_count(dns_records.get('txt', []))),
            _safe_text(_valid_record_count(dns_records.get('ns', []))),
        ),
    ]

    security_features = security.get('security_features', [])
    risk_factors = security.get('risk_factors', [])
    recommendations = security.get('recommendations', [])

    if security_features:
        lines.append('')
        lines.append('<span class="results-header">SECURITY FEATURES</span>')
        for feature in security_features[:5]:
            lines.append('- {}'.format(_safe_text(feature)))

    if risk_factors:
        lines.append('')
        lines.append('<span class="results-header">RISK FACTORS</span>')
        for factor in risk_factors[:5]:
            lines.append('- {}'.format(_safe_text(factor)))

    if recommendations:
        lines.append('')
        lines.append('<span class="results-header">RECOMMENDATIONS</span>')
        for recommendation in recommendations[:5]:
            lines.append('- {}'.format(_safe_text(recommendation)))

    lines.append('')
    lines.append('<span class="scan-complete">✓ Domain analysis completed</span>')
    return '\n'.join(lines)


def run_email_analyzer(args):
    if EMAIL_ANALYZER is None:
        return _core_tools_unavailable_message('email')

    if not args:
        return """<span class="tool-header">EMAIL SECURITY</span>

Usage: email <address> [--content <email_text>]
  address       Sender address to analyze
  --content     Optional email body snippet for phishing/spam checks

Examples:
  email security@example.com
  email security@example.com --content "urgent verify your account"

<span class="error">Error: No email address specified</span>"""

    address_tokens = list(args)
    content_text = None

    if '--content' in args:
        content_index = args.index('--content')
        address_tokens = args[:content_index]
        content_tokens = args[content_index + 1 :]
        if not content_tokens:
            return '<span class="error">Error: --content requires text to analyze.</span>'
        content_text = ' '.join(content_tokens)

    address = ' '.join(address_tokens).strip()
    if not address:
        return '<span class="error">Error: No email address specified.</span>'

    address_report = EMAIL_ANALYZER.analyze_email_address(address)
    if address_report.get('error'):
        return (
            '<span class="tool-header">EMAIL SECURITY</span>\n\n'
            '<span class="error">Analysis failed: {}</span>'.format(_safe_text(address_report.get('error')))
        )

    lines = [
        '<span class="tool-header">EMAIL SECURITY</span>',
        '',
        'Address: {}'.format(_safe_text(address_report.get('email', address))),
        'Risk Score: {}/100'.format(_safe_text(address_report.get('risk_score', 0))),
        'Local Part: {}'.format(_safe_text(address_report.get('local_part', 'N/A'))),
        'Domain: {}'.format(_safe_text(address_report.get('domain', 'N/A'))),
    ]

    risk_factors = list(address_report.get('risk_factors', []))
    risk_factors.extend(address_report.get('domain_analysis', {}).get('risk_factors', []))

    if risk_factors:
        lines.append('')
        lines.append('<span class="results-header">RISK FACTORS</span>')
        for factor in risk_factors[:6]:
            lines.append('- {}'.format(_safe_text(factor)))

    recommendations = address_report.get('recommendations', [])
    if recommendations:
        lines.append('')
        lines.append('<span class="results-header">RECOMMENDATIONS</span>')
        for recommendation in recommendations[:5]:
            lines.append('- {}'.format(_safe_text(recommendation)))

    if content_text is not None:
        content_report = EMAIL_ANALYZER.analyze_email_content(content_text, sender_email=address)
        if content_report.get('error'):
            lines.append('')
            lines.append('<span class="error">Content analysis failed: {}</span>'.format(_safe_text(content_report.get('error'))))
        else:
            lines.extend(
                [
                    '',
                    '<span class="results-header">CONTENT ANALYSIS</span>',
                    'Security Score: {}/100'.format(_safe_text(content_report.get('security_score', 'N/A'))),
                    'Phishing Indicators: {}'.format(_safe_text(len(content_report.get('phishing_indicators', [])))),
                    'Spam Indicators: {}'.format(_safe_text(len(content_report.get('spam_indicators', [])))),
                    'Suspicious Links: {}'.format(_safe_text(len(content_report.get('suspicious_links', [])))),
                ]
            )

    lines.append('')
    lines.append('<span class="scan-complete">✓ Email analysis completed</span>')
    return '\n'.join(lines)


def run_log_analyzer(args):
    if LOG_ANALYZER is None:
        return _core_tools_unavailable_message('logs')

    if not args:
        return """<span class="tool-header">LOG ANALYZER</span>

Usage: logs [--type <log_type>] <log_text>
  --type        Optional parser hint (apache_common, apache_combined, nginx, ssh, syslog)
  log_text      Raw log line(s) to analyze

Examples:
  logs --type ssh "failed password for root from 203.0.113.9"
  logs --type apache_common "203.0.113.9 - - [31/Jul/2026:12:00:00 +0000] \"GET /admin HTTP/1.1\" 401 721"

<span class="error">Error: No log input provided</span>"""

    log_type = None
    log_tokens = []
    index = 0

    while index < len(args):
        token = args[index]
        if token == '--type':
            if index + 1 >= len(args):
                return '<span class="error">Error: --type requires a parser name.</span>'
            log_type = args[index + 1]
            index += 2
            continue

        log_tokens.append(token)
        index += 1

    if not log_tokens:
        return '<span class="error">Error: No log text provided.</span>'

    log_content = ' '.join(log_tokens)
    report = LOG_ANALYZER.analyze_logs(log_content, log_type=log_type)
    if report.get('error'):
        return (
            '<span class="tool-header">LOG ANALYZER</span>\n\n'
            '<span class="error">Analysis failed: {}</span>'.format(_safe_text(report.get('error')))
        )

    lines = [
        '<span class="tool-header">LOG ANALYZER</span>',
        '',
        'Entries Parsed: {}'.format(_safe_text(report.get('total_entries', 0))),
        'Security Events: {}'.format(_safe_text(report.get('security_events', 0))),
        'Failed Logins: {}'.format(_safe_text(report.get('failed_logins', 0))),
        'Suspicious IPs: {}'.format(_safe_text(report.get('suspicious_ips', 0))),
    ]

    threats = report.get('threats', [])
    if threats:
        lines.append('')
        lines.append('<span class="results-header">TOP THREATS</span>')
        for threat in threats[:5]:
            lines.append(
                '- {type}: {count} event(s), severity={severity}, unique_ips={ips}'.format(
                    type=_safe_text(threat.get('type', 'unknown')),
                    count=_safe_text(threat.get('count', 0)),
                    severity=_safe_text(threat.get('severity', 'Unknown')),
                    ips=_safe_text(threat.get('unique_ips', 0)),
                )
            )

    recommendations = report.get('recommendations', [])
    if recommendations:
        lines.append('')
        lines.append('<span class="results-header">RECOMMENDATIONS</span>')
        for recommendation in recommendations[:5]:
            lines.append(
                '- [{priority}] {category}: {text}'.format(
                    priority=_safe_text(recommendation.get('priority', 'Medium')),
                    category=_safe_text(recommendation.get('category', 'General')),
                    text=_safe_text(recommendation.get('recommendation', 'Review findings')),
                )
            )

    lines.append('')
    lines.append('<span class="scan-complete">✓ Log analysis completed</span>')
    return '\n'.join(lines)


def run_report_generator(args):
    if REPORT_GENERATOR is None:
        return _core_tools_unavailable_message('report')

    report_type_map = {
        'vulnerability': 'vulnerability_assessment',
        'vulnerability_assessment': 'vulnerability_assessment',
        'network': 'network_security',
        'network_security': 'network_security',
        'comprehensive': 'comprehensive',
    }

    report_type = 'comprehensive'
    title = 'Security Report'
    include_charts = False
    include_recommendations = True

    idx = 0
    while idx < len(args):
        token = args[idx]
        lowered = token.lower()

        if lowered == '--type':
            if idx + 1 >= len(args):
                return '<span class="error">Error: --type requires a value.</span>'
            report_type = report_type_map.get(args[idx + 1].lower(), report_type)
            idx += 2
            continue

        if lowered == '--title':
            if idx + 1 >= len(args):
                return '<span class="error">Error: --title requires a value.</span>'

            title_tokens = []
            idx += 1
            while idx < len(args) and not args[idx].startswith('--'):
                title_tokens.append(args[idx])
                idx += 1

            title = ' '.join(title_tokens).strip()
            if not title:
                return '<span class="error">Error: --title requires a value.</span>'
            continue

        if lowered == '--charts':
            include_charts = True
            idx += 1
            continue

        if lowered == '--no-recommendations':
            include_recommendations = False
            idx += 1
            continue

        if lowered in report_type_map:
            report_type = report_type_map[lowered]

        idx += 1

    summary_by_type = {
        'vulnerability_assessment': {
            'total_assets': 0,
            'vulnerabilities_found': 0,
            'critical_issues': 0,
            'high_risk_issues': 0,
            'medium_risk_issues': 0,
            'low_risk_issues': 0,
        },
        'network_security': {
            'network_ranges': 'N/A',
            'total_hosts': 0,
            'active_services': 0,
            'security_issues': 0,
        },
        'comprehensive': {
            'total_assets': 0,
            'controls_evaluated': 0,
            'critical_issues': 0,
            'high_issues': 0,
            'medium_issues': 0,
            'low_issues': 0,
            'total_findings': 0,
            'recommendations': 0,
        },
    }

    report_data = {
        'type': report_type,
        'title': title,
        'summary': summary_by_type[report_type],
    }

    report = REPORT_GENERATOR.generate_report(
        report_data,
        include_charts=include_charts,
        include_recommendations=include_recommendations,
    )

    if report.get('error'):
        return (
            '<span class="tool-header">REPORT GENERATOR</span>\n\n'
            '<span class="error">Generation failed: {}</span>'.format(_safe_text(report.get('error')))
        )

    content_lines = str(report.get('content', '')).splitlines()
    preview = '\n'.join(content_lines[:16]).strip()

    lines = [
        '<span class="tool-header">REPORT GENERATOR</span>',
        '',
        'Title: {}'.format(_safe_text(report.get('title', title))),
        'Type: {}'.format(_safe_text(report.get('type', report_type))),
        'Timestamp: {}'.format(_safe_text(report.get('timestamp', 'N/A'))),
        'Charts Included: {}'.format(_safe_text(_yes_no(include_charts))),
        'Recommendations Included: {}'.format(_safe_text(_yes_no(include_recommendations))),
    ]

    if preview:
        lines.extend(
            [
                '',
                '<span class="results-header">REPORT PREVIEW</span>',
                _safe_text(preview),
            ]
        )

    lines.extend(
        [
            '',
            '<span class="help-footer">Tip: use the report module in code for full Markdown/JSON/HTML exports.</span>',
            '<span class="scan-complete">✓ Report generation completed</span>',
        ]
    )
    return '\n'.join(lines)


def get_file_content(filename):
    files = {
        'README.txt': """CyberSec Terminal v2.1 - Professional Security Analysis Platform

This terminal provides access to practical cybersecurity tools
for network analysis, vulnerability assessment, and TLS hygiene checks.

All operations are for authorized security testing only.
Use 'help' for command reference.""",
        'version.info': """CyberSec Terminal
Version: 2.1.0
Build: Professional Edition
Platform: Cross-platform Security Analysis""",
    }

    return files.get(filename, 'cat: {}: No such file or directory'.format(_safe_text(filename)))


def main():
    """Start the CyberSec web terminal and open browser tab."""

    def open_browser():
        time.sleep(1)
        import webbrowser

        webbrowser.open('http://127.0.0.1:5000')

    threading.Thread(target=open_browser, daemon=True).start()

    print('Starting CyberSec Web Terminal...')
    print('Opening browser at http://127.0.0.1:5000')
    print('Press Ctrl+C to stop the server')

    app.run(
        debug=False,
        host=os.environ.get('HOST', '127.0.0.1'),
        port=int(os.environ.get('PORT', 5000)),
    )


if __name__ == '__main__':
    main()
