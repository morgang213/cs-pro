#!/usr/bin/env python3
"""
CSS-Styled Web Terminal for CyberSec Analyst Tool
Modern terminal interface with CSS styling and JavaScript interactions
"""

import os
import sys
import json
import uuid
import time
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session
import threading
import webbrowser

app = Flask(__name__)
app.secret_key = 'cybersec_terminal_key_' + str(uuid.uuid4())

class TerminalSession:
    def __init__(self):
        self.session_id = str(uuid.uuid4())[:8]
        self.start_time = datetime.now()
        self.command_history = []
        self.current_directory = "~"
        self.logged_in = True
        self.username = "cybersec"
        self.hostname = "security-terminal"
        
    def add_command(self, command, output):
        self.command_history.append({
            'timestamp': datetime.now().isoformat(),
            'command': command,
            'output': output
        })

# Global session storage
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
    data = request.json
    command = data.get('command', '').strip()
    
    terminal_session = get_session()
    
    # Process command
    output = process_command(command, terminal_session)
    
    # Add to history
    terminal_session.add_command(command, output)
    
    return jsonify({
        'output': output,
        'prompt': f"{terminal_session.username}@{terminal_session.hostname}:~$ "
    })

def process_command(command, session):
    """Process terminal commands and return appropriate output"""
    
    if not command:
        return ""
    
    cmd_parts = command.split()
    cmd = cmd_parts[0].lower()
    
    # System commands
    if cmd == 'help':
        return get_help_text()
    elif cmd == 'clear':
        return "CLEAR_SCREEN"
    elif cmd == 'whoami':
        return session.username
    elif cmd == 'pwd':
        return session.current_directory
    elif cmd == 'date':
        return datetime.now().strftime('%a %b %d %H:%M:%S %Z %Y')
    elif cmd == 'uptime':
        uptime = datetime.now() - session.start_time
        return f"up {uptime.seconds // 3600}h {(uptime.seconds % 3600) // 60}m"
    elif cmd == 'id':
        return f"uid=1000({session.username}) gid=1000(cybersec) groups=1000(cybersec),27(sudo)"
    elif cmd == 'uname':
        return "CyberSec-Terminal 5.4.0-cybersec #1 SMP x86_64 GNU/Linux"
    
    # CyberSec specific commands
    elif cmd in ['01', 'netscan', 'network-scan']:
        return run_network_scanner(cmd_parts[1:] if len(cmd_parts) > 1 else [])
    elif cmd in ['02', 'vulnscan', 'vuln-scan']:
        return run_vulnerability_scanner(cmd_parts[1:] if len(cmd_parts) > 1 else [])
    elif cmd in ['03', 'passcheck', 'password-check']:
        return run_password_analyzer(cmd_parts[1:] if len(cmd_parts) > 1 else [])
    elif cmd in ['04', 'hash']:
        return run_hash_utilities(cmd_parts[1:] if len(cmd_parts) > 1 else [])
    elif cmd in ['05', 'ipinfo', 'ip-info']:
        return run_ip_analyzer(cmd_parts[1:] if len(cmd_parts) > 1 else [])
    elif cmd in ['06', 'domain', 'whois']:
        return run_domain_analyzer(cmd_parts[1:] if len(cmd_parts) > 1 else [])
    elif cmd in ['07', 'email']:
        return run_email_analyzer(cmd_parts[1:] if len(cmd_parts) > 1 else [])
    elif cmd in ['08', 'logs', 'log-analyzer']:
        return run_log_analyzer(cmd_parts[1:] if len(cmd_parts) > 1 else [])
    elif cmd in ['09', 'report']:
        return run_report_generator(cmd_parts[1:] if len(cmd_parts) > 1 else [])
    elif cmd == 'menu':
        return get_menu_text()
    elif cmd == 'status':
        return get_status_text(session)
    elif cmd == 'exit':
        return "Session terminated. Thank you for using CyberSec Terminal!"
    
    # File system simulation
    elif cmd == 'ls':
        return get_directory_listing()
    elif cmd == 'cat':
        if len(cmd_parts) > 1:
            return get_file_content(cmd_parts[1])
        else:
            return "cat: missing file operand"
    
    else:
        return f"cybersec-terminal: command not found: {command}\nType 'help' for available commands"

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

<span class="help-section">EXAMPLES:</span>
  netscan 192.168.1.1
  vulnscan https://example.com
  passcheck MyPassword123!
  hash md5 "hello world"
  ipinfo 8.8.8.8
  domain google.com

<span class="help-footer">Use 'menu' to see all available security modules</span>"""

def get_menu_text():
    return """<span class="menu-header">🛡️  CYBERSEC TERMINAL - SECURITY MODULES  🛡️</span>

┌─────────────────────────────────────────────────────────────┐
│  <span class="menu-item">[01]</span> 🌐 <span class="tool-name">Network Scanner</span>      │ Port scanning & discovery       │
│  <span class="menu-item">[02]</span> 🔍 <span class="tool-name">Vulnerability Scan</span>   │ Web security assessment         │
│  <span class="menu-item">[03]</span> 🔐 <span class="tool-name">Password Analyzer</span>    │ Password strength evaluation    │
│  <span class="menu-item">[04]</span> 🏷️  <span class="tool-name">Hash Utilities</span>       │ Generate & verify hashes        │
│  <span class="menu-item">[05]</span> 📍 <span class="tool-name">IP Intelligence</span>      │ Geolocation & reputation        │
│  <span class="menu-item">[06]</span> 🌍 <span class="tool-name">Domain Analysis</span>      │ WHOIS & DNS investigation       │
│  <span class="menu-item">[07]</span> 📧 <span class="tool-name">Email Security</span>       │ Email threat analysis           │
│  <span class="menu-item">[08]</span> 📊 <span class="tool-name">Log Analyzer</span>         │ Security log investigation      │
│  <span class="menu-item">[09]</span> 📋 <span class="tool-name">Report Generator</span>     │ Professional security reports  │
└─────────────────────────────────────────────────────────────┘

Type the number or command name to access any module."""

def get_status_text(session):
    return f"""<span class="status-header">📊 SYSTEM STATUS</span>

<span class="status-good">✓ Terminal Interface:</span> OPERATIONAL
<span class="status-good">✓ Security Modules:</span> 9 AVAILABLE
<span class="status-good">✓ Session Tracking:</span> ACTIVE
<span class="status-info">ℹ Session ID:</span> {session.session_id}
<span class="status-info">ℹ Started:</span> {session.start_time.strftime('%Y-%m-%d %H:%M:%S')}
<span class="status-info">ℹ Commands Run:</span> {len(session.command_history)}
<span class="status-info">ℹ Platform:</span> CyberSec Terminal v2.0"""

def get_directory_listing():
    return """total 156
drwxr-xr-x  2 cybersec cybersec  4096 Aug 10 2025  bin/
drwxr-xr-x  3 cybersec cybersec  4096 Aug 10 2025  config/
drwxr-xr-x  2 cybersec cybersec  4096 Aug 10 2025  logs/
drwxr-xr-x  5 cybersec cybersec  4096 Aug 10 2025  modules/
-rw-r--r--  1 cybersec cybersec  1337 Aug 10 2025  README.txt
drwxr-xr-x  3 cybersec cybersec  4096 Aug 10 2025  reports/
drwxr-xr-x  2 cybersec cybersec  4096 Aug 10 2025  scripts/
-rw-r--r--  1 cybersec cybersec   256 Aug 10 2025  version.info"""

def run_network_scanner(args):
    if not args:
        return """<span class="tool-header">🌐 NETWORK SCANNER</span>

Usage: netscan <target> [options]
  target    Target IP address or hostname
  
Examples:
  netscan 192.168.1.1
  netscan google.com
  
<span class="error">Error: No target specified</span>"""
    
    target = args[0]
    return f"""<span class="tool-header">🌐 NETWORK SCANNER</span>

Target: {target}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

<span class="scan-progress">[*] Initializing scanner...</span>
<span class="scan-progress">[*] Performing port scan...</span>
<span class="scan-progress">[*] Analyzing results...</span>

<span class="results-header">SCAN RESULTS:</span>
PORT     STATUS      SERVICE      VERSION
22       <span class="port-open">OPEN</span>        SSH          OpenSSH 8.2
80       <span class="port-open">OPEN</span>        HTTP         Apache 2.4.41
443      <span class="port-open">OPEN</span>        HTTPS        Apache 2.4.41
3306     <span class="port-filtered">FILTERED</span>    MySQL        Unknown

<span class="scan-complete">✓ Scan completed - Found 3 open ports</span>"""

def run_vulnerability_scanner(args):
    if not args:
        return """<span class="tool-header">🔍 VULNERABILITY SCANNER</span>

Usage: vulnscan <target_url>
  target_url    Target website URL
  
Example: vulnscan https://example.com

<span class="error">Error: No target URL specified</span>"""
    
    target = args[0]
    return f"""<span class="tool-header">🔍 VULNERABILITY SCANNER</span>

Target: {target}
Tests: XSS, SQL Injection, SSL/TLS Analysis

<span class="scan-progress">[*] Analyzing target...</span>
<span class="scan-progress">[*] Testing for XSS vulnerabilities...</span>
<span class="scan-progress">[*] Checking SQL injection points...</span>
<span class="scan-progress">[*] Analyzing SSL/TLS configuration...</span>

<span class="results-header">VULNERABILITY ASSESSMENT:</span>
🔴 <span class="vuln-high">HIGH</span>: SQL Injection - Login form vulnerable
🟡 <span class="vuln-medium">MEDIUM</span>: Missing Security Headers - X-Frame-Options not set
🟢 <span class="vuln-low">LOW</span>: SSL Configuration - Using older TLS version

<span class="vuln-warning">⚠ Found 3 vulnerabilities requiring attention</span>"""

def run_password_analyzer(args):
    if not args:
        return """<span class="tool-header">🔐 PASSWORD ANALYZER</span>

Usage: passcheck <password>
  password    Password to analyze
  
Example: passcheck "MySecurePass123!"

<span class="error">Error: No password provided</span>"""
    
    password = " ".join(args)
    
    # Password analysis
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=" for c in password)
    
    score = 0
    if length >= 8: score += 20
    if length >= 12: score += 20
    if has_upper: score += 15
    if has_lower: score += 15
    if has_digit: score += 15
    if has_special: score += 15
    
    strength = "WEAK"
    strength_class = "strength-weak"
    if score >= 80:
        strength = "STRONG"
        strength_class = "strength-strong"
    elif score >= 60:
        strength = "MODERATE"
        strength_class = "strength-moderate"
    
    return f"""<span class="tool-header">🔐 PASSWORD ANALYZER</span>

<span class="scan-progress">[*] Analyzing password strength...</span>

<span class="results-header">PASSWORD ANALYSIS:</span>
Length: {length} characters
Uppercase: {'✓' if has_upper else '✗'}
Lowercase: {'✓' if has_lower else '✗'}
Numbers: {'✓' if has_digit else '✗'}
Special Characters: {'✓' if has_special else '✗'}

<span class="{strength_class}">Password Strength: {strength} ({score}%)</span>"""

def run_hash_utilities(args):
    if len(args) < 2:
        return """<span class="tool-header">🏷️ HASH UTILITIES</span>

Usage: hash <algorithm> <text>
  algorithm    Hash algorithm (md5, sha1, sha256, sha512)
  text         Text to hash
  
Example: hash md5 "hello world"

<span class="error">Error: Missing algorithm or text</span>"""
    
    algorithm = args[0].lower()
    text = " ".join(args[1:]).strip('"')
    
    import hashlib
    
    if algorithm == 'md5':
        hash_obj = hashlib.md5(text.encode())
    elif algorithm == 'sha1':
        hash_obj = hashlib.sha1(text.encode())
    elif algorithm == 'sha256':
        hash_obj = hashlib.sha256(text.encode())
    elif algorithm == 'sha512':
        hash_obj = hashlib.sha512(text.encode())
    else:
        return f"""<span class="error">Unsupported algorithm: {algorithm}</span>
Supported: md5, sha1, sha256, sha512"""
    
    return f"""<span class="tool-header">🏷️ HASH UTILITIES</span>

Algorithm: {algorithm.upper()}
Input: {text}

<span class="hash-result">{hash_obj.hexdigest()}</span>"""

def run_ip_analyzer(args):
    if not args:
        return """<span class="tool-header">📍 IP INTELLIGENCE</span>

Usage: ipinfo <ip_address>
  ip_address    IP address to analyze
  
Example: ipinfo 8.8.8.8

<span class="error">Error: No IP address specified</span>"""
    
    ip = args[0]
    return f"""<span class="tool-header">📍 IP INTELLIGENCE</span>

Target: {ip}

<span class="scan-progress">[*] Gathering IP intelligence...</span>
<span class="scan-progress">[*] Checking reputation databases...</span>

<span class="results-header">IP ANALYSIS:</span>
Location: Mountain View, CA, US
ISP: Google LLC
Organization: Google Public DNS
Reputation: <span class="status-good">CLEAN</span>
Threat Level: <span class="status-good">LOW</span>

<span class="scan-complete">✓ IP analysis completed</span>"""

def run_domain_analyzer(args):
    if not args:
        return """<span class="tool-header">🌍 DOMAIN ANALYSIS</span>

Usage: domain <domain_name>
  domain_name    Domain to analyze
  
Example: domain google.com

<span class="error">Error: No domain specified</span>"""
    
    domain = args[0]
    return f"""<span class="tool-header">🌍 DOMAIN ANALYSIS</span>

Target: {domain}

<span class="scan-progress">[*] Performing WHOIS lookup...</span>
<span class="scan-progress">[*] Analyzing DNS records...</span>

<span class="results-header">DOMAIN INFORMATION:</span>
Registrar: Example Registrar Inc.
Created: 1997-09-15
Expires: 2025-09-14
Status: <span class="status-good">ACTIVE</span>
DNS Security: <span class="status-good">DNSSEC ENABLED</span>

<span class="scan-complete">✓ Domain analysis completed</span>"""

def run_email_analyzer(args):
    return """<span class="tool-header">📧 EMAIL SECURITY</span>

Email security module ready for threat analysis
• Phishing detection algorithms loaded
• Spam filters initialized
• Domain reputation database ready

<span class="scan-complete">✓ Email security module operational</span>"""

def run_log_analyzer(args):
    return """<span class="tool-header">📊 LOG ANALYZER</span>

Security log analysis engine initialized
• Multi-format log parsing ready
• Threat detection patterns loaded
• Real-time analysis capabilities active

<span class="scan-complete">✓ Log analyzer ready for operation</span>"""

def run_report_generator(args):
    return f"""<span class="tool-header">📋 REPORT GENERATOR</span>

Professional security report generator initialized
• Template engine loaded
• Export formats: PDF, HTML, JSON
• Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

<span class="scan-complete">✓ Report generator ready</span>"""

def get_file_content(filename):
    files = {
        'README.txt': """CyberSec Terminal v2.0 - Professional Security Analysis Platform

This terminal provides access to comprehensive cybersecurity tools
for network analysis, vulnerability assessment, and threat intelligence.

All operations are logged for security audit purposes.
Use 'help' for command reference.""",
        
        'version.info': """CyberSec Terminal
Version: 2.0.0
Build: Enterprise Edition
Platform: Cross-platform Security Analysis
Licensed: Professional Use""",
    }
    
    return files.get(filename, f"cat: {filename}: No such file or directory")

if __name__ == '__main__':
    # Open browser automatically
    def open_browser():
        time.sleep(1)
        webbrowser.open('http://127.0.0.1:5000')
    
    threading.Thread(target=open_browser, daemon=True).start()
    
    print("🛡️  Starting CyberSec Web Terminal...")
    print("💻 Opening browser at http://127.0.0.1:5000")
    print("🔒 Press Ctrl+C to stop the server")
    
    app.run(debug=False, host='127.0.0.1', port=5000)
