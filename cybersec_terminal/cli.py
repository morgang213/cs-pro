#!/usr/bin/env python3
"""Interactive CLI terminal backed by real scanner modules."""

import argparse
import os
import re
import shlex
import sys
import uuid
from datetime import datetime
from html import unescape

if __package__ in (None, ""):
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

try:
    from colorama import init as colorama_init
except ImportError:  # pragma: no cover - optional runtime dependency path
    colorama_init = None

HTML_BREAK_REPLACEMENTS = ("<br />", "<br/>", "<br>")
HTML_TAG_RE = re.compile(r"<[^>]+>")
LOCAL_ANALYZER_COMMANDS = {
    "05",
    "ipinfo",
    "ip-info",
    "06",
    "domain",
    "whois",
    "07",
    "email",
    "08",
    "logs",
    "log-analyzer",
    "09",
    "report",
}


class LocalTerminalSession:
    """Minimal terminal session state for fallback command handling."""

    def __init__(self):
        self.session_id = str(uuid.uuid4())[:8]
        self.start_time = datetime.now()
        self.command_history = []
        self.current_directory = "~"
        self.username = "cybersec"
        self.hostname = "security-terminal"

    def add_command(self, command, output):
        self.command_history.append(
            {
                "timestamp": datetime.now().isoformat(),
                "command": command,
                "output": output,
            }
        )


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def render_terminal_output(value):
    """Convert web-style HTML output to plain terminal text."""
    if value is None:
        return ""

    text = str(value)
    for marker in HTML_BREAK_REPLACEMENTS:
        text = text.replace(marker, "\n")
    text = HTML_TAG_RE.sub("", text)
    return unescape(text)


def _load_tool(module_name, class_name):
    try:
        module = __import__(module_name, fromlist=[class_name])
        return getattr(module, class_name)
    except Exception as exc:
        raise RuntimeError(
            "Unable to load {} from {}: {}".format(class_name, module_name, exc)
        )


def _yes_no(value):
    return "yes" if bool(value) else "no"


def _extract_command_name(raw_command):
    try:
        parts = shlex.split(raw_command)
    except ValueError:
        return None

    if not parts:
        return None

    return parts[0].lower()


def _fallback_help_text():
    return """CyberSec Terminal - Command Reference

SYSTEM COMMANDS:
  help           - Show this help message
  clear          - Clear the terminal screen
  menu           - Show security modules menu
  status         - Show session and tool status
  whoami         - Display current user
  pwd            - Print working directory
  date           - Display current date/time
  exit           - Exit terminal

SECURITY TOOLS:
  01, netscan    - Network scanner
  02, vulnscan   - Vulnerability scanner
  03, passcheck  - Password analyzer
  04, hash       - Hash utility
    05, ipinfo     - IP intelligence
    06, domain     - Domain intelligence
    07, email      - Email security analysis
    08, logs       - Log threat analysis
    09, report     - Report generation
  10, tlscheck   - TLS security analyzer

EXAMPLES:
  netscan 192.168.1.1 quick
  netscan 192.168.1.1 port 22,80,443
  vulnscan https://example.com web --aggressive
  vulnscan 10.0.0.5 network
  tlscheck example.com 443
  hash sha256 message-to-hash
    ipinfo 8.8.8.8
    domain example.com
    email admin@example.com --content "urgent verify your account"
    logs --type apache_combined "192.0.2.10 - - [31/Jul/2026:12:00:00 +0000] \"GET /login HTTP/1.1\" 401 721"
    report comprehensive --title "Weekly Security Snapshot"
"""


def _fallback_menu_text():
    return """CYBERSEC TERMINAL - SECURITY MODULES

[01] Network Scanner      - Port scanning and discovery
[02] Vulnerability Scan   - Web and service assessment
[03] Password Analyzer    - Password strength evaluation
[04] Hash Utilities       - Generate and verify hashes
[05] IP Intelligence      - Reputation and network context
[06] Domain Analysis      - WHOIS, DNS, and security posture
[07] Email Security       - Address and content risk analysis
[08] Log Analyzer         - Threat event extraction from logs
[09] Report Generator     - Markdown security report generation
[10] TLS Analyzer         - Certificate and protocol checks
"""


def _fallback_status_text(session):
    uptime = datetime.now() - session.start_time
    return """SYSTEM STATUS

Terminal Interface: OPERATIONAL
Session ID: {session_id}
Started: {started}
Commands Run: {commands}
Uptime: {hours}h {minutes}m
Platform: CyberSec Terminal v2.1""".format(
        session_id=session.session_id,
        started=session.start_time.strftime("%Y-%m-%d %H:%M:%S"),
        commands=len(session.command_history),
        hours=uptime.seconds // 3600,
        minutes=(uptime.seconds % 3600) // 60,
    )


def _fallback_network_scan(args):
    if not args:
        return """NETWORK SCANNER

Usage: netscan <target> [quick|full|port <port-range>]
  target       Target IP address or hostname
  quick        Scan common ports (default)
  full         Scan ports 1-1024
  port         Custom ports like 22,80,443 or 1-1024

Error: No target specified"""

    target = args[0]
    mode = args[1].lower() if len(args) > 1 else "quick"
    custom_ports = None

    if mode == "quick":
        scan_type = "quick_scan"
    elif mode == "full":
        scan_type = "full_scan"
    elif mode in ("port", "custom"):
        scan_type = "custom_ports"
        if len(args) < 3:
            return "Error: Custom port mode requires a port list/range."
        custom_ports = args[2]
    else:
        return "Unknown scan mode: {}. Use quick, full, or port.".format(mode)

    scanner = _load_tool("network_scanner", "NetworkScanner")()
    result = scanner.scan_target(
        target,
        scan_type=scan_type,
        custom_ports=custom_ports,
        grab_banners=(scan_type == "custom_ports"),
    )

    if result.get("status") != "completed":
        return "NETWORK SCANNER\n\nScan failed: {}".format(result.get("error", "unknown error"))

    lines = [
        "NETWORK SCANNER",
        "",
        "Target: {}".format(result.get("target", target)),
        "Resolved IP: {}".format(result.get("target_ip", "N/A")),
        "Scan Type: {}".format(result.get("scan_type", "quick_scan")),
        "Scanned Ports: {}".format(result.get("total_ports_scanned", 0)),
        "Duration: {}s".format(result.get("scan_duration_seconds", 0)),
        "",
        "OPEN PORTS",
    ]

    open_ports = result.get("open_ports", [])
    if not open_ports:
        lines.append("No open ports detected in the scanned range")
    else:
        lines.append("PORT     STATE      SERVICE      BANNER")
        for item in open_ports:
            lines.append(
                "{:<8} {:<10} {:<12} {}".format(
                    item.get("port", "?"),
                    str(item.get("state", "open")).upper(),
                    item.get("service", "Unknown"),
                    item.get("banner", "-"),
                )
            )

    summary = result.get("risk_summary", {})
    lines.append("")
    lines.append("Exposure Risk: {}".format(str(summary.get("risk_level", "unknown")).upper()))

    recommendations = summary.get("recommendations", [])
    if recommendations:
        lines.append("Recommendations:")
        for recommendation in recommendations:
            lines.append("- {}".format(recommendation))

    lines.append("")
    lines.append("Scan completed - Found {} open ports".format(len(open_ports)))
    return "\n".join(lines)


def _fallback_vulnerability_scan(args):
    if not args:
        return """VULNERABILITY SCANNER

Usage: vulnscan <target> [web|network|ssl] [--aggressive]
  target       Target URL, host, or IP
  web          Web configuration assessment (default)
  network      Network service exposure assessment
  ssl          TLS/certificate assessment
  --aggressive Enables active payload checks for web scans

Error: No target specified"""

    target = args[0]
    assessment = "web"
    aggressive = False

    for argument in args[1:]:
        lowered = argument.lower()
        if lowered in ("web", "network", "ssl"):
            assessment = lowered
        elif lowered == "--aggressive":
            aggressive = True

    scanner = _load_tool("vulnerability_scanner", "VulnerabilityScanner")()
    report = scanner.assess_target(target, assessment_type=assessment, aggressive=aggressive)

    if report.get("status") != "completed":
        return "VULNERABILITY SCANNER\n\nAssessment failed: {}".format(report.get("error", "unknown error"))

    counts = report.get("severity_counts", {})
    lines = [
        "VULNERABILITY SCANNER",
        "",
        "Target: {}".format(report.get("target", target)),
        "Assessment Type: {}".format(report.get("assessment_type", assessment)),
        "Aggressive Checks: {}".format("enabled" if aggressive else "disabled"),
        "Risk Level: {}".format(str(report.get("risk_level", "unknown")).upper()),
        "",
        "SEVERITY SUMMARY",
        "Critical: {} | High: {} | Medium: {} | Low: {} | Info: {}".format(
            counts.get("critical", 0),
            counts.get("high", 0),
            counts.get("medium", 0),
            counts.get("low", 0),
            counts.get("info", 0),
        ),
        "",
        "FINDINGS",
    ]

    findings = report.get("vulnerabilities", [])
    if not findings:
        lines.append("No findings detected for this assessment mode.")
    else:
        for finding in findings:
            lines.append("- [{severity}] {name}".format(
                severity=str(finding.get("severity", "low")).upper(),
                name=finding.get("name", "Unnamed finding"),
            ))
            lines.append("  Description: {}".format(finding.get("description", "No details")))
            if finding.get("recommendation"):
                lines.append("  Recommendation: {}".format(finding.get("recommendation")))

    lines.append("")
    lines.append("Assessment completed - {} finding(s)".format(len(findings)))
    return "\n".join(lines)


def _fallback_tls_scan(args):
    if not args:
        return """TLS SECURITY ANALYZER

Usage: tlscheck <target> [port]
  target       Hostname, host:port, or URL
  port         Optional port override (default: 443)

Error: No target specified"""

    target = args[0]
    port = 443

    if len(args) > 1:
        try:
            port = int(args[1])
        except ValueError:
            return "Invalid port: {}".format(args[1])

    analyzer = _load_tool("tls_security_analyzer", "TLSSecurityAnalyzer")()
    report = analyzer.analyze_target(target, port=port)

    if report.get("status") != "completed":
        return "TLS SECURITY ANALYZER\n\nAnalysis failed: {}".format(report.get("error", "unknown error"))

    cert = report.get("certificate", {})
    cipher = report.get("cipher", {})

    lines = [
        "TLS SECURITY ANALYZER",
        "",
        "Target: {}".format(report.get("target", target)),
        "Host: {}".format(report.get("hostname", "N/A")),
        "Port: {}".format(report.get("port", port)),
        "Risk Level: {}".format(str(report.get("risk_level", "unknown")).upper()),
        "",
        "CERTIFICATE",
        "Subject: {}".format(cert.get("subject", "N/A")),
        "Issuer: {}".format(cert.get("issuer", "N/A")),
        "Expires: {}".format(cert.get("not_after", "N/A")),
        "Days Until Expiry: {}".format(cert.get("days_until_expiry", "N/A")),
        "",
        "NEGOTIATED CIPHER",
        "Protocol: {}".format(cipher.get("protocol", "N/A")),
        "Cipher: {}".format(cipher.get("name", "N/A")),
    ]

    support = report.get("protocol_support", {})
    if support:
        lines.append("")
        lines.append("PROTOCOL SUPPORT")
        for protocol, enabled in support.items():
            if enabled is True:
                state = "enabled"
            elif enabled is False:
                state = "disabled"
            else:
                state = "unknown"
            lines.append("- {}: {}".format(protocol, state))

    findings = report.get("findings", [])
    if findings:
        lines.append("")
        lines.append("FINDINGS")
        for finding in findings:
            lines.append("- [{severity}] {name}".format(
                severity=str(finding.get("severity", "low")).upper(),
                name=finding.get("name", "Unnamed finding"),
            ))
            lines.append("  Description: {}".format(finding.get("description", "No details")))

    lines.append("")
    lines.append("Analysis completed")
    return "\n".join(lines)


def _fallback_password_check(args):
    if not args:
        return "Usage: passcheck <password>"

    password = " ".join(args)
    analyzer = _load_tool("password_analyzer", "PasswordAnalyzer")()
    report = analyzer.analyze_password(password)

    lines = [
        "PASSWORD ANALYZER",
        "",
        "Score: {}/100".format(report.get("score", 0)),
        "Complexity: {}".format(report.get("complexity", "Unknown")),
        "Entropy: {}".format(report.get("entropy", "N/A")),
    ]

    recommendations = report.get("recommendations", [])
    if recommendations:
        lines.append("")
        lines.append("Recommendations:")
        for recommendation in recommendations:
            lines.append("- {}".format(recommendation))

    return "\n".join(lines)


def _fallback_hash(args):
    if not args:
        return "Usage: hash [md5|sha1|sha256|sha512] <text>"

    algorithm = "sha256"
    payload_parts = list(args)

    if payload_parts[0].lower() in {"md5", "sha1", "sha256", "sha512"}:
        algorithm = payload_parts.pop(0).lower()

    if not payload_parts:
        return "Usage: hash [md5|sha1|sha256|sha512] <text>"

    payload = " ".join(payload_parts)
    hasher = _load_tool("hash_utils", "HashUtils")()
    digest = hasher.generate_hash(payload, algorithm)

    return "HASH RESULT\n\nAlgorithm: {}\nInput: {}\nDigest: {}".format(
        algorithm.upper(),
        payload,
        digest,
    )


def _fallback_ip_analysis(args):
    if not args:
        return """IP INTELLIGENCE

Usage: ipinfo <ip_address>
  ip_address    IP address to analyze

Example: ipinfo 8.8.8.8

Error: No IP address specified"""

    ip_address = args[0]
    analyzer = _load_tool("ip_analyzer", "IPAnalyzer")()
    result = analyzer.analyze_ip(ip_address)

    if result.get("error"):
        return "IP INTELLIGENCE\n\nAnalysis failed: {}".format(result["error"])

    network = result.get("network_info", {})
    reputation = result.get("reputation", {})
    security = result.get("security", {})
    geolocation = result.get("geolocation", {})

    lines = [
        "IP INTELLIGENCE",
        "",
        "Target: {}".format(result.get("ip_address", ip_address)),
        "IP Version: IPv{}".format(result.get("ip_version", "?")),
        "Private: {} | Loopback: {} | Reserved: {}".format(
            _yes_no(result.get("is_private")),
            _yes_no(result.get("is_loopback")),
            _yes_no(result.get("is_reserved")),
        ),
        "",
        "NETWORK CONTEXT",
        "Hostname: {}".format(network.get("hostname", "N/A")),
        "Global Reachability: {}".format(_yes_no(network.get("is_global"))),
        "Compressed: {}".format(network.get("compressed", "N/A")),
    ]

    if geolocation:
        lines.extend(
            [
                "",
                "GEOLOCATION",
                "Country: {} | City: {}".format(
                    geolocation.get("country", geolocation.get("status", "N/A")),
                    geolocation.get("city", "N/A"),
                ),
                "Organization: {}".format(geolocation.get("org", "N/A")),
            ]
        )

    lines.extend(
        [
            "",
            "REPUTATION",
            "Score: {}".format(reputation.get("score", "N/A")),
            "Status: {}".format(reputation.get("reputation", reputation.get("status", "Unknown"))),
        ]
    )

    threats = reputation.get("threats", [])
    if threats:
        lines.append("Indicators:")
        for threat in threats[:5]:
            lines.append("- {}".format(threat))

    if security:
        lines.extend(
            [
                "",
                "SECURITY SOURCES",
                "VirusTotal: {}".format(security.get("virustotal_status", "N/A")),
                "AbuseIPDB: {}".format(security.get("abuseipdb_status", "N/A")),
            ]
        )

    lines.append("")
    lines.append("IP analysis completed")
    return "\n".join(lines)


def _valid_record_count(records):
    if not isinstance(records, list):
        return 0

    return len(
        [
            record
            for record in records
            if not str(record).lower().startswith(("error:", "no records found", "domain not found"))
        ]
    )


def _fallback_domain_analysis(args):
    if not args:
        return """DOMAIN ANALYSIS

Usage: domain <domain_name>
  domain_name    Domain to analyze

Example: domain example.com

Error: No domain specified"""

    domain_name = args[0]
    analyzer = _load_tool("whois_analyzer", "WhoisAnalyzer")()
    result = analyzer.analyze_domain(domain_name)

    if result.get("error"):
        return "DOMAIN ANALYSIS\n\nAnalysis failed: {}".format(result["error"])

    whois_data = result.get("whois", {})
    dns_records = result.get("dns_records", {})
    security = result.get("security_assessment", {})

    lines = [
        "DOMAIN ANALYSIS",
        "",
        "Target: {}".format(result.get("domain", domain_name)),
        "Status: {}".format(result.get("status", "Unknown")),
        "",
        "WHOIS",
        "Registrar: {}".format(whois_data.get("registrar", "Unknown")),
        "Created: {}".format(whois_data.get("creation_date", "Unknown")),
        "Expires: {}".format(whois_data.get("expiration_date", "Unknown")),
        "",
        "DNS SUMMARY",
        "A: {} | AAAA: {} | MX: {} | TXT: {} | NS: {}".format(
            _valid_record_count(dns_records.get("a", [])),
            _valid_record_count(dns_records.get("aaaa", [])),
            _valid_record_count(dns_records.get("mx", [])),
            _valid_record_count(dns_records.get("txt", [])),
            _valid_record_count(dns_records.get("ns", [])),
        ),
    ]

    security_features = security.get("security_features", [])
    risk_factors = security.get("risk_factors", [])
    recommendations = security.get("recommendations", [])

    if security_features:
        lines.append("")
        lines.append("SECURITY FEATURES")
        for item in security_features[:5]:
            lines.append("- {}".format(item))

    if risk_factors:
        lines.append("")
        lines.append("RISK FACTORS")
        for item in risk_factors[:5]:
            lines.append("- {}".format(item))

    if recommendations:
        lines.append("")
        lines.append("RECOMMENDATIONS")
        for item in recommendations[:5]:
            lines.append("- {}".format(item))

    lines.append("")
    lines.append("Domain analysis completed")
    return "\n".join(lines)


def _fallback_email_analysis(args):
    if not args:
        return """EMAIL SECURITY

Usage: email <address> [--content <email_text>]
  address       Sender address to analyze
  --content     Optional email body snippet for phishing/spam checks

Examples:
  email security@example.com
  email security@example.com --content "urgent verify your account"

Error: No email address specified"""

    address_tokens = list(args)
    content_text = None

    if "--content" in args:
        idx = args.index("--content")
        address_tokens = args[:idx]
        content_tokens = args[idx + 1 :]
        if not content_tokens:
            return "Error: --content requires text to analyze."
        content_text = " ".join(content_tokens)

    email_address = " ".join(address_tokens).strip()
    if not email_address:
        return "Error: No email address specified."

    analyzer = _load_tool("email_analyzer", "EmailAnalyzer")()
    address_report = analyzer.analyze_email_address(email_address)

    if address_report.get("error"):
        return "EMAIL SECURITY\n\nAnalysis failed: {}".format(address_report["error"])

    lines = [
        "EMAIL SECURITY",
        "",
        "Address: {}".format(address_report.get("email", email_address)),
        "Risk Score: {}/100".format(address_report.get("risk_score", 0)),
        "Local Part: {}".format(address_report.get("local_part", "N/A")),
        "Domain: {}".format(address_report.get("domain", "N/A")),
    ]

    risk_factors = list(address_report.get("risk_factors", []))
    risk_factors.extend(address_report.get("domain_analysis", {}).get("risk_factors", []))

    if risk_factors:
        lines.append("")
        lines.append("RISK FACTORS")
        for factor in risk_factors[:6]:
            lines.append("- {}".format(factor))

    recommendations = address_report.get("recommendations", [])
    if recommendations:
        lines.append("")
        lines.append("RECOMMENDATIONS")
        for recommendation in recommendations[:5]:
            lines.append("- {}".format(recommendation))

    if content_text is not None:
        content_report = analyzer.analyze_email_content(content_text, sender_email=email_address)
        if content_report.get("error"):
            lines.append("")
            lines.append("Content Analysis Error: {}".format(content_report["error"]))
        else:
            lines.extend(
                [
                    "",
                    "CONTENT ANALYSIS",
                    "Security Score: {}/100".format(content_report.get("security_score", "N/A")),
                    "Phishing Indicators: {}".format(len(content_report.get("phishing_indicators", []))),
                    "Spam Indicators: {}".format(len(content_report.get("spam_indicators", []))),
                    "Suspicious Links: {}".format(len(content_report.get("suspicious_links", []))),
                ]
            )

    lines.append("")
    lines.append("Email analysis completed")
    return "\n".join(lines)


def _fallback_log_analysis(args):
    if not args:
        return """LOG ANALYZER

Usage: logs [--file <path>] [--type <log_type>] <log_text>
  --file        Analyze logs from a file path
  --type        Optional parser hint (apache_common, apache_combined, nginx, ssh, syslog)

Examples:
  logs --file /var/log/auth.log --type ssh
  logs --type apache_combined "192.0.2.10 - - [31/Jul/2026:12:00:00 +0000] \"GET /admin HTTP/1.1\" 401 721"

Error: No log input provided"""

    file_path = None
    log_type = None
    log_tokens = []

    idx = 0
    while idx < len(args):
        token = args[idx]
        if token == "--file":
            if idx + 1 >= len(args):
                return "Error: --file requires a path."
            file_path = args[idx + 1]
            idx += 2
            continue
        if token == "--type":
            if idx + 1 >= len(args):
                return "Error: --type requires a parser name."
            log_type = args[idx + 1]
            idx += 2
            continue

        log_tokens.append(token)
        idx += 1

    if file_path:
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as handle:
                log_content = handle.read(500000)
        except OSError as exc:
            return "LOG ANALYZER\n\nUnable to read file {}: {}".format(file_path, exc)
    else:
        if not log_tokens:
            return "Error: No log text provided."
        log_content = " ".join(log_tokens)

    analyzer = _load_tool("log_analyzer", "LogAnalyzer")()
    result = analyzer.analyze_logs(log_content, log_type=log_type)

    if result.get("error"):
        return "LOG ANALYZER\n\nAnalysis failed: {}".format(result["error"])

    lines = [
        "LOG ANALYZER",
        "",
        "Entries Parsed: {}".format(result.get("total_entries", 0)),
        "Security Events: {}".format(result.get("security_events", 0)),
        "Failed Logins: {}".format(result.get("failed_logins", 0)),
        "Suspicious IPs: {}".format(result.get("suspicious_ips", 0)),
    ]

    threats = result.get("threats", [])
    if threats:
        lines.append("")
        lines.append("TOP THREATS")
        for threat in threats[:5]:
            lines.append(
                "- {type}: {count} event(s), severity={severity}, unique_ips={ips}".format(
                    type=threat.get("type", "unknown"),
                    count=threat.get("count", 0),
                    severity=threat.get("severity", "Unknown"),
                    ips=threat.get("unique_ips", 0),
                )
            )

    recommendations = result.get("recommendations", [])
    if recommendations:
        lines.append("")
        lines.append("RECOMMENDATIONS")
        for recommendation in recommendations[:5]:
            lines.append(
                "- [{priority}] {category}: {text}".format(
                    priority=recommendation.get("priority", "Medium"),
                    category=recommendation.get("category", "General"),
                    text=recommendation.get("recommendation", "Review findings"),
                )
            )

    lines.append("")
    lines.append("Log analysis completed")
    return "\n".join(lines)


def _fallback_report_generation(args):
    report_type_map = {
        "vulnerability": "vulnerability_assessment",
        "vulnerability_assessment": "vulnerability_assessment",
        "network": "network_security",
        "network_security": "network_security",
        "comprehensive": "comprehensive",
    }

    report_type = "comprehensive"
    title = "Security Report"
    include_charts = False
    include_recommendations = True

    idx = 0
    while idx < len(args):
        token = args[idx]
        lowered = token.lower()

        if lowered == "--type":
            if idx + 1 >= len(args):
                return "Error: --type requires a value."
            report_type = report_type_map.get(args[idx + 1].lower(), report_type)
            idx += 2
            continue

        if lowered == "--title":
            if idx + 1 >= len(args):
                return "Error: --title requires a value."
            title = args[idx + 1]
            idx += 2
            continue

        if lowered == "--charts":
            include_charts = True
            idx += 1
            continue

        if lowered == "--no-recommendations":
            include_recommendations = False
            idx += 1
            continue

        if lowered in report_type_map:
            report_type = report_type_map[lowered]

        idx += 1

    summary_by_type = {
        "vulnerability_assessment": {
            "total_assets": 0,
            "vulnerabilities_found": 0,
            "critical_issues": 0,
            "high_risk_issues": 0,
            "medium_risk_issues": 0,
            "low_risk_issues": 0,
        },
        "network_security": {
            "network_ranges": "N/A",
            "total_hosts": 0,
            "active_services": 0,
            "security_issues": 0,
        },
        "comprehensive": {
            "total_assets": 0,
            "controls_evaluated": 0,
            "critical_issues": 0,
            "high_issues": 0,
            "medium_issues": 0,
            "low_issues": 0,
            "total_findings": 0,
            "recommendations": 0,
        },
    }

    report_data = {
        "type": report_type,
        "title": title,
        "summary": summary_by_type[report_type],
    }

    generator = _load_tool("report_generator", "ReportGenerator")()
    report = generator.generate_report(
        report_data,
        include_charts=include_charts,
        include_recommendations=include_recommendations,
    )

    if report.get("error"):
        return "REPORT GENERATOR\n\nGeneration failed: {}".format(report["error"])

    content_lines = str(report.get("content", "")).splitlines()
    preview = "\n".join(content_lines[:18]).strip()

    lines = [
        "REPORT GENERATOR",
        "",
        "Title: {}".format(report.get("title", title)),
        "Type: {}".format(report.get("type", report_type)),
        "Timestamp: {}".format(report.get("timestamp", "N/A")),
        "Charts Included: {}".format(_yes_no(include_charts)),
        "Recommendations Included: {}".format(_yes_no(include_recommendations)),
    ]

    if preview:
        lines.extend(["", "REPORT PREVIEW", preview])

    lines.extend(
        [
            "",
            "Tip: use the report module in code for full Markdown/JSON/HTML exports.",
            "Report generation completed",
        ]
    )
    return "\n".join(lines)


def fallback_process_command(command, user_session):
    """Fallback command processor that does not depend on Flask imports."""
    if not command:
        return ""

    try:
        cmd_parts = shlex.split(command)
    except ValueError as exc:
        return "Command parsing error: {}".format(exc)

    if not cmd_parts:
        return ""

    cmd = cmd_parts[0].lower()
    args = cmd_parts[1:]

    if cmd == "help":
        return _fallback_help_text()
    if cmd == "clear":
        return "CLEAR_SCREEN"
    if cmd == "menu":
        return _fallback_menu_text()
    if cmd == "status":
        return _fallback_status_text(user_session)
    if cmd == "whoami":
        return user_session.username
    if cmd == "pwd":
        return user_session.current_directory
    if cmd == "date":
        return datetime.now().strftime("%a %b %d %H:%M:%S %Y")
    if cmd == "uptime":
        uptime = datetime.now() - user_session.start_time
        return "up {}h {}m".format(uptime.seconds // 3600, (uptime.seconds % 3600) // 60)
    if cmd == "id":
        return "uid=1000(cybersec) gid=1000(cybersec) groups=1000(cybersec)"
    if cmd == "uname":
        return "CyberSec-Terminal 5.4.0-cybersec #1 SMP x86_64 GNU/Linux"
    if cmd in ("exit", "quit"):
        return "Session terminated. Thank you for using CyberSec Terminal."

    try:
        if cmd in ("01", "netscan", "network-scan"):
            return _fallback_network_scan(args)
        if cmd in ("02", "vulnscan", "vuln-scan"):
            return _fallback_vulnerability_scan(args)
        if cmd in ("03", "passcheck", "password-check"):
            return _fallback_password_check(args)
        if cmd in ("04", "hash"):
            return _fallback_hash(args)
        if cmd in ("05", "ipinfo", "ip-info"):
            return _fallback_ip_analysis(args)
        if cmd in ("06", "domain", "whois"):
            return _fallback_domain_analysis(args)
        if cmd in ("07", "email"):
            return _fallback_email_analysis(args)
        if cmd in ("08", "logs", "log-analyzer"):
            return _fallback_log_analysis(args)
        if cmd in ("09", "report"):
            return _fallback_report_generation(args)
        if cmd in ("10", "tlscheck", "tls-scan"):
            return _fallback_tls_scan(args)
    except RuntimeError as exc:
        return "Tool error: {}".format(exc)
    except Exception as exc:  # pragma: no cover - defensive path
        return "Unexpected command error: {}".format(exc)

    return "cybersec-terminal: command not found: {}\nType 'help' for available commands".format(command)


def load_terminal_backend():
    """Load shared command handlers from the web backend when available."""
    try:
        from cybersec_terminal.web import TerminalSession, process_command

        return TerminalSession, process_command, None
    except Exception as exc:
        return LocalTerminalSession, fallback_process_command, str(exc)


class InteractiveTerminal:
    """Command terminal using shared handlers or fallback scanner-backed handlers."""

    def __init__(self):
        terminal_session, command_handler, backend_error = load_terminal_backend()
        self.session = terminal_session()
        self.command_handler = command_handler
        self.local_handler = fallback_process_command
        self.backend_error = backend_error

    @property
    def prompt(self):
        return "{}@{}:~$ ".format(self.session.username, self.session.hostname)

    def print_banner(self):
        print("=" * 63)
        print("CYBERSEC TERMINAL v2.1")
        print("Professional Security Analysis")
        print("Session: {}".format(self.session.session_id))
        print("=" * 63)

        if self.backend_error:
            print("Running local fallback backend (web backend unavailable: {}).".format(self.backend_error))

    def run_command(self, command):
        command_name = _extract_command_name(command)
        use_local_handler = self.backend_error or (command_name in LOCAL_ANALYZER_COMMANDS)

        if use_local_handler:
            output = self.local_handler(command, self.session)
        else:
            output = self.command_handler(command, self.session)

        self.session.add_command(command, output)

        if output == "CLEAR_SCREEN":
            clear_screen()
            return

        rendered = render_terminal_output(output)
        if rendered:
            print(rendered)

    def run(self):
        clear_screen()
        self.print_banner()
        self.run_command("menu")
        print("Type 'help' for commands and 'exit' to quit.")

        while True:
            try:
                command = input(self.prompt).strip()
            except EOFError:
                print()
                break
            except KeyboardInterrupt:
                print("\nUse 'exit' to close the terminal.")
                continue

            if not command:
                continue

            self.run_command(command)
            if command.lower() in ("exit", "quit"):
                break


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="CyberSec interactive terminal",
        epilog="Example: cybersec-terminal --command 'netscan 127.0.0.1 quick'",
    )
    parser.add_argument(
        "--command",
        "-c",
        help="Run one terminal command and exit",
    )
    return parser.parse_args(argv)


def main(argv=None):
    if colorama_init is not None:
        colorama_init(autoreset=True)

    args = parse_args(argv)
    terminal = InteractiveTerminal()

    if args.command:
        terminal.run_command(args.command)
        return

    terminal.run()


if __name__ == "__main__":
    main(sys.argv[1:])
