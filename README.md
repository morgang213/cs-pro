# CyberSec Analyst Tool

[![CI Pipeline](https://github.com/morgang213/cs-pro/workflows/CI%20Pipeline/badge.svg)](https://github.com/morgang213/cs-pro/actions/workflows/ci.yml)
[![Release](https://github.com/morgang213/cs-pro/workflows/Release%20and%20Deploy/badge.svg)](https://github.com/morgang213/cs-pro/actions/workflows/deploy.yml)
[![Security Audit](https://github.com/morgang213/cs-pro/workflows/Dependency%20and%20Security%20Audit/badge.svg)](https://github.com/morgang213/cs-pro/actions/workflows/security-audit.yml)
[![Docker](https://github.com/morgang213/cs-pro/workflows/Docker%20Build%20and%20Push/badge.svg)](https://github.com/morgang213/cs-pro/actions/workflows/docker.yml)
[![Code Quality](https://github.com/morgang213/cs-pro/workflows/Code%20Quality%20and%20Documentation/badge.svg)](https://github.com/morgang213/cs-pro/actions/workflows/code-quality.yml)

A comprehensive cybersecurity analysis and assessment platform with a modern web terminal interface, providing a suite of security tools for network scanning, vulnerability assessment, password analysis, and threat intelligence.

## 🌐 Web-Based User Interface

This application provides a **complete web interface** accessible through your browser:

### Quick Start
```bash
# Option 1: Easy startup script
python3 start.py

# Option 2: Direct launch
python3 terminal_web.py
```

**Access at:** `http://127.0.0.1:5000`

The interface includes:
- 📊 **Interactive Dashboard** with security metrics
- 🔧 **10 Integrated Terminal Security Modules** 
- 📈 **Real-time Charts and Visualizations**
- 📄 **Report Generation and Export**
- 🗂️ **Database Management Interface**
- 👤 **Session Tracking and Analytics**

> **See [UI_GUIDE.md](UI_GUIDE.md) for detailed interface documentation**

## Features

### 🌐 Network Security
- **Network Scanner**: Port scanning and host discovery with concurrent scanning capabilities
- **Vulnerability Assessment**: Web application security testing including XSS, SQL injection, and SSL/TLS analysis
- **IP Analysis**: Geolocation, reputation checking, and threat intelligence

### 🔐 Security Analysis
- **Password Analyzer**: Comprehensive password strength assessment with entropy calculation
- **Hash Generator/Verifier**: Cryptographic hash operations supporting multiple algorithms
- **Email Security**: Email address analysis and content scanning for phishing/spam detection

### 🌍 Domain Intelligence
- **WHOIS Analysis**: Domain registration information and DNS record investigation
- **DNS Security**: SPF, DMARC, and security configuration analysis
- **Domain Reputation**: Risk assessment and suspicious pattern detection

### 📊 Monitoring & Reporting
- **Security Log Analysis**: Multi-format log parsing and threat detection
- **Report Generator**: Comprehensive security reports in multiple formats
- **Dashboard**: Real-time security monitoring and analysis overview

## 🚀 Installation

### **Quick Install (Recommended)**

#### **Linux/macOS:**
```bash
# Download and extract
wget https://github.com/morgang213/cs-pro/releases/latest/download/cybersec-terminal-v2.0.0.tar.gz
tar -xzf cybersec-terminal-v2.0.0.tar.gz
cd cybersec-terminal-v2.0.0/

# One-command install
./install.sh
```

#### **Windows:**
1. Download `cybersec-terminal-v2.0.0.zip` from releases
2. Extract the ZIP file
3. Double-click `install.bat`

### **Manual Installation**

#### **Prerequisites:**
- Python 3.7 or higher
- pip (Python package installer)

#### **Step-by-step:**
```bash
# Clone repository
git clone https://github.com/morgang213/cs-pro.git
cd cs-pro

# Install dependencies
pip install -r requirements.txt

# Run application
python terminal_web.py  # Web Terminal (recommended)
# OR
python app.py          # Interactive CLI terminal
# OR
python cli.py --help   # Automation CLI options
```

### **Package Installation**
```bash
# Install as Python package
pip install cybersec-terminal

# Run commands
cybersec           # Launch interface selector
cybersec-web       # Start web terminal
cybersec-terminal  # Start CLI mode
```

### **macOS DMG Builder**
```bash
# Build a drag-and-drop macOS installer image
./build_macos_dmg.sh

# Open the generated installer
open dist/CyberSec-Terminal-macOS.dmg
```

Optional release signing/notarization:
```bash
# Sign app + DMG
./build_macos_dmg.sh --codesign-identity "Developer ID Application: Example Co (TEAMID)"

# Sign + notarize with a preconfigured notarytool keychain profile
./build_macos_dmg.sh --codesign-identity "Developer ID Application: Example Co (TEAMID)" --notarize --notary-profile "AC_PASSWORD_PROFILE"
```

## Usage

### **Quick Start Options:**

#### **1. Web Terminal (Recommended)**
```bash
# Launch web interface
python terminal_web.py
# OR
cybersec-web

# Access at: http://127.0.0.1:5000
```

#### **2. CLI Terminal**
```bash
# Launch interactive command-line terminal
python app.py
# OR
cybersec-terminal
```

#### **3. Automation CLI**
```bash
# Scriptable scanner commands
python cli.py --scan 127.0.0.1 --type quick
python cli.py --vuln https://example.com --assessment web --aggressive
python cli.py --tls example.com --tls-port 443
python cli.py --json --scan 127.0.0.1 --type port --ports 22,80,443
```

#### **4. Interface Selector**
```bash
# Choose between web and CLI
python launch_terminal.py
# OR
cybersec
```

### **Terminal Commands:**
- `help` - Show all available commands
- `menu` - Display security modules
- `netscan <target>` - Network port scanning
- `vulnscan <target> [web|network|ssl]` - Vulnerability assessment modes
- `tlscheck <target> [port]` - TLS certificate/protocol analysis
- `passcheck <password>` - Password strength analysis
- `hash <algorithm> <text>` - Generate cryptographic hashes
- `ipinfo <ip>` - IP geolocation and reputation
- `domain <domain>` - WHOIS and DNS analysis
- `email <address> [--content <text>]` - Email address/content risk analysis
- `logs [--file <path>] [--type <parser>] <log text>` - Log threat analysis
- `report [vulnerability|network|comprehensive] [--title <name>]` - Security report generation
- `clear` - Clear terminal screen

### **Example Usage:**
```bash
# Network scan
netscan 192.168.1.1

# Vulnerability assessment
vulnscan https://example.com

# TLS analysis
tlscheck example.com 443

# Password analysis
passcheck "MySecurePassword123!"

# Hash generation
hash sha256 "hello world"
```

## Security Features

### Network Analysis
- Port scanning with service identification
- Concurrent scanning for improved performance
- Host discovery and OS detection
- SSL/TLS configuration analysis

### Threat Detection
- Phishing email detection
- Spam content analysis
- Suspicious link identification
- Brute force attack detection
- SQL injection pattern recognition
- XSS vulnerability detection

### Intelligence Gathering
- WHOIS domain information
- DNS record analysis
- IP geolocation and reputation
- Email domain verification
- Security header analysis

## External API Integration

The tool supports optional integration with external threat intelligence services:

- **IPInfo**: IP geolocation services (requires IPINFO_TOKEN)
- **VirusTotal**: Malware and threat intelligence (requires VIRUSTOTAL_API_KEY)
- **AbuseIPDB**: IP reputation checking (requires ABUSEIPDB_API_KEY)

Set these as environment variables to enable enhanced features.

## Architecture

### Frontend
- **Flask + HTML/CSS terminal UI**: Browser-based interactive terminal
- **Responsive Design**: Keyboard-first command interface

### Backend
- **Modular Design**: Separate utility classes for each analysis type
- **Concurrent Processing**: Multi-threaded operations for improved performance
- **Error Handling**: Robust error handling with user-friendly messages

### Security Considerations
- Input validation and sanitization
- Rate limiting for network operations
- Secure API key handling via environment variables
- SSL certificate verification options

## Tool Modules

### Network Scanner (`network_scanner.py`)
- Port scanning with customizable ranges
- Service identification and OS detection
- Concurrent scanning capabilities

### Vulnerability Scanner (`vulnerability_scanner.py`)
- Web application security testing
- SSL/TLS configuration analysis
- Common vulnerability detection

### Password Analyzer (`password_analyzer.py`)
- Entropy calculation and complexity assessment
- Pattern detection and strength scoring
- Security recommendations

### Hash Utils (`hash_utils.py`)
- Multiple hash algorithm support
- File hash generation and verification
- HMAC and password hashing capabilities

### IP Analyzer (`ip_analyzer.py`)
- Geolocation and network information
- Threat intelligence integration
- Reputation scoring

### WHOIS Analyzer (`whois_analyzer.py`)
- Domain registration information
- DNS record analysis
- Security assessment and recommendations

### Email Analyzer (`email_analyzer.py`)
- Email address security analysis
- Content scanning for threats
- Phishing and spam detection

### Log Analyzer (`log_analyzer.py`)
- Multi-format log parsing
- Security event detection
- Threat pattern analysis

### Report Generator (`report_generator.py`)
- Comprehensive security reports
- Multiple export formats
- Template-based reporting

## 🐳 Deployment

### Docker Deployment

#### Using Pre-built Images
```bash
# Pull from GitHub Container Registry
docker pull ghcr.io/morgang213/cs-pro:latest

# Run container
docker run -d -p 5000:5000 ghcr.io/morgang213/cs-pro:latest

# Access at http://localhost:5000
```

#### Using Docker Compose
```bash
# Clone repository
git clone https://github.com/morgang213/cs-pro.git
cd cs-pro

# Start services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

#### Building Custom Image
```bash
# Build image
docker build -t cybersec-terminal:custom .

# Run with custom configuration
docker run -d \
  -p 5000:5000 \
  -e IPINFO_TOKEN=your_token \
  -e VIRUSTOTAL_API_KEY=your_key \
  cybersec-terminal:custom
```

### CI/CD Workflows

This repository includes comprehensive GitHub Actions workflows for automated testing, building, and deployment:

- **CI Pipeline**: Automated testing on multiple Python versions
- **Release & Deploy**: Automatic release creation when tags are pushed
- **Security Audit**: Weekly dependency and security scans
- **Code Quality**: Automated code quality checks
- **Docker Build**: Multi-platform Docker image builds

**Creating a Release:**
```bash
# Update version and create tag
git tag -a v2.0.1 -m "Release version 2.0.1"
git push origin v2.0.1
# Workflow automatically creates GitHub release with packages
```

For detailed workflow documentation, see [.github/WORKFLOWS.md](.github/WORKFLOWS.md)

## Configuration

### Server Configuration (`.streamlit/config.toml`)
```toml
[server]
headless = true
address = "0.0.0.0"
port = 5000
```

### Environment Variables
```bash
# Optional API keys for enhanced functionality
IPINFO_TOKEN=your_ipinfo_token
VIRUSTOTAL_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is intended for educational and authorized security testing purposes only. Users are responsible for compliance with applicable laws and regulations.

## Support

For issues, feature requests, or questions:
1. Check the built-in help documentation in the sidebar
2. Review the tool descriptions and quick tips
3. Consult the comprehensive analysis capabilities overview

## Disclaimer

This tool is designed for authorized security testing and educational purposes. Users must ensure they have proper authorization before conducting any security assessments on systems they do not own or have explicit permission to test.