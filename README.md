# CyberSec Analyst Tool

A comprehensive cybersecurity analysis and assessment platform with a **modern web-based user interface** built with Streamlit, providing a suite of security tools for network scanning, vulnerability assessment, password analysis, and threat intelligence.

## 🌐 Web-Based User Interface

This application provides a **complete web interface** accessible through your browser:

### Quick Start
```bash
# Option 1: Easy startup script
python3 start.py

# Option 2: Direct launch
streamlit run app.py --server.port 5500
```

**Access at:** `http://localhost:5500`

The interface includes:
- 📊 **Interactive Dashboard** with security metrics
- 🔧 **19 Integrated Security Tools** 
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
python app.py          # CLI Terminal
```

### **Package Installation**
```bash
# Install as Python package
pip install cybersec-terminal

# Run commands
cybersec           # Launch interface selector
cybersec-web       # Start web terminal
cybersec-cli       # Start CLI terminal
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
# Launch command-line interface
python app.py
# OR
cybersec-cli
```

#### **3. Interface Selector**
```bash
# Choose between web and CLI
python launch_terminal.py
# OR
cybersec
```

### **Web Terminal Commands:**
- `help` - Show all available commands
- `menu` - Display security modules
- `netscan <target>` - Network port scanning
- `vulnscan <url>` - Web vulnerability assessment
- `passcheck <password>` - Password strength analysis
- `hash <algorithm> <text>` - Generate cryptographic hashes
- `ipinfo <ip>` - IP geolocation and reputation
- `domain <domain>` - WHOIS and DNS analysis
- `clear` - Clear terminal screen

### **Example Usage:**
```bash
# Network scan
netscan 192.168.1.1

# Vulnerability assessment
vulnscan https://example.com

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
- **Streamlit**: Interactive web application framework
- **Plotly**: Data visualization and charting
- **Responsive Design**: Wide layout with expandable sidebar

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

### Network Scanner (`utils/network_scanner.py`)
- Port scanning with customizable ranges
- Service identification and OS detection
- Concurrent scanning capabilities

### Vulnerability Scanner (`utils/vulnerability_scanner.py`)
- Web application security testing
- SSL/TLS configuration analysis
- Common vulnerability detection

### Password Analyzer (`utils/password_analyzer.py`)
- Entropy calculation and complexity assessment
- Pattern detection and strength scoring
- Security recommendations

### Hash Utils (`utils/hash_utils.py`)
- Multiple hash algorithm support
- File hash generation and verification
- HMAC and password hashing capabilities

### IP Analyzer (`utils/ip_analyzer.py`)
- Geolocation and network information
- Threat intelligence integration
- Reputation scoring

### WHOIS Analyzer (`utils/whois_analyzer.py`)
- Domain registration information
- DNS record analysis
- Security assessment and recommendations

### Email Analyzer (`utils/email_analyzer.py`)
- Email address security analysis
- Content scanning for threats
- Phishing and spam detection

### Log Analyzer (`utils/log_analyzer.py`)
- Multi-format log parsing
- Security event detection
- Threat pattern analysis

### Report Generator (`utils/report_generator.py`)
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