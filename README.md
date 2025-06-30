# CyberSec Analyst Tool

A comprehensive cybersecurity analysis and assessment platform built with Streamlit, providing a suite of security tools for network scanning, vulnerability assessment, password analysis, and threat intelligence.

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

## Installation

The application runs on Replit with all dependencies automatically managed:

```bash
# Dependencies are automatically installed via uv
# Core packages: streamlit, pandas, plotly, requests
# Security packages: cryptography, bcrypt, scapy, python-whois, dnspython, shodan, python-nmap
```

## Usage

1. **Start the Application**
   ```bash
   streamlit run app.py --server.port 5000
   ```

2. **Access the Dashboard**
   - Navigate to the provided URL (typically http://localhost:5000)
   - Select tools from the sidebar navigation

3. **Tool-Specific Usage**
   - **Network Scanner**: Enter target IP/hostname and select scan type
   - **Vulnerability Assessment**: Input target URL and choose assessment type
   - **Password Analyzer**: Enter password for strength evaluation
   - **Hash Utils**: Generate or verify cryptographic hashes
   - **IP Analysis**: Analyze IP addresses for geolocation and reputation
   - **Domain Analysis**: Investigate domains with WHOIS and DNS analysis
   - **Email Security**: Check email addresses and content for threats
   - **Log Analysis**: Upload security logs for threat detection
   - **Report Generator**: Create comprehensive security assessment reports

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