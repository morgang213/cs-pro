# GitHub Copilot Instructions for CyberSec Terminal

## Project Overview

CyberSec Terminal is a comprehensive cybersecurity analysis and assessment platform providing security tools for network scanning, vulnerability assessment, password analysis, and threat intelligence. The project offers both web-based (Streamlit) and CLI interfaces for security professionals and educational purposes.

## Tech Stack

### Core Technologies
- **Python**: 3.7+ (supporting 3.7-3.12)
- **Web Framework**: Flask 2.3.0+ for backend, Streamlit for UI
- **Key Libraries**:
  - `requests` for HTTP operations
  - `python-whois` for domain analysis
  - `dnspython` for DNS queries
  - `cryptography` for security operations
  - `colorama` for CLI formatting

### Architecture
- **Modular Design**: Separate Python modules for each security analysis type
- **Concurrent Processing**: Multi-threaded operations for network scanning
- **Web UI**: Streamlit-based interactive dashboard with Plotly visualizations
- **CLI**: Flask-based terminal interface

## Project Structure

```
/
├── *.py                    # Security analysis modules (network_scanner, vulnerability_scanner, etc.)
├── app.py                  # Streamlit web application
├── cli.py                  # CLI entry point
├── terminal_web.py         # Web terminal interface
├── launch_terminal.py      # Interface selector
├── database.py             # Database management
├── requirements.txt        # Production dependencies
├── setup.py                # Package configuration
├── templates/              # HTML templates for web interface
└── .github/                # CI/CD workflows and documentation
```

## Coding Conventions

### Python Style
- Follow PEP 8 style guidelines
- Use descriptive variable names (e.g., `target_ip`, `scan_results`)
- Maximum line length: 120 characters (flexible for readability)
- Use type hints where beneficial for clarity
- Avoid excessive comments; prefer self-documenting code

### Security Best Practices
- **Input Validation**: Always validate and sanitize user inputs
- **Rate Limiting**: Implement rate limiting for network operations
- **Error Handling**: Use try-except blocks with user-friendly error messages
- **API Keys**: Store sensitive data in environment variables, never hardcode
- **SSL/TLS**: Enable certificate verification by default, allow override only when necessary
- **Authorization**: All tools must include disclaimers about authorized use only

### Module Structure
Each security analysis module should follow this pattern:
```python
class AnalyzerName:
    def __init__(self):
        """Initialize analyzer with configuration"""
        pass
    
    def analyze(self, target):
        """Main analysis method with validation"""
        # Input validation
        # Analysis logic
        # Return structured results
        pass
    
    def _helper_method(self):
        """Private helper methods prefixed with underscore"""
        pass
```

### Error Handling
- Use descriptive error messages that help users understand what went wrong
- Log errors appropriately without exposing sensitive information
- Provide actionable suggestions in error messages when possible
- Handle network timeouts gracefully with configurable retry logic

## Testing and Quality

### Build and Test Commands
```bash
# Install dependencies
pip install -r requirements.txt

# Build package
python setup.py sdist bdist_wheel

# Verify imports (minimal testing)
python -c "import network_scanner, vulnerability_scanner, password_analyzer"

# Run linting
flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics

# Run security checks
safety check
bandit -r . -f json -o bandit-report.json
```

### Code Quality
- Run `flake8` for syntax errors before committing
- Use `safety` to check for vulnerable dependencies
- Use `bandit` for security issue scanning
- All CI checks must pass before merging

## Build and Deployment

### Local Development
```bash
# Web UI (recommended for development)
python start.py
# OR
streamlit run app.py --server.port 5500

# Web Terminal
python terminal_web.py  # Access at http://127.0.0.1:5000

# CLI Terminal
python app.py
```

### Package Building
```bash
# Build distribution packages
python setup.py sdist bdist_wheel

# Verify package
twine check dist/*
```

### Docker
```bash
# Build image
docker build -t cybersec-terminal .

# Run container
docker run -d -p 5000:5000 cybersec-terminal

# Use docker-compose
docker-compose up -d
```

### Release Process
- Version tags follow semantic versioning: `v2.0.0`
- Releases are automated via GitHub Actions when tags matching `v*.*.*` are pushed
- The release workflow builds packages, creates archives, and publishes to GitHub Releases
- See `.github/WORKFLOWS.md` for detailed CI/CD documentation

## Security Considerations

### This is a Security Tool
- **Authorization Required**: All features are for authorized testing only
- **Educational Purpose**: Emphasize legitimate security research and education
- **Responsible Disclosure**: Security vulnerabilities should be reported privately
- **No Malicious Use**: Code must not facilitate unauthorized access or attacks

### Secure Coding Requirements
- Validate all user inputs to prevent injection attacks
- Use parameterized queries for any database operations
- Implement proper exception handling to avoid information leakage
- Use secure random number generation for cryptographic operations
- Follow principle of least privilege in file and network operations

### API Integration
External services require API keys via environment variables:
- `IPINFO_TOKEN` - IP geolocation services
- `VIRUSTOTAL_API_KEY` - Malware and threat intelligence
- `ABUSEIPDB_API_KEY` - IP reputation checking

Never commit API keys or secrets to the repository.

## Documentation

### Update Documentation When:
- Adding new security analysis modules
- Changing CLI commands or web interface features
- Modifying installation or deployment procedures
- Adding new external API integrations
- Updating dependencies or Python version requirements

### Key Documentation Files
- `README.md` - Main project documentation and quick start
- `UI_GUIDE.md` - Web interface documentation
- `TERMINAL_GUIDE.md` - CLI terminal documentation
- `CONTRIBUTING.md` - Contribution guidelines
- `.github/WORKFLOWS.md` - CI/CD workflow documentation

## Dependencies

### Adding New Dependencies
1. Add to `requirements.txt` with minimum version: `package>=X.Y.Z`
2. Add to `setup.py` in `install_requires` list
3. Test compatibility with Python 3.7-3.12
4. Run `safety check` to verify no known vulnerabilities
5. Update documentation if the dependency adds new features

### Dependency Philosophy
- Prefer standard library when possible
- Use well-maintained, security-focused libraries
- Minimize dependency count to reduce attack surface
- Pin minimum versions but allow patch updates

## Common Tasks

### Adding a New Security Analysis Module
1. Create new Python file: `new_analyzer.py`
2. Implement class with `__init__` and `analyze` methods
3. Add input validation and error handling
4. Include security disclaimers in docstrings
5. Update `app.py` to integrate into web UI
6. Update `cli.py` to add CLI command
7. Document in `README.md` and relevant guides

### Updating the Web UI
- Streamlit components in `app.py`
- Use Streamlit widgets: `st.text_input()`, `st.button()`, `st.selectbox()`
- Maintain wide layout: `st.set_page_config(layout="wide")`
- Use expandable sections for organization: `st.expander()`
- Add loading spinners for long operations: `with st.spinner():`

### Modifying CLI Commands
- CLI implementation in `cli.py` and `terminal_web.py`
- Use Flask routes for web terminal commands
- Maintain consistent command structure: `command <target> [options]`
- Provide help text for all commands
- Return formatted results using colorama for CLI

## CI/CD Workflows

### Automated Workflows
- **CI Pipeline**: Tests on push/PR (Python 3.7-3.12)
- **Release**: Triggered by version tags, creates GitHub release
- **Security Audit**: Weekly dependency scans
- **Code Quality**: Linting and style checks
- **Docker Build**: Multi-platform image builds

### Workflow Triggers
- `main` and `develop` branches trigger CI on push
- Pull requests trigger full CI suite
- Version tags (`v*.*.*`) trigger release workflow
- Weekly schedule for security audits

## Notes for Copilot

- **Security First**: This is a cybersecurity tool; security is paramount
- **Educational Focus**: All features should support legitimate security education and authorized testing
- **Minimal Dependencies**: Keep the dependency footprint small
- **Cross-Platform**: Support Linux, macOS, and Windows
- **Python Compatibility**: Maintain compatibility with Python 3.7-3.12
- **User-Friendly**: Provide clear error messages and helpful feedback
- **Modular Architecture**: Keep security analysis modules independent
- **Documentation**: Comprehensive documentation is essential for security tools
