# Contributing to CyberSec Terminal

Thank you for your interest in contributing to CyberSec Terminal! We welcome contributions from the cybersecurity community.

## 🛡️ Security First

- **Responsible Disclosure**: Report security vulnerabilities privately before public disclosure
- **Authorized Testing**: Only include features that promote authorized security testing
- **Educational Focus**: Contributions should have clear educational or legitimate security testing value

## 🚀 How to Contribute

### 1. Fork the Repository
```bash
git clone https://github.com/morgang213/cs-pro.git
cd cs-pro
```

### 2. Set Up Development Environment
```bash
# Linux/macOS
./install.sh

# Windows
install.bat
```

### 3. Create Feature Branch
```bash
git checkout -b feature/your-feature-name
```

### 4. Make Your Changes
- Follow existing code style and conventions
- Add tests for new functionality
- Update documentation as needed
- Ensure security best practices

### 5. Test Your Changes
```bash
# Test CLI terminal
python cybersec_terminal/cli.py

# Test web terminal
python cybersec_terminal/web.py

# Run tests (if available)
pytest tests/
```

### 6. Submit Pull Request
- Provide clear description of changes
- Include screenshots for UI changes
- Reference any related issues

## 📝 Code Standards

### Python Style
- Follow PEP 8 style guidelines
- Use type hints where appropriate
- Include docstrings for functions and classes
- Keep functions focused and small

### Security Considerations
- Validate all user inputs
- Use secure defaults
- Implement proper error handling
- Follow OWASP security guidelines

### Documentation
- Update README.md for new features
- Add inline comments for complex logic
- Include usage examples
- Update TERMINAL_GUIDE.md for UI changes

## 🐛 Bug Reports

When reporting bugs, include:
- Operating system and version
- Python version
- Complete error messages
- Steps to reproduce
- Expected vs actual behavior

## 💡 Feature Requests

For new features, provide:
- Clear use case description
- Security implications assessment
- Implementation approach (if known)
- Benefits to the community

## 🔧 Development Setup

### Required Tools
- Python 3.7+
- Git
- Text editor/IDE
- Web browser (for web terminal testing)

### Optional Tools
- pytest (for testing)
- black (for code formatting)
- flake8 (for linting)

## 📋 Pull Request Checklist

- [ ] Code follows project style guidelines
- [ ] Tests pass (if applicable)
- [ ] Documentation is updated
- [ ] Security implications considered
- [ ] Commit messages are clear and descriptive
- [ ] No sensitive information in commits

## 🏆 Recognition

Contributors will be recognized in:
- README.md contributors section
- Release notes
- Project documentation

Thank you for helping make cybersecurity tools more accessible and secure! 🛡️
