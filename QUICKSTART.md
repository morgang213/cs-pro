# 🚀 CyberSec Terminal - Quick Start Guide

## ⚡ 30-Second Setup

### **Linux/macOS:**
```bash
wget -O cybersec.tar.gz https://github.com/morgang213/cs-pro/archive/main.tar.gz
tar -xzf cybersec.tar.gz && cd cs-pro-main
./install.sh
cybersec-web  # Start web terminal
```

### **Windows:**
1. Download ZIP from GitHub
2. Extract and open folder
3. Double-click `install.bat`
4. Double-click `cybersec-web.bat`

### **Browser Access:**
Open http://127.0.0.1:5000 in your browser

---

## 🎯 Essential Commands

| Command | Purpose | Example |
|---------|---------|---------|
| `help` | Show all commands | `help` |
| `menu` | Show security tools | `menu` |
| `netscan` | Network scanning | `netscan 192.168.1.1` |
| `vulnscan` | Vulnerability test | `vulnscan https://example.com` |
| `tlscheck` | TLS posture analysis | `tlscheck example.com 443` |
| `passcheck` | Password strength | `passcheck "MyPass123!"` |
| `hash` | Generate hashes | `hash sha256 "text"` |
| `ipinfo` | IP analysis | `ipinfo 8.8.8.8` |
| `domain` | Domain analysis | `domain google.com` |
| `email` | Email security analysis | `email security@example.com` |
| `logs` | Log threat analysis | `logs --type ssh "failed password"` |
| `report` | Generate security report | `report comprehensive` |
| `clear` | Clear screen | `clear` |

---

## 🛠️ Interface Options

### **1. Web Terminal (Recommended)**
- Modern browser interface
- Professional terminal styling
- Mobile-friendly design
- Run: `cybersec-web` or `python terminal_web.py`

### **2. CLI Terminal**  
- Traditional command-line
- Lightweight and fast
- Pure terminal experience
- Run: `cybersec-terminal` or `python app.py`

### **3. Automation CLI**
- Scriptable scanner-first command mode
- JSON output for pipelines and integrations
- Run: `python cli.py --help`

### **4. Launcher**
- Choose your preferred interface
- Easy switching between modes
- Run: `cybersec` or `python launch_terminal.py`

---

## 🔒 Security Tools Overview

### **Network Analysis**
- **Port Scanning**: Discover open services
- **Host Discovery**: Find active systems
- **Service Detection**: Identify running services

### **Vulnerability Assessment**
- **Web Security**: Test for common vulnerabilities
- **SSL/TLS Analysis**: Check encryption configuration
- **Security Headers**: Verify proper headers

### **Password Security**
- **Strength Analysis**: Evaluate password quality
- **Entropy Calculation**: Measure randomness
- **Best Practice Checks**: Security recommendations

### **Digital Forensics**
- **Hash Generation**: Create file checksums
- **IP Intelligence**: Geolocation and reputation
- **Domain Investigation**: WHOIS and DNS analysis

---

## 📱 Platform Support

### **Fully Compatible**
- ✅ Windows 10/11
- ✅ macOS 10.15+
- ✅ Ubuntu 18.04+
- ✅ Debian 10+
- ✅ CentOS 7+
- ✅ Fedora 30+

### **Browser Support**
- ✅ Chrome 80+
- ✅ Firefox 75+
- ✅ Safari 13+
- ✅ Edge 80+
- ✅ Mobile browsers

---

## ⚠️ Important Security Notes

### **Authorized Use Only**
- Only test systems you own or have written permission to test
- Follow responsible disclosure practices
- Comply with local laws and regulations

### **Educational Purpose**
- This tool is for learning and authorized security testing
- Not intended for malicious activities
- Use only with explicit authorization on approved targets

### **Best Practices**
- Always obtain proper authorization before testing
- Document your testing activities
- Report vulnerabilities responsibly
- Keep the tool updated

---

## 🆘 Troubleshooting

### **Installation Issues**
```bash
# Check Python version (need 3.7+)
python3 --version

# Install missing dependencies
pip install -r requirements.txt

# Reset virtual environment
rm -rf venv && ./install.sh
```

### **Web Terminal Not Loading**
1. Check if port 5000 is available
2. Try different port: `PORT=8080 python terminal_web.py`
3. Check firewall settings
4. Restart the application

### **Command Not Found**
1. Add `~/.local/bin` to your PATH
2. Use full paths: `python3 terminal_web.py`
3. Reinstall with `./install.sh`

### **Permission Errors**
```bash
# Fix script permissions
chmod +x install.sh
chmod +x build.sh

# Fix virtual environment
sudo chown -R $(whoami) venv/
```

---

## 🎓 Learning Resources

### **Getting Started**
1. Run `help` command for full reference
2. Try `menu` to see all tools
3. Start with simple commands like `ipinfo 8.8.8.8`
4. Read TERMINAL_GUIDE.md for detailed usage

### **Advanced Usage**
- Explore different scan types
- Combine tools for comprehensive analysis
- Generate reports for documentation
- Customize terminal appearance

### **Community**
- GitHub Issues for bug reports
- Discussions for feature requests
- Contributing guidelines in CONTRIBUTING.md
- Security advisories for vulnerabilities

---

## 🎉 You're Ready!

Your CyberSec Terminal is now ready for professional security analysis!

**Next Steps:**
1. Open web terminal: http://127.0.0.1:5000
2. Type `help` to see all commands
3. Try `menu` to explore security tools
4. Start with simple scans and build up

**Remember:** Always use responsibly and with proper authorization! 🛡️

---

*Happy Security Testing!* 🚀
