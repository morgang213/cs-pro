#!/bin/bash

# CyberSec Terminal - Easy Installation Script
# Professional Cybersecurity Analysis Platform

set -e

echo "🛡️  CyberSec Terminal - Installation Script"
echo "=============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_header() {
    echo -e "${PURPLE}$1${NC}"
}

# Check if Python is installed
check_python() {
    print_status "Checking Python installation..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d ' ' -f 2)
        print_success "Python $PYTHON_VERSION found"
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then
        PYTHON_VERSION=$(python --version | cut -d ' ' -f 2)
        if [[ $PYTHON_VERSION == 3* ]]; then
            print_success "Python $PYTHON_VERSION found"
            PYTHON_CMD="python"
        else
            print_error "Python 3.7+ is required. Found Python $PYTHON_VERSION"
            exit 1
        fi
    else
        print_error "Python is not installed. Please install Python 3.7+ first."
        echo "Visit: https://www.python.org/downloads/"
        exit 1
    fi
}

# Check if pip is installed
check_pip() {
    print_status "Checking pip installation..."
    
    if command -v pip3 &> /dev/null; then
        print_success "pip3 found"
        PIP_CMD="pip3"
    elif command -v pip &> /dev/null; then
        print_success "pip found"
        PIP_CMD="pip"
    else
        print_error "pip is not installed. Installing pip..."
        $PYTHON_CMD -m ensurepip --upgrade || {
            print_error "Failed to install pip. Please install it manually."
            exit 1
        }
        PIP_CMD="$PYTHON_CMD -m pip"
    fi
}

# Create virtual environment
create_venv() {
    print_status "Creating virtual environment..."
    
    if [ ! -d "venv" ]; then
        $PYTHON_CMD -m venv venv
        print_success "Virtual environment created"
    else
        print_warning "Virtual environment already exists"
    fi
    
    # Activate virtual environment
    source venv/bin/activate || source venv/Scripts/activate
    print_success "Virtual environment activated"
}

# Install requirements
install_requirements() {
    print_status "Installing Python packages..."
    
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
        print_success "Requirements installed successfully"
    else
        print_warning "requirements.txt not found. Installing basic packages..."
        pip install flask colorama requests python-whois dnspython cryptography
    fi
}

# Install package
install_package() {
    print_status "Installing CyberSec Terminal package..."
    
    pip install -e .
    print_success "Package installed successfully"
}

# Create desktop shortcuts (Linux/macOS)
create_shortcuts() {
    print_status "Creating application shortcuts..."
    
    # Create bin directory
    mkdir -p ~/.local/bin
    
    # Create cybersec command
    cat > ~/.local/bin/cybersec << 'EOF'
#!/bin/bash
cd "$(dirname "$0")/../../"
source venv/bin/activate 2>/dev/null || source venv/Scripts/activate 2>/dev/null
python -m cybersec_terminal.launcher
EOF
    
    chmod +x ~/.local/bin/cybersec
    
    # Create cybersec-web command
    cat > ~/.local/bin/cybersec-web << 'EOF'
#!/bin/bash
cd "$(dirname "$0")/../../"
source venv/bin/activate 2>/dev/null || source venv/Scripts/activate 2>/dev/null
python -m cybersec_terminal.web
EOF
    
    chmod +x ~/.local/bin/cybersec-web
    
    # Create cybersec-cli command
    cat > ~/.local/bin/cybersec-cli << 'EOF'
#!/bin/bash
cd "$(dirname "$0")/../../"
source venv/bin/activate 2>/dev/null || source venv/Scripts/activate 2>/dev/null
python -m cybersec_terminal.cli
EOF
    
    chmod +x ~/.local/bin/cybersec-cli
    
    print_success "Command shortcuts created in ~/.local/bin/"
}

# Main installation function
main() {
    print_header "🚀 Starting CyberSec Terminal Installation"
    echo
    
    # Check system requirements
    check_python
    check_pip
    
    # Setup environment
    create_venv
    install_requirements
    
    # Install package
    if [ -f "setup.py" ]; then
        install_package
    fi
    
    # Create shortcuts
    create_shortcuts
    
    echo
    print_header "✅ Installation Complete!"
    echo
    print_success "CyberSec Terminal has been successfully installed!"
    echo
    echo -e "${CYAN}🚀 Quick Start:${NC}"
    echo "  cybersec              - Launch terminal selector"
    echo "  cybersec-web          - Start web terminal"
    echo "  cybersec-cli          - Start CLI terminal"
    echo
    echo -e "${CYAN}📚 Documentation:${NC}"
    echo "  README.md             - Main documentation"
    echo "  TERMINAL_GUIDE.md     - Terminal usage guide"
    echo
    echo -e "${CYAN}🌐 Web Terminal:${NC}"
    echo "  Run 'cybersec-web' and open http://127.0.0.1:5000"
    echo
    echo -e "${YELLOW}⚠️  Important:${NC}"
    echo "  - Add ~/.local/bin to your PATH if not already added"
    echo "  - Use only on systems you own or have permission to test"
    echo "  - Follow responsible disclosure practices"
    echo
    print_success "Happy Security Testing! 🛡️"
}

# Run main function
main "$@"
