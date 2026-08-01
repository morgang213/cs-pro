#!/bin/bash

# CyberSec Terminal - Easy Installation Script
# Professional Cybersecurity Analysis Platform

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
INSTALL_DIR="$SCRIPT_DIR"

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
        pip install flask colorama requests python-whois dnspython cryptography validators
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

    create_launcher_script() {
        local output_path="$1"
        local module_name="$2"

        cat > "$output_path" <<EOF
#!/bin/bash
PROJECT_DIR="$INSTALL_DIR"
VENV_PYTHON="\$PROJECT_DIR/venv/bin/python"

cd "\$PROJECT_DIR" || exit 1

if [ -x "\$VENV_PYTHON" ]; then
    exec "\$VENV_PYTHON" -m $module_name "\$@"
fi

exec /usr/bin/env python3 -m $module_name "\$@"
EOF

        chmod +x "$output_path"
    }

    create_launcher_script ~/.local/bin/cybersec cybersec_terminal.launcher
    create_launcher_script ~/.local/bin/cybersec-web cybersec_terminal.web
    create_launcher_script ~/.local/bin/cybersec-terminal cybersec_terminal.cli

    # Backward-compatible alias for older docs/scripts.
    ln -sf ~/.local/bin/cybersec-terminal ~/.local/bin/cybersec-cli
    
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
    echo "  cybersec-terminal     - Start CLI terminal"
    echo "  cybersec-cli          - Legacy CLI alias"
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
