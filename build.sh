#!/bin/bash

# CyberSec Terminal - Build and Distribution Script
# Creates distributable packages for the cybersecurity platform

set -e

echo "🛡️  CyberSec Terminal - Build Script"
echo "====================================="

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

print_status() {
    echo -e "${BLUE}[BUILD]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the right directory
if [ ! -f "setup.py" ]; then
    print_error "setup.py not found. Please run from project root directory."
    exit 1
fi

print_status "Checking build requirements..."

# Check Python
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is required for building"
    exit 1
fi

# Install build dependencies
print_status "Installing build dependencies..."
pip install --upgrade pip setuptools wheel build twine

# Clean previous builds
print_status "Cleaning previous builds..."
rm -rf build/
rm -rf dist/
rm -rf *.egg-info/
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -name "*.pyc" -delete 2>/dev/null || true

print_success "Cleanup completed"

# Build source distribution
print_status "Building source distribution..."
python3 setup.py sdist

# Build wheel distribution
print_status "Building wheel distribution..."
python3 setup.py bdist_wheel

print_success "Package build completed"

# Create release archive
print_status "Creating release archive..."
VERSION=$(python3 setup.py --version)
RELEASE_NAME="cybersec-terminal-v${VERSION}"
RELEASE_DIR="dist/${RELEASE_NAME}"

# Create release directory structure
mkdir -p "${RELEASE_DIR}"

# Copy essential files
cp -r cybersec_terminal "${RELEASE_DIR}/"
cp -r templates "${RELEASE_DIR}/" 2>/dev/null || true
cp README.md "${RELEASE_DIR}/"
cp LICENSE "${RELEASE_DIR}/"
cp CHANGELOG.md "${RELEASE_DIR}/"
cp CONTRIBUTING.md "${RELEASE_DIR}/"
cp TERMINAL_GUIDE.md "${RELEASE_DIR}/"
cp requirements.txt "${RELEASE_DIR}/"
cp setup.py "${RELEASE_DIR}/"
cp MANIFEST.in "${RELEASE_DIR}/"
cp install.sh "${RELEASE_DIR}/"
cp install.bat "${RELEASE_DIR}/"
cp *.py "${RELEASE_DIR}/" 2>/dev/null || true

# Make install scripts executable
chmod +x "${RELEASE_DIR}/install.sh"

# Create release archive
cd dist/
tar -czf "${RELEASE_NAME}.tar.gz" "${RELEASE_NAME}/"
zip -r "${RELEASE_NAME}.zip" "${RELEASE_NAME}/" > /dev/null

print_success "Release archives created:"
print_success "  - ${RELEASE_NAME}.tar.gz (Linux/macOS)"
print_success "  - ${RELEASE_NAME}.zip (Windows)"

# Create installation instructions
cat > "${RELEASE_DIR}/INSTALL.md" << 'EOF'
# CyberSec Terminal - Installation Instructions

## Quick Install

### Linux/macOS:
```bash
# Extract the archive
tar -xzf cybersec-terminal-v*.tar.gz
cd cybersec-terminal-v*

# Run installation script
./install.sh
```

### Windows:
```cmd
# Extract the ZIP file
# Navigate to the extracted folder
# Double-click install.bat
```

## Manual Install

### 1. Install Python 3.7+
Download from: https://www.python.org/downloads/

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the Application
```bash
# Web Terminal (recommended)
python terminal_web.py

# CLI Terminal
python app.py

# Launcher (choose interface)
python launch_terminal.py
```

## Usage

### Web Terminal
1. Run `python terminal_web.py`
2. Open http://127.0.0.1:5000 in your browser
3. Type `help` for available commands

### Available Commands
- `menu` - Show security tools
- `netscan <target>` - Network scanning
- `vulnscan <url>` - Vulnerability assessment
- `passcheck <password>` - Password analysis
- `hash <algorithm> <text>` - Hash generation
- `help` - Show all commands

## Security Notice
⚠️ Use only on systems you own or have permission to test.
This tool is for educational and authorized security testing only.
EOF

print_success "Installation guide created"

# Generate checksums
print_status "Generating checksums..."
cd "${RELEASE_DIR}/../"
shasum -a 256 "${RELEASE_NAME}.tar.gz" > "${RELEASE_NAME}.tar.gz.sha256"
shasum -a 256 "${RELEASE_NAME}.zip" > "${RELEASE_NAME}.zip.sha256"

print_success "Checksums generated"

# Display build summary
echo
echo "🎉 Build Summary"
echo "================"
echo "Version: ${VERSION}"
echo "Release: ${RELEASE_NAME}"
echo
echo "📦 Distributions Created:"
echo "  - dist/${RELEASE_NAME}.tar.gz"
echo "  - dist/${RELEASE_NAME}.zip"
echo "  - dist/cybersec_terminal-${VERSION}-py3-none-any.whl"
echo "  - dist/cybersec-terminal-${VERSION}.tar.gz"
echo
echo "🔐 Checksums:"
echo "  - ${RELEASE_NAME}.tar.gz.sha256"
echo "  - ${RELEASE_NAME}.zip.sha256"
echo
echo "📁 Release Directory:"
echo "  - dist/${RELEASE_NAME}/"
echo
print_success "Build completed successfully! 🚀"
echo
echo "Next steps:"
echo "1. Test the release packages"
echo "2. Update GitHub releases"
echo "3. Share with the cybersecurity community"
echo
echo "Happy Security Testing! 🛡️"
