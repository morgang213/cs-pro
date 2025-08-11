#!/bin/bash

# CyberSec Terminal - Test Installation Script
# Tests the packaged installation to ensure everything works

set -e

echo "🧪 CyberSec Terminal - Installation Test"
echo "========================================"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

print_status() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

# Test Python availability
test_python() {
    print_status "Testing Python installation..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version)
        print_success "Python found: $PYTHON_VERSION"
        return 0
    else
        print_error "Python 3 not found"
        return 1
    fi
}

# Test package installation
test_package_install() {
    print_status "Testing package installation..."
    
    # Create temporary directory
    TEST_DIR="/tmp/cybersec-test-$$"
    mkdir -p "$TEST_DIR"
    cd "$TEST_DIR"
    
    # Copy installation files
    cp -r "/Users/morgangamble/Documents/Coding projects/cs-pro"/* .
    
    # Run installation
    if ./install.sh &> install.log; then
        print_success "Installation completed successfully"
        return 0
    else
        print_error "Installation failed. Check install.log for details"
        cat install.log
        return 1
    fi
}

# Test web terminal
test_web_terminal() {
    print_status "Testing web terminal startup..."
    
    # Start web terminal in background
    timeout 10s python3 terminal_web.py &> web.log &
    WEB_PID=$!
    
    # Wait a moment for startup
    sleep 3
    
    # Test if port 5000 is listening
    if netstat -ln 2>/dev/null | grep -q ":5000 "; then
        print_success "Web terminal started successfully on port 5000"
        kill $WEB_PID 2>/dev/null || true
        return 0
    else
        print_error "Web terminal failed to start"
        cat web.log
        kill $WEB_PID 2>/dev/null || true
        return 1
    fi
}

# Test CLI terminal
test_cli_terminal() {
    print_status "Testing CLI terminal..."
    
    # Test if CLI terminal can be imported
    if python3 -c "import sys; sys.path.append('.'); import app; print('CLI terminal import successful')" &> cli.log; then
        print_success "CLI terminal loads successfully"
        return 0
    else
        print_error "CLI terminal failed to load"
        cat cli.log
        return 1
    fi
}

# Test launcher
test_launcher() {
    print_status "Testing launcher script..."
    
    if python3 -c "import sys; sys.path.append('.'); import launch_terminal; print('Launcher import successful')" &> launcher.log; then
        print_success "Launcher loads successfully"
        return 0
    else
        print_error "Launcher failed to load"
        cat launcher.log
        return 1
    fi
}

# Test dependencies
test_dependencies() {
    print_status "Testing dependencies..."
    
    local deps=("flask" "colorama" "requests" "whois" "dns.resolver" "cryptography")
    local failed=0
    
    for dep in "${deps[@]}"; do
        if python3 -c "import $dep" 2>/dev/null; then
            print_success "Dependency $dep: OK"
        else
            print_error "Dependency $dep: MISSING"
            ((failed++))
        fi
    done
    
    if [ $failed -eq 0 ]; then
        print_success "All dependencies are available"
        return 0
    else
        print_error "$failed dependencies are missing"
        return 1
    fi
}

# Main test function
main() {
    local total_tests=0
    local passed_tests=0
    
    echo "Starting comprehensive installation test..."
    echo
    
    # Run tests
    tests=(
        "test_python"
        "test_dependencies"
        "test_cli_terminal"
        "test_launcher"
        "test_web_terminal"
    )
    
    for test in "${tests[@]}"; do
        ((total_tests++))
        if $test; then
            ((passed_tests++))
        fi
        echo
    done
    
    # Summary
    echo "=================================="
    echo "Test Results: $passed_tests/$total_tests passed"
    echo
    
    if [ $passed_tests -eq $total_tests ]; then
        print_success "🎉 All tests passed! Installation is working correctly."
        echo
        echo "🚀 Ready to use:"
        echo "  python3 terminal_web.py  # Start web terminal"
        echo "  python3 app.py          # Start CLI terminal"
        echo "  python3 launch_terminal.py  # Choose interface"
        return 0
    else
        print_error "❌ Some tests failed. Please check the installation."
        return 1
    fi
}

# Cleanup function
cleanup() {
    if [ -n "$TEST_DIR" ] && [ -d "$TEST_DIR" ]; then
        rm -rf "$TEST_DIR"
    fi
}

# Set trap for cleanup
trap cleanup EXIT

# Run main test
main "$@"
