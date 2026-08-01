#!/usr/bin/env python3
"""CyberSec startup launcher for the web terminal interface."""

import subprocess
import sys
import os

def check_dependencies():
    """Check if required packages are installed"""
    try:
        import flask
        import requests
        print("✅ Core dependencies found")
        return True
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        return False

def start_application():
    """Start the CyberSec web terminal application"""
    if not check_dependencies():
        print("💡 Install dependencies with: pip install -r requirements.txt")
        return False
    
    print("🚀 Starting CyberSec Analyst Platform...")
    print("🌐 Web terminal will open automatically")
    print("📍 Access at: http://127.0.0.1:5000")
    print("⏹️  Press Ctrl+C to stop")
    
    try:
        subprocess.run([sys.executable, "terminal_web.py"])
    except KeyboardInterrupt:
        print("\n🛑 Application stopped by user")
    except Exception as e:
        print(f"❌ Error starting application: {e}")

if __name__ == "__main__":
    print("=" * 60)
    print("🔒 CyberSec Analyst Platform")
    print("   Enterprise Security Operations Center")
    print("=" * 60)
    
    start_application()
