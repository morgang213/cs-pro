#!/usr/bin/env python3
"""
CyberSec Analyst Tool - Startup Script
Quick launcher for the cybersecurity analysis platform
"""

import subprocess
import sys
import os

def check_dependencies():
    """Check if required packages are installed"""
    try:
        import streamlit
        import pandas
        import plotly
        print("✅ Core dependencies found")
        return True
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        return False

def start_application():
    """Start the Streamlit application"""
    if not check_dependencies():
        print("💡 Install dependencies with: pip install streamlit pandas plotly")
        return False
    
    print("🚀 Starting CyberSec Analyst Platform...")
    print("🌐 Web interface will open automatically")
    print("📍 Access at: http://localhost:5500")
    print("⏹️  Press Ctrl+C to stop")
    
    try:
        # Start Streamlit app
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", "app.py",
            "--server.headless", "false",
            "--server.port", "5500",
            "--server.address", "localhost"
        ])
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
