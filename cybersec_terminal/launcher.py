#!/usr/bin/env python3
"""
CyberSec Terminal Launcher
Unified launcher for both CLI and Web Terminal interfaces
"""

import sys
import os

def print_banner():
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                    CYBERSEC TERMINAL LAUNCHER                 ║
║                 Professional Security Analysis                ║
╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def main():
    print_banner()
    
    print("Select Terminal Interface:")
    print("1. 🌐 Web Terminal (CSS-styled browser interface)")
    print("2. 💻 CLI Terminal (command-line interface)")
    print("3. ❌ Exit")
    
    while True:
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == '1':
            print("\n🚀 Starting Web Terminal...")
            print("📱 Opening in your browser at http://127.0.0.1:5000")
            print("🔒 Press Ctrl+C to stop the server\n")
            
            try:
                # Import and run the web terminal module
                from cybersec_terminal.web import main as web_main
                web_main()
            except KeyboardInterrupt:
                print("\n✓ Web terminal stopped")
            break
            
        elif choice == '2':
            print("\n🚀 Starting CLI Terminal...\n")
            
            try:
                # Import and run the CLI terminal module
                from cybersec_terminal.cli import main as cli_main
                cli_main()
            except KeyboardInterrupt:
                print("\n✓ CLI terminal stopped")
            break
            
        elif choice == '3':
            print("👋 Goodbye!")
            break
            
        else:
            print("❌ Invalid choice. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()
