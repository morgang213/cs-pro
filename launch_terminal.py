#!/usr/bin/env python3
"""
CyberSec Terminal Launcher
Unified launcher for both CLI and Web Terminal interfaces
"""

import sys
import os
import subprocess


def get_project_dir():
    """Get the project root directory based on this script's location."""
    return os.path.dirname(os.path.abspath(__file__))


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

    project_dir = get_project_dir()

    while True:
        choice = input("\nEnter your choice (1-3): ").strip()

        if choice == '1':
            print("\n🚀 Starting Web Terminal...")
            print("📱 Opening in your browser at http://127.0.0.1:5000")
            print("🔒 Press Ctrl+C to stop the server\n")

            try:
                subprocess.run([
                    sys.executable,
                    os.path.join(project_dir, "terminal_web.py")
                ], cwd=project_dir)
            except KeyboardInterrupt:
                print("\n✓ Web terminal stopped")
            break

        elif choice == '2':
            print("\n🚀 Starting CLI Terminal...\n")

            try:
                subprocess.run([
                    sys.executable,
                    os.path.join(project_dir, "app.py")
                ], cwd=project_dir)
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
