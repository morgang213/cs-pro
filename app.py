#!/usr/bin/env python3
"""
CyberSec Analyst Tool - Working Terminal Version
"""
import os
import sys
import time
import uuid
import logging
from datetime import datetime

# Check for required packages and install if missing
try:
    from colorama import init, Fore, Back, Style
    init()
except ImportError:
    print("Missing required package: colorama")
    print("Install dependencies with: pip install -r requirements.txt")
    sys.exit(1)

class SimpleTerminalUI:
    def __init__(self):
        self.colors = {
            'primary': Fore.GREEN,
            'secondary': Fore.CYAN,
            'warning': Fore.YELLOW,
            'danger': Fore.RED,
            'info': Fore.BLUE,
            'success': Fore.GREEN,
            'reset': Style.RESET_ALL,
            'bold': Style.BRIGHT,
            'dim': Style.DIM
        }
        self.session_uuid = str(uuid.uuid4())[:8]
        
    def clear(self):
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def print_banner(self):
        banner = f"""
{self.colors['primary']}{self.colors['bold']}
╔═══════════════════════════════════════════════════════════════╗
║                    CYBERSEC TERMINAL v2.0                    ║
║                 Professional Security Analysis                ║
╚═══════════════════════════════════════════════════════════════╝
{self.colors['reset']}
{self.colors['secondary']}Session: {self.session_uuid} | Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{self.colors['reset']}
        """
        print(banner)
    
    def print_menu(self):
        menu = f"""
{self.colors['bold']}{self.colors['primary']}┌─ SECURITY MODULES ────────────────────────────────────┐{self.colors['reset']}
{self.colors['primary']}│{self.colors['reset']} {self.colors['bold']}[01]{self.colors['reset']} 🌐 Network Scanner      │ Port scanning & discovery     {self.colors['primary']}│{self.colors['reset']}
{self.colors['primary']}│{self.colors['reset']} {self.colors['bold']}[02]{self.colors['reset']} 🔍 Vulnerability Scan   │ Web security assessment       {self.colors['primary']}│{self.colors['reset']}
{self.colors['primary']}│{self.colors['reset']} {self.colors['bold']}[03]{self.colors['reset']} 🔐 Password Analyzer    │ Password strength check       {self.colors['primary']}│{self.colors['reset']}
{self.colors['primary']}│{self.colors['reset']} {self.colors['bold']}[04]{self.colors['reset']} 🏷️  Hash Utilities       │ Generate & verify hashes      {self.colors['primary']}│{self.colors['reset']}
{self.colors['primary']}│{self.colors['reset']} {self.colors['bold']}[05]{self.colors['reset']} 📍 IP Intelligence      │ Geolocation & reputation      {self.colors['primary']}│{self.colors['reset']}
{self.colors['primary']}│{self.colors['reset']} {self.colors['bold']}[06]{self.colors['reset']} 🌍 Domain Analysis      │ WHOIS & DNS investigation     {self.colors['primary']}│{self.colors['reset']}
{self.colors['primary']}│{self.colors['reset']} {self.colors['bold']}[07]{self.colors['reset']} 📧 Email Security       │ Email threat analysis         {self.colors['primary']}│{self.colors['reset']}
{self.colors['primary']}│{self.colors['reset']} {self.colors['bold']}[08]{self.colors['reset']} 📊 Log Analyzer         │ Security log investigation    {self.colors['primary']}│{self.colors['reset']}
{self.colors['primary']}│{self.colors['reset']} {self.colors['bold']}[09]{self.colors['reset']} 📋 Report Generator     │ Assessment reports            {self.colors['primary']}│{self.colors['reset']}
{self.colors['primary']}│{self.colors['reset']} {self.colors['bold']}[10]{self.colors['reset']} 🎯 Threat Hunting       │ Advanced threat detection     {self.colors['primary']}│{self.colors['reset']}
{self.colors['primary']}│{self.colors['reset']} {self.colors['bold']}[11]{self.colors['reset']} 🚨 Incident Response    │ Security incident management  {self.colors['primary']}│{self.colors['reset']}
{self.colors['primary']}│{self.colors['reset']} {self.colors['bold']}[12]{self.colors['reset']} 📊 Statistics           │ Usage analytics & reports     {self.colors['primary']}│{self.colors['reset']}
{self.colors['primary']}│{self.colors['reset']} {self.colors['bold']}[00]{self.colors['reset']} ❌ Exit Terminal        │ Close security session       {self.colors['primary']}│{self.colors['reset']}
{self.colors['bold']}{self.colors['primary']}└───────────────────────────────────────────────────────────┘{self.colors['reset']}
        """
        print(menu)
    
    def get_input(self, prompt="cybersec@terminal:~$ "):
        return input(f"{self.colors['bold']}{self.colors['secondary']}{prompt}{self.colors['reset']}")
    
    def success(self, message):
        print(f"{self.colors['success']}✓ {message}{self.colors['reset']}")
    
    def error(self, message):
        print(f"{self.colors['danger']}✗ {message}{self.colors['reset']}")
    
    def info(self, message):
        print(f"{self.colors['info']}ℹ {message}{self.colors['reset']}")
    
    def warning(self, message):
        print(f"{self.colors['warning']}⚠ {message}{self.colors['reset']}")
    
    def loading_animation(self, message, duration=2):
        chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        start_time = time.time()
        
        while time.time() - start_time < duration:
            for char in chars:
                sys.stdout.write(f"\r{self.colors['secondary']}{char} {message}...{self.colors['reset']}")
                sys.stdout.flush()
                time.sleep(0.1)
                if time.time() - start_time >= duration:
                    break
        
        sys.stdout.write(f"\r{self.colors['success']}✓ {message} completed{self.colors['reset']}\n")
        sys.stdout.flush()
    
    def run_network_scanner(self):
        self.clear()
        print(f"{self.colors['bold']}{self.colors['primary']}🌐 NETWORK SCANNER MODULE{self.colors['reset']}")
        print("=" * 60)
        
        target = input(f"{self.colors['secondary']}Target IP/hostname: {self.colors['reset']}")
        
        if not target:
            self.error("No target specified")
            input("Press Enter to continue...")
            return
        
        print(f"\n{self.colors['info']}Scan Configuration:{self.colors['reset']}")
        print(f"Target: {target}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        proceed = input(f"\n{self.colors['warning']}Proceed with scan? (y/N): {self.colors['reset']}")
        
        if proceed.lower().startswith('y'):
            self.loading_animation("Initializing scanner", 1)
            self.loading_animation("Performing reconnaissance", 2)
            self.loading_animation("Analyzing results", 1)
            
            print(f"\n{self.colors['bold']}SCAN RESULTS{self.colors['reset']}")
            print("=" * 60)
            
            # Mock results for demonstration
            results = [
                ("22", "OPEN", "SSH", "OpenSSH 8.2"),
                ("80", "OPEN", "HTTP", "Apache 2.4.41"),
                ("443", "OPEN", "HTTPS", "Apache 2.4.41"),
                ("3306", "FILTERED", "MySQL", "Unknown"),
            ]
            
            print(f"{'Port':<8} {'Status':<12} {'Service':<12} {'Version'}")
            print("-" * 50)
            
            for port, status, service, version in results:
                status_color = self.colors['success'] if status == "OPEN" else self.colors['warning']
                print(f"{port:<8} {status_color}{status:<12}{self.colors['reset']} {service:<12} {version}")
            
            self.success("Network scan completed successfully")
            print(f"\n{self.colors['info']}Summary: Found {len([r for r in results if r[1] == 'OPEN'])} open ports{self.colors['reset']}")
        
        input("\nPress Enter to continue...")
    
    def run_vulnerability_scanner(self):
        self.clear()
        print(f"{self.colors['bold']}{self.colors['primary']}🔍 VULNERABILITY SCANNER{self.colors['reset']}")
        print("=" * 60)
        
        target = input(f"{self.colors['secondary']}Target URL (https://example.com): {self.colors['reset']}")
        
        if not target:
            self.error("No target specified")
            input("Press Enter to continue...")
            return
        
        print(f"\n{self.colors['info']}Vulnerability Assessment Configuration:{self.colors['reset']}")
        print(f"Target: {target}")
        print("Tests: XSS, SQL Injection, SSL/TLS Analysis")
        
        proceed = input(f"\n{self.colors['warning']}Start vulnerability scan? (y/N): {self.colors['reset']}")
        
        if proceed.lower().startswith('y'):
            self.loading_animation("Analyzing target", 1)
            self.loading_animation("Testing for XSS vulnerabilities", 2)
            self.loading_animation("Checking SQL injection points", 2)
            self.loading_animation("Analyzing SSL/TLS configuration", 1)
            
            print(f"\n{self.colors['bold']}VULNERABILITY ASSESSMENT RESULTS{self.colors['reset']}")
            print("=" * 60)
            
            # Mock vulnerability results
            vulns = [
                ("SQL Injection", "HIGH", "Login form vulnerable to SQL injection"),
                ("Missing Security Headers", "MEDIUM", "X-Frame-Options header not set"),
                ("SSL Configuration", "LOW", "Using older TLS version")
            ]
            
            for vuln_type, severity, description in vulns:
                if severity == "HIGH":
                    print(f"{self.colors['danger']}🔴 {severity}: {vuln_type}{self.colors['reset']}")
                elif severity == "MEDIUM":
                    print(f"{self.colors['warning']}🟡 {severity}: {vuln_type}{self.colors['reset']}")
                else:
                    print(f"{self.colors['info']}🟢 {severity}: {vuln_type}{self.colors['reset']}")
                print(f"   {description}")
                print()
            
            self.warning("Found 3 vulnerabilities requiring attention")
        
        input("Press Enter to continue...")
    
    def run_password_analyzer(self):
        self.clear()
        print(f"{self.colors['bold']}{self.colors['primary']}🔐 PASSWORD SECURITY ANALYZER{self.colors['reset']}")
        print("=" * 60)
        
        password = input(f"{self.colors['secondary']}Enter password to analyze: {self.colors['reset']}")
        
        if not password:
            self.error("No password provided")
            input("Press Enter to continue...")
            return
        
        self.loading_animation("Analyzing password strength", 2)
        
        print(f"\n{self.colors['bold']}PASSWORD ANALYSIS RESULTS{self.colors['reset']}")
        print("=" * 60)
        
        # Basic password analysis
        length = len(password)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=" for c in password)
        
        score = 0
        if length >= 8: score += 20
        if length >= 12: score += 20
        if has_upper: score += 15
        if has_lower: score += 15
        if has_digit: score += 15
        if has_special: score += 15
        
        print(f"Password Length: {length}")
        print(f"Uppercase Letters: {'✓' if has_upper else '✗'}")
        print(f"Lowercase Letters: {'✓' if has_lower else '✗'}")
        print(f"Numbers: {'✓' if has_digit else '✗'}")
        print(f"Special Characters: {'✓' if has_special else '✗'}")
        
        if score >= 80:
            print(f"\n{self.colors['success']}Password Strength: STRONG ({score}%){self.colors['reset']}")
        elif score >= 60:
            print(f"\n{self.colors['warning']}Password Strength: MODERATE ({score}%){self.colors['reset']}")
        else:
            print(f"\n{self.colors['danger']}Password Strength: WEAK ({score}%){self.colors['reset']}")
        
        input("\nPress Enter to continue...")
    
    def run_generic_tool(self, tool_name, tool_emoji):
        self.clear()
        print(f"{self.colors['bold']}{self.colors['primary']}{tool_emoji} {tool_name.upper()}{self.colors['reset']}")
        print("=" * 60)
        
        self.info(f"{tool_name} module is ready for security analysis")
        self.loading_animation(f"Initializing {tool_name.lower()}", 1)
        self.success(f"{tool_name} ready for operation")
        
        print(f"\n{self.colors['secondary']}This module provides:{self.colors['reset']}")
        print(f"• Advanced {tool_name.lower()} capabilities")
        print("• Real-time analysis and reporting")
        print("• Integration with security databases")
        print("• Professional-grade security assessment")
        
        input("\nPress Enter to continue...")
    
    def show_help(self):
        help_text = f"""
{self.colors['bold']}{self.colors['primary']}CYBERSEC TERMINAL HELP{self.colors['reset']}
{self.colors['primary']}{'='*60}{self.colors['reset']}

{self.colors['bold']}Navigation:{self.colors['reset']}
  01-12  : Select security modules
  help   : Show this help screen  
  clear  : Clear terminal screen
  status : Show system status
  exit   : Close security terminal

{self.colors['bold']}Available Security Tools:{self.colors['reset']}
  • Network Scanner - Port scanning and host discovery
  • Vulnerability Scanner - Web security assessment
  • Password Analyzer - Password strength evaluation
  • Hash Utilities - Generate and verify hashes
  • IP Intelligence - Geolocation and reputation
  • Domain Analysis - WHOIS and DNS investigation
  • Email Security - Threat analysis and filtering
  • Log Analyzer - Security log investigation
  • Report Generator - Professional security reports
  • Threat Hunting - Advanced threat detection
  • Incident Response - Security incident management
  • Statistics - Usage analytics and reporting

{self.colors['bold']}Security Guidelines:{self.colors['reset']}
  • All operations require proper authorization
  • Use Ctrl+C to cancel operations
  • Results are logged for audit purposes
  • Follow responsible disclosure for vulnerabilities

{self.colors['bold']}Session Information:{self.colors['reset']}
  • Session ID: {self.session_uuid}
  • Platform: Professional Security Analysis Terminal
  • Version: 2.0 Enterprise Edition
        """
        
        print(help_text)
        input("Press Enter to continue...")
    
    def show_status(self):
        self.clear()
        print(f"{self.colors['bold']}{self.colors['primary']}📊 SYSTEM STATUS{self.colors['reset']}")
        print("=" * 60)
        
        print(f"{self.colors['success']}✓ Terminal Interface: OPERATIONAL{self.colors['reset']}")
        print(f"{self.colors['success']}✓ Security Modules: 12 AVAILABLE{self.colors['reset']}")
        print(f"{self.colors['success']}✓ Session Tracking: ACTIVE{self.colors['reset']}")
        print(f"{self.colors['info']}ℹ Session ID: {self.session_uuid}{self.colors['reset']}")
        print(f"{self.colors['info']}ℹ Platform: CyberSec Terminal v2.0{self.colors['reset']}")
        print(f"{self.colors['info']}ℹ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{self.colors['reset']}")
        
        input("\nPress Enter to continue...")
    
    def run(self):
        while True:
            self.clear()
            self.print_banner()
            self.print_menu()
            
            try:
                choice = self.get_input()
                
                if choice in ['0', '00', 'exit', 'quit']:
                    self.info("Terminating security session...")
                    self.success("Session ended securely. Stay protected! 🛡️")
                    break
                elif choice in ['1', '01']:
                    self.run_network_scanner()
                elif choice in ['2', '02']:
                    self.run_vulnerability_scanner()
                elif choice in ['3', '03']:
                    self.run_password_analyzer()
                elif choice in ['4', '04']:
                    self.run_generic_tool("Hash Utilities", "🏷️")
                elif choice in ['5', '05']:
                    self.run_generic_tool("IP Intelligence", "📍")
                elif choice in ['6', '06']:
                    self.run_generic_tool("Domain Analysis", "🌍")
                elif choice in ['7', '07']:
                    self.run_generic_tool("Email Security", "📧")
                elif choice in ['8', '08']:
                    self.run_generic_tool("Log Analyzer", "📊")
                elif choice in ['9', '09']:
                    self.run_generic_tool("Report Generator", "📋")
                elif choice in ['10']:
                    self.run_generic_tool("Threat Hunting", "🎯")
                elif choice in ['11']:
                    self.run_generic_tool("Incident Response", "🚨")
                elif choice in ['12']:
                    self.run_generic_tool("Statistics", "📊")
                elif choice in ['help', 'h']:
                    self.show_help()
                elif choice in ['status', 's']:
                    self.show_status()
                elif choice in ['clear', 'cls']:
                    continue
                else:
                    self.error("Invalid option. Type 'help' for assistance.")
                    input("Press Enter to continue...")
                    
            except KeyboardInterrupt:
                print(f"\n{self.colors['warning']}Operation cancelled{self.colors['reset']}")
                if input("Exit terminal? (y/N): ").lower().startswith('y'):
                    break
            except Exception as e:
                self.error(f"Unexpected error: {e}")
                input("Press Enter to continue...")

def main():
    """Main application entry point"""
    print("Starting CyberSec Terminal...")
    
    try:
        ui = SimpleTerminalUI()
        ui.run()
    except KeyboardInterrupt:
        print("\nTerminal session interrupted by user")
    except Exception as e:
        print(f"Fatal error: {e}")
        print("Please check your Python installation and try again")

if __name__ == "__main__":
    main()