#!/usr/bin/env python3
"""
CyberSec Terminal Setup Script
Professional Cybersecurity Analysis Platform
"""

from setuptools import setup, find_packages
import os

# Read long description from README
def read_long_description():
    try:
        with open('README.md', 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return "Professional Cybersecurity Analysis Platform with Web and CLI interfaces"

setup(
    name="cybersec-terminal",
    version="2.0.0",
    author="CyberSec Tools Team",
    author_email="security@cybersec-tools.com",
    description="Professional Cybersecurity Analysis Platform",
    long_description=read_long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/morgang213/cs-pro",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Web Environment",
        "Environment :: Console",
    ],
    python_requires=">=3.7",
    install_requires=[
        "flask>=2.3.0",
        "colorama>=0.4.6",
        "requests>=2.25.0",
        "python-whois>=0.8.0",
        "dnspython>=2.0.0",
        "cryptography>=3.4.0"
    ],
    entry_points={
        "console_scripts": [
            "cybersec-terminal=app:main",
            "cybersec-web=terminal_web:main",
            "cybersec=launch_terminal:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords=["cybersecurity", "security-tools", "network-scanner", "vulnerability-assessment", "terminal"],
    project_urls={
        "Bug Reports": "https://github.com/morgang213/cs-pro/issues",
        "Source": "https://github.com/morgang213/cs-pro",
        "Documentation": "https://github.com/morgang213/cs-pro/blob/main/README.md",
    },
)
