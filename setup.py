#!/usr/bin/env python3
"""
APIVuln - API Vulnerability Scanner
Setup script for package installation.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text() if readme_path.exists() else ""

setup(
    name="apivuln",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="API Vulnerability Scanner for Security Professionals",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/apivuln",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
    ],
    python_requires=">=3.9",
    install_requires=[
        "aiohttp>=3.8.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.20.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "apivuln=apivuln.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "apivuln": [
            "payloads/*.txt",
            "payloads/*.json",
            "templates/*.html",
        ],
    },
    keywords=[
        "api",
        "security",
        "vulnerability",
        "scanner",
        "pentesting",
        "bug-bounty",
        "OWASP",
        "BOLA",
        "IDOR",
        "injection",
    ],
    project_urls={
        "Bug Reports": "https://github.com/yourusername/apivuln/issues",
        "Source": "https://github.com/yourusername/apivuln",
        "Documentation": "https://github.com/yourusername/apivuln#readme",
    },
)
