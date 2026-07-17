#!/usr/bin/env python3
"""XPing — Setup Script for pip installation."""

import re
from setuptools import setup, find_packages


def read_version():
    """Read version from xping/__init__.py without importing the package."""
    with open("xping/__init__.py", encoding="utf-8") as f:
        match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', f.read(), re.M)
    if not match:
        raise RuntimeError("Cannot find __version__ in xping/__init__.py")
    return match.group(1)


setup(
    name="xping",
    version=read_version(),
    description="All-in-One Linux Security & Systems Analysis Toolkit",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Giridharan K",
    author_email="",
    url="https://github.com/giridharan-dev/xping",
    project_urls={
        "Bug Tracker": "https://github.com/giridharan-dev/xping/issues",
        "Documentation": "https://github.com/giridharan-dev/xping#readme",
        "Source Code": "https://github.com/giridharan-dev/xping",
    },
    license="MIT",
    python_requires=">=3.8",
    packages=find_packages(),
    package_data={"xping": ["py.typed"]},
    entry_points={
        "console_scripts": [
            "xping=xping.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "Typing :: Typed",
    ],
    keywords="security audit linux hardening reconnaissance pentest",
)
