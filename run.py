#!/usr/bin/env python3
"""
XPing — Direct Execution Entry Point

Usage:
    python3 run.py scan --all
    python3 run.py scan --modules sysrecon,netaudit --format json -o report.json
    python3 run.py list
    python3 run.py --help
"""

import sys
import os

# Ensure the project root is on the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from xping.cli import main

if __name__ == "__main__":
    sys.exit(main())
