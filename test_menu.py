#!/usr/bin/env python
"""Test menu display."""
import sys, os

# Fix Unicode
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except:
        pass

sys.path.insert(0, os.path.dirname(__file__))
from main import BANNER, MENU

print(BANNER)
print(MENU)
print("\n[Banner and Menu display test - No encoding errors!]")
