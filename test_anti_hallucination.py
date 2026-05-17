#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Test anti-hallucination fix for Menu 1 relationship display
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from main import run_query

# Test CVE-2026-8719 (should show total_relationships = 0)
print("\n" + "="*70)
print("TEST: CVE-2026-8719 (total_relationships = 0)")
print("="*70)

query = "Quét CVE-2026-8719 từ NVD, so khớp với thiết bị nội bộ"
result = run_query(query, verbose=True)

# Test CVE-2021-44228 (should show relationships)
print("\n" + "="*70)
print("TEST: CVE-2021-44228 (should have relationships)")
print("="*70)

query = "Quét CVE-2021-44228 từ NVD, so khớp với thiết bị nội bộ"
result = run_query(query, verbose=True)

print("\n[TEST COMPLETE]")
