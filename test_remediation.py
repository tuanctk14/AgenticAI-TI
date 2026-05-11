#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Test remediation display from agent_analyst"""

import sys
sys.path.insert(0, '.')

from main import run_query

# Test query with CVE + device matching
query = "Quet CVE-2021-44228 va tim thiet bi bi anh huong trong CMDB"

print("Testing remediation display from agent_analyst...")
print("=" * 70)

result = run_query(query, verbose=True, chat_mode=False)

print("\n[OK] Test completed")
