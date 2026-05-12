#!/usr/bin/env python3
"""Debug CWE extraction from NVD"""
import sys
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from tools.nvd_client import fetch_cve_by_id

print("=" * 80)
print("CWE Structure in NVD API Response")
print("=" * 80)

# Test multiple CVEs to see CWE structure
test_cves = ['CVE-2026-8259', 'CVE-2021-44228', 'CVE-2021-41773']

for cve_id in test_cves:
    result = fetch_cve_by_id(cve_id)
    cves = result.get('context', [])

    if cves:
        cve = cves[0]
        print(f"\n{cve_id}:")
        print(f"  Description: {cve.get('description', '')[:60]}...")

        # Check for weaknesses (CWE)
        weaknesses = cve.get('weaknesses', [])
        print(f"  Weaknesses (CWE): {len(weaknesses)} items")

        if weaknesses:
            for weakness in weaknesses[:2]:
                print(f"\n    Weakness keys: {list(weakness.keys())}")
                print(f"    {json.dumps(weakness, indent=6)}")
