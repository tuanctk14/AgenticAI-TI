#!/usr/bin/env python3
"""Test CWE extraction from NVD API"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from tools.nvd_client import fetch_cve_by_id
from tools.cve_parser import parse_cve_metadata

print("=" * 80)
print("CWE Extraction Test")
print("=" * 80)

test_cves = ['CVE-2021-44228', 'CVE-2021-41773', 'CVE-2026-8259']

for cve_id in test_cves:
    result = fetch_cve_by_id(cve_id)
    cves = result.get('context', [])

    if cves:
        cve = cves[0]
        print(f"\n{cve_id}:")
        print(f"  Description: {cve.get('description', '')[:60]}...")

        # Direct CWE from CVE data
        cwe_ids = cve.get('cwe_ids', [])
        print(f"  CWE (from NVD): {cwe_ids if cwe_ids else 'None'}")

        # Via parse_cve_metadata
        metadata = parse_cve_metadata(cve)
        cwe_from_metadata = metadata.get('cwe_ids', [])
        print(f"  CWE (from metadata): {cwe_from_metadata if cwe_from_metadata else 'None'}")
