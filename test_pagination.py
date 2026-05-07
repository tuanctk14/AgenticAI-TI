#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Test NVD pagination and OpenCTI new fields"""
import sys
import os

# Fix encoding for Windows
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from tools.nvd_client import fetch_nvd_cves
from tools.opencti_client import fetch_opencti_indicators
from datetime import datetime, timedelta, timezone

print("=" * 70)
print("TEST: NVD Full Pagination + OpenCTI New Fields")
print("=" * 70)

# Test 1: NVD pagination for 7 days
print("\nTEST 1: NVD Pagination (7 days)")
print("-" * 70)
end_dt = datetime.now(timezone.utc)
start_dt = end_dt - timedelta(days=7)
start_date = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
end_date = end_dt.strftime("%Y-%m-%dT%H:%M:%S.000")

result = fetch_nvd_cves(keyword="", severity="HIGH", start_date=start_date, end_date=end_date)
cves = result.get("context", [])
print(f"\nGot {len(cves)} CVEs")
print(f"Total results available: {result.get('total', 0)}")
if cves:
    print(f"\nFirst 3 CVEs:")
    for i, cve in enumerate(cves[:3], 1):
        print(f"{i}. {cve['id']} - CVSS: {cve['cvss_score']}, Severity: {cve['severity']}")

# Test 2: OpenCTI with new fields
print("\n\nTEST 2: OpenCTI with New Fields (malware_types, x_mitre_id)")
print("-" * 70)
result = fetch_opencti_indicators(search_term="")
indicators = result.get("context", [])
print(f"\nGot {len(indicators)} indicators")

# Count by entity type
entity_counts = {}
for ind in indicators:
    et = ind.get("entity_type", "Unknown")
    entity_counts[et] = entity_counts.get(et, 0) + 1

print(f"\nBreakdown by entity type:")
for et, count in entity_counts.items():
    print(f"- {et}: {count}")

# Show samples
print(f"\nSample Malwares (with malware_types field):")
malwares = [i for i in indicators if i.get("entity_type") == "Malware"]
for i, mw in enumerate(malwares[:2], 1):
    print(f"{i}. {mw['name']}")
    print(f"   malware_types: {mw.get('malware_types', 'N/A')}")
    print(f"   aliases: {mw.get('aliases', [])}")

print(f"\nSample Attack Patterns (with technique_id):")
patterns = [i for i in indicators if i.get("entity_type") == "Attack Pattern"]
for i, pat in enumerate(patterns[:2], 1):
    print(f"{i}. {pat['name']}")
    print(f"   technique_id: {pat.get('technique_id', 'N/A')}")

print("\n" + "=" * 70)
print("Test completed!")
print("=" * 70)
