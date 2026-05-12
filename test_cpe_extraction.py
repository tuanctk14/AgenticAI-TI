#!/usr/bin/env python3
"""Test CPE extraction from NVD API"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from tools.nvd_client import fetch_cve_by_id
from tools.cve_parser import parse_cve_metadata, CPEParser

print("=" * 80)
print("CVE-2026-8259 CPE Extraction Test")
print("=" * 80)

# Fetch from NVD
result = fetch_cve_by_id('CVE-2026-8259')
cves = result.get('context', [])

if cves:
    cve = cves[0]
    print(f"\nCVE: {cve.get('id')}")
    print(f"Configurations count: {len(cve.get('configurations', []))}")

    # Extract CPE
    configs = cve.get('configurations', [])
    if configs:
        cpes = CPEParser.extract_cpe_from_configurations(configs)
        print(f"\nExtracted CPEs: {len(cpes)}")
        for cpe in cpes[:3]:
            print(f"  {cpe}")
            parsed = CPEParser.parse_cpe_uri(cpe)
            print(f"    -> vendor={parsed.get('vendor')}, product={parsed.get('product')}")

    # Parse with CPE-first architecture
    metadata = parse_cve_metadata(cve)
    print(f"\nparse_cve_metadata (CPE-first):")
    print(f"  Vendor: {metadata.get('vendor')}")
    print(f"  Product: {metadata.get('product')}")
    print(f"  Normalized ID: {metadata.get('normalized_software_id')}")
    print(f"  Source: {metadata.get('source')}")
    print(f"\nResult: {metadata.get('normalized_software_id') or 'NONE'} (from {metadata.get('source')})")
else:
    print("CVE not found")
