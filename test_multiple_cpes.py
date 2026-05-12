#!/usr/bin/env python3
"""Check all CPEs for CVE-2021-44228"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from tools.nvd_client import fetch_cve_by_id
from tools.cve_parser import CPEParser

result = fetch_cve_by_id('CVE-2021-44228')
cves = result.get('context', [])

if cves:
    cve = cves[0]
    configs = cve.get('configurations', [])

    print("All CPEs for CVE-2021-44228:")
    print("=" * 80)

    cpes = CPEParser.extract_cpe_from_configurations(configs)
    print(f"Total CPEs: {len(cpes)}\n")

    for i, cpe in enumerate(cpes[:10], 1):
        parsed = CPEParser.parse_cpe_uri(cpe)
        print(f"{i}. {cpe}")
        print(f"   Vendor: {parsed.get('vendor')}, Product: {parsed.get('product')}")
