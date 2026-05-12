#!/usr/bin/env python3
"""Test complete flow: NVD -> CPE -> CWE -> MITRE/NIST -> CMDB matching"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from tools.nvd_client import fetch_cve_by_id
from tools.cve_parser import parse_cve_metadata
from tools.cmdb import match_cves_with_cmdb

print("=" * 80)
print("Complete Flow: NVD -> CPE -> CWE -> MITRE/NIST -> Device Matching")
print("=" * 80)

# Test CVE-2021-44228 (Log4j)
result = fetch_cve_by_id('CVE-2021-44228')
cves = result.get('context', [])

if cves:
    cve = cves[0]
    print(f"\n{cve.get('id')}:")
    print(f"  Description: {cve.get('description', '')[:70]}...")

    # Parse metadata (CPE-first)
    metadata = parse_cve_metadata(cve)
    print(f"\n  1. CPE Extraction:")
    print(f"     Vendor: {metadata.get('vendor')}")
    print(f"     Product: {metadata.get('product')}")
    print(f"     Normalized ID: {metadata.get('normalized_software_id')}")
    print(f"     Source: {metadata.get('source')}")

    # CWE
    print(f"\n  2. CWE Extraction:")
    cwe_ids = metadata.get('cwe_ids', [])
    print(f"     CWE IDs: {cwe_ids}")

    # Match with CMDB
    print(f"\n  3. Device Matching:")
    result = match_cves_with_cmdb([cve])
    matches = result.get('context', [])

    print(f"     Matched devices: {len(matches)}")
    for match in matches:
        print(f"\n     Device: {match.get('device_id')} ({match.get('hostname')})")
        print(f"       Software: {match.get('affected_software')} {match.get('device_version')}")
        print(f"       Risk: {match.get('risk_level')}")

        # CWE -> MITRE
        techniques = match.get('mitre_techniques', [])
        if techniques:
            print(f"       MITRE Techniques ({len(techniques)}):")
            for tech in techniques[:2]:
                print(f"         - {tech.get('id')}: {tech.get('name')}")

        # CWE -> NIST
        controls = match.get('nist_controls', [])
        if controls:
            print(f"       NIST Controls ({len(controls)}):")
            for ctrl in controls[:2]:
                print(f"         - {ctrl.get('id')}: {ctrl.get('name')}")
