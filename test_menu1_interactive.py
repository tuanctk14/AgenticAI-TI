#!/usr/bin/env python3
"""Interactive Menu 1 test - CVE Scan & Device Impact"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from tools.nvd_client import fetch_cve_by_id
from tools.cve_parser import parse_cve_metadata
from tools.cmdb import match_cves_with_cmdb
import json

print("=" * 80)
print("MENU 1: CVE SCAN & DEVICE IMPACT - INTERACTIVE TEST")
print("=" * 80)

# Test CVEs
test_cases = [
    "CVE-2021-44228",  # Log4j
    "CVE-2021-41773",  # Apache HTTP
    "CVE-2023-20198",  # Cisco IOS
]

for cve_id in test_cases:
    print(f"\n{'='*80}")
    print(f"CVE: {cve_id}")
    print("=" * 80)

    # Fetch from NVD
    result = fetch_cve_by_id(cve_id)
    cves = result.get('context', [])

    if not cves:
        print("CVE not found in NVD")
        continue

    cve = cves[0]

    # Display CVE info
    print(f"\nDescription: {cve.get('description', '')[:100]}...")
    print(f"CVSS Score: {cve.get('cvss_score', 'N/A')}")
    print(f"Severity: {cve.get('severity', 'N/A')}")

    # Parse metadata (CPE-first)
    metadata = parse_cve_metadata(cve)
    print(f"\nVulnerable Product:")
    print(f"  Vendor: {metadata.get('vendor')}")
    print(f"  Product: {metadata.get('product')}")
    print(f"  Normalized ID: {metadata.get('normalized_software_id')}")
    print(f"  CPE Source: {metadata.get('source')}")

    # CWE & MITRE/NIST
    cwe_ids = metadata.get('cwe_ids', [])
    print(f"\nWeakness Analysis:")
    print(f"  CWE IDs: {cwe_ids}")

    # Match with CMDB
    print(f"\nDevice Matching:")
    result = match_cves_with_cmdb([cve])
    matches = result.get('context', [])

    if matches:
        print(f"  Affected Devices: {len(matches)}")
        for match in matches:
            print(f"\n    Device: {match.get('device_id')} ({match.get('hostname')})")
            print(f"      IP: {match.get('ip')}")
            print(f"      Software: {match.get('affected_software')} {match.get('device_version', '')}")
            print(f"      OS: {match.get('os')}")
            print(f"      Risk Level: {match.get('risk_level')}")
            print(f"      Match Type: {match.get('match_type')}")
            print(f"      Criticality: {match.get('criticality')}")

            # MITRE
            techniques = match.get('mitre_techniques', [])
            if techniques:
                print(f"      MITRE Techniques ({len(techniques)}):")
                for tech in techniques:
                    print(f"        - {tech.get('id')}: {tech.get('name')}")

            # NIST
            controls = match.get('nist_controls', [])
            if controls:
                print(f"      NIST Controls ({len(controls)}):")
                for ctrl in controls:
                    print(f"        - {ctrl.get('id')}: {ctrl.get('name')}")
    else:
        print(f"  No affected devices in CMDB")

print("\n" + "=" * 80)
print("MENU 1 TEST COMPLETED")
print("=" * 80)
