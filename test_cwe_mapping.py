#!/usr/bin/env python3
"""Test CWE to MITRE/NIST mapping"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from tools.nvd_client import fetch_cve_by_id
from tools.cve_parser import parse_cve_metadata
from tools.cwe_mapper import get_cwe_analysis

print("=" * 80)
print("CWE to MITRE/NIST Mapping Test")
print("=" * 80)

test_cves = ['CVE-2021-44228', 'CVE-2021-41773']

for cve_id in test_cves:
    result = fetch_cve_by_id(cve_id)
    cves = result.get('context', [])

    if cves:
        cve = cves[0]
        metadata = parse_cve_metadata(cve)

        print(f"\n{cve_id}:")
        print(f"  Description: {cve.get('description', '')[:60]}...")

        cwe_ids = metadata.get('cwe_ids', [])
        print(f"  CWE IDs: {cwe_ids}")

        # Get CWE analysis
        analysis = get_cwe_analysis(cve)

        print(f"\n  MITRE Techniques ({analysis['total_techniques']}):")
        for tech in analysis['mitre_techniques'][:3]:
            print(f"    - {tech['id']}: {tech['name']}")
            if tech.get('tactics'):
                print(f"      Tactics: {', '.join(tech['tactics'])}")

        print(f"\n  NIST Controls ({analysis['total_controls']}):")
        for ctrl in analysis['nist_controls'][:3]:
            print(f"    - {ctrl['id']}: {ctrl['name']}")
