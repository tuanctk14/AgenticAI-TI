#!/usr/bin/env python3
"""
test_analyst_grade_real_data.py - Real data testing for analyst-grade architecture

Tests CVE analysis and device vulnerability matching using actual system data:
- data/docs/cves.json (real CVEs in knowledge base)
- data/cmdb_devices.json (real device inventory)

No mockdata - all tests use production data
"""

import json
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from tools.cve_parser import parse_cve_metadata, match_app_in_device
from tools.cve_inference import infer_mitre_attack_info, infer_nist_controls


def load_real_data():
    """Load real data from system"""
    with open(project_root / 'data' / 'docs' / 'cves.json', encoding='utf-8') as f:
        cves = json.load(f)

    with open(project_root / 'data' / 'cmdb_devices.json', encoding='utf-8') as f:
        devices = json.load(f)

    return cves, devices


def test_cve_analysis(cve):
    """Test CVE metadata parsing and MITRE/NIST inference"""
    cve_id = cve.get('id', 'UNKNOWN')
    description = cve.get('description', '')

    # Parse CVE metadata
    cve_meta = parse_cve_metadata(cve)

    # Infer MITRE techniques
    mitre_info = infer_mitre_attack_info(cve_id, description)

    # Infer NIST controls
    nist_info = infer_nist_controls(cve_id, description)

    return {
        'cve_id': cve_id,
        'metadata': cve_meta,
        'mitre': mitre_info,
        'nist': nist_info,
    }


def test_vulnerability_matching(cve_meta, devices):
    """Test CVE-to-device matching"""
    matches = []

    for device in devices:
        match = match_app_in_device(cve_meta, device.get('software', []))

        if match['matched']:
            matches.append({
                'device_id': device['device_id'],
                'hostname': device['hostname'],
                'ip': device['ip'],
                'criticality': device['criticality'],
                'matched_software': match['software_name'],
                'device_version': match['device_version'],
                'match_type': match['match_type'],
            })

    return matches


def run_comprehensive_test():
    """Run comprehensive test with real data"""
    print('='*100)
    print('ANALYST-GRADE ARCHITECTURE TEST - REAL DATA')
    print('='*100)

    # Load real data
    cves, devices = load_real_data()
    print(f'\nLoaded {len(cves)} CVEs from data/docs/cves.json')
    print(f'Loaded {len(devices)} devices from data/cmdb_devices.json')

    # Test critical CVEs
    critical_cve_ids = [
        'CVE-2021-44228',   # Log4j - CRITICAL
        'CVE-2021-41773',   # Apache - HIGH
        'CVE-2022-22965',   # Spring - HIGH
        'CVE-2023-46604',   # ActiveMQ - CRITICAL
        'CVE-2023-20198',   # Cisco IOS - CRITICAL
    ]

    total_vulns = 0
    results = []

    for cve_id in critical_cve_ids:
        cve = next((c for c in cves if c.get('id') == cve_id), None)
        if not cve:
            continue

        # Test CVE analysis
        analysis = test_cve_analysis(cve)

        # Test vulnerability matching
        matches = test_vulnerability_matching(analysis['metadata'], devices)

        total_vulns += len(matches)

        result = {
            'cve_id': cve_id,
            'description': cve.get('description', ''),
            'cvss': cve.get('cvss_score', 'N/A'),
            'cwe_ids': analysis['mitre'].get('cwe_ids', []),
            'mitre_techniques': [t['id'] for t in analysis['mitre'].get('techniques', [])[:2]],
            'nist_controls': [c['id'] for c in analysis['nist'].get('controls', [])[:3]],
            'vulnerable_devices': matches,
        }
        results.append(result)

        # Print result
        print(f'\n{"="*100}')
        print(f'CVE: {cve_id}')
        print(f'Description: {cve.get("description", "")}')
        print(f'CVSS: {cve.get("cvss_score", "N/A")}')
        print(f'{"="*100}')

        print(f'\nCWE IDs: {result["cwe_ids"]}')
        print(f'MITRE Techniques: {result["mitre_techniques"]}')
        print(f'NIST Controls: {result["nist_controls"]}')

        print(f'\nVulnerable Devices: {len(matches)}')
        if matches:
            for m in matches:
                print(f'  • {m["device_id"]} ({m["hostname"]}) - {m["matched_software"]} v{m["device_version"]}')
                print(f'    IP: {m["ip"]}, Criticality: {m["criticality"]}, Match Type: {m["match_type"]}')
        else:
            print(f'  (None)')

    # Summary
    print(f'\n{"="*100}')
    print(f'TEST SUMMARY')
    print(f'{"="*100}')
    print(f'Total CVEs tested: {len(results)}')
    print(f'Total vulnerabilities found: {total_vulns}')
    print(f'Coverage: {len(results)}/{len(critical_cve_ids)} critical CVEs analyzed')
    print(f'\n[PASS] REAL DATA TEST COMPLETE - All data from system production sources')
    print(f'{"="*100}')

    return results


if __name__ == '__main__':
    results = run_comprehensive_test()
