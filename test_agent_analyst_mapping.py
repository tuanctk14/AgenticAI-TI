#!/usr/bin/env python3
"""Test: Agent Analyst MITRE/NIST Extraction from Matched Devices"""
import json
from tools.nvd_client import fetch_cve_by_id
from tools.cmdb import match_cves_with_cmdb

# Fetch CVE and match with CMDB
print("=" * 80)
print("TEST: Agent Analyst Data Extraction")
print("=" * 80)

result = fetch_cve_by_id('CVE-2021-44228')
cves = result.get('context', [])

if cves:
    # Simulate state after matcher
    state = {
        'collected_cves': cves,
        'matched_devices': match_cves_with_cmdb(cves).get('context', []),
    }

    print(f"\nCVEs collected: {len(state['collected_cves'])}")
    print(f"Devices matched: {len(state['matched_devices'])}")

    # Show what agent_analyst should see in context
    print("\n" + "=" * 80)
    print("CONTEXT DATA FOR AGENT_ANALYST")
    print("=" * 80)

    devices = state.get("matched_devices", [])
    for device in devices:
        print(f"\nDevice: {device.get('device_id')} ({device.get('hostname')})")
        print(f"  Software: {device.get('affected_software')} {device.get('device_version', '')}")
        print(f"  CWE IDs: {device.get('cwe_ids', [])}")

        # MITRE data
        mitre_techs = device.get('mitre_techniques', [])
        print(f"\n  MITRE Techniques ({len(mitre_techs)}):")
        if mitre_techs:
            for t in mitre_techs:
                tactics_str = ', '.join(t.get('tactics', []))
                print(f"    - {t.get('id')}: {t.get('name')}")
                print(f"      Tactic: {tactics_str}")
                desc = t.get('description', '')
                if len(desc) > 80:
                    desc = desc[:80] + "..."
                print(f"      Description: {desc}")
        else:
            print(f"    None")

        # NIST data
        nist_ctrls = device.get('nist_controls', [])
        print(f"\n  NIST Controls ({len(nist_ctrls)}):")
        if nist_ctrls:
            for n in nist_ctrls:
                print(f"    - {n.get('id')}: {n.get('name')}")
                print(f"      Family: {n.get('family')}")
                desc = n.get('description', '')
                if len(desc) > 80:
                    desc = desc[:80] + "..."
                print(f"      Description: {desc}")
        else:
            print(f"    None")

    # Show what proper response should look like
    print("\n" + "=" * 80)
    print("EXPECTED AGENT RESPONSE FORMAT")
    print("=" * 80)

    print("\n[MITRE ATT&CK Techniques tu CWE Analysis]")
    for device in devices:
        mitre_techs = device.get('mitre_techniques', [])
        if mitre_techs:
            for t in mitre_techs:
                tactics_str = ', '.join(t.get('tactics', []))
                print(f"- {t.get('id')}: {t.get('name')}")
                print(f"  Tactic: {tactics_str}")

    print("\n[NIST SP 800-53 Controls tu CWE Analysis]")
    for device in devices:
        nist_ctrls = device.get('nist_controls', [])
        if nist_ctrls:
            for n in nist_ctrls:
                print(f"- {n.get('id')}: {n.get('name')}")
                print(f"  Family: {n.get('family')}")

    print("\n[Remediation dua tren MITRE Techniques va NIST Controls]")
    print("\nBUOC 0 (GENERIC):")
    print("0. Patch apache:log4j to latest version with security fixes.")

    for device in devices:
        mitre_techs = device.get('mitre_techniques', [])
        for t in mitre_techs:
            print(f"\n{t.get('id')} - {t.get('name')}:")
            print(f"1. Implement controls to mitigate {t.get('id')} exploitation")

    for device in devices:
        nist_ctrls = device.get('nist_controls', [])
        for n in nist_ctrls:
            print(f"\n{n.get('id')} - {n.get('name')}:")
            print(f"1. Implement {n.get('id')} control for {n.get('family')}")

    print("\nKet thuc.")

print("\n" + "=" * 80)
