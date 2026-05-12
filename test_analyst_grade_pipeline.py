#!/usr/bin/env python3
"""
Test: Analyst-Grade CPE-First Vulnerability Intelligence Pipeline
Verifies: CPE extraction → CWE analysis → MITRE/NIST mapping → Device matching
"""
import json
from tools.nvd_client import fetch_cve_by_id
from tools.cve_parser import parse_cve_metadata
from tools.cmdb import match_cves_with_cmdb
from tools.cwe_mapper import CWEMapper

test_cases = [
    {
        "cve_id": "CVE-2021-44228",
        "expected_vendor": "apache",
        "expected_product": "log4j",
        "expected_cwe": ["20", "400", "502", "917"],
        "expected_mitre": ["T1190", "T1498"],
        "expected_devices": 1,  # SRV-002
    },
    {
        "cve_id": "CVE-2021-41773",
        "expected_vendor": "apache",
        "expected_product": "http_server",
        "expected_cwe": ["22"],
        "expected_mitre": ["T1083"],
        "expected_devices": 2,  # SRV-001, SRV-004
    },
]

print("=" * 80)
print("ANALYST-GRADE VULNERABILITY PIPELINE TEST")
print("=" * 80)

mapper = CWEMapper()
all_passed = True

for test in test_cases:
    cve_id = test["cve_id"]
    print(f"\n{'='*80}")
    print(f"TEST: {cve_id}")
    print("=" * 80)

    # LAYER 1: CPE Extraction
    print("\n[LAYER 1] CPE Extraction (Gold Source)")
    result = fetch_cve_by_id(cve_id)
    cves = result.get("context", [])

    if not cves:
        print(f"  ❌ FAIL: CVE not found")
        all_passed = False
        continue

    cve = cves[0]
    metadata = parse_cve_metadata(cve)

    vendor = metadata.get("vendor", "")
    product = metadata.get("product", "")
    cpe_source = metadata.get("source", "")

    print(f"  Vendor: {vendor}")
    print(f"  Product: {product}")
    print(f"  CPE Source: {cpe_source}")

    if vendor == test["expected_vendor"] and product == test["expected_product"]:
        print(f"  [PASS] CPE correctly identified")
    else:
        print(f"  [FAIL] Expected {test['expected_vendor']}:{test['expected_product']}, got {vendor}:{product}")
        all_passed = False

    # LAYER 2: CWE Extraction
    print("\n[LAYER 2] CWE Extraction (Weakness Analysis)")
    cwe_ids = metadata.get("cwe_ids", [])
    print(f"  CWE IDs: {cwe_ids}")

    if set(cwe_ids) == set(test["expected_cwe"]):
        print(f"  [PASS] CWE correctly extracted")
    else:
        print(f"  [FAIL] Expected {test['expected_cwe']}, got {cwe_ids}")
        all_passed = False

    # LAYER 3: MITRE Mapping
    print("\n[LAYER 3] MITRE ATT&CK Mapping")
    analysis = mapper.analyze_cwe_ids(cwe_ids)
    mitre_ids = [t["id"] for t in analysis.get("mitre_techniques", [])]
    mitre_names = [t["name"] for t in analysis.get("mitre_techniques", [])]

    for tid, tname in zip(mitre_ids, mitre_names):
        print(f"  {tid}: {tname}")

    if set(mitre_ids) == set(test["expected_mitre"]):
        print(f"  [PASS] MITRE techniques correctly mapped")
    else:
        print(f"  [FAIL] Expected {test['expected_mitre']}, got {mitre_ids}")
        all_passed = False

    # LAYER 4: NIST Mapping
    print("\n[LAYER 4] NIST Controls Mapping")
    nist_ids = [c["id"] for c in analysis.get("nist_controls", [])]
    nist_names = [c["name"] for c in analysis.get("nist_controls", [])]

    print(f"  Control Count: {len(nist_ids)}")
    for nid in nist_ids:
        print(f"  - {nid}")

    if len(nist_ids) > 0:
        print(f"  [PASS] NIST controls mapped")
    else:
        print(f"  [FAIL] No NIST controls mapped")
        all_passed = False

    # LAYER 5: Device Matching
    print("\n[LAYER 5] Device Matching & Impact Assessment")
    match_result = match_cves_with_cmdb(cves)
    matched = match_result.get("context", [])

    print(f"  Devices Matched: {len(matched)}")

    for device in matched:
        print(f"\n  Device: {device['device_id']} ({device['hostname']})")
        print(f"    Software: {device.get('affected_software')} {device.get('device_version', '')}")
        print(f"    Risk Level: {device['risk_level']}")
        print(f"    Match Type: {device['match_type']}")

        dev_mitre = device.get("mitre_techniques", [])
        dev_nist = device.get("nist_controls", [])

        print(f"    MITRE Techniques in result: {len(dev_mitre)}")
        print(f"    NIST Controls in result: {len(dev_nist)}")

        if dev_mitre and dev_nist:
            print(f"    [OK] Data embedded in device match")

    if len(matched) == test["expected_devices"]:
        print(f"  [PASS] Expected {test['expected_devices']} device(s), got {len(matched)}")
    else:
        print(f"  [FAIL] Expected {test['expected_devices']} device(s), got {len(matched)}")
        all_passed = False

print("\n" + "=" * 80)
if all_passed:
    print("[PASS] ALL TESTS PASSED - ANALYST-GRADE PIPELINE VERIFIED")
else:
    print("[FAIL] SOME TESTS FAILED")
print("=" * 80)
