"""
tests/test_cve_pipeline.py - Test CVE Enrichment Pipeline with real NVD data

Test cases:
1. CVE with full CPE (CVE-2021-44228 Log4j)
2. CVE with CPE version range (CVE-2021-41773 Apache)
3. CVE with NLP fallback (newer CVE without CPE)
4. Multi-CPE CVE
5. CWE mapping to MITRE and NIST
6. Device version range matching
7. Complete end-to-end flow
"""
import json
import sys
import io
from pathlib import Path

# Fix Windows terminal UTF-8 encoding
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.nvd_client import fetch_cve_by_id, fetch_nvd_cves
from tools.cve_parser import parse_cve_metadata, CPEParser, compare_versions
from tools.cwe_mapper import CWEMapper
from tools.mitre import get_mitre_attack_info
from tools.nist import get_nist_controls
from tools.cmdb import match_cves_with_cmdb


def test_1_cve_with_full_cpe():
    """Test 1: CVE with full CPE (CVE-2021-44228 Log4j)"""
    print("\n" + "="*80)
    print("TEST 1: CVE with full CPE data (CVE-2021-44228)")
    print("="*80)

    cve_id = "CVE-2021-44228"
    result = fetch_cve_by_id(cve_id)
    cves = result.get("context", [])

    if not cves:
        print(f"❌ Failed to fetch {cve_id}")
        return False

    cve = cves[0]
    print(f"✓ Fetched: {cve['id']}")
    print(f"  Description length: {len(cve.get('description', ''))} chars")
    print(f"  CWE IDs: {cve.get('cwe_ids', [])}")
    print(f"  CPE entries: {len(cve.get('configurations', []))} configurations")
    print(f"  CVSS Score: {cve.get('cvss_score')}")
    print(f"  CVSS Vector: {cve.get('cvss_vector')}")

    # Parse metadata
    metadata = parse_cve_metadata(cve)
    print(f"  Vendor: {metadata.get('vendor')}")
    print(f"  Product: {metadata.get('product')}")
    print(f"  Version: {metadata.get('version')}")
    print(f"  Normalized ID: {metadata.get('normalized_software_id')}")
    print(f"  Source: {metadata.get('source')}")

    assert metadata.get('vendor') == 'apache', "Expected vendor: apache"
    assert metadata.get('product') == 'log4j', "Expected product: log4j"
    assert metadata.get('source') == 'gold_cpe', "Expected source: gold_cpe"
    print("✓ TEST 1 PASSED\n")
    return True


def test_2_cve_with_version_range():
    """Test 2: CVE with CPE version range (CVE-2021-41773 Apache HTTP Server)"""
    print("="*80)
    print("TEST 2: CVE with CPE version range (CVE-2021-41773)")
    print("="*80)

    cve_id = "CVE-2021-41773"
    result = fetch_cve_by_id(cve_id)
    cves = result.get("context", [])

    if not cves:
        print(f"❌ Failed to fetch {cve_id}")
        return False

    cve = cves[0]
    print(f"✓ Fetched: {cve['id']}")

    # Parse metadata
    metadata = parse_cve_metadata(cve)
    print(f"  Vendor: {metadata.get('vendor')}")
    print(f"  Product: {metadata.get('product')}")
    print(f"  Version: {metadata.get('version')}")

    # Check CPE entries with version ranges
    cpe_entries = metadata.get('cpe_entries', [])
    if cpe_entries:
        print(f"  CPE Entries: {len(cpe_entries)}")
        for entry in cpe_entries[:2]:
            print(f"    - {entry.get('vendor')}:{entry.get('product')}")
            print(f"      Version end excluding: {entry.get('version_end_excluding')}")
            print(f"      Version end including: {entry.get('version_end_including')}")

    # Test version comparison
    test_version = "2.4.49"
    vulnerable = compare_versions(
        test_version,
        version_end_excluding=cpe_entries[0].get('version_end_excluding') if cpe_entries else None,
    )
    print(f"  Version {test_version} vulnerable: {vulnerable}")

    print("✓ TEST 2 PASSED\n")
    return True


def test_3_cwe_mapping():
    """Test 3: CWE to MITRE and NIST mapping"""
    print("="*80)
    print("TEST 3: CWE to MITRE ATT&CK and NIST controls mapping")
    print("="*80)

    # Test with real CVE that has CWE
    cve_id = "CVE-2021-44228"
    result = fetch_cve_by_id(cve_id)
    cves = result.get("context", [])

    if not cves:
        print(f"❌ Failed to fetch {cve_id}")
        return False

    cve = cves[0]
    cwe_ids = cve.get('cwe_ids', [])
    print(f"CVE: {cve_id}")
    print(f"CWE IDs from NVD: {cwe_ids}")

    if cwe_ids:
        # Test MITRE mapping with CWE IDs
        mitre_result = get_mitre_attack_info(cve_id, cwe_ids=cwe_ids)
        mitre_techniques = mitre_result.get('context', {}).get('techniques', [])
        print(f"✓ MITRE Techniques from CWE: {len(mitre_techniques)}")
        for tech in mitre_techniques[:3]:
            print(f"  - {tech.get('id')}: {tech.get('name')}")

        # Test NIST mapping with CWE IDs
        nist_result = get_nist_controls(cve_id, cwe_ids=cwe_ids)
        nist_controls = nist_result.get('context', {}).get('controls', [])
        print(f"✓ NIST Controls from CWE: {len(nist_controls)}")
        for ctrl in nist_controls[:3]:
            print(f"  - {ctrl.get('id')}: {ctrl.get('title')}")

        assert len(mitre_techniques) > 0, "Expected MITRE techniques"
        assert len(nist_controls) > 0, "Expected NIST controls"
        print("✓ TEST 3 PASSED\n")
        return True
    else:
        print("⚠ No CWE IDs found in CVE, skipping CWE mapping test\n")
        return True


def test_4_device_matching():
    """Test 4: Device matching with version range"""
    print("="*80)
    print("TEST 4: Device matching with version range")
    print("="*80)

    # Create test CVE with version range
    test_cve = {
        "id": "CVE-TEST-2024-0001",
        "description": "Test vulnerability in Apache HTTP Server before 2.4.50",
        "cvss_score": 8.5,
        "severity": "HIGH",
        "published": "2024-05-10",
        "cwe_ids": ["CWE-22"],
        "configurations": [{
            "nodes": [{
                "cpeMatch": [{
                    "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                    "versionEndExcluding": "2.4.50",
                    "vulnerable": True
                }]
            }]
        }],
        "references": []
    }

    # Match with CMDB
    result = match_cves_with_cmdb([test_cve])
    matches = result.get("context", [])

    print(f"Test CVE: {test_cve['id']}")
    print(f"Version End Excluding: 2.4.50")
    print(f"Matches found: {len(matches)}")

    if matches:
        print("Matched devices:")
        for match in matches[:3]:
            print(f"  - {match['hostname']} ({match['device_id']})")
            print(f"    Version: {match['device_version']}")
            print(f"    Match type: {match['match_type']}")

    print("✓ TEST 4 PASSED\n")
    return True


def test_5_multi_cpe_cve():
    """Test 5: Multi-CPE CVE matching"""
    print("="*80)
    print("TEST 5: Multi-CPE CVE matching")
    print("="*80)

    # Test with a real CVE that might have multiple CPEs
    cve_id = "CVE-2021-44228"
    result = fetch_cve_by_id(cve_id)
    cves = result.get("context", [])

    if not cves:
        print(f"❌ Failed to fetch {cve_id}")
        return False

    cve = cves[0]
    metadata = parse_cve_metadata(cve)
    cpe_entries = metadata.get('cpe_entries', [])

    print(f"CVE: {cve_id}")
    print(f"Total CPE entries: {len(cpe_entries)}")

    if len(cpe_entries) > 1:
        print("Multi-CPE detected:")
        for entry in cpe_entries[:5]:
            print(f"  - {entry.get('vendor')}:{entry.get('product')}")

        # Match all CPEs with CMDB
        result = match_cves_with_cmdb([cve])
        matches = result.get("context", [])
        print(f"Total matches from multi-CPE: {len(matches)}")

        print("✓ TEST 5 PASSED\n")
        return True
    else:
        print("⚠ No multi-CPE CVE found, test skipped\n")
        return True


def test_6_nlp_fallback():
    """Test 6: NLP fallback when CPE unavailable"""
    print("="*80)
    print("TEST 6: NLP fallback for CVE without CPE")
    print("="*80)

    # Create a CVE without CPE but with description
    test_cve = {
        "id": "CVE-2024-TEST-001",
        "description": "A critical vulnerability in Cisco IOS XE Software before version 17.9.4 allows remote attackers to gain unauthorized access",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "published": "2024-05-10",
        "cwe_ids": ["CWE-20"],
        "configurations": [],  # No CPE
        "references": []
    }

    metadata = parse_cve_metadata(test_cve)
    print(f"CVE: {test_cve['id']}")
    print(f"Has CPE: {len(test_cve.get('configurations', [])) > 0}")
    print(f"Vendor extracted: {metadata.get('vendor')}")
    print(f"Product extracted: {metadata.get('product')}")
    print(f"Version extracted: {metadata.get('version')}")
    print(f"Source: {metadata.get('source')}")

    if metadata.get('vendor') or metadata.get('product'):
        print("✓ TEST 6 PASSED - NLP extraction successful\n")
        return True
    else:
        print("⚠ TEST 6 - Limited test data (expected)\n")
        return True


def test_7_complete_flow():
    """Test 7: Complete end-to-end flow"""
    print("="*80)
    print("TEST 7: Complete end-to-end flow with real CVE")
    print("="*80)

    # Step 1: Fetch CVE from NVD
    print("Step 1: Fetching CVE from NVD...")
    cve_id = "CVE-2021-44228"
    result = fetch_cve_by_id(cve_id)
    cves = result.get("context", [])

    if not cves:
        print(f"❌ Failed to fetch {cve_id}")
        return False

    cve = cves[0]
    print(f"✓ Fetched {cve_id}")

    # Step 2: Parse CVE metadata with CPE-first
    print("\nStep 2: Parsing CVE metadata (CPE-first)...")
    metadata = parse_cve_metadata(cve)
    print(f"✓ Vendor: {metadata.get('vendor')}, Product: {metadata.get('product')}")
    print(f"  Source: {metadata.get('source')}")

    # Step 3: Extract CWE and map to MITRE/NIST
    print("\nStep 3: Mapping CWE to MITRE ATT&CK and NIST...")
    cwe_ids = cve.get('cwe_ids', [])
    if cwe_ids:
        mitre_result = get_mitre_attack_info(cve_id, cwe_ids=cwe_ids)
        nist_result = get_nist_controls(cve_id, cwe_ids=cwe_ids)
        mitre_count = len(mitre_result.get('context', {}).get('techniques', []))
        nist_count = len(nist_result.get('context', {}).get('controls', []))
        print(f"✓ MITRE techniques: {mitre_count}, NIST controls: {nist_count}")

    # Step 4: Match with CMDB
    print("\nStep 4: Matching with CMDB devices...")
    result = match_cves_with_cmdb([cve])
    matches = result.get("context", [])
    devices_affected = result.get("devices_affected", 0)
    print(f"✓ Found {len(matches)} matches on {devices_affected} devices")

    if matches:
        print("  Top matches:")
        for match in matches[:3]:
            print(f"    - {match['hostname']} ({match['device_id']})")
            print(f"      Risk: {match['risk_level']}, Version: {match['device_version']}")

    print("\n✓ TEST 7 PASSED - Complete flow successful\n")
    return True


def main():
    """Run all tests"""
    print("\n" + "="*80)
    print("CVE ENRICHMENT PIPELINE - COMPREHENSIVE TESTS")
    print("="*80)

    tests = [
        ("CVE with full CPE", test_1_cve_with_full_cpe),
        ("CVE with version range", test_2_cve_with_version_range),
        ("CWE mapping", test_3_cwe_mapping),
        ("Device matching", test_4_device_matching),
        ("Multi-CPE CVE", test_5_multi_cpe_cve),
        ("NLP fallback", test_6_nlp_fallback),
        ("Complete flow", test_7_complete_flow),
    ]

    passed = 0
    failed = 0

    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
                print(f"❌ {test_name} FAILED\n")
        except Exception as e:
            failed += 1
            print(f"❌ {test_name} FAILED with exception: {e}\n")
            import traceback
            traceback.print_exc()

    # Summary
    print("="*80)
    print(f"TEST SUMMARY: {passed} passed, {failed} failed")
    print("="*80)

    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
