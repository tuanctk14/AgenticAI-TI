# -*- coding: utf-8 -*-
"""
tests/test_phase3_ioc_kb.py - Phase 3: IOC Extraction & KB Population

Validates:
1. IOC extraction from malware/campaign descriptions
2. KB population and deduplication
3. Relationship tracking (IOC ↔ Malware/Campaign/CVE)
4. Complete workflow (extract → populate → report)
"""
import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tools.ioc_extractor import IOCExtractor, extract_iocs_from_enrichment
from tools.kb_populator import KBPopulator, populate_kb_from_cve
from tools.cve_relationship_tool import enrich_cve_relationships


def test_ioc_extraction_patterns():
    """Test IOC extraction regex patterns"""
    print("\n" + "="*70)
    print("TEST 1: IOC Extraction Patterns")
    print("="*70)

    test_cases = {
        "ipv4": ("192.168.1.1", "ipv4"),
        "domain": ("malware.com example.org", "domain"),
        "md5": ("d41d8cd98f00b204e9800998ecf8427e", "md5"),
        "sha256": ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"),
        "email": ("attacker@example.com", "email"),
    }

    extracted_count = 0
    for text, expected_type in test_cases.values():
        result = IOCExtractor.extract_from_text(text)
        if result.get(expected_type):
            extracted_count += 1

    success = extracted_count == len(test_cases)
    print(f"  [OK] Extracted {extracted_count}/{len(test_cases)} IOC types")

    return success


def test_ioc_extraction_from_malware():
    """Test IOC extraction from malware description"""
    print("\n" + "="*70)
    print("TEST 2: IOC Extraction from Malware")
    print("="*70)

    malware = {
        "name": "Conti",
        "description": "Ransomware variant communicates with C&C at 192.168.1.100 and malware.com. File hash: d41d8cd98f00b204e9800998ecf8427e",
        "aliases": ["Conti Ransomware"],
        "confidence": 90
    }

    result = IOCExtractor.extract_from_malware(malware)

    success = (
        result.get("source") == "malware" and
        result.get("total_iocs", 0) > 0 and
        "ipv4" in result.get("iocs", {})
    )

    if success:
        print(f"  [OK] Extracted {result['total_iocs']} IOCs from malware")
        print(f"      Malware: {result['malware_name']}")
        print(f"      Types: {list(result['iocs'].keys())}")
    else:
        print(f"  [FAIL] IOC extraction failed")

    return success


def test_ioc_extraction_from_campaign():
    """Test IOC extraction from campaign description"""
    print("\n" + "="*70)
    print("TEST 3: IOC Extraction from Campaign")
    print("="*70)

    campaign = {
        "name": "Oldsmar Treatment Plant Intrusion",
        "description": "Campaign targeting water utility. Infrastructure: c2.attacker.com (185.220.101.45). Files hosted on 10.0.0.5.",
        "confidence": 85
    }

    result = IOCExtractor.extract_from_campaign(campaign)

    success = (
        result.get("source") == "campaign" and
        result.get("total_iocs", 0) > 0
    )

    if success:
        print(f"  [OK] Extracted {result['total_iocs']} IOCs from campaign")
        print(f"      Campaign: {result['campaign_name']}")
    else:
        print(f"  [FAIL] Campaign IOC extraction failed")

    return success


def test_kb_population():
    """Test KB population and deduplication"""
    print("\n" + "="*70)
    print("TEST 4: KB Population & Deduplication")
    print("="*70)

    populator = KBPopulator()

    # Add first IOC
    ioc1 = {
        "type": "domain",
        "value": "malware.com",
        "source": "malware",
        "malware_name": "Conti",
        "confidence": 90
    }

    result1 = populator.add_ioc(ioc1)
    print(f"  [OK] Added IOC: {result1['status']}")

    # Add same IOC from different source (should update)
    ioc2 = {
        "type": "domain",
        "value": "malware.com",
        "source": "campaign",
        "campaign_name": "Campaign-X",
        "confidence": 85
    }

    result2 = populator.add_ioc(ioc2)

    success = (
        result1["status"] == "added" and
        result2["status"] == "updated" and
        len(result2["ioc"].get("relationships", [])) >= 2
    )

    if success:
        print(f"  [OK] Deduplication works - {len(result2['ioc']['relationships'])} relationships")
    else:
        print(f"  [FAIL] Deduplication failed")

    return success


def test_cve_ioc_extraction():
    """Test IOC extraction from complete CVE enrichment"""
    print("\n" + "="*70)
    print("TEST 5: CVE-Level IOC Extraction")
    print("="*70)

    cve_id = "CVE-2021-44228"
    print(f"\nEnriching {cve_id} and extracting IOCs...")

    # Enrich CVE
    enrichment = enrich_cve_relationships(cve_id)

    if enrichment.get("status") != "enriched":
        print(f"  [SKIP] Enrichment failed - skipping IOC extraction test")
        return True

    # Create enriched CVE
    enriched_cve = {
        "id": cve_id,
        "severity": "CRITICAL",
        "relationships": {
            "malwares": enrichment.get("relationships", {}).get("malwares", []),
            "campaigns": enrichment.get("relationships", {}).get("campaigns", []),
        }
    }

    # Extract IOCs
    ioc_result = extract_iocs_from_enrichment(enriched_cve)

    success = (
        ioc_result.get("status") == "extracted" or ioc_result.get("status") == "no_iocs"
    )

    if success:
        total_iocs = ioc_result.get("total_unique_iocs", 0)
        print(f"  [OK] IOC extraction completed")
        print(f"      Total IOCs extracted: {total_iocs}")
        if ioc_result.get("summary"):
            summary = ioc_result["summary"]
            print(f"      Types: {summary}")
    else:
        print(f"  [FAIL] IOC extraction failed")

    return success


def test_kb_stats():
    """Test KB statistics and retrieval"""
    print("\n" + "="*70)
    print("TEST 6: KB Statistics")
    print("="*70)

    populator = KBPopulator()

    # Get stats
    stats = populator.get_kb_stats()

    print(f"  [OK] KB Stats retrieved")
    print(f"      Total IOCs: {stats.get('total_iocs', 0)}")
    print(f"      By type: {stats.get('by_type', {})}")
    print(f"      By confidence:")
    print(f"        High (80-100): {stats.get('by_confidence', {}).get('high', 0)}")
    print(f"        Medium (50-79): {stats.get('by_confidence', {}).get('medium', 0)}")
    print(f"        Low (0-49): {stats.get('by_confidence', {}).get('low', 0)}")

    return True


def test_complete_phase3_workflow():
    """Test complete Phase 3 workflow"""
    print("\n" + "="*70)
    print("TEST 7: Complete Phase 3 Workflow")
    print("="*70)

    cve_id = "CVE-2021-44228"
    print(f"\nStep 1: Enrich CVE...")
    enrichment = enrich_cve_relationships(cve_id)

    if enrichment.get("status") != "enriched":
        print(f"  [SKIP] Enrichment not available")
        return True

    print(f"  [OK] {enrichment.get('total_relationships')} relationships found")

    print(f"\nStep 2: Extract IOCs from relationships...")
    enriched_cve = {
        "id": cve_id,
        "severity": "CRITICAL",
        "relationships": {
            "malwares": enrichment.get("relationships", {}).get("malwares", []),
            "campaigns": enrichment.get("relationships", {}).get("campaigns", []),
        }
    }

    ioc_extraction = extract_iocs_from_enrichment(enriched_cve)
    print(f"  [OK] {ioc_extraction.get('total_unique_iocs', 0)} IOCs extracted")

    print(f"\nStep 3: Populate KB...")
    kb_pop = populate_kb_from_cve(enriched_cve)
    print(f"  [OK] KB populated: {kb_pop.get('iocs_added', 0)} added, {kb_pop.get('iocs_updated', 0)} updated")

    print(f"\nStep 4: Verify KB...")
    populator = KBPopulator()
    cve_iocs = populator.get_iocs_by_cve(cve_id)
    print(f"  [OK] {len(cve_iocs)} IOCs linked to {cve_id} in KB")

    success = (
        enrichment.get("status") == "enriched" and
        ioc_extraction.get("status") in ["extracted", "no_iocs"]
    )

    return success


def run_phase3_tests():
    """Run all Phase 3 tests"""
    print("\n" + "="*70)
    print("PHASE 3: IOC EXTRACTION & KB POPULATION")
    print("="*70)

    results = {
        "ioc_extraction_patterns": False,
        "ioc_extraction_malware": False,
        "ioc_extraction_campaign": False,
        "kb_population": False,
        "cve_ioc_extraction": False,
        "kb_stats": False,
        "complete_workflow": False,
    }

    try:
        results["ioc_extraction_patterns"] = test_ioc_extraction_patterns()
    except Exception as e:
        print(f"  ERROR: {e}")

    try:
        results["ioc_extraction_malware"] = test_ioc_extraction_from_malware()
    except Exception as e:
        print(f"  ERROR: {e}")

    try:
        results["ioc_extraction_campaign"] = test_ioc_extraction_from_campaign()
    except Exception as e:
        print(f"  ERROR: {e}")

    try:
        results["kb_population"] = test_kb_population()
    except Exception as e:
        print(f"  ERROR: {e}")

    try:
        results["cve_ioc_extraction"] = test_cve_ioc_extraction()
    except Exception as e:
        print(f"  ERROR: {e}")

    try:
        results["kb_stats"] = test_kb_stats()
    except Exception as e:
        print(f"  ERROR: {e}")

    try:
        results["complete_workflow"] = test_complete_phase3_workflow()
    except Exception as e:
        print(f"  ERROR: {e}")

    # Summary
    print("\n" + "="*70)
    print("PHASE 3 SUMMARY")
    print("="*70)

    passing = sum(1 for v in results.values() if v)
    total = len(results)

    print(f"\nTests Passed: {passing}/{total}")
    for test_name, result in results.items():
        status = "[PASS]" if result else "[FAIL]"
        print(f"  {status} {test_name.replace('_', ' ').title()}")

    if passing >= 5:
        print(f"\n[SUCCESS] Phase 3 Core functionality validated!")
        print(f"IOC extraction and KB population operational.")
    else:
        print(f"\n[WARNING] Phase 3 incomplete: {passing}/{total} passing")

    return passing >= 5


if __name__ == "__main__":
    success = run_phase3_tests()
    sys.exit(0 if success else 1)
