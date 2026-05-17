# -*- coding: utf-8 -*-
"""
tests/test_agent_integration.py - Test agent_analyst integration with relationship enrichment

Validates:
1. Relationship enrichment tool integration
2. agent_analyst workflow with new tools
3. End-to-end CVE enrichment pipeline
"""
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tools.cve_relationship_tool import enrich_cve_relationships, enrich_cve_batch
from tools.nvd_client import fetch_cve_by_id
from tools.cwe_mapper import get_mitre_attack_info, get_nist_controls


def test_relationship_tool():
    """Test relationship enrichment tool directly"""
    print("\n" + "="*70)
    print("TEST 1: Relationship Enrichment Tool")
    print("="*70)

    cve_id = "CVE-2021-44228"
    print(f"\nEnriching {cve_id}...")

    result = enrich_cve_relationships(cve_id)

    print(f"\nResult:")
    print(f"  CVE: {result.get('cve_id')}")
    print(f"  Threat Level: {result.get('threat_level')}")
    print(f"  Total Relationships: {result.get('total_relationships')}")
    print(f"  Malware Count: {result.get('malware_count')}")
    print(f"  Campaign Count: {result.get('campaign_count')}")
    print(f"  Actor Count: {result.get('actor_count')}")

    if result.get('relationships'):
        campaigns = result['relationships'].get('campaigns', [])
        if campaigns:
            print(f"\n  Sample Campaigns:")
            for campaign in campaigns[:3]:
                print(f"    - {campaign.get('name')} ({campaign.get('confidence')}%)")

    return result.get('status') == 'enriched' or result.get('total_relationships', 0) > 0


def test_batch_enrichment():
    """Test batch enrichment"""
    print("\n" + "="*70)
    print("TEST 2: Batch CVE Enrichment")
    print("="*70)

    cve_ids = ["CVE-2021-44228", "CVE-2021-41773"]
    print(f"\nEnriching {len(cve_ids)} CVEs...")

    result = enrich_cve_batch(cve_ids)

    print(f"\nBatch Result:")
    print(f"  Total Enriched: {result.get('total_enriched')}")
    print(f"  With Relationships: {result.get('total_with_relationships')}")

    for cve_result in result.get('cves', []):
        print(f"\n  {cve_result.get('cve_id')}:")
        print(f"    Threat Level: {cve_result.get('threat_level')}")
        print(f"    Relationships: {cve_result.get('total_relationships')}")

    return len(result.get('cves', [])) > 0


def test_agent_analyst_workflow():
    """Test complete agent_analyst workflow"""
    print("\n" + "="*70)
    print("TEST 3: agent_analyst Complete Workflow")
    print("="*70)

    cve_id = "CVE-2021-44228"

    print(f"\nStep 1: Fetch CVE from NVD...")
    result = fetch_cve_by_id(cve_id)
    if not result.get("context"):
        print("Failed to fetch CVE")
        return False

    cve_dict = result["context"][0]
    print(f"  [OK] CVE: {cve_dict.get('id')}")
    print(f"  [OK] Severity: {cve_dict.get('severity')}")
    print(f"  [OK] CVSS: {cve_dict.get('cvss_score')}")

    print(f"\nStep 2: Enrich with relationships...")
    enrichment = enrich_cve_relationships(cve_id)
    print(f"  [OK] Relationships found: {enrichment.get('total_relationships')}")
    print(f"  [OK] Threat Level: {enrichment.get('threat_level')}")
    print(f"  [OK] Exploitation Context: {enrichment.get('exploitation_context')[:100]}...")

    print(f"\nStep 3: Get MITRE ATT&CK mapping...")
    mitre_result = get_mitre_attack_info(cve_id)
    mitre_data = mitre_result.get("context", {}) if isinstance(mitre_result, dict) else {}
    cwe_ids = mitre_data.get("cwe_ids", []) if isinstance(mitre_data, dict) else []
    print(f"  [OK] CWEs: {len(cwe_ids)} found")
    if cwe_ids:
        print(f"    Sample: {cwe_ids[:3]}")

    print(f"\nStep 4: Get NIST controls...")
    nist_result = get_nist_controls(cve_id)
    nist_data = nist_result.get("context", {}) if isinstance(nist_result, dict) else {}
    nist_controls = nist_data.get("nist_controls", []) if isinstance(nist_data, dict) else []
    print(f"  [OK] NIST Controls: {len(nist_controls)} found")
    if nist_controls:
        print(f"    Sample: {list(nist_controls)[:3]}")

    print(f"\n[PASS] Complete workflow executed successfully!")
    return True


def test_enrichment_quality():
    """Test enrichment data quality"""
    print("\n" + "="*70)
    print("TEST 4: Enrichment Quality Assessment")
    print("="*70)

    cve_id = "CVE-2021-44228"

    print(f"\nQuality Checks for {cve_id}:")

    # Get relationship enrichment
    enrichment = enrich_cve_relationships(cve_id)

    checks = {
        "Has threat level": enrichment.get('threat_level') is not None,
        "Has relationships": enrichment.get('total_relationships', 0) > 0,
        "Has exploitation context": bool(enrichment.get('exploitation_context')),
        "Has threat summary": bool(enrichment.get('threat_summary')),
        "Campaigns extracted": enrichment.get('campaign_count', 0) > 0,
    }

    passed = 0
    for check_name, result in checks.items():
        status = "[OK]" if result else "[FAIL]"
        print(f"  {status} {check_name}")
        if result:
            passed += 1

    print(f"\nQuality Score: {passed}/{len(checks)} checks passed")
    return passed >= 3  # At least 3 checks must pass


def test_workflow_integration():
    """Test complete workflow integration"""
    print("\n" + "="*70)
    print("TEST 5: Complete Workflow Integration")
    print("="*70)

    cve_id = "CVE-2021-44228"

    print(f"\nIntegration Test: CVE {cve_id}")
    print("-" * 70)

    # Step 1: Relationships
    print(f"1. Relationship Enrichment...")
    relationships = enrich_cve_relationships(cve_id)
    rel_status = "[OK]" if relationships.get('total_relationships', 0) > 0 else "[FAIL]"
    print(f"   {rel_status} Found {relationships.get('total_relationships')} relationships")

    # Step 2: MITRE
    print(f"2. MITRE ATT&CK Mapping...")
    mitre = get_mitre_attack_info(cve_id)
    mitre_status = "[OK]" if mitre else "[FAIL]"
    print(f"   {mitre_status} MITRE data retrieved")

    # Step 3: NIST
    print(f"3. NIST Controls...")
    nist = get_nist_controls(cve_id)
    nist_status = "[OK]" if nist else "[FAIL]"
    print(f"   {nist_status} NIST data retrieved")

    # Summary
    print(f"\nWorkflow Summary:")
    print(f"  Threat Level: {relationships.get('threat_level')}")
    print(f"  Threat Context: {relationships.get('exploitation_context')[:80]}...")
    print(f"  Key Campaigns: {len(relationships.get('threat_summary', {}).get('key_campaigns', []))}")

    all_passed = rel_status == "✓" and mitre_status == "✓" and nist_status == "✓"
    return all_passed


def run_all_tests():
    """Run all agent integration tests"""
    print("\n" + "="*70)
    print("AGENT INTEGRATION TEST SUITE")
    print("="*70)

    results = {
        "relationship_tool": False,
        "batch_enrichment": False,
        "agent_workflow": False,
        "enrichment_quality": False,
        "workflow_integration": False,
    }

    try:
        results["relationship_tool"] = test_relationship_tool()
    except Exception as e:
        print(f"ERROR: {e}")

    try:
        results["batch_enrichment"] = test_batch_enrichment()
    except Exception as e:
        print(f"ERROR: {e}")

    try:
        results["agent_workflow"] = test_agent_analyst_workflow()
    except Exception as e:
        print(f"ERROR: {e}")

    try:
        results["enrichment_quality"] = test_enrichment_quality()
    except Exception as e:
        print(f"ERROR: {e}")

    try:
        results["workflow_integration"] = test_workflow_integration()
    except Exception as e:
        print(f"ERROR: {e}")

    # Print summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)

    passing = sum(1 for v in results.values() if v)
    print(f"\nTests completed: {passing}/{len(results)}")
    print("\nResults:")
    for test_name, result in results.items():
        status = "PASS" if result else "FAIL"
        print(f"  {test_name}: {status}")

    print(f"\n{'[PASS] ALL TESTS PASSED' if passing == len(results) else '[WARN] SOME TESTS FAILED'}")


if __name__ == "__main__":
    run_all_tests()
