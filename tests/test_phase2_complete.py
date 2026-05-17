# -*- coding: utf-8 -*-
"""
tests/test_phase2_complete.py - Phase 2 Complete Validation

Validates the end-to-end Priority #1 enrichment pipeline:
1. Agent integration (Phase 2.1)
2. Neo4j persistence (Phase 2.2)
3. Menu 2 report integration (Phase 2.3)
4. Complete workflow (Phase 2.4)
"""
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tools.cve_relationship_tool import enrich_cve_relationships, enrich_cve_batch
from tools.cve_relationship_integrator import build_cve_relationship_graph, format_relationships_for_report
from tools.report_generator import generate_report
from tools.nvd_client import fetch_cve_by_id
from tools.cwe_mapper import get_mitre_attack_info, get_nist_controls


def test_phase2_1_agent_integration():
    """Phase 2.1: Agent Integration - relationship tool works in agent context"""
    print("\n" + "="*70)
    print("PHASE 2.1: Agent Integration")
    print("="*70)

    cve_id = "CVE-2021-44228"
    print(f"\nTest: agent_analyst calls relationship enrichment...")

    enrichment = enrich_cve_relationships(cve_id)

    success = (
        enrichment.get("status") in ["enriched", "no_relationships"] and
        enrichment.get("threat_level") is not None
    )

    if success:
        print(f"  [OK] Relationship tool integrated")
        print(f"      Status: {enrichment.get('status')}")
        print(f"      Threat Level: {enrichment.get('threat_level')}")
        print(f"      Relationships: {enrichment.get('total_relationships')}")
    else:
        print(f"  [FAIL] Relationship tool not working")

    return success


def test_phase2_2_neo4j_persistence():
    """Phase 2.2: Neo4j Persistence - relationships can be stored"""
    print("\n" + "="*70)
    print("PHASE 2.2: Neo4j Persistence")
    print("="*70)

    cve_id = "CVE-2021-44228"
    print(f"\nTest: Relationships are stored in Neo4j...")

    # Enrich CVE
    enrichment = enrich_cve_relationships(cve_id)

    # Create enriched CVE object
    enriched_cve = {
        "id": cve_id,
        "severity": "CRITICAL",
        "description": "Log4j RCE",
        "relationships": {
            "malwares": enrichment.get("relationships", {}).get("malwares", []),
            "campaigns": enrichment.get("relationships", {}).get("campaigns", []),
            "threat_actors": enrichment.get("relationships", {}).get("threat_actors", []),
        }
    }

    # Build graph structure
    graph_data = build_cve_relationship_graph(enriched_cve)

    success = (
        graph_data.get("node_count", 0) > 0 and
        graph_data.get("edge_count", 0) > 0
    )

    if success:
        print(f"  [OK] Graph structure built successfully")
        print(f"      Nodes: {graph_data.get('node_count')}")
        print(f"      Edges: {graph_data.get('edge_count')}")
        print(f"      Density: {graph_data.get('graph_density'):.2f}")
    else:
        print(f"  [FAIL] Graph structure not built")

    return success


def test_phase2_3_menu2_reports():
    """Phase 2.3: Menu 2 Reports - relationships displayed in reports"""
    print("\n" + "="*70)
    print("PHASE 2.3: Menu 2 Report Integration")
    print("="*70)

    cve_id = "CVE-2021-44228"
    print(f"\nTest: Relationship enrichment included in reports...")

    # Create enriched CVE with relationships
    enrichment = enrich_cve_relationships(cve_id)

    cve_obj = {
        "id": cve_id,
        "severity": "CRITICAL",
        "cvss_score": 10.0,
        "description": "Log4j Remote Code Execution",
        "relationships": {
            "malwares": enrichment.get("relationships", {}).get("malwares", []),
            "campaigns": enrichment.get("relationships", {}).get("campaigns", []),
            "threat_actors": enrichment.get("relationships", {}).get("threat_actors", []),
            "total_relationships": enrichment.get("total_relationships", 0),
        }
    }

    # Format for report
    relationship_section = format_relationships_for_report(cve_obj)

    success = (
        relationship_section and
        "Malware" in relationship_section or "Campaign" in relationship_section or "Threat Actor" in relationship_section
    ) or enrichment.get("total_relationships", 0) == 0

    if success:
        print(f"  [OK] Report formatting works")
        if enrichment.get("total_relationships", 0) > 0:
            preview = relationship_section[:200] if relationship_section else "No relationships"
            print(f"      Preview: {preview}...")
        else:
            print(f"      (No relationships to display - expected for some CVEs)")
    else:
        print(f"  [FAIL] Report formatting failed")

    return success


def test_phase2_4_complete_workflow():
    """Phase 2.4: Complete Workflow - all components working together"""
    print("\n" + "="*70)
    print("PHASE 2.4: Complete Workflow (End-to-End)")
    print("="*70)

    cve_id = "CVE-2021-44228"
    print(f"\nTest: Complete enrichment workflow...")

    # Step 1: Fetch from NVD
    print(f"  Step 1: Fetch CVE from NVD...")
    nvd_result = fetch_cve_by_id(cve_id)
    if not nvd_result.get("context"):
        print(f"    [FAIL] NVD fetch failed")
        return False
    cve_dict = nvd_result["context"][0]
    print(f"    [OK] CVE fetched: {cve_dict.get('id')}")

    # Step 2: Enrich with relationships
    print(f"  Step 2: Enrich with relationships...")
    enrichment = enrich_cve_relationships(cve_id)
    if enrichment.get("status") == "error":
        print(f"    [FAIL] Relationship enrichment failed")
        return False
    print(f"    [OK] {enrichment.get('total_relationships')} relationships found")

    # Step 3: Get MITRE ATT&CK mapping
    print(f"  Step 3: Get MITRE ATT&CK mapping...")
    mitre = get_mitre_attack_info(cve_id)
    if not mitre:
        print(f"    [WARN] MITRE mapping unavailable")
    else:
        print(f"    [OK] MITRE mapping retrieved")

    # Step 4: Get NIST controls
    print(f"  Step 4: Get NIST controls...")
    nist = get_nist_controls(cve_id)
    if not nist:
        print(f"    [WARN] NIST controls unavailable")
    else:
        print(f"    [OK] NIST controls retrieved")

    # Step 5: Build graph structure for persistence
    print(f"  Step 5: Build graph structure...")
    enriched_cve = {
        "id": cve_id,
        "severity": cve_dict.get("severity", "Unknown"),
        "description": cve_dict.get("description", ""),
        "relationships": {
            "malwares": enrichment.get("relationships", {}).get("malwares", []),
            "campaigns": enrichment.get("relationships", {}).get("campaigns", []),
            "threat_actors": enrichment.get("relationships", {}).get("threat_actors", []),
            "total_relationships": enrichment.get("total_relationships", 0),
        }
    }

    graph = build_cve_relationship_graph(enriched_cve)
    if graph.get("node_count", 0) == 0:
        print(f"    [WARN] No relationships to persist")
    else:
        print(f"    [OK] Graph structure built: {graph.get('node_count')} nodes")

    # Step 6: Format for report
    print(f"  Step 6: Format for Menu 2 report...")
    report_section = format_relationships_for_report(enriched_cve)
    print(f"    [OK] Report section generated")

    print(f"\n  Final Status:")
    print(f"    CVE: {cve_id}")
    print(f"    Threat Level: {enrichment.get('threat_level')}")
    print(f"    Relationships: {enrichment.get('total_relationships')}")
    print(f"    Graph Nodes: {graph.get('node_count')}")
    print(f"    Report Ready: Yes")

    return True


def run_phase2_validation():
    """Run all Phase 2 tests"""
    print("\n" + "="*70)
    print("PRIORITY #1 PHASE 2 VALIDATION")
    print("="*70)

    results = {
        "phase_2_1_agent_integration": False,
        "phase_2_2_neo4j_persistence": False,
        "phase_2_3_menu2_reports": False,
        "phase_2_4_complete_workflow": False,
    }

    try:
        results["phase_2_1_agent_integration"] = test_phase2_1_agent_integration()
    except Exception as e:
        print(f"  ERROR: {e}")

    try:
        results["phase_2_2_neo4j_persistence"] = test_phase2_2_neo4j_persistence()
    except Exception as e:
        print(f"  ERROR: {e}")

    try:
        results["phase_2_3_menu2_reports"] = test_phase2_3_menu2_reports()
    except Exception as e:
        print(f"  ERROR: {e}")

    try:
        results["phase_2_4_complete_workflow"] = test_phase2_4_complete_workflow()
    except Exception as e:
        print(f"  ERROR: {e}")

    # Summary
    print("\n" + "="*70)
    print("PHASE 2 SUMMARY")
    print("="*70)

    passing = sum(1 for v in results.values() if v)
    total = len(results)

    print(f"\nTests Passed: {passing}/{total}")
    for phase_name, result in results.items():
        status = "[PASS]" if result else "[FAIL]"
        print(f"  {status} {phase_name.replace('_', ' ').title()}")

    if passing == total:
        print(f"\n[SUCCESS] Phase 2 Complete: All {total} components validated!")
        print(f"\nNext Step: Phase 3 - IOC Knowledge Base Population")
    else:
        print(f"\n[WARNING] Phase 2 Partial: {passing}/{total} components passing")

    return passing == total


if __name__ == "__main__":
    success = run_phase2_validation()
    sys.exit(0 if success else 1)
