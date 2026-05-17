# -*- coding: utf-8 -*-
"""
tests/test_relationship_enrichment.py - Test Malware/Campaign Relationship Enrichment

Validates:
1. OpenCTI relationship extraction
2. CVE enrichment integration
3. Graph building
4. Report formatting
"""
import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tools.nvd_client import fetch_cve_by_id
from tools.opencti_relationship_enricher import (
    enrich_cve_with_relationships,
    extract_attack_techniques,
    query_cve_malware_relationships,
    query_cve_campaign_relationships,
    query_cve_threat_actor_relationships,
)
from tools.cve_relationship_integrator import (
    add_relationships_to_cve,
    build_cve_relationship_graph,
    format_relationships_for_report,
    create_threat_summary,
)


def test_malware_relationship_query():
    """Test malware relationship extraction from OpenCTI"""
    print("\n" + "="*70)
    print("TEST 1: Malware Relationship Query")
    print("="*70)

    cve_id = "CVE-2021-44228"
    result = query_cve_malware_relationships(cve_id, max_results=20)

    print(f"\nCVE: {cve_id}")
    print(f"Source: {result.get('source')}")
    print(f"Malwares found: {len(result.get('malwares', []))}")

    if result.get("malwares"):
        print("\nMalware families:")
        for malware in result.get("malwares", []):
            print(f"  - {malware.get('name')}")
            print(f"    Confidence: {malware.get('confidence')}%")
            print(f"    Types: {', '.join(malware.get('malware_types', []))}")
            if malware.get('aliases'):
                print(f"    Aliases: {', '.join(malware.get('aliases', []))}")
        return True
    else:
        print("\nNo malwares found (OpenCTI may not be connected or no data available)")
        return False


def test_campaign_relationship_query():
    """Test campaign relationship extraction from OpenCTI"""
    print("\n" + "="*70)
    print("TEST 2: Campaign Relationship Query")
    print("="*70)

    cve_id = "CVE-2021-44228"
    result = query_cve_campaign_relationships(cve_id, max_results=20)

    print(f"\nCVE: {cve_id}")
    print(f"Source: {result.get('source')}")
    print(f"Campaigns found: {len(result.get('campaigns', []))}")

    if result.get("campaigns"):
        print("\nCampaigns:")
        for campaign in result.get("campaigns", []):
            print(f"  - {campaign.get('name')}")
            print(f"    Confidence: {campaign.get('confidence')}%")
        return True
    else:
        print("\nNo campaigns found")
        return False


def test_threat_actor_relationship_query():
    """Test threat actor relationship extraction from OpenCTI"""
    print("\n" + "="*70)
    print("TEST 3: Threat Actor Relationship Query")
    print("="*70)

    cve_id = "CVE-2021-44228"
    result = query_cve_threat_actor_relationships(cve_id, max_results=20)

    print(f"\nCVE: {cve_id}")
    print(f"Source: {result.get('source')}")
    print(f"Threat actors found: {len(result.get('threat_actors', []))}")

    if result.get("threat_actors"):
        print("\nThreat actors:")
        for actor in result.get("threat_actors", []):
            print(f"  - {actor.get('name')}")
            print(f"    Confidence: {actor.get('confidence')}%")
            if actor.get('aliases'):
                print(f"    Aliases: {', '.join(actor.get('aliases', []))}")
        return True
    else:
        print("\nNo threat actors found")
        return False


def test_complete_enrichment():
    """Test complete relationship enrichment"""
    print("\n" + "="*70)
    print("TEST 4: Complete Relationship Enrichment")
    print("="*70)

    cve_id = "CVE-2021-44228"

    print(f"\nEnriching {cve_id}...")
    enrichment = enrich_cve_with_relationships(cve_id)

    print(f"\nEnrichment results:")
    print(f"  CVE: {enrichment.get('cve_id')}")
    print(f"  Total relationships: {enrichment.get('total_relationships')}")
    print(f"  Malware families: {len(enrichment.get('malwares', []))}")
    print(f"  Campaigns: {len(enrichment.get('campaigns', []))}")
    print(f"  Threat actors: {len(enrichment.get('threat_actors', []))}")
    print(f"  Status: {enrichment.get('status')}")

    return enrichment


def test_cve_integration():
    """Test integration with NVD CVE data"""
    print("\n" + "="*70)
    print("TEST 5: CVE Integration (NVD + OpenCTI)")
    print("="*70)

    cve_id = "CVE-2021-44228"

    # Fetch CVE from NVD
    print(f"\nFetching {cve_id} from NVD...")
    result = fetch_cve_by_id(cve_id)

    if not result.get("context"):
        print("Failed to fetch CVE from NVD")
        return None

    cve_dict = result["context"][0]
    print(f"  CVE: {cve_dict.get('id')}")
    print(f"  Severity: {cve_dict.get('severity')}")
    print(f"  CVSS: {cve_dict.get('cvss_score')}")

    # Add relationships
    print(f"\nAdding relationships...")
    enhanced_cve = add_relationships_to_cve(cve_dict)

    relationships = enhanced_cve.get("relationships", {})
    print(f"\nEnhanced CVE:")
    print(f"  Total relationships: {relationships.get('total_relationships')}")
    print(f"  Malware: {len(relationships.get('malwares', []))}")
    print(f"  Campaigns: {len(relationships.get('campaigns', []))}")
    print(f"  Threat actors: {len(relationships.get('threat_actors', []))}")
    print(f"  Attack techniques: {len(relationships.get('attack_techniques', []))}")

    return enhanced_cve


def test_graph_building():
    """Test relationship graph building"""
    print("\n" + "="*70)
    print("TEST 6: Relationship Graph Building")
    print("="*70)

    cve_id = "CVE-2021-44228"

    # Fetch and enrich CVE
    result = fetch_cve_by_id(cve_id)
    if not result.get("context"):
        print("Failed to fetch CVE")
        return None

    cve_dict = result["context"][0]
    enhanced_cve = add_relationships_to_cve(cve_dict)

    # Build graph
    print(f"\nBuilding relationship graph for {cve_id}...")
    graph = build_cve_relationship_graph(enhanced_cve)

    print(f"\nGraph structure:")
    print(f"  Nodes: {graph.get('node_count')}")
    print(f"  Edges: {graph.get('edge_count')}")
    print(f"  Graph density: {graph.get('graph_density', 0):.2f}")

    if graph.get("nodes"):
        print(f"\nNode types:")
        node_types = {}
        for node in graph.get("nodes", []):
            node_type = node.get("type")
            node_types[node_type] = node_types.get(node_type, 0) + 1

        for node_type, count in node_types.items():
            print(f"  {node_type}: {count}")

    if graph.get("edges"):
        print(f"\nEdge types:")
        edge_types = {}
        for edge in graph.get("edges", []):
            relation = edge.get("relation")
            edge_types[relation] = edge_types.get(relation, 0) + 1

        for relation, count in edge_types.items():
            print(f"  {relation}: {count}")

    return graph


def test_report_formatting():
    """Test relationship formatting for reports"""
    print("\n" + "="*70)
    print("TEST 7: Report Formatting")
    print("="*70)

    cve_id = "CVE-2021-44228"

    # Fetch and enrich CVE
    result = fetch_cve_by_id(cve_id)
    if not result.get("context"):
        print("Failed to fetch CVE")
        return None

    cve_dict = result["context"][0]
    enhanced_cve = add_relationships_to_cve(cve_dict)

    # Format for report
    print(f"\nFormatting relationships for Menu 2 report...")
    report_text = format_relationships_for_report(enhanced_cve)

    print("\nFormatted report section:")
    print(report_text)

    return report_text


def test_threat_summary():
    """Test threat summary creation"""
    print("\n" + "="*70)
    print("TEST 8: Threat Summary Creation")
    print("="*70)

    cve_id = "CVE-2021-44228"

    # Fetch and enrich CVE
    result = fetch_cve_by_id(cve_id)
    if not result.get("context"):
        print("Failed to fetch CVE")
        return None

    cve_dict = result["context"][0]
    enhanced_cve = add_relationships_to_cve(cve_dict)

    # Create summary
    print(f"\nCreating threat summary...")
    summary = create_threat_summary(enhanced_cve)

    print(f"\nThreat Summary for {cve_id}:")
    print(f"  Severity: {summary.get('severity')}")
    print(f"  EPSS Score: {summary.get('epss_score')}")
    print(f"  Threat Level: {summary.get('threat_level')}")
    print(f"  Intelligence Type: {summary.get('intelligence_type')}")
    print(f"  Total Relationships: {summary.get('total_relationships')}")
    print(f"\n  Exploitation Context:")
    print(f"  {summary.get('exploitation_context')}")
    print(f"\n  Key Actors: {', '.join(summary.get('key_actors', []))}")
    print(f"  Key Campaigns: {', '.join(summary.get('key_campaigns', []))}")

    return summary


def run_all_tests():
    """Run all relationship enrichment tests"""
    print("\n" + "="*70)
    print("RELATIONSHIP ENRICHMENT TEST SUITE")
    print("="*70)

    results = {
        "malware_query": False,
        "campaign_query": False,
        "actor_query": False,
        "complete_enrichment": None,
        "cve_integration": None,
        "graph_building": None,
        "report_formatting": None,
        "threat_summary": None,
    }

    try:
        results["malware_query"] = test_malware_relationship_query()
    except Exception as e:
        print(f"ERROR: {e}")

    try:
        results["campaign_query"] = test_campaign_relationship_query()
    except Exception as e:
        print(f"ERROR: {e}")

    try:
        results["actor_query"] = test_threat_actor_relationship_query()
    except Exception as e:
        print(f"ERROR: {e}")

    try:
        results["complete_enrichment"] = test_complete_enrichment()
    except Exception as e:
        print(f"ERROR: {e}")

    try:
        results["cve_integration"] = test_cve_integration()
    except Exception as e:
        print(f"ERROR: {e}")

    try:
        results["graph_building"] = test_graph_building()
    except Exception as e:
        print(f"ERROR: {e}")

    try:
        results["report_formatting"] = test_report_formatting()
    except Exception as e:
        print(f"ERROR: {e}")

    try:
        results["threat_summary"] = test_threat_summary()
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
        status = "PASS" if result else "FAIL" if result is False else "PENDING"
        print(f"  {test_name}: {status}")


if __name__ == "__main__":
    run_all_tests()
