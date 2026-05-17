# -*- coding: utf-8 -*-
"""
tools/cve_relationship_tool.py - CVE Relationship Enrichment Tool for Agents

Wrapper function for agent use to enrich CVEs with malware/campaign/threat actor relationships.

This tool is designed to be called by agent_analyst as part of the enrichment workflow.
"""

from tools.cve_relationship_integrator import (
    add_relationships_to_cve,
    create_threat_summary,
)
from tools.neo4j_relationship_persister import persist_cve_relationships
from tools.ioc_extractor import extract_iocs_from_enrichment
from tools.kb_populator import populate_kb_from_cve


def enrich_cve_relationships(cve_id: str) -> dict:
    """
    Enrich a single CVE with malware/campaign/threat actor relationships from OpenCTI.

    This is the main tool interface for agents.

    Args:
        cve_id: CVE identifier (e.g., "CVE-2021-44228")

    Returns: {
        "cve_id": "CVE-2021-44228",
        "threat_level": "CRITICAL",
        "exploitation_context": "used in 14 known campaigns",
        "relationships": {
            "malwares": [...],
            "campaigns": [...],
            "threat_actors": [...],
            "attack_techniques": [...]
        },
        "threat_summary": {
            "threat_level": "CRITICAL",
            "key_actors": [...],
            "key_campaigns": [...]
        },
        "status": "enriched"
    }
    """
    print(f"  [RelationshipTool] Enriching {cve_id}...")

    try:
        # Create mock CVE object with required fields
        # In real usage, this would be passed from agent_ti
        cve_dict = {
            "id": cve_id,
            "description": f"Enriching relationships for {cve_id}",
            "severity": "CRITICAL",
            "enrichment": {
                "epss_score": 0.0,  # Placeholder
            }
        }

        # Enrich with relationships
        enriched_cve = add_relationships_to_cve(cve_dict)

        # Persist relationships to Neo4j
        persistence_result = persist_cve_relationships(enriched_cve)

        # Extract and populate IOCs
        ioc_extraction = extract_iocs_from_enrichment(enriched_cve)
        kb_population = populate_kb_from_cve(enriched_cve)

        # Generate threat summary
        threat_summary = create_threat_summary(enriched_cve)

        # Extract key information for agent response
        relationships = enriched_cve.get("relationships", {})

        result = {
            "cve_id": cve_id,
            "threat_level": threat_summary.get("threat_level", "UNKNOWN"),
            "exploitation_context": threat_summary.get("exploitation_context", "No context"),
            "total_relationships": relationships.get("total_relationships", 0),
            "malware_count": len(relationships.get("malwares", [])),
            "campaign_count": len(relationships.get("campaigns", [])),
            "actor_count": len(relationships.get("threat_actors", [])),
            "relationships": {
                "malwares": [
                    {
                        "name": m.get("name"),
                        "confidence": m.get("confidence"),
                        "types": m.get("malware_types", [])
                    }
                    for m in relationships.get("malwares", [])
                ],
                "campaigns": [
                    {
                        "name": c.get("name"),
                        "confidence": c.get("confidence")
                    }
                    for c in relationships.get("campaigns", [])
                ],
                "threat_actors": [
                    {
                        "name": a.get("name"),
                        "confidence": a.get("confidence"),
                        "aliases": a.get("aliases", [])
                    }
                    for a in relationships.get("threat_actors", [])
                ],
                "attack_techniques": relationships.get("attack_techniques", []),
                "total_relationships": relationships.get("total_relationships", 0)
            },
            "threat_summary": {
                "threat_level": threat_summary.get("threat_level"),
                "epss_score": threat_summary.get("epss_score"),
                "key_actors": threat_summary.get("key_actors", []),
                "key_campaigns": threat_summary.get("key_campaigns", []),
            },
            "status": "enriched" if relationships.get("total_relationships", 0) > 0 else "no_relationships",
            "persistence": {
                "status": persistence_result.get("status"),
                "malware_relationships": persistence_result.get("malware_relationships", 0),
                "campaign_relationships": persistence_result.get("campaign_relationships", 0),
                "actor_relationships": persistence_result.get("actor_relationships", 0),
            },
            "ioc_extraction": {
                "status": ioc_extraction.get("status"),
                "total_iocs": ioc_extraction.get("total_unique_iocs", 0),
            },
            "kb_population": {
                "status": kb_population.get("status"),
                "iocs_added": kb_population.get("iocs_added", 0),
                "iocs_updated": kb_population.get("iocs_updated", 0),
            }
        }

        print(f"  [RelationshipTool] SUCCESS: {result['total_relationships']} relationships found")
        print(f"  [RelationshipTool] PERSISTED: {persistence_result.get('total_persisted', 0)} relationships to Neo4j")
        print(f"  [RelationshipTool] IOC EXTRACTED: {ioc_extraction.get('total_unique_iocs', 0)} IOCs")
        print(f"  [RelationshipTool] KB POPULATED: {kb_population.get('iocs_added', 0)} added, {kb_population.get('iocs_updated', 0)} updated")
        return result

    except Exception as e:
        print(f"  [RelationshipTool] ERROR: {e}")
        return {
            "cve_id": cve_id,
            "status": "error",
            "error": str(e)
        }


def enrich_cve_batch(cve_ids: list) -> dict:
    """
    Enrich multiple CVEs with relationships.

    Args:
        cve_ids: List of CVE identifiers

    Returns: {
        "cves": [
            {"cve_id": "CVE-2021-44228", "threat_level": "CRITICAL", ...},
            ...
        ],
        "total_enriched": 5,
        "total_with_relationships": 4,
        "status": "completed"
    }
    """
    print(f"  [RelationshipTool] Enriching batch of {len(cve_ids)} CVEs...")

    results = []
    for cve_id in cve_ids:
        result = enrich_cve_relationships(cve_id)
        results.append(result)

    enriched_count = sum(1 for r in results if r.get("status") == "enriched")

    return {
        "cves": results,
        "total_enriched": len(results),
        "total_with_relationships": enriched_count,
        "status": "completed"
    }
