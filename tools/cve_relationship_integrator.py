# -*- coding: utf-8 -*-
"""
tools/cve_relationship_integrator.py - Integrate malware/campaign relationships into CVE enrichment

This module bridges the NVD CVE enrichment with OpenCTI relationship enrichment.

Flow:
CVE from NVD
    ↓
[enrich_cve_with_relationships]
    ├─→ Query malware families
    ├─→ Query campaigns
    ├─→ Query threat actors
    ├─→ Extract ATT&CK techniques
    ↓
Enhanced CVE object with relationships
    ↓
[Store in Neo4j]
    ↓
Available for Menu 2 reports + Menu 4 queries
"""

from tools.opencti_relationship_enricher import enrich_cve_with_relationships, extract_attack_techniques


def add_relationships_to_cve(cve_dict: dict) -> dict:
    """
    Enhance CVE object with relationship intelligence from OpenCTI.

    Takes a CVE from NVD and adds:
    - Malware families exploiting it
    - Campaigns leveraging it
    - Threat actors behind it
    - ATT&CK techniques from DIRECT OpenCTI relationships (authoritative source)

    Args:
        cve_dict: CVE object from NVD (with id, description, etc.)

    Returns: Enhanced CVE dict with "relationships" section
    """
    cve_id = cve_dict.get("id")
    if not cve_id:
        return cve_dict

    # Fetch relationships from OpenCTI (now includes attack_patterns from direct edges)
    enrichment = enrich_cve_with_relationships(cve_id)

    # Use DIRECT attack patterns from OpenCTI first (authoritative)
    # Only fall back to regex extraction if OpenCTI has no attack patterns
    attack_patterns = enrichment.get("attack_patterns", [])
    if not attack_patterns:
        # Fallback: extract from malware/actor descriptions if OpenCTI doesn't have direct patterns
        techniques = extract_attack_techniques(
            enrichment.get("malwares", []),
            enrichment.get("threat_actors", [])
        )
        attack_patterns = [{"technique_id": t, "source": "heuristic-extraction"} for t in techniques]

    # Add to CVE object
    cve_dict["relationships"] = {
        "malwares": enrichment.get("malwares", []),
        "campaigns": enrichment.get("campaigns", []),
        "threat_actors": enrichment.get("threat_actors", []),
        "attack_techniques": attack_patterns,  # Now from OpenCTI direct edges (authoritative)
        "total_relationships": enrichment.get("total_relationships", 0),
        "relationship_source": "OpenCTI",
        "relationship_status": enrichment.get("status", "unknown")
    }

    return cve_dict


def build_cve_relationship_graph(cve_dict: dict) -> dict:
    """
    Build graph representation of CVE and its relationships.

    Returns:
    {
        "nodes": [
            {"type": "CVE", "id": "CVE-2021-44228", "label": "Log4Shell"},
            {"type": "Malware", "id": "...", "label": "Conti", "confidence": 90},
            ...
        ],
        "edges": [
            {"from": "CVE-2021-44228", "to": "Conti", "relation": "exploited_by"},
            {"from": "Conti", "to": "Campaign-X", "relation": "used_in"},
            ...
        ]
    }
    """
    cve_id = cve_dict.get("id", "Unknown")
    cve_desc = cve_dict.get("description", "")[:100]

    nodes = [
        {
            "type": "CVE",
            "id": cve_id,
            "label": cve_id,
            "description": cve_desc,
            "severity": cve_dict.get("severity", "Unknown"),
            "epss_score": cve_dict.get("enrichment", {}).get("epss_score"),
        }
    ]

    edges = []

    # Add malware nodes and edges
    relationships = cve_dict.get("relationships", {})
    for malware in relationships.get("malwares", []):
        malware_id = malware.get("id", malware.get("name", "Unknown"))
        nodes.append({
            "type": "Malware",
            "id": malware_id,
            "label": malware.get("name", "Unknown"),
            "description": malware.get("description", ""),
            "confidence": malware.get("confidence", 0),
        })
        edges.append({
            "from": cve_id,
            "to": malware_id,
            "relation": "exploited_by_malware",
            "confidence": malware.get("confidence", 0),
        })

    # Add campaign nodes and edges
    for campaign in relationships.get("campaigns", []):
        campaign_id = campaign.get("id", campaign.get("name", "Unknown"))
        nodes.append({
            "type": "Campaign",
            "id": campaign_id,
            "label": campaign.get("name", "Unknown"),
            "description": campaign.get("description", ""),
            "confidence": campaign.get("confidence", 0),
        })
        edges.append({
            "from": cve_id,
            "to": campaign_id,
            "relation": "exploited_in_campaign",
            "confidence": campaign.get("confidence", 0),
        })

    # Add threat actor nodes and edges
    for actor in relationships.get("threat_actors", []):
        actor_id = actor.get("id", actor.get("name", "Unknown"))
        nodes.append({
            "type": "ThreatActor",
            "id": actor_id,
            "label": actor.get("name", "Unknown"),
            "aliases": actor.get("aliases", []),
            "description": actor.get("description", ""),
            "confidence": actor.get("confidence", 0),
        })
        edges.append({
            "from": cve_id,
            "to": actor_id,
            "relation": "exploited_by_actor",
            "confidence": actor.get("confidence", 0),
        })

    return {
        "cve_id": cve_id,
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "graph_density": len(edges) / max(len(nodes) - 1, 1) if len(nodes) > 1 else 0,
    }


def format_relationships_for_report(cve_dict: dict) -> str:
    """
    Format relationships for inclusion in Menu 2 reports.

    Returns formatted markdown/text for threat relationships.
    """
    relationships = cve_dict.get("relationships", {})

    if not relationships or relationships.get("total_relationships", 0) == 0:
        return "No known relationships with malware/campaigns found."

    report_lines = []

    # Malware section
    malwares = relationships.get("malwares", [])
    if malwares:
        report_lines.append("\n### Malware Families")
        for malware in malwares:
            name = malware.get("name", "Unknown")
            confidence = malware.get("confidence", 0)
            types = ", ".join(malware.get("malware_types", [])) or "unknown"
            report_lines.append(f"- **{name}** (confidence: {confidence}%, type: {types})")
            if malware.get("aliases"):
                aliases = ", ".join(malware.get("aliases", []))
                report_lines.append(f"  Aliases: {aliases}")

    # Campaign section
    campaigns = relationships.get("campaigns", [])
    if campaigns:
        report_lines.append("\n### Campaigns")
        for campaign in campaigns:
            name = campaign.get("name", "Unknown")
            confidence = campaign.get("confidence", 0)
            report_lines.append(f"- **{name}** (confidence: {confidence}%)")

    # Threat Actor section
    actors = relationships.get("threat_actors", [])
    if actors:
        report_lines.append("\n### Threat Actors")
        for actor in actors:
            name = actor.get("name", "Unknown")
            confidence = actor.get("confidence", 0)
            aliases = actor.get("aliases", [])
            report_lines.append(f"- **{name}** (confidence: {confidence}%)")
            if aliases:
                report_lines.append(f"  Also known as: {', '.join(aliases)}")

    # ATT&CK Techniques section
    techniques = relationships.get("attack_techniques", [])
    if techniques:
        report_lines.append("\n### ATT&CK Techniques")
        for technique in techniques:
            report_lines.append(f"- {technique}")

    return "\n".join(report_lines)


def create_threat_summary(cve_dict: dict) -> dict:
    """
    Create a threat summary combining CVE data with relationships.

    Returns:
    {
        "cve_id": "CVE-2021-44228",
        "severity": "CRITICAL",
        "epss_score": 0.94358,
        "threat_level": "CRITICAL",
        "exploitation_context": "Actively exploited by Conti, LockBit, and other ransomware groups",
        "key_actors": ["Conti", "LockBit", "ALPHV/BlackCat"],
        "key_campaigns": [...],
        "recommendations": [...]
    }
    """
    cve_id = cve_dict.get("id", "Unknown")
    severity = cve_dict.get("severity", "Unknown")
    epss_score = cve_dict.get("enrichment", {}).get("epss_score", 0)
    relationships = cve_dict.get("relationships", {})

    # Determine threat level
    threat_level = severity
    if epss_score > 0.95:
        threat_level = "CRITICAL"
    elif epss_score > 0.90:
        threat_level = "CRITICAL"
    elif epss_score > 0.80:
        threat_level = "HIGH"

    # Extract key actors and campaigns
    key_actors = [m.get("name") for m in relationships.get("malwares", [])][:5]
    key_campaigns = [c.get("name") for c in relationships.get("campaigns", [])][:3]
    actors = [a.get("name") for a in relationships.get("threat_actors", [])][:3]

    # Build exploitation context
    context_parts = []
    if key_actors:
        context_parts.append(f"exploited by {', '.join(key_actors)}")
    if key_campaigns:
        context_parts.append(f"used in campaigns: {', '.join(key_campaigns)}")
    if actors:
        context_parts.append(f"attributed to {', '.join(actors)}")

    exploitation_context = " and ".join(context_parts) if context_parts else "Limited exploitation intelligence available"

    return {
        "cve_id": cve_id,
        "severity": severity,
        "epss_score": epss_score,
        "threat_level": threat_level,
        "exploitation_context": exploitation_context,
        "key_actors": key_actors,
        "key_campaigns": key_campaigns,
        "threat_actors": actors,
        "total_relationships": relationships.get("total_relationships", 0),
        "intelligence_type": "enriched" if relationships.get("total_relationships", 0) > 0 else "basic",
    }
