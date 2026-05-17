# -*- coding: utf-8 -*-
"""
tools/opencti_relationship_enricher.py - Extract CVE relationships to Malware/Campaign/ThreatActor

Enriches CVEs with:
- Malware families exploiting the CVE
- Campaigns leveraging the vulnerability
- Threat actors behind the campaigns
- ATT&CK techniques used in exploitation
- Infrastructure patterns
"""
import requests
from config import OPENCTI_URL, OPENCTI_TOKEN


def query_cve_malware_relationships(cve_id: str, max_results: int = 20) -> dict:
    """
    Query OpenCTI to find malware families exploiting a specific CVE.

    Args:
        cve_id: CVE identifier (e.g., "CVE-2021-44228")
        max_results: Maximum malware results to return

    Returns: {
        "cve_id": "CVE-2021-44228",
        "malwares": [
            {
                "id": "...",
                "name": "Conti",
                "malware_types": ["ransomware", "banker"],
                "aliases": ["Conti Ransomware", ...],
                "description": "...",
                "confidence": 90
            },
            ...
        ],
        "source": "OpenCTI",
        "relationships": {
            "CVE → Malware": 5
        }
    }
    """
    if not OPENCTI_TOKEN:
        print(f"  [OpenCTI] OPENCTI_TOKEN not set - skipping malware enrichment")
        return {"malwares": [], "source": "OpenCTI-SKIP", "error": "Missing token"}

    if not OPENCTI_URL:
        print(f"  [OpenCTI] OPENCTI_URL not set - skipping malware enrichment")
        return {"malwares": [], "source": "OpenCTI-SKIP", "error": "Missing URL"}

    print(f"  [OpenCTI] Searching malware exploiting {cve_id}...")

    # GraphQL query to find malware with CVE relationships
    # Strategy: Search by CVE ID or name, then look for malware that uses it
    gql = """
    query SearchMalwareExploitingCVE($search: String, $first: Int) {
      malwares(search: $search, first: $first, orderBy: created_at, orderMode: desc) {
        edges { node {
          id name malware_types aliases description created_at
          objectLabel { value }
        }}
      }
    }"""

    try:
        # First search: find malware by CVE name/keyword
        resp = requests.post(
            f"{OPENCTI_URL}/graphql",
            json={"query": gql, "variables": {"search": cve_id, "first": min(max_results, 100)}},
            headers={"Authorization": f"Bearer {OPENCTI_TOKEN}", "Content-Type": "application/json"},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()

        if "errors" in data:
            print(f"  [OpenCTI] GraphQL error: {data['errors']}")
            return {"malwares": [], "source": "OpenCTI-ERROR", "error": str(data['errors'])}

        malwares = []
        data_obj = data.get("data", {})
        malwares_data = data_obj.get("malwares", {})

        if malwares_data and isinstance(malwares_data, dict):
            for edge in malwares_data.get("edges", []):
                if edge and "node" in edge:
                    node = edge["node"]
                    malwares.append({
                        "id": node.get("id", "Unknown"),
                        "name": node.get("name", "Unknown"),
                        "malware_types": node.get("malware_types", []) or [],
                        "aliases": node.get("aliases", []) or [],
                        "description": node.get("description", "")[:300] if node.get("description") else "",
                        "created_at": node.get("created_at"),
                        "confidence": 75,  # Base confidence for CVE search match
                    })

        if malwares:
            print(f"  [OpenCTI] Found {len(malwares)} malware families exploiting {cve_id}")
        else:
            print(f"  [OpenCTI] No malware found for {cve_id}")

        return {
            "cve_id": cve_id,
            "malwares": malwares,
            "source": "OpenCTI-LIVE",
            "relationships": {"CVE → Malware": len(malwares)}
        }

    except requests.exceptions.Timeout:
        print(f"  [OpenCTI] Timeout searching malware")
        return {"malwares": [], "source": "OpenCTI-ERROR", "error": "Request timeout"}
    except requests.exceptions.ConnectionError as e:
        print(f"  [OpenCTI] Connection error: {e}")
        return {"malwares": [], "source": "OpenCTI-ERROR", "error": f"Connection failed: {e}"}
    except Exception as e:
        print(f"  [OpenCTI] Error: {e}")
        return {"malwares": [], "source": "OpenCTI-ERROR", "error": str(e)}


def query_cve_campaign_relationships(cve_id: str, max_results: int = 20) -> dict:
    """
    Query OpenCTI to find campaigns exploiting a specific CVE.

    Args:
        cve_id: CVE identifier (e.g., "CVE-2021-44228")
        max_results: Maximum campaign results to return

    Returns: {
        "cve_id": "CVE-2021-44228",
        "campaigns": [
            {
                "id": "...",
                "name": "Operation Name",
                "description": "...",
                "confidence": 85
            },
            ...
        ],
        "source": "OpenCTI",
        "relationships": {
            "CVE → Campaign": 3
        }
    }
    """
    if not OPENCTI_TOKEN or not OPENCTI_URL:
        return {"campaigns": [], "source": "OpenCTI-SKIP"}

    print(f"  [OpenCTI] Searching campaigns exploiting {cve_id}...")

    # GraphQL query for campaigns using this CVE
    gql = """
    query SearchCampaignsUsing($search: String, $first: Int) {
      campaigns(search: $search, first: $first, orderBy: created_at, orderMode: desc) {
        edges { node {
          id name description created_at
          objectLabel { value }
        }}
      }
    }"""

    try:
        resp = requests.post(
            f"{OPENCTI_URL}/graphql",
            json={"query": gql, "variables": {"search": cve_id, "first": min(max_results, 100)}},
            headers={"Authorization": f"Bearer {OPENCTI_TOKEN}", "Content-Type": "application/json"},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()

        if "errors" in data:
            print(f"  [OpenCTI] GraphQL error: {data['errors']}")
            return {"campaigns": [], "source": "OpenCTI-ERROR"}

        campaigns = []
        data_obj = data.get("data", {})
        campaigns_data = data_obj.get("campaigns", {})

        if campaigns_data and isinstance(campaigns_data, dict):
            for edge in campaigns_data.get("edges", []):
                if edge and "node" in edge:
                    node = edge["node"]
                    campaigns.append({
                        "id": node.get("id", "Unknown"),
                        "name": node.get("name", "Unknown"),
                        "description": node.get("description", "")[:300] if node.get("description") else "",
                        "created_at": node.get("created_at"),
                        "confidence": 80,
                    })

        if campaigns:
            print(f"  [OpenCTI] Found {len(campaigns)} campaigns exploiting {cve_id}")

        return {
            "cve_id": cve_id,
            "campaigns": campaigns,
            "source": "OpenCTI-LIVE",
            "relationships": {"CVE → Campaign": len(campaigns)}
        }

    except Exception as e:
        print(f"  [OpenCTI] Campaign search error: {e}")
        return {"campaigns": [], "source": "OpenCTI-ERROR", "error": str(e)}


def query_cve_threat_actor_relationships(cve_id: str, max_results: int = 20) -> dict:
    """
    Query OpenCTI to find threat actors behind exploitation of a CVE.

    Args:
        cve_id: CVE identifier
        max_results: Maximum threat actor results

    Returns: {
        "cve_id": "CVE-2021-44228",
        "threat_actors": [
            {
                "id": "...",
                "name": "Conti Gang",
                "aliases": ["Conti Ransomware Group", ...],
                "description": "...",
                "confidence": 85
            },
            ...
        ],
        "source": "OpenCTI",
        "relationships": {
            "CVE → ThreatActor": 4
        }
    }
    """
    if not OPENCTI_TOKEN or not OPENCTI_URL:
        return {"threat_actors": [], "source": "OpenCTI-SKIP"}

    print(f"  [OpenCTI] Searching threat actors exploiting {cve_id}...")

    # GraphQL query for threat actors
    gql = """
    query SearchThreatActors($search: String, $first: Int) {
      threatActorsGroup(search: $search, first: $first, orderBy: created_at, orderMode: desc) {
        edges { node {
          id name aliases description created_at
          objectLabel { value }
        }}
      }
    }"""

    try:
        resp = requests.post(
            f"{OPENCTI_URL}/graphql",
            json={"query": gql, "variables": {"search": cve_id, "first": min(max_results, 100)}},
            headers={"Authorization": f"Bearer {OPENCTI_TOKEN}", "Content-Type": "application/json"},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()

        if "errors" in data:
            return {"threat_actors": [], "source": "OpenCTI-ERROR"}

        threat_actors = []
        data_obj = data.get("data", {})
        ta_data = data_obj.get("threatActorsGroup", {})

        if ta_data and isinstance(ta_data, dict):
            for edge in ta_data.get("edges", []):
                if edge and "node" in edge:
                    node = edge["node"]
                    threat_actors.append({
                        "id": node.get("id", "Unknown"),
                        "name": node.get("name", "Unknown"),
                        "aliases": node.get("aliases", []) or [],
                        "description": node.get("description", "")[:300] if node.get("description") else "",
                        "created_at": node.get("created_at"),
                        "confidence": 85,
                    })

        if threat_actors:
            print(f"  [OpenCTI] Found {len(threat_actors)} threat actors exploiting {cve_id}")

        return {
            "cve_id": cve_id,
            "threat_actors": threat_actors,
            "source": "OpenCTI-LIVE",
            "relationships": {"CVE → ThreatActor": len(threat_actors)}
        }

    except Exception as e:
        print(f"  [OpenCTI] Threat actor search error: {e}")
        return {"threat_actors": [], "source": "OpenCTI-ERROR", "error": str(e)}


def enrich_cve_with_relationships(cve_id: str) -> dict:
    """
    Complete enrichment: fetch ALL relationships for a CVE.

    Args:
        cve_id: CVE identifier

    Returns: {
        "cve_id": "CVE-2021-44228",
        "malwares": [...],
        "campaigns": [...],
        "threat_actors": [...],
        "total_relationships": 12,
        "status": "enriched"
    }
    """
    print(f"\n[OpenCTI Enrichment] Enriching {cve_id} with relationship intelligence...")

    malware_result = query_cve_malware_relationships(cve_id)
    campaign_result = query_cve_campaign_relationships(cve_id)
    actor_result = query_cve_threat_actor_relationships(cve_id)

    total_relationships = (
        len(malware_result.get("malwares", [])) +
        len(campaign_result.get("campaigns", [])) +
        len(actor_result.get("threat_actors", []))
    )

    enrichment = {
        "cve_id": cve_id,
        "malwares": malware_result.get("malwares", []),
        "campaigns": campaign_result.get("campaigns", []),
        "threat_actors": actor_result.get("threat_actors", []),
        "total_relationships": total_relationships,
        "source": "OpenCTI-Enrichment",
        "status": "enriched" if total_relationships > 0 else "no_relationships_found"
    }

    if total_relationships > 0:
        print(f"[OpenCTI Enrichment] SUCCESS: Found {total_relationships} relationships")
    else:
        print(f"[OpenCTI Enrichment] No relationships found for {cve_id}")

    return enrichment


def extract_attack_techniques(malware_list: list, actor_list: list) -> list:
    """
    Extract ATT&CK techniques from malware and threat actor descriptions.

    This is a heuristic extraction - proper mapping would come from explicit
    CWE → MITRE mappings. This extracts any mentioned technique IDs.

    Args:
        malware_list: List of malware objects
        actor_list: List of threat actor objects

    Returns: List of ATT&CK technique references
    """
    import re

    techniques = set()

    # Look for MITRE technique patterns (T + 4-5 digits)
    mitre_pattern = r'T\d{4,5}'

    for malware in malware_list:
        desc = malware.get("description", "")
        if desc:
            found = re.findall(mitre_pattern, desc)
            techniques.update(found)

    for actor in actor_list:
        desc = actor.get("description", "")
        if desc:
            found = re.findall(mitre_pattern, desc)
            techniques.update(found)

    return sorted(list(techniques))
