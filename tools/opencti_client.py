"""
tools/opencti_client.py - Lấy Threat Intelligence từ OpenCTI (chỉ dùng API thật)
"""
import requests
from config import OPENCTI_URL, OPENCTI_TOKEN


def fetch_opencti_indicators(search_term: str = "", indicator_type: str = "all") -> dict:
    """
    Truy vấn OpenCTI GraphQL API để lấy IOC, Malware, Threat Actors, Attack Patterns.

    Queries multiple entity types:
    - indicators: IOC patterns (file hashes, domains, etc.)
    - malwares: Malware families
    - threat_actors: APT/Threat Actor groups
    - attack_patterns: ATT&CK patterns

    Required: OPENCTI_TOKEN environment variable phải được set.
    """
    print(f"  [OpenCTI] Tìm: term='{search_term}', type='{indicator_type}'")

    # Bắt buộc có OPENCTI_TOKEN
    if not OPENCTI_TOKEN:
        print(f"  [OpenCTI] ❌ OPENCTI_TOKEN không được set")
        return {"context": [], "source": "OpenCTI-ERROR", "error": "Missing OPENCTI_TOKEN"}

    if not OPENCTI_URL:
        print(f"  [OpenCTI] ❌ OPENCTI_URL không được set")
        return {"context": [], "source": "OpenCTI-ERROR", "error": "Missing OPENCTI_URL"}

    # Multi-query GraphQL: lấy indicators + malwares + threatActorsGroup
    # Simplified: removed stixCoreRelationships which causes subscription errors
    gql = """
    query GetThreatIntel($search: String, $first: Int) {
      indicators(search: $search, first: $first) {
        edges { node {
          id name indicator_types pattern confidence description
        }}
      }
      malwares(search: $search, first: $first) {
        edges { node {
          id name aliases description
        }}
      }
      threatActorsGroup(search: $search, first: $first) {
        edges { node {
          id name aliases description
        }}
      }
      attackPatterns(search: $search, first: $first) {
        edges { node {
          id name description
        }}
      }
    }"""

    try:
        resp = requests.post(
            f"{OPENCTI_URL}/graphql",
            json={"query": gql, "variables": {"search": search_term, "first": 50}},
            headers={"Authorization": f"Bearer {OPENCTI_TOKEN}", "Content-Type": "application/json"},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()

        if "errors" in data:
            print(f"  [OpenCTI] ❌ GraphQL error: {data['errors']}")
            return {"context": [], "source": "OpenCTI-ERROR", "error": str(data['errors'])}

        results = []
        data_obj = data.get("data", {})

        # Process indicators - handle potential None values
        indicators_data = data_obj.get("indicators")
        if indicators_data and isinstance(indicators_data, dict):
            for edge in indicators_data.get("edges", []):
                if edge and "node" in edge:
                    n = edge["node"]
                    results.append({
                        "id": n.get("id", "Unknown"), "name": n.get("name", "Unknown"),
                        "entity_type": "Indicator",
                        "types": n.get("indicator_types", []),
                        "pattern": n.get("pattern", "")[:200] if n.get("pattern") else "",
                        "score": 75,
                        "confidence": n.get("confidence", 0),
                        "description": n.get("description", "")[:300] if n.get("description") else "",
                    })

        # Process malwares
        malwares_data = data_obj.get("malwares")
        if malwares_data and isinstance(malwares_data, dict):
            for edge in malwares_data.get("edges", []):
                if edge and "node" in edge:
                    n = edge["node"]
                    results.append({
                        "id": n.get("id", "Unknown"), "name": n.get("name", "Unknown"),
                        "entity_type": "Malware",
                        "aliases": n.get("aliases", []) or [],
                        "score": 80,
                        "description": n.get("description", "")[:300] if n.get("description") else "",
                    })

        # Process threat actors
        threat_actors_data = data_obj.get("threatActorsGroup")
        if threat_actors_data and isinstance(threat_actors_data, dict):
            for edge in threat_actors_data.get("edges", []):
                if edge and "node" in edge:
                    n = edge["node"]
                    results.append({
                        "id": n.get("id", "Unknown"), "name": n.get("name", "Unknown"),
                        "entity_type": "Threat Actor",
                        "aliases": n.get("aliases", []) or [],
                        "score": 85,
                        "description": n.get("description", "")[:300] if n.get("description") else "",
                    })

        # Process attack patterns
        attack_patterns_data = data_obj.get("attackPatterns")
        if attack_patterns_data and isinstance(attack_patterns_data, dict):
            for edge in attack_patterns_data.get("edges", []):
                if edge and "node" in edge:
                    n = edge["node"]
                    results.append({
                        "id": n.get("id", "Unknown"), "name": n.get("name", "Unknown"),
                        "entity_type": "Attack Pattern",
                        "score": 70,
                        "description": n.get("description", "")[:300] if n.get("description") else "",
                    })

        if results:
            entity_counts = {}
            for r in results:
                et = r.get("entity_type", "Unknown")
                entity_counts[et] = entity_counts.get(et, 0) + 1
            breakdown = ", ".join([f"{count} {entity_type}" for entity_type, count in entity_counts.items()])
            print(f"  [OpenCTI] ✅ {len(results)} results: {breakdown}")
        else:
            print(f"  [OpenCTI] ✅ 0 results found")
        return {"context": results, "source": "OpenCTI-LIVE"}

    except requests.exceptions.Timeout:
        print(f"  [OpenCTI] ⏱️  Timeout - OpenCTI server không phản hồi")
        return {"context": [], "source": "OpenCTI-ERROR", "error": "Request timeout"}
    except requests.exceptions.ConnectionError as e:
        print(f"  [OpenCTI] 🔌 Connection error - {e}")
        return {"context": [], "source": "OpenCTI-ERROR", "error": f"Connection failed: {e}"}
    except Exception as e:
        print(f"  [OpenCTI] ❌ Error: {e}")
        return {"context": [], "source": "OpenCTI-ERROR", "error": str(e)}
