"""
tools/opencti_client.py - Lấy Threat Intelligence từ OpenCTI (chỉ dùng API thật)
"""
import requests
from config import OPENCTI_URL, OPENCTI_TOKEN


def fetch_opencti_indicators(search_term: str = "", indicator_type: str = "all", start_date: str = None, end_date: str = None, max_results: int = 50) -> dict:
    """
    Truy vấn OpenCTI GraphQL API để lấy IOC, Malware, Threat Actors, Attack Patterns.

    Queries multiple entity types:
    - indicators: IOC patterns (file hashes, domains, etc.)
    - malwares: Malware families
    - threat_actors: APT/Threat Actor groups
    - attack_patterns: ATT&CK patterns

    Args:
        search_term: Từ khóa tìm kiếm
        indicator_type: Loại indicator (all | indicator | malware | threat_actor | attack_pattern)
        start_date: ISO format để lọc theo ngày tạo (hiện tại không hỗ trợ, nhưng có thể dùng trong tương lai)
        end_date: ISO format để lọc theo ngày tạo (hiện tại không hỗ trợ, nhưng có thể dùng trong tương lai)
        max_results: Max results per entity type (default 50, max 500 từ API)

    Note: OpenCTI API sắp xếp theo created_at desc (mới nhất trước), nên lấy top N là đủ

    Required: OPENCTI_TOKEN environment variable phải được set.
    """
    print(f"  [OpenCTI] Tìm: term='{search_term}', type='{indicator_type}', max_results_per_type={max_results}")

    # Bắt buộc có OPENCTI_TOKEN
    if not OPENCTI_TOKEN:
        print(f"  [OpenCTI] ❌ OPENCTI_TOKEN không được set")
        return {"context": [], "source": "OpenCTI-ERROR", "error": "Missing OPENCTI_TOKEN"}

    if not OPENCTI_URL:
        print(f"  [OpenCTI] ❌ OPENCTI_URL không được set")
        return {"context": [], "source": "OpenCTI-ERROR", "error": "Missing OPENCTI_URL"}

    # Multi-query GraphQL: lấy indicators + malwares + threatActorsGroup + attackPatterns
    # Với ordering theo created_at desc (mới nhất trước)
    # Lấy created_at field để lọc theo date range (client-side)
    gql = """
    query GetThreatIntel($search: String, $first: Int) {
      indicators(search: $search, first: $first, orderBy: created_at, orderMode: desc) {
        edges { node {
          id name indicator_types pattern confidence description created_at
        }}
      }
      malwares(search: $search, first: $first, orderBy: created_at, orderMode: desc) {
        edges { node {
          id name malware_types aliases description created_at
        }}
      }
      threatActorsGroup(search: $search, first: $first, orderBy: created_at, orderMode: desc) {
        edges { node {
          id name aliases description created_at
        }}
      }
      attackPatterns(search: $search, first: $first, orderBy: created_at, orderMode: desc) {
        edges { node {
          id name x_mitre_id description created_at
        }}
      }
    }"""

    try:
        resp = requests.post(
            f"{OPENCTI_URL}/graphql",
            json={"query": gql, "variables": {"search": search_term, "first": min(max_results, 500)}},
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
                        "created_at": n.get("created_at"),
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
                        "malware_types": n.get("malware_types", []) or [],
                        "aliases": n.get("aliases", []) or [],
                        "score": 80,
                        "description": n.get("description", "")[:300] if n.get("description") else "",
                        "created_at": n.get("created_at"),
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
                        "created_at": n.get("created_at"),
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
                        "technique_id": n.get("x_mitre_id", "N/A"),
                        "score": 70,
                        "description": n.get("description", "")[:300] if n.get("description") else "",
                        "created_at": n.get("created_at"),
                    })

        # Client-side date filtering dùng created_at field
        if start_date or end_date:
            from datetime import datetime, timezone
            filtered_results = []
            for r in results:
                created_at_str = r.get("created_at")
                if not created_at_str:
                    # Nếu không có created_at, skip entity này vì lọc theo date
                    continue

                try:
                    # Parse created_at (format: 2026-05-05T06:05:18.797Z) - luôn có timezone
                    created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))

                    # Lọc theo start_date - ensure timezone aware
                    if start_date:
                        # start_date từ main.py không có Z suffix, nên thêm +00:00
                        start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                        # Nếu naive, thêm timezone UTC
                        if start_dt.tzinfo is None:
                            start_dt = start_dt.replace(tzinfo=timezone.utc)
                        if created_at < start_dt:
                            continue

                    # Lọc theo end_date - ensure timezone aware
                    if end_date:
                        # end_date từ main.py không có Z suffix, nên thêm +00:00
                        end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                        # Nếu naive, thêm timezone UTC
                        if end_dt.tzinfo is None:
                            end_dt = end_dt.replace(tzinfo=timezone.utc)
                        if created_at > end_dt:
                            continue

                    filtered_results.append(r)
                except (ValueError, AttributeError, TypeError) as e:
                    # Nếu parse fail, skip entity này
                    continue

            results = filtered_results
            if len(results) == 0:
                print(f"  [OpenCTI] ℹ️  No results in date range")

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
