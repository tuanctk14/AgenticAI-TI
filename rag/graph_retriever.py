"""
rag/graph_retriever.py - GraphRetriever để lấy context từ Neo4j graph.

Extract entities từ query (CVE, IP, hash, malware) → traverse 1-2 hop → return related nodes.
"""

import re
from typing import List, Dict, Tuple, Optional


class GraphRetriever:
    """Retrieve related threat intelligence từ knowledge graph."""

    def __init__(self, graph_client=None):
        """Khởi tạo GraphRetriever.

        Args:
            graph_client: Neo4j driver hoặc mock client (tạm thời optional)
        """
        self.graph_client = graph_client
        # Entity patterns
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d+')
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.hash_pattern = re.compile(r'\b[a-f0-9]{32,64}\b')

    def extract_entities(self, query: str) -> Dict[str, List[str]]:
        """Extract entities từ query string.

        Returns:
            {
                "cves": [...],
                "ips": [...],
                "hashes": [...],
                "malwares": [...]
            }
        """
        entities = {
            "cves": self.cve_pattern.findall(query),
            "ips": self.ip_pattern.findall(query),
            "hashes": self.hash_pattern.findall(query),
            "malwares": []  # Would need malware family list from KB
        }
        return entities

    def retrieve_related_nodes(
        self,
        entity_type: str,
        entity_value: str,
        hops: int = 1
    ) -> List[Dict]:
        """Retrieve related nodes từ graph.

        Args:
            entity_type: Loại entity (CVE, IP, hash, malware)
            entity_value: Giá trị entity
            hops: Số hop traversal (1 hoặc 2)

        Returns:
            List[Dict] với {id, type, score, ...}
        """
        if not self.graph_client:
            # Mock implementation - trả về empty list
            return []

        results = []

        try:
            # Query logic sẽ được implement khi integrate Neo4j
            # Tạm thời: return mock results để test hybrid search
            if entity_type == "CVE":
                # Simulate finding related CVEs, IOCs, campaigns
                results = [
                    {"id": f"IOC-related-1", "type": "IOC", "score": 1.0},
                    {"id": f"CAMPAIGN-related-1", "type": "Campaign", "score": 0.8},
                    {"id": f"ACTOR-related-1", "type": "Actor", "score": 0.6},
                ]

        except Exception as e:
            pass  # Silent fail

        return results

    def hybrid_retrieve(
        self,
        query: str,
        top_k: int = 10
    ) -> List[Dict]:
        """Retrieve hybrid results: entities + related nodes.

        Args:
            query: Query string
            top_k: Số kết quả

        Returns:
            List[Dict] with {id, type, score, hop_distance}
        """
        results = []

        # Extract entities
        entities = self.extract_entities(query)

        # For each entity type, retrieve related nodes
        for entity_type, values in entities.items():
            if not values:
                continue

            for value in values[:3]:  # Limit to top 3 per type
                # 1-hop
                related_1hop = self.retrieve_related_nodes(entity_type, value, hops=1)
                for node in related_1hop:
                    node["hop_distance"] = 1
                    results.append(node)

                # 2-hop (discount score)
                related_2hop = self.retrieve_related_nodes(entity_type, value, hops=2)
                for node in related_2hop:
                    node["score"] = (node.get("score", 0.5)) * 0.5  # Discount
                    node["hop_distance"] = 2
                    results.append(node)

        # Deduplicate by ID and sort by score
        seen = set()
        deduped = []
        for r in sorted(results, key=lambda x: x.get("score", 0), reverse=True):
            rid = r.get("id")
            if rid not in seen:
                seen.add(rid)
                deduped.append(r)

        return deduped[:top_k]
