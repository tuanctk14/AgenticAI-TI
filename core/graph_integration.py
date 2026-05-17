"""
core/graph_integration.py - Knowledge Graph Integration Engine

Integrates threat entities into unified knowledge graph:
- Entity graph population from threat sources
- Relationship inference and validation
- Temporal evolution tracking
- Graph-based threat assessment
- Cross-layer threat correlation
"""

from typing import Dict, List, Optional, Set, Any, Tuple
from datetime import datetime, timedelta
from core.knowledge_graph import KnowledgeGraph, GraphNode, GraphEdge, NodeType, EdgeType
from core.threat_schema import (
    Vulnerability,
    IOC,
    Campaign,
    ThreatActor,
    Infrastructure,
    Asset,
    Relationship,
    RelationshipType,
)


class GraphIntegrationEngine:
    """Integrates threat entities into knowledge graph."""

    def __init__(self):
        """Initialize graph integration engine."""
        self.graph = KnowledgeGraph()
        self.entity_cache = {}  # Maps entity IDs to node IDs
        self.relationship_index = {}  # Maps relationship IDs to edge IDs

    def populate_vulnerability(self, vuln: Vulnerability) -> str:
        """Add vulnerability to graph.

        Args:
            vuln: Vulnerability object

        Returns:
            Node ID
        """
        node_id = f"vuln:{vuln.id}"

        properties = {
            "cve_id": vuln.id,
            "severity": vuln.severity.value if vuln.severity else None,
            "published": vuln.published_date,
            "description": vuln.description[:100] if vuln.description else "",
        }

        node = self.graph.add_node(
            node_id,
            NodeType.VULNERABILITY,
            properties,
            {"cve_id": vuln.id}
        )

        self.entity_cache[vuln.id] = node_id
        return node_id

    def populate_ioc(self, ioc: IOC) -> str:
        """Add IOC to graph.

        Args:
            ioc: IOC object

        Returns:
            Node ID
        """
        node_id = f"ioc:{ioc.ioc_type.value}:{ioc.value[:20]}"

        properties = {
            "type": ioc.ioc_type.value,
            "value": ioc.value,
            "severity": ioc.severity.value if ioc.severity else None,
            "first_seen": ioc.first_seen,
            "last_seen": ioc.last_seen,
        }

        node = self.graph.add_node(
            node_id,
            NodeType.IOC,
            properties,
            {"ioc_type": ioc.ioc_type.value, "value": ioc.value}
        )

        self.entity_cache[ioc.value] = node_id
        return node_id

    def populate_campaign(self, campaign: Campaign) -> str:
        """Add campaign to graph.

        Args:
            campaign: Campaign object

        Returns:
            Node ID
        """
        node_id = f"campaign:{campaign.id}"

        properties = {
            "campaign_id": campaign.id,
            "name": campaign.name,
            "start_date": campaign.start_date,
            "end_date": campaign.end_date,
            "sectors": campaign.sectors[:5] if campaign.sectors else [],
        }

        node = self.graph.add_node(
            node_id,
            NodeType.CAMPAIGN,
            properties,
            {"campaign_id": campaign.id}
        )

        self.entity_cache[campaign.id] = node_id
        return node_id

    def populate_actor(self, actor: ThreatActor) -> str:
        """Add threat actor to graph.

        Args:
            actor: ThreatActor object

        Returns:
            Node ID
        """
        node_id = f"actor:{actor.id}"

        properties = {
            "actor_id": actor.id,
            "name": actor.name,
            "aliases": actor.aliases[:5] if actor.aliases else [],
            "activity_level": actor.activity_level,
            "target_sectors": actor.target_sectors[:5] if actor.target_sectors else [],
        }

        node = self.graph.add_node(
            node_id,
            NodeType.ACTOR,
            properties,
            {"actor_id": actor.id}
        )

        self.entity_cache[actor.id] = node_id
        return node_id

    def populate_infrastructure(self, infra: Infrastructure) -> str:
        """Add infrastructure to graph.

        Args:
            infra: Infrastructure object

        Returns:
            Node ID
        """
        node_id = f"infra:{infra.id}"

        properties = {
            "infra_id": infra.id,
            "type": infra.node_type,
            "value": infra.value,
            "first_seen": infra.first_seen,
            "last_seen": infra.last_seen,
        }

        node = self.graph.add_node(
            node_id,
            NodeType.INFRASTRUCTURE,
            properties,
            {"infra_id": infra.id}
        )

        self.entity_cache[infra.id] = node_id
        return node_id

    def populate_asset(self, asset: Asset) -> str:
        """Add asset to graph.

        Args:
            asset: Asset object

        Returns:
            Node ID
        """
        node_id = f"asset:{asset.id}"

        properties = {
            "asset_id": asset.id,
            "hostname": asset.hostname,
            "ip_address": asset.ip_address,
            "criticality": asset.criticality,
        }

        node = self.graph.add_node(
            node_id,
            NodeType.ASSET,
            properties,
            {"asset_id": asset.id}
        )

        self.entity_cache[asset.id] = node_id
        return node_id

    def add_relationship(
        self,
        source_id: str,
        target_id: str,
        rel_type: str,
        weight: float = 1.0,
        confidence: float = 1.0
    ) -> Optional[str]:
        """Add relationship edge between entities.

        Args:
            source_id: Source entity ID (node ID)
            target_id: Target entity ID (node ID)
            rel_type: Relationship type
            weight: Edge weight
            confidence: Confidence score

        Returns:
            Edge ID or None
        """
        # Map relationship type string to edge type enum
        edge_type_map = {
            "exploits": EdgeType.EXPLOITS,
            "targets": EdgeType.TARGETS,
            "uses": EdgeType.USES,
            "part_of": EdgeType.PART_OF,
            "communicates_with": EdgeType.COMMUNICATES_WITH,
            "infrastructure": EdgeType.INFRASTRUCTURE,
            "attributed_to": EdgeType.ATTRIBUTED_TO,
            "similar_to": EdgeType.SIMILAR_TO,
            "related_to": EdgeType.RELATED_TO,
        }

        edge_type = edge_type_map.get(rel_type.lower(), EdgeType.RELATED_TO)

        edge = self.graph.add_edge(
            source_id,
            target_id,
            edge_type,
            weight,
            confidence
        )

        if edge:
            return edge.edge_id
        return None

    def get_threat_landscape(self, entity_id: str) -> Dict[str, Any]:
        """Get threat landscape around an entity.

        Args:
            entity_id: Node ID of entity

        Returns:
            Dict with threat relationships
        """
        if entity_id not in self.graph.nodes:
            return {}

        node = self.graph.get_node(entity_id)
        neighbors = self.graph.get_neighbors(entity_id)
        incoming = self.graph.get_incoming_nodes(entity_id)

        # Build relationship map
        outgoing_rels = {}
        for neighbor in neighbors:
            for edge in self.graph.edges.values():
                if edge.source_id == entity_id and edge.target_id == neighbor.node_id:
                    if edge.edge_type.value not in outgoing_rels:
                        outgoing_rels[edge.edge_type.value] = []
                    outgoing_rels[edge.edge_type.value].append(neighbor.to_dict())

        incoming_rels = {}
        for source in incoming:
            for edge in self.graph.edges.values():
                if edge.source_id == source.node_id and edge.target_id == entity_id:
                    if edge.edge_type.value not in incoming_rels:
                        incoming_rels[edge.edge_type.value] = []
                    incoming_rels[edge.edge_type.value].append(source.to_dict())

        return {
            "entity": node.to_dict(),
            "outgoing_relationships": outgoing_rels,
            "incoming_relationships": incoming_rels,
            "total_connections": len(neighbors) + len(incoming),
        }

    def find_attack_chain(self, source_id: str, target_id: str) -> Dict[str, Any]:
        """Find attack path from source to target.

        Args:
            source_id: Source entity ID
            target_id: Target entity ID

        Returns:
            Dict with attack chain details
        """
        paths = self.graph.find_all_paths(source_id, target_id, max_paths=5)

        if not paths:
            return {"found": False, "paths": []}

        chain_details = []
        for path in paths:
            path_nodes = [self.graph.get_node(nid) for nid in path]
            path_edges = []

            for i in range(len(path) - 1):
                for edge in self.graph.edges.values():
                    if edge.source_id == path[i] and edge.target_id == path[i + 1]:
                        path_edges.append(edge.to_dict())
                        break

            chain_details.append({
                "path": [n.to_dict() for n in path_nodes if n],
                "edges": path_edges,
                "length": len(path) - 1,
            })

        return {
            "found": True,
            "chains": chain_details,
            "chain_count": len(chain_details),
        }

    def detect_threat_clusters(self) -> List[Dict[str, Any]]:
        """Detect threat clusters in graph.

        Returns:
            List of cluster descriptions
        """
        components = self.graph.get_connected_components()
        clusters = []

        for component in components:
            if len(component) < 2:
                continue

            subgraph = self.graph.get_subgraph(list(component))
            influence = {}

            for node_id in component:
                inf = self.graph.get_entity_influence(node_id)
                influence[node_id] = inf

            # Find most influential node (cluster center)
            center_id = max(influence.keys(), key=lambda k: influence[k].get("influence_score", 0))

            clusters.append({
                "cluster_id": center_id,
                "size": len(component),
                "nodes": [self.graph.get_node(nid).to_dict() for nid in component if self.graph.get_node(nid)],
                "center": self.graph.get_node(center_id).to_dict() if self.graph.get_node(center_id) else None,
                "influence_map": influence,
            })

        return clusters

    def get_graph_intelligence(self) -> Dict[str, Any]:
        """Get comprehensive graph intelligence.

        Returns:
            Dict with full graph analysis
        """
        stats = self.graph.get_graph_stats()
        clusters = self.detect_threat_clusters()
        centrality = self.graph.calculate_degree_centrality()

        # Top influential entities
        top_entities = sorted(
            centrality.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]

        return {
            "timestamp": datetime.utcnow(),
            "graph_stats": stats,
            "clusters": clusters,
            "top_entities": [
                {
                    "node_id": nid,
                    "centrality": score,
                    "node": self.graph.get_node(nid).to_dict() if self.graph.get_node(nid) else None,
                }
                for nid, score in top_entities
            ],
            "cluster_count": len(clusters),
        }

    def export_graph_snapshot(self) -> Dict[str, Any]:
        """Export complete graph snapshot.

        Returns:
            Dict representation of graph
        """
        return {
            "timestamp": datetime.utcnow(),
            "graph": self.graph.to_dict(),
            "intelligence": self.get_graph_intelligence(),
        }
