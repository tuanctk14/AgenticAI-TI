"""
core/knowledge_graph.py - Knowledge Graph Integration

Unified threat knowledge graph:
- Entity node creation and management
- Relationship edge modeling
- Graph query engine with pattern matching
- Path discovery and traversal
- Influence scoring and centrality analysis
- Subgraph extraction and clustering
"""

from typing import Dict, List, Set, Optional, Tuple, Any
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
import json


class NodeType(Enum):
    """Knowledge graph node types."""
    VULNERABILITY = "vulnerability"
    IOC = "ioc"
    CAMPAIGN = "campaign"
    ACTOR = "actor"
    INFRASTRUCTURE = "infrastructure"
    ASSET = "asset"
    MALWARE = "malware"
    TECHNIQUE = "technique"


class EdgeType(Enum):
    """Knowledge graph edge types."""
    EXPLOITS = "exploits"
    TARGETS = "targets"
    USES = "uses"
    PART_OF = "part_of"
    COMMUNICATES_WITH = "communicates_with"
    INFRASTRUCTURE = "infrastructure"
    ATTRIBUTED_TO = "attributed_to"
    SIMILAR_TO = "similar_to"
    RELATED_TO = "related_to"


@dataclass
class GraphNode:
    """Knowledge graph node."""
    node_id: str
    node_type: NodeType
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert node to dictionary."""
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "properties": self.properties,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class GraphEdge:
    """Knowledge graph edge."""
    edge_id: str
    source_id: str
    target_id: str
    edge_type: EdgeType
    weight: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert edge to dictionary."""
        return {
            "edge_id": self.edge_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value,
            "weight": self.weight,
            "confidence": self.confidence,
            "created_at": self.created_at,
        }


class KnowledgeGraph:
    """Unified threat knowledge graph."""

    def __init__(self):
        """Initialize knowledge graph."""
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: Dict[str, GraphEdge] = {}
        self.adjacency: Dict[str, List[str]] = {}  # node_id -> [target_node_ids]
        self.reverse_adjacency: Dict[str, List[str]] = {}  # node_id -> [source_node_ids]

    def add_node(
        self,
        node_id: str,
        node_type: NodeType,
        properties: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> GraphNode:
        """Add node to graph.

        Args:
            node_id: Unique node identifier
            node_type: Type of node
            properties: Node properties
            metadata: Additional metadata

        Returns:
            Created GraphNode
        """
        if node_id in self.nodes:
            self.nodes[node_id].updated_at = datetime.utcnow()
            if properties:
                self.nodes[node_id].properties.update(properties)
            return self.nodes[node_id]

        node = GraphNode(
            node_id=node_id,
            node_type=node_type,
            properties=properties or {},
            metadata=metadata or {}
        )
        self.nodes[node_id] = node
        self.adjacency[node_id] = []
        self.reverse_adjacency[node_id] = []
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType,
        weight: float = 1.0,
        confidence: float = 1.0,
        properties: Optional[Dict[str, Any]] = None
    ) -> GraphEdge:
        """Add edge between nodes.

        Args:
            source_id: Source node ID
            target_id: Target node ID
            edge_type: Type of relationship
            weight: Edge weight (importance)
            confidence: Confidence score (0.0-1.0)
            properties: Edge properties

        Returns:
            Created GraphEdge
        """
        if source_id not in self.nodes or target_id not in self.nodes:
            return None

        edge_id = f"{source_id}-{edge_type.value}-{target_id}"

        if edge_id in self.edges:
            self.edges[edge_id].weight = weight
            self.edges[edge_id].confidence = confidence
            return self.edges[edge_id]

        edge = GraphEdge(
            edge_id=edge_id,
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            weight=weight,
            confidence=confidence,
            properties=properties or {}
        )
        self.edges[edge_id] = edge
        self.adjacency[source_id].append(target_id)
        self.reverse_adjacency[target_id].append(source_id)
        return edge

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Get node by ID.

        Args:
            node_id: Node identifier

        Returns:
            GraphNode or None
        """
        return self.nodes.get(node_id)

    def get_neighbors(self, node_id: str) -> List[GraphNode]:
        """Get neighboring nodes.

        Args:
            node_id: Node identifier

        Returns:
            List of neighboring nodes
        """
        if node_id not in self.adjacency:
            return []
        return [self.nodes[nid] for nid in self.adjacency[node_id]]

    def get_incoming_nodes(self, node_id: str) -> List[GraphNode]:
        """Get nodes with edges to this node.

        Args:
            node_id: Node identifier

        Returns:
            List of source nodes
        """
        if node_id not in self.reverse_adjacency:
            return []
        return [self.nodes[nid] for nid in self.reverse_adjacency[node_id]]

    def find_path(self, source_id: str, target_id: str, max_depth: int = 5) -> Optional[List[str]]:
        """Find path between two nodes (BFS).

        Args:
            source_id: Source node ID
            target_id: Target node ID
            max_depth: Maximum path depth

        Returns:
            List of node IDs forming path, or None
        """
        if source_id not in self.nodes or target_id not in self.nodes:
            return None

        if source_id == target_id:
            return [source_id]

        visited = {source_id}
        queue = [(source_id, [source_id])]
        depth = 0

        while queue and depth < max_depth:
            node_id, path = queue.pop(0)

            for neighbor_id in self.adjacency.get(node_id, []):
                if neighbor_id == target_id:
                    return path + [neighbor_id]

                if neighbor_id not in visited:
                    visited.add(neighbor_id)
                    queue.append((neighbor_id, path + [neighbor_id]))

            if len(path) >= max_depth:
                depth += 1

        return None

    def find_all_paths(self, source_id: str, target_id: str, max_paths: int = 10) -> List[List[str]]:
        """Find multiple paths between nodes.

        Args:
            source_id: Source node ID
            target_id: Target node ID
            max_paths: Maximum paths to return

        Returns:
            List of paths
        """
        if source_id not in self.nodes or target_id not in self.nodes:
            return []

        paths = []
        visited_paths = set()

        def dfs(node_id: str, target: str, path: List[str], visited: Set[str]):
            if len(paths) >= max_paths:
                return

            if node_id == target:
                path_tuple = tuple(path)
                if path_tuple not in visited_paths:
                    visited_paths.add(path_tuple)
                    paths.append(path.copy())
                return

            if len(path) > 5:  # Max depth
                return

            for neighbor_id in self.adjacency.get(node_id, []):
                if neighbor_id not in visited or neighbor_id == target:
                    visited_copy = visited.copy()
                    visited_copy.add(neighbor_id)
                    dfs(neighbor_id, target, path + [neighbor_id], visited_copy)

        dfs(source_id, target_id, [source_id], {source_id})
        return paths

    def get_subgraph(self, node_ids: List[str]) -> 'KnowledgeGraph':
        """Extract subgraph containing specified nodes.

        Args:
            node_ids: List of node IDs

        Returns:
            New KnowledgeGraph with subgraph
        """
        subgraph = KnowledgeGraph()
        node_set = set(node_ids)

        # Add nodes
        for node_id in node_ids:
            if node_id in self.nodes:
                node = self.nodes[node_id]
                subgraph.add_node(
                    node.node_id,
                    node.node_type,
                    node.properties.copy(),
                    node.metadata.copy()
                )

        # Add edges between nodes in subgraph
        for edge in self.edges.values():
            if edge.source_id in node_set and edge.target_id in node_set:
                subgraph.add_edge(
                    edge.source_id,
                    edge.target_id,
                    edge.edge_type,
                    edge.weight,
                    edge.confidence,
                    edge.properties.copy()
                )

        return subgraph

    def calculate_degree_centrality(self) -> Dict[str, float]:
        """Calculate degree centrality for all nodes.

        Returns:
            Dict mapping node_id to centrality score
        """
        if not self.nodes:
            return {}

        max_degree = len(self.nodes) - 1
        centrality = {}

        for node_id in self.nodes:
            degree = len(self.adjacency.get(node_id, [])) + len(self.reverse_adjacency.get(node_id, []))
            centrality[node_id] = degree / max_degree if max_degree > 0 else 0.0

        return centrality

    def calculate_betweenness_centrality(self) -> Dict[str, float]:
        """Calculate betweenness centrality (simplified).

        Returns:
            Dict mapping node_id to centrality score
        """
        centrality = {node_id: 0.0 for node_id in self.nodes}

        # Count how many shortest paths pass through each node
        for source in self.nodes:
            for target in self.nodes:
                if source != target:
                    path = self.find_path(source, target)
                    if path:
                        for node_id in path[1:-1]:  # Exclude source and target
                            centrality[node_id] += 1.0

        # Normalize
        if self.nodes:
            max_count = sum(centrality.values()) / len(self.nodes) if centrality.values() else 1
            for node_id in centrality:
                centrality[node_id] = centrality[node_id] / max_count if max_count > 0 else 0.0

        return centrality

    def get_connected_components(self) -> List[Set[str]]:
        """Find connected components in graph.

        Returns:
            List of node ID sets (components)
        """
        visited = set()
        components = []

        def dfs(node_id: str, component: Set[str]):
            visited.add(node_id)
            component.add(node_id)

            for neighbor_id in self.adjacency.get(node_id, []):
                if neighbor_id not in visited:
                    dfs(neighbor_id, component)

            for source_id in self.reverse_adjacency.get(node_id, []):
                if source_id not in visited:
                    dfs(source_id, component)

        for node_id in self.nodes:
            if node_id not in visited:
                component = set()
                dfs(node_id, component)
                if component:
                    components.append(component)

        return components

    def get_entity_influence(self, node_id: str) -> Dict[str, Any]:
        """Calculate influence score for entity.

        Args:
            node_id: Node identifier

        Returns:
            Dict with influence metrics
        """
        if node_id not in self.nodes:
            return {}

        degree_cent = self.calculate_degree_centrality()
        betweenness_cent = self.calculate_betweenness_centrality()

        neighbors = self.get_neighbors(node_id)
        incoming = self.get_incoming_nodes(node_id)

        # Calculate influence as weighted combination
        influence_score = (
            (degree_cent.get(node_id, 0.0) * 0.3) +
            (betweenness_cent.get(node_id, 0.0) * 0.4) +
            (len(neighbors) / max(len(self.nodes), 1) * 0.2) +
            (len(incoming) / max(len(self.nodes), 1) * 0.1)
        )

        return {
            "node_id": node_id,
            "influence_score": min(influence_score, 1.0),
            "degree_centrality": degree_cent.get(node_id, 0.0),
            "betweenness_centrality": betweenness_cent.get(node_id, 0.0),
            "outgoing_edges": len(neighbors),
            "incoming_edges": len(incoming),
            "total_edges": len(neighbors) + len(incoming),
        }

    def get_graph_stats(self) -> Dict[str, Any]:
        """Get graph statistics.

        Returns:
            Dict with graph metrics
        """
        total_edges = len(self.edges)
        components = self.get_connected_components()

        edge_types = {}
        for edge in self.edges.values():
            edge_type = edge.edge_type.value
            edge_types[edge_type] = edge_types.get(edge_type, 0) + 1

        node_types = {}
        for node in self.nodes.values():
            node_type = node.node_type.value
            node_types[node_type] = node_types.get(node_type, 0) + 1

        avg_degree = (total_edges * 2) / len(self.nodes) if self.nodes else 0.0

        return {
            "total_nodes": len(self.nodes),
            "total_edges": total_edges,
            "node_types": node_types,
            "edge_types": edge_types,
            "connected_components": len(components),
            "avg_degree": avg_degree,
            "largest_component": max((len(c) for c in components), default=0),
        }

    def query_nodes(
        self,
        node_type: Optional[NodeType] = None,
        properties: Optional[Dict[str, Any]] = None
    ) -> List[GraphNode]:
        """Query nodes by type and properties.

        Args:
            node_type: Filter by node type
            properties: Filter by properties

        Returns:
            List of matching nodes
        """
        results = []

        for node in self.nodes.values():
            if node_type and node.node_type != node_type:
                continue

            if properties:
                match = True
                for key, value in properties.items():
                    if node.properties.get(key) != value:
                        match = False
                        break
                if not match:
                    continue

            results.append(node)

        return results

    def export_graphml(self) -> str:
        """Export graph as GraphML format.

        Returns:
            GraphML XML string
        """
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
            '<graph mode="static" directed="true">',
        ]

        # Add nodes
        for node in self.nodes.values():
            lines.append(f'  <node id="{node.node_id}" label="{node.node_id}"/>')

        # Add edges
        for edge in self.edges.values():
            lines.append(
                f'  <edge source="{edge.source_id}" target="{edge.target_id}" '
                f'label="{edge.edge_type.value}" weight="{edge.weight}"/>'
            )

        lines.append('</graph>')
        lines.append('</graphml>')

        return '\n'.join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Convert graph to dictionary.

        Returns:
            Dict representation of graph
        """
        return {
            "nodes": [node.to_dict() for node in self.nodes.values()],
            "edges": [edge.to_dict() for edge in self.edges.values()],
            "stats": self.get_graph_stats(),
        }
