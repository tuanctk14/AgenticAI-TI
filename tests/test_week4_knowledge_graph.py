"""
tests/test_week4_knowledge_graph.py - Knowledge Graph Tests

Tests for:
- Knowledge graph creation and node management
- Edge relationships and path discovery
- Centrality analysis and influence scoring
- Graph queries and subgraph extraction
- Integration with threat entities
- Threat landscape and attack chain analysis
"""

import pytest
from datetime import datetime, timedelta

from core.knowledge_graph import (
    KnowledgeGraph,
    GraphNode,
    GraphEdge,
    NodeType,
    EdgeType,
)
from core.graph_integration import GraphIntegrationEngine
from core.threat_schema import (
    Vulnerability,
    IOC,
    Campaign,
    ThreatActor,
    Infrastructure,
    Asset,
)


class TestGraphNode:
    """Test graph node functionality."""

    def test_create_graph_node(self):
        """Test creating graph node."""
        node = GraphNode("node-1", NodeType.VULNERABILITY)

        assert node.node_id == "node-1"
        assert node.node_type == NodeType.VULNERABILITY
        assert node.properties == {}
        assert node.metadata == {}

    def test_graph_node_with_properties(self):
        """Test node with properties."""
        props = {"severity": "high", "cvss": 9.0}
        node = GraphNode("node-2", NodeType.IOC, properties=props)

        assert node.properties == props
        assert node.properties["severity"] == "high"

    def test_graph_node_serialization(self):
        """Test node serialization."""
        node = GraphNode("node-3", NodeType.CAMPAIGN, properties={"name": "APT"})
        data = node.to_dict()

        assert data["node_id"] == "node-3"
        assert data["node_type"] == "campaign"
        assert data["properties"]["name"] == "APT"


class TestGraphEdge:
    """Test graph edge functionality."""

    def test_create_graph_edge(self):
        """Test creating graph edge."""
        edge = GraphEdge("edge-1", "source", "target", EdgeType.EXPLOITS)

        assert edge.edge_id == "edge-1"
        assert edge.source_id == "source"
        assert edge.target_id == "target"
        assert edge.edge_type == EdgeType.EXPLOITS
        assert edge.weight == 1.0
        assert edge.confidence == 1.0

    def test_graph_edge_with_weight(self):
        """Test edge with custom weight."""
        edge = GraphEdge("edge-2", "src", "tgt", EdgeType.TARGETS, weight=0.8, confidence=0.95)

        assert edge.weight == 0.8
        assert edge.confidence == 0.95

    def test_graph_edge_serialization(self):
        """Test edge serialization."""
        edge = GraphEdge("edge-3", "s", "t", EdgeType.RELATED_TO, weight=0.7)
        data = edge.to_dict()

        assert data["edge_id"] == "edge-3"
        assert data["source_id"] == "s"
        assert data["edge_type"] == "related_to"
        assert data["weight"] == 0.7


class TestKnowledgeGraph:
    """Test knowledge graph operations."""

    def test_create_knowledge_graph(self):
        """Test creating knowledge graph."""
        graph = KnowledgeGraph()

        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0

    def test_add_node(self):
        """Test adding node to graph."""
        graph = KnowledgeGraph()
        node = graph.add_node("vuln-1", NodeType.VULNERABILITY)

        assert "vuln-1" in graph.nodes
        assert node.node_type == NodeType.VULNERABILITY

    def test_add_multiple_nodes(self):
        """Test adding multiple nodes."""
        graph = KnowledgeGraph()

        for i in range(5):
            graph.add_node(f"node-{i}", NodeType.IOC)

        assert len(graph.nodes) == 5

    def test_add_edge(self):
        """Test adding edge between nodes."""
        graph = KnowledgeGraph()
        graph.add_node("vuln-1", NodeType.VULNERABILITY)
        graph.add_node("ioc-1", NodeType.IOC)

        edge = graph.add_edge("vuln-1", "ioc-1", EdgeType.EXPLOITS)

        assert edge is not None
        assert edge.source_id == "vuln-1"
        assert edge.target_id == "ioc-1"

    def test_get_neighbors(self):
        """Test getting neighboring nodes."""
        graph = KnowledgeGraph()
        graph.add_node("n1", NodeType.VULNERABILITY)
        graph.add_node("n2", NodeType.IOC)
        graph.add_node("n3", NodeType.CAMPAIGN)
        graph.add_edge("n1", "n2", EdgeType.EXPLOITS)
        graph.add_edge("n1", "n3", EdgeType.TARGETS)

        neighbors = graph.get_neighbors("n1")

        assert len(neighbors) == 2

    def test_find_path_direct(self):
        """Test finding direct path."""
        graph = KnowledgeGraph()
        graph.add_node("src", NodeType.IOC)
        graph.add_node("tgt", NodeType.IOC)
        graph.add_edge("src", "tgt", EdgeType.RELATED_TO)

        path = graph.find_path("src", "tgt")

        assert path == ["src", "tgt"]

    def test_find_path_indirect(self):
        """Test finding indirect path."""
        graph = KnowledgeGraph()
        for i in range(4):
            graph.add_node(f"n{i}", NodeType.IOC)

        graph.add_edge("n0", "n1", EdgeType.RELATED_TO)
        graph.add_edge("n1", "n2", EdgeType.RELATED_TO)
        graph.add_edge("n2", "n3", EdgeType.RELATED_TO)

        path = graph.find_path("n0", "n3")

        assert path == ["n0", "n1", "n2", "n3"]

    def test_find_path_not_found(self):
        """Test path not found."""
        graph = KnowledgeGraph()
        graph.add_node("n1", NodeType.IOC)
        graph.add_node("n2", NodeType.IOC)

        path = graph.find_path("n1", "n2")

        assert path is None

    def test_find_all_paths(self):
        """Test finding multiple paths."""
        graph = KnowledgeGraph()
        for i in range(5):
            graph.add_node(f"n{i}", NodeType.IOC)

        # Create multiple paths from n0 to n4
        graph.add_edge("n0", "n1", EdgeType.RELATED_TO)
        graph.add_edge("n1", "n4", EdgeType.RELATED_TO)
        graph.add_edge("n0", "n2", EdgeType.RELATED_TO)
        graph.add_edge("n2", "n3", EdgeType.RELATED_TO)
        graph.add_edge("n3", "n4", EdgeType.RELATED_TO)

        paths = graph.find_all_paths("n0", "n4")

        assert len(paths) >= 2

    def test_get_subgraph(self):
        """Test extracting subgraph."""
        graph = KnowledgeGraph()
        for i in range(5):
            graph.add_node(f"n{i}", NodeType.IOC)

        graph.add_edge("n0", "n1", EdgeType.RELATED_TO)
        graph.add_edge("n1", "n2", EdgeType.RELATED_TO)
        graph.add_edge("n3", "n4", EdgeType.RELATED_TO)

        subgraph = graph.get_subgraph(["n0", "n1", "n2"])

        assert len(subgraph.nodes) == 3
        assert len(subgraph.edges) == 2

    def test_degree_centrality(self):
        """Test degree centrality calculation."""
        graph = KnowledgeGraph()
        graph.add_node("hub", NodeType.IOC)
        for i in range(5):
            graph.add_node(f"n{i}", NodeType.IOC)
            graph.add_edge("hub", f"n{i}", EdgeType.RELATED_TO)

        centrality = graph.calculate_degree_centrality()

        assert "hub" in centrality
        assert centrality["hub"] > 0.5

    def test_connected_components(self):
        """Test finding connected components."""
        graph = KnowledgeGraph()
        # Component 1
        for i in range(3):
            graph.add_node(f"c1-n{i}", NodeType.IOC)
        graph.add_edge("c1-n0", "c1-n1", EdgeType.RELATED_TO)
        graph.add_edge("c1-n1", "c1-n2", EdgeType.RELATED_TO)

        # Component 2
        for i in range(2):
            graph.add_node(f"c2-n{i}", NodeType.IOC)
        graph.add_edge("c2-n0", "c2-n1", EdgeType.RELATED_TO)

        components = graph.get_connected_components()

        assert len(components) == 2

    def test_entity_influence(self):
        """Test entity influence calculation."""
        graph = KnowledgeGraph()
        graph.add_node("entity", NodeType.IOC)
        for i in range(3):
            graph.add_node(f"neighbor-{i}", NodeType.IOC)
            graph.add_edge("entity", f"neighbor-{i}", EdgeType.RELATED_TO)

        influence = graph.get_entity_influence("entity")

        assert influence["influence_score"] > 0
        assert influence["total_edges"] == 3

    def test_query_nodes_by_type(self):
        """Test querying nodes by type."""
        graph = KnowledgeGraph()
        graph.add_node("ioc-1", NodeType.IOC)
        graph.add_node("ioc-2", NodeType.IOC)
        graph.add_node("vuln-1", NodeType.VULNERABILITY)

        iocs = graph.query_nodes(node_type=NodeType.IOC)

        assert len(iocs) == 2

    def test_graph_statistics(self):
        """Test graph statistics."""
        graph = KnowledgeGraph()
        for i in range(5):
            graph.add_node(f"n{i}", NodeType.IOC)

        for i in range(4):
            graph.add_edge(f"n{i}", f"n{i+1}", EdgeType.RELATED_TO)

        stats = graph.get_graph_stats()

        assert stats["total_nodes"] == 5
        assert stats["total_edges"] == 4


class TestGraphIntegration:
    """Test graph integration with threat entities."""

    def test_integrate_vulnerability(self):
        """Test integrating vulnerability."""
        engine = GraphIntegrationEngine()
        vuln = Vulnerability(
            id="CVE-2024-1234",
            description="Test vulnerability",
        )

        node_id = engine.populate_vulnerability(vuln)

        assert node_id in engine.graph.nodes
        assert engine.graph.get_node(node_id).node_type == NodeType.VULNERABILITY

    def test_integrate_ioc(self):
        """Test integrating IOC."""
        from core.threat_schema import IOCType, SeverityLevel
        engine = GraphIntegrationEngine()
        ioc = IOC(
            id="ioc-001",
            ioc_type=IOCType.IP,
            value="192.168.1.1",
            severity=SeverityLevel.HIGH,
        )

        node_id = engine.populate_ioc(ioc)

        assert node_id in engine.graph.nodes
        assert engine.graph.get_node(node_id).node_type == NodeType.IOC

    def test_integrate_campaign(self):
        """Test integrating campaign."""
        engine = GraphIntegrationEngine()
        campaign = Campaign(
            id="campaign-001",
            name="APT Campaign",
        )

        node_id = engine.populate_campaign(campaign)

        assert node_id in engine.graph.nodes
        assert engine.graph.get_node(node_id).node_type == NodeType.CAMPAIGN

    def test_integrate_actor(self):
        """Test integrating threat actor."""
        engine = GraphIntegrationEngine()
        actor = ThreatActor(
            id="actor-001",
            name="APT Group",
        )

        node_id = engine.populate_actor(actor)

        assert node_id in engine.graph.nodes
        assert engine.graph.get_node(node_id).node_type == NodeType.ACTOR

    def test_integrate_infrastructure(self):
        """Test integrating infrastructure."""
        engine = GraphIntegrationEngine()
        infra = Infrastructure(
            id="infra-001",
            node_type="domain",
            value="malicious.com",
        )

        node_id = engine.populate_infrastructure(infra)

        assert node_id in engine.graph.nodes
        assert engine.graph.get_node(node_id).node_type == NodeType.INFRASTRUCTURE

    def test_integrate_asset(self):
        """Test integrating asset."""
        engine = GraphIntegrationEngine()
        asset = Asset(
            id="asset-001",
            hostname="web-server-01",
            criticality="high",
        )

        node_id = engine.populate_asset(asset)

        assert node_id in engine.graph.nodes
        assert engine.graph.get_node(node_id).node_type == NodeType.ASSET

    def test_add_relationship(self):
        """Test adding relationships."""
        from core.threat_schema import IOCType, SeverityLevel
        engine = GraphIntegrationEngine()
        vuln = Vulnerability(id="CVE-2024-1234", description="Test")
        ioc = IOC(id="ioc-001", ioc_type=IOCType.IP, value="192.168.1.1", severity=SeverityLevel.HIGH)

        vuln_id = engine.populate_vulnerability(vuln)
        ioc_id = engine.populate_ioc(ioc)

        edge_id = engine.add_relationship(vuln_id, ioc_id, "exploits")

        assert edge_id is not None

    def test_threat_landscape(self):
        """Test threat landscape analysis."""
        from core.threat_schema import IOCType, SeverityLevel
        engine = GraphIntegrationEngine()
        campaign = Campaign(id="c1", name="Campaign")
        ioc = IOC(id="ioc-001", ioc_type=IOCType.IP, value="192.168.1.1", severity=SeverityLevel.HIGH)

        c_id = engine.populate_campaign(campaign)
        i_id = engine.populate_ioc(ioc)
        engine.add_relationship(c_id, i_id, "uses")

        landscape = engine.get_threat_landscape(c_id)

        assert landscape["entity"]["node_id"] == c_id
        assert "outgoing_relationships" in landscape

    def test_attack_chain(self):
        """Test attack chain discovery."""
        engine = GraphIntegrationEngine()
        for i in range(4):
            engine.graph.add_node(f"n{i}", NodeType.IOC)

        engine.graph.add_edge("n0", "n1", EdgeType.USES)
        engine.graph.add_edge("n1", "n2", EdgeType.COMMUNICATES_WITH)
        engine.graph.add_edge("n2", "n3", EdgeType.TARGETS)

        chain = engine.find_attack_chain("n0", "n3")

        assert chain["found"] is True
        assert len(chain["chains"]) > 0

    def test_threat_clusters(self):
        """Test threat cluster detection."""
        engine = GraphIntegrationEngine()
        for i in range(5):
            engine.graph.add_node(f"n{i}", NodeType.IOC)

        engine.graph.add_edge("n0", "n1", EdgeType.RELATED_TO)
        engine.graph.add_edge("n1", "n2", EdgeType.RELATED_TO)
        engine.graph.add_edge("n3", "n4", EdgeType.RELATED_TO)

        clusters = engine.detect_threat_clusters()

        assert len(clusters) >= 1

    def test_graph_intelligence(self):
        """Test comprehensive graph intelligence."""
        engine = GraphIntegrationEngine()
        for i in range(5):
            engine.graph.add_node(f"n{i}", NodeType.IOC)

        for i in range(4):
            engine.graph.add_edge(f"n{i}", f"n{i+1}", EdgeType.RELATED_TO)

        intelligence = engine.get_graph_intelligence()

        assert "graph_stats" in intelligence
        assert "clusters" in intelligence
        assert "top_entities" in intelligence


class TestIntegration:
    """Test complete graph integration workflow."""

    def test_complete_threat_graph(self):
        """Test building complete threat graph."""
        from core.threat_schema import IOCType, SeverityLevel
        engine = GraphIntegrationEngine()

        # Create entities
        vuln = Vulnerability(id="CVE-2024-1234", description="Test")
        campaign = Campaign(id="c1", name="Campaign")
        actor = ThreatActor(id="a1", name="APT")
        ioc = IOC(id="ioc-001", ioc_type=IOCType.IP, value="192.168.1.1", severity=SeverityLevel.HIGH)
        infra = Infrastructure(id="i1", node_type="domain", value="evil.com")

        # Populate graph
        vuln_id = engine.populate_vulnerability(vuln)
        camp_id = engine.populate_campaign(campaign)
        actor_id = engine.populate_actor(actor)
        ioc_id = engine.populate_ioc(ioc)
        infra_id = engine.populate_infrastructure(infra)

        # Add relationships
        engine.add_relationship(vuln_id, ioc_id, "exploits")
        engine.add_relationship(camp_id, ioc_id, "uses")
        engine.add_relationship(actor_id, camp_id, "attributed_to")
        engine.add_relationship(ioc_id, infra_id, "communicates_with")

        # Verify graph
        assert len(engine.graph.nodes) == 5
        assert len(engine.graph.edges) == 4

        # Test analysis
        intelligence = engine.get_graph_intelligence()
        assert intelligence["graph_stats"]["total_nodes"] == 5
        assert intelligence["graph_stats"]["total_edges"] == 4


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
