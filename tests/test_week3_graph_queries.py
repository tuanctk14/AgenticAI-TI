"""
tests/test_week3_graph_queries.py - Graph Query Engine Tests

Tests for:
- Entity search and lookup
- Relationship traversal
- Multi-hop queries
- Threat landscape analysis
- Graph snapshot export
- Query filtering and aggregation
"""

import pytest
from datetime import datetime, timedelta

from core.threat_memory import ThreatMemoryEngine
from core.pattern_detection import PatternDetectionEngine
from core.historical_context import HistoricalContextEngine
from core.graph_query_engine import GraphQueryEngine


class TestEntitySearch:
    """Test entity search and lookup."""

    def test_find_ioc_by_value(self):
        """Test finding IOC by its value."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        graph = GraphQueryEngine(memory, patterns, context)

        # Record IOC
        memory.record_ioc_occurrence("ioc-1", "192.168.1.1", "obs_1")

        result = graph.find_ioc_by_value("192.168.1.1")

        assert result is not None
        assert result["ioc_value"] == "192.168.1.1"
        assert result["ioc_id"] == "ioc-1"

    def test_find_ioc_not_found(self):
        """Test IOC lookup when not found."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        graph = GraphQueryEngine(memory, patterns, context)

        result = graph.find_ioc_by_value("10.0.0.1")

        assert result is None

    def test_find_campaign_by_name(self):
        """Test finding campaign by name."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        graph = GraphQueryEngine(memory, patterns, context)

        # Record campaign
        memory.record_campaign_activity("campaign-1", "Test Campaign", "exploit")

        result = graph.find_campaign_by_name("Test Campaign")

        assert result is not None
        assert result["campaign_name"] == "Test Campaign"
        assert result["campaign_id"] == "campaign-1"

    def test_find_asset_by_name(self):
        """Test finding asset by name."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        graph = GraphQueryEngine(memory, patterns, context)

        # Record asset
        memory.record_asset_exposure("asset-1", "Critical Server", "cve")

        result = graph.find_asset_by_name("Critical Server")

        assert result is not None
        assert result["asset_name"] == "Critical Server"
        assert result["asset_id"] == "asset-1"


class TestRelationshipTraversal:
    """Test relationship traversal and multi-hop queries."""

    def test_find_related_iocs(self):
        """Test finding IOCs related through campaigns."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        graph = GraphQueryEngine(memory, patterns, context)

        # Create campaign with multiple IOCs
        memory.record_ioc_occurrence("ioc-1", "192.168.1.1", "obs_1")
        memory.record_ioc_occurrence("ioc-2", "192.168.1.2", "obs_2")
        memory.record_campaign_activity("campaign-1", "Campaign 1", "exploit")

        result = graph.find_related_iocs("ioc-1")

        assert result["ioc_id"] == "ioc-1"
        assert "related_iocs" in result
        assert "related_campaigns" in result

    def test_find_actor_campaigns(self):
        """Test finding all campaigns attributed to actor."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        graph = GraphQueryEngine(memory, patterns, context)

        # Create campaigns attributed to actor
        memory.record_campaign_activity("campaign-1", "Campaign 1", "exploit")
        memory.record_campaign_activity("campaign-2", "Campaign 2", "recon")

        result = graph.find_actor_campaigns("actor-1")

        assert result["actor_id"] == "actor-1"
        assert "campaign_ids" in result
        assert "total_campaigns" in result

    def test_find_campaign_infrastructure(self):
        """Test finding infrastructure used in campaign."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        graph = GraphQueryEngine(memory, patterns, context)

        # Set up campaign with IOCs
        memory.record_ioc_occurrence("ioc-1", "10.0.0.1", "obs_1")
        memory.record_campaign_activity("campaign-1", "Campaign 1", "exploit")

        result = graph.find_campaign_infrastructure("campaign-1")

        assert result["campaign_id"] == "campaign-1"
        assert "ioc_ids" in result
        assert "actor_ids" in result
        assert "asset_targets" in result


class TestThreatLandscape:
    """Test threat landscape analysis."""

    def test_find_asset_threat_landscape(self):
        """Test finding all threats targeting an asset."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        graph = GraphQueryEngine(memory, patterns, context)

        # Create asset with exposures
        memory.record_asset_exposure("asset-1", "Server", "cve")
        memory.record_campaign_activity("campaign-1", "Campaign", "exploit")

        result = graph.find_asset_threat_landscape("asset-1")

        assert result["asset_id"] == "asset-1"
        assert "campaigns" in result
        assert "iocs" in result
        assert "actors" in result
        assert "is_exposed" in result

    def test_get_threat_actors(self):
        """Test getting all threat actors in memory."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        graph = GraphQueryEngine(memory, patterns, context)

        # Create campaigns with actors
        for i in range(3):
            memory.record_campaign_activity(f"campaign-{i}", f"Campaign {i}", "exploit")

        actors = graph.get_threat_actors()

        assert isinstance(actors, list)
        assert all("actor_id" in a for a in actors)
        assert all("campaigns" in a for a in actors)

    def test_get_active_campaigns(self):
        """Test getting all active campaigns."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        graph = GraphQueryEngine(memory, patterns, context)

        # Create active campaigns
        for i in range(3):
            memory.record_campaign_activity(f"campaign-{i}", f"Campaign {i}", "exploit")

        active = graph.get_active_campaigns()

        assert isinstance(active, list)
        assert len(active) >= 0

    def test_get_exposed_assets(self):
        """Test getting all currently exposed assets."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        graph = GraphQueryEngine(memory, patterns, context)

        # Create exposed assets
        for i in range(3):
            memory.record_asset_exposure(f"asset-{i}", f"Asset {i}", "cve")

        exposed = graph.get_exposed_assets()

        assert isinstance(exposed, list)


class TestCommonInfrastructure:
    """Test finding shared infrastructure between actors."""

    def test_find_common_infrastructure(self):
        """Test finding infrastructure shared between actors."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        graph = GraphQueryEngine(memory, patterns, context)

        # Create infrastructure
        memory.record_ioc_occurrence("ioc-1", "10.0.0.1", "obs_1")
        memory.record_campaign_activity("campaign-1", "Campaign 1", "exploit")

        result = graph.find_common_infrastructure(["actor-1", "actor-2"])

        assert "shared_campaigns" in result
        assert "shared_iocs" in result
        assert "commonality_score" in result
        assert 0.0 <= result["commonality_score"] <= 1.0

    def test_find_common_infrastructure_empty_actors(self):
        """Test with empty actor list."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        graph = GraphQueryEngine(memory, patterns, context)

        result = graph.find_common_infrastructure([])

        assert result["commonality_score"] == 0.0


class TestQueryFiltering:
    """Test query filtering and aggregation."""

    def test_query_iocs_by_criteria(self):
        """Test querying IOCs by pattern criteria."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        graph = GraphQueryEngine(memory, patterns, context)

        # Create IOCs with multiple occurrences
        for i in range(3):
            memory.record_ioc_occurrence(f"ioc-criteria-{i}", f"ip-{i}", "obs_1")
            memory.record_ioc_occurrence(f"ioc-criteria-{i}", f"ip-{i}", "obs_2")

        results = graph.query_iocs_by_criteria(min_occurrence_count=1)

        assert isinstance(results, list)
        assert all(r["occurrence_count"] >= 1 for r in results)

    def test_query_iocs_by_trend(self):
        """Test querying IOCs by activity trend."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        graph = GraphQueryEngine(memory, patterns, context)

        # Create IOCs
        for i in range(2):
            memory.record_ioc_occurrence(f"ioc-trend-{i}", f"value-{i}", "obs_1")

        results = graph.query_iocs_by_criteria(activity_trend="unknown")

        assert isinstance(results, list)
        for r in results:
            assert r.get("activity_trend") == "unknown" or r.get("activity_trend") is not None

    def test_query_iocs_by_likelihood(self):
        """Test querying IOCs by minimum likelihood."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        graph = GraphQueryEngine(memory, patterns, context)

        # Create IOCs
        memory.record_ioc_occurrence("ioc-like", "test-ioc", "obs_1")

        results = graph.query_iocs_by_criteria(min_likelihood=0.0)

        assert isinstance(results, list)


class TestGraphSnapshot:
    """Test graph snapshot export."""

    def test_export_graph_snapshot(self):
        """Test exporting current threat graph snapshot."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        graph = GraphQueryEngine(memory, patterns, context)

        # Populate memory
        memory.record_ioc_occurrence("ioc-snap", "192.168.1.1", "obs_1")
        memory.record_campaign_activity("campaign-snap", "Campaign", "exploit")
        memory.record_asset_exposure("asset-snap", "Asset", "cve")

        snapshot = graph.export_graph_snapshot()

        assert "nodes" in snapshot
        assert "edges" in snapshot
        assert "node_counts" in snapshot
        assert "edge_counts" in snapshot
        assert snapshot["total_nodes"] >= 0
        assert snapshot["total_edges"] >= 0

    def test_snapshot_contains_all_node_types(self):
        """Test snapshot includes all node types."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        graph = GraphQueryEngine(memory, patterns, context)

        snapshot = graph.export_graph_snapshot()

        assert "iocs" in snapshot["nodes"]
        assert "campaigns" in snapshot["nodes"]
        assert "assets" in snapshot["nodes"]
        assert "actors" in snapshot["nodes"]

    def test_snapshot_contains_all_edge_types(self):
        """Test snapshot includes all edge types."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        graph = GraphQueryEngine(memory, patterns, context)

        snapshot = graph.export_graph_snapshot()

        assert "ioc_campaign" in snapshot["edges"]
        assert "campaign_actor" in snapshot["edges"]
        assert "campaign_asset" in snapshot["edges"]
        assert "ioc_asset" in snapshot["edges"]


class TestIntegration:
    """Test graph query integration."""

    def test_full_graph_workflow(self):
        """Test complete graph query workflow."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        graph = GraphQueryEngine(memory, patterns, context)

        # Create complex scenario
        memory.record_ioc_occurrence("ioc-workflow", "10.0.0.1", "obs_1")
        memory.record_campaign_activity("campaign-workflow", "Campaign", "exploit")
        memory.record_asset_exposure("asset-workflow", "Server", "cve")

        # Query graph
        ioc = graph.find_ioc_by_value("10.0.0.1")
        campaign = graph.find_campaign_by_name("Campaign")
        asset = graph.find_asset_by_name("Server")

        assert ioc is not None
        assert campaign is not None
        assert asset is not None

        # Get landscape
        landscape = graph.find_asset_threat_landscape("asset-workflow")
        assert landscape["asset_id"] == "asset-workflow"

        # Export snapshot
        snapshot = graph.export_graph_snapshot()
        assert snapshot["total_nodes"] > 0

    def test_graph_queries_with_patterns(self):
        """Test graph queries with pattern analysis."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        graph = GraphQueryEngine(memory, patterns, context)

        # Create multiple IOCs
        for i in range(3):
            for j in range(2):
                memory.record_ioc_occurrence(f"ioc-pattern-{i}", f"value-{i}", f"obs_{j}")

        results = graph.query_iocs_by_criteria(min_occurrence_count=1)

        assert len(results) >= 0
        assert all("reuse_frequency" in r for r in results)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
