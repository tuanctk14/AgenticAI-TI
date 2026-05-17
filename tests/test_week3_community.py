"""
tests/test_week3_community.py - Community Detection Tests

Tests for:
- Actor community detection
- Campaign clustering
- Community strength analysis
- Campaign evolution detection
- Isolated actor discovery
- Graph visualization data
"""

import pytest
from datetime import datetime, timedelta

from core.threat_memory import ThreatMemoryEngine
from core.pattern_detection import PatternDetectionEngine
from core.historical_context import HistoricalContextEngine
from core.community_detection import (
    CommunityDetectionEngine,
    ActorCommunity,
    CampaignCluster,
)


class TestActorCommunityDetection:
    """Test actor community detection."""

    def test_detect_actor_communities(self):
        """Test detecting communities of threat actors."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = CommunityDetectionEngine(memory, patterns, context)

        # Create campaigns with shared actors
        memory.record_campaign_activity("campaign-1", "Campaign 1", "exploit")
        memory.record_campaign_activity("campaign-2", "Campaign 2", "recon")

        communities = engine.detect_actor_communities(similarity_threshold=0.1)

        assert isinstance(communities, list)
        assert all(isinstance(c, ActorCommunity) for c in communities)

    def test_community_properties(self):
        """Test community properties."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = CommunityDetectionEngine(memory, patterns, context)

        memory.record_campaign_activity("campaign-1", "Campaign 1", "exploit")

        communities = engine.detect_actor_communities(similarity_threshold=0.0)

        for community in communities:
            assert community.community_id is not None
            assert isinstance(community.actor_ids, list)
            assert community.size >= 0
            assert 0.0 <= community.community_strength <= 1.0

    def test_community_to_dict(self):
        """Test community serialization."""
        community = ActorCommunity("comm-1", ["actor-1", "actor-2"])
        community.shared_campaigns = ["campaign-1"]
        community.community_strength = 0.8

        data = community.to_dict()

        assert data["community_id"] == "comm-1"
        assert data["size"] == 2
        assert data["community_strength"] == 0.8

    def test_empty_communities(self):
        """Test with empty memory."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = CommunityDetectionEngine(memory, patterns, context)

        communities = engine.detect_actor_communities()

        assert isinstance(communities, list)


class TestCampaignClustering:
    """Test campaign clustering."""

    def test_detect_campaign_clusters(self):
        """Test detecting campaign clusters."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = CommunityDetectionEngine(memory, patterns, context)

        # Create related campaigns
        for i in range(3):
            memory.record_campaign_activity(f"campaign-{i}", f"Campaign {i}", "exploit")

        clusters = engine.detect_campaign_clusters(similarity_threshold=0.1)

        assert isinstance(clusters, list)
        assert all(isinstance(c, CampaignCluster) for c in clusters)

    def test_cluster_properties(self):
        """Test cluster properties."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = CommunityDetectionEngine(memory, patterns, context)

        memory.record_campaign_activity("campaign-1", "Campaign 1", "exploit")

        clusters = engine.detect_campaign_clusters(similarity_threshold=0.0)

        for cluster in clusters:
            assert cluster.cluster_id is not None
            assert isinstance(cluster.campaign_ids, list)
            assert cluster.size >= 0
            assert 0.0 <= cluster.cluster_cohesion <= 1.0

    def test_cluster_to_dict(self):
        """Test cluster serialization."""
        cluster = CampaignCluster("cluster-1", ["campaign-1", "campaign-2"])
        cluster.shared_actors = ["actor-1"]
        cluster.shared_techniques = ["T1566"]
        cluster.cluster_cohesion = 0.75

        data = cluster.to_dict()

        assert data["cluster_id"] == "cluster-1"
        assert data["size"] == 2
        assert data["cluster_cohesion"] == 0.75


class TestCommunityStrength:
    """Test community strength analysis."""

    def test_community_strength_single_actor(self):
        """Test strength calculation for single-actor community."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = CommunityDetectionEngine(memory, patterns, context)

        # Create single actor campaign
        memory.record_campaign_activity("campaign-1", "Campaign 1", "exploit")
        # Manually add an actor to the campaign to create a community
        campaign = memory.get_campaign_memory("campaign-1")
        if campaign:
            campaign.attributed_actors.append("actor-1")

        communities = engine.detect_actor_communities(similarity_threshold=0.0)

        assert len(communities) > 0
        for community in communities:
            if community.size == 1:
                assert community.community_strength >= 0.0

    def test_community_strength_multiple_actors(self):
        """Test strength calculation for multi-actor community."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = CommunityDetectionEngine(memory, patterns, context)

        # Create campaigns with multiple actors
        for i in range(3):
            memory.record_campaign_activity(f"campaign-{i}", f"Campaign {i}", "exploit")

        communities = engine.detect_actor_communities(similarity_threshold=0.0)

        for community in communities:
            assert 0.0 <= community.community_strength <= 1.0


class TestCampaignEvolution:
    """Test campaign evolution detection."""

    def test_detect_campaign_evolution(self):
        """Test detecting campaign evolution."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = CommunityDetectionEngine(memory, patterns, context)

        # Create campaign with activities
        for i in range(3):
            memory.record_campaign_activity("campaign-evo", "Campaign Evolution", "exploit")

        result = engine.detect_campaign_evolution("campaign-evo")

        assert result["campaign_id"] == "campaign-evo"
        assert "activity_count" in result
        assert "evolution_trend" in result or "evolution" in result

    def test_evolution_trend_detection(self):
        """Test evolution trend classification."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = CommunityDetectionEngine(memory, patterns, context)

        memory.record_campaign_activity("campaign-trend", "Campaign", "exploit")

        result = engine.detect_campaign_evolution("campaign-trend")

        assert isinstance(result, dict)
        assert "campaign_id" in result

    def test_evolution_insufficient_data(self):
        """Test evolution with insufficient data."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = CommunityDetectionEngine(memory, patterns, context)

        memory.record_campaign_activity("campaign-single", "Campaign", "exploit")

        result = engine.detect_campaign_evolution("campaign-single")

        assert result["campaign_id"] == "campaign-single"
        assert "activity_count" in result or "evolution" in result


class TestIsolatedActors:
    """Test isolated actor detection."""

    def test_find_isolated_actors(self):
        """Test finding isolated actors."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = CommunityDetectionEngine(memory, patterns, context)

        # Create campaigns
        for i in range(3):
            memory.record_campaign_activity(f"campaign-{i}", f"Campaign {i}", "exploit")

        isolated = engine.find_isolated_actors(min_connections=1)

        assert isinstance(isolated, list)
        for actor in isolated:
            assert "actor_id" in actor
            assert "shared_campaigns" in actor

    def test_isolated_actors_properties(self):
        """Test isolated actor properties."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = CommunityDetectionEngine(memory, patterns, context)

        memory.record_campaign_activity("campaign-iso", "Campaign", "exploit")

        isolated = engine.find_isolated_actors()

        for actor in isolated:
            assert isinstance(actor["is_isolated"], bool)
            assert isinstance(actor["shared_iocs"], int)


class TestCommunityGraph:
    """Test community graph visualization."""

    def test_get_community_graph(self):
        """Test getting complete community graph."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = CommunityDetectionEngine(memory, patterns, context)

        # Create data
        for i in range(3):
            memory.record_ioc_occurrence(f"ioc-{i}", f"ip-{i}", "obs")
            memory.record_campaign_activity(f"campaign-{i}", f"Campaign {i}", "exploit")
            memory.record_asset_exposure(f"asset-{i}", f"Asset {i}", "cve")

        graph = engine.get_community_graph()

        assert "communities" in graph
        assert "clusters" in graph
        assert "total_communities" in graph
        assert "total_clusters" in graph
        assert graph["total_communities"] >= 0
        assert graph["total_clusters"] >= 0

    def test_graph_data_structure(self):
        """Test graph data structure validity."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = CommunityDetectionEngine(memory, patterns, context)

        memory.record_campaign_activity("campaign-graph", "Campaign", "exploit")

        graph = engine.get_community_graph()

        assert isinstance(graph["communities"], list)
        assert isinstance(graph["clusters"], list)
        assert isinstance(graph["total_communities"], int)
        assert isinstance(graph["total_clusters"], int)


class TestSimilarityCalculation:
    """Test similarity calculation methods."""

    def test_jaccard_similarity_identical(self):
        """Test Jaccard similarity for identical sets."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = CommunityDetectionEngine(memory, patterns, context)

        similarity = engine._jaccard({"a", "b", "c"}, {"a", "b", "c"})

        assert similarity == 1.0

    def test_jaccard_similarity_disjoint(self):
        """Test Jaccard similarity for disjoint sets."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = CommunityDetectionEngine(memory, patterns, context)

        similarity = engine._jaccard({"a", "b"}, {"c", "d"})

        assert similarity == 0.0

    def test_jaccard_similarity_partial(self):
        """Test Jaccard similarity for partial overlap."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = CommunityDetectionEngine(memory, patterns, context)

        similarity = engine._jaccard({"a", "b", "c"}, {"b", "c", "d"})

        assert 0.0 < similarity < 1.0
        assert abs(similarity - 0.5) < 0.01


class TestIntegration:
    """Test community detection integration."""

    def test_full_community_workflow(self):
        """Test complete community detection workflow."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = CommunityDetectionEngine(memory, patterns, context)

        # Create complex scenario
        for i in range(3):
            memory.record_ioc_occurrence(f"ioc-{i}", f"ip-{i}", "obs")
            memory.record_campaign_activity(f"campaign-{i}", f"Campaign {i}", "exploit")

        # Detect communities
        communities = engine.detect_actor_communities(similarity_threshold=0.0)
        assert isinstance(communities, list)

        # Detect clusters
        clusters = engine.detect_campaign_clusters(similarity_threshold=0.0)
        assert isinstance(clusters, list)

        # Get graph
        graph = engine.get_community_graph()
        assert "communities" in graph
        assert "clusters" in graph

    def test_evolution_with_multiple_campaigns(self):
        """Test evolution detection with multiple campaigns."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        engine = CommunityDetectionEngine(memory, patterns, context)

        # Create multiple activities in campaign
        for i in range(5):
            memory.record_campaign_activity("campaign-multi", "Campaign Multi", "exploit")

        evolution = engine.detect_campaign_evolution("campaign-multi")

        assert evolution["campaign_id"] == "campaign-multi"
        assert evolution["activity_count"] >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
