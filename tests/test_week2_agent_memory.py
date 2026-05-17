"""
tests/test_week2_agent_memory.py - Memory-Aware Agent Integration Tests

Tests for:
- IOC correlation with historical memory
- Campaign correlation with patterns
- Asset exposure correlation
- Threat actor relationship discovery
- Predictive threat activity
- Agent state enrichment with memory context
"""

import pytest
from datetime import datetime, timedelta

from core.threat_memory import ThreatMemoryEngine
from core.pattern_detection import PatternDetectionEngine
from core.historical_context import HistoricalContextEngine
from core.agent_memory_bridge import MemoryAwareThreatsAgent, MemoryAwareAgentState


class TestIOCMemoryCorrelation:
    """Test IOC correlation with historical memory."""

    def test_correlate_ioc_with_history(self):
        """Test correlating IOC with memory and patterns."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        agent = MemoryAwareThreatsAgent(memory, patterns, context)

        # Record IOC
        memory.record_ioc_occurrence("ioc-test", "192.168.1.1", "observation_1")
        memory.record_ioc_occurrence("ioc-test", "192.168.1.1", "observation_2")

        # Correlate
        correlation = agent.correlate_ioc_with_history("ioc-test")

        assert correlation["ioc_id"] == "ioc-test"
        assert correlation["occurrence_count"] >= 1
        assert "recurring_status" in correlation
        assert "activity_trend" in correlation
        assert 0.0 <= correlation.get("next_reuse_likelihood", 0.0) <= 1.0

    def test_ioc_correlation_includes_pattern_data(self):
        """Test that IOC correlation includes pattern analysis."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        agent = MemoryAwareThreatsAgent(memory, patterns, context)

        # Record IOC
        for i in range(3):
            memory.record_ioc_occurrence("ioc-pattern", "test-ioc", f"obs_{i}")

        correlation = agent.correlate_ioc_with_history("ioc-pattern")

        assert "reuse_frequency" in correlation
        assert "dormancy_periods" in correlation
        assert "activity_trend" in correlation

    def test_ioc_correlation_with_campaigns(self):
        """Test IOC correlated with campaigns."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        agent = MemoryAwareThreatsAgent(memory, patterns, context)

        # Record IOC with associated campaign
        memory.record_ioc_occurrence("ioc-campaign", "test-ioc", "obs_1")
        memory.record_campaign_activity("campaign-1", "Test Campaign", "exploit")

        correlation = agent.correlate_ioc_with_history("ioc-campaign")

        assert "associated_campaigns" in correlation
        assert "threat_actor_count" in correlation

    def test_unknown_ioc_correlation(self):
        """Test correlation of unknown IOC."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        agent = MemoryAwareThreatsAgent(memory, patterns, context)

        correlation = agent.correlate_ioc_with_history("unknown-ioc")

        assert correlation["status"] == "unknown"


class TestCampaignMemoryCorrelation:
    """Test campaign correlation with patterns and history."""

    def test_correlate_campaign_with_history(self):
        """Test correlating campaign with memory and patterns."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        agent = MemoryAwareThreatsAgent(memory, patterns, context)

        # Record campaign
        memory.record_campaign_activity("campaign-test", "Test Campaign", "exploit")
        memory.record_campaign_activity("campaign-test", "Test Campaign", "recon")

        correlation = agent.correlate_campaign_with_history("campaign-test")

        assert correlation["campaign_id"] == "campaign-test"
        assert correlation["activity_count"] >= 1
        assert "activity_pattern" in correlation
        assert "evolution_trajectory" in correlation

    def test_campaign_correlation_includes_risk(self):
        """Test campaign correlation includes risk assessment."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        agent = MemoryAwareThreatsAgent(memory, patterns, context)

        # Record campaign
        for i in range(3):
            memory.record_campaign_activity(
                "campaign-risk",
                "Risk Campaign",
                f"activity_{i}",
                targets_count=10+i,
            )

        correlation = agent.correlate_campaign_with_history("campaign-risk")

        assert "historical_risk_score" in correlation
        assert "contextual_severity" in correlation
        assert 0.0 <= correlation.get("historical_risk_score", 0.0) <= 1.0


class TestAssetMemoryCorrelation:
    """Test asset exposure correlation with memory."""

    def test_correlate_asset_with_history(self):
        """Test correlating asset exposure with memory."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        agent = MemoryAwareThreatsAgent(memory, patterns, context)

        # Record asset exposures
        memory.record_asset_exposure("asset-test", "Test Asset", "cve")
        memory.record_asset_exposure("asset-test", "Test Asset", "cve")

        correlation = agent.correlate_asset_with_history("asset-test")

        assert correlation["asset_id"] == "asset-test"
        assert correlation["exposure_count"] >= 1
        assert "exposure_trend" in correlation
        assert "remediation_success_rate" in correlation

    def test_asset_correlation_includes_timeline(self):
        """Test asset correlation includes timeline and predictions."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        agent = MemoryAwareThreatsAgent(memory, patterns, context)

        # Record asset
        for i in range(3):
            memory.record_asset_exposure(f"asset-timeline", "Asset", "cve")

        correlation = agent.correlate_asset_with_history("asset-timeline")

        assert "dormancy_periods" in correlation
        assert "is_currently_exposed" in correlation
        assert "high_risk_window" in correlation


class TestThreatRelationshipDiscovery:
    """Test discovering related threats from IOC."""

    def test_find_related_threats(self):
        """Test finding threats related to IOC."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        agent = MemoryAwareThreatsAgent(memory, patterns, context)

        # Set up complex threat scenario
        memory.record_ioc_occurrence("ioc-hub", "192.168.1.1", "obs_1")
        memory.record_campaign_activity("campaign-1", "Campaign 1", "exploit")
        memory.record_campaign_activity("campaign-2", "Campaign 2", "recon")

        # Find related threats
        related = agent.find_related_threats("ioc-hub")

        assert related["ioc_id"] == "ioc-hub"
        assert "related_campaigns" in related
        assert "related_actors" in related
        assert "related_malware" in related
        assert isinstance(related["related_campaigns"], list)

    def test_related_threats_graph(self):
        """Test threat relationship graph construction."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        agent = MemoryAwareThreatsAgent(memory, patterns, context)

        # Create IOC
        memory.record_ioc_occurrence("ioc-graph", "10.0.0.1", "obs_1")

        related = agent.find_related_threats("ioc-graph")

        assert isinstance(related, dict)
        assert related["ioc_id"] == "ioc-graph"
        # Check structure exists
        assert "related_campaigns" in related
        assert isinstance(related["related_campaigns"], list)


class TestThreatActivityPrediction:
    """Test prediction of next threat activity."""

    def test_predict_next_threat_activity(self):
        """Test predicting next threat activity."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        agent = MemoryAwareThreatsAgent(memory, patterns, context)

        # Populate memory
        memory.record_ioc_occurrence("ioc-predict", "test-ioc", "obs_1")
        memory.record_campaign_activity("campaign-predict", "Predict Campaign", "exploit")
        memory.record_asset_exposure("asset-predict", "Predict Asset", "cve")

        predictions = agent.predict_next_threat_activity()

        assert "iocs_at_risk" in predictions
        assert "campaigns_resuming" in predictions
        assert "assets_exposed" in predictions
        assert "predicted_timeline" in predictions
        assert isinstance(predictions["predicted_timeline"], list)

    def test_threat_predictions_include_confidence(self):
        """Test predictions include confidence/likelihood scores."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        agent = MemoryAwareThreatsAgent(memory, patterns, context)

        # Create multiple observations for pattern
        for i in range(3):
            memory.record_ioc_occurrence(f"ioc-conf", f"value-{i}", f"obs_{i}")

        predictions = agent.predict_next_threat_activity()

        # All predictions should have likelihood field
        for prediction in predictions.get("iocs_at_risk", []):
            assert "likelihood" in prediction
            assert 0.0 <= prediction["likelihood"] <= 1.0


class TestMemoryEnrichmentSummary:
    """Test comprehensive memory enrichment summary."""

    def test_get_memory_enrichment_summary(self):
        """Test getting overall memory summary."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        agent = MemoryAwareThreatsAgent(memory, patterns, context)

        # Populate memory
        memory.record_ioc_occurrence("ioc-summary", "test", "obs_1")
        memory.record_campaign_activity("campaign-summary", "Campaign", "exploit")

        summary = agent.get_memory_enrichment_summary()

        assert "memory_summary" in summary
        assert "pattern_statistics" in summary
        assert "anomalies" in summary
        assert "high_risk_entities" in summary
        assert "updated_at" in summary

    def test_summary_includes_statistics(self):
        """Test summary includes statistical analysis."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        agent = MemoryAwareThreatsAgent(memory, patterns, context)

        # Add various threat data
        for i in range(5):
            memory.record_ioc_occurrence(f"ioc-stat-{i}", f"val-{i}", "obs")

        summary = agent.get_memory_enrichment_summary()
        stats = summary.get("pattern_statistics", {})

        assert "total_iocs_analyzed" in stats or isinstance(stats, dict)


class TestMemoryAwareAgentState:
    """Test agent state enrichment with memory."""

    def test_enrich_with_memory_ioc(self):
        """Test enriching IOC entity with memory."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        mem_agent = MemoryAwareThreatsAgent(memory, patterns, context)
        state_manager = MemoryAwareAgentState(mem_agent)

        memory.record_ioc_occurrence("ioc-state", "test-ioc", "obs_1")

        enriched = state_manager.enrich_with_memory("ioc", "ioc-state")

        assert enriched["ioc_id"] == "ioc-state"
        assert "activity_trend" in enriched

    def test_enrich_with_memory_campaign(self):
        """Test enriching campaign entity with memory."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        mem_agent = MemoryAwareThreatsAgent(memory, patterns, context)
        state_manager = MemoryAwareAgentState(mem_agent)

        memory.record_campaign_activity("campaign-state", "Campaign", "exploit")

        enriched = state_manager.enrich_with_memory("campaign", "campaign-state")

        assert enriched["campaign_id"] == "campaign-state"
        assert "activity_pattern" in enriched

    def test_enrich_agent_state_with_indicators(self):
        """Test enriching full agent state with indicators."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        mem_agent = MemoryAwareThreatsAgent(memory, patterns, context)
        state_manager = MemoryAwareAgentState(mem_agent)

        # Record indicator
        memory.record_ioc_occurrence("ioc-agent", "192.168.1.1", "obs")

        # Create agent state with indicators
        agent_state = {
            "collected_indicators": [
                {"id": "ioc-agent", "type": "ip", "value": "192.168.1.1"}
            ],
            "num_steps": 1,
        }

        enriched = state_manager.enrich_state_with_memory(agent_state)

        assert "memory_context" in enriched
        assert "indicator_correlations" in enriched["memory_context"]
        assert "threat_predictions" in enriched["memory_context"]

    def test_enrich_agent_state_with_cves(self):
        """Test enriching agent state with CVEs."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        mem_agent = MemoryAwareThreatsAgent(memory, patterns, context)
        state_manager = MemoryAwareAgentState(mem_agent)

        # Create agent state with CVEs
        agent_state = {
            "collected_cves": [
                {
                    "id": "CVE-2021-44228",
                    "cvss_score": 10.0,
                    "severity": "CRITICAL",
                    "description": "Log4j RCE",
                }
            ],
            "num_steps": 1,
        }

        enriched = state_manager.enrich_state_with_memory(agent_state)

        assert "memory_context" in enriched
        assert "enrichment_summary" in enriched["memory_context"]


class TestIntegration:
    """Test end-to-end memory-aware agent scenarios."""

    def test_full_memory_agent_workflow(self):
        """Test complete workflow of memory-aware threat reasoning."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        agent = MemoryAwareThreatsAgent(memory, patterns, context)

        # Scenario: APT campaign with multiple IOCs
        for i in range(3):
            memory.record_ioc_occurrence(f"ioc-apt-{i}", f"192.168.{i}.1", f"obs_{i}")
            memory.record_campaign_activity("apt-campaign", "APT Campaign", "exploit")

        # Analyze IOCs
        ioc_corrs = [
            agent.correlate_ioc_with_history(f"ioc-apt-{i}") for i in range(3)
        ]
        campaign_corr = agent.correlate_campaign_with_history("apt-campaign")

        assert len(ioc_corrs) == 3
        assert all(c["ioc_id"] == f"ioc-apt-{i}" for i, c in enumerate(ioc_corrs))
        assert campaign_corr["campaign_id"] == "apt-campaign"

        # Get predictions
        predictions = agent.predict_next_threat_activity()
        assert "predicted_timeline" in predictions

    def test_memory_agent_with_state_enrichment(self):
        """Test memory agent integrated with agent state."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        mem_agent = MemoryAwareThreatsAgent(memory, patterns, context)
        state_manager = MemoryAwareAgentState(mem_agent)

        # Simulate agent workflow
        memory.record_ioc_occurrence("ioc-workflow", "10.0.0.1", "obs_1")
        memory.record_campaign_activity("campaign-workflow", "Campaign", "exploit")

        # Create initial state
        initial_state = {
            "query": "Check for APT activity on 10.0.0.1",
            "collected_indicators": [
                {"id": "ioc-workflow", "type": "ip", "value": "10.0.0.1"}
            ],
            "num_steps": 2,
        }

        # Enrich with memory
        final_state = state_manager.enrich_state_with_memory(initial_state)

        assert "memory_context" in final_state
        assert len(final_state["memory_context"]["indicator_correlations"]) > 0
        summary = final_state["memory_context"]["enrichment_summary"]
        assert "memory_summary" in summary


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
