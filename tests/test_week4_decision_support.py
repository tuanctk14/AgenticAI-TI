"""
tests/test_week4_decision_support.py - Decision Support System Tests

Tests for:
- Threat prioritization and risk scoring
- Mitigation strategy generation
- Threat hunting priorities
- Resource allocation recommendations
- Action timeline planning
- Decision support summary
"""

import pytest
from datetime import datetime, timedelta

from core.threat_memory import ThreatMemoryEngine
from core.pattern_detection import PatternDetectionEngine
from core.historical_context import HistoricalContextEngine
from core.community_detection import CommunityDetectionEngine
from core.actor_profiling import ActorProfilingEngine
from core.trend_analysis import TrendAnalyzer
from core.anomaly_detection import AnomalyDetector
from core.threat_intelligence_reasoner import ThreatIntelligenceReasoner
from core.decision_support import (
    DecisionSupportSystem,
    PrioritizedThreat,
    MitigationStrategy,
)


class TestPrioritizedThreat:
    """Test threat prioritization."""

    def test_create_prioritized_threat(self):
        """Test creating prioritized threat."""
        threat = PrioritizedThreat("threat-1", "campaign")

        assert threat.threat_id == "threat-1"
        assert threat.threat_type == "campaign"
        assert threat.priority_score == 0.0

    def test_threat_to_dict(self):
        """Test threat serialization."""
        threat = PrioritizedThreat("test-threat", "actor")
        threat.priority_score = 0.85
        threat.risk_level = "high"
        threat.urgency = "high"

        data = threat.to_dict()

        assert data["threat_id"] == "test-threat"
        assert data["priority_score"] == 0.85
        assert data["risk_level"] == "high"


class TestThreatPrioritization:
    """Test threat prioritization."""

    def test_prioritize_threats(self):
        """Test threat prioritization."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        communities = CommunityDetectionEngine(memory, patterns, context)
        profiling = ActorProfilingEngine(memory, patterns, context)
        trends = TrendAnalyzer(memory, patterns, context)
        anomalies = AnomalyDetector(memory, patterns, context)
        reasoner = ThreatIntelligenceReasoner(
            memory, patterns, context, communities, profiling, trends, anomalies
        )
        decision = DecisionSupportSystem(
            memory, patterns, context, communities, profiling, trends, anomalies, reasoner
        )

        # Create threats
        for i in range(3):
            memory.record_campaign_activity(f"campaign-{i}", f"Campaign {i}", "exploit")
            campaign = memory.get_campaign_memory(f"campaign-{i}")
            if campaign:
                campaign.is_active = (i == 0)  # First one is active
                campaign.attributed_actors.append(f"actor-{i}")

        threats = decision.prioritize_threats(limit=5)

        assert isinstance(threats, list)
        assert all(isinstance(t, PrioritizedThreat) for t in threats)
        assert all(0.0 <= t.priority_score <= 1.0 for t in threats)

    def test_threat_urgency_levels(self):
        """Test threat urgency classification."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        communities = CommunityDetectionEngine(memory, patterns, context)
        profiling = ActorProfilingEngine(memory, patterns, context)
        trends = TrendAnalyzer(memory, patterns, context)
        anomalies = AnomalyDetector(memory, patterns, context)
        reasoner = ThreatIntelligenceReasoner(
            memory, patterns, context, communities, profiling, trends, anomalies
        )
        decision = DecisionSupportSystem(
            memory, patterns, context, communities, profiling, trends, anomalies, reasoner
        )

        # Create active campaign
        memory.record_campaign_activity("campaign-urgent", "Campaign", "exploit")
        campaign = memory.get_campaign_memory("campaign-urgent")
        if campaign:
            campaign.is_active = True
            for j in range(5):
                memory.record_campaign_activity("campaign-urgent", "Campaign", "exploit")

        threats = decision.prioritize_threats(limit=1)

        if threats:
            assert threats[0].urgency in ["critical", "high", "medium", "low"]

    def test_prioritized_threats_sorted(self):
        """Test that threats are sorted by priority."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        communities = CommunityDetectionEngine(memory, patterns, context)
        profiling = ActorProfilingEngine(memory, patterns, context)
        trends = TrendAnalyzer(memory, patterns, context)
        anomalies = AnomalyDetector(memory, patterns, context)
        reasoner = ThreatIntelligenceReasoner(
            memory, patterns, context, communities, profiling, trends, anomalies
        )
        decision = DecisionSupportSystem(
            memory, patterns, context, communities, profiling, trends, anomalies, reasoner
        )

        for i in range(3):
            memory.record_campaign_activity(f"campaign-sort-{i}", f"Campaign {i}", "exploit")

        threats = decision.prioritize_threats(limit=10)

        if len(threats) > 1:
            scores = [t.priority_score for t in threats]
            assert scores == sorted(scores, reverse=True)


class TestMitigationStrategies:
    """Test mitigation strategy generation."""

    def test_generate_campaign_strategies(self):
        """Test mitigation strategies for campaign."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        communities = CommunityDetectionEngine(memory, patterns, context)
        profiling = ActorProfilingEngine(memory, patterns, context)
        trends = TrendAnalyzer(memory, patterns, context)
        anomalies = AnomalyDetector(memory, patterns, context)
        reasoner = ThreatIntelligenceReasoner(
            memory, patterns, context, communities, profiling, trends, anomalies
        )
        decision = DecisionSupportSystem(
            memory, patterns, context, communities, profiling, trends, anomalies, reasoner
        )

        memory.record_campaign_activity("campaign-mitigation", "Campaign", "exploit")
        campaign = memory.get_campaign_memory("campaign-mitigation")
        if campaign:
            campaign.current_targets.extend(["target-1", "target-2"])

        strategies = decision.generate_mitigation_strategies("campaign-mitigation", "campaign")

        assert isinstance(strategies, list)
        for strategy in strategies:
            assert isinstance(strategy, MitigationStrategy)
            assert len(strategy.short_term_actions) > 0
            assert strategy.effectiveness_score > 0.0

    def test_generate_actor_strategies(self):
        """Test mitigation strategies for actor."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        communities = CommunityDetectionEngine(memory, patterns, context)
        profiling = ActorProfilingEngine(memory, patterns, context)
        trends = TrendAnalyzer(memory, patterns, context)
        anomalies = AnomalyDetector(memory, patterns, context)
        reasoner = ThreatIntelligenceReasoner(
            memory, patterns, context, communities, profiling, trends, anomalies
        )
        decision = DecisionSupportSystem(
            memory, patterns, context, communities, profiling, trends, anomalies, reasoner
        )

        memory.record_campaign_activity("campaign-actor-strat", "Campaign", "exploit")
        campaign = memory.get_campaign_memory("campaign-actor-strat")
        if campaign:
            campaign.attributed_actors.append("actor-strat")

        strategies = decision.generate_mitigation_strategies("actor-strat", "actor")

        assert isinstance(strategies, list)

    def test_strategy_properties(self):
        """Test mitigation strategy properties."""
        strategy = MitigationStrategy("strat-1", "threat-1")
        strategy.title = "Test Strategy"
        strategy.description = "A test mitigation strategy"
        strategy.effectiveness_score = 0.8

        data = strategy.to_dict()

        assert data["strategy_id"] == "strat-1"
        assert data["title"] == "Test Strategy"
        assert data["effectiveness_score"] == 0.8


class TestHuntingPriorities:
    """Test threat hunting priorities."""

    def test_get_hunting_priorities(self):
        """Test getting hunting priorities."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        communities = CommunityDetectionEngine(memory, patterns, context)
        profiling = ActorProfilingEngine(memory, patterns, context)
        trends = TrendAnalyzer(memory, patterns, context)
        anomalies = AnomalyDetector(memory, patterns, context)
        reasoner = ThreatIntelligenceReasoner(
            memory, patterns, context, communities, profiling, trends, anomalies
        )
        decision = DecisionSupportSystem(
            memory, patterns, context, communities, profiling, trends, anomalies, reasoner
        )

        # Create hunting scenarios
        for i in range(3):
            memory.record_ioc_occurrence(f"ioc-hunt-{i}", f"ip-{i}", f"obs_{i}")
            memory.record_campaign_activity(
                f"campaign-hunt-{i}",
                f"Campaign {i}",
                "exploit",
                techniques_used=["T1566", "T1598"]
            )

        priorities = decision.get_hunting_priorities(max_count=5)

        assert isinstance(priorities, list)
        for priority in priorities:
            assert "hunt_type" in priority
            assert "indicator" in priority
            assert "priority" in priority
            assert "guidance" in priority

    def test_hunting_priority_search_locations(self):
        """Test hunting priority includes search locations."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        communities = CommunityDetectionEngine(memory, patterns, context)
        profiling = ActorProfilingEngine(memory, patterns, context)
        trends = TrendAnalyzer(memory, patterns, context)
        anomalies = AnomalyDetector(memory, patterns, context)
        reasoner = ThreatIntelligenceReasoner(
            memory, patterns, context, communities, profiling, trends, anomalies
        )
        decision = DecisionSupportSystem(
            memory, patterns, context, communities, profiling, trends, anomalies, reasoner
        )

        priorities = decision.get_hunting_priorities()

        for priority in priorities:
            assert "search_locations" in priority
            assert len(priority["search_locations"]) > 0


class TestResourceAllocation:
    """Test resource allocation recommendations."""

    def test_get_resource_allocation(self):
        """Test resource allocation recommendations."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        communities = CommunityDetectionEngine(memory, patterns, context)
        profiling = ActorProfilingEngine(memory, patterns, context)
        trends = TrendAnalyzer(memory, patterns, context)
        anomalies = AnomalyDetector(memory, patterns, context)
        reasoner = ThreatIntelligenceReasoner(
            memory, patterns, context, communities, profiling, trends, anomalies
        )
        decision = DecisionSupportSystem(
            memory, patterns, context, communities, profiling, trends, anomalies, reasoner
        )

        allocation = decision.get_resource_allocation()

        assert isinstance(allocation, dict)
        assert "monitoring" in allocation
        assert "hunting" in allocation
        assert "hardening" in allocation
        assert "detection" in allocation

    def test_allocation_hours_valid(self):
        """Test allocation hours are valid."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        communities = CommunityDetectionEngine(memory, patterns, context)
        profiling = ActorProfilingEngine(memory, patterns, context)
        trends = TrendAnalyzer(memory, patterns, context)
        anomalies = AnomalyDetector(memory, patterns, context)
        reasoner = ThreatIntelligenceReasoner(
            memory, patterns, context, communities, profiling, trends, anomalies
        )
        decision = DecisionSupportSystem(
            memory, patterns, context, communities, profiling, trends, anomalies, reasoner
        )

        allocation = decision.get_resource_allocation()

        for resource, details in allocation.items():
            assert details["hours_per_week"] >= 0
            assert details["priority"] in ["critical", "high", "medium", "low"]

    def test_allocation_with_critical_threat(self):
        """Test allocation increases with critical threats."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        communities = CommunityDetectionEngine(memory, patterns, context)
        profiling = ActorProfilingEngine(memory, patterns, context)
        trends = TrendAnalyzer(memory, patterns, context)
        anomalies = AnomalyDetector(memory, patterns, context)
        reasoner = ThreatIntelligenceReasoner(
            memory, patterns, context, communities, profiling, trends, anomalies
        )
        decision = DecisionSupportSystem(
            memory, patterns, context, communities, profiling, trends, anomalies, reasoner
        )

        # Create critical scenario
        for i in range(3):
            memory.record_campaign_activity(f"campaign-crit-{i}", f"Campaign {i}", "exploit")
            campaign = memory.get_campaign_memory(f"campaign-crit-{i}")
            if campaign:
                campaign.is_active = True
                for j in range(8):
                    memory.record_campaign_activity(f"campaign-crit-{i}", f"Campaign {i}", "exploit")

        allocation = decision.get_resource_allocation()

        # With multiple active campaigns, monitoring should get significant hours
        assert allocation["monitoring"]["hours_per_week"] > 0


class TestActionTimeline:
    """Test action timeline planning."""

    def test_get_action_timeline(self):
        """Test action timeline generation."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        communities = CommunityDetectionEngine(memory, patterns, context)
        profiling = ActorProfilingEngine(memory, patterns, context)
        trends = TrendAnalyzer(memory, patterns, context)
        anomalies = AnomalyDetector(memory, patterns, context)
        reasoner = ThreatIntelligenceReasoner(
            memory, patterns, context, communities, profiling, trends, anomalies
        )
        decision = DecisionSupportSystem(
            memory, patterns, context, communities, profiling, trends, anomalies, reasoner
        )

        timeline = decision.get_action_timeline(days=30)

        assert isinstance(timeline, list)
        assert len(timeline) >= 4  # At least immediate, short, medium, long term
        for phase in timeline:
            assert "phase" in phase
            assert "actions" in phase
            assert len(phase["actions"]) > 0

    def test_timeline_phase_sequence(self):
        """Test timeline phases are in correct sequence."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        communities = CommunityDetectionEngine(memory, patterns, context)
        profiling = ActorProfilingEngine(memory, patterns, context)
        trends = TrendAnalyzer(memory, patterns, context)
        anomalies = AnomalyDetector(memory, patterns, context)
        reasoner = ThreatIntelligenceReasoner(
            memory, patterns, context, communities, profiling, trends, anomalies
        )
        decision = DecisionSupportSystem(
            memory, patterns, context, communities, profiling, trends, anomalies, reasoner
        )

        timeline = decision.get_action_timeline()

        phases = [t["phase"] for t in timeline]
        assert "Immediate" in phases[0]
        assert "Long-term" in phases[-1]


class TestDecisionSummary:
    """Test decision support summary."""

    def test_get_decision_summary(self):
        """Test decision support summary generation."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        communities = CommunityDetectionEngine(memory, patterns, context)
        profiling = ActorProfilingEngine(memory, patterns, context)
        trends = TrendAnalyzer(memory, patterns, context)
        anomalies = AnomalyDetector(memory, patterns, context)
        reasoner = ThreatIntelligenceReasoner(
            memory, patterns, context, communities, profiling, trends, anomalies
        )
        decision = DecisionSupportSystem(
            memory, patterns, context, communities, profiling, trends, anomalies, reasoner
        )

        # Create scenario
        for i in range(3):
            memory.record_campaign_activity(f"campaign-summary-{i}", f"Campaign {i}", "exploit")

        summary = decision.get_decision_summary()

        assert "timestamp" in summary
        assert "prioritized_threats" in summary
        assert "hunting_priorities" in summary
        assert "resource_allocation" in summary
        assert "action_timeline" in summary
        assert "summary" in summary

    def test_summary_text_content(self):
        """Test decision summary includes proper content."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        communities = CommunityDetectionEngine(memory, patterns, context)
        profiling = ActorProfilingEngine(memory, patterns, context)
        trends = TrendAnalyzer(memory, patterns, context)
        anomalies = AnomalyDetector(memory, patterns, context)
        reasoner = ThreatIntelligenceReasoner(
            memory, patterns, context, communities, profiling, trends, anomalies
        )
        decision = DecisionSupportSystem(
            memory, patterns, context, communities, profiling, trends, anomalies, reasoner
        )

        summary = decision.get_decision_summary()

        assert "DECISION SUPPORT SUMMARY" in summary["summary"]
        assert "RECOMMENDED RESOURCE ALLOCATION" in summary["summary"]


class TestIntegration:
    """Test decision support integration."""

    def test_complete_decision_support_workflow(self):
        """Test complete decision support workflow."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        communities = CommunityDetectionEngine(memory, patterns, context)
        profiling = ActorProfilingEngine(memory, patterns, context)
        trends = TrendAnalyzer(memory, patterns, context)
        anomalies = AnomalyDetector(memory, patterns, context)
        reasoner = ThreatIntelligenceReasoner(
            memory, patterns, context, communities, profiling, trends, anomalies
        )
        decision = DecisionSupportSystem(
            memory, patterns, context, communities, profiling, trends, anomalies, reasoner
        )

        # Create comprehensive scenario
        for i in range(4):
            memory.record_ioc_occurrence(f"ioc-workflow-{i}", f"ip-{i}", f"obs_{i}")
            memory.record_campaign_activity(
                f"campaign-workflow-{i}",
                f"Campaign {i}",
                "exploit",
                techniques_used=["T1566", "T1598"]
            )
            campaign = memory.get_campaign_memory(f"campaign-workflow-{i}")
            if campaign:
                campaign.attributed_actors.append(f"actor-{i}")
                if i < 2:
                    campaign.is_active = True

        # Execute all decision support functions
        threats = decision.prioritize_threats(limit=5)
        assert len(threats) > 0

        strategies = decision.generate_mitigation_strategies(threats[0].threat_id, threats[0].threat_type)
        assert isinstance(strategies, list)

        priorities = decision.get_hunting_priorities(max_count=3)
        assert isinstance(priorities, list)

        allocation = decision.get_resource_allocation()
        assert allocation["monitoring"]["hours_per_week"] > 0

        timeline = decision.get_action_timeline(days=30)
        assert len(timeline) > 0

        summary = decision.get_decision_summary()
        assert "timestamp" in summary


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
