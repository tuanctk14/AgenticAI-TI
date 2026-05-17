"""
tests/test_week4_reasoning.py - Threat Intelligence Reasoning Tests

Tests for:
- Threat assessment and level determination
- Entity threat scoring
- Tactical recommendations
- Strategic intelligence synthesis
- Attack path analysis
- Complete report generation
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
from core.threat_intelligence_reasoner import (
    ThreatIntelligenceReasoner,
    ThreatAssessment,
)


class TestThreatAssessment:
    """Test threat assessment."""

    def test_create_threat_assessment(self):
        """Test creating threat assessment."""
        assessment = ThreatAssessment("assessment-1")

        assert assessment.assessment_id == "assessment-1"
        assert assessment.threat_level == "unknown"
        assert 0.0 <= assessment.confidence_score <= 1.0

    def test_assessment_to_dict(self):
        """Test assessment serialization."""
        assessment = ThreatAssessment("test-assess")
        assessment.threat_level = "high"
        assessment.confidence_score = 0.85
        assessment.risk_score = 0.65

        data = assessment.to_dict()

        assert data["assessment_id"] == "test-assess"
        assert data["threat_level"] == "high"
        assert data["confidence_score"] == 0.85


class TestGlobalThreatAssessment:
    """Test global threat assessment."""

    def test_assess_threat_level(self):
        """Test global threat level assessment."""
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

        assessment = reasoner.assess_threat_level()

        assert isinstance(assessment, ThreatAssessment)
        assert assessment.threat_level in ["critical", "high", "medium", "elevated", "low"]
        assert 0.0 <= assessment.confidence_score <= 1.0

    def test_assessment_with_active_campaigns(self):
        """Test assessment with active campaigns."""
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

        # Create active campaigns
        for i in range(3):
            memory.record_campaign_activity(f"campaign-active-{i}", f"Campaign {i}", "exploit")
            campaign = memory.get_campaign_memory(f"campaign-active-{i}")
            if campaign:
                campaign.is_active = True

        assessment = reasoner.assess_threat_level()

        assert assessment.affected_entities["active_campaigns"] >= 3


class TestEntityThreatAssessment:
    """Test entity-level threat assessment."""

    def test_assess_campaign_threat(self):
        """Test campaign threat assessment."""
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

        memory.record_campaign_activity("campaign-entity", "Campaign", "exploit")
        campaign = memory.get_campaign_memory("campaign-entity")
        if campaign:
            campaign.is_active = True
            campaign.attributed_actors.append("actor-1")

        assessment = reasoner.assess_entity_threat("campaign", "campaign-entity")

        assert assessment["entity_type"] == "campaign"
        assert assessment["threat_level"] in ["critical", "high", "medium", "elevated", "low"]
        assert 0.0 <= assessment["risk_score"] <= 1.0
        assert len(assessment["factors"]) > 0

    def test_assess_actor_threat(self):
        """Test actor threat assessment."""
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

        memory.record_campaign_activity("campaign-actor-threat", "Campaign", "exploit")
        campaign = memory.get_campaign_memory("campaign-actor-threat")
        if campaign:
            campaign.attributed_actors.append("actor-threat")

        assessment = reasoner.assess_entity_threat("actor", "actor-threat")

        assert assessment["entity_type"] == "actor"
        assert assessment["threat_level"] in ["critical", "high", "medium", "low", "unknown"]

    def test_assess_ioc_threat(self):
        """Test IOC threat assessment."""
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

        memory.record_ioc_occurrence("ioc-threat", "192.168.1.1", "obs_1")

        assessment = reasoner.assess_entity_threat("ioc", "ioc-threat")

        assert assessment["entity_type"] == "ioc"
        assert assessment["threat_level"] in ["critical", "high", "medium", "low"]

    def test_assess_unknown_entity(self):
        """Test assessment for unknown entity."""
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

        assessment = reasoner.assess_entity_threat("campaign", "unknown-campaign")

        assert assessment["threat_level"] == "unknown"


class TestTacticalRecommendations:
    """Test tactical recommendations."""

    def test_get_tactical_recommendations(self):
        """Test generating tactical recommendations."""
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

        # Create scenario with active campaign
        memory.record_campaign_activity("campaign-tactical", "Campaign", "exploit")
        campaign = memory.get_campaign_memory("campaign-tactical")
        if campaign:
            campaign.is_active = True

        recommendations = reasoner.get_tactical_recommendations()

        assert "immediate_actions" in recommendations
        assert "detection_actions" in recommendations
        assert "remediation_actions" in recommendations
        assert "prioritized_targets" in recommendations

    def test_recommendations_with_anomalies(self):
        """Test recommendations based on anomalies."""
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

        # Create IOCs
        for i in range(8):
            memory.record_ioc_occurrence(f"ioc-anom-{i}", f"ip-{i}", f"obs_{i}")

        recommendations = reasoner.get_tactical_recommendations()

        assert isinstance(recommendations["immediate_actions"], list)


class TestStrategicIntelligence:
    """Test strategic intelligence synthesis."""

    def test_get_strategic_intelligence(self):
        """Test strategic intelligence generation."""
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

        # Create scenario
        for i in range(3):
            memory.record_campaign_activity(f"campaign-strat-{i}", f"Campaign {i}", "exploit")
            campaign = memory.get_campaign_memory(f"campaign-strat-{i}")
            if campaign:
                campaign.attributed_actors.append(f"actor-{i}")

        intelligence = reasoner.get_strategic_intelligence()

        assert "threat_landscape_overview" in intelligence
        assert "actor_landscape" in intelligence
        assert "emerging_trends" in intelligence
        assert "long_term_patterns" in intelligence

    def test_intelligence_completeness(self):
        """Test intelligence report completeness."""
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

        intelligence = reasoner.get_strategic_intelligence()

        assert len(intelligence["threat_landscape_overview"]) > 0


class TestAttackPathAnalysis:
    """Test attack path analysis."""

    def test_analyze_attack_path(self):
        """Test attack path analysis."""
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

        # Create asset with targeted campaigns
        memory.record_asset_exposure("asset-1", "Server", "cve")
        memory.record_campaign_activity("campaign-path", "Campaign", "exploit")
        campaign = memory.get_campaign_memory("campaign-path")
        if campaign:
            campaign.current_targets.append("asset-1")
            campaign.attributed_actors.append("actor-path")

        analysis = reasoner.analyze_attack_path("asset-1")

        assert analysis["asset_id"] == "asset-1"
        assert len(analysis["attack_paths"]) > 0
        assert len(analysis["threat_actors"]) > 0
        assert analysis["risk_level"] in ["critical", "high", "medium", "low"]

    def test_attack_path_with_no_attacks(self):
        """Test attack path for asset with no attacks."""
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

        memory.record_asset_exposure("asset-safe", "Server", "cve")

        analysis = reasoner.analyze_attack_path("asset-safe")

        assert analysis["risk_level"] == "low"
        assert len(analysis["attack_paths"]) == 0


class TestCompleteReport:
    """Test complete report generation."""

    def test_get_complete_report(self):
        """Test complete intelligence report generation."""
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

        report = reasoner.get_complete_intelligence_report()

        assert "timestamp" in report
        assert "threat_assessment" in report
        assert "tactical_recommendations" in report
        assert "strategic_intelligence" in report
        assert "report_summary" in report

    def test_report_summary_generation(self):
        """Test report summary generation."""
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

        report = reasoner.get_complete_intelligence_report()

        assert "THREAT INTELLIGENCE REPORT" in report["report_summary"]
        assert "EXECUTIVE SUMMARY" in report["report_summary"]
        assert "KEY FINDINGS" in report["report_summary"]


class TestIntegration:
    """Test reasoning engine integration."""

    def test_complete_reasoning_workflow(self):
        """Test complete reasoning workflow."""
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

        # Create complex scenario
        for i in range(4):
            memory.record_ioc_occurrence(f"ioc-full-{i}", f"ip-{i}", f"obs_{i}")
            memory.record_campaign_activity(
                f"campaign-full-{i}",
                f"Campaign {i}",
                "exploit",
                techniques_used=["T1566"]
            )
            campaign = memory.get_campaign_memory(f"campaign-full-{i}")
            if campaign:
                campaign.attributed_actors.append("actor-full")
                if i % 2 == 0:
                    campaign.is_active = True

        memory.record_asset_exposure("asset-full", "Server", "cve")
        asset = memory.get_asset_memory("asset-full")
        if asset:
            camp = memory.get_campaign_memory("campaign-full-0")
            if camp:
                camp.current_targets.append("asset-full")

        # Execute all reasoning
        assessment = reasoner.assess_threat_level()
        assert assessment.threat_level != "unknown"

        entity_assessment = reasoner.assess_entity_threat("campaign", "campaign-full-0")
        assert entity_assessment["threat_level"] != "unknown"

        recommendations = reasoner.get_tactical_recommendations()
        assert len(recommendations["immediate_actions"]) >= 0

        intelligence = reasoner.get_strategic_intelligence()
        assert len(intelligence["threat_landscape_overview"]) > 0

        attack_path = reasoner.analyze_attack_path("asset-full")
        assert len(attack_path["attack_paths"]) > 0

        report = reasoner.get_complete_intelligence_report()
        assert "timestamp" in report


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
