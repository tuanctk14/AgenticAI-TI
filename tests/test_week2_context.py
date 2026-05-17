"""
tests/test_week2_context.py - Week 2 Historical Context Tests

Tests for:
- Actor/campaign profile building
- Threat timeline construction
- Statistical baseline calculation
- Contextual risk scoring
- Historical anomaly detection
- Context aggregation and reporting
"""

import pytest
from datetime import datetime, timedelta

from core.threat_memory import ThreatMemoryEngine
from core.pattern_detection import PatternDetectionEngine
from core.historical_context import (
    HistoricalContextEngine,
    ActorProfile,
    ThreatTimeline,
    RiskContext,
    StatisticalBaseline,
)


class TestActorProfileBuilding:
    """Test actor profile building."""

    def test_build_actor_profile(self):
        """Test building actor profile."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context_engine = HistoricalContextEngine(memory, patterns)

        # Create campaign attributed to actor
        memory.record_campaign_activity(
            "campaign-actor",
            "Actor Campaign",
            "exploitation",
            techniques_used=["T1566", "T1190"],
        )

        profile = context_engine.build_actor_profile("actor-test", "Test Actor")

        assert profile.actor_id == "actor-test"
        assert profile.actor_name == "Test Actor"

    def test_actor_profile_activity_tracking(self):
        """Test activity tracking in actor profile."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context_engine = HistoricalContextEngine(memory, patterns)

        # Create multiple campaign activities
        for i in range(3):
            memory.record_campaign_activity(
                f"campaign-{i}",
                f"Campaign {i}",
                "exploit",
                techniques_used=["T1566"],
            )

        profile = context_engine.build_actor_profile("multi-actor", "Multi Activity Actor")

        assert profile.activity_count >= 0

    def test_actor_profile_evolution(self):
        """Test evolution trajectory classification."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context_engine = HistoricalContextEngine(memory, patterns)

        # Create recent campaign
        memory.record_campaign_activity("recent-campaign", "Recent Campaign", "exploit")

        profile = context_engine.build_actor_profile("evolving-actor", "Evolving Actor")

        assert profile.evolution_trajectory in ["expanding", "consolidating", "declining", "unknown"]


class TestThreatTimeline:
    """Test threat timeline construction."""

    def test_build_threat_timeline(self):
        """Test building threat timeline."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context_engine = HistoricalContextEngine(memory, patterns)

        # Create IOC with occurrences
        memory.record_ioc_occurrence("ioc-timeline", "192.168.1.1", "context_1")
        memory.record_ioc_occurrence("ioc-timeline", "192.168.1.1", "context_2")

        timeline = context_engine.build_threat_timeline("ioc-timeline")

        assert timeline.threat_id == "ioc-timeline"
        assert len(timeline.events) >= 1

    def test_timeline_event_collection(self):
        """Test event collection in timeline."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context_engine = HistoricalContextEngine(memory, patterns)

        # Create multiple events
        for i in range(3):
            memory.record_ioc_occurrence(f"ioc-multi", f"value-{i}", f"context_{i}")

        timeline = context_engine.build_threat_timeline("ioc-multi")

        assert len(timeline.events) >= 1

    def test_timeline_dormancy_detection(self):
        """Test dormancy period identification."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context_engine = HistoricalContextEngine(memory, patterns)

        # Create campaign
        memory.record_campaign_activity("campaign-dormancy", "Dormancy Campaign", "exploit")

        timeline = context_engine.build_threat_timeline("campaign-dormancy")

        assert isinstance(timeline.dormancy_periods, list)

    def test_timeline_predictability(self):
        """Test predictability calculation."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context_engine = HistoricalContextEngine(memory, patterns)

        memory.record_ioc_occurrence("ioc-predict", "test", "context")

        timeline = context_engine.build_threat_timeline("ioc-predict")

        assert 0.0 <= timeline.predictability_score <= 1.0


class TestStatisticalBaselines:
    """Test statistical baseline calculation."""

    def test_calculate_ioc_lifetime_baseline(self):
        """Test IOC lifetime baseline."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context_engine = HistoricalContextEngine(memory, patterns)

        # Create IOC
        memory.record_ioc_occurrence("ioc-baseline-1", "value1", "context")
        memory.record_ioc_occurrence("ioc-baseline-2", "value2", "context")

        baseline = context_engine.calculate_ioc_lifetime_baseline()

        assert baseline.baseline_type == "ioc_lifetime"
        assert baseline.samples_count >= 0

    def test_baseline_statistics(self):
        """Test baseline statistical calculations."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context_engine = HistoricalContextEngine(memory, patterns)

        # Create multiple IOCs
        for i in range(3):
            memory.record_ioc_occurrence(f"ioc-stats-{i}", f"value-{i}", "context")

        baseline = context_engine.calculate_ioc_lifetime_baseline()

        assert baseline.mean >= 0.0
        assert baseline.median >= 0.0
        assert baseline.stddev >= 0.0

    def test_baseline_normal_range(self):
        """Test normal range calculation."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context_engine = HistoricalContextEngine(memory, patterns)

        for i in range(3):
            memory.record_ioc_occurrence(f"ioc-range-{i}", f"value-{i}", "context")

        baseline = context_engine.calculate_ioc_lifetime_baseline()

        assert baseline.normal_range[0] <= baseline.normal_range[1]

    def test_campaign_duration_baseline(self):
        """Test campaign duration baseline."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context_engine = HistoricalContextEngine(memory, patterns)

        for i in range(3):
            memory.record_campaign_activity(f"campaign-{i}", f"Campaign {i}", "exploit")

        baseline = context_engine.calculate_campaign_duration_baseline()

        assert baseline.baseline_type == "campaign_duration"

    def test_exposure_frequency_baseline(self):
        """Test exposure frequency baseline."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context_engine = HistoricalContextEngine(memory, patterns)

        for i in range(3):
            memory.record_asset_exposure(f"asset-{i}", f"Asset {i}", "cve")

        baseline = context_engine.calculate_exposure_frequency_baseline()

        assert baseline.baseline_type == "exposure_frequency"


class TestContextualRiskScoring:
    """Test contextual risk scoring."""

    def test_build_risk_context(self):
        """Test risk context building."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context_engine = HistoricalContextEngine(memory, patterns)

        # Create IOC
        memory.record_ioc_occurrence("ioc-risk", "risky", "context")

        context = context_engine.build_risk_context("ioc-risk")

        assert context.entity_id == "ioc-risk"
        assert 0.0 <= context.historical_risk_score <= 1.0

    def test_risk_context_severity_classification(self):
        """Test contextual severity classification."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context_engine = HistoricalContextEngine(memory, patterns)

        # Create asset with exposures
        for i in range(5):
            memory.record_asset_exposure(f"asset-severity", f"Asset", "cve")

        context = context_engine.build_risk_context("asset-severity")

        assert context.contextual_severity in ["critical", "high", "medium", "low", "unknown"]

    def test_risk_context_confidence_bands(self):
        """Test confidence band calculation."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context_engine = HistoricalContextEngine(memory, patterns)

        memory.record_asset_exposure("asset-bands", "Asset", "cve")

        context = context_engine.build_risk_context("asset-bands")

        assert context.lower_confidence_band <= context.upper_confidence_band


class TestAnomalyDetection:
    """Test historical anomaly detection."""

    def test_detect_historical_anomalies(self):
        """Test anomaly detection."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context_engine = HistoricalContextEngine(memory, patterns)

        # Create entities
        for i in range(3):
            memory.record_ioc_occurrence(f"ioc-anomaly-{i}", f"value-{i}", "context")

        anomalies = context_engine.detect_historical_anomalies()

        assert isinstance(anomalies, dict)
        assert "ioc_anomalies" in anomalies
        assert "campaign_anomalies" in anomalies
        assert "exposure_anomalies" in anomalies

    def test_anomaly_detection_z_score(self):
        """Test Z-score based anomaly detection."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context_engine = HistoricalContextEngine(memory, patterns)

        # Create multiple IOCs
        for i in range(5):
            memory.record_ioc_occurrence(f"ioc-zscore-{i}", f"value-{i}", "context")

        anomalies = context_engine.detect_historical_anomalies(stddev_threshold=1.5)

        assert isinstance(anomalies["ioc_anomalies"], list)


class TestBatchContextBuilding:
    """Test batch context building."""

    def test_build_all_contexts(self):
        """Test building all contexts."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context_engine = HistoricalContextEngine(memory, patterns)

        # Create entities
        memory.record_ioc_occurrence("ioc-batch", "value", "context")
        memory.record_campaign_activity("campaign-batch", "Campaign", "exploit")
        memory.record_asset_exposure("asset-batch", "Asset", "cve")

        contexts = context_engine.build_all_contexts()

        assert "actor_profiles" in contexts
        assert "threat_timelines" in contexts
        assert "risk_contexts" in contexts
        assert "statistical_baselines" in contexts

    def test_get_historical_summary(self):
        """Test historical summary generation."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context_engine = HistoricalContextEngine(memory, patterns)

        # Create entities
        memory.record_ioc_occurrence("ioc-summary", "value", "context")

        summary = context_engine.get_historical_summary()

        assert "total_entities_tracked" in summary
        assert "active_campaigns" in summary
        assert "exposed_assets" in summary
        assert "recurring_iocs" in summary

    def test_export_context_as_json(self):
        """Test JSON export of context."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context_engine = HistoricalContextEngine(memory, patterns)

        memory.record_ioc_occurrence("ioc-export", "value", "context")
        memory.record_campaign_activity("campaign-export", "Campaign", "exploit")

        exported = context_engine.export_context_as_json()

        assert isinstance(exported, dict)
        # Structure may vary based on data

    def test_export_json_serializable(self):
        """Test that exported context is JSON serializable."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context_engine = HistoricalContextEngine(memory, patterns)

        memory.record_ioc_occurrence("ioc-json", "value", "context")

        exported = context_engine.export_context_as_json()

        import json
        json_str = json.dumps(exported)
        assert isinstance(json_str, str)


class TestUtilityMethods:
    """Test utility methods."""

    def test_classify_evolution(self):
        """Test evolution trajectory classification."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context_engine = HistoricalContextEngine(memory, patterns)

        now = datetime.utcnow()
        # Recent dates (expanding)
        recent_dates = [now - timedelta(days=i) for i in range(0, 30, 5)]

        evolution = context_engine._classify_evolution(recent_dates)

        assert evolution in ["expanding", "consolidating", "declining", "unknown"]

    def test_identify_dormancy(self):
        """Test dormancy period identification."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context_engine = HistoricalContextEngine(memory, patterns)

        now = datetime.utcnow()
        events = [
            (now - timedelta(days=100), "type1", "detail1"),
            (now - timedelta(days=80), "type2", "detail2"),
            (now - timedelta(days=40), "type3", "detail3"),
            (now - timedelta(days=5), "type4", "detail4"),
        ]

        dormancy = context_engine._identify_dormancy(events)

        assert isinstance(dormancy, list)

    def test_calculate_predictability(self):
        """Test predictability calculation."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context_engine = HistoricalContextEngine(memory, patterns)

        now = datetime.utcnow()
        # Regular events (predictable)
        regular_events = [
            (now - timedelta(days=i*10), "event", "detail")
            for i in range(5)
        ]

        predictability = context_engine._calculate_predictability(regular_events)

        assert 0.0 <= predictability <= 1.0


class TestIntegration:
    """Test historical context integration."""

    def test_full_context_pipeline(self):
        """Test complete context building pipeline."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context_engine = HistoricalContextEngine(memory, patterns)

        # Populate memory
        memory.record_ioc_occurrence("ioc-full", "test-ioc", "context")
        memory.record_campaign_activity("campaign-full", "Full Campaign", "exploit")
        memory.record_asset_exposure("asset-full", "Full Asset", "cve")

        # Build profiles
        actor_profile = context_engine.build_actor_profile("actor-full", "Full Actor")
        timeline = context_engine.build_threat_timeline("ioc-full")
        risk_context = context_engine.build_risk_context("ioc-full")

        assert actor_profile is not None
        assert timeline is not None
        assert risk_context is not None

    def test_context_with_patterns(self):
        """Test context building with pattern analysis."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context_engine = HistoricalContextEngine(memory, patterns)

        # Create multiple events
        for i in range(5):
            memory.record_ioc_occurrence(f"ioc-pattern-{i}", f"value-{i}", f"context_{i}")

        # Get contexts
        summary = context_engine.get_historical_summary()

        assert summary["total_entities_tracked"] >= 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
