"""
tests/test_week3_trend_analysis.py - Trend Analysis Tests

Tests for:
- IOC activity trends (rising/stable/declining)
- Campaign activity surge detection
- Technique adoption trends
- Target preference shifts
- Actor emergence and dormancy
- Global threat tempo analysis
"""

import pytest
from datetime import datetime, timedelta

from core.threat_memory import ThreatMemoryEngine
from core.pattern_detection import PatternDetectionEngine
from core.historical_context import HistoricalContextEngine
from core.trend_analysis import TrendAnalyzer


class TestIOCTrends:
    """Test IOC activity trend analysis."""

    def test_analyze_ioc_trends(self):
        """Test IOC trend analysis."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        analyzer = TrendAnalyzer(memory, patterns, context)

        # Record IOC occurrences
        for i in range(3):
            memory.record_ioc_occurrence(f"ioc-{i}", f"ip-{i}", f"obs_{i}")

        trends = analyzer.analyze_ioc_trends(days_window=90)

        assert isinstance(trends, list)
        assert all("trend" in t for t in trends)
        assert all(t["trend"] in ["rising", "stable", "declining", "emerging"] for t in trends)

    def test_ioc_trend_properties(self):
        """Test IOC trend result properties."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        analyzer = TrendAnalyzer(memory, patterns, context)

        memory.record_ioc_occurrence("ioc-prop", "test-ip", "obs_1")

        trends = analyzer.analyze_ioc_trends()

        for trend in trends:
            assert "ioc_id" in trend
            assert "ioc_value" in trend
            assert "first_half_count" in trend
            assert "second_half_count" in trend
            assert "total_occurrences" in trend

    def test_empty_ioc_trends(self):
        """Test trend analysis with no IOCs."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        analyzer = TrendAnalyzer(memory, patterns, context)

        trends = analyzer.analyze_ioc_trends()

        assert isinstance(trends, list)


class TestCampaignSurges:
    """Test campaign activity surge detection."""

    def test_detect_campaign_surge(self):
        """Test campaign activity surge detection."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        analyzer = TrendAnalyzer(memory, patterns, context)

        # Create campaign with activities
        for i in range(5):
            memory.record_campaign_activity("campaign-surge", "Campaign", "exploit")

        surges = analyzer.analyze_campaign_activity_surge()

        assert isinstance(surges, list)
        for surge in surges:
            assert "campaign_id" in surge
            assert "is_surge" in surge
            assert "surge_ratio" in surge

    def test_surge_properties(self):
        """Test surge detection properties."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        analyzer = TrendAnalyzer(memory, patterns, context)

        for i in range(6):
            memory.record_campaign_activity("campaign-test", "Campaign", "exploit")

        surges = analyzer.analyze_campaign_activity_surge(threshold=1.5)

        for surge in surges:
            assert surge["surge_ratio"] >= 0.0
            assert isinstance(surge["is_surge"], bool)

    def test_surge_with_low_threshold(self):
        """Test surge detection with low threshold."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        analyzer = TrendAnalyzer(memory, patterns, context)

        memory.record_campaign_activity("campaign-low", "Campaign", "exploit")
        memory.record_campaign_activity("campaign-low", "Campaign", "exploit")

        surges = analyzer.analyze_campaign_activity_surge(threshold=1.0)

        assert isinstance(surges, list)


class TestTechniqueTrends:
    """Test technique adoption trend analysis."""

    def test_analyze_technique_trends(self):
        """Test technique adoption trend analysis."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        analyzer = TrendAnalyzer(memory, patterns, context)

        # Create campaigns with techniques
        for i in range(2):
            memory.record_campaign_activity(
                f"campaign-tech-{i}",
                f"Campaign {i}",
                "exploit",
                techniques_used=["T1566", "T1598"]
            )

        trends = analyzer.analyze_technique_adoption_trends(days_window=90)

        assert isinstance(trends, list)
        for trend in trends:
            assert "technique" in trend
            assert "trend" in trend
            assert trend["trend"] in ["rising", "stable", "declining", "emerging"]

    def test_technique_trend_properties(self):
        """Test technique trend properties."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        analyzer = TrendAnalyzer(memory, patterns, context)

        memory.record_campaign_activity(
            "campaign-tech-prop",
            "Campaign",
            "exploit",
            techniques_used=["T1566"]
        )

        trends = analyzer.analyze_technique_adoption_trends()

        for trend in trends:
            assert "total_usage" in trend
            assert "first_half_usage" in trend
            assert "second_half_usage" in trend


class TestTargetShifts:
    """Test target preference shift analysis."""

    def test_analyze_target_shifts(self):
        """Test target preference shift analysis."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        analyzer = TrendAnalyzer(memory, patterns, context)

        # Create campaigns with sector targets
        for i in range(2):
            memory.record_campaign_activity(
                f"campaign-target-{i}",
                f"Campaign {i}",
                "exploit"
            )
            campaign = memory.get_campaign_memory(f"campaign-target-{i}")
            if campaign:
                campaign.current_targets.extend(["bank-1", "bank-2"])

        shifts = analyzer.analyze_target_preference_shift(days_window=90)

        assert isinstance(shifts, list)
        for shift in shifts:
            assert "sector" in shift
            assert "preference_shift" in shift

    def test_target_shift_properties(self):
        """Test target shift properties."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        analyzer = TrendAnalyzer(memory, patterns, context)

        memory.record_campaign_activity("campaign-shift", "Campaign", "exploit")
        campaign = memory.get_campaign_memory("campaign-shift")
        if campaign:
            campaign.current_targets.append("hospital-1")

        shifts = analyzer.analyze_target_preference_shift()

        for shift in shifts:
            assert "total_targets" in shift
            assert "change_percent" in shift


class TestEmergingActors:
    """Test emerging actor detection."""

    def test_detect_emerging_actors(self):
        """Test emerging actor detection."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        analyzer = TrendAnalyzer(memory, patterns, context)

        # Create recent campaign
        memory.record_campaign_activity("campaign-emerging", "Campaign", "exploit")
        campaign = memory.get_campaign_memory("campaign-emerging")
        if campaign:
            campaign.attributed_actors.append("actor-new")

        emerging = analyzer.detect_emerging_actors(recent_days=60)

        assert isinstance(emerging, list)
        for actor in emerging:
            assert "actor_id" in actor
            assert "days_since_emergence" in actor

    def test_emerging_actor_velocity(self):
        """Test emerging actor activity velocity."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        analyzer = TrendAnalyzer(memory, patterns, context)

        for i in range(3):
            memory.record_campaign_activity(f"campaign-vel-{i}", f"Campaign {i}", "exploit")
            campaign = memory.get_campaign_memory(f"campaign-vel-{i}")
            if campaign:
                campaign.attributed_actors.append("actor-velocity")

        emerging = analyzer.detect_emerging_actors(recent_days=365)

        for actor in emerging:
            assert "emergence_velocity" in actor


class TestDormantActors:
    """Test dormant actor detection."""

    def test_detect_dormant_actors(self):
        """Test dormant actor detection."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        analyzer = TrendAnalyzer(memory, patterns, context)

        memory.record_campaign_activity("campaign-dormant", "Campaign", "exploit")
        campaign = memory.get_campaign_memory("campaign-dormant")
        if campaign:
            campaign.attributed_actors.append("actor-dormant")

        dormant = analyzer.detect_dormant_actors(dormant_days=180)

        assert isinstance(dormant, list)
        for actor in dormant:
            assert "actor_id" in actor
            assert "days_dormant" in actor

    def test_dormant_actor_properties(self):
        """Test dormant actor result properties."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        analyzer = TrendAnalyzer(memory, patterns, context)

        memory.record_campaign_activity("campaign-dorm-prop", "Campaign", "exploit")
        campaign = memory.get_campaign_memory("campaign-dorm-prop")
        if campaign:
            campaign.attributed_actors.append("actor-dorm")

        dormant = analyzer.detect_dormant_actors()

        for actor in dormant:
            assert actor["days_dormant"] >= 0
            assert "last_observed" in actor


class TestGlobalTempo:
    """Test global threat tempo analysis."""

    def test_analyze_global_tempo(self):
        """Test global threat tempo analysis."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        analyzer = TrendAnalyzer(memory, patterns, context)

        # Create campaigns with activities
        for i in range(3):
            memory.record_campaign_activity(f"campaign-tempo-{i}", f"Campaign {i}", "exploit")
            memory.record_campaign_activity(f"campaign-tempo-{i}", f"Campaign {i}", "exploit")

        tempo = analyzer.analyze_threat_tempo_global(window_days=90)

        assert isinstance(tempo, dict)
        assert "activity_trend" in tempo
        assert "tempo_classification" in tempo
        assert tempo["window_days"] == 90

    def test_tempo_properties(self):
        """Test tempo analysis properties."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        analyzer = TrendAnalyzer(memory, patterns, context)

        memory.record_campaign_activity("campaign-tempo-prop", "Campaign", "exploit")

        tempo = analyzer.analyze_threat_tempo_global()

        assert "total_activity_events" in tempo
        assert "avg_daily_events" in tempo
        assert "tempo_classification" in tempo


class TestAnomalousActivity:
    """Test anomalous activity surge detection."""

    def test_detect_anomalies(self):
        """Test anomalous activity detection."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        analyzer = TrendAnalyzer(memory, patterns, context)

        # Create multiple activities
        for i in range(10):
            memory.record_campaign_activity(f"campaign-anom-{i}", f"Campaign {i}", "exploit")

        anomalies = analyzer.detect_anomalous_activity_surge(threshold=2.0)

        assert isinstance(anomalies, list)
        for anomaly in anomalies:
            assert "date" in anomaly
            assert "z_score" in anomaly

    def test_anomaly_surge_detection(self):
        """Test anomaly surge vs drop detection."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        analyzer = TrendAnalyzer(memory, patterns, context)

        for i in range(8):
            memory.record_campaign_activity(f"campaign-surge-{i}", f"Campaign {i}", "exploit")

        anomalies = analyzer.detect_anomalous_activity_surge(threshold=1.5)

        for anomaly in anomalies:
            assert isinstance(anomaly["is_surge"], bool)
            assert isinstance(anomaly["is_drop"], bool)


class TestTrendSummary:
    """Test comprehensive trend summary."""

    def test_get_trend_summary(self):
        """Test comprehensive trend summary."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        analyzer = TrendAnalyzer(memory, patterns, context)

        # Create test data
        for i in range(3):
            memory.record_ioc_occurrence(f"ioc-summary-{i}", f"ip-{i}", f"obs_{i}")
            memory.record_campaign_activity(
                f"campaign-summary-{i}",
                f"Campaign {i}",
                "exploit",
                techniques_used=["T1566"]
            )

        summary = analyzer.get_trend_summary()

        assert isinstance(summary, dict)
        assert "ioc_trends" in summary
        assert "campaign_surges" in summary
        assert "technique_trends" in summary
        assert "target_shifts" in summary
        assert "emerging_actors" in summary
        assert "dormant_actors" in summary
        assert "global_tempo" in summary
        assert "anomalous_activity" in summary

    def test_summary_completeness(self):
        """Test that summary contains all analysis results."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        analyzer = TrendAnalyzer(memory, patterns, context)

        summary = analyzer.get_trend_summary()

        for key in ["ioc_trends", "campaign_surges", "technique_trends", "target_shifts"]:
            assert key in summary
            assert isinstance(summary[key], list)


class TestIntegration:
    """Test trend analysis integration."""

    def test_complete_trend_analysis_workflow(self):
        """Test complete trend analysis workflow."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        analyzer = TrendAnalyzer(memory, patterns, context)

        # Create complex scenario
        for i in range(5):
            memory.record_ioc_occurrence(f"ioc-{i}", f"ip-{i}", f"obs_{i}")
            memory.record_campaign_activity(
                f"campaign-{i}",
                f"Campaign {i}",
                "exploit",
                techniques_used=["T1566", "T1598"]
            )
            campaign = memory.get_campaign_memory(f"campaign-{i}")
            if campaign:
                campaign.attributed_actors.append(f"actor-{i % 2}")
                campaign.current_targets.extend(["bank-1", "finance-2"])

        # Perform all analyses
        ioc_trends = analyzer.analyze_ioc_trends()
        assert len(ioc_trends) > 0

        campaign_surges = analyzer.analyze_campaign_activity_surge()
        assert isinstance(campaign_surges, list)

        tech_trends = analyzer.analyze_technique_adoption_trends()
        assert len(tech_trends) > 0

        target_shifts = analyzer.analyze_target_preference_shift()
        assert isinstance(target_shifts, list)

        emerging = analyzer.detect_emerging_actors()
        assert isinstance(emerging, list)

        dormant = analyzer.detect_dormant_actors()
        assert isinstance(dormant, list)

        global_tempo = analyzer.analyze_threat_tempo_global()
        assert global_tempo["total_activity_events"] >= 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
