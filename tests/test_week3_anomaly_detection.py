"""
tests/test_week3_anomaly_detection.py - Anomaly Detection Tests

Tests for:
- IOC reuse anomalies
- Campaign timing irregularities
- Technique adoption anomalies
- Actor behavior changes
- Infrastructure anomalies
- Risk scoring
"""

import pytest
from datetime import datetime, timedelta

from core.threat_memory import ThreatMemoryEngine
from core.pattern_detection import PatternDetectionEngine
from core.historical_context import HistoricalContextEngine
from core.anomaly_detection import AnomalyDetector


class TestIOCReuseAnomalies:
    """Test IOC reuse anomaly detection."""

    def test_detect_ioc_anomalies(self):
        """Test IOC reuse anomaly detection."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        detector = AnomalyDetector(memory, patterns, context)

        # Create IOCs with varying reuse
        for i in range(5):
            memory.record_ioc_occurrence(f"ioc-{i}", f"ip-{i}", f"obs_{i}")

        anomalies = detector.detect_ioc_reuse_anomalies()

        assert isinstance(anomalies, list)
        for anomaly in anomalies:
            assert "ioc_id" in anomaly
            assert "z_score" in anomaly
            assert "occurrence_count" in anomaly

    def test_ioc_anomaly_properties(self):
        """Test IOC anomaly result properties."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        detector = AnomalyDetector(memory, patterns, context)

        for i in range(6):
            memory.record_ioc_occurrence(f"ioc-prop-{i}", f"ip-{i}", f"obs_{i}")

        anomalies = detector.detect_ioc_reuse_anomalies(z_score_threshold=1.0)

        for anomaly in anomalies:
            assert "is_over_reused" in anomaly
            assert "is_under_reused" in anomaly
            assert isinstance(anomaly["is_over_reused"], bool)

    def test_ioc_anomaly_empty(self):
        """Test IOC anomaly detection with insufficient data."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        detector = AnomalyDetector(memory, patterns, context)

        anomalies = detector.detect_ioc_reuse_anomalies()

        assert isinstance(anomalies, list)


class TestCampaignTimingAnomalies:
    """Test campaign timing anomaly detection."""

    def test_detect_campaign_timing_anomalies(self):
        """Test campaign timing anomaly detection."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        detector = AnomalyDetector(memory, patterns, context)

        # Create campaigns with activities
        for i in range(6):
            for j in range(3):
                memory.record_campaign_activity(f"campaign-time-{i}", f"Campaign {i}", "exploit")

        anomalies = detector.detect_campaign_timing_anomalies()

        assert isinstance(anomalies, list)
        for anomaly in anomalies:
            assert "campaign_id" in anomaly
            assert "duration_days" in anomaly
            assert "z_score" in anomaly

    def test_timing_anomaly_properties(self):
        """Test timing anomaly properties."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        detector = AnomalyDetector(memory, patterns, context)

        for i in range(6):
            for j in range(2):
                memory.record_campaign_activity(f"campaign-{i}", f"Campaign {i}", "exploit")

        anomalies = detector.detect_campaign_timing_anomalies(z_score_threshold=1.5)

        for anomaly in anomalies:
            assert "is_unusually_long" in anomaly
            assert "is_unusually_short" in anomaly


class TestTechniqueAnomalies:
    """Test technique adoption anomalies."""

    def test_detect_technique_anomalies(self):
        """Test technique adoption anomaly detection."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        detector = AnomalyDetector(memory, patterns, context)

        # Create campaigns with varying techniques
        tech_list = ["T1566", "T1598", "T1192", "T1199"]
        for i in range(6):
            memory.record_campaign_activity(
                f"campaign-tech-anom-{i}",
                f"Campaign {i}",
                "exploit",
                techniques_used=tech_list[:((i % 4) + 1)]
            )

        anomalies = detector.detect_technique_adoption_anomalies()

        assert isinstance(anomalies, list)
        for anomaly in anomalies:
            assert "technique" in anomaly
            assert "usage_count" in anomaly
            assert "z_score" in anomaly

    def test_technique_anomaly_properties(self):
        """Test technique anomaly properties."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        detector = AnomalyDetector(memory, patterns, context)

        for i in range(6):
            memory.record_campaign_activity(
                f"campaign-tech-prop-{i}",
                f"Campaign {i}",
                "exploit",
                techniques_used=["T1566"]
            )

        anomalies = detector.detect_technique_adoption_anomalies(z_score_threshold=1.0)

        for anomaly in anomalies:
            assert "is_unusually_common" in anomaly
            assert "is_unusually_rare" in anomaly


class TestActorBehaviorChanges:
    """Test actor behavior change detection."""

    def test_detect_behavior_changes(self):
        """Test actor behavior change detection."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        detector = AnomalyDetector(memory, patterns, context)

        # Create actor with changing behavior
        for i in range(3):
            memory.record_campaign_activity(
                f"campaign-behavior-{i}",
                f"Campaign {i}",
                "exploit",
                techniques_used=["T1566"] if i < 2 else ["T1598", "T1192"]
            )
            campaign = memory.get_campaign_memory(f"campaign-behavior-{i}")
            if campaign:
                campaign.attributed_actors.append("actor-behavior")

        changes = detector.detect_actor_behavior_changes(window_days=365)

        assert isinstance(changes, list)
        for change in changes:
            assert "actor_id" in change
            assert "behavior_change_score" in change
            assert "new_techniques" in change

    def test_behavior_change_properties(self):
        """Test behavior change properties."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        detector = AnomalyDetector(memory, patterns, context)

        for i in range(2):
            memory.record_campaign_activity(
                f"campaign-change-{i}",
                f"Campaign {i}",
                "exploit",
                techniques_used=["T1566"]
            )
            campaign = memory.get_campaign_memory(f"campaign-change-{i}")
            if campaign:
                campaign.attributed_actors.append("actor-change")

        changes = detector.detect_actor_behavior_changes()

        for change in changes:
            assert "is_significant_change" in change
            assert isinstance(change["is_significant_change"], bool)


class TestInfrastructureAnomalies:
    """Test infrastructure anomaly detection."""

    def test_detect_infrastructure_anomalies(self):
        """Test infrastructure anomaly detection."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        detector = AnomalyDetector(memory, patterns, context)

        # Create infrastructure with varying usage
        for i in range(6):
            memory.record_ioc_occurrence(f"ioc-infra-{i}", f"ip-{i}", f"obs_{i}")

        anomalies = detector.detect_infrastructure_anomalies()

        assert isinstance(anomalies, list)
        for anomaly in anomalies:
            assert "ioc_id" in anomaly
            assert "campaign_diversity" in anomaly
            assert "z_score" in anomaly

    def test_infrastructure_anomaly_properties(self):
        """Test infrastructure anomaly properties."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        detector = AnomalyDetector(memory, patterns, context)

        for i in range(6):
            memory.record_ioc_occurrence(f"ioc-infra-prop-{i}", f"ip-{i}", f"obs_{i}")

        anomalies = detector.detect_infrastructure_anomalies(z_score_threshold=1.0)

        for anomaly in anomalies:
            assert "is_highly_shared" in anomaly
            assert "is_isolated" in anomaly


class TestAnomalySummary:
    """Test anomaly summary generation."""

    def test_get_anomaly_summary(self):
        """Test comprehensive anomaly summary."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        detector = AnomalyDetector(memory, patterns, context)

        # Create test data
        for i in range(6):
            memory.record_ioc_occurrence(f"ioc-summary-{i}", f"ip-{i}", f"obs_{i}")
            memory.record_campaign_activity(
                f"campaign-summary-{i}",
                f"Campaign {i}",
                "exploit",
                techniques_used=["T1566"]
            )

        summary = detector.get_anomaly_summary()

        assert isinstance(summary, dict)
        assert "ioc_reuse_anomalies" in summary
        assert "campaign_timing_anomalies" in summary
        assert "technique_anomalies" in summary
        assert "actor_behavior_changes" in summary
        assert "infrastructure_anomalies" in summary
        assert "summary" in summary

    def test_summary_counts(self):
        """Test anomaly summary counts."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        detector = AnomalyDetector(memory, patterns, context)

        summary = detector.get_anomaly_summary()

        assert summary["summary"]["total_ioc_anomalies"] >= 0
        assert summary["summary"]["total_campaign_anomalies"] >= 0
        assert summary["summary"]["total_technique_anomalies"] >= 0


class TestRiskScoring:
    """Test risk scoring."""

    def test_ioc_risk_score(self):
        """Test IOC risk scoring."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        detector = AnomalyDetector(memory, patterns, context)

        memory.record_ioc_occurrence("ioc-risk", "test-ip", "obs_1")

        score = detector.get_risk_score("ioc", "ioc-risk")

        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0

    def test_campaign_risk_score(self):
        """Test campaign risk scoring."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        detector = AnomalyDetector(memory, patterns, context)

        memory.record_campaign_activity("campaign-risk", "Campaign", "exploit")

        score = detector.get_risk_score("campaign", "campaign-risk")

        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0

    def test_actor_risk_score(self):
        """Test actor risk scoring."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        detector = AnomalyDetector(memory, patterns, context)

        memory.record_campaign_activity("campaign-actor", "Campaign", "exploit")
        campaign = memory.get_campaign_memory("campaign-actor")
        if campaign:
            campaign.attributed_actors.append("actor-risk")

        score = detector.get_risk_score("actor", "actor-risk")

        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0

    def test_unknown_entity_risk_score(self):
        """Test risk score for unknown entity."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        detector = AnomalyDetector(memory, patterns, context)

        score = detector.get_risk_score("ioc", "unknown-ioc")

        assert score == 0.0


class TestIntegration:
    """Test anomaly detection integration."""

    def test_complete_anomaly_detection_workflow(self):
        """Test complete anomaly detection workflow."""
        memory = ThreatMemoryEngine()
        patterns = PatternDetectionEngine(memory)
        context = HistoricalContextEngine(memory, patterns)
        detector = AnomalyDetector(memory, patterns, context)

        # Create complex scenario
        for i in range(8):
            memory.record_ioc_occurrence(f"ioc-workflow-{i}", f"ip-{i}", f"obs_{i}")
            memory.record_campaign_activity(
                f"campaign-workflow-{i}",
                f"Campaign {i}",
                "exploit",
                techniques_used=["T1566"]
            )
            campaign = memory.get_campaign_memory(f"campaign-workflow-{i}")
            if campaign:
                campaign.attributed_actors.append("actor-workflow")

        # Perform all analyses
        ioc_anomalies = detector.detect_ioc_reuse_anomalies()
        assert isinstance(ioc_anomalies, list)

        timing_anomalies = detector.detect_campaign_timing_anomalies()
        assert isinstance(timing_anomalies, list)

        technique_anomalies = detector.detect_technique_adoption_anomalies()
        assert isinstance(technique_anomalies, list)

        behavior_changes = detector.detect_actor_behavior_changes()
        assert isinstance(behavior_changes, list)

        infrastructure_anomalies = detector.detect_infrastructure_anomalies()
        assert isinstance(infrastructure_anomalies, list)

        summary = detector.get_anomaly_summary()
        assert "summary" in summary


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
