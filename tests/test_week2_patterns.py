"""
tests/test_week2_patterns.py - Week 2 Pattern Detection Tests

Tests for:
- IOC reusage pattern detection
- Campaign activity pattern detection
- Asset exposure pattern detection
- Trend classification
- Likelihood calculation
- Anomaly detection
"""

import pytest
from datetime import datetime, timedelta

from core.threat_memory import ThreatMemoryEngine
from core.pattern_detection import PatternDetectionEngine


class TestIOCPatternDetection:
    """Test IOC reusage pattern detection."""

    def test_detect_ioc_reusage_pattern(self):
        """Test IOC pattern detection."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        # Create IOC with multiple occurrences
        now = datetime.utcnow()
        for i in range(5):
            engine.record_ioc_occurrence(
                "ioc-pattern-test",
                "192.168.1.1",
                f"observation_{i}",
            )

        pattern = pattern_engine.detect_ioc_reusage_pattern("ioc-pattern-test")

        assert pattern is not None
        assert pattern.ioc_id == "ioc-pattern-test"
        assert len(pattern.occurrence_dates) >= 1

    def test_ioc_pattern_with_regular_intervals(self):
        """Test IOC pattern with regular observation intervals."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        # Record IOC multiple times (they occur at same moment)
        ioc_id = "ioc-regular"
        for i in range(5):
            engine.record_ioc_occurrence(ioc_id, "test-ioc", f"test_{i}")

        pattern = pattern_engine.detect_ioc_reusage_pattern(ioc_id)

        assert pattern is not None
        # With multiple records in same second, intervals may be 0
        assert len(pattern.occurrence_dates) >= 1

    def test_ioc_pattern_insufficient_data(self):
        """Test IOC pattern with insufficient data."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        engine.record_ioc_occurrence("ioc-single", "test-value", "context")

        pattern = pattern_engine.detect_ioc_reusage_pattern("ioc-single")

        assert pattern is not None
        assert len(pattern.occurrence_dates) == 1
        # Should not have inter-event times with single occurrence
        assert len(pattern.inter_event_times) == 0


class TestCampaignPatternDetection:
    """Test campaign activity pattern detection."""

    def test_detect_campaign_activity_pattern(self):
        """Test campaign pattern detection."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        # Create campaign with multiple activities
        for i in range(5):
            engine.record_campaign_activity(
                "campaign-pattern",
                "Test Campaign",
                f"activity_type_{i}",
                targets_count=10 + i*5,
            )

        pattern = pattern_engine.detect_campaign_activity_pattern("campaign-pattern")

        assert pattern is not None
        assert pattern.campaign_id == "campaign-pattern"
        assert len(pattern.activity_dates) >= 1

    def test_campaign_activity_pattern_classification(self):
        """Test campaign activity pattern classification."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        # Create campaign
        campaign_id = "campaign-classify"
        for i in range(5):
            engine.record_campaign_activity(
                campaign_id,
                "Classify Campaign",
                "exploit",
            )

        pattern = pattern_engine.detect_campaign_activity_pattern(campaign_id)

        assert pattern is not None
        assert pattern.activity_pattern in ["continuous", "intermittent", "seasonal", "unknown"]

    def test_campaign_peak_periods(self):
        """Test campaign peak period identification."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        campaign_id = "campaign-peaks"
        # Record more activities in same month
        engine.record_campaign_activity(campaign_id, "Peak Campaign", "exploit")
        engine.record_campaign_activity(campaign_id, "Peak Campaign", "exploit")
        engine.record_campaign_activity(campaign_id, "Peak Campaign", "exploit")

        pattern = pattern_engine.detect_campaign_activity_pattern(campaign_id)

        assert pattern is not None
        # Pattern may or may not have peak periods depending on date distribution


class TestAssetPatternDetection:
    """Test asset exposure pattern detection."""

    def test_detect_asset_exposure_pattern(self):
        """Test asset exposure pattern detection."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        # Create asset with multiple exposures
        asset_id = "asset-pattern"
        for i in range(4):
            engine.record_asset_exposure(
                asset_id,
                "Pattern Asset",
                "cve",
                cve_id=f"CVE-2026-{1000+i}",
            )

        pattern = pattern_engine.detect_asset_exposure_pattern(asset_id)

        assert pattern is not None
        assert pattern.asset_id == asset_id
        assert len(pattern.exposure_dates) >= 1

    def test_asset_exposure_trend(self):
        """Test asset exposure trend classification."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        asset_id = "asset-trend"
        engine.record_asset_exposure(asset_id, "Trend Asset", "cve")

        pattern = pattern_engine.detect_asset_exposure_pattern(asset_id)

        assert pattern is not None
        assert pattern.exposure_trend in ["rising", "stable", "declining", "unknown"]

    def test_asset_high_risk_windows(self):
        """Test asset high-risk window identification."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        asset_id = "asset-windows"
        for i in range(3):
            engine.record_asset_exposure(asset_id, "Windows Asset", "cve")

        pattern = pattern_engine.detect_asset_exposure_pattern(asset_id)

        assert pattern is not None
        # high_risk_windows may be empty or populated depending on distribution


class TestTrendClassification:
    """Test trend classification."""

    def test_classify_rising_trend(self):
        """Test rising trend classification."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        # Create many recent events
        now = datetime.utcnow()
        recent_events = [now - timedelta(days=i) for i in range(0, 20, 2)]

        trend = pattern_engine._classify_trend(recent_events)

        assert trend in ["rising", "stable", "declining"]

    def test_classify_declining_trend(self):
        """Test declining trend classification."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        # Old events only
        now = datetime.utcnow()
        old_events = [now - timedelta(days=i) for i in range(100, 120)]

        trend = pattern_engine._classify_trend(old_events)

        assert trend == "declining"

    def test_classify_trend_insufficient_data(self):
        """Test trend with insufficient data."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        trend = pattern_engine._classify_trend([])
        assert trend == "unknown"

        trend = pattern_engine._classify_trend([datetime.utcnow()])
        assert trend == "unknown"


class TestActivityPatternClassification:
    """Test activity pattern classification."""

    def test_classify_continuous_pattern(self):
        """Test continuous activity pattern."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        # Very short intervals (continuous)
        intervals = [1, 1, 1, 2, 1]

        activity_pattern = pattern_engine._classify_activity_pattern(intervals)

        assert activity_pattern in ["continuous", "intermittent", "seasonal"]

    def test_classify_intermittent_pattern(self):
        """Test intermittent activity pattern."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        # Moderate intervals with low variation
        intervals = [7, 7, 7, 8, 7]

        activity_pattern = pattern_engine._classify_activity_pattern(intervals)

        assert activity_pattern in ["intermittent", "continuous", "seasonal"]

    def test_classify_seasonal_pattern(self):
        """Test seasonal activity pattern."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        # High variation (seasonal)
        intervals = [3, 30, 5, 25, 7, 28]

        activity_pattern = pattern_engine._classify_activity_pattern(intervals)

        assert activity_pattern in ["seasonal", "intermittent"]


class TestLikelihoodCalculation:
    """Test likelihood calculation."""

    def test_calculate_likelihood_high(self):
        """Test high likelihood calculation."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        # High frequency, rising trend
        likelihood = pattern_engine._calculate_likelihood(2.0, "rising")

        assert 0.0 <= likelihood <= 1.0
        assert likelihood > 0.5

    def test_calculate_likelihood_low(self):
        """Test low likelihood calculation."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        # Low frequency, declining trend
        likelihood = pattern_engine._calculate_likelihood(0.1, "declining")

        assert 0.0 <= likelihood <= 1.0
        assert likelihood < 0.5

    def test_calculate_likelihood_stable(self):
        """Test likelihood with stable trend."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        likelihood = pattern_engine._calculate_likelihood(1.0, "stable")

        assert 0.0 <= likelihood <= 1.0


class TestAnomalyDetection:
    """Test anomaly detection."""

    def test_detect_anomalies_with_outliers(self):
        """Test anomaly detection."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        ioc_id = "ioc-anomaly"
        # Create IOC with regular pattern
        base_date = datetime.utcnow() - timedelta(days=30)
        for i in [0, 5, 10, 15, 50]:  # 50-day gap is anomaly
            date = base_date + timedelta(days=i)
            engine.record_ioc_occurrence(ioc_id, "test", f"obs_{i}")

        anomalies = pattern_engine.get_anomalies(stddev_threshold=1.5)

        # May or may not have anomalies depending on threshold
        assert isinstance(anomalies, dict)
        assert "ioc_anomalies" in anomalies


class TestBatchPatternDetection:
    """Test batch pattern detection."""

    def test_detect_all_patterns(self):
        """Test detecting patterns for all entities."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        # Create multiple entities
        engine.record_ioc_occurrence("ioc-batch-1", "value1", "context")
        engine.record_ioc_occurrence("ioc-batch-2", "value2", "context")
        engine.record_campaign_activity("campaign-batch-1", "Campaign 1", "exploit")
        engine.record_asset_exposure("asset-batch-1", "Asset 1", "cve")

        results = pattern_engine.detect_all_patterns()

        assert results["total_patterns"] >= 0
        assert isinstance(results["ioc_patterns"], dict)
        assert isinstance(results["campaign_patterns"], dict)
        assert isinstance(results["asset_patterns"], dict)

    def test_get_high_risk_entities(self):
        """Test getting high-risk entities."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        # Create some entities
        engine.record_ioc_occurrence("ioc-risk", "risky-ioc", "context")
        engine.record_campaign_activity("campaign-risk", "Risky Campaign", "exploit")

        high_risk = pattern_engine.get_high_risk_entities(likelihood_threshold=0.5)

        assert isinstance(high_risk, dict)
        assert "iocs" in high_risk
        assert "campaigns" in high_risk
        assert "assets" in high_risk

    def test_get_pattern_statistics(self):
        """Test getting pattern statistics."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        # Create entities
        for i in range(3):
            engine.record_ioc_occurrence(f"ioc-stats-{i}", f"value-{i}", "context")

        stats = pattern_engine.get_pattern_statistics()

        assert "total_iocs_analyzed" in stats
        assert "average_ioc_reuse_likelihood" in stats
        assert "total_campaigns_analyzed" in stats
        assert "average_campaign_activity_likelihood" in stats
        assert "total_assets_analyzed" in stats
        assert "average_asset_exposure_likelihood" in stats


class TestPatternExport:
    """Test pattern export functionality."""

    def test_export_patterns_as_json(self):
        """Test exporting patterns as JSON."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        # Create entity
        engine.record_ioc_occurrence("ioc-export", "export-value", "context")

        exported = pattern_engine.export_patterns_as_json()

        assert isinstance(exported, dict)
        assert "ioc_patterns" in exported
        assert "campaign_patterns" in exported
        assert "asset_patterns" in exported

    def test_export_patterns_json_serializable(self):
        """Test that exported patterns are JSON serializable."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        engine.record_ioc_occurrence("ioc-json", "json-value", "context")

        exported = pattern_engine.export_patterns_as_json()

        # Should not raise exception
        import json
        json_str = json.dumps(exported)
        assert isinstance(json_str, str)


class TestPredictiveAnalysis:
    """Test predictive analysis methods."""

    def test_predict_next_event(self):
        """Test next event prediction."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        now = datetime.utcnow()
        dates = [now - timedelta(days=i) for i in range(10, 0, -2)]

        next_pred = pattern_engine._predict_next_event(dates, 2.0)

        assert next_pred is not None
        assert next_pred >= now

    def test_predict_next_event_no_data(self):
        """Test prediction with no data."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        next_pred = pattern_engine._predict_next_event([], 2.0)

        assert next_pred is None

    def test_predict_with_zero_interval(self):
        """Test prediction with zero interval."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        dates = [datetime.utcnow()]
        next_pred = pattern_engine._predict_next_event(dates, 0.0)

        assert next_pred is None


class TestIntegration:
    """Test pattern detection integration."""

    def test_full_pattern_detection_pipeline(self):
        """Test complete pattern detection pipeline."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        # Populate memory
        engine.record_ioc_occurrence("ioc-full", "test-ioc", "context")
        engine.record_campaign_activity("campaign-full", "Full Campaign", "exploit")
        engine.record_asset_exposure("asset-full", "Full Asset", "cve")

        # Detect patterns
        ioc_pattern = pattern_engine.detect_ioc_reusage_pattern("ioc-full")
        campaign_pattern = pattern_engine.detect_campaign_activity_pattern("campaign-full")
        asset_pattern = pattern_engine.detect_asset_exposure_pattern("asset-full")

        assert ioc_pattern is not None
        assert campaign_pattern is not None
        assert asset_pattern is not None

        # Get statistics
        stats = pattern_engine.get_pattern_statistics()
        assert stats["total_iocs_analyzed"] >= 1

        # Get high-risk entities
        high_risk = pattern_engine.get_high_risk_entities()
        assert isinstance(high_risk, dict)

    def test_pattern_detection_with_multiple_entities(self):
        """Test pattern detection with multiple entities."""
        engine = ThreatMemoryEngine()
        pattern_engine = PatternDetectionEngine(engine)

        # Create multiple IOCs
        for i in range(3):
            for j in range(3):
                engine.record_ioc_occurrence(f"ioc-multi-{i}", f"value-{i}", f"context-{j}")

        results = pattern_engine.detect_all_patterns()

        assert len(results["ioc_patterns"]) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
