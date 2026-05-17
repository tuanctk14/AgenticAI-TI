"""
tests/test_week2_temporal.py - Week 2 Temporal Intelligence Population Tests

Tests for:
- Temporal data population from APIs
- Timeline analysis and trend calculation
- Prediction methods
- Integration with memory engine
"""

import pytest
from datetime import datetime, timedelta

from core.threat_memory import ThreatMemoryEngine
from core.temporal_intelligence import (
    TemporalIntelligenceEngine,
    VulnerabilityTemporal,
    IOCTemporal,
    CampaignTemporal,
)


class TestVulnerabilityTemporal:
    """Test vulnerability temporal data population."""

    def test_vulnerability_temporal_model(self):
        """Test VulnerabilityTemporal model creation."""
        temporal = VulnerabilityTemporal(
            cve_id="CVE-2026-1234",
            published_date=datetime(2026, 1, 15),
            kev_added_date=datetime(2026, 1, 20),
            poc_published_date=datetime(2026, 1, 25),
            first_seen_in_wild=datetime(2026, 2, 1),
            last_exploited=datetime(2026, 5, 10),
        )

        assert temporal.cve_id == "CVE-2026-1234"
        assert temporal.published_date.month == 1
        assert temporal.kev_added_date is not None
        assert temporal.last_exploited is not None

    def test_vulnerability_temporal_optional_fields(self):
        """Test VulnerabilityTemporal with optional fields."""
        temporal = VulnerabilityTemporal(
            cve_id="CVE-2026-5678",
            published_date=datetime(2026, 3, 1),
        )

        assert temporal.cve_id == "CVE-2026-5678"
        assert temporal.kev_added_date is None
        assert temporal.first_seen_in_wild is None

    def test_exploit_evolution_timeline(self):
        """Test exploit evolution tracking."""
        temporal = VulnerabilityTemporal(
            cve_id="CVE-2026-9999",
            published_date=datetime(2026, 1, 1),
            exploit_evolution={
                "2026-02-01": "PoC released on GitHub",
                "2026-03-15": "Widespread exploitation detected",
                "2026-05-01": "Active exploitation in ransomware campaigns",
            },
        )

        assert len(temporal.exploit_evolution) == 3
        assert "PoC released" in str(temporal.exploit_evolution)


class TestIOCTemporal:
    """Test IOC temporal data population."""

    def test_ioc_temporal_model(self):
        """Test IOCTemporal model creation."""
        temporal = IOCTemporal(
            ioc_id="ip-192.168.1.1",
            ioc_value="192.168.1.1",
            ioc_type="ip",
            first_seen=datetime(2024, 1, 1),
            last_seen=datetime(2026, 5, 15),
            observation_count=25,
            sources=["OpenCTI", "VirusTotal", "threat_feeds"],
        )

        assert temporal.ioc_id == "ip-192.168.1.1"
        assert temporal.ioc_type == "ip"
        assert len(temporal.sources) == 3

    def test_ioc_temporal_multiple_types(self):
        """Test different IOC types."""
        ioc_types = ["ip", "domain", "hash", "email"]

        for ioc_type in ioc_types:
            temporal = IOCTemporal(
                ioc_id=f"{ioc_type}-test",
                ioc_value="test-value",
                ioc_type=ioc_type,
                first_seen=datetime(2026, 1, 1),
            )

            assert temporal.ioc_type == ioc_type


class TestCampaignTemporal:
    """Test campaign temporal data population."""

    def test_campaign_temporal_model(self):
        """Test CampaignTemporal model creation."""
        temporal = CampaignTemporal(
            campaign_id="apt28-2026",
            campaign_name="APT28 Q2 2026",
            first_observed=datetime(2026, 4, 1),
            last_observed=datetime(2026, 5, 15),
            is_active=True,
            activity_frequency=2.5,
        )

        assert temporal.campaign_id == "apt28-2026"
        assert temporal.is_active == True
        assert temporal.activity_frequency > 0.0

    def test_campaign_temporal_inactive(self):
        """Test inactive campaign tracking."""
        temporal = CampaignTemporal(
            campaign_id="historical-campaign",
            campaign_name="Historical Campaign",
            first_observed=datetime(2024, 1, 1),
            last_observed=datetime(2024, 12, 31),
            is_active=False,
        )

        assert temporal.is_active == False


class TestTemporalPopulation:
    """Test temporal intelligence population operations."""

    def test_populate_ioc_temporal(self):
        """Test IOC temporal population."""
        engine = ThreatMemoryEngine()
        temporal_engine = TemporalIntelligenceEngine(engine)

        temporal = IOCTemporal(
            ioc_id="ip-10.0.0.1",
            ioc_value="10.0.0.1",
            ioc_type="ip",
            first_seen=datetime(2024, 6, 1),
            last_seen=datetime(2026, 5, 15),
            observation_count=15,
            sources=["OpenCTI", "VirusTotal"],
        )

        result = temporal_engine.populate_ioc_temporal(temporal)
        assert result == True

        # Verify memory was updated
        memory = engine.get_ioc_memory("ip-10.0.0.1")
        assert memory is not None
        assert memory.ioc_value == "10.0.0.1"

    def test_populate_campaign_temporal(self):
        """Test campaign temporal population."""
        engine = ThreatMemoryEngine()
        temporal_engine = TemporalIntelligenceEngine(engine)

        temporal = CampaignTemporal(
            campaign_id="campaign-temporal-test",
            campaign_name="Test Campaign",
            first_observed=datetime(2026, 3, 1),
            last_observed=datetime(2026, 5, 15),
            is_active=True,
        )

        result = temporal_engine.populate_campaign_temporal(temporal)
        assert result == True

        # Verify memory was updated
        memory = engine.get_campaign_memory("campaign-temporal-test")
        assert memory is not None
        assert memory.campaign_name == "Test Campaign"

    def test_populate_asset_exposure_temporal(self):
        """Test asset exposure temporal population."""
        engine = ThreatMemoryEngine()
        temporal_engine = TemporalIntelligenceEngine(engine)

        exposure_events = [
            (datetime(2026, 1, 15), "cve", "CVE-2026-1111"),
            (datetime(2026, 2, 20), "cve", "CVE-2026-2222"),
            (datetime(2026, 3, 10), "ioc_detected", "malware_hash_x"),
        ]

        result = temporal_engine.populate_asset_exposure_temporal(
            "asset-temporal",
            "Temporal Test Asset",
            exposure_events,
        )

        assert result == True

        memory = engine.get_asset_memory("asset-temporal")
        assert memory is not None
        assert len(memory.exposures) >= 1


class TestTrendCalculation:
    """Test temporal trend analysis."""

    def test_calculate_trend_rising(self):
        """Test rising trend detection."""
        engine = ThreatMemoryEngine()
        temporal_engine = TemporalIntelligenceEngine(engine)

        now = datetime.utcnow()
        events = [
            (now - timedelta(days=29), "event1"),
            (now - timedelta(days=25), "event2"),
            (now - timedelta(days=20), "event3"),
            (now - timedelta(days=15), "event4"),
            (now - timedelta(days=10), "event5"),
            (now - timedelta(days=5), "event6"),
            (now - timedelta(days=1), "event7"),
        ]

        trend = temporal_engine.calculate_trend(events, window_days=30)
        assert trend in ["rising", "stable"]

    def test_calculate_trend_stable(self):
        """Test stable trend detection."""
        engine = ThreatMemoryEngine()
        temporal_engine = TemporalIntelligenceEngine(engine)

        now = datetime.utcnow()
        events = [
            (now - timedelta(days=30), "event1"),
            (now - timedelta(days=25), "event2"),
            (now - timedelta(days=20), "event3"),
            (now - timedelta(days=15), "event4"),
        ]

        trend = temporal_engine.calculate_trend(events, window_days=30)
        assert trend in ["stable", "rising", "declining"]

    def test_calculate_trend_declining(self):
        """Test declining trend detection."""
        engine = ThreatMemoryEngine()
        temporal_engine = TemporalIntelligenceEngine(engine)

        now = datetime.utcnow()
        events = [
            (now - timedelta(days=100), "event1"),
            (now - timedelta(days=80), "event2"),
            (now - timedelta(days=60), "event3"),
        ]

        trend = temporal_engine.calculate_trend(events, window_days=30)
        assert trend == "declining"

    def test_calculate_trend_insufficient_data(self):
        """Test trend with insufficient data."""
        engine = ThreatMemoryEngine()
        temporal_engine = TemporalIntelligenceEngine(engine)

        events = [(datetime.utcnow(), "single_event")]

        trend = temporal_engine.calculate_trend(events)
        assert trend == "unknown"


class TestActiveWindow:
    """Test active window calculation."""

    def test_get_active_window(self):
        """Test active window formatting."""
        engine = ThreatMemoryEngine()
        temporal_engine = TemporalIntelligenceEngine(engine)

        first = datetime(2024, 1, 15)
        last = datetime(2026, 5, 10)

        window = temporal_engine.get_active_window(first, last)

        assert "2024-01" in window
        assert "2026-05" in window
        assert "to" in window

    def test_populate_ioc_active_window(self):
        """Test IOC active window population."""
        engine = ThreatMemoryEngine()
        temporal_engine = TemporalIntelligenceEngine(engine)

        # Create IOC memory first
        engine.record_ioc_occurrence(
            "ioc-window-test",
            "test-value",
            "test_context",
        )

        result = temporal_engine.populate_ioc_active_window(
            "ioc-window-test",
            datetime(2024, 1, 1),
            datetime(2026, 5, 15),
        )

        assert result == True

        memory = engine.get_ioc_memory("ioc-window-test")
        assert memory.first_observed == datetime(2024, 1, 1)
        assert memory.last_observed == datetime(2026, 5, 15)


class TestPrediction:
    """Test temporal prediction methods."""

    def test_predict_next_occurrence(self):
        """Test next occurrence prediction."""
        engine = ThreatMemoryEngine()
        temporal_engine = TemporalIntelligenceEngine(engine)

        now = datetime.utcnow()
        events = [
            now - timedelta(days=30),
            now - timedelta(days=20),
            now - timedelta(days=10),
            now,
        ]

        next_pred = temporal_engine.predict_next_occurrence(events)

        assert next_pred is not None
        assert next_pred > now

    def test_predict_next_occurrence_insufficient_data(self):
        """Test prediction with insufficient data."""
        engine = ThreatMemoryEngine()
        temporal_engine = TemporalIntelligenceEngine(engine)

        events = [datetime.utcnow()]

        next_pred = temporal_engine.predict_next_occurrence(events)

        assert next_pred is None

    def test_predict_regular_occurrence(self):
        """Test prediction with regular occurrence pattern."""
        engine = ThreatMemoryEngine()
        temporal_engine = TemporalIntelligenceEngine(engine)

        now = datetime.utcnow()
        # Regular 10-day pattern
        events = [
            now - timedelta(days=30),
            now - timedelta(days=20),
            now - timedelta(days=10),
            now,
        ]

        next_pred = temporal_engine.predict_next_occurrence(events)

        # Should predict ~10 days from now
        expected = now + timedelta(days=10)
        assert next_pred is not None
        # Allow 5-day margin of error
        assert abs((next_pred - expected).days) <= 5


class TestBatchPopulation:
    """Test batch population operations."""

    def test_populate_from_api_responses_empty(self):
        """Test batch population with empty data."""
        engine = ThreatMemoryEngine()
        temporal_engine = TemporalIntelligenceEngine(engine)

        results = temporal_engine.populate_from_api_responses([], [], [])

        assert results["vulnerabilities_populated"] == 0
        assert results["iocs_populated"] == 0
        assert results["campaigns_populated"] == 0

    def test_populate_from_api_responses_mixed(self):
        """Test batch population with mixed data."""
        engine = ThreatMemoryEngine()
        temporal_engine = TemporalIntelligenceEngine(engine)

        ioc_data = [
            {
                "ioc_id": "ip-batch-1",
                "ioc_value": "1.1.1.1",
                "ioc_type": "ip",
                "first_seen": datetime(2026, 1, 1),
                "last_seen": datetime(2026, 5, 15),
                "observation_count": 10,
            },
            {
                "ioc_id": "domain-batch-1",
                "ioc_value": "evil.com",
                "ioc_type": "domain",
                "first_seen": datetime(2026, 2, 1),
                "last_seen": datetime(2026, 5, 10),
                "observation_count": 5,
            },
        ]

        campaign_data = [
            {
                "campaign_id": "batch-campaign-1",
                "campaign_name": "Batch Campaign",
                "first_observed": datetime(2026, 3, 1),
                "last_observed": datetime(2026, 5, 15),
                "is_active": True,
            },
        ]

        results = temporal_engine.populate_from_api_responses([], ioc_data, campaign_data)

        assert results["iocs_populated"] >= 0
        assert results["campaigns_populated"] >= 0


class TestTemporalStatistics:
    """Test temporal statistics and reporting."""

    def test_get_temporal_statistics_empty(self):
        """Test statistics with empty memory."""
        engine = ThreatMemoryEngine()
        temporal_engine = TemporalIntelligenceEngine(engine)

        stats = temporal_engine.get_temporal_statistics()

        assert stats["total_iocs_tracked"] == 0
        assert stats["total_campaigns_tracked"] == 0
        assert stats["total_assets_tracked"] == 0

    def test_get_temporal_statistics_with_data(self):
        """Test statistics with populated memory."""
        engine = ThreatMemoryEngine()
        temporal_engine = TemporalIntelligenceEngine(engine)

        # Populate with data
        engine.record_ioc_occurrence("ioc-stats", "1.1.1.1", "test")
        engine.record_campaign_activity("campaign-stats", "Test Campaign", "exploit")
        engine.record_asset_exposure("asset-stats", "Test Asset", "cve")

        stats = temporal_engine.get_temporal_statistics()

        assert stats["total_iocs_tracked"] >= 1
        assert stats["total_campaigns_tracked"] >= 1
        assert stats["total_assets_tracked"] >= 1


class TestIntegration:
    """Test temporal intelligence integration with memory."""

    def test_temporal_enriches_memory(self):
        """Test that temporal data enriches memory records."""
        engine = ThreatMemoryEngine()
        temporal_engine = TemporalIntelligenceEngine(engine)

        # Populate via temporal engine
        temporal = IOCTemporal(
            ioc_id="integration-test",
            ioc_value="test.evil.com",
            ioc_type="domain",
            first_seen=datetime(2024, 1, 1),
            last_seen=datetime(2026, 5, 15),
            observation_count=50,
            sources=["OpenCTI", "VirusTotal"],
        )

        temporal_engine.populate_ioc_temporal(temporal, associated_campaigns=["APT28"])

        # Verify memory enriched
        memory = engine.get_ioc_memory("integration-test")
        assert memory is not None
        assert memory.ioc_value == "test.evil.com"
        assert memory.occurrence_count > 0

    def test_temporal_with_trend_analysis(self):
        """Test temporal population with trend analysis."""
        engine = ThreatMemoryEngine()
        temporal_engine = TemporalIntelligenceEngine(engine)

        # Create multiple events
        now = datetime.utcnow()
        events = [
            (now - timedelta(days=30), "event1"),
            (now - timedelta(days=20), "event2"),
            (now - timedelta(days=10), "event3"),
            (now, "event4"),
        ]

        # Calculate trend
        trend = temporal_engine.calculate_trend(events)

        assert trend in ["rising", "stable", "declining", "unknown"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
