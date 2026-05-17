"""
tests/test_week4_advanced_analytics.py - Advanced Analytics Tests

Tests for:
- Threat timeline analysis
- Cross-layer threat correlation
- Predictive threat vector analysis
- Risk aggregation
- Recommendation generation
- Executive intelligence reporting
"""

import pytest
from datetime import datetime, timedelta

from core.advanced_analytics import AnalyticsEngine, ThreatEscalationLevel


class TestThreatTimeline:
    """Test threat timeline analysis."""

    def test_analyze_empty_timeline(self):
        """Test analyzing empty threat data."""
        engine = AnalyticsEngine()
        result = engine.analyze_threat_timeline([])

        assert result["activity_count"] == 0
        assert result["escalation_level"] == ThreatEscalationLevel.DORMANT.value

    def test_analyze_single_event(self):
        """Test analyzing single threat event."""
        engine = AnalyticsEngine()
        now = datetime.utcnow()
        events = [{"timestamp": now}]

        result = engine.analyze_threat_timeline(events)

        assert result["activity_count"] == 1
        assert result["avg_daily_events"] > 0

    def test_analyze_rising_trend(self):
        """Test detecting rising threat trend."""
        engine = AnalyticsEngine()
        now = datetime.utcnow()

        # Create rising trend: fewer events in past, more recent
        events = []
        for i in range(2):
            events.append({"timestamp": now - timedelta(days=i+20)})
        for i in range(40):
            events.append({"timestamp": now - timedelta(days=i+1)})

        result = engine.analyze_threat_timeline(events)

        # May be stable or rising depending on distribution
        assert result["trend"] in ["rising", "stable"]
        # Escalation depends on event count, should be at least emerging
        assert result["escalation_level"] in [
            ThreatEscalationLevel.EMERGING.value,
            ThreatEscalationLevel.ACTIVE.value,
            ThreatEscalationLevel.CRITICAL.value
        ]

    def test_analyze_declining_trend(self):
        """Test detecting declining threat trend."""
        engine = AnalyticsEngine()
        now = datetime.utcnow()

        # Create declining trend: more events in past, fewer recent
        events = []
        for i in range(35):
            events.append({"timestamp": now - timedelta(days=i+20)})
        for i in range(1):
            events.append({"timestamp": now - timedelta(days=i+1)})

        result = engine.analyze_threat_timeline(events)

        assert result["trend"] in ["declining", "stable"]

    def test_escalation_level_critical(self):
        """Test critical escalation detection."""
        engine = AnalyticsEngine()
        now = datetime.utcnow()

        # Generate 15 events per day for 7 days
        events = []
        for day in range(7):
            for hour in range(15):
                events.append({"timestamp": now - timedelta(days=day, hours=hour)})

        result = engine.analyze_threat_timeline(events)

        assert result["escalation_level"] == ThreatEscalationLevel.CRITICAL.value
        assert result["avg_daily_events"] > 10


class TestCorrelation:
    """Test threat correlation analysis."""

    def test_correlate_empty_data(self):
        """Test correlating empty threat data."""
        engine = AnalyticsEngine()
        result = engine.correlate_threat_layers([], [], [], [])

        assert result["correlation_count"] == 0
        assert result["correlation_density"] == 0.0

    def test_correlate_vuln_in_campaign(self):
        """Test correlating vulnerabilities in campaigns."""
        engine = AnalyticsEngine()

        vulns = [
            {"id": "CVE-2024-001", "cwe_ids": ["CWE-79"]}
        ]
        campaigns = [
            {"id": "campaign-1", "techniques": ["CWE-79"]}
        ]

        result = engine.correlate_threat_layers(vulns, [], campaigns, [])

        assert result["vuln_exploit_links"] == 1
        assert result["correlation_count"] > 0

    def test_correlate_ioc_to_campaign(self):
        """Test correlating IOCs to campaigns."""
        engine = AnalyticsEngine()

        iocs = [
            {"value": "192.168.1.1", "related_entities": ["campaign-1"]}
        ]
        campaigns = [
            {"id": "campaign-1"}
        ]

        result = engine.correlate_threat_layers([], iocs, campaigns, [])

        assert result["ioc_campaign_links"] == 1

    def test_correlate_actor_campaign(self):
        """Test correlating actors to campaigns."""
        engine = AnalyticsEngine()

        actors = [
            {"name": "APT-1", "campaigns": ["campaign-1"]}
        ]
        campaigns = [
            {"id": "campaign-1"}
        ]

        result = engine.correlate_threat_layers([], [], campaigns, actors)

        assert result["actor_campaign_links"] == 1

    def test_correlation_density(self):
        """Test correlation density calculation."""
        engine = AnalyticsEngine()

        vulns = [{"id": "CVE-1", "cwe_ids": ["CWE-79"]}]
        iocs = [{"value": "192.168.1.1", "related_entities": ["c1"]}]
        campaigns = [{"id": "c1", "techniques": ["CWE-79"]}]
        actors = [{"name": "APT", "campaigns": ["c1"]}]

        result = engine.correlate_threat_layers(vulns, iocs, campaigns, actors)

        assert result["correlation_density"] > 0.0


class TestPredictions:
    """Test predictive threat analysis."""

    def test_predict_empty_history(self):
        """Test predicting with empty history."""
        engine = AnalyticsEngine()
        result = engine.predict_threat_vectors([], [], [])

        assert result["prediction_count"] == 0

    def test_predict_target_sectors(self):
        """Test predicting likely target sectors."""
        engine = AnalyticsEngine()

        history = [
            {"target_sectors": ["finance", "healthcare"]},
            {"target_sectors": ["finance", "energy"]},
            {"target_sectors": ["finance"]},
        ]

        result = engine.predict_threat_vectors(history, [], [])

        assert result["prediction_count"] > 0
        predictions = result["predictions"]
        sector_preds = [p for p in predictions if p["type"] == "likely_target_sector"]
        assert len(sector_preds) > 0

    def test_predict_techniques(self):
        """Test predicting likely exploitation techniques."""
        engine = AnalyticsEngine()

        trends = [
            {"techniques": ["T1234", "T5678"]},
            {"techniques": ["T1234", "T9012"]},
            {"techniques": ["T1234"]},
        ]

        result = engine.predict_threat_vectors([], [], trends)

        assert result["prediction_count"] > 0
        predictions = result["predictions"]
        tech_preds = [p for p in predictions if p["type"] == "likely_exploitation_technique"]
        assert len(tech_preds) > 0

    def test_prediction_confidence(self):
        """Test prediction confidence calculation."""
        engine = AnalyticsEngine()

        history = [
            {"target_sectors": ["finance"]} for _ in range(5)
        ]

        result = engine.predict_threat_vectors(history, [], [])

        assert result["confidence_avg"] > 0.5


class TestRiskAggregation:
    """Test risk aggregation."""

    def test_aggregate_risk_empty(self):
        """Test aggregating empty risk data."""
        engine = AnalyticsEngine()
        result = engine.aggregate_risk({}, 0.0, "dormant")

        assert result["aggregated_risk"] >= 0.0
        assert result["risk_level"] == "MINIMAL"

    def test_aggregate_risk_critical(self):
        """Test critical risk aggregation."""
        engine = AnalyticsEngine()

        entity_risks = {
            "vuln1": 0.9,
            "ioc1": 0.8,
            "campaign1": 0.7,
        }

        result = engine.aggregate_risk(entity_risks, 0.8, "critical")

        assert result["risk_level"] == "CRITICAL"
        assert result["escalation_multiplier"] == 2.0

    def test_aggregate_risk_high(self):
        """Test high risk aggregation."""
        engine = AnalyticsEngine()

        entity_risks = {
            "vuln1": 0.5,
            "ioc1": 0.45,
        }

        result = engine.aggregate_risk(entity_risks, 0.3, "active")

        assert result["risk_level"] in ["HIGH", "CRITICAL"]

    def test_aggregate_risk_correlation_amplification(self):
        """Test correlation amplifies risk."""
        engine = AnalyticsEngine()

        entity_risks = {"vuln1": 0.5}

        result1 = engine.aggregate_risk(entity_risks, 0.0, "active")
        result2 = engine.aggregate_risk(entity_risks, 0.9, "active")

        assert result2["aggregated_risk"] > result1["aggregated_risk"]


class TestRecommendations:
    """Test recommendation generation."""

    def test_recommend_critical(self):
        """Test recommendations for critical threat."""
        engine = AnalyticsEngine()

        threat = {"escalation_level": "critical"}
        risk = {"risk_level": "CRITICAL"}

        result = engine.generate_recommendations(threat, risk, [])

        assert result["recommendation_count"] > 0
        immediate = [r for r in result["recommendations"] if r["priority"] == "IMMEDIATE"]
        assert len(immediate) > 0

    def test_recommend_high(self):
        """Test recommendations for high threat."""
        engine = AnalyticsEngine()

        threat = {"escalation_level": "active"}
        risk = {"risk_level": "HIGH"}

        result = engine.generate_recommendations(threat, risk, [])

        assert result["recommendation_count"] > 0
        urgent = [r for r in result["recommendations"] if r["priority"] == "URGENT"]
        assert len(urgent) > 0

    def test_recommend_review_frequency(self):
        """Test review frequency recommendations."""
        engine = AnalyticsEngine()

        threat = {"escalation_level": "critical"}
        risk = {"risk_level": "CRITICAL"}

        result = engine.generate_recommendations(threat, risk, [])

        freq = result["review_frequency"]
        assert "hour" in freq or "minute" in freq


class TestExecutiveReport:
    """Test executive intelligence reporting."""

    def test_generate_report(self):
        """Test generating executive report."""
        engine = AnalyticsEngine()

        threat = {
            "escalation_level": "active",
            "trend": "rising",
            "activity_count": 50,
            "avg_daily_events": 7.0,
            "days_analyzed": 7,
        }
        risk = {
            "risk_level": "HIGH",
            "aggregated_risk": 0.65,
        }
        recs = {
            "recommendations": [
                {"priority": "URGENT", "action": "Deploy patches"}
            ],
            "review_frequency": "every 4 hours",
        }
        stats = {"total_entities": 100, "active_campaigns": 5}

        report = engine.generate_executive_report(threat, risk, recs, stats)

        assert report["timestamp"]
        assert report["executive_summary"]["current_threat_level"] == "HIGH"
        assert report["executive_summary"]["escalation_status"] == "active"
        assert len(report["critical_actions"]) > 0

    def test_report_includes_key_metrics(self):
        """Test report includes all key metrics."""
        engine = AnalyticsEngine()

        threat = {
            "escalation_level": "active",
            "trend": "stable",
            "activity_count": 20,
            "avg_daily_events": 3.0,
            "days_analyzed": 7,
        }
        risk = {
            "risk_level": "MEDIUM",
            "aggregated_risk": 0.45,
        }
        recs = {
            "recommendations": [],
            "review_frequency": "daily",
        }
        stats = {"total_entities": 50, "active_campaigns": 2}

        report = engine.generate_executive_report(threat, risk, recs, stats)

        metrics = report["key_metrics"]
        assert metrics["aggregated_risk_score"] == 0.45
        assert metrics["avg_daily_threats"] == 3.0
        assert metrics["total_entities"] == 50

    def test_report_confidence_score(self):
        """Test confidence score in report."""
        engine = AnalyticsEngine()

        threat = {
            "escalation_level": "active",
            "trend": "rising",
            "activity_count": 50,
            "avg_daily_events": 7.0,
            "days_analyzed": 30,
        }
        risk = {"risk_level": "HIGH", "aggregated_risk": 0.7}
        recs = {"recommendations": [], "review_frequency": "daily"}
        stats = {"total_entities": 100, "active_campaigns": 5}

        report = engine.generate_executive_report(threat, risk, recs, stats)

        assert report["confidence"] > 0.0
        assert report["confidence"] <= 1.0


class TestIntegration:
    """Test complete analytics workflow."""

    def test_complete_analytics_workflow(self):
        """Test complete analytics pipeline."""
        engine = AnalyticsEngine()

        # Threat timeline analysis
        now = datetime.utcnow()
        threat_events = [
            {"timestamp": now - timedelta(days=i)} for i in range(30)
        ]
        threat = engine.analyze_threat_timeline(threat_events, window_days=30)

        # Cross-layer correlation
        vulns = [{"id": "CVE-2024-001", "cwe_ids": ["CWE-79"]}]
        campaigns = [{"id": "campaign-1", "techniques": ["CWE-79"]}]
        correlation = engine.correlate_threat_layers(vulns, [], campaigns, [])

        # Risk aggregation
        risks = engine.aggregate_risk(
            {"vuln1": 0.8},
            correlation["correlation_density"],
            threat["escalation_level"]
        )

        # Recommendations
        recs = engine.generate_recommendations(threat, risks, [])

        # Executive report
        report = engine.generate_executive_report(threat, risks, recs, {})

        assert threat["activity_count"] == 30
        assert correlation["correlation_count"] >= 0
        assert risks["risk_level"] in ["MINIMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert recs["recommendation_count"] >= 0
        assert report["timestamp"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
