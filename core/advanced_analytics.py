"""
core/advanced_analytics.py - Advanced Analytics & System Integration

Unified analytics across all threat components:
- Cross-layer threat correlation
- Predictive threat timeline analysis
- Risk aggregation and escalation
- System-wide recommendations
- Executive intelligence reporting
"""

from typing import Dict, List, Optional, Set, Any, Tuple
from datetime import datetime, timedelta
from enum import Enum
import statistics


class ThreatEscalationLevel(Enum):
    """Threat escalation classification."""
    DORMANT = "dormant"  # No recent activity
    EMERGING = "emerging"  # Early signs of activity
    ACTIVE = "active"  # Ongoing threat
    CRITICAL = "critical"  # Immediate action required


class AnalyticsEngine:
    """Advanced analytics and integration engine."""

    def __init__(self):
        """Initialize analytics engine."""
        self.threat_events = []  # Timeline of detected threats
        self.correlation_results = []  # Cross-layer correlations
        self.predictions = []  # Predicted threat vectors
        self.recommendations = []  # System recommendations

    def analyze_threat_timeline(
        self,
        threat_data: List[Dict[str, Any]],
        window_days: int = 30
    ) -> Dict[str, Any]:
        """Analyze threat activity timeline.

        Args:
            threat_data: List of threat events with timestamps
            window_days: Analysis window in days

        Returns:
            Timeline analysis with trends
        """
        if not threat_data:
            return {
                "trend": "unknown",
                "activity_count": 0,
                "avg_daily_events": 0.0,
                "escalation_level": ThreatEscalationLevel.DORMANT.value,
            }

        # Sort by timestamp
        sorted_data = sorted(threat_data, key=lambda x: x.get("timestamp", 0))

        # Calculate time-based metrics
        now = datetime.utcnow()
        cutoff = now - timedelta(days=window_days)

        recent_events = [
            e for e in sorted_data
            if isinstance(e.get("timestamp"), datetime) and e["timestamp"] > cutoff
        ]

        if not recent_events:
            return {
                "trend": "declining",
                "activity_count": 0,
                "avg_daily_events": 0.0,
                "escalation_level": ThreatEscalationLevel.DORMANT.value,
            }

        # Calculate daily event counts
        daily_counts = {}
        for event in recent_events:
            date = event["timestamp"].date() if isinstance(event["timestamp"], datetime) else None
            if date:
                daily_counts[date] = daily_counts.get(date, 0) + 1

        avg_daily = sum(daily_counts.values()) / len(daily_counts) if daily_counts else 0
        total_events = len(recent_events)

        # Determine trend (rising, stable, declining)
        if len(daily_counts) > 7:
            first_week = sorted(daily_counts.items())[:7]
            last_week = sorted(daily_counts.items())[-7:]
            first_avg = statistics.mean([v for k, v in first_week])
            last_avg = statistics.mean([v for k, v in last_week])

            if last_avg > first_avg * 1.2:
                trend = "rising"
            elif last_avg < first_avg * 0.8:
                trend = "declining"
            else:
                trend = "stable"
        else:
            trend = "insufficient_data"

        # Determine escalation level
        if avg_daily > 10:
            escalation = ThreatEscalationLevel.CRITICAL.value
        elif avg_daily > 5:
            escalation = ThreatEscalationLevel.ACTIVE.value
        elif avg_daily > 0:
            escalation = ThreatEscalationLevel.EMERGING.value
        else:
            escalation = ThreatEscalationLevel.DORMANT.value

        return {
            "trend": trend,
            "activity_count": total_events,
            "avg_daily_events": round(avg_daily, 2),
            "escalation_level": escalation,
            "days_analyzed": len(daily_counts),
            "peak_daily_count": max(daily_counts.values()) if daily_counts else 0,
        }

    def correlate_threat_layers(
        self,
        vulnerabilities: List[Dict[str, Any]],
        iocs: List[Dict[str, Any]],
        campaigns: List[Dict[str, Any]],
        actors: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Correlate threats across all layers.

        Args:
            vulnerabilities: Vulnerability data
            iocs: IOC data
            campaigns: Campaign data
            actors: Threat actor data

        Returns:
            Cross-layer correlation analysis
        """
        correlations = []

        # Find vulnerabilities exploited in campaigns
        vuln_exploit_count = 0
        for campaign in campaigns:
            techniques = campaign.get("techniques", [])
            if vulnerabilities:
                for vuln in vulnerabilities:
                    cwe_ids = vuln.get("cwe_ids", [])
                    if any(cwe in techniques for cwe in cwe_ids):
                        vuln_exploit_count += 1
                        correlations.append({
                            "type": "vuln_in_campaign",
                            "vuln": vuln.get("id"),
                            "campaign": campaign.get("id"),
                            "confidence": 0.85,
                        })

        # Find IOCs linked to campaigns
        ioc_campaign_links = 0
        for ioc in iocs:
            for campaign in campaigns:
                if campaign.get("id") in ioc.get("related_entities", []):
                    ioc_campaign_links += 1
                    correlations.append({
                        "type": "ioc_in_campaign",
                        "ioc": ioc.get("value"),
                        "campaign": campaign.get("id"),
                        "confidence": 0.90,
                    })

        # Find campaigns attributed to actors
        actor_campaign_links = 0
        for actor in actors:
            for campaign in campaigns:
                if campaign.get("id") in actor.get("campaigns", []):
                    actor_campaign_links += 1
                    correlations.append({
                        "type": "campaign_by_actor",
                        "actor": actor.get("name"),
                        "campaign": campaign.get("id"),
                        "confidence": 0.95,
                    })

        # Calculate correlation strength
        total_entities = len(vulnerabilities) + len(iocs) + len(campaigns) + len(actors)
        correlation_density = len(correlations) / max(total_entities, 1)

        return {
            "correlation_count": len(correlations),
            "correlation_density": round(correlation_density, 3),
            "vuln_exploit_links": vuln_exploit_count,
            "ioc_campaign_links": ioc_campaign_links,
            "actor_campaign_links": actor_campaign_links,
            "top_correlations": sorted(
                correlations,
                key=lambda x: x.get("confidence", 0),
                reverse=True
            )[:10],
        }

    def predict_threat_vectors(
        self,
        actor_history: List[Dict[str, Any]],
        campaign_patterns: List[Dict[str, Any]],
        exploitation_trends: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Predict future threat vectors.

        Args:
            actor_history: Historical actor behavior
            campaign_patterns: Campaign pattern data
            exploitation_trends: CVE exploitation trends

        Returns:
            Predicted threat vectors
        """
        predictions = []

        # Predict likely next targets based on history
        if actor_history:
            sector_history = {}
            for record in actor_history:
                sectors = record.get("target_sectors", [])
                for sector in sectors:
                    sector_history[sector] = sector_history.get(sector, 0) + 1

            most_targeted = sorted(
                sector_history.items(),
                key=lambda x: x[1],
                reverse=True
            )[:3]

            for sector, count in most_targeted:
                predictions.append({
                    "type": "likely_target_sector",
                    "sector": sector,
                    "historical_attacks": count,
                    "confidence": min(count / max(len(actor_history), 1), 1.0),
                })

        # Predict likely exploitation methods
        if exploitation_trends:
            technique_frequency = {}
            for trend in exploitation_trends:
                techniques = trend.get("techniques", [])
                for tech in techniques:
                    technique_frequency[tech] = technique_frequency.get(tech, 0) + 1

            top_techniques = sorted(
                technique_frequency.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]

            for technique, frequency in top_techniques:
                predictions.append({
                    "type": "likely_exploitation_technique",
                    "technique": technique,
                    "historical_frequency": frequency,
                    "confidence": min(frequency / max(len(exploitation_trends), 1), 1.0),
                })

        return {
            "prediction_count": len(predictions),
            "predictions": predictions,
            "confidence_avg": (
                statistics.mean([p.get("confidence", 0) for p in predictions])
                if predictions else 0.0
            ),
        }

    def aggregate_risk(
        self,
        entity_risks: Dict[str, float],
        correlation_strength: float,
        escalation_level: str
    ) -> Dict[str, Any]:
        """Aggregate risk across entities.

        Args:
            entity_risks: Risk scores by entity
            correlation_strength: Cross-layer correlation density
            escalation_level: Current escalation level

        Returns:
            Aggregated risk assessment
        """
        if not entity_risks:
            base_risk = 0.0
        else:
            base_risk = statistics.mean(entity_risks.values())

        # Escalation multiplier
        escalation_multipliers = {
            "dormant": 0.5,
            "emerging": 1.0,
            "active": 1.5,
            "critical": 2.0,
        }
        multiplier = escalation_multipliers.get(escalation_level, 1.0)

        # Correlation amplification
        correlation_factor = 1.0 + (correlation_strength * 0.5)

        # Final aggregated risk
        aggregated_risk = min(base_risk * multiplier * correlation_factor, 1.0)

        return {
            "aggregated_risk": round(aggregated_risk, 3),
            "base_risk": round(base_risk, 3),
            "escalation_multiplier": multiplier,
            "correlation_amplification": round(correlation_factor, 3),
            "risk_level": self._classify_risk(aggregated_risk),
        }

    def _classify_risk(self, score: float) -> str:
        """Classify risk level from score.

        Args:
            score: Risk score (0.0-1.0)

        Returns:
            Risk classification
        """
        if score >= 0.8:
            return "CRITICAL"
        elif score >= 0.6:
            return "HIGH"
        elif score >= 0.4:
            return "MEDIUM"
        elif score >= 0.2:
            return "LOW"
        else:
            return "MINIMAL"

    def generate_recommendations(
        self,
        threat_assessment: Dict[str, Any],
        risk_aggregation: Dict[str, Any],
        available_mitigations: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate system-wide recommendations.

        Args:
            threat_assessment: Threat analysis results
            risk_aggregation: Aggregated risk data
            available_mitigations: List of mitigation strategies

        Returns:
            Prioritized recommendations
        """
        recommendations = []

        risk_level = risk_aggregation.get("risk_level", "UNKNOWN")

        # Recommend based on risk level
        if risk_level == "CRITICAL":
            recommendations.append({
                "priority": "IMMEDIATE",
                "action": "Activate incident response procedures",
                "reason": "Critical-level threat detected",
                "timeline": "0-1 hours",
            })
            recommendations.append({
                "priority": "IMMEDIATE",
                "action": "Isolate affected systems",
                "reason": "Active threat exploitation in progress",
                "timeline": "0-2 hours",
            })
        elif risk_level == "HIGH":
            recommendations.append({
                "priority": "URGENT",
                "action": "Deploy enhanced monitoring",
                "reason": "High-level threat activity detected",
                "timeline": "0-4 hours",
            })
            recommendations.append({
                "priority": "URGENT",
                "action": "Apply security patches",
                "reason": "Known vulnerabilities being exploited",
                "timeline": "4-24 hours",
            })
        elif risk_level == "MEDIUM":
            recommendations.append({
                "priority": "HIGH",
                "action": "Review and update detection rules",
                "reason": "Moderate threat activity detected",
                "timeline": "1-7 days",
            })

        # Threat-specific recommendations
        escalation = threat_assessment.get("escalation_level", "unknown")
        if escalation == "rising":
            recommendations.append({
                "priority": "HIGH",
                "action": "Increase monitoring sensitivity",
                "reason": "Threat activity trending upward",
                "timeline": "immediate",
            })

        return {
            "recommendation_count": len(recommendations),
            "recommendations": recommendations,
            "review_frequency": self._recommend_review_frequency(risk_level),
        }

    def _recommend_review_frequency(self, risk_level: str) -> str:
        """Recommend review frequency based on risk level.

        Args:
            risk_level: Risk classification

        Returns:
            Recommended review frequency
        """
        frequency_map = {
            "CRITICAL": "every 1 hour",
            "HIGH": "every 4 hours",
            "MEDIUM": "daily",
            "LOW": "weekly",
            "MINIMAL": "monthly",
        }
        return frequency_map.get(risk_level, "as needed")

    def generate_executive_report(
        self,
        threat_analysis: Dict[str, Any],
        risk_aggregation: Dict[str, Any],
        recommendations: Dict[str, Any],
        system_stats: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate executive-level intelligence report.

        Args:
            threat_analysis: Threat timeline analysis
            risk_aggregation: Aggregated risk metrics
            recommendations: System recommendations
            system_stats: System statistics

        Returns:
            Executive intelligence report
        """
        return {
            "timestamp": datetime.utcnow(),
            "executive_summary": {
                "current_threat_level": risk_aggregation.get("risk_level", "UNKNOWN"),
                "escalation_status": threat_analysis.get("escalation_level", "UNKNOWN"),
                "activity_trend": threat_analysis.get("trend", "UNKNOWN"),
                "recent_activity": threat_analysis.get("activity_count", 0),
            },
            "key_metrics": {
                "aggregated_risk_score": risk_aggregation.get("aggregated_risk", 0.0),
                "avg_daily_threats": threat_analysis.get("avg_daily_events", 0.0),
                "total_entities": system_stats.get("total_entities", 0),
                "active_campaigns": system_stats.get("active_campaigns", 0),
            },
            "critical_actions": [
                r for r in recommendations.get("recommendations", [])
                if r.get("priority") in ["IMMEDIATE", "URGENT"]
            ],
            "review_frequency": recommendations.get("review_frequency", "as needed"),
            "confidence": round(
                statistics.mean([
                    risk_aggregation.get("aggregated_risk", 0.5),
                    threat_analysis.get("days_analyzed", 1) / 30,
                ]),
                3
            ),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert engine state to dictionary.

        Returns:
            Dict representation
        """
        return {
            "timestamp": datetime.utcnow(),
            "threat_events": self.threat_events,
            "correlations": self.correlation_results,
            "predictions": self.predictions,
            "recommendations": self.recommendations,
        }
