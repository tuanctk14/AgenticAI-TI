"""
core/threat_intelligence_reasoner.py - Threat Intelligence Reasoning Engine

Advanced reasoning over threat intelligence:
- Multi-source threat assessment
- Risk scoring and prioritization
- Tactical recommendations
- Strategic intelligence synthesis
- Attack path analysis
- Incident response recommendations
"""

from typing import Dict, List, Set, Optional, Any, Tuple
from datetime import datetime, timedelta
from collections import defaultdict

from core.threat_memory import ThreatMemoryEngine
from core.pattern_detection import PatternDetectionEngine
from core.historical_context import HistoricalContextEngine
from core.community_detection import CommunityDetectionEngine
from core.actor_profiling import ActorProfilingEngine
from core.trend_analysis import TrendAnalyzer
from core.anomaly_detection import AnomalyDetector


class ThreatAssessment:
    """Comprehensive threat assessment."""

    def __init__(self, assessment_id: str):
        """Initialize threat assessment.

        Args:
            assessment_id: Unique assessment identifier
        """
        self.assessment_id = assessment_id
        self.timestamp = datetime.utcnow()
        self.threat_level = "unknown"
        self.confidence_score = 0.0
        self.risk_score = 0.0
        self.affected_entities = {}
        self.recommended_actions = []
        self.intelligence_summary = ""
        self.supporting_evidence = []

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "assessment_id": self.assessment_id,
            "timestamp": self.timestamp,
            "threat_level": self.threat_level,
            "confidence_score": self.confidence_score,
            "risk_score": self.risk_score,
            "affected_entities": self.affected_entities,
            "recommended_actions": self.recommended_actions,
            "intelligence_summary": self.intelligence_summary,
            "supporting_evidence": self.supporting_evidence,
        }


class ThreatIntelligenceReasoner:
    """Advanced threat intelligence reasoning engine."""

    def __init__(
        self,
        memory_engine: ThreatMemoryEngine,
        pattern_engine: PatternDetectionEngine,
        context_engine: HistoricalContextEngine,
        community_engine: CommunityDetectionEngine,
        profiling_engine: ActorProfilingEngine,
        trend_analyzer: TrendAnalyzer,
        anomaly_detector: AnomalyDetector,
    ):
        """Initialize reasoning engine.

        Args:
            memory_engine: Threat memory engine
            pattern_engine: Pattern detection engine
            context_engine: Historical context engine
            community_engine: Community detection engine
            profiling_engine: Actor profiling engine
            trend_analyzer: Trend analysis engine
            anomaly_detector: Anomaly detection engine
        """
        self.memory = memory_engine
        self.patterns = pattern_engine
        self.context = context_engine
        self.communities = community_engine
        self.profiling = profiling_engine
        self.trends = trend_analyzer
        self.anomalies = anomaly_detector

    def assess_threat_level(self) -> ThreatAssessment:
        """Generate comprehensive threat assessment.

        Returns:
            ThreatAssessment with integrated analysis
        """
        assessment = ThreatAssessment(f"assessment-{datetime.utcnow().timestamp()}")

        # Collect evidence from all engines
        evidence = []

        # 1. Active campaign analysis
        active_campaigns = []
        for campaign_id, camp_mem in self.memory.campaign_memory.items():
            if camp_mem.is_active:
                active_campaigns.append((campaign_id, camp_mem))

        if active_campaigns:
            evidence.append(f"Active campaigns detected: {len(active_campaigns)}")

        # 2. Emerging actor analysis
        emerging_actors = self.trends.detect_emerging_actors(recent_days=60)
        if emerging_actors:
            evidence.append(f"Emerging threat actors: {len(emerging_actors)}")

        # 3. Anomaly analysis
        anomaly_summary = self.anomalies.get_anomaly_summary()
        total_anomalies = (
            anomaly_summary["summary"]["total_ioc_anomalies"] +
            anomaly_summary["summary"]["total_campaign_anomalies"] +
            anomaly_summary["summary"]["total_technique_anomalies"]
        )
        if total_anomalies > 0:
            evidence.append(f"Detected anomalies: {total_anomalies}")

        # 4. Risk calculation
        total_risk = 0.0
        entity_count = 0

        for campaign_id in self.memory.campaign_memory:
            risk = self.anomalies.get_risk_score("campaign", campaign_id)
            total_risk += risk
            entity_count += 1

        avg_risk = total_risk / max(entity_count, 1)

        # 5. Determine threat level
        if len(active_campaigns) > 2 and avg_risk > 0.7:
            threat_level = "critical"
            confidence = 0.95
        elif len(active_campaigns) > 0 and avg_risk > 0.5:
            threat_level = "high"
            confidence = 0.85
        elif total_anomalies > 5 or len(emerging_actors) > 2:
            threat_level = "medium"
            confidence = 0.70
        elif len(active_campaigns) > 0 or total_anomalies > 0:
            threat_level = "elevated"
            confidence = 0.60
        else:
            threat_level = "low"
            confidence = 0.90

        # Populate assessment
        assessment.threat_level = threat_level
        assessment.confidence_score = confidence
        assessment.risk_score = min(avg_risk, 1.0)
        assessment.supporting_evidence = evidence
        assessment.affected_entities = {
            "active_campaigns": len(active_campaigns),
            "emerging_actors": len(emerging_actors),
            "anomalies_detected": total_anomalies,
        }

        # Generate summary
        assessment.intelligence_summary = (
            f"Threat Level: {threat_level.upper()} (Confidence: {confidence:.0%}). "
            f"Active campaigns: {len(active_campaigns)}. "
            f"Emerging actors: {len(emerging_actors)}. "
            f"Average risk score: {avg_risk:.2f}."
        )

        return assessment

    def assess_entity_threat(self, entity_type: str, entity_id: str) -> Dict[str, Any]:
        """Assess threat level for specific entity.

        Args:
            entity_type: Type of entity (ioc, campaign, actor)
            entity_id: Entity identifier

        Returns:
            Dict with entity threat assessment
        """
        assessment = {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "threat_level": "unknown",
            "risk_score": 0.0,
            "factors": [],
            "recommendations": [],
        }

        if entity_type == "campaign":
            camp_mem = self.memory.get_campaign_memory(entity_id)
            if not camp_mem:
                return assessment

            factors = []
            risk = 0.0

            # Active status
            if camp_mem.is_active:
                factors.append("Campaign is currently active")
                risk += 0.4

            # Activity count
            if camp_mem.activity_count > 10:
                factors.append(f"High activity ({camp_mem.activity_count} recorded activities)")
                risk += 0.2

            # Attributed actors
            if camp_mem.attributed_actors:
                factors.append(f"Attribution: {len(camp_mem.attributed_actors)} threat actor(s)")
                risk += 0.1

            # Targets
            if camp_mem.current_targets:
                factors.append(f"{len(camp_mem.current_targets)} targets identified")
                risk += 0.1

            assessment["risk_score"] = min(risk, 1.0)
            assessment["factors"] = factors

            if risk > 0.7:
                assessment["threat_level"] = "critical"
            elif risk > 0.5:
                assessment["threat_level"] = "high"
            elif risk > 0.3:
                assessment["threat_level"] = "medium"
            else:
                assessment["threat_level"] = "low"

            # Recommendations
            if camp_mem.is_active:
                assessment["recommendations"].append("Immediate incident response activation")
                assessment["recommendations"].append("Real-time monitoring implementation")

        elif entity_type == "actor":
            profile = self.profiling.profile_actor(entity_id)

            factors = []
            risk = 0.0

            if profile.total_campaigns > 3:
                factors.append(f"Experienced actor ({profile.total_campaigns} campaigns)")
                risk += 0.3

            if profile.sophistication_level in ["high", "very_high"]:
                factors.append(f"High sophistication: {profile.sophistication_level}")
                risk += 0.3

            if profile.is_active:
                factors.append("Currently active")
                risk += 0.2

            assessment["risk_score"] = min(risk, 1.0)
            assessment["factors"] = factors

            if risk > 0.7:
                assessment["threat_level"] = "critical"
            elif risk > 0.5:
                assessment["threat_level"] = "high"
            elif risk > 0.3:
                assessment["threat_level"] = "medium"
            else:
                assessment["threat_level"] = "low"

            if profile.is_active:
                assessment["recommendations"].append(f"Monitor {profile.total_campaigns} known campaigns")
                assessment["recommendations"].append("Implement hunting for new campaigns")

        elif entity_type == "ioc":
            ioc_mem = self.memory.get_ioc_memory(entity_id)
            if not ioc_mem:
                return assessment

            factors = []
            risk = self.anomalies.get_risk_score("ioc", entity_id)

            if ioc_mem.occurrence_count > 5:
                factors.append(f"High reuse ({ioc_mem.occurrence_count} occurrences)")

            if ioc_mem.activity_trend == "rising":
                factors.append("Activity trend: rising")
                risk += 0.2

            assessment["risk_score"] = risk
            assessment["factors"] = factors

            if risk > 0.7:
                assessment["threat_level"] = "critical"
            elif risk > 0.5:
                assessment["threat_level"] = "high"
            elif risk > 0.3:
                assessment["threat_level"] = "medium"
            else:
                assessment["threat_level"] = "low"

            if ioc_mem.next_reuse_likelihood > 0.7:
                assessment["recommendations"].append("Block or sinkhole this indicator")
                assessment["recommendations"].append("Monitor for re-emergence")

        return assessment

    def get_tactical_recommendations(self) -> Dict[str, Any]:
        """Generate tactical response recommendations.

        Returns:
            Dict with immediate action recommendations
        """
        recommendations = {
            "immediate_actions": [],
            "detection_actions": [],
            "remediation_actions": [],
            "prioritized_targets": [],
        }

        # Identify immediate actions
        active_campaigns = [
            (cid, cm) for cid, cm in self.memory.campaign_memory.items()
            if cm.is_active
        ]

        if active_campaigns:
            recommendations["immediate_actions"].append(
                f"Activate incident response for {len(active_campaigns)} active campaign(s)"
            )
            recommendations["immediate_actions"].append(
                "Escalate to security operations center (SOC)"
            )

        # Detect anomalous IOCs
        ioc_anomalies = self.anomalies.detect_ioc_reuse_anomalies(z_score_threshold=2.0)
        if ioc_anomalies:
            recommendations["detection_actions"].append(
                f"Implement blocking for {len(ioc_anomalies)} anomalous IOC(s)"
            )

        # Remediation for emerging threats
        emerging_actors = self.trends.detect_emerging_actors(recent_days=90)
        if emerging_actors:
            recommendations["remediation_actions"].append(
                f"Develop detection signatures for {len(emerging_actors)} emerging actor(s)"
            )

        # Prioritize targets
        for campaign_id, camp_mem in active_campaigns[:3]:
            if camp_mem.current_targets:
                for target in camp_mem.current_targets[:2]:
                    recommendations["prioritized_targets"].append({
                        "target": target,
                        "campaign": campaign_id,
                        "actors": camp_mem.attributed_actors,
                    })

        return recommendations

    def get_strategic_intelligence(self) -> Dict[str, Any]:
        """Generate strategic threat intelligence summary.

        Returns:
            Dict with strategic analysis and trends
        """
        intelligence = {
            "threat_landscape_overview": "",
            "actor_landscape": [],
            "emerging_trends": [],
            "long_term_patterns": [],
        }

        # Overview
        total_campaigns = len(self.memory.campaign_memory)
        total_actors = len(set(
            actor for camp in self.memory.campaign_memory.values()
            for actor in camp.attributed_actors
        ))
        active_campaigns = sum(
            1 for camp in self.memory.campaign_memory.values()
            if camp.is_active
        )

        intelligence["threat_landscape_overview"] = (
            f"Tracking {total_campaigns} campaigns from {total_actors} distinct threat actors. "
            f"{active_campaigns} campaigns currently active."
        )

        # Actor landscape
        actor_rankings = self.profiling.rank_actors_by_threat()
        for actor_rank in actor_rankings[:5]:
            intelligence["actor_landscape"].append({
                "actor_id": actor_rank["actor_id"],
                "threat_score": actor_rank["threat_score"],
                "sophistication": actor_rank["sophistication"],
                "campaign_count": actor_rank["total_campaigns"],
            })

        # Emerging trends
        ioc_trends = self.trends.analyze_ioc_trends(days_window=90)
        rising_iocs = [t for t in ioc_trends if t["trend"] == "rising"]
        if rising_iocs:
            intelligence["emerging_trends"].append(
                f"{len(rising_iocs)} IOCs showing rising activity"
            )

        technique_trends = self.trends.analyze_technique_adoption_trends(days_window=90)
        emerging_techniques = [t for t in technique_trends if t["trend"] == "emerging"]
        if emerging_techniques:
            intelligence["emerging_trends"].append(
                f"{len(emerging_techniques)} techniques newly adopted"
            )

        # Long-term patterns
        global_tempo = self.trends.analyze_threat_tempo_global(window_days=90)
        if "avg_daily_events" in global_tempo:
            intelligence["long_term_patterns"].append(
                f"Overall threat tempo: {global_tempo['tempo_classification']} "
                f"({global_tempo['avg_daily_events']:.1f} events/day)"
            )

        return intelligence

    def analyze_attack_path(self, asset_id: str) -> Dict[str, Any]:
        """Analyze attack paths to specific asset.

        Args:
            asset_id: Target asset identifier

        Returns:
            Dict with attack path analysis
        """
        analysis = {
            "asset_id": asset_id,
            "attack_paths": [],
            "threat_actors": [],
            "iocs": [],
            "techniques": [],
            "risk_level": "unknown",
        }

        asset_mem = self.memory.get_asset_memory(asset_id)
        if not asset_mem:
            return analysis

        # Identify campaigns targeting asset
        targeted_campaigns = []
        for campaign_id, camp_mem in self.memory.campaign_memory.items():
            if asset_id in camp_mem.current_targets:
                targeted_campaigns.append((campaign_id, camp_mem))

        # Extract threat actors
        for campaign_id, camp_mem in targeted_campaigns:
            analysis["threat_actors"].extend(camp_mem.attributed_actors)
            analysis["techniques"].extend(camp_mem.techniques_evolution)

        # Extract IOCs
        for campaign_id, camp_mem in targeted_campaigns:
            for ioc_id, ioc_mem in self.memory.ioc_memory.items():
                if campaign_id in ioc_mem.associated_campaigns:
                    analysis["iocs"].append({
                        "ioc_id": ioc_id,
                        "ioc_value": ioc_mem.ioc_value,
                    })

        # Build attack paths
        for campaign_id, camp_mem in targeted_campaigns:
            path = {
                "campaign": campaign_id,
                "actors": camp_mem.attributed_actors,
                "techniques": camp_mem.techniques_evolution,
                "is_active": camp_mem.is_active,
            }
            analysis["attack_paths"].append(path)

        # Assess risk
        if any(c[1].is_active for c in targeted_campaigns):
            analysis["risk_level"] = "critical"
        elif len(targeted_campaigns) > 2:
            analysis["risk_level"] = "high"
        elif len(targeted_campaigns) > 0:
            analysis["risk_level"] = "medium"
        else:
            analysis["risk_level"] = "low"

        return analysis

    def get_complete_intelligence_report(self) -> Dict[str, Any]:
        """Generate complete intelligence report.

        Returns:
            Dict with all reasoning outputs
        """
        return {
            "timestamp": datetime.utcnow(),
            "threat_assessment": self.assess_threat_level().to_dict(),
            "tactical_recommendations": self.get_tactical_recommendations(),
            "strategic_intelligence": self.get_strategic_intelligence(),
            "report_summary": self._generate_report_summary(),
        }

    def _generate_report_summary(self) -> str:
        """Generate natural language report summary.

        Returns:
            Human-readable summary
        """
        assessment = self.assess_threat_level()
        trends = self.trends.analyze_threat_tempo_global(window_days=90)

        tempo_line = ""
        if "avg_daily_events" in trends:
            tempo_line = (
                f"- Threat Tempo: {trends['tempo_classification']} "
                f"({trends['avg_daily_events']:.1f} events/day)\n"
            )

        summary = (
            f"THREAT INTELLIGENCE REPORT\n"
            f"Generated: {datetime.utcnow().isoformat()}\n\n"
            f"EXECUTIVE SUMMARY\n"
            f"Overall Threat Level: {assessment.threat_level.upper()}\n"
            f"Assessment Confidence: {assessment.confidence_score:.0%}\n"
            f"Risk Score: {assessment.risk_score:.2f}/1.00\n\n"
            f"KEY FINDINGS\n"
            f"- {assessment.affected_entities.get('active_campaigns', 0)} active campaigns\n"
            f"- {assessment.affected_entities.get('emerging_actors', 0)} emerging threat actors\n"
            f"- {assessment.affected_entities.get('anomalies_detected', 0)} anomalies detected\n"
            f"{tempo_line}"
        )

        return summary
