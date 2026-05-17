"""
core/anomaly_detection.py - Threat Anomaly Detection Engine

Detects behavioral anomalies in threat landscape:
- Behavioral deviation detection (Z-score analysis)
- IOC reuse anomalies
- Campaign timing irregularities
- Technique adoption anomalies
- Target selection anomalies
- Actor behavior changes
- Infrastructure reuse patterns
"""

from typing import Dict, List, Set, Optional, Any
from datetime import datetime, timedelta
from collections import defaultdict
import math

from core.threat_memory import ThreatMemoryEngine
from core.pattern_detection import PatternDetectionEngine
from core.historical_context import HistoricalContextEngine


class AnomalyDetector:
    """Engine for detecting threat landscape anomalies."""

    def __init__(
        self,
        memory_engine: ThreatMemoryEngine,
        pattern_engine: PatternDetectionEngine,
        context_engine: HistoricalContextEngine,
    ):
        """Initialize anomaly detector.

        Args:
            memory_engine: Threat memory engine
            pattern_engine: Pattern detection engine
            context_engine: Historical context engine
        """
        self.memory = memory_engine
        self.patterns = pattern_engine
        self.context = context_engine

    def detect_ioc_reuse_anomalies(self, z_score_threshold: float = 2.0) -> List[Dict[str, Any]]:
        """Detect IOCs with anomalous reuse patterns.

        Args:
            z_score_threshold: Z-score threshold for anomaly detection

        Returns:
            List of IOCs with anomalous reuse patterns
        """
        anomalies = []

        # Collect reuse counts
        reuse_counts = []
        ioc_data = {}

        for ioc_id, ioc_mem in self.memory.ioc_memory.items():
            count = ioc_mem.occurrence_count
            reuse_counts.append(count)
            ioc_data[ioc_id] = count

        if len(reuse_counts) < 5:
            return anomalies

        # Calculate statistics
        mean = sum(reuse_counts) / len(reuse_counts)
        variance = sum((x - mean) ** 2 for x in reuse_counts) / len(reuse_counts)
        stddev = math.sqrt(variance) if variance > 0 else 0.0

        if stddev == 0:
            return anomalies

        # Find anomalies
        for ioc_id, count in ioc_data.items():
            z_score = (count - mean) / stddev
            if abs(z_score) >= z_score_threshold:
                ioc_mem = self.memory.get_ioc_memory(ioc_id)
                anomalies.append({
                    "ioc_id": ioc_id,
                    "ioc_value": ioc_mem.ioc_value if ioc_mem else "unknown",
                    "occurrence_count": count,
                    "z_score": z_score,
                    "expected_count": mean,
                    "is_over_reused": z_score > z_score_threshold,
                    "is_under_reused": z_score < -z_score_threshold,
                })

        return sorted(anomalies, key=lambda x: abs(x["z_score"]), reverse=True)

    def detect_campaign_timing_anomalies(self, z_score_threshold: float = 2.0) -> List[Dict[str, Any]]:
        """Detect campaigns with anomalous timing/duration.

        Args:
            z_score_threshold: Z-score threshold for anomaly detection

        Returns:
            List of campaigns with timing anomalies
        """
        anomalies = []

        # Calculate campaign durations
        durations = []
        campaign_data = {}

        for campaign_id, camp_mem in self.memory.campaign_memory.items():
            if len(camp_mem.activities) < 2:
                continue

            first = camp_mem.activities[0].date
            last = camp_mem.activities[-1].date
            duration = (last - first).days
            durations.append(duration)
            campaign_data[campaign_id] = duration

        if len(durations) < 5:
            return anomalies

        # Calculate statistics
        mean = sum(durations) / len(durations)
        variance = sum((x - mean) ** 2 for x in durations) / len(durations)
        stddev = math.sqrt(variance) if variance > 0 else 0.0

        if stddev == 0:
            return anomalies

        # Find anomalies
        for campaign_id, duration in campaign_data.items():
            z_score = (duration - mean) / stddev
            if abs(z_score) >= z_score_threshold:
                camp_mem = self.memory.get_campaign_memory(campaign_id)
                anomalies.append({
                    "campaign_id": campaign_id,
                    "campaign_name": camp_mem.campaign_name if camp_mem else "unknown",
                    "duration_days": duration,
                    "z_score": z_score,
                    "expected_duration": mean,
                    "is_unusually_long": z_score > z_score_threshold,
                    "is_unusually_short": z_score < -z_score_threshold,
                })

        return sorted(anomalies, key=lambda x: abs(x["z_score"]), reverse=True)

    def detect_technique_adoption_anomalies(self, z_score_threshold: float = 2.0) -> List[Dict[str, Any]]:
        """Detect techniques with anomalous adoption patterns.

        Args:
            z_score_threshold: Z-score threshold for anomaly detection

        Returns:
            List of techniques with adoption anomalies
        """
        anomalies = []

        # Count technique usage
        technique_usage = defaultdict(int)
        for campaign_id, camp_mem in self.memory.campaign_memory.items():
            for technique in camp_mem.techniques_evolution:
                technique_usage[technique] += 1

        if len(technique_usage) < 5:
            return anomalies

        usage_counts = list(technique_usage.values())
        mean = sum(usage_counts) / len(usage_counts)
        variance = sum((x - mean) ** 2 for x in usage_counts) / len(usage_counts)
        stddev = math.sqrt(variance) if variance > 0 else 0.0

        if stddev == 0:
            return anomalies

        # Find anomalies
        for technique, count in technique_usage.items():
            z_score = (count - mean) / stddev
            if abs(z_score) >= z_score_threshold:
                anomalies.append({
                    "technique": technique,
                    "usage_count": count,
                    "z_score": z_score,
                    "expected_usage": mean,
                    "is_unusually_common": z_score > z_score_threshold,
                    "is_unusually_rare": z_score < -z_score_threshold,
                })

        return sorted(anomalies, key=lambda x: abs(x["z_score"]), reverse=True)

    def detect_actor_behavior_changes(self, window_days: int = 60) -> List[Dict[str, Any]]:
        """Detect actors with significant behavior changes.

        Args:
            window_days: Analysis window in days

        Returns:
            List of actors with detected behavior changes
        """
        changes = []
        cutoff_date = datetime.utcnow() - timedelta(days=window_days)

        actors = set()
        for camp_mem in self.memory.campaign_memory.values():
            actors.update(camp_mem.attributed_actors)

        for actor_id in actors:
            # Get historical techniques
            all_techniques = set()
            recent_techniques = set()

            for campaign_id, camp_mem in self.memory.campaign_memory.items():
                if actor_id not in camp_mem.attributed_actors:
                    continue

                all_techniques.update(camp_mem.techniques_evolution)

                if camp_mem.first_observed and camp_mem.first_observed > cutoff_date:
                    recent_techniques.update(camp_mem.techniques_evolution)

            if not all_techniques:
                continue

            # Calculate technique shift
            new_techniques = recent_techniques - (all_techniques - recent_techniques)
            dropped_techniques = (all_techniques - recent_techniques) - recent_techniques

            if len(new_techniques) > 0 or len(dropped_techniques) > 0:
                change_score = (len(new_techniques) + len(dropped_techniques)) / len(all_techniques)

                changes.append({
                    "actor_id": actor_id,
                    "new_techniques": list(new_techniques),
                    "dropped_techniques": list(dropped_techniques),
                    "total_techniques_used": len(all_techniques),
                    "behavior_change_score": change_score,
                    "is_significant_change": change_score > 0.3,
                })

        return sorted(changes, key=lambda x: x["behavior_change_score"], reverse=True)

    def detect_infrastructure_anomalies(self, z_score_threshold: float = 2.0) -> List[Dict[str, Any]]:
        """Detect infrastructure nodes with anomalous usage patterns.

        Args:
            z_score_threshold: Z-score threshold for anomaly detection

        Returns:
            List of infrastructure nodes with anomalies
        """
        anomalies = []

        # Calculate usage diversity (number of different actors/campaigns per IOC)
        ioc_diversity = defaultdict(int)

        for ioc_id, ioc_mem in self.memory.ioc_memory.items():
            if ioc_mem.associated_campaigns:
                ioc_diversity[ioc_id] = len(set(ioc_mem.associated_campaigns))

        if len(ioc_diversity) < 5:
            return anomalies

        diversity_scores = list(ioc_diversity.values())
        mean = sum(diversity_scores) / len(diversity_scores)
        variance = sum((x - mean) ** 2 for x in diversity_scores) / len(diversity_scores)
        stddev = math.sqrt(variance) if variance > 0 else 0.0

        if stddev == 0:
            return anomalies

        # Find anomalies
        for ioc_id, diversity in ioc_diversity.items():
            z_score = (diversity - mean) / stddev
            if abs(z_score) >= z_score_threshold:
                ioc_mem = self.memory.get_ioc_memory(ioc_id)
                anomalies.append({
                    "ioc_id": ioc_id,
                    "ioc_value": ioc_mem.ioc_value if ioc_mem else "unknown",
                    "campaign_diversity": diversity,
                    "z_score": z_score,
                    "expected_diversity": mean,
                    "is_highly_shared": z_score > z_score_threshold,
                    "is_isolated": z_score < -z_score_threshold,
                })

        return sorted(anomalies, key=lambda x: abs(x["z_score"]), reverse=True)

    def get_anomaly_summary(self) -> Dict[str, Any]:
        """Get comprehensive anomaly summary.

        Returns:
            Dict with all anomaly detection results
        """
        return {
            "ioc_reuse_anomalies": self.detect_ioc_reuse_anomalies(),
            "campaign_timing_anomalies": self.detect_campaign_timing_anomalies(),
            "technique_anomalies": self.detect_technique_adoption_anomalies(),
            "actor_behavior_changes": self.detect_actor_behavior_changes(),
            "infrastructure_anomalies": self.detect_infrastructure_anomalies(),
            "summary": {
                "total_ioc_anomalies": len(self.detect_ioc_reuse_anomalies()),
                "total_campaign_anomalies": len(self.detect_campaign_timing_anomalies()),
                "total_technique_anomalies": len(self.detect_technique_adoption_anomalies()),
                "total_actor_changes": len(self.detect_actor_behavior_changes()),
                "total_infrastructure_anomalies": len(self.detect_infrastructure_anomalies()),
            }
        }

    def get_risk_score(self, entity_type: str, entity_id: str) -> float:
        """Calculate risk score for entity (0.0-1.0) considering anomalies.

        Args:
            entity_type: Type of entity (ioc, campaign, actor)
            entity_id: Entity identifier

        Returns:
            Risk score from 0.0 (no risk) to 1.0 (critical risk)
        """
        if entity_type == "ioc":
            ioc_mem = self.memory.get_ioc_memory(entity_id)
            if not ioc_mem:
                return 0.0

            # Risk based on occurrence count
            occurrence_risk = min(ioc_mem.occurrence_count / 10.0, 1.0)

            # Risk based on activity trend
            trend_risk = {
                "rising": 0.9,
                "stable": 0.5,
                "declining": 0.2,
                "unknown": 0.3,
            }.get(ioc_mem.activity_trend, 0.3)

            # Risk based on reuse likelihood
            likelihood_risk = ioc_mem.next_reuse_likelihood

            return (occurrence_risk * 0.3 + trend_risk * 0.3 + likelihood_risk * 0.4)

        elif entity_type == "campaign":
            camp_mem = self.memory.get_campaign_memory(entity_id)
            if not camp_mem:
                return 0.0

            # Risk based on activity count
            activity_risk = min(camp_mem.activity_count / 20.0, 1.0)

            # Risk based on active status
            active_risk = 1.0 if camp_mem.is_active else 0.3

            return (activity_risk * 0.4 + active_risk * 0.6)

        elif entity_type == "actor":
            # Risk based on campaign count
            campaigns = 0
            for camp_mem in self.memory.campaign_memory.values():
                if entity_id in camp_mem.attributed_actors:
                    campaigns += 1

            campaign_risk = min(campaigns / 5.0, 1.0)
            return campaign_risk

        return 0.0
