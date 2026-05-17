"""
core/historical_context.py - Historical Context Building Engine

Aggregates historical threat data to build contextual intelligence:
- Actor/campaign profiles from historical activities
- Statistical baselines and confidence bands
- Threat evolution analysis
- Contextual risk scoring
- Historical anomalies and outliers

Enables memory-aware threat reasoning with historical perspective.
"""

from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timedelta
from statistics import mean, stdev, median
from collections import Counter

from core.threat_memory import ThreatMemoryEngine
from core.pattern_detection import PatternDetectionEngine


# ============================================================
# HISTORICAL CONTEXT MODELS
# ============================================================

class ActorProfile:
    """Historical profile of threat actor/campaign."""

    def __init__(self, actor_id: str, actor_name: str):
        self.actor_id = actor_id
        self.actor_name = actor_name
        self.first_observed: Optional[datetime] = None
        self.last_observed: Optional[datetime] = None
        self.activity_count: int = 0
        self.activity_dates: List[datetime] = []
        self.techniques_used: List[str] = []
        self.targets: List[str] = []
        self.malware_families: List[str] = []
        self.infrastructure_nodes: List[str] = []
        self.avg_activity_frequency: float = 0.0
        self.evolution_trajectory: str = "unknown"  # expanding, consolidating, declining
        self.confidence: float = 0.0
        self.is_active: bool = True


class ThreatTimeline:
    """Historical threat timeline with context."""

    def __init__(self, threat_id: str):
        self.threat_id = threat_id
        self.events: List[Tuple[datetime, str, str]] = []  # (date, event_type, details)
        self.timeline_length_days: int = 0
        self.event_density: float = 0.0  # events per day
        self.dormancy_periods: List[Tuple[datetime, datetime]] = []
        self.resurgence_count: int = 0
        self.predictability_score: float = 0.0


class RiskContext:
    """Contextual risk factors from history."""

    def __init__(self, entity_id: str):
        self.entity_id = entity_id
        self.historical_risk_score: float = 0.0  # 0.0-1.0
        self.threat_actor_count: int = 0
        self.campaign_count: int = 0
        self.vulnerability_count: int = 0
        self.exposure_recurrence: float = 0.0  # % recurrence rate
        self.avg_time_to_exploitation_days: int = 0
        self.baseline_incident_rate: float = 0.0  # per month
        self.upper_confidence_band: float = 0.0
        self.lower_confidence_band: float = 0.0
        self.risk_trend: str = "unknown"
        self.contextual_severity: str = "unknown"  # critical, high, medium, low


class StatisticalBaseline:
    """Statistical baseline for threat classification."""

    def __init__(self, baseline_type: str):
        self.baseline_type = baseline_type  # ioc_lifetime, campaign_duration, exposure_frequency
        self.observations: List[float] = []
        self.mean: float = 0.0
        self.median: float = 0.0
        self.stddev: float = 0.0
        self.min_value: float = 0.0
        self.max_value: float = 0.0
        self.percentile_25: float = 0.0
        self.percentile_75: float = 0.0
        self.normal_range: Tuple[float, float] = (0.0, 0.0)
        self.samples_count: int = 0


# ============================================================
# HISTORICAL CONTEXT ENGINE
# ============================================================

class HistoricalContextEngine:
    """
    Build historical context for threat intelligence.

    Aggregates historical data to:
    - Create actor/campaign profiles
    - Establish statistical baselines
    - Enable contextual risk scoring
    - Detect historical anomalies
    - Support predictive threat analysis
    """

    def __init__(self, memory_engine: ThreatMemoryEngine, pattern_engine: PatternDetectionEngine):
        """Initialize with memory and pattern references."""
        self.memory = memory_engine
        self.patterns = pattern_engine

    # ============================================================
    # ACTOR/CAMPAIGN PROFILING
    # ============================================================

    def build_actor_profile(self, actor_id: str, actor_name: str) -> ActorProfile:
        """Build historical profile of threat actor."""
        profile = ActorProfile(actor_id, actor_name)

        # Collect activities from campaigns
        for campaign_id, campaign_mem in self.memory.campaign_memory.items():
            if actor_id in campaign_mem.attributed_actors:
                profile.activity_dates.extend([a.date for a in campaign_mem.activities])
                profile.techniques_used.extend(campaign_mem.techniques_evolution)
                profile.targets.extend(campaign_mem.current_targets)
                profile.activity_count += campaign_mem.activity_count

                # Track associated infrastructure
                # (would be populated from relationship data)

        if not profile.activity_dates:
            return profile

        profile.activity_dates = sorted(set(profile.activity_dates))
        profile.first_observed = profile.activity_dates[0] if profile.activity_dates else None
        profile.last_observed = profile.activity_dates[-1] if profile.activity_dates else None

        # Calculate activity frequency
        if len(profile.activity_dates) > 1:
            days_active = (profile.last_observed - profile.first_observed).days + 1
            months_active = max(1, days_active / 30.0)
            profile.avg_activity_frequency = profile.activity_count / months_active

        # Determine evolution trajectory
        profile.evolution_trajectory = self._classify_evolution(profile.activity_dates)

        # Calculate confidence
        profile.confidence = min(1.0, len(profile.activity_dates) / 10.0)

        # Determine if active
        if profile.last_observed:
            days_since_last = (datetime.utcnow() - profile.last_observed).days
            profile.is_active = days_since_last < 90

        return profile

    def build_threat_timeline(self, threat_id: str) -> ThreatTimeline:
        """Build historical timeline for threat entity."""
        timeline = ThreatTimeline(threat_id)

        # Collect events from IOC memory
        if threat_id in self.memory.ioc_memory:
            ioc_mem = self.memory.ioc_memory[threat_id]
            for occurrence in ioc_mem.occurrences:
                timeline.events.append((occurrence.date, "ioc_observation", occurrence.context))

        # Collect events from campaign memory
        elif threat_id in self.memory.campaign_memory:
            campaign_mem = self.memory.campaign_memory[threat_id]
            for activity in campaign_mem.activities:
                timeline.events.append((activity.date, "campaign_activity", activity.activity_type))

        if not timeline.events:
            return timeline

        # Sort events by date
        timeline.events = sorted(timeline.events, key=lambda x: x[0])

        # Calculate timeline metrics
        first_date = timeline.events[0][0]
        last_date = timeline.events[-1][0]
        timeline.timeline_length_days = (last_date - first_date).days + 1
        timeline.event_density = len(timeline.events) / max(1, timeline.timeline_length_days)

        # Identify dormancy periods
        timeline.dormancy_periods = self._identify_dormancy(timeline.events)
        timeline.resurgence_count = len(timeline.dormancy_periods)

        # Calculate predictability
        timeline.predictability_score = self._calculate_predictability(timeline.events)

        return timeline

    # ============================================================
    # STATISTICAL BASELINE CALCULATION
    # ============================================================

    def calculate_ioc_lifetime_baseline(self) -> StatisticalBaseline:
        """Calculate baseline IOC lifetime across all observations."""
        baseline = StatisticalBaseline("ioc_lifetime")

        for ioc_id, ioc_mem in self.memory.ioc_memory.items():
            if ioc_mem.first_observed and ioc_mem.last_observed:
                lifetime_days = (ioc_mem.last_observed - ioc_mem.first_observed).days
                baseline.observations.append(float(lifetime_days))

        return self._finalize_baseline(baseline)

    def calculate_campaign_duration_baseline(self) -> StatisticalBaseline:
        """Calculate baseline campaign duration."""
        baseline = StatisticalBaseline("campaign_duration")

        for campaign_id, campaign_mem in self.memory.campaign_memory.items():
            if campaign_mem.first_observed and campaign_mem.last_observed:
                duration_days = (campaign_mem.last_observed - campaign_mem.first_observed).days
                baseline.observations.append(float(duration_days))

        return self._finalize_baseline(baseline)

    def calculate_exposure_frequency_baseline(self) -> StatisticalBaseline:
        """Calculate baseline asset exposure frequency."""
        baseline = StatisticalBaseline("exposure_frequency")

        for asset_id, asset_mem in self.memory.asset_memory.items():
            if asset_mem.first_exposure and asset_mem.last_exposure:
                days_active = (asset_mem.last_exposure - asset_mem.first_exposure).days + 1
                months_active = max(1, days_active / 30.0)
                frequency = asset_mem.exposure_count / months_active
                baseline.observations.append(frequency)

        return self._finalize_baseline(baseline)

    def _finalize_baseline(self, baseline: StatisticalBaseline) -> StatisticalBaseline:
        """Finalize baseline calculations."""
        if not baseline.observations:
            return baseline

        baseline.samples_count = len(baseline.observations)
        baseline.mean = mean(baseline.observations)
        baseline.median = median(baseline.observations)
        baseline.min_value = min(baseline.observations)
        baseline.max_value = max(baseline.observations)

        if len(baseline.observations) > 1:
            baseline.stddev = stdev(baseline.observations)
        else:
            baseline.stddev = 0.0

        # Calculate percentiles
        sorted_obs = sorted(baseline.observations)
        baseline.percentile_25 = sorted_obs[int(len(sorted_obs) * 0.25)]
        baseline.percentile_75 = sorted_obs[int(len(sorted_obs) * 0.75)]

        # Normal range: mean ± 1 stddev
        baseline.normal_range = (
            max(0, baseline.mean - baseline.stddev),
            baseline.mean + baseline.stddev
        )

        return baseline

    # ============================================================
    # CONTEXTUAL RISK SCORING
    # ============================================================

    def build_risk_context(self, entity_id: str) -> RiskContext:
        """Build contextual risk factors for entity."""
        context = RiskContext(entity_id)

        # Check in IOC memory
        ioc_mem = self.memory.ioc_memory.get(entity_id)
        if ioc_mem:
            # Count associated threats
            context.threat_actor_count = len(ioc_mem.associated_actors)
            context.campaign_count = len(ioc_mem.associated_campaigns)
            context.exposure_recurrence = ioc_mem.reuse_frequency

            # Historical risk score
            base_score = min(1.0, ioc_mem.occurrence_count / 20.0)
            actor_multiplier = 1.0 + (context.threat_actor_count * 0.1)
            context.historical_risk_score = min(1.0, base_score * actor_multiplier)

        # Check in asset memory
        asset_mem = self.memory.asset_memory.get(entity_id)
        if asset_mem:
            context.vulnerability_count = asset_mem.exposure_count
            context.baseline_incident_rate = asset_mem.exposure_frequency
            context.historical_risk_score = asset_mem.remediation_success_rate

            # Calculate confidence bands (±1 stddev)
            context.upper_confidence_band = asset_mem.exposure_frequency * 1.5
            context.lower_confidence_band = max(0, asset_mem.exposure_frequency * 0.5)

        # Determine contextual severity
        context.contextual_severity = self._classify_contextual_severity(context)

        return context

    def _classify_contextual_severity(self, context: RiskContext) -> str:
        """Classify severity based on historical context."""
        score = context.historical_risk_score

        if context.threat_actor_count > 3 or context.campaign_count > 5:
            score += 0.3

        if context.exposure_recurrence > 0.7:
            score += 0.2

        if score >= 0.8:
            return "critical"
        elif score >= 0.6:
            return "high"
        elif score >= 0.4:
            return "medium"
        else:
            return "low"

    # ============================================================
    # ANOMALY AND OUTLIER DETECTION
    # ============================================================

    def detect_historical_anomalies(
        self,
        stddev_threshold: float = 2.0,
    ) -> Dict[str, List[Tuple[str, float]]]:
        """Detect historical anomalies vs baselines."""
        anomalies = {
            "ioc_anomalies": [],
            "campaign_anomalies": [],
            "exposure_anomalies": [],
        }

        # IOC lifetime anomalies
        ioc_baseline = self.calculate_ioc_lifetime_baseline()
        for ioc_id, ioc_mem in self.memory.ioc_memory.items():
            if ioc_mem.first_observed and ioc_mem.last_observed:
                lifetime = (ioc_mem.last_observed - ioc_mem.first_observed).days
                z_score = (lifetime - ioc_baseline.mean) / max(0.1, ioc_baseline.stddev)
                if abs(z_score) > stddev_threshold:
                    anomalies["ioc_anomalies"].append((ioc_id, z_score))

        # Campaign duration anomalies
        campaign_baseline = self.calculate_campaign_duration_baseline()
        for campaign_id, campaign_mem in self.memory.campaign_memory.items():
            if campaign_mem.first_observed and campaign_mem.last_observed:
                duration = (campaign_mem.last_observed - campaign_mem.first_observed).days
                z_score = (duration - campaign_baseline.mean) / max(0.1, campaign_baseline.stddev)
                if abs(z_score) > stddev_threshold:
                    anomalies["campaign_anomalies"].append((campaign_id, z_score))

        # Exposure frequency anomalies
        exposure_baseline = self.calculate_exposure_frequency_baseline()
        for asset_id, asset_mem in self.memory.asset_memory.items():
            if asset_mem.first_exposure and asset_mem.last_exposure:
                freq = asset_mem.exposure_frequency
                z_score = (freq - exposure_baseline.mean) / max(0.1, exposure_baseline.stddev)
                if abs(z_score) > stddev_threshold:
                    anomalies["exposure_anomalies"].append((asset_id, z_score))

        return anomalies

    # ============================================================
    # UTILITY METHODS
    # ============================================================

    def _classify_evolution(self, activity_dates: List[datetime]) -> str:
        """Classify actor evolution trajectory."""
        if len(activity_dates) < 2:
            return "unknown"

        recent_count = len([d for d in activity_dates if (datetime.utcnow() - d).days < 180])
        old_count = len([d for d in activity_dates if (datetime.utcnow() - d).days >= 180])

        if recent_count > old_count * 1.5:
            return "expanding"
        elif recent_count < old_count * 0.67:
            return "declining"
        else:
            return "consolidating"

    def _identify_dormancy(self, events: List[Tuple[datetime, str, str]]) -> List[Tuple[datetime, datetime]]:
        """Identify dormancy periods (gaps between activities)."""
        if len(events) < 2:
            return []

        dormancy_periods = []
        threshold_days = 30

        for i in range(1, len(events)):
            gap = (events[i][0] - events[i-1][0]).days
            if gap > threshold_days:
                dormancy_periods.append((events[i-1][0], events[i][0]))

        return dormancy_periods

    def _calculate_predictability(self, events: List[Tuple[datetime, str, str]]) -> float:
        """Calculate event predictability (0.0-1.0)."""
        if len(events) < 2:
            return 0.0

        # Calculate inter-event times
        inter_event_times = []
        for i in range(1, len(events)):
            delta = (events[i][0] - events[i-1][0]).days
            inter_event_times.append(delta)

        if not inter_event_times:
            return 0.0

        # Low variation = predictable
        avg_interval = mean(inter_event_times)
        var = stdev(inter_event_times) if len(inter_event_times) > 1 else 0
        cv = var / avg_interval if avg_interval > 0 else 1.0

        # Coefficient of variation: 0 = perfectly predictable, >1 = unpredictable
        predictability = 1.0 / (1.0 + cv)

        return min(1.0, predictability)

    # ============================================================
    # BATCH CONTEXT BUILDING
    # ============================================================

    def build_all_contexts(self) -> Dict[str, Any]:
        """Build contexts for all entities."""
        return {
            "actor_profiles": {
                actor_id: self.build_actor_profile(actor_id, actor_id)
                for actor_id in self.memory.campaign_memory.keys()
            },
            "threat_timelines": {
                threat_id: self.build_threat_timeline(threat_id)
                for threat_id in list(self.memory.ioc_memory.keys()) + list(self.memory.campaign_memory.keys())
            },
            "risk_contexts": {
                entity_id: self.build_risk_context(entity_id)
                for entity_id in list(self.memory.ioc_memory.keys()) + list(self.memory.asset_memory.keys())
            },
            "statistical_baselines": {
                "ioc_lifetime": self.calculate_ioc_lifetime_baseline(),
                "campaign_duration": self.calculate_campaign_duration_baseline(),
                "exposure_frequency": self.calculate_exposure_frequency_baseline(),
            },
        }

    def get_historical_summary(self) -> Dict[str, Any]:
        """Get summary of historical threat landscape."""
        return {
            "total_entities_tracked": (
                len(self.memory.ioc_memory) +
                len(self.memory.campaign_memory) +
                len(self.memory.asset_memory)
            ),
            "active_campaigns": len(self.memory.get_active_campaigns()),
            "exposed_assets": len(self.memory.get_exposed_assets()),
            "recurring_iocs": len(self.memory.get_recurring_iocs()),
            "average_actor_activity_frequency": self._calculate_avg_frequency(),
            "historical_anomalies": self.detect_historical_anomalies(),
        }

    def _calculate_avg_frequency(self) -> float:
        """Calculate average activity frequency across all campaigns."""
        frequencies = []
        for campaign_mem in self.memory.campaign_memory.values():
            if campaign_mem.first_observed and campaign_mem.last_observed:
                days = (campaign_mem.last_observed - campaign_mem.first_observed).days + 1
                months = max(1, days / 30.0)
                frequencies.append(campaign_mem.activity_count / months)

        return mean(frequencies) if frequencies else 0.0

    def export_context_as_json(self) -> Dict[str, Any]:
        """Export historical context for reporting."""
        contexts = self.build_all_contexts()
        exported = {}

        # Export actor profiles
        if "actor_profiles" in contexts:
            exported["actors"] = {}
            for actor_id, profile in contexts["actor_profiles"].items():
                exported["actors"][actor_id] = {
                    "name": profile.actor_name,
                    "first_observed": profile.first_observed.isoformat() if profile.first_observed else None,
                    "last_observed": profile.last_observed.isoformat() if profile.last_observed else None,
                    "activity_count": profile.activity_count,
                    "avg_frequency": round(profile.avg_activity_frequency, 2),
                    "evolution": profile.evolution_trajectory,
                    "is_active": profile.is_active,
                    "confidence": round(profile.confidence, 3),
                }

        # Export risk contexts
        if "risk_contexts" in contexts:
            exported["risk_analysis"] = {}
            for entity_id, context in contexts["risk_contexts"].items():
                exported["risk_analysis"][entity_id] = {
                    "historical_risk_score": round(context.historical_risk_score, 3),
                    "threat_actor_count": context.threat_actor_count,
                    "campaign_count": context.campaign_count,
                    "vulnerability_count": context.vulnerability_count,
                    "exposure_recurrence": round(context.exposure_recurrence, 3),
                    "contextual_severity": context.contextual_severity,
                    "baseline_incident_rate": round(context.baseline_incident_rate, 3),
                }

        # Export statistical baselines
        if "statistical_baselines" in contexts:
            exported["baselines"] = {}
            for baseline_type, baseline in contexts["statistical_baselines"].items():
                exported["baselines"][baseline_type] = {
                    "mean": round(baseline.mean, 2),
                    "median": round(baseline.median, 2),
                    "stddev": round(baseline.stddev, 2),
                    "min": round(baseline.min_value, 2),
                    "max": round(baseline.max_value, 2),
                    "samples": baseline.samples_count,
                }

        return exported
