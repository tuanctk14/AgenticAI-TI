"""
core/trend_analysis.py - Threat Trend Analysis Engine

Detects and analyzes threat trends:
- IOC activity trends (rising/stable/declining)
- Campaign activity surge detection
- Technique adoption trends
- Target selection shifts
- Threat actor emergence and retirement
- Temporal pattern analysis
"""

from typing import Dict, List, Set, Optional, Any, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import math

from core.threat_memory import ThreatMemoryEngine
from core.pattern_detection import PatternDetectionEngine
from core.historical_context import HistoricalContextEngine


class TrendAnalyzer:
    """Engine for analyzing threat landscape trends."""

    def __init__(
        self,
        memory_engine: ThreatMemoryEngine,
        pattern_engine: PatternDetectionEngine,
        context_engine: HistoricalContextEngine,
    ):
        """Initialize trend analyzer.

        Args:
            memory_engine: Threat memory engine
            pattern_engine: Pattern detection engine
            context_engine: Historical context engine
        """
        self.memory = memory_engine
        self.patterns = pattern_engine
        self.context = context_engine

    def analyze_ioc_trends(self, days_window: int = 90) -> List[Dict[str, Any]]:
        """Analyze IOC activity trends over time window.

        Args:
            days_window: Number of days to analyze

        Returns:
            List of IOC trends with rising/stable/declining classification
        """
        trends = []
        cutoff_date = datetime.utcnow() - timedelta(days=days_window)

        for ioc_id, ioc_mem in self.memory.ioc_memory.items():
            # Count occurrences in first and second half of window
            first_half_count = 0
            second_half_count = 0

            for occurrence in ioc_mem.occurrences:
                if occurrence.date < cutoff_date:
                    continue
                midpoint = cutoff_date + timedelta(days=days_window / 2)
                if occurrence.date < midpoint:
                    first_half_count += 1
                else:
                    second_half_count += 1

            if first_half_count == 0 and second_half_count == 0:
                continue

            # Determine trend
            if first_half_count == 0:
                trend_class = "emerging"
            elif second_half_count == 0:
                trend_class = "declining"
            else:
                ratio = second_half_count / first_half_count
                if ratio > 1.5:
                    trend_class = "rising"
                elif ratio < 0.67:
                    trend_class = "declining"
                else:
                    trend_class = "stable"

            trends.append({
                "ioc_id": ioc_id,
                "ioc_value": ioc_mem.ioc_value,
                "trend": trend_class,
                "first_half_count": first_half_count,
                "second_half_count": second_half_count,
                "total_occurrences": ioc_mem.occurrence_count,
                "activity_change_percent": (
                    ((second_half_count - first_half_count) / first_half_count * 100)
                    if first_half_count > 0 else 0.0
                ),
            })

        return sorted(trends, key=lambda x: x["total_occurrences"], reverse=True)

    def analyze_campaign_activity_surge(self, threshold: float = 1.5) -> List[Dict[str, Any]]:
        """Detect campaign activity surges.

        Args:
            threshold: Surge multiplier (e.g., 1.5 = 50% increase)

        Returns:
            List of campaigns with activity surge detection
        """
        surges = []

        for campaign_id, camp_mem in self.memory.campaign_memory.items():
            if len(camp_mem.activities) < 4:
                continue

            # Compare early and late activity rates
            mid_idx = len(camp_mem.activities) // 2
            early_activities = camp_mem.activities[:mid_idx]
            late_activities = camp_mem.activities[mid_idx:]

            if not early_activities or not late_activities:
                continue

            # Calculate activity rates
            early_timespan = (early_activities[-1].date - early_activities[0].date).days
            late_timespan = (late_activities[-1].date - late_activities[0].date).days

            early_rate = len(early_activities) / max(early_timespan, 1)
            late_rate = len(late_activities) / max(late_timespan, 1)

            if early_rate == 0:
                surge_ratio = float('inf') if late_rate > 0 else 1.0
            else:
                surge_ratio = late_rate / early_rate

            if surge_ratio >= threshold:
                surges.append({
                    "campaign_id": campaign_id,
                    "campaign_name": camp_mem.campaign_name,
                    "early_activity_rate": early_rate,
                    "late_activity_rate": late_rate,
                    "surge_ratio": surge_ratio,
                    "is_surge": surge_ratio >= threshold,
                    "total_activities": len(camp_mem.activities),
                })

        return sorted(surges, key=lambda x: x["surge_ratio"], reverse=True)

    def analyze_technique_adoption_trends(self, days_window: int = 90) -> List[Dict[str, Any]]:
        """Analyze technique adoption trends.

        Args:
            days_window: Number of days to analyze

        Returns:
            List of techniques with adoption trend data
        """
        trends = []
        cutoff_date = datetime.utcnow() - timedelta(days=days_window)
        midpoint = cutoff_date + timedelta(days=days_window / 2)

        technique_usage = defaultdict(lambda: {"first_half": 0, "second_half": 0})

        for campaign_id, camp_mem in self.memory.campaign_memory.items():
            if camp_mem.first_observed < cutoff_date:
                continue

            for technique in camp_mem.techniques_evolution:
                if camp_mem.first_observed < midpoint:
                    technique_usage[technique]["first_half"] += 1
                else:
                    technique_usage[technique]["second_half"] += 1

        for technique, counts in technique_usage.items():
            first_half = counts["first_half"]
            second_half = counts["second_half"]

            if first_half == 0 and second_half == 0:
                continue

            if first_half == 0:
                trend_class = "emerging"
            elif second_half == 0:
                trend_class = "declining"
            else:
                ratio = second_half / first_half
                if ratio > 1.5:
                    trend_class = "rising"
                elif ratio < 0.67:
                    trend_class = "declining"
                else:
                    trend_class = "stable"

            trends.append({
                "technique": technique,
                "trend": trend_class,
                "first_half_usage": first_half,
                "second_half_usage": second_half,
                "total_usage": first_half + second_half,
                "adoption_rate_change": (
                    ((second_half - first_half) / first_half * 100)
                    if first_half > 0 else 0.0
                ),
            })

        return sorted(trends, key=lambda x: x["total_usage"], reverse=True)

    def analyze_target_preference_shift(self, days_window: int = 90) -> List[Dict[str, Any]]:
        """Analyze shifts in target preferences.

        Args:
            days_window: Number of days to analyze

        Returns:
            List of target sectors with preference change data
        """
        shifts = []
        cutoff_date = datetime.utcnow() - timedelta(days=days_window)
        midpoint = cutoff_date + timedelta(days=days_window / 2)

        sector_map = {
            "finance": ["bank", "fin", "exchange", "payment"],
            "healthcare": ["hospital", "pharma", "clinic", "medical"],
            "energy": ["power", "oil", "gas", "utility"],
            "technology": ["tech", "software", "cloud"],
        }

        sector_usage = defaultdict(lambda: {"first_half": 0, "second_half": 0})

        for campaign_id, camp_mem in self.memory.campaign_memory.items():
            if camp_mem.first_observed < cutoff_date:
                continue

            for target in camp_mem.current_targets:
                target_lower = target.lower()
                for sector, keywords in sector_map.items():
                    if any(kw in target_lower for kw in keywords):
                        if camp_mem.first_observed < midpoint:
                            sector_usage[sector]["first_half"] += 1
                        else:
                            sector_usage[sector]["second_half"] += 1

        for sector, counts in sector_usage.items():
            first_half = counts["first_half"]
            second_half = counts["second_half"]

            if first_half == 0 and second_half == 0:
                continue

            if first_half == 0:
                preference_shift = "emerging"
            elif second_half == 0:
                preference_shift = "declining"
            else:
                ratio = second_half / first_half
                if ratio > 1.5:
                    preference_shift = "increasing"
                elif ratio < 0.67:
                    preference_shift = "decreasing"
                else:
                    preference_shift = "stable"

            shifts.append({
                "sector": sector,
                "preference_shift": preference_shift,
                "first_half_targets": first_half,
                "second_half_targets": second_half,
                "total_targets": first_half + second_half,
                "change_percent": (
                    ((second_half - first_half) / first_half * 100)
                    if first_half > 0 else 0.0
                ),
            })

        return sorted(shifts, key=lambda x: x["total_targets"], reverse=True)

    def detect_emerging_actors(self, recent_days: int = 60) -> List[Dict[str, Any]]:
        """Detect recently emerged threat actors.

        Args:
            recent_days: Days to consider as "recent"

        Returns:
            List of emerging actors with activity metrics
        """
        emerging = []
        cutoff_date = datetime.utcnow() - timedelta(days=recent_days)

        actors = set()
        for camp_mem in self.memory.campaign_memory.values():
            actors.update(camp_mem.attributed_actors)

        for actor_id in actors:
            actor_campaigns = []
            for campaign_id, camp_mem in self.memory.campaign_memory.items():
                if actor_id in camp_mem.attributed_actors:
                    actor_campaigns.append((campaign_id, camp_mem))

            if not actor_campaigns:
                continue

            # Check if actor is recent
            first_observed = min(
                (c[1].first_observed for c in actor_campaigns if c[1].first_observed),
                default=None
            )

            if first_observed and first_observed > cutoff_date:
                recent_campaigns = sum(
                    1 for _, c in actor_campaigns if c.first_observed and c.first_observed > cutoff_date
                )

                emerging.append({
                    "actor_id": actor_id,
                    "first_observed": first_observed,
                    "recent_campaigns": recent_campaigns,
                    "total_campaigns": len(actor_campaigns),
                    "days_since_emergence": (datetime.utcnow() - first_observed).days,
                    "emergence_velocity": recent_campaigns / max(
                        (datetime.utcnow() - first_observed).days, 1
                    ),
                })

        return sorted(emerging, key=lambda x: x["days_since_emergence"])

    def detect_dormant_actors(self, dormant_days: int = 180) -> List[Dict[str, Any]]:
        """Detect dormant threat actors (inactive for extended period).

        Args:
            dormant_days: Days of inactivity threshold

        Returns:
            List of dormant actors with last activity dates
        """
        dormant = []
        cutoff_date = datetime.utcnow() - timedelta(days=dormant_days)

        actors = set()
        for camp_mem in self.memory.campaign_memory.values():
            actors.update(camp_mem.attributed_actors)

        for actor_id in actors:
            last_observed = None
            total_campaigns = 0

            for campaign_id, camp_mem in self.memory.campaign_memory.items():
                if actor_id in camp_mem.attributed_actors:
                    total_campaigns += 1
                    if camp_mem.last_observed:
                        if not last_observed or camp_mem.last_observed > last_observed:
                            last_observed = camp_mem.last_observed

            if last_observed and last_observed < cutoff_date:
                dormant.append({
                    "actor_id": actor_id,
                    "last_observed": last_observed,
                    "days_dormant": (datetime.utcnow() - last_observed).days,
                    "total_campaigns": total_campaigns,
                })

        return sorted(dormant, key=lambda x: x["days_dormant"], reverse=True)

    def analyze_threat_tempo_global(self, window_days: int = 90) -> Dict[str, Any]:
        """Analyze overall threat tempo across landscape.

        Args:
            window_days: Analysis window in days

        Returns:
            Dict with global threat tempo metrics
        """
        cutoff_date = datetime.utcnow() - timedelta(days=window_days)
        midpoint = cutoff_date + timedelta(days=window_days / 2)

        first_half_activity = 0
        second_half_activity = 0

        for campaign_id, camp_mem in self.memory.campaign_memory.items():
            for activity in camp_mem.activities:
                if activity.date < cutoff_date:
                    continue
                if activity.date < midpoint:
                    first_half_activity += 1
                else:
                    second_half_activity += 1

        total_activity = first_half_activity + second_half_activity

        if total_activity == 0:
            return {
                "window_days": window_days,
                "total_activity_events": 0,
                "first_half_events": 0,
                "second_half_events": 0,
                "activity_trend": "no_data",
                "tempo_classification": "dormant",
            }

        if first_half_activity == 0:
            activity_ratio = float('inf')
            trend = "emerging"
        else:
            activity_ratio = second_half_activity / first_half_activity
            if activity_ratio > 1.5:
                trend = "accelerating"
            elif activity_ratio < 0.67:
                trend = "decelerating"
            else:
                trend = "stable"

        # Classify overall tempo
        avg_daily_activity = total_activity / window_days
        if avg_daily_activity > 10:
            tempo = "very_active"
        elif avg_daily_activity > 5:
            tempo = "active"
        elif avg_daily_activity > 1:
            tempo = "moderate"
        else:
            tempo = "low"

        return {
            "window_days": window_days,
            "total_activity_events": total_activity,
            "first_half_events": first_half_activity,
            "second_half_events": second_half_activity,
            "activity_ratio": activity_ratio if activity_ratio != float('inf') else -1.0,
            "activity_trend": trend,
            "avg_daily_events": avg_daily_activity,
            "tempo_classification": tempo,
        }

    def detect_anomalous_activity_surge(self, threshold: float = 3.0) -> List[Dict[str, Any]]:
        """Detect anomalous activity surges (Z-score > threshold).

        Args:
            threshold: Z-score threshold for anomaly

        Returns:
            List of anomalous activity periods
        """
        anomalies = []

        # Collect daily activity counts
        daily_activity = defaultdict(int)
        for campaign_id, camp_mem in self.memory.campaign_memory.items():
            for activity in camp_mem.activities:
                date_key = activity.date.date()
                daily_activity[date_key] += 1

        if len(daily_activity) < 5:
            return anomalies

        # Calculate statistics
        activities = list(daily_activity.values())
        mean = sum(activities) / len(activities)
        variance = sum((x - mean) ** 2 for x in activities) / len(activities)
        stddev = math.sqrt(variance) if variance > 0 else 0.0

        if stddev == 0:
            return anomalies

        # Find anomalies
        for date_key, count in sorted(daily_activity.items()):
            z_score = (count - mean) / stddev
            if abs(z_score) >= threshold:
                anomalies.append({
                    "date": date_key,
                    "activity_count": count,
                    "z_score": z_score,
                    "expected_count": mean,
                    "is_surge": z_score > threshold,
                    "is_drop": z_score < -threshold,
                })

        return sorted(anomalies, key=lambda x: abs(x["z_score"]), reverse=True)

    def get_trend_summary(self) -> Dict[str, Any]:
        """Get comprehensive trend summary.

        Returns:
            Dict with all trend analysis results
        """
        return {
            "ioc_trends": self.analyze_ioc_trends(days_window=90),
            "campaign_surges": self.analyze_campaign_activity_surge(),
            "technique_trends": self.analyze_technique_adoption_trends(days_window=90),
            "target_shifts": self.analyze_target_preference_shift(days_window=90),
            "emerging_actors": self.detect_emerging_actors(recent_days=60),
            "dormant_actors": self.detect_dormant_actors(dormant_days=180),
            "global_tempo": self.analyze_threat_tempo_global(window_days=90),
            "anomalous_activity": self.detect_anomalous_activity_surge(threshold=2.0),
        }
