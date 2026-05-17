"""
core/pattern_detection.py - Recurrence Pattern Detection Engine

Analyzes historical observations to detect patterns:
- IOC reuse frequency and cycles
- Campaign activity patterns
- Asset exposure windows
- Infrastructure persistence patterns
- Exploitation technique adoption

Enables predictive threat intelligence and anomaly detection.
"""

from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timedelta
from statistics import mean, stdev
import math

from core.threat_memory import ThreatMemoryEngine


# ============================================================
# PATTERN DETECTION MODELS
# ============================================================

class IOCReusagePattern:
    """IOC reuse pattern analysis."""

    def __init__(self, ioc_id: str):
        self.ioc_id = ioc_id
        self.occurrence_dates: List[datetime] = []
        self.inter_event_times: List[int] = []  # days between occurrences
        self.average_interval: float = 0.0
        self.interval_stddev: float = 0.0
        self.reuse_frequency: float = 0.0  # occurrences per month
        self.activity_trend: str = "unknown"
        self.next_reuse_likelihood: float = 0.0
        self.predicted_next_use: Optional[datetime] = None


class CampaignActivityPattern:
    """Campaign activity pattern analysis."""

    def __init__(self, campaign_id: str):
        self.campaign_id = campaign_id
        self.activity_dates: List[datetime] = []
        self.activity_intervals: List[int] = []  # days between activities
        self.average_interval: float = 0.0
        self.activity_frequency: float = 0.0  # activities per month
        self.activity_pattern: str = "unknown"  # continuous, intermittent, seasonal
        self.peak_periods: List[str] = []  # months with high activity
        self.next_activity_likelihood: float = 0.0
        self.predicted_next_activity: Optional[datetime] = None


class AssetExposurePattern:
    """Asset exposure pattern analysis."""

    def __init__(self, asset_id: str):
        self.asset_id = asset_id
        self.exposure_dates: List[datetime] = []
        self.exposure_intervals: List[int] = []  # days between exposures
        self.average_interval: float = 0.0
        self.exposure_frequency: float = 0.0  # exposures per month
        self.exposure_trend: str = "unknown"
        self.high_risk_windows: List[Tuple[str, str]] = []  # (start_month, end_month)
        self.next_exposure_likelihood: float = 0.0
        self.predicted_next_exposure: Optional[datetime] = None


# ============================================================
# PATTERN DETECTION ENGINE
# ============================================================

class PatternDetectionEngine:
    """
    Detect recurrence patterns from threat memory.

    Analyzes historical observations to:
    - Identify cyclical patterns
    - Calculate likelihoods
    - Predict future occurrences
    - Detect anomalies
    """

    def __init__(self, memory_engine: ThreatMemoryEngine):
        """Initialize with memory reference."""
        self.memory = memory_engine

    # ============================================================
    # IOC PATTERN DETECTION
    # ============================================================

    def detect_ioc_reusage_pattern(self, ioc_id: str) -> Optional[IOCReusagePattern]:
        """Detect IOC reuse pattern from historical observations."""
        memory = self.memory.get_ioc_memory(ioc_id)
        if not memory or not memory.occurrences:
            return None

        pattern = IOCReusagePattern(ioc_id)

        # Collect occurrence dates
        pattern.occurrence_dates = sorted([o.date for o in memory.occurrences])

        if len(pattern.occurrence_dates) < 2:
            return pattern

        # Calculate inter-event times
        for i in range(1, len(pattern.occurrence_dates)):
            delta = (pattern.occurrence_dates[i] - pattern.occurrence_dates[i-1]).days
            pattern.inter_event_times.append(delta)

        # Calculate statistics
        if pattern.inter_event_times:
            pattern.average_interval = mean(pattern.inter_event_times)
            if len(pattern.inter_event_times) > 1:
                pattern.interval_stddev = stdev(pattern.inter_event_times)

        # Calculate reuse frequency
        first_date = pattern.occurrence_dates[0]
        last_date = pattern.occurrence_dates[-1]
        months_active = (last_date - first_date).days / 30.0
        if months_active > 0:
            pattern.reuse_frequency = len(pattern.occurrence_dates) / months_active

        # Determine trend
        pattern.activity_trend = self._classify_trend(pattern.occurrence_dates)

        # Calculate next reuse likelihood
        pattern.next_reuse_likelihood = self._calculate_likelihood(
            pattern.reuse_frequency,
            pattern.activity_trend
        )

        # Predict next occurrence
        pattern.predicted_next_use = self._predict_next_event(
            pattern.occurrence_dates,
            pattern.average_interval
        )

        return pattern

    def detect_campaign_activity_pattern(self, campaign_id: str) -> Optional[CampaignActivityPattern]:
        """Detect campaign activity pattern from historical activities."""
        memory = self.memory.get_campaign_memory(campaign_id)
        if not memory or not memory.activities:
            return None

        pattern = CampaignActivityPattern(campaign_id)

        # Collect activity dates
        pattern.activity_dates = sorted([a.date for a in memory.activities])

        if len(pattern.activity_dates) < 2:
            return pattern

        # Calculate inter-activity times
        for i in range(1, len(pattern.activity_dates)):
            delta = (pattern.activity_dates[i] - pattern.activity_dates[i-1]).days
            pattern.activity_intervals.append(delta)

        # Calculate statistics
        if pattern.activity_intervals:
            pattern.average_interval = mean(pattern.activity_intervals)

        # Calculate activity frequency
        first_date = pattern.activity_dates[0]
        last_date = pattern.activity_dates[-1]
        months_active = (last_date - first_date).days / 30.0
        if months_active > 0:
            pattern.activity_frequency = len(pattern.activity_dates) / months_active

        # Classify activity pattern
        pattern.activity_pattern = self._classify_activity_pattern(pattern.activity_intervals)

        # Identify peak periods
        pattern.peak_periods = self._identify_peak_periods(pattern.activity_dates)

        # Calculate next activity likelihood
        pattern.next_activity_likelihood = self._calculate_likelihood(
            pattern.activity_frequency,
            self._classify_trend(pattern.activity_dates)
        )

        # Predict next activity
        pattern.predicted_next_activity = self._predict_next_event(
            pattern.activity_dates,
            pattern.average_interval
        )

        return pattern

    def detect_asset_exposure_pattern(self, asset_id: str) -> Optional[AssetExposurePattern]:
        """Detect asset exposure pattern from historical exposures."""
        memory = self.memory.get_asset_memory(asset_id)
        if not memory or not memory.exposures:
            return None

        pattern = AssetExposurePattern(asset_id)

        # Collect exposure dates
        pattern.exposure_dates = sorted([e.date for e in memory.exposures])

        if len(pattern.exposure_dates) < 2:
            return pattern

        # Calculate inter-exposure times
        for i in range(1, len(pattern.exposure_dates)):
            delta = (pattern.exposure_dates[i] - pattern.exposure_dates[i-1]).days
            pattern.exposure_intervals.append(delta)

        # Calculate statistics
        if pattern.exposure_intervals:
            pattern.average_interval = mean(pattern.exposure_intervals)

        # Calculate exposure frequency
        first_date = pattern.exposure_dates[0]
        last_date = pattern.exposure_dates[-1]
        months_active = (last_date - first_date).days / 30.0
        if months_active > 0:
            pattern.exposure_frequency = len(pattern.exposure_dates) / months_active

        # Determine trend
        pattern.exposure_trend = self._classify_trend(pattern.exposure_dates)

        # Identify high-risk windows
        pattern.high_risk_windows = self._identify_risk_windows(pattern.exposure_dates)

        # Calculate next exposure likelihood
        pattern.next_exposure_likelihood = self._calculate_likelihood(
            pattern.exposure_frequency,
            pattern.exposure_trend
        )

        # Predict next exposure
        pattern.predicted_next_exposure = self._predict_next_event(
            pattern.exposure_dates,
            pattern.average_interval
        )

        return pattern

    # ============================================================
    # PATTERN ANALYSIS UTILITIES
    # ============================================================

    def _classify_trend(self, dates: List[datetime]) -> str:
        """Classify trend as rising, stable, or declining."""
        if len(dates) < 2:
            return "unknown"

        now = datetime.utcnow()
        recent_days = 30
        recent_events = [d for d in dates if (now - d).days <= recent_days]

        if not recent_events:
            return "declining"

        recent_rate = len(recent_events) / recent_days
        overall_rate = len(dates) / max(1, (now - dates[0]).days / 30.0)

        if recent_rate > overall_rate * 1.5:
            return "rising"
        elif recent_rate < overall_rate * 0.5:
            return "declining"
        else:
            return "stable"

    def _classify_activity_pattern(self, intervals: List[int]) -> str:
        """Classify activity pattern as continuous, intermittent, or seasonal."""
        if not intervals:
            return "unknown"

        avg_interval = mean(intervals)
        stddev = stdev(intervals) if len(intervals) > 1 else 0

        # Coefficient of variation
        cv = stddev / avg_interval if avg_interval > 0 else 0

        if avg_interval < 7:  # Less than weekly
            return "continuous"
        elif cv > 1.0:  # High variability (seasonal)
            return "seasonal"
        else:
            return "intermittent"

    def _identify_peak_periods(self, dates: List[datetime]) -> List[str]:
        """Identify peak activity months."""
        if not dates:
            return []

        month_counts = {}
        for date in dates:
            month_key = date.strftime("%Y-%m")
            month_counts[month_key] = month_counts.get(month_key, 0) + 1

        if not month_counts:
            return []

        # Find months above average
        avg_count = mean(month_counts.values())
        peak_months = [m for m, c in month_counts.items() if c > avg_count]

        return sorted(peak_months)

    def _identify_risk_windows(self, dates: List[datetime]) -> List[Tuple[str, str]]:
        """Identify high-risk exposure windows."""
        if len(dates) < 3:
            return []

        # Group by month
        month_counts = {}
        for date in dates:
            month_key = date.strftime("%m")  # Month of year
            month_counts[month_key] = month_counts.get(month_key, 0) + 1

        if not month_counts:
            return []

        # Find high-risk months
        avg_count = mean(month_counts.values())
        high_risk_months = sorted([int(m) for m, c in month_counts.items() if c > avg_count])

        if not high_risk_months:
            return []

        # Group consecutive months
        windows = []
        start_month = high_risk_months[0]
        end_month = high_risk_months[0]

        for month in high_risk_months[1:]:
            if month == end_month + 1 or month == end_month:
                end_month = month
            else:
                windows.append((f"{start_month:02d}", f"{end_month:02d}"))
                start_month = month
                end_month = month

        windows.append((f"{start_month:02d}", f"{end_month:02d}"))
        return windows

    def _calculate_likelihood(self, frequency: float, trend: str) -> float:
        """Calculate likelihood score (0.0 to 1.0) based on frequency and trend."""
        # Base likelihood from frequency
        # Assume 0.5 per month is "baseline"
        base_likelihood = min(1.0, frequency / 2.0)

        # Adjust for trend
        if trend == "rising":
            trend_multiplier = 1.5
        elif trend == "stable":
            trend_multiplier = 1.0
        elif trend == "declining":
            trend_multiplier = 0.5
        else:
            trend_multiplier = 1.0

        return min(1.0, base_likelihood * trend_multiplier)

    def _predict_next_event(
        self,
        dates: List[datetime],
        avg_interval: float,
    ) -> Optional[datetime]:
        """Predict next event occurrence."""
        if not dates or avg_interval <= 0:
            return None

        last_event = dates[-1]
        days_until_next = int(round(avg_interval))
        predicted_next = last_event + timedelta(days=days_until_next)

        return predicted_next

    # ============================================================
    # BATCH PATTERN DETECTION
    # ============================================================

    def detect_all_patterns(self) -> Dict[str, Any]:
        """Detect patterns for all entities in memory."""
        results = {
            "ioc_patterns": {},
            "campaign_patterns": {},
            "asset_patterns": {},
            "total_patterns": 0,
        }

        # IOC patterns
        for ioc_id in self.memory.ioc_memory.keys():
            pattern = self.detect_ioc_reusage_pattern(ioc_id)
            if pattern:
                results["ioc_patterns"][ioc_id] = pattern
                results["total_patterns"] += 1

        # Campaign patterns
        for campaign_id in self.memory.campaign_memory.keys():
            pattern = self.detect_campaign_activity_pattern(campaign_id)
            if pattern:
                results["campaign_patterns"][campaign_id] = pattern
                results["total_patterns"] += 1

        # Asset patterns
        for asset_id in self.memory.asset_memory.keys():
            pattern = self.detect_asset_exposure_pattern(asset_id)
            if pattern:
                results["asset_patterns"][asset_id] = pattern
                results["total_patterns"] += 1

        return results

    def get_high_risk_entities(self, likelihood_threshold: float = 0.7) -> Dict[str, List[str]]:
        """Get entities with high risk (likelihood > threshold)."""
        high_risk = {
            "iocs": [],
            "campaigns": [],
            "assets": [],
        }

        # IOCs
        for ioc_id in self.memory.ioc_memory.keys():
            pattern = self.detect_ioc_reusage_pattern(ioc_id)
            if pattern and pattern.next_reuse_likelihood >= likelihood_threshold:
                high_risk["iocs"].append(ioc_id)

        # Campaigns
        for campaign_id in self.memory.campaign_memory.keys():
            pattern = self.detect_campaign_activity_pattern(campaign_id)
            if pattern and pattern.next_activity_likelihood >= likelihood_threshold:
                high_risk["campaigns"].append(campaign_id)

        # Assets
        for asset_id in self.memory.asset_memory.keys():
            pattern = self.detect_asset_exposure_pattern(asset_id)
            if pattern and pattern.next_exposure_likelihood >= likelihood_threshold:
                high_risk["assets"].append(asset_id)

        return high_risk

    def get_anomalies(self, stddev_threshold: float = 2.0) -> Dict[str, List[Tuple[str, str]]]:
        """Detect anomalies (events deviating from pattern by N standard deviations)."""
        anomalies = {
            "ioc_anomalies": [],
            "campaign_anomalies": [],
            "asset_anomalies": [],
        }

        # IOC anomalies
        for ioc_id in self.memory.ioc_memory.keys():
            pattern = self.detect_ioc_reusage_pattern(ioc_id)
            if pattern and pattern.interval_stddev > 0:
                for i in range(1, len(pattern.inter_event_times)):
                    interval = pattern.inter_event_times[i]
                    z_score = (interval - pattern.average_interval) / pattern.interval_stddev
                    if abs(z_score) > stddev_threshold:
                        anomalies["ioc_anomalies"].append((ioc_id, f"Z-score: {z_score:.2f}"))

        return anomalies

    # ============================================================
    # STATISTICS AND REPORTING
    # ============================================================

    def get_pattern_statistics(self) -> Dict[str, Any]:
        """Get overall pattern statistics."""
        ioc_patterns = list(self.memory.ioc_memory.keys())
        campaign_patterns = list(self.memory.campaign_memory.keys())
        asset_patterns = list(self.memory.asset_memory.keys())

        # Calculate average likelihoods
        ioc_likelihoods = []
        for ioc_id in ioc_patterns:
            pattern = self.detect_ioc_reusage_pattern(ioc_id)
            if pattern:
                ioc_likelihoods.append(pattern.next_reuse_likelihood)

        campaign_likelihoods = []
        for campaign_id in campaign_patterns:
            pattern = self.detect_campaign_activity_pattern(campaign_id)
            if pattern:
                campaign_likelihoods.append(pattern.next_activity_likelihood)

        asset_likelihoods = []
        for asset_id in asset_patterns:
            pattern = self.detect_asset_exposure_pattern(asset_id)
            if pattern:
                asset_likelihoods.append(pattern.next_exposure_likelihood)

        return {
            "total_iocs_analyzed": len(ioc_patterns),
            "average_ioc_reuse_likelihood": mean(ioc_likelihoods) if ioc_likelihoods else 0.0,
            "total_campaigns_analyzed": len(campaign_patterns),
            "average_campaign_activity_likelihood": mean(campaign_likelihoods) if campaign_likelihoods else 0.0,
            "total_assets_analyzed": len(asset_patterns),
            "average_asset_exposure_likelihood": mean(asset_likelihoods) if asset_likelihoods else 0.0,
        }

    def export_patterns_as_json(self) -> Dict[str, Any]:
        """Export detected patterns as JSON-serializable dict."""
        patterns = self.detect_all_patterns()
        exported = {
            "ioc_patterns": {},
            "campaign_patterns": {},
            "asset_patterns": {},
        }

        # Export IOC patterns
        for ioc_id, pattern in patterns["ioc_patterns"].items():
            exported["ioc_patterns"][ioc_id] = {
                "occurrence_count": len(pattern.occurrence_dates),
                "average_interval_days": round(pattern.average_interval, 2),
                "reuse_frequency_per_month": round(pattern.reuse_frequency, 2),
                "activity_trend": pattern.activity_trend,
                "next_reuse_likelihood": round(pattern.next_reuse_likelihood, 3),
                "predicted_next_use": pattern.predicted_next_use.isoformat() if pattern.predicted_next_use else None,
            }

        # Export campaign patterns
        for campaign_id, pattern in patterns["campaign_patterns"].items():
            exported["campaign_patterns"][campaign_id] = {
                "activity_count": len(pattern.activity_dates),
                "average_interval_days": round(pattern.average_interval, 2),
                "activity_frequency_per_month": round(pattern.activity_frequency, 2),
                "activity_pattern": pattern.activity_pattern,
                "peak_periods": pattern.peak_periods,
                "next_activity_likelihood": round(pattern.next_activity_likelihood, 3),
                "predicted_next_activity": pattern.predicted_next_activity.isoformat() if pattern.predicted_next_activity else None,
            }

        # Export asset patterns
        for asset_id, pattern in patterns["asset_patterns"].items():
            exported["asset_patterns"][asset_id] = {
                "exposure_count": len(pattern.exposure_dates),
                "average_interval_days": round(pattern.average_interval, 2),
                "exposure_frequency_per_month": round(pattern.exposure_frequency, 2),
                "exposure_trend": pattern.exposure_trend,
                "high_risk_windows": [{"start": s, "end": e} for s, e in pattern.high_risk_windows],
                "next_exposure_likelihood": round(pattern.next_exposure_likelihood, 3),
                "predicted_next_exposure": pattern.predicted_next_exposure.isoformat() if pattern.predicted_next_exposure else None,
            }

        return exported
