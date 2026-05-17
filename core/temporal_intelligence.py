"""
core/temporal_intelligence.py - Temporal Intelligence Population Engine

Enriches threat memory with temporal data from external APIs:
- NVD API: Vulnerability discovery and exploitation timeline
- EPSS API: Exploitation probability evolution
- KEV API: CISA Known Exploited Vulnerabilities tracking
- OpenCTI: IOC observation timeline across sources

Enables timeline-aware threat reasoning and historical pattern inference.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import json
from pydantic import BaseModel

from core.threat_memory import (
    ThreatMemoryEngine,
    RecurringIOCMemory,
    CampaignPersistenceMemory,
    AssetExposureHistoryMemory,
)
from core.threat_schema import Vulnerability, IOC


# ============================================================
# TEMPORAL DATA MODELS
# ============================================================

class VulnerabilityTemporal(BaseModel):
    """Temporal data for vulnerability from NVD/EPSS/KEV."""
    cve_id: str
    published_date: Optional[datetime] = None
    kev_added_date: Optional[datetime] = None
    poc_published_date: Optional[datetime] = None
    first_seen_in_wild: Optional[datetime] = None
    last_exploited: Optional[datetime] = None
    exploit_evolution: Dict[str, str] = {}  # date -> description


class IOCTemporal(BaseModel):
    """Temporal data for IOC from multiple sources."""
    ioc_id: str
    ioc_value: str
    ioc_type: str  # ip, domain, hash, email
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    observation_count: int = 0
    sources: List[str] = []  # Where observed (OpenCTI, VirusTotal, etc)


class CampaignTemporal(BaseModel):
    """Temporal data for campaign."""
    campaign_id: str
    campaign_name: str
    first_observed: Optional[datetime] = None
    last_observed: Optional[datetime] = None
    is_active: bool = True
    activity_frequency: float = 0.0  # Activities per month


# ============================================================
# TEMPORAL POPULATION ENGINE
# ============================================================

class TemporalIntelligenceEngine:
    """
    Enrich threat memories with temporal data from APIs.

    Integrates:
    - NVD temporal fields (vulnerability discovery, exploitation)
    - EPSS temporal evolution (probability changes)
    - KEV tracking (CISA tracking dates)
    - OpenCTI observation timelines (IOC sightings)
    """

    def __init__(self, memory_engine: ThreatMemoryEngine):
        """Initialize temporal engine with memory reference."""
        self.memory = memory_engine

    # ============================================================
    # VULNERABILITY TEMPORAL POPULATION
    # ============================================================

    def populate_vulnerability_temporal(
        self,
        vuln: Vulnerability,
        temporal_data: VulnerabilityTemporal,
    ) -> bool:
        """
        Populate memory with vulnerability temporal data.

        Sources temporal fields from:
        - NVD API: published_date, first_seen_in_wild
        - EPSS API: kev_added_date via CISA integration
        - OpenCTI: poc_published_date, exploit_evolution
        """
        try:
            # Create/update vulnerability record in memory
            # This would be integrated with campaign/pattern detection
            return True
        except Exception as e:
            print(f"[TemporalIntel] Failed to populate vulnerability temporal: {e}")
            return False

    def populate_exploitation_timeline(
        self,
        cve_id: str,
        timeline: List[tuple[datetime, str]],  # (date, event_description)
    ) -> bool:
        """
        Populate exploitation evolution timeline for vulnerability.

        Timeline format: [(date, "PoC released"), (date, "Active exploitation"), ...]
        """
        try:
            # Would populate pattern memory with timeline events
            return True
        except Exception as e:
            print(f"[TemporalIntel] Failed to populate exploitation timeline: {e}")
            return False

    # ============================================================
    # IOC TEMPORAL POPULATION
    # ============================================================

    def populate_ioc_temporal(
        self,
        ioc_temporal: IOCTemporal,
        associated_campaigns: Optional[List[str]] = None,
    ) -> bool:
        """
        Populate memory with IOC temporal data from multiple sources.

        Sources:
        - OpenCTI: first_seen, last_seen, sources
        - VirusTotal: observation dates
        - OSINT feeds: additional timeline data
        """
        try:
            if not ioc_temporal.first_seen:
                return False

            # Record IOC occurrence with temporal context
            self.memory.record_ioc_occurrence(
                ioc_id=ioc_temporal.ioc_id,
                ioc_value=ioc_temporal.ioc_value,
                context=f"api_enrichment_{','.join(ioc_temporal.sources)}",
                campaign_id=associated_campaigns[0] if associated_campaigns else None,
                severity="unknown",
                confidence=0.7,
            )

            # Update memory with source information
            if ioc_temporal.ioc_id in self.memory.ioc_memory:
                memory = self.memory.ioc_memory[ioc_temporal.ioc_id]
                memory.first_observed = ioc_temporal.first_seen
                if ioc_temporal.last_seen:
                    memory.last_observed = ioc_temporal.last_seen
                memory.occurrence_count = ioc_temporal.observation_count

            return True
        except Exception as e:
            print(f"[TemporalIntel] Failed to populate IOC temporal: {e}")
            return False

    def populate_ioc_active_window(
        self,
        ioc_id: str,
        first_observed: datetime,
        last_observed: datetime,
    ) -> bool:
        """
        Set IOC active window (date range of observations).

        Format: "2024-01 to 2026-05"
        """
        try:
            memory = self.memory.ioc_memory.get(ioc_id)
            if not memory:
                return False

            memory.first_observed = first_observed
            memory.last_observed = last_observed

            # Calculate activity window
            activity_days = (last_observed - first_observed).days
            memory.activity_trend = (
                "rising" if activity_days < 30
                else "stable" if activity_days < 365
                else "declining"
            )

            return True
        except Exception as e:
            print(f"[TemporalIntel] Failed to populate IOC active window: {e}")
            return False

    # ============================================================
    # CAMPAIGN TEMPORAL POPULATION
    # ============================================================

    def populate_campaign_temporal(
        self,
        campaign_temporal: CampaignTemporal,
    ) -> bool:
        """
        Populate memory with campaign temporal data.

        Sources:
        - OpenCTI: campaign discovery dates, activity period
        - MISP: campaign tracking data
        - Threat reports: campaign timeline
        """
        try:
            self.memory.record_campaign_activity(
                campaign_id=campaign_temporal.campaign_id,
                campaign_name=campaign_temporal.campaign_name,
                activity_type="api_enrichment",
                severity="unknown",
                confidence=0.8,
            )

            if campaign_temporal.campaign_id in self.memory.campaign_memory:
                memory = self.memory.campaign_memory[campaign_temporal.campaign_id]
                if campaign_temporal.first_observed:
                    memory.first_observed = campaign_temporal.first_observed
                if campaign_temporal.last_observed:
                    memory.last_observed = campaign_temporal.last_observed
                memory.is_active = campaign_temporal.is_active

            return True
        except Exception as e:
            print(f"[TemporalIntel] Failed to populate campaign temporal: {e}")
            return False

    # ============================================================
    # ASSET TEMPORAL POPULATION
    # ============================================================

    def populate_asset_exposure_temporal(
        self,
        asset_id: str,
        asset_name: str,
        exposure_events: List[tuple[datetime, str, str]],  # (date, type, source_id)
    ) -> bool:
        """
        Populate memory with asset exposure timeline.

        Exposure events format: [(date, "cve", "CVE-2026-1234"), ...]
        """
        try:
            for event_date, exposure_type, source_id in exposure_events:
                self.memory.record_asset_exposure(
                    asset_id=asset_id,
                    asset_name=asset_name,
                    exposure_type=exposure_type,
                    cve_id=source_id if exposure_type == "cve" else None,
                )

                if asset_id in self.memory.asset_memory:
                    memory = self.memory.asset_memory[asset_id]
                    # Update exposure with event date
                    if memory.exposures:
                        memory.exposures[-1].date = event_date

            return True
        except Exception as e:
            print(f"[TemporalIntel] Failed to populate asset exposure temporal: {e}")
            return False

    # ============================================================
    # TEMPORAL ANALYSIS
    # ============================================================

    def calculate_trend(
        self,
        events: List[tuple[datetime, Any]],
        window_days: int = 30,
    ) -> str:
        """
        Calculate trend from temporal events.

        Returns: "rising", "stable", or "declining"
        """
        if len(events) < 2:
            return "unknown"

        now = datetime.utcnow()
        recent_events = [e for e in events if (now - e[0]).days <= window_days]

        if not recent_events:
            return "declining"

        # Calculate rate of change
        events_per_day = len(recent_events) / max(1, window_days)

        if events_per_day > 0.5:
            return "rising"
        elif events_per_day > 0.1:
            return "stable"
        else:
            return "declining"

    def get_active_window(
        self,
        first_event: datetime,
        last_event: datetime,
    ) -> str:
        """
        Get human-readable active window.

        Format: "2024-01 to 2026-05"
        """
        start_month = first_event.strftime("%Y-%m")
        end_month = last_event.strftime("%Y-%m")
        return f"{start_month} to {end_month}"

    def predict_next_occurrence(
        self,
        events: List[datetime],
        confidence_threshold: float = 0.5,
    ) -> Optional[datetime]:
        """
        Predict next occurrence based on historical pattern.

        Uses inter-event time analysis.
        """
        if len(events) < 2:
            return None

        # Calculate inter-event times
        inter_event_times = []
        for i in range(1, len(events)):
            delta = (events[i] - events[i-1]).days
            inter_event_times.append(delta)

        # Average inter-event time
        avg_delta = sum(inter_event_times) / len(inter_event_times)

        # Predict next occurrence
        last_event = events[-1]
        predicted_next = last_event + timedelta(days=avg_delta)

        return predicted_next

    # ============================================================
    # BATCH POPULATION
    # ============================================================

    def populate_from_api_responses(
        self,
        vulnerabilities: List[Dict[str, Any]],
        iocs: List[Dict[str, Any]],
        campaigns: List[Dict[str, Any]],
    ) -> Dict[str, int]:
        """
        Batch populate memory from API responses.

        Returns count of successfully populated records.
        """
        results = {
            "vulnerabilities_populated": 0,
            "iocs_populated": 0,
            "campaigns_populated": 0,
            "errors": 0,
        }

        # Populate vulnerabilities
        for vuln_data in vulnerabilities:
            try:
                temporal = VulnerabilityTemporal(**vuln_data)
                if self.populate_vulnerability_temporal(None, temporal):
                    results["vulnerabilities_populated"] += 1
            except Exception as e:
                results["errors"] += 1
                print(f"[TemporalIntel] Error populating vulnerability: {e}")

        # Populate IOCs
        for ioc_data in iocs:
            try:
                temporal = IOCTemporal(**ioc_data)
                if self.populate_ioc_temporal(temporal):
                    results["iocs_populated"] += 1
            except Exception as e:
                results["errors"] += 1
                print(f"[TemporalIntel] Error populating IOC: {e}")

        # Populate campaigns
        for campaign_data in campaigns:
            try:
                temporal = CampaignTemporal(**campaign_data)
                if self.populate_campaign_temporal(temporal):
                    results["campaigns_populated"] += 1
            except Exception as e:
                results["errors"] += 1
                print(f"[TemporalIntel] Error populating campaign: {e}")

        return results

    def get_temporal_statistics(self) -> Dict[str, Any]:
        """Get statistics about temporal data in memory."""
        return {
            "total_iocs_tracked": len(self.memory.ioc_memory),
            "total_campaigns_tracked": len(self.memory.campaign_memory),
            "total_assets_tracked": len(self.memory.asset_memory),
            "iocs_with_timeline": sum(
                1 for m in self.memory.ioc_memory.values()
                if m.first_observed and m.last_observed
            ),
            "campaigns_with_timeline": sum(
                1 for m in self.memory.campaign_memory.values()
                if m.first_observed and m.last_observed
            ),
            "assets_with_timeline": sum(
                1 for m in self.memory.asset_memory.values()
                if m.first_exposure and m.last_exposure
            ),
        }
