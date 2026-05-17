"""
core/threat_memory.py - Persistent Threat Memory Engine

Maintains persistent threat cognition across runs.
Enables historical pattern inference and anomaly detection.

5 Memory Features:
1. Recurring IOC Memory - Track IOC occurrences, detect reuse
2. Campaign Persistence - Historical campaign activities, evolution
3. Asset Exposure History - Asset vulnerability timeline, exposure patterns
4. Infrastructure Reuse History - Track infrastructure reuse patterns
5. Exploitation Pattern Memory - Recurring attack patterns, technique evolution
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


# ============================================================
# MEMORY MODELS
# ============================================================

class IOCOccurrence(BaseModel):
    """Single IOC observation record."""
    date: datetime
    context: str  # Where/how observed (campaign, asset, network, etc)
    campaign_id: Optional[str] = None
    asset_id: Optional[str] = None
    severity: str = "unknown"
    confidence: float = 0.5


class RecurringIOCMemory(BaseModel):
    """
    Memory for IOC that recurs over time.

    Tracks reuse patterns, infrastructure persistence, etc.
    """
    ioc_id: str
    ioc_value: str  # IP, domain, hash, etc
    first_observed: datetime
    last_observed: datetime
    occurrence_count: int = 0
    occurrences: List[IOCOccurrence] = Field(default_factory=list)

    # Analysis
    reuse_frequency: float = 0.0  # % occurrences across campaigns
    associated_campaigns: List[str] = Field(default_factory=list)
    associated_malware: List[str] = Field(default_factory=list)
    associated_actors: List[str] = Field(default_factory=list)

    # Trend
    is_active: bool = True
    activity_trend: str = "unknown"  # rising, stable, declining
    next_reuse_likelihood: float = 0.0


class CampaignActivity(BaseModel):
    """Single campaign activity record."""
    date: datetime
    activity_type: str  # "exploit", "reconnaissance", "malware_delivery", etc
    targets_count: int = 0
    techniques_used: List[str] = Field(default_factory=list)
    severity: str = "unknown"
    confidence: float = 0.5


class CampaignPersistenceMemory(BaseModel):
    """
    Memory for campaign persistence over time.

    Tracks campaign evolution, target changes, TTPs, etc.
    """
    campaign_id: str
    campaign_name: str
    first_observed: datetime
    last_observed: datetime
    activity_count: int = 0
    activities: List[CampaignActivity] = Field(default_factory=list)

    # Target evolution
    initial_targets: List[str] = Field(default_factory=list)
    current_targets: List[str] = Field(default_factory=list)
    target_change_frequency: float = 0.0  # How often targets change

    # TTP evolution
    techniques_evolution: List[str] = Field(default_factory=list)
    technique_changes: int = 0

    # Activity patterns
    activity_pattern: str = "unknown"  # "continuous", "intermittent", "seasonal"
    peak_activity_period: Optional[str] = None  # Month/quarter when most active

    # Attribution
    confidence: float = 0.5
    attributed_actors: List[str] = Field(default_factory=list)

    # Prediction
    is_active: bool = True
    next_activity_likelihood: float = 0.0
    predicted_targets: List[str] = Field(default_factory=list)


class AssetExposure(BaseModel):
    """Single asset exposure event."""
    date: datetime
    exposure_type: str  # "cve", "ioc_detected", "malware", "anomaly"
    cve_id: Optional[str] = None
    ioc_id: Optional[str] = None
    exposure_duration_days: int = 0
    remediation_action: Optional[str] = None
    remediation_date: Optional[datetime] = None


class AssetExposureHistoryMemory(BaseModel):
    """
    Memory for asset exposure over time.

    Tracks vulnerability window, exposure patterns, remediation history.
    """
    asset_id: str
    asset_name: str
    exposure_count: int = 0
    exposures: List[AssetExposure] = Field(default_factory=list)

    # Timeline
    first_exposure: Optional[datetime] = None
    last_exposure: Optional[datetime] = None

    # Patterns
    exposure_frequency: float = 0.0  # Exposures per month
    average_exposure_duration_days: float = 0.0
    remediation_success_rate: float = 0.0  # % exposures fixed

    # Risk
    is_currently_exposed: bool = False
    current_exposure_id: Optional[str] = None
    current_exposure_duration_days: int = 0

    # Trend
    exposure_trend: str = "unknown"  # rising, stable, declining
    high_risk_window: Optional[str] = None  # When exposures most likely

    # Prediction
    next_exposure_likelihood: float = 0.0
    predicted_vulnerability: Optional[str] = None


class InfrastructureNode(BaseModel):
    """Infrastructure node record."""
    node_id: str
    node_type: str  # "ip", "domain", "c2", "proxy"
    value: str
    first_seen: datetime
    last_seen: datetime
    campaigns_using: List[str] = Field(default_factory=list)
    malware_families: List[str] = Field(default_factory=list)


class InfrastructureReuseMemory(BaseModel):
    """
    Memory for infrastructure reuse patterns.

    Tracks C2 reuse, domain/IP pivot chains, infrastructure persistence.
    """
    infrastructure_id: str
    first_observed: datetime
    last_observed: datetime
    reuse_count: int = 0
    nodes: List[InfrastructureNode] = Field(default_factory=list)

    # Network analysis
    connected_nodes: List[str] = Field(default_factory=list)  # Other infra nodes connected
    pivot_chains: List[List[str]] = Field(default_factory=list)  # Attack pivot paths

    # Actor/Campaign pattern
    associated_campaigns: List[str] = Field(default_factory=list)
    associated_actors: List[str] = Field(default_factory=list)

    # Persistence pattern
    infrastructure_family: str = "unknown"  # Related infrastructure group
    reuse_frequency: float = 0.0  # % reuse across campaigns
    time_between_reuse_days: float = 0.0  # Average days between reuses

    # Risk
    is_active: bool = True
    activity_level: str = "unknown"  # high, medium, low

    # Prediction
    next_reuse_likelihood: float = 0.0
    predicted_next_use_date: Optional[datetime] = None


class AttackPattern(BaseModel):
    """Single attack pattern occurrence."""
    date: datetime
    technique_id: str
    technique_name: str
    campaign_id: Optional[str] = None
    success: bool = False
    target_count: int = 0


class ExploitationPatternMemory(BaseModel):
    """
    Memory for recurring exploitation patterns.

    Tracks TTP evolution, success rates, technique adoption.
    """
    pattern_id: str
    pattern_name: str
    first_observed: datetime
    last_observed: datetime
    occurrence_count: int = 0
    occurrences: List[AttackPattern] = Field(default_factory=list)

    # Technique analysis
    primary_techniques: List[str] = Field(default_factory=list)
    supporting_techniques: List[str] = Field(default_factory=list)

    # Effectiveness
    success_rate: float = 0.0  # % successful exploitations
    average_targets_per_occurrence: float = 0.0

    # Adoption
    adopting_campaigns: List[str] = Field(default_factory=list)
    adoption_trend: str = "unknown"  # "rising", "stable", "declining"

    # Evolution
    technique_changes: int = 0  # Times pattern modified/evolved
    evolution_timeline: List[str] = Field(default_factory=list)  # How technique evolved

    # Prediction
    is_active: bool = True
    predicted_effectiveness: float = 0.0
    predicted_next_evolution: Optional[str] = None


# ============================================================
# THREAT MEMORY ENGINE
# ============================================================

class ThreatMemoryEngine:
    """
    Persistent threat memory system.

    Maintains 5 types of threat cognition:
    1. Recurring IOC Memory
    2. Campaign Persistence
    3. Asset Exposure History
    4. Infrastructure Reuse
    5. Exploitation Patterns
    """

    def __init__(self):
        """Initialize memory engine."""
        self.ioc_memory: Dict[str, RecurringIOCMemory] = {}
        self.campaign_memory: Dict[str, CampaignPersistenceMemory] = {}
        self.asset_memory: Dict[str, AssetExposureHistoryMemory] = {}
        self.infrastructure_memory: Dict[str, InfrastructureReuseMemory] = {}
        self.pattern_memory: Dict[str, ExploitationPatternMemory] = {}

    # ============================================================
    # RECURRING IOC MEMORY
    # ============================================================

    def record_ioc_occurrence(
        self,
        ioc_id: str,
        ioc_value: str,
        context: str,
        campaign_id: Optional[str] = None,
        asset_id: Optional[str] = None,
        severity: str = "unknown",
        confidence: float = 0.5,
    ) -> RecurringIOCMemory:
        """Record IOC observation."""
        if ioc_id not in self.ioc_memory:
            self.ioc_memory[ioc_id] = RecurringIOCMemory(
                ioc_id=ioc_id,
                ioc_value=ioc_value,
                first_observed=datetime.utcnow(),
                last_observed=datetime.utcnow(),
            )

        memory = self.ioc_memory[ioc_id]
        memory.last_observed = datetime.utcnow()
        memory.occurrence_count += 1

        # Record occurrence
        occurrence = IOCOccurrence(
            date=datetime.utcnow(),
            context=context,
            campaign_id=campaign_id,
            asset_id=asset_id,
            severity=severity,
            confidence=confidence,
        )
        memory.occurrences.append(occurrence)

        # Track associations
        if campaign_id and campaign_id not in memory.associated_campaigns:
            memory.associated_campaigns.append(campaign_id)

        # Update reuse frequency
        memory.reuse_frequency = min(
            1.0,
            memory.occurrence_count / max(1, len(memory.associated_campaigns))
        )

        return memory

    def get_ioc_memory(self, ioc_id: str) -> Optional[RecurringIOCMemory]:
        """Get IOC memory."""
        return self.ioc_memory.get(ioc_id)

    def get_recurring_iocs(self, min_occurrences: int = 2) -> List[RecurringIOCMemory]:
        """Get IOCs that recur frequently."""
        return [
            mem for mem in self.ioc_memory.values()
            if mem.occurrence_count >= min_occurrences
        ]

    # ============================================================
    # CAMPAIGN PERSISTENCE MEMORY
    # ============================================================

    def record_campaign_activity(
        self,
        campaign_id: str,
        campaign_name: str,
        activity_type: str,
        targets_count: int = 0,
        techniques_used: Optional[List[str]] = None,
        severity: str = "unknown",
        confidence: float = 0.5,
    ) -> CampaignPersistenceMemory:
        """Record campaign activity."""
        if campaign_id not in self.campaign_memory:
            self.campaign_memory[campaign_id] = CampaignPersistenceMemory(
                campaign_id=campaign_id,
                campaign_name=campaign_name,
                first_observed=datetime.utcnow(),
                last_observed=datetime.utcnow(),
            )

        memory = self.campaign_memory[campaign_id]
        memory.last_observed = datetime.utcnow()
        memory.activity_count += 1

        # Record activity
        activity = CampaignActivity(
            date=datetime.utcnow(),
            activity_type=activity_type,
            targets_count=targets_count,
            techniques_used=techniques_used or [],
            severity=severity,
            confidence=confidence,
        )
        memory.activities.append(activity)

        # Track technique evolution
        if techniques_used:
            for tech in techniques_used:
                if tech not in memory.techniques_evolution:
                    memory.techniques_evolution.append(tech)
                    memory.technique_changes += 1

        return memory

    def get_campaign_memory(self, campaign_id: str) -> Optional[CampaignPersistenceMemory]:
        """Get campaign memory."""
        return self.campaign_memory.get(campaign_id)

    def get_active_campaigns(self) -> List[CampaignPersistenceMemory]:
        """Get currently active campaigns."""
        return [
            mem for mem in self.campaign_memory.values()
            if mem.is_active
        ]

    # ============================================================
    # ASSET EXPOSURE HISTORY
    # ============================================================

    def record_asset_exposure(
        self,
        asset_id: str,
        asset_name: str,
        exposure_type: str,
        cve_id: Optional[str] = None,
        ioc_id: Optional[str] = None,
        severity: str = "unknown",
    ) -> AssetExposureHistoryMemory:
        """Record asset exposure event."""
        if asset_id not in self.asset_memory:
            self.asset_memory[asset_id] = AssetExposureHistoryMemory(
                asset_id=asset_id,
                asset_name=asset_name,
                first_exposure=datetime.utcnow(),
                last_exposure=datetime.utcnow(),
            )

        memory = self.asset_memory[asset_id]
        memory.last_exposure = datetime.utcnow()
        memory.exposure_count += 1
        memory.is_currently_exposed = True

        # Record exposure
        exposure = AssetExposure(
            date=datetime.utcnow(),
            exposure_type=exposure_type,
            cve_id=cve_id,
            ioc_id=ioc_id,
        )
        memory.exposures.append(exposure)

        # Update frequency
        days_active = (memory.last_exposure - memory.first_exposure).days + 1
        memory.exposure_frequency = memory.exposure_count / max(1, days_active / 30)

        return memory

    def record_asset_remediation(
        self,
        asset_id: str,
        exposure_duration_days: int,
        action: str,
    ) -> Optional[AssetExposureHistoryMemory]:
        """Record exposure remediation."""
        memory = self.asset_memory.get(asset_id)
        if not memory or not memory.exposures:
            return None

        # Update last exposure
        memory.exposures[-1].exposure_duration_days = exposure_duration_days
        memory.exposures[-1].remediation_action = action
        memory.exposures[-1].remediation_date = datetime.utcnow()

        # Update metrics
        memory.is_currently_exposed = False
        memory.average_exposure_duration_days = (
            sum(e.exposure_duration_days for e in memory.exposures) / len(memory.exposures)
        )

        return memory

    def get_asset_memory(self, asset_id: str) -> Optional[AssetExposureHistoryMemory]:
        """Get asset exposure history."""
        return self.asset_memory.get(asset_id)

    def get_exposed_assets(self) -> List[AssetExposureHistoryMemory]:
        """Get currently exposed assets."""
        return [
            mem for mem in self.asset_memory.values()
            if mem.is_currently_exposed
        ]

    # ============================================================
    # INFRASTRUCTURE REUSE MEMORY
    # ============================================================

    def record_infrastructure_use(
        self,
        infrastructure_id: str,
        node_type: str,
        node_value: str,
        campaign_id: Optional[str] = None,
        malware_family: Optional[str] = None,
    ) -> InfrastructureReuseMemory:
        """Record infrastructure use."""
        if infrastructure_id not in self.infrastructure_memory:
            self.infrastructure_memory[infrastructure_id] = InfrastructureReuseMemory(
                infrastructure_id=infrastructure_id,
                first_observed=datetime.utcnow(),
                last_observed=datetime.utcnow(),
            )

        memory = self.infrastructure_memory[infrastructure_id]
        memory.last_observed = datetime.utcnow()
        memory.reuse_count += 1

        # Record node
        node = InfrastructureNode(
            node_id=f"{node_type}-{node_value}",
            node_type=node_type,
            value=node_value,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        if campaign_id:
            node.campaigns_using.append(campaign_id)
        if malware_family:
            node.malware_families.append(malware_family)

        memory.nodes.append(node)

        # Track associations
        if campaign_id and campaign_id not in memory.associated_campaigns:
            memory.associated_campaigns.append(campaign_id)

        return memory

    def get_infrastructure_memory(
        self, infrastructure_id: str
    ) -> Optional[InfrastructureReuseMemory]:
        """Get infrastructure reuse memory."""
        return self.infrastructure_memory.get(infrastructure_id)

    def get_reused_infrastructure(self, min_reuses: int = 2) -> List[InfrastructureReuseMemory]:
        """Get infrastructure reused multiple times."""
        return [
            mem for mem in self.infrastructure_memory.values()
            if mem.reuse_count >= min_reuses
        ]

    # ============================================================
    # EXPLOITATION PATTERN MEMORY
    # ============================================================

    def record_exploitation_pattern(
        self,
        pattern_id: str,
        pattern_name: str,
        technique_id: str,
        technique_name: str,
        campaign_id: Optional[str] = None,
        success: bool = False,
        target_count: int = 0,
    ) -> ExploitationPatternMemory:
        """Record exploitation pattern use."""
        if pattern_id not in self.pattern_memory:
            self.pattern_memory[pattern_id] = ExploitationPatternMemory(
                pattern_id=pattern_id,
                pattern_name=pattern_name,
                first_observed=datetime.utcnow(),
                last_observed=datetime.utcnow(),
            )

        memory = self.pattern_memory[pattern_id]
        memory.last_observed = datetime.utcnow()
        memory.occurrence_count += 1

        # Record pattern use
        pattern = AttackPattern(
            date=datetime.utcnow(),
            technique_id=technique_id,
            technique_name=technique_name,
            campaign_id=campaign_id,
            success=success,
            target_count=target_count,
        )
        memory.occurrences.append(pattern)

        # Track technique
        if technique_id not in memory.primary_techniques:
            memory.primary_techniques.append(technique_id)

        # Track adoption
        if campaign_id and campaign_id not in memory.adopting_campaigns:
            memory.adopting_campaigns.append(campaign_id)

        # Update success rate
        successful = sum(1 for o in memory.occurrences if o.success)
        memory.success_rate = successful / len(memory.occurrences)

        return memory

    def get_pattern_memory(self, pattern_id: str) -> Optional[ExploitationPatternMemory]:
        """Get exploitation pattern memory."""
        return self.pattern_memory.get(pattern_id)

    def get_effective_patterns(self, min_success_rate: float = 0.5) -> List[ExploitationPatternMemory]:
        """Get highly effective exploitation patterns."""
        return [
            mem for mem in self.pattern_memory.values()
            if mem.success_rate >= min_success_rate
        ]

    # ============================================================
    # MEMORY QUERIES
    # ============================================================

    def get_memory_summary(self) -> Dict[str, Any]:
        """Get summary of all memories."""
        return {
            "ioc_memory_count": len(self.ioc_memory),
            "campaign_memory_count": len(self.campaign_memory),
            "asset_memory_count": len(self.asset_memory),
            "infrastructure_memory_count": len(self.infrastructure_memory),
            "pattern_memory_count": len(self.pattern_memory),
            "active_campaigns": len(self.get_active_campaigns()),
            "exposed_assets": len(self.get_exposed_assets()),
            "recurring_iocs": len(self.get_recurring_iocs()),
            "reused_infrastructure": len(self.get_reused_infrastructure()),
        }

    def get_threat_timeline(self, days_back: int = 30) -> List[Dict[str, Any]]:
        """Get threat timeline for last N days."""
        cutoff_date = datetime.utcnow().timestamp() - (days_back * 86400)

        timeline_events = []

        # IOC occurrences
        for ioc in self.ioc_memory.values():
            for occurrence in ioc.occurrences:
                if occurrence.date.timestamp() > cutoff_date:
                    timeline_events.append({
                        "date": occurrence.date,
                        "type": "ioc_observation",
                        "ioc_id": ioc.ioc_id,
                        "ioc_value": ioc.ioc_value,
                        "context": occurrence.context,
                    })

        # Campaign activities
        for campaign in self.campaign_memory.values():
            for activity in campaign.activities:
                if activity.date.timestamp() > cutoff_date:
                    timeline_events.append({
                        "date": activity.date,
                        "type": "campaign_activity",
                        "campaign_id": campaign.campaign_id,
                        "campaign_name": campaign.campaign_name,
                        "activity_type": activity.activity_type,
                    })

        # Asset exposures
        for asset in self.asset_memory.values():
            for exposure in asset.exposures:
                if exposure.date.timestamp() > cutoff_date:
                    timeline_events.append({
                        "date": exposure.date,
                        "type": "asset_exposure",
                        "asset_id": asset.asset_id,
                        "asset_name": asset.asset_name,
                        "exposure_type": exposure.exposure_type,
                    })

        # Sort by date
        return sorted(timeline_events, key=lambda x: x["date"])
