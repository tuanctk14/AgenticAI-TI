"""
core - Threat Intelligence Foundation Package

Canonical threat schema, repository abstraction, and fusion engine.
"""

from core.threat_schema import (
    Vulnerability,
    IOC,
    Asset,
    Relationship,
    RiskContext,
    ThreatIntelligenceObject,
    EntityType,
    RelationshipType,
    RelationshipMetadata,
    SeverityLevel,
    Campaign,
    ThreatActor,
    Infrastructure,
)
from core.threat_repository import ThreatKnowledgeRepository, TTLStatus
from core.threat_adapters import (
    NVDAdapter,
    EPSSAdapter,
    KEVAdapter,
    VulnersAdapter,
    OpenCTIAdapter,
)
from core.threat_fusion import ThreatFusionEngine
from core.threat_memory import (
    ThreatMemoryEngine,
    RecurringIOCMemory,
    CampaignPersistenceMemory,
    AssetExposureHistoryMemory,
    InfrastructureReuseMemory,
    ExploitationPatternMemory,
)
from core.temporal_intelligence import (
    TemporalIntelligenceEngine,
    VulnerabilityTemporal,
    IOCTemporal,
    CampaignTemporal,
)
from core.pattern_detection import PatternDetectionEngine
from core.historical_context import (
    HistoricalContextEngine,
    ActorProfile,
    ThreatTimeline,
    RiskContext,
    StatisticalBaseline,
)
from core.agent_memory_bridge import (
    MemoryAwareThreatsAgent,
    MemoryAwareAgentState,
)
from core.graph_query_engine import GraphQueryEngine
from core.community_detection import (
    CommunityDetectionEngine,
    ActorCommunity,
    CampaignCluster,
)
from core.actor_profiling import (
    ActorProfilingEngine,
    ActorProfile,
)
from core.trend_analysis import TrendAnalyzer

__all__ = [
    # Schema - Core Entities
    "Vulnerability",
    "IOC",
    "Asset",
    "Relationship",
    "RiskContext",
    "ThreatIntelligenceObject",
    # Schema - Lightweight Entities (NEW Week 1)
    "Campaign",
    "ThreatActor",
    "Infrastructure",
    # Schema - Enums & Metadata
    "EntityType",
    "RelationshipType",
    "RelationshipMetadata",
    "SeverityLevel",
    # Repository
    "ThreatKnowledgeRepository",
    "TTLStatus",
    # Adapters
    "NVDAdapter",
    "EPSSAdapter",
    "KEVAdapter",
    "VulnersAdapter",
    "OpenCTIAdapter",
    # Fusion
    "ThreatFusionEngine",
    # Memory (NEW Week 2 Day 1)
    "ThreatMemoryEngine",
    "RecurringIOCMemory",
    "CampaignPersistenceMemory",
    "AssetExposureHistoryMemory",
    "InfrastructureReuseMemory",
    "ExploitationPatternMemory",
    # Temporal Intelligence (NEW Week 2 Day 2)
    "TemporalIntelligenceEngine",
    "VulnerabilityTemporal",
    "IOCTemporal",
    "CampaignTemporal",
    # Pattern Detection (NEW Week 2 Day 3)
    "PatternDetectionEngine",
    # Historical Context (NEW Week 2 Day 4)
    "HistoricalContextEngine",
    "ActorProfile",
    "ThreatTimeline",
    "RiskContext",
    "StatisticalBaseline",
    # Memory-Aware Agent Bridge (NEW Week 2 Day 5)
    "MemoryAwareThreatsAgent",
    "MemoryAwareAgentState",
    # Graph Query Engine (NEW Week 3 Day 1)
    "GraphQueryEngine",
    # Community Detection (NEW Week 3 Day 2)
    "CommunityDetectionEngine",
    "ActorCommunity",
    "CampaignCluster",
    # Actor Profiling (NEW Week 3 Day 3)
    "ActorProfilingEngine",
    "ActorProfile",
    # Trend Analysis (NEW Week 3 Day 4)
    "TrendAnalyzer",
]
