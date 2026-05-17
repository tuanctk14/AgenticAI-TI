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
    # Memory (NEW Week 2)
    "ThreatMemoryEngine",
    "RecurringIOCMemory",
    "CampaignPersistenceMemory",
    "AssetExposureHistoryMemory",
    "InfrastructureReuseMemory",
    "ExploitationPatternMemory",
]
