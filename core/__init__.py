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
    SeverityLevel,
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

__all__ = [
    # Schema
    "Vulnerability",
    "IOC",
    "Asset",
    "Relationship",
    "RiskContext",
    "ThreatIntelligenceObject",
    "EntityType",
    "RelationshipType",
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
]
