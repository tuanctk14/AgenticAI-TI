"""
core/threat_schema.py - Canonical Threat Schema (Pydantic Models)

Unified schema for threat intelligence entities.
Reasoning-centric, not API-centric.
Storage-agnostic (SQLite/Neo4j/PostgreSQL compatible).

This is the foundation for:
- Threat Fusion Engine
- Relationship Intelligence
- Graph-based Reasoning
- Persistent Threat Memory
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
from uuid import uuid4
from pydantic import BaseModel, Field


# ============================================================
# ENUMS
# ============================================================

class EntityType(str, Enum):
    """Entity types in threat intelligence."""
    VULNERABILITY = "vulnerability"
    IOC = "ioc"
    ASSET = "asset"
    RELATIONSHIP = "relationship"
    MALWARE = "malware"
    CAMPAIGN = "campaign"
    THREAT_ACTOR = "threat_actor"
    ATTACK_PATTERN = "attack_pattern"


class RelationshipType(str, Enum):
    """Relationship types between entities."""
    VULNERABLE_TO = "vulnerable_to"  # Asset vulnerable to CVE
    LINKED_TO = "linked_to"  # IOC linked to Malware
    EXPLOITS = "exploits"  # Campaign exploits CVE
    COMMUNICATES_WITH = "communicates_with"  # Asset communicates with IOC
    MAPPED_TO = "mapped_to"  # Asset mapped to CPE
    DETECTED_ON = "detected_on"  # IOC detected on Asset
    REACHABLE_TO = "reachable_to"  # Asset reachable to Asset
    EXPOSED_TO = "exposed_to"  # Asset exposed to Internet
    USES = "uses"  # Threat Actor uses Malware
    OBSERVED_IN = "observed_in"  # IOC observed in Campaign


class IOCType(str, Enum):
    """IOC types."""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    HASH = "hash"
    HOSTNAME = "hostname"


class SeverityLevel(str, Enum):
    """Severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


# ============================================================
# RISK CONTEXT (Multi-source Enrichment)
# ============================================================

class RiskContext(BaseModel):
    """
    Contextual risk information from multiple sources.
    This is the foundation for contextual threat scoring.
    """
    # Base severity
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cvss_source: Optional[str] = None  # "nvd", "cwe", "vulners"

    # Exploitation probability
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None

    # Exploited in wild
    kev_listed: bool = False
    kev_added_date: Optional[str] = None

    # Public exploit availability
    public_exploit_available: bool = False
    metasploit_available: bool = False
    exploit_count: int = 0
    exploit_sources: List[str] = Field(default_factory=list)

    # Contextual factors
    internet_exposed: bool = False
    asset_criticality: Optional[str] = None  # "critical", "high", "medium", "low"
    attack_path_exists: bool = False
    lateral_movement_potential: bool = False

    # Campaign/Malware linkage
    linked_campaigns: List[str] = Field(default_factory=list)
    linked_malware: List[str] = Field(default_factory=list)
    ransomware_linked: bool = False

    # Data source confidence
    data_freshness: Optional[datetime] = None
    data_sources: List[str] = Field(default_factory=list)  # ["nvd", "epss", "kev", "vulners"]

    class Config:
        json_schema_extra = {
            "example": {
                "cvss_score": 9.8,
                "epss_score": 0.97,
                "kev_listed": True,
                "public_exploit_available": True,
                "internet_exposed": True,
                "attack_path_exists": True,
                "linked_campaigns": ["ransomware-x"],
                "ransomware_linked": True
            }
        }


# ============================================================
# CORE ENTITIES
# ============================================================

class Vulnerability(BaseModel):
    """
    Canonical Vulnerability Entity.
    Schema designed for threat reasoning, not API compliance.
    """
    entity_type: EntityType = EntityType.VULNERABILITY
    id: str  # CVE-XXXX-XXXX

    # Core information
    description: str
    cwe_ids: List[str] = Field(default_factory=list)
    cpe_uris: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)

    # Severity and risk
    severity: SeverityLevel = SeverityLevel.UNKNOWN
    risk_context: RiskContext = Field(default_factory=RiskContext)

    # Temporal information
    published_date: Optional[str] = None
    modified_date: Optional[str] = None
    discovered_date: Optional[str] = None

    # Relationships
    related_entities: List[str] = Field(default_factory=list)  # entity IDs

    # System metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    ttl_hours: int = 24  # How long before re-fetch

    class Config:
        json_schema_extra = {
            "example": {
                "entity_type": "vulnerability",
                "id": "CVE-2026-8181",
                "description": "Example vulnerability",
                "cwe_ids": ["CWE-79"],
                "severity": "CRITICAL",
                "risk_context": {
                    "cvss_score": 9.8,
                    "epss_score": 0.97,
                    "kev_listed": True,
                    "public_exploit_available": True
                }
            }
        }


class IOC(BaseModel):
    """
    Canonical IOC (Indicator of Compromise) Entity.
    """
    entity_type: EntityType = EntityType.IOC
    id: str  # Normalized IOC value (IP/domain/hash/etc)

    # IOC classification
    ioc_type: IOCType

    # Content
    value: str  # Raw IOC value
    description: Optional[str] = None

    # Relationships to malware/campaigns
    related_entities: List[str] = Field(default_factory=list)  # Malware/Campaign IDs

    # Observation context
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    observation_count: int = 0

    # Risk information
    severity: SeverityLevel = SeverityLevel.LOW
    risk_context: RiskContext = Field(default_factory=RiskContext)

    # System metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    ttl_hours: int = 6  # IOC refreshes faster

    class Config:
        json_schema_extra = {
            "example": {
                "entity_type": "ioc",
                "id": "192.168.1.100",
                "ioc_type": "ip",
                "value": "192.168.1.100",
                "related_entities": ["malware-x"],
                "severity": "HIGH",
                "observation_count": 5
            }
        }


class Asset(BaseModel):
    """
    Canonical Asset Entity.
    Represents internal infrastructure/systems.
    """
    entity_type: EntityType = EntityType.ASSET
    id: str  # Device ID, hostname, or CPE

    # Asset identification
    hostname: str
    ip_address: Optional[str] = None
    os: Optional[str] = None
    platform: Optional[str] = None

    # Asset context
    location: Optional[str] = None  # "DMZ", "Internal", "Cloud"
    criticality: Optional[str] = None  # "critical", "high", "medium", "low"
    owner: Optional[str] = None

    # Software/components
    installed_software: List[Dict[str, Any]] = Field(default_factory=list)
    cpe_mappings: List[str] = Field(default_factory=list)

    # Network exposure
    internet_facing: bool = False
    exposed_ports: List[int] = Field(default_factory=list)

    # Vulnerabilities
    vulnerable_cves: List[str] = Field(default_factory=list)  # CVE IDs
    detected_iocs: List[str] = Field(default_factory=list)  # IOC IDs

    # Relationships
    related_entities: List[str] = Field(default_factory=list)
    reachable_assets: List[str] = Field(default_factory=list)  # Other asset IDs

    # Risk
    risk_context: RiskContext = Field(default_factory=RiskContext)

    # System metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    ttl_hours: int = 48  # Asset info refreshes slower

    class Config:
        json_schema_extra = {
            "example": {
                "entity_type": "asset",
                "id": "dmz-web-01",
                "hostname": "dmz-web-01",
                "ip_address": "10.0.1.5",
                "os": "Ubuntu 20.04",
                "internet_facing": True,
                "criticality": "high",
                "vulnerable_cves": ["CVE-2026-8181"]
            }
        }


class Relationship(BaseModel):
    """
    FIRST-CLASS RELATIONSHIP OBJECT.

    This is critical for:
    - Persistent relationship intelligence
    - Graph-based reasoning
    - Relationship-centric analysis

    DO NOT treat relationships as metadata.
    They are primary objects.
    """
    entity_type: EntityType = EntityType.RELATIONSHIP
    id: str = Field(default_factory=lambda: str(uuid4()))  # Unique relationship ID

    # Endpoints
    source_id: str  # Source entity ID
    source_type: EntityType
    target_id: str  # Target entity ID
    target_type: EntityType

    # Relationship type
    relationship_type: RelationshipType

    # Strength and confidence
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)  # 0-1 confidence score
    strength: str = "medium"  # "strong", "medium", "weak"

    # Evidence
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_sources: List[str] = Field(default_factory=list)  # ["nvd", "opencti", "internal"]

    # Temporal
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    active_period_start: Optional[str] = None
    active_period_end: Optional[str] = None

    # Context
    context: Dict[str, Any] = Field(default_factory=dict)  # Additional context

    class Config:
        json_schema_extra = {
            "example": {
                "entity_type": "relationship",
                "source_id": "dmz-web-01",
                "source_type": "asset",
                "target_id": "CVE-2026-8181",
                "target_type": "vulnerability",
                "relationship_type": "vulnerable_to",
                "confidence": 0.92,
                "evidence_sources": ["cpematch", "internal_scan"],
                "strength": "strong"
            }
        }


# ============================================================
# INTELLIGENCE OBJECT (Fusion Result)
# ============================================================

class ThreatIntelligenceObject(BaseModel):
    """
    Single fused threat intelligence object.
    Result of threat fusion engine.
    Ready for contextual threat scoring and graph reasoning.
    """
    entity_id: str
    entity_type: EntityType

    # Core entity
    entity: Vulnerability | IOC | Asset

    # Fused risk context
    fused_risk: RiskContext

    # Relationships
    relationships: List[Relationship] = Field(default_factory=list)

    # Contextual threat score (0-100)
    threat_score: float = Field(ge=0.0, le=100.0, default=50.0)
    threat_level: SeverityLevel = SeverityLevel.MEDIUM

    # Reasoning summary
    threat_reasoning: Optional[str] = None

    # Fusion sources
    fusion_sources: List[str] = Field(default_factory=list)

    # Persistence decision
    should_persist: bool = False
    persistence_reason: Optional[str] = None

    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        json_schema_extra = {
            "example": {
                "entity_id": "CVE-2026-8181",
                "entity_type": "vulnerability",
                "fused_risk": {
                    "cvss_score": 9.8,
                    "epss_score": 0.97,
                    "kev_listed": True,
                    "public_exploit_available": True,
                    "internet_exposed": True,
                    "attack_path_exists": True
                },
                "threat_score": 94,
                "threat_level": "CRITICAL",
                "should_persist": True,
                "threat_reasoning": "Critical CVE with public exploit, KEV listed, internet-exposed asset found with attack path"
            }
        }
