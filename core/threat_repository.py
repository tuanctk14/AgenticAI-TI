"""
core/threat_repository.py - Repository Abstraction Layer

Storage-agnostic interface for threat intelligence persistence.
Future graph migration (Neo4j/ArangoDB) must NOT require agent changes.

This layer ensures:
- Agents interact only with ThreatKnowledgeRepository interface
- Storage implementation is hidden
- Easy migration from SQLite → Neo4j/PostgreSQL/ArangoDB
- TTL management for data freshness
- Relationship-centric queries
"""

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from enum import Enum

from core.threat_schema import (
    EntityType,
    Vulnerability,
    IOC,
    Asset,
    Relationship,
    ThreatIntelligenceObject,
)


class TTLStatus(str, Enum):
    """Data freshness status."""
    FRESH = "fresh"  # Within TTL
    STALE = "stale"  # Exceeded TTL
    NOT_FOUND = "not_found"  # Entity doesn't exist


class QueryContext:
    """Query parameters for flexibility."""
    def __init__(
        self,
        entity_type: Optional[EntityType] = None,
        freshness_only: bool = True,
        include_relationships: bool = True,
        max_results: int = 100,
    ):
        self.entity_type = entity_type
        self.freshness_only = freshness_only
        self.include_relationships = include_relationships
        self.max_results = max_results


# ============================================================
# REPOSITORY INTERFACE
# ============================================================

class ThreatKnowledgeRepository(ABC):
    """
    Abstract interface for threat intelligence persistence.

    Agents interact ONLY with this interface.
    Storage implementation is completely hidden.
    """

    # ============================================================
    # ENTITY OPERATIONS
    # ============================================================

    @abstractmethod
    async def get_vulnerability(
        self,
        cve_id: str,
        freshness_only: bool = True
    ) -> tuple[Optional[Vulnerability], TTLStatus]:
        """
        Get vulnerability by CVE ID.

        Returns:
            (entity, status) where status indicates freshness.
        """
        pass

    @abstractmethod
    async def get_ioc(
        self,
        ioc_id: str,
        freshness_only: bool = True
    ) -> tuple[Optional[IOC], TTLStatus]:
        """Get IOC by ID (normalized value)."""
        pass

    @abstractmethod
    async def get_asset(
        self,
        asset_id: str,
        freshness_only: bool = True
    ) -> tuple[Optional[Asset], TTLStatus]:
        """Get asset by ID."""
        pass

    @abstractmethod
    async def save_vulnerability(self, vuln: Vulnerability) -> bool:
        """Persist vulnerability (with TTL)."""
        pass

    @abstractmethod
    async def save_ioc(self, ioc: IOC) -> bool:
        """Persist IOC (with TTL)."""
        pass

    @abstractmethod
    async def save_asset(self, asset: Asset) -> bool:
        """Persist asset (with TTL)."""
        pass

    @abstractmethod
    async def save_intelligence_object(
        self,
        obj: ThreatIntelligenceObject
    ) -> bool:
        """Save fused intelligence object (if should_persist=True)."""
        pass

    # ============================================================
    # RELATIONSHIP OPERATIONS (CRITICAL)
    # ============================================================

    @abstractmethod
    async def create_relationship(
        self,
        relationship: Relationship
    ) -> bool:
        """Create relationship between entities."""
        pass

    @abstractmethod
    async def get_relationships(
        self,
        source_id: str,
        relationship_type: Optional[str] = None,
    ) -> List[Relationship]:
        """
        Get relationships from source entity.

        Used for:
        - Finding all CVEs affecting an asset
        - Finding all assets vulnerable to CVE
        - Finding campaign-related entities
        """
        pass

    @abstractmethod
    async def get_related_entities(
        self,
        entity_id: str,
        entity_type: EntityType,
        relationship_type: Optional[str] = None,
        max_depth: int = 2,
    ) -> List[Dict[str, Any]]:
        """
        Get related entities (transitive relationships).

        Used for:
        - Finding attack paths
        - Finding campaign cascades
        - Finding infrastructure relationships
        """
        pass

    @abstractmethod
    async def correlate_ioc_to_malware(self, ioc_id: str) -> List[str]:
        """Find malware families linked to IOC."""
        pass

    @abstractmethod
    async def correlate_cve_to_campaigns(self, cve_id: str) -> List[str]:
        """Find campaigns exploiting CVE."""
        pass

    @abstractmethod
    async def correlate_asset_vulnerabilities(
        self,
        asset_id: str
    ) -> List[Vulnerability]:
        """Find all CVEs affecting asset."""
        pass

    # ============================================================
    # FRESHNESS / TTL MANAGEMENT
    # ============================================================

    @abstractmethod
    async def check_freshness(
        self,
        entity_id: str,
        entity_type: EntityType,
    ) -> TTLStatus:
        """Check if entity data is fresh (within TTL)."""
        pass

    @abstractmethod
    async def refresh_entity(
        self,
        entity_id: str,
        entity_type: EntityType,
        new_ttl_hours: int,
    ) -> bool:
        """Extend TTL after refreshing from API."""
        pass

    @abstractmethod
    async def cleanup_stale_entities(self) -> int:
        """Remove entities that exceeded TTL. Returns count deleted."""
        pass

    # ============================================================
    # CONTEXTUAL MEMORY (LONG-TERM THREAT INTELLIGENCE)
    # ============================================================

    @abstractmethod
    async def record_threat_observation(
        self,
        entity_id: str,
        observation_type: str,  # "ioc_detected", "cve_exploited", "campaign_activity"
        context: Dict[str, Any],
    ) -> bool:
        """Record threat observation for historical analysis."""
        pass

    @abstractmethod
    async def get_threat_history(
        self,
        entity_id: str,
        days_back: int = 90,
    ) -> List[Dict[str, Any]]:
        """Get historical threat observations."""
        pass

    @abstractmethod
    async def get_recurring_threats(
        self,
        threshold: int = 3,  # Minimum occurrences
        days_back: int = 90,
    ) -> List[Dict[str, Any]]:
        """Find threats that recur (attack patterns, repeated IOC, etc)."""
        pass

    # ============================================================
    # SELECTIVE PERSISTENCE QUERIES
    # ============================================================

    @abstractmethod
    async def list_high_risk_cves(
        self,
        min_threat_score: float = 80.0,
        limit: int = 100,
    ) -> List[Vulnerability]:
        """List CVEs with threat score >= threshold."""
        pass

    @abstractmethod
    async def list_kev_cves(self, limit: int = 100) -> List[Vulnerability]:
        """List all KEV CVEs in knowledge base."""
        pass

    @abstractmethod
    async def list_correlated_iocs(
        self,
        limit: int = 100,
    ) -> List[IOC]:
        """List IOCs linked to campaigns/malware."""
        pass

    @abstractmethod
    async def list_critical_assets(
        self,
        internet_facing_only: bool = True,
        min_threat_score: float = 70.0,
        limit: int = 100,
    ) -> List[Asset]:
        """List assets with high exposure/criticality."""
        pass

    # ============================================================
    # BULK OPERATIONS
    # ============================================================

    @abstractmethod
    async def batch_save_entities(
        self,
        entities: List[Vulnerability | IOC | Asset]
    ) -> int:
        """Save multiple entities. Returns count saved."""
        pass

    @abstractmethod
    async def batch_create_relationships(
        self,
        relationships: List[Relationship]
    ) -> int:
        """Create multiple relationships. Returns count created."""
        pass

    # ============================================================
    # SEARCH / DISCOVERY
    # ============================================================

    @abstractmethod
    async def search_by_id(
        self,
        query: str,
        entity_types: Optional[List[EntityType]] = None,
    ) -> List[Dict[str, Any]]:
        """Search entities by ID (CVE, IOC value, hostname, etc)."""
        pass

    @abstractmethod
    async def search_by_description(
        self,
        query: str,
        entity_types: Optional[List[EntityType]] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Full-text search on descriptions."""
        pass

    # ============================================================
    # ADMIN / DIAGNOSTICS
    # ============================================================

    @abstractmethod
    async def get_stats(self) -> Dict[str, Any]:
        """Get knowledge base statistics."""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Check repository connectivity."""
        pass


# ============================================================
# FUTURE IMPLEMENTATIONS
# ============================================================

# These will be implemented as separate classes:
#
# class SQLiteRepository(ThreatKnowledgeRepository):
#     """SQLite-based persistence (Phase 1)."""
#     pass
#
# class Neo4jRepository(ThreatKnowledgeRepository):
#     """Neo4j graph database (Phase 5)."""
#     pass
#
# class PostgresRepository(ThreatKnowledgeRepository):
#     """PostgreSQL + relationship tables (Phase 1B)."""
#     pass
#
# Migration from SQLite → Neo4j requires ZERO agent changes.
# Only repository implementation changes.
