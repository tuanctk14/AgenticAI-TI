"""
core/sqlite_repository.py - SQLite Implementation of ThreatKnowledgeRepository

Persistent threat intelligence storage with:
- TTL management (automatic stale data removal)
- Entity persistence (CVE, IOC, Asset, Relationship)
- Relationship queries
- Selective persistence (high-value intelligence only)
- Contextual threat memory (observations, history)

Note: This is Phase 1D (SQLite).
Phase 5 will add Neo4j implementation without requiring agent changes.
"""

import sqlite3
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any
import asyncio

from core.threat_schema import (
    Vulnerability,
    IOC,
    Asset,
    Relationship,
    EntityType,
    RelationshipType,
    ThreatIntelligenceObject,
)
from core.threat_repository import (
    ThreatKnowledgeRepository,
    TTLStatus,
    QueryContext,
)
from core.migrations.manager import MigrationManager
from core.threat_memory import ThreatMemoryEngine


class SQLiteRepository(ThreatKnowledgeRepository):
    """SQLite-based threat intelligence persistence."""

    def __init__(self, db_path: str = "data/threat_knowledge.db"):
        """Initialize SQLite repository."""
        self.db_path = db_path
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.memory_engine = ThreatMemoryEngine()
        self._init_db()
        # Apply any pending migrations (Week 1 adds new tables)
        self._apply_migrations()
        # Load memory from persistence
        self._load_memory_from_db()

    def _init_db(self):
        """Initialize database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Vulnerabilities table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                epss_score REAL,
                kev_listed BOOLEAN,
                public_exploit BOOLEAN,
                internet_exposed BOOLEAN,
                attack_path_exists BOOLEAN,
                data_sources TEXT,
                created_at TEXT,
                updated_at TEXT,
                expires_at TEXT,
                data JSON
            )
        """)

        # IOCs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                id TEXT PRIMARY KEY,
                ioc_type TEXT,
                value TEXT,
                severity TEXT,
                observation_count INTEGER,
                first_seen TEXT,
                last_seen TEXT,
                created_at TEXT,
                updated_at TEXT,
                expires_at TEXT,
                data JSON
            )
        """)

        # Assets table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY,
                hostname TEXT,
                ip_address TEXT,
                os TEXT,
                internet_facing BOOLEAN,
                criticality TEXT,
                created_at TEXT,
                updated_at TEXT,
                expires_at TEXT,
                data JSON
            )
        """)

        # Relationships table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS relationships (
                id TEXT PRIMARY KEY,
                source_id TEXT,
                source_type TEXT,
                target_id TEXT,
                target_type TEXT,
                relationship_type TEXT,
                confidence REAL,
                strength TEXT,
                evidence_sources TEXT,
                created_at TEXT,
                updated_at TEXT,
                data JSON
            )
        """)

        # Threat observations (for contextual memory)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_observations (
                id TEXT PRIMARY KEY,
                entity_id TEXT,
                observation_type TEXT,
                observed_at TEXT,
                context JSON
            )
        """)

        # Intelligence objects (fused results)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS intelligence_objects (
                id TEXT PRIMARY KEY,
                entity_id TEXT,
                entity_type TEXT,
                threat_score REAL,
                threat_level TEXT,
                should_persist BOOLEAN,
                created_at TEXT,
                data JSON
            )
        """)

        # Memory persistence tables (Week 2)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ioc_memory (
                ioc_id TEXT PRIMARY KEY,
                ioc_value TEXT,
                first_observed TEXT,
                last_observed TEXT,
                memory_data JSON
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS campaign_memory (
                campaign_id TEXT PRIMARY KEY,
                campaign_name TEXT,
                first_observed TEXT,
                last_observed TEXT,
                memory_data JSON
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS asset_memory (
                asset_id TEXT PRIMARY KEY,
                asset_name TEXT,
                first_exposure TEXT,
                last_exposure TEXT,
                memory_data JSON
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS infrastructure_memory (
                infrastructure_id TEXT PRIMARY KEY,
                first_observed TEXT,
                last_observed TEXT,
                memory_data JSON
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pattern_memory (
                pattern_id TEXT PRIMARY KEY,
                pattern_name TEXT,
                first_observed TEXT,
                last_observed TEXT,
                memory_data JSON
            )
        """)

        # Indexes for performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vuln_expires ON vulnerabilities(expires_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ioc_expires ON iocs(expires_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_asset_expires ON assets(expires_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rel_source ON relationships(source_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rel_target ON relationships(target_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_obs_entity ON threat_observations(entity_id)")

        # Memory indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ioc_mem_observed ON ioc_memory(last_observed)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_campaign_mem_observed ON campaign_memory(last_observed)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_asset_mem_exposed ON asset_memory(last_exposure)")

        conn.commit()
        conn.close()

    def _apply_migrations(self):
        """Apply any pending database migrations."""
        try:
            conn = sqlite3.connect(self.db_path)
            manager = MigrationManager(self.db_path)
            if manager.migrate_to_latest(conn):
                conn.close()
            else:
                conn.close()
                raise RuntimeError("Failed to apply migrations")
        except Exception as e:
            print(f"[SQLiteRepository] Warning: Migration error: {e}")
            # Non-fatal: system can still work with basic schema

    # ============================================================
    # ENTITY OPERATIONS
    # ============================================================

    async def get_vulnerability(
        self,
        cve_id: str,
        freshness_only: bool = True
    ) -> tuple[Optional[Vulnerability], TTLStatus]:
        """Get vulnerability by CVE ID."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT data, expires_at FROM vulnerabilities WHERE id = ?
            """,
            (cve_id,)
        )
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None, TTLStatus.NOT_FOUND

        data, expires_at = row

        # Check TTL
        if expires_at:
            expire_dt = datetime.fromisoformat(expires_at)
            if datetime.utcnow() > expire_dt:
                if freshness_only:
                    return None, TTLStatus.STALE
                # Fall through to return stale data if not freshness_only

        vuln_data = json.loads(data)
        vuln = Vulnerability(**vuln_data)
        status = TTLStatus.STALE if expires_at and datetime.fromisoformat(expires_at) < datetime.utcnow() else TTLStatus.FRESH
        return vuln, status

    async def get_ioc(
        self,
        ioc_id: str,
        freshness_only: bool = True
    ) -> tuple[Optional[IOC], TTLStatus]:
        """Get IOC by ID."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT data, expires_at FROM iocs WHERE id = ?
            """,
            (ioc_id,)
        )
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None, TTLStatus.NOT_FOUND

        data, expires_at = row

        # Check TTL
        if expires_at:
            expire_dt = datetime.fromisoformat(expires_at)
            if datetime.utcnow() > expire_dt:
                if freshness_only:
                    return None, TTLStatus.STALE

        ioc_data = json.loads(data)
        ioc = IOC(**ioc_data)
        status = TTLStatus.STALE if expires_at and datetime.fromisoformat(expires_at) < datetime.utcnow() else TTLStatus.FRESH
        return ioc, status

    async def get_asset(
        self,
        asset_id: str,
        freshness_only: bool = True
    ) -> tuple[Optional[Asset], TTLStatus]:
        """Get asset by ID."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT data, expires_at FROM assets WHERE id = ?
            """,
            (asset_id,)
        )
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None, TTLStatus.NOT_FOUND

        data, expires_at = row

        # Check TTL
        if expires_at:
            expire_dt = datetime.fromisoformat(expires_at)
            if datetime.utcnow() > expire_dt:
                if freshness_only:
                    return None, TTLStatus.STALE

        asset_data = json.loads(data)
        asset = Asset(**asset_data)
        status = TTLStatus.STALE if expires_at and datetime.fromisoformat(expires_at) < datetime.utcnow() else TTLStatus.FRESH
        return asset, status

    async def save_vulnerability(self, vuln: Vulnerability) -> bool:
        """Persist vulnerability with TTL."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            now = datetime.utcnow().isoformat()
            expires_at = (datetime.utcnow() + timedelta(hours=vuln.ttl_hours)).isoformat()

            data = vuln.model_dump_json()
            data_dict = json.loads(data)

            cursor.execute(
                """
                INSERT OR REPLACE INTO vulnerabilities
                (id, description, severity, cvss_score, epss_score, kev_listed,
                 public_exploit, internet_exposed, attack_path_exists, data_sources,
                 created_at, updated_at, expires_at, data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    vuln.id,
                    vuln.description,
                    vuln.severity.value,
                    vuln.risk_context.cvss_score if vuln.risk_context else None,
                    vuln.risk_context.epss_score if vuln.risk_context else None,
                    vuln.risk_context.kev_listed if vuln.risk_context else False,
                    vuln.risk_context.public_exploit_available if vuln.risk_context else False,
                    vuln.risk_context.internet_exposed if vuln.risk_context else False,
                    vuln.risk_context.attack_path_exists if vuln.risk_context else False,
                    json.dumps(vuln.risk_context.data_sources if vuln.risk_context else []),
                    now,
                    now,
                    expires_at,
                    data,
                )
            )

            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"[SQLiteRepository] Error saving vulnerability: {e}")
            return False

    async def save_ioc(self, ioc: IOC) -> bool:
        """Persist IOC."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            now = datetime.utcnow().isoformat()
            expires_at = (datetime.utcnow() + timedelta(hours=ioc.ttl_hours)).isoformat()

            data = ioc.model_dump_json()

            cursor.execute(
                """
                INSERT OR REPLACE INTO iocs
                (id, ioc_type, value, severity, observation_count, first_seen,
                 last_seen, created_at, updated_at, expires_at, data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ioc.id,
                    ioc.ioc_type.value,
                    ioc.value,
                    ioc.severity.value,
                    ioc.observation_count,
                    ioc.first_seen,
                    ioc.last_seen,
                    now,
                    now,
                    expires_at,
                    data,
                )
            )

            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"[SQLiteRepository] Error saving IOC: {e}")
            return False

    async def save_asset(self, asset: Asset) -> bool:
        """Persist asset."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            now = datetime.utcnow().isoformat()
            expires_at = (datetime.utcnow() + timedelta(hours=asset.ttl_hours)).isoformat()

            data = asset.model_dump_json()

            cursor.execute(
                """
                INSERT OR REPLACE INTO assets
                (id, hostname, ip_address, os, internet_facing, criticality,
                 created_at, updated_at, expires_at, data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    asset.id,
                    asset.hostname,
                    asset.ip_address,
                    asset.os,
                    asset.internet_facing,
                    asset.criticality,
                    now,
                    now,
                    expires_at,
                    data,
                )
            )

            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"[SQLiteRepository] Error saving asset: {e}")
            return False

    async def save_intelligence_object(
        self,
        obj: ThreatIntelligenceObject
    ) -> bool:
        """Save fused intelligence object."""
        if not obj.should_persist:
            return False  # Don't persist low-value intelligence

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            now = datetime.utcnow().isoformat()
            data = obj.model_dump_json()

            cursor.execute(
                """
                INSERT OR REPLACE INTO intelligence_objects
                (id, entity_id, entity_type, threat_score, threat_level,
                 should_persist, created_at, data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"{obj.entity_id}_{now}",  # Unique ID
                    obj.entity_id,
                    obj.entity_type.value,
                    obj.threat_score,
                    obj.threat_level.value,
                    obj.should_persist,
                    now,
                    data,
                )
            )

            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"[SQLiteRepository] Error saving intelligence object: {e}")
            return False

    # ============================================================
    # RELATIONSHIP OPERATIONS
    # ============================================================

    async def create_relationship(
        self,
        relationship: Relationship
    ) -> bool:
        """Create relationship between entities."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            now = datetime.utcnow().isoformat()
            data = relationship.model_dump_json()

            cursor.execute(
                """
                INSERT OR REPLACE INTO relationships
                (id, source_id, source_type, target_id, target_type,
                 relationship_type, confidence, strength, evidence_sources,
                 created_at, updated_at, data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    relationship.id,
                    relationship.source_id,
                    relationship.source_type.value,
                    relationship.target_id,
                    relationship.target_type.value,
                    relationship.relationship_type.value,
                    relationship.confidence,
                    relationship.strength,
                    json.dumps(relationship.evidence_sources),
                    now,
                    now,
                    data,
                )
            )

            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"[SQLiteRepository] Error creating relationship: {e}")
            return False

    async def get_relationships(
        self,
        source_id: str,
        relationship_type: Optional[str] = None,
    ) -> List[Relationship]:
        """Get relationships from source entity."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            if relationship_type:
                cursor.execute(
                    """
                    SELECT data FROM relationships
                    WHERE source_id = ? AND relationship_type = ?
                    """,
                    (source_id, relationship_type)
                )
            else:
                cursor.execute(
                    """
                    SELECT data FROM relationships WHERE source_id = ?
                    """,
                    (source_id,)
                )

            rows = cursor.fetchall()
            conn.close()

            relationships = []
            for row in rows:
                rel_data = json.loads(row[0])
                rel = Relationship(**rel_data)
                relationships.append(rel)

            return relationships
        except Exception as e:
            print(f"[SQLiteRepository] Error getting relationships: {e}")
            return []

    async def get_related_entities(
        self,
        entity_id: str,
        entity_type: EntityType,
        relationship_type: Optional[str] = None,
        max_depth: int = 2,
    ) -> List[Dict[str, Any]]:
        """Get related entities (transitive relationships)."""
        # Simplified implementation - in Neo4j this would be a graph traversal
        # For SQLite, we do BFS manually
        results = []
        visited = set()
        queue = [(entity_id, 0)]

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            while queue and max_depth > 0:
                current_id, depth = queue.pop(0)

                if current_id in visited:
                    continue
                visited.add(current_id)

                # Find related entities
                cursor.execute(
                    """
                    SELECT target_id, target_type, relationship_type FROM relationships
                    WHERE source_id = ?
                    """,
                    (current_id,)
                )

                for target_id, target_type, rel_type in cursor.fetchall():
                    if target_id not in visited:
                        results.append({
                            "entity_id": target_id,
                            "entity_type": target_type,
                            "relationship_type": rel_type,
                            "depth": depth + 1,
                        })

                        if depth + 1 < max_depth:
                            queue.append((target_id, depth + 1))

            conn.close()
            return results
        except Exception as e:
            print(f"[SQLiteRepository] Error getting related entities: {e}")
            return []

    async def correlate_ioc_to_malware(self, ioc_id: str) -> List[str]:
        """Find malware families linked to IOC."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT DISTINCT target_id FROM relationships
                WHERE source_id = ? AND relationship_type = 'linked_to'
                AND target_type = 'malware'
                """,
                (ioc_id,)
            )

            malware_ids = [row[0] for row in cursor.fetchall()]
            conn.close()
            return malware_ids
        except Exception as e:
            print(f"[SQLiteRepository] Error correlating IOC to malware: {e}")
            return []

    async def correlate_cve_to_campaigns(self, cve_id: str) -> List[str]:
        """Find campaigns exploiting CVE."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT DISTINCT source_id FROM relationships
                WHERE target_id = ? AND relationship_type = 'exploits'
                AND source_type = 'campaign'
                """,
                (cve_id,)
            )

            campaign_ids = [row[0] for row in cursor.fetchall()]
            conn.close()
            return campaign_ids
        except Exception as e:
            print(f"[SQLiteRepository] Error correlating CVE to campaigns: {e}")
            return []

    async def correlate_asset_vulnerabilities(
        self,
        asset_id: str
    ) -> List[Vulnerability]:
        """Find all CVEs affecting asset."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Find CVEs asset is vulnerable to
            cursor.execute(
                """
                SELECT DISTINCT target_id FROM relationships
                WHERE source_id = ? AND relationship_type = 'vulnerable_to'
                AND target_type = 'vulnerability'
                """,
                (asset_id,)
            )

            cve_ids = [row[0] for row in cursor.fetchall()]
            conn.close()

            # Fetch CVE data
            cves = []
            for cve_id in cve_ids:
                vuln, _ = await self.get_vulnerability(cve_id, freshness_only=False)
                if vuln:
                    cves.append(vuln)

            return cves
        except Exception as e:
            print(f"[SQLiteRepository] Error correlating asset vulnerabilities: {e}")
            return []

    # ============================================================
    # FRESHNESS / TTL MANAGEMENT
    # ============================================================

    async def check_freshness(
        self,
        entity_id: str,
        entity_type: EntityType,
    ) -> TTLStatus:
        """Check if entity data is fresh."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            table_map = {
                EntityType.VULNERABILITY: "vulnerabilities",
                EntityType.IOC: "iocs",
                EntityType.ASSET: "assets",
            }

            table = table_map.get(entity_type)
            if not table:
                return TTLStatus.NOT_FOUND

            cursor.execute(
                f"SELECT expires_at FROM {table} WHERE id = ?",
                (entity_id,)
            )
            row = cursor.fetchone()
            conn.close()

            if not row:
                return TTLStatus.NOT_FOUND

            expires_at = row[0]
            if expires_at:
                expire_dt = datetime.fromisoformat(expires_at)
                if datetime.utcnow() > expire_dt:
                    return TTLStatus.STALE

            return TTLStatus.FRESH
        except Exception as e:
            print(f"[SQLiteRepository] Error checking freshness: {e}")
            return TTLStatus.NOT_FOUND

    async def refresh_entity(
        self,
        entity_id: str,
        entity_type: EntityType,
        new_ttl_hours: int,
    ) -> bool:
        """Extend TTL after refreshing from API."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            table_map = {
                EntityType.VULNERABILITY: "vulnerabilities",
                EntityType.IOC: "iocs",
                EntityType.ASSET: "assets",
            }

            table = table_map.get(entity_type)
            if not table:
                return False

            new_expires = (datetime.utcnow() + timedelta(hours=new_ttl_hours)).isoformat()

            cursor.execute(
                f"""
                UPDATE {table}
                SET expires_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (new_expires, datetime.utcnow().isoformat(), entity_id)
            )

            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"[SQLiteRepository] Error refreshing entity: {e}")
            return False

    async def cleanup_stale_entities(self) -> int:
        """Remove entities that exceeded TTL."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            now = datetime.utcnow().isoformat()
            count = 0

            for table in ["vulnerabilities", "iocs", "assets"]:
                cursor.execute(
                    f"DELETE FROM {table} WHERE expires_at < ?",
                    (now,)
                )
                count += cursor.rowcount

            conn.commit()
            conn.close()

            if count > 0:
                print(f"[SQLiteRepository] Cleaned up {count} stale entities")

            return count
        except Exception as e:
            print(f"[SQLiteRepository] Error cleaning up stale entities: {e}")
            return 0

    # ============================================================
    # REMAINING METHODS (stubs for now)
    # ============================================================

    async def record_threat_observation(
        self,
        entity_id: str,
        observation_type: str,
        context: Dict[str, Any],
    ) -> bool:
        """Record threat observation for historical analysis."""
        # TODO: Implement threat observation recording
        return True

    async def get_threat_history(
        self,
        entity_id: str,
        days_back: int = 90,
    ) -> List[Dict[str, Any]]:
        """Get historical threat observations."""
        # TODO: Implement threat history retrieval
        return []

    async def get_recurring_threats(
        self,
        threshold: int = 3,
        days_back: int = 90,
    ) -> List[Dict[str, Any]]:
        """Find threats that recur."""
        # TODO: Implement recurring threat detection
        return []

    async def list_high_risk_cves(
        self,
        min_threat_score: float = 80.0,
        limit: int = 100,
    ) -> List[Vulnerability]:
        """List CVEs with threat score >= threshold."""
        # TODO: Implement high-risk CVE listing
        return []

    async def list_kev_cves(self, limit: int = 100) -> List[Vulnerability]:
        """List all KEV CVEs in knowledge base."""
        # TODO: Implement KEV CVE listing
        return []

    async def list_correlated_iocs(
        self,
        limit: int = 100,
    ) -> List[IOC]:
        """List IOCs linked to campaigns/malware."""
        # TODO: Implement correlated IOC listing
        return []

    async def list_critical_assets(
        self,
        internet_facing_only: bool = True,
        min_threat_score: float = 70.0,
        limit: int = 100,
    ) -> List[Asset]:
        """List assets with high exposure/criticality."""
        # TODO: Implement critical asset listing
        return []

    async def batch_save_entities(
        self,
        entities: List[Vulnerability | IOC | Asset]
    ) -> int:
        """Save multiple entities."""
        count = 0
        for entity in entities:
            if isinstance(entity, Vulnerability):
                if await self.save_vulnerability(entity):
                    count += 1
            elif isinstance(entity, IOC):
                if await self.save_ioc(entity):
                    count += 1
            elif isinstance(entity, Asset):
                if await self.save_asset(entity):
                    count += 1
        return count

    async def batch_create_relationships(
        self,
        relationships: List[Relationship]
    ) -> int:
        """Create multiple relationships."""
        count = 0
        for rel in relationships:
            if await self.create_relationship(rel):
                count += 1
        return count

    async def search_by_id(
        self,
        query: str,
        entity_types: Optional[List[EntityType]] = None,
    ) -> List[Dict[str, Any]]:
        """Search entities by ID."""
        # TODO: Implement entity ID search
        return []

    async def search_by_description(
        self,
        query: str,
        entity_types: Optional[List[EntityType]] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Full-text search on descriptions."""
        # TODO: Implement full-text search
        return []

    async def get_stats(self) -> Dict[str, Any]:
        """Get knowledge base statistics."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            stats = {}
            for table in ["vulnerabilities", "iocs", "assets", "relationships"]:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                count = cursor.fetchone()[0]
                stats[table] = count

            conn.close()
            return stats
        except Exception as e:
            print(f"[SQLiteRepository] Error getting stats: {e}")
            return {}

    async def health_check(self) -> bool:
        """Check repository connectivity."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            conn.close()
            return True
        except Exception as e:
            print(f"[SQLiteRepository] Health check failed: {e}")
            return False

    # ============================================================
    # MEMORY PERSISTENCE (Week 2)
    # ============================================================

    def _load_memory_from_db(self):
        """Load all memories from database into engine."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Load IOC memory
            cursor.execute("SELECT memory_data FROM ioc_memory")
            for (memory_json,) in cursor.fetchall():
                try:
                    data = json.loads(memory_json)
                    from core.threat_memory import RecurringIOCMemory
                    memory = RecurringIOCMemory(**data)
                    self.memory_engine.ioc_memory[memory.ioc_id] = memory
                except Exception as e:
                    print(f"[Memory] Failed to load IOC memory: {e}")

            # Load campaign memory
            cursor.execute("SELECT memory_data FROM campaign_memory")
            for (memory_json,) in cursor.fetchall():
                try:
                    data = json.loads(memory_json)
                    from core.threat_memory import CampaignPersistenceMemory
                    memory = CampaignPersistenceMemory(**data)
                    self.memory_engine.campaign_memory[memory.campaign_id] = memory
                except Exception as e:
                    print(f"[Memory] Failed to load campaign memory: {e}")

            # Load asset memory
            cursor.execute("SELECT memory_data FROM asset_memory")
            for (memory_json,) in cursor.fetchall():
                try:
                    data = json.loads(memory_json)
                    from core.threat_memory import AssetExposureHistoryMemory
                    memory = AssetExposureHistoryMemory(**data)
                    self.memory_engine.asset_memory[memory.asset_id] = memory
                except Exception as e:
                    print(f"[Memory] Failed to load asset memory: {e}")

            # Load infrastructure memory
            cursor.execute("SELECT memory_data FROM infrastructure_memory")
            for (memory_json,) in cursor.fetchall():
                try:
                    data = json.loads(memory_json)
                    from core.threat_memory import InfrastructureReuseMemory
                    memory = InfrastructureReuseMemory(**data)
                    self.memory_engine.infrastructure_memory[memory.infrastructure_id] = memory
                except Exception as e:
                    print(f"[Memory] Failed to load infrastructure memory: {e}")

            # Load pattern memory
            cursor.execute("SELECT memory_data FROM pattern_memory")
            for (memory_json,) in cursor.fetchall():
                try:
                    data = json.loads(memory_json)
                    from core.threat_memory import ExploitationPatternMemory
                    memory = ExploitationPatternMemory(**data)
                    self.memory_engine.pattern_memory[memory.pattern_id] = memory
                except Exception as e:
                    print(f"[Memory] Failed to load pattern memory: {e}")

            conn.close()
        except Exception as e:
            print(f"[Memory] Failed to load memories: {e}")

    def _save_memory_to_db(self):
        """Persist all memories to database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Save IOC memory
            for ioc_id, memory in self.memory_engine.ioc_memory.items():
                data = json.dumps(json.loads(memory.model_dump_json()), default=str)
                cursor.execute("""
                    INSERT OR REPLACE INTO ioc_memory
                    (ioc_id, ioc_value, first_observed, last_observed, memory_data)
                    VALUES (?, ?, ?, ?, ?)
                """, (ioc_id, memory.ioc_value, memory.first_observed.isoformat(),
                      memory.last_observed.isoformat(), data))

            # Save campaign memory
            for campaign_id, memory in self.memory_engine.campaign_memory.items():
                data = json.dumps(json.loads(memory.model_dump_json()), default=str)
                cursor.execute("""
                    INSERT OR REPLACE INTO campaign_memory
                    (campaign_id, campaign_name, first_observed, last_observed, memory_data)
                    VALUES (?, ?, ?, ?, ?)
                """, (campaign_id, memory.campaign_name, memory.first_observed.isoformat(),
                      memory.last_observed.isoformat(), data))

            # Save asset memory
            for asset_id, memory in self.memory_engine.asset_memory.items():
                data = json.dumps(json.loads(memory.model_dump_json()), default=str)
                cursor.execute("""
                    INSERT OR REPLACE INTO asset_memory
                    (asset_id, asset_name, first_exposure, last_exposure, memory_data)
                    VALUES (?, ?, ?, ?, ?)
                """, (asset_id, memory.asset_name,
                      memory.first_exposure.isoformat() if memory.first_exposure else None,
                      memory.last_exposure.isoformat() if memory.last_exposure else None, data))

            # Save infrastructure memory
            for infra_id, memory in self.memory_engine.infrastructure_memory.items():
                data = json.dumps(json.loads(memory.model_dump_json()), default=str)
                cursor.execute("""
                    INSERT OR REPLACE INTO infrastructure_memory
                    (infrastructure_id, first_observed, last_observed, memory_data)
                    VALUES (?, ?, ?, ?)
                """, (infra_id, memory.first_observed.isoformat(),
                      memory.last_observed.isoformat(), data))

            # Save pattern memory
            for pattern_id, memory in self.memory_engine.pattern_memory.items():
                data = json.dumps(json.loads(memory.model_dump_json()), default=str)
                cursor.execute("""
                    INSERT OR REPLACE INTO pattern_memory
                    (pattern_id, pattern_name, first_observed, last_observed, memory_data)
                    VALUES (?, ?, ?, ?, ?)
                """, (pattern_id, memory.pattern_name, memory.first_observed.isoformat(),
                      memory.last_observed.isoformat(), data))

            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[Memory] Failed to save memories: {e}")

    async def persist_memories(self) -> bool:
        """Save all memories to database."""
        self._save_memory_to_db()
        return True
