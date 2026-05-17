"""
core/neo4j_migration_example.py - Phase 5 Neo4j Migration Example

Demonstrates complete backward compatibility:
- Agents don't need to change ANY code
- Just swap repository implementation (SQLite -> Neo4j)
- All methods work identically
- Graph-native performance for complex queries

Key insight: The repository pattern enables seamless database migrations.
No business logic changes, no agent code changes, just swap the backend.
"""

import asyncio
from datetime import datetime

from core.threat_schema import (
    Vulnerability,
    Asset,
    IOC,
    Relationship,
    RelationshipType,
    EntityType,
    SeverityLevel,
    RiskContext,
    IOCType,
)

# === CRITICAL: This is the ONLY line that differs between implementations ===
# In production, just swap which repository you import
# Agents don't care - they use ThreatKnowledgeRepository interface

from core.sqlite_repository import SQLiteRepository as RepositoryImpl
# from core.neo4j_repository import Neo4jRepository as RepositoryImpl


async def demo_repository_abstraction():
    """
    Demonstrate Phase 5: Neo4j Migration with zero agent code changes.

    This example shows:
    1. Repository abstraction allows easy backend switching
    2. Agents use ThreatKnowledgeRepository interface
    3. No business logic changes needed
    4. Both SQLite and Neo4j implementations work identically
    5. Graph-native queries available in Neo4j
    """

    print("\n" + "=" * 70)
    print("PHASE 5: NEO4J MIGRATION - ZERO AGENT CODE CHANGES")
    print("=" * 70)

    print("\n[ARCHITECTURE] Repository Pattern Benefits")
    print("-" * 70)
    print("""
    +--------+
    | Agents |
    +----+---+
         |
         v
    +--------------------+
    | Repository         |  <-- Interface contract
    | Interface          |      (ThreatKnowledgeRepository)
    +--------+-----------+
             |
      +------+------+
      |             |
      v             v
    SQLite        Neo4j  <-- Implementations (agents don't care)
    (Phase 1D)    (Phase 5)
    """)

    # Initialize repository (swap RepositoryImpl to switch backends)
    print("\n[SETUP] Initializing repository...")
    repo = RepositoryImpl(db_path="data/migration_example.db")
    print(f"  [OK] Using {repo.__class__.__name__}")

    # ============================================================
    # PART 1: CREATE TEST DATA (Agent doesn't care about backend)
    # ============================================================
    print("\n[PART 1] Creating Test Data")
    print("-" * 70)

    print("\nCreating vulnerability objects...")
    vuln1 = Vulnerability(
        id="CVE-2024-1234",
        description="Critical RCE in web framework",
        severity=SeverityLevel.CRITICAL,
        cpe_uris=["cpe:2.3:a:framework:web:1.0:*:*:*:*:*:*:*"],
        risk_context=RiskContext(
            cvss_score=9.8,
            epss_score=0.95,
            kev_listed=True,
            public_exploit_available=True,
            threat_score=98,
        ),
    )

    vuln2 = Vulnerability(
        id="CVE-2024-5678",
        description="SQL injection in database connector",
        severity=SeverityLevel.HIGH,
        cpe_uris=["cpe:2.3:a:database:connector:2.0:*:*:*:*:*:*:*"],
        risk_context=RiskContext(
            cvss_score=8.5,
            epss_score=0.80,
            kev_listed=False,
            public_exploit_available=True,
            threat_score=85,
        ),
    )

    print("Creating asset objects...")
    asset1 = Asset(
        id="web-server-01",
        hostname="web-server-01",
        ip_address="10.0.1.10",
        os="Linux",
        internet_facing=True,
        criticality="high",
        cpe_mappings=["cpe:2.3:a:framework:web:1.0:*:*:*:*:*:*:*"],
    )

    asset2 = Asset(
        id="database-01",
        hostname="database-01",
        ip_address="10.1.1.20",
        os="Linux",
        internet_facing=False,
        criticality="critical",
        cpe_mappings=["cpe:2.3:a:database:connector:2.0:*:*:*:*:*:*:*"],
    )

    print("Creating IOC objects...")
    ioc1 = IOC(
        id="c2.malicious.com",
        ioc_type=IOCType.DOMAIN,
        value="c2.malicious.com",
        severity=SeverityLevel.CRITICAL,
    )

    # Save to repository (agent doesn't know/care if it's SQLite or Neo4j)
    print("\n[SAVE] Saving to repository (implementation-agnostic)...")
    await repo.save_vulnerability(vuln1)
    await repo.save_vulnerability(vuln2)
    await repo.save_asset(asset1)
    await repo.save_asset(asset2)
    await repo.save_ioc(ioc1)
    print("  [OK] All entities saved")

    # ============================================================
    # PART 2: RETRIEVE DATA (Works identically on SQLite and Neo4j)
    # ============================================================
    print("\n[PART 2] Retrieving Data")
    print("-" * 70)

    print("\nRetrieving vulnerability...")
    vuln_retrieved, status = await repo.get_vulnerability("CVE-2024-1234")
    print(f"  CVE: {vuln_retrieved.id if vuln_retrieved else 'Not found'}")
    print(f"  CVSS: {vuln_retrieved.risk_context.cvss_score if vuln_retrieved else 'N/A'}")
    print(f"  Status: {status.value}")

    print("\nRetrieving asset...")
    asset_retrieved, status = await repo.get_asset("web-server-01")
    print(f"  Hostname: {asset_retrieved.hostname if asset_retrieved else 'Not found'}")
    print(f"  IP: {asset_retrieved.ip_address if asset_retrieved else 'N/A'}")

    # ============================================================
    # PART 3: CREATE RELATIONSHIPS (Graph structure)
    # ============================================================
    print("\n[PART 3] Creating Relationships")
    print("-" * 70)

    print("\nCreating vulnerability relationships...")
    rel1 = Relationship(
        source_id="web-server-01",
        source_type=EntityType.ASSET,
        target_id="CVE-2024-1234",
        target_type=EntityType.VULNERABILITY,
        relationship_type=RelationshipType.VULNERABLE_TO,
        confidence=0.95,
        evidence_sources=["cpematch"],
    )

    rel2 = Relationship(
        source_id="database-01",
        source_type=EntityType.ASSET,
        target_id="CVE-2024-5678",
        target_type=EntityType.VULNERABILITY,
        relationship_type=RelationshipType.VULNERABLE_TO,
        confidence=0.95,
        evidence_sources=["cpematch"],
    )

    rel3 = Relationship(
        source_id="web-server-01",
        source_type=EntityType.ASSET,
        target_id="database-01",
        target_type=EntityType.ASSET,
        relationship_type=RelationshipType.REACHABLE_TO,
        confidence=0.90,
        evidence_sources=["network_topology"],
    )

    await repo.create_relationship(rel1)
    await repo.create_relationship(rel2)
    await repo.create_relationship(rel3)
    print("  [OK] Relationships created")

    # ============================================================
    # PART 4: GRAPH QUERIES (Key strength of Neo4j)
    # ============================================================
    print("\n[PART 4] Graph Queries (Works on both SQLite and Neo4j)")
    print("-" * 70)

    print("\n[QUERY 1] Find all vulnerabilities for asset...")
    vulns = await repo.correlate_asset_vulnerabilities("web-server-01")
    print(f"  Found {len(vulns)} vulnerabilities:")
    for v in vulns:
        print(f"    - {v.id}: {v.description[:50]}...")

    print("\n[QUERY 2] Find all relationships from asset...")
    rels = await repo.get_relationships("web-server-01")
    print(f"  Found {len(rels)} relationships:")
    for r in rels:
        print(f"    - {r.source_id} --[{r.relationship_type.value}]--> {r.target_id}")

    # ============================================================
    # PART 5: TTL MANAGEMENT (Works on both)
    # ============================================================
    print("\n[PART 5] TTL Management")
    print("-" * 70)

    print("\n[CHECK] Checking freshness...")
    status = await repo.check_freshness("CVE-2024-1234", EntityType.VULNERABILITY)
    print(f"  CVE-2024-1234 status: {status.value}")

    print("\n[REFRESH] Refreshing TTL...")
    refreshed = await repo.refresh_entity("CVE-2024-1234", EntityType.VULNERABILITY, 48)
    print(f"  Refresh result: {refreshed}")

    # ============================================================
    # PART 6: STATISTICS (Works on both)
    # ============================================================
    print("\n[PART 6] Statistics")
    print("-" * 70)

    stats = await repo.get_stats()
    print("\n[KB STATS]")
    for key, value in stats.items():
        print(f"  {key}: {value}")

    # ============================================================
    # PART 7: HEALTH CHECK (Works on both)
    # ============================================================
    print("\n[PART 7] Health Check")
    print("-" * 70)

    healthy = await repo.health_check()
    print(f"\n[HEALTH] Repository status: {'HEALTHY' if healthy else 'UNHEALTHY'}")

    # ============================================================
    # SUMMARY
    # ============================================================
    print("\n" + "=" * 70)
    print("PHASE 5 MIGRATION DEMONSTRATION COMPLETE")
    print("=" * 70)

    print("""
[KEY INSIGHT: Repository Pattern Enables Seamless Migration]

The repository abstraction (ThreatKnowledgeRepository) enables:

1. ZERO AGENT CODE CHANGES
   - Agents only use repository interface
   - Swap SQLite -> Neo4j by changing one import
   - All business logic continues to work

2. IDENTICAL SEMANTICS
   - save_vulnerability() works the same
   - get_vulnerability() returns identical Vulnerability object
   - create_relationship() creates relationships identically
   - All agents see no difference

3. DATABASE-AGNOSTIC DESIGN
   Phase 1A: Canonical Schema (Pydantic models)
   Phase 1B: Threat Fusion (business logic)
   Phase 1C: Correlation Engine (algorithms)
   Phase 1D: SQLite Repository (storage)
   Phase 2:  Enrichment Pipeline (data ingestion)
   Phase 3:  Graph Analyzer (graph algorithms)
   Phase 4:  Intelligence Layer (queries)
   Phase 5:  Neo4j Repository (storage upgrade) <-- Just swap this

4. PERFORMANCE BENEFITS OF NEO4J
   - Graph-native relationship queries
   - Native support for transitive reasoning
   - Cypher query language for complex patterns
   - Built-in algorithms (PageRank, community detection)
   - Horizontal scaling for large graphs
   - Real-time relationship updates
   - ACID transactions

5. MIGRATION PATH
   Step 1: Create Neo4jRepository (compatible interface)
   Step 2: Run tests with Neo4j backend
   Step 3: Swap import statement
   Step 4: Deploy - agents unaffected
    """)

    print("\n[MIGRATION OPTIONS]")
    print("  Option 1: SQLite for small deployments (< 1M relationships)")
    print("  Option 2: Neo4j for production (> 1M relationships)")
    print("  Option 3: Hybrid - SQLite cache + Neo4j backend")
    print("  Option 4: Multi-backend - Route queries to appropriate store")

    print("\n[NEXT STEPS]")
    print("  1. Deploy Neo4j cluster")
    print("  2. Run Neo4jRepository tests")
    print("  3. Migrate data (SQLite -> Neo4j)")
    print("  4. Swap repository import")
    print("  5. No agent changes required")

    print("\n[DATABASE]")
    print(f"  Repository type: {repo.__class__.__name__}")
    print(f"  Backend: {'SQLite' if 'SQLite' in repo.__class__.__name__ else 'Neo4j'}")
    print(f"  Stats: {stats}")


if __name__ == "__main__":
    asyncio.run(demo_repository_abstraction())
