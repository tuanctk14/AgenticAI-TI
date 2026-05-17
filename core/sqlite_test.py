"""
core/sqlite_test.py - Test SQLite Repository Implementation

Demonstrates:
- Saving and retrieving entities
- TTL management
- Relationship creation and queries
- Statistics
"""

import asyncio
import os
from core.threat_schema import (
    Vulnerability,
    Asset,
    IOC,
    IOCType,
    SeverityLevel,
    RiskContext,
    Relationship,
    RelationshipType,
    EntityType,
)
from core.sqlite_repository import SQLiteRepository


async def test_sqlite_repository():
    """Test SQLite repository functionality."""
    print("\n" + "=" * 70)
    print("SQLITE REPOSITORY - FUNCTIONALITY TEST")
    print("=" * 70)

    # Use test database
    db_path = "data/test_threat_knowledge.db"

    # Clean up if exists
    if os.path.exists(db_path):
        os.remove(db_path)

    repo = SQLiteRepository(db_path=db_path)

    print("\n[TEST 1] ENTITY PERSISTENCE")
    print("-" * 70)

    # Create test entities
    vuln = Vulnerability(
        id="CVE-2026-8181",
        description="Critical RCE vulnerability",
        severity=SeverityLevel.CRITICAL,
        cpe_uris=["cpe:2.3:a:vendor:framework:1.0:*:*:*:*:*:*:*"],
        risk_context=RiskContext(
            cvss_score=9.8,
            epss_score=0.97,
            kev_listed=True,
            public_exploit_available=True,
        ),
    )

    asset = Asset(
        id="dmz-web-01",
        hostname="dmz-web-01",
        ip_address="10.0.1.5",
        internet_facing=True,
        criticality="high",
        cpe_mappings=["cpe:2.3:a:vendor:framework:1.0:*:*:*:*:*:*:*"],
    )

    ioc = IOC(
        id="192.168.1.100",
        ioc_type=IOCType.IP,
        value="192.168.1.100",
    )

    # Save entities
    print("  Saving vulnerability...")
    vuln_saved = await repo.save_vulnerability(vuln)
    print(f"    Result: {vuln_saved}")

    print("  Saving asset...")
    asset_saved = await repo.save_asset(asset)
    print(f"    Result: {asset_saved}")

    print("  Saving IOC...")
    ioc_saved = await repo.save_ioc(ioc)
    print(f"    Result: {ioc_saved}")

    # Retrieve entities
    print("\n  Retrieving vulnerability...")
    retrieved_vuln, status = await repo.get_vulnerability("CVE-2026-8181")
    print(f"    Retrieved: {retrieved_vuln is not None}")
    print(f"    Status: {status.value}")
    print(f"    CVSS: {retrieved_vuln.risk_context.cvss_score if retrieved_vuln else 'N/A'}")

    print("  Retrieving asset...")
    retrieved_asset, status = await repo.get_asset("dmz-web-01")
    print(f"    Retrieved: {retrieved_asset is not None}")
    print(f"    Hostname: {retrieved_asset.hostname if retrieved_asset else 'N/A'}")

    print("  Retrieving IOC...")
    retrieved_ioc, status = await repo.get_ioc("192.168.1.100")
    print(f"    Retrieved: {retrieved_ioc is not None}")
    print(f"    Type: {retrieved_ioc.ioc_type.value if retrieved_ioc else 'N/A'}")

    print("\n[TEST 2] RELATIONSHIP CREATION & QUERIES")
    print("-" * 70)

    # Create relationship
    rel = Relationship(
        source_id="dmz-web-01",
        source_type=EntityType.ASSET,
        target_id="CVE-2026-8181",
        target_type=EntityType.VULNERABILITY,
        relationship_type=RelationshipType.VULNERABLE_TO,
        confidence=0.95,
        evidence_sources=["cpematch"],
    )

    print("  Creating relationship...")
    rel_created = await repo.create_relationship(rel)
    print(f"    Result: {rel_created}")

    # Query relationships
    print("\n  Querying relationships from dmz-web-01...")
    relationships = await repo.get_relationships("dmz-web-01")
    print(f"    Found: {len(relationships)}")
    for r in relationships:
        print(f"      {r.source_id} --[{r.relationship_type.value}]--> {r.target_id}")

    print("\n  Correlating asset vulnerabilities...")
    vuln_for_asset = await repo.correlate_asset_vulnerabilities("dmz-web-01")
    print(f"    Found: {len(vuln_for_asset)} CVE(s)")
    for v in vuln_for_asset:
        print(f"      {v.id}")

    print("\n[TEST 3] FRESHNESS & TTL MANAGEMENT")
    print("-" * 70)

    print("  Checking freshness of CVE-2026-8181...")
    freshness = await repo.check_freshness("CVE-2026-8181", EntityType.VULNERABILITY)
    print(f"    Status: {freshness.value}")

    print("\n  Refreshing CVE-2026-8181 TTL (48 hours)...")
    refreshed = await repo.refresh_entity("CVE-2026-8181", EntityType.VULNERABILITY, 48)
    print(f"    Result: {refreshed}")

    print("\n  Checking freshness after refresh...")
    freshness = await repo.check_freshness("CVE-2026-8181", EntityType.VULNERABILITY)
    print(f"    Status: {freshness.value}")

    print("\n[TEST 4] BATCH OPERATIONS")
    print("-" * 70)

    # Create multiple entities
    batch_vulns = [
        Vulnerability(
            id=f"CVE-2026-{1000+i}",
            description=f"Test vulnerability {i}",
            severity=SeverityLevel.HIGH,
        )
        for i in range(5)
    ]

    print(f"  Saving {len(batch_vulns)} vulnerabilities...")
    count = await repo.batch_save_entities(batch_vulns)
    print(f"    Saved: {count}")

    print("\n[TEST 5] STATISTICS")
    print("-" * 70)

    print("  Getting knowledge base statistics...")
    stats = await repo.get_stats()
    for key, value in stats.items():
        print(f"    {key}: {value}")

    print("\n[TEST 6] HEALTH CHECK")
    print("-" * 70)

    print("  Running health check...")
    healthy = await repo.health_check()
    print(f"    Result: {'HEALTHY' if healthy else 'UNHEALTHY'}")

    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print("\n[SQLite Repository Tests]:")
    print("  * Entity persistence (CVE, Asset, IOC)")
    print("  * Entity retrieval and freshness checks")
    print("  * Relationship creation and queries")
    print("  * CVE-Asset correlation via relationships")
    print("  * TTL management and refresh")
    print("  * Batch operations")
    print("  * Statistics and health checks")
    print("\nDatabase: " + db_path)

    # Cleanup
    # os.remove(db_path)


if __name__ == "__main__":
    asyncio.run(test_sqlite_repository())
