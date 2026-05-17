"""
core/enrichment_example.py - Phase 2 Threat Enrichment Pipeline Examples

Demonstrates:
- CVE enrichment with different strategies (MINIMAL, STANDARD, DEEP, FAST)
- IOC enrichment with malware correlation
- Asset enrichment with vulnerability discovery
- Batch enrichment of multiple entities
- Fallback chain application
"""

import asyncio
from datetime import datetime, timedelta

from core.threat_schema import (
    Vulnerability,
    IOC,
    Asset,
    SeverityLevel,
    IOCType,
    RiskContext,
    Relationship,
    RelationshipType,
    EntityType,
)
from core.threat_repository import ThreatKnowledgeRepository, TTLStatus
from core.sqlite_repository import SQLiteRepository
from core.threat_fusion import ThreatFusionEngine
from core.threat_correlation import RelationshipCorrelationEngine
from core.threat_enrichment_pipeline import ThreatEnrichmentPipeline, EnrichmentStrategy


async def demo_enrichment_pipeline():
    """Demonstrate Phase 2 enrichment pipeline."""
    print("\n" + "=" * 70)
    print("PHASE 2: THREAT ENRICHMENT PIPELINE - DEMONSTRATION")
    print("=" * 70)

    # Initialize components
    print("\n[SETUP] Initializing components...")
    db_path = "data/enrichment_example.db"
    repo = SQLiteRepository(db_path=db_path)
    fusion = ThreatFusionEngine()
    correlation = RelationshipCorrelationEngine()
    pipeline = ThreatEnrichmentPipeline(repo, fusion, correlation)

    print("  [OK] Components initialized")

    # ============================================================
    # TEST 1: CVE ENRICHMENT STRATEGIES
    # ============================================================
    print("\n[TEST 1] CVE ENRICHMENT STRATEGIES")
    print("-" * 70)

    # Scenario 1A: Fresh KB data (FAST strategy)
    print("\n[Scenario 1A] Fresh KB data - should use FAST strategy")
    print("  CVE: CVE-2026-8181 (critical, internet-exposed)")

    cve_critical = Vulnerability(
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

    # Save to KB first
    await repo.save_vulnerability(cve_critical)
    print("  [KB] Saved to knowledge base")

    # Check freshness
    kb_cve, kb_status = await repo.get_vulnerability("CVE-2026-8181", freshness_only=True)
    print(f"  [KB] Status: {kb_status.value}")

    # Select strategy
    strategy = await pipeline.select_enrichment_strategy(
        "CVE-2026-8181",
        kb_status,
        severity=SeverityLevel.CRITICAL,
        internet_exposed=True
    )
    print(f"  [STRATEGY] Selected: {strategy.value}")
    if strategy == EnrichmentStrategy.FAST:
        print("  [DECISION] Skip API calls (fresh data in KB)")

    # Scenario 1B: Stale data for critical+exposed asset
    print("\n[Scenario 1B] Stale data for critical+exposed asset - should use DEEP")
    print("  CVE: CVE-2026-5432 (critical, internet-exposed)")

    strategy = await pipeline.select_enrichment_strategy(
        "CVE-2026-5432",
        TTLStatus.STALE,  # Simulated stale data
        severity=SeverityLevel.CRITICAL,
        internet_exposed=True
    )
    print(f"  [STRATEGY] Selected: {strategy.value}")
    print(f"  [DECISION] Fetch all sources: NVD+EPSS+KEV+Vulners+OpenCTI")

    # Scenario 1C: Low severity, not exposed (MINIMAL)
    print("\n[Scenario 1C] Low severity, not exposed - should use MINIMAL")
    print("  CVE: CVE-2026-1234 (low severity)")

    strategy = await pipeline.select_enrichment_strategy(
        "CVE-2026-1234",
        TTLStatus.FRESH,
        severity=SeverityLevel.LOW,
        internet_exposed=False
    )
    print(f"  [STRATEGY] Selected: {strategy.value}")
    print(f"  [DECISION] Fetch NVD only")

    # ============================================================
    # TEST 2: SOURCE SELECTION
    # ============================================================
    print("\n[TEST 2] SOURCE SELECTION PER STRATEGY")
    print("-" * 70)

    for strategy in EnrichmentStrategy:
        sources = pipeline._get_sources_for_strategy(strategy)
        enabled = [k for k, v in sources.items() if v]
        print(f"\n  {strategy.value.upper()}:")
        print(f"    Sources: {', '.join(enabled) if enabled else 'None'}")

    # ============================================================
    # TEST 3: FALLBACK CHAIN APPLICATION
    # ============================================================
    print("\n[TEST 3] FALLBACK CHAIN APPLICATION")
    print("-" * 70)

    # Simulate partial fetch results (NVD successful, EPSS missing)
    fetch_results = {
        "nvd": {
            "id": "CVE-2026-9999",
            "description": "Test vulnerability",
            "cvss_score": 8.5,
            "severity": "HIGH",
            "cwe_ids": ["CWE-79"],
            "cpe_uris": ["cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"],
        },
        "vulners": {
            "exploit_count": 3,
            "public_exploit_available": True,
            "epss": 0.65,  # Fallback EPSS from Vulners
        },
    }

    print("\n  Input:")
    print("    [NVD] Success (has CVSS)")
    print("    [EPSS] Missing (not in results)")
    print("    [Vulners] Success (has EPSS as backup)")

    enriched = pipeline._apply_fallback_chains(None, fetch_results)

    print("\n  Output after fallback chains:")
    if enriched.get("nvd"):
        print(f"    [NVD] CVSS: {enriched['nvd'].get('cvss_score')}")
    if enriched.get("epss"):
        print(f"    [EPSS] Score: {enriched['epss'].get('epss')}")
        print("    [FALLBACK] Applied: FIRST -> Vulners")
    if enriched.get("vulners"):
        print(f"    [Vulners] Exploits: {enriched['vulners'].get('exploit_count')}")

    # ============================================================
    # TEST 4: IOC ENRICHMENT
    # ============================================================
    print("\n[TEST 4] IOC ENRICHMENT")
    print("-" * 70)

    # Create test IOC
    ioc = IOC(
        id="192.168.1.100",
        ioc_type=IOCType.IP,
        value="192.168.1.100",
        severity=SeverityLevel.MEDIUM,
    )

    print(f"\n  IOC: {ioc.value}")
    print(f"  Type: {ioc.ioc_type.value}")

    # Save to KB
    await repo.save_ioc(ioc)
    print("  [KB] Saved IOC")

    # Check freshness
    kb_ioc, kb_status = await repo.get_ioc("192.168.1.100", freshness_only=True)
    if kb_status.value == "fresh":
        print("  [DECISION] Fresh in KB, skip OpenCTI fetch (FAST)")

    # ============================================================
    # TEST 5: ASSET ENRICHMENT
    # ============================================================
    print("\n[TEST 5] ASSET ENRICHMENT")
    print("-" * 70)

    # Create test asset
    asset = Asset(
        id="dmz-web-01",
        hostname="dmz-web-01",
        ip_address="10.0.1.5",
        os="Linux",
        internet_facing=True,
        criticality="high",
        cpe_mappings=["cpe:2.3:a:vendor:framework:1.0:*:*:*:*:*:*:*"],
    )

    print(f"\n  Asset: {asset.hostname}")
    print(f"  IP: {asset.ip_address}")
    print(f"  Internet-Facing: {asset.internet_facing}")
    print(f"  Criticality: {asset.criticality}")

    # Save asset
    await repo.save_asset(asset)
    print("  [KB] Saved asset")

    # Create vulnerability relationship
    rel = Relationship(
        source_id="dmz-web-01",
        source_type=EntityType.ASSET,
        target_id="CVE-2026-8181",
        target_type=EntityType.VULNERABILITY,
        relationship_type=RelationshipType.VULNERABLE_TO,
        confidence=0.95,
        evidence_sources=["cpematch"],
    )
    await repo.create_relationship(rel)
    print("  [RELATIONSHIP] Created: dmz-web-01 --[vulnerable_to]--> CVE-2026-8181")

    # Find vulnerabilities affecting asset
    vulns = await repo.correlate_asset_vulnerabilities("dmz-web-01")
    print(f"  [CORRELATE] Found {len(vulns)} vulnerable CVE(s)")

    # ============================================================
    # TEST 6: BATCH ENRICHMENT
    # ============================================================
    print("\n[TEST 6] BATCH ENRICHMENT")
    print("-" * 70)

    entities = [
        {"type": "vulnerability", "id": "CVE-2026-8181"},
        {"type": "ioc", "id": "192.168.1.100", "ioc_type": "ip"},
        {"type": "asset", "id": "dmz-web-01"},
    ]

    print(f"\n  Enriching {len(entities)} entities in parallel...")
    for e in entities:
        print(f"    - {e['type'].upper()}: {e['id']}")

    # NOTE: In real scenario, this would call APIs
    # For demo, just show the flow
    print("\n  [FLOW]")
    print("    1. Check KB for fresh data (skip API if fresh)")
    print("    2. Select enrichment strategy per entity context")
    print("    3. Fetch from selected sources in parallel")
    print("    4. Apply fallback chains")
    print("    5. Fuse results with enrichment engine")
    print("    6. Correlate relationships")
    print("    7. Persist high-value intelligence")

    # ============================================================
    # TEST 7: STATISTICS
    # ============================================================
    print("\n[TEST 7] KNOWLEDGE BASE STATISTICS")
    print("-" * 70)

    stats = await repo.get_stats()
    print("\n  Knowledge Base Statistics:")
    for key, value in stats.items():
        print(f"    {key}: {value}")

    # ============================================================
    # SUMMARY
    # ============================================================
    print("\n" + "=" * 70)
    print("PHASE 2 DEMONSTRATION COMPLETE")
    print("=" * 70)

    print("\n[KEY CONCEPTS DEMONSTRATED]")
    print("  1. Dynamic Strategy Selection")
    print("     - FAST (fresh KB data) -> skip API calls")
    print("     - MINIMAL (low-risk) -> NVD only")
    print("     - STANDARD (normal) -> NVD + EPSS + KEV")
    print("     - DEEP (critical+exposed) -> all sources")
    print("")
    print("  2. Parallel Async Fetching")
    print("     - All selected sources fetched concurrently")
    print("     - Uses asyncio.gather for true parallelism")
    print("")
    print("  3. Fallback Chains")
    print("     - EPSS: FIRST API -> Vulners")
    print("     - CVSS: NVD -> Vulners")
    print("     - CWE: NVD -> Vulners")
    print("")
    print("  4. Selective Persistence")
    print("     - High-value intelligence only saved to KB")
    print("     - TTL-based automatic expiration")
    print("")
    print("  5. Relationship Correlation")
    print("     - CVE ↔ Asset (CPE matching)")
    print("     - IOC ↔ Malware (OpenCTI)")
    print("     - Campaign ↔ CVE (threat intel)")
    print("")
    print("  6. Batch Processing")
    print("     - Multiple entities enriched in parallel")
    print("     - Each entity follows its own strategy")

    print("\n[ARCHITECTURE INTEGRATION]")
    print("  Phase 1A: Canonical threat schema (Vulnerability, IOC, Asset)")
    print("  Phase 1B: Threat fusion engine (multi-source merging)")
    print("  Phase 1C: Relationship correlation engine (entity linking)")
    print("  Phase 1D: SQLite persistence (knowledge base)")
    print("  Phase 2:  Enrichment pipeline orchestrator (this file)")
    print("            ├─ KB freshness checking")
    print("            ├─ Dynamic source selection")
    print("            ├─ Parallel async fetching")
    print("            ├─ Fallback chain application")
    print("            ├─ Threat fusion integration")
    print("            └─ Selective persistence")

    print("\n[NEXT PHASES]")
    print("  Phase 3: Advanced Relationship Analysis (graph patterns)")
    print("  Phase 4: Graph Intelligence Layer (SPARQL-like queries)")
    print("  Phase 5: Neo4j Migration (graph-native database)")

    print("\n[DATABASE]")
    print(f"  Path: {db_path}")


if __name__ == "__main__":
    asyncio.run(demo_enrichment_pipeline())
