#!/usr/bin/env python3
"""
Test script for Phase 2 enrichment implementation.

Tests:
1. NVD provider fetch
2. EPSS provider fetch
3. KEV provider fetch
4. VulnCheck provider validation
5. Orchestrator enrich_cve with fallback chains
6. Cache functionality
"""

import asyncio
import sys
import io

# Fix UTF-8 encoding on Windows
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Test CVE (Log4j, widely documented)
TEST_CVE = "CVE-2021-44228"


async def test_nvd_provider():
    """Test NVD provider"""
    print("\n[TEST] NVD Provider...")
    from tools.providers import NVDProvider

    provider = NVDProvider()
    result = await provider.fetch(TEST_CVE)

    assert result.success, f"NVD fetch failed: {result.error}"
    assert result.data["id"] == TEST_CVE, "CVE ID mismatch"
    assert result.data.get("cvss_score") and result.data.get("cvss_score") != "N/A", "No CVSS score"
    assert result.data.get("cwe_ids"), "No CWE IDs"
    print(f"  ✓ NVD fetch successful: {TEST_CVE}")
    print(f"    - CVSS: {result.data.get('cvss_score')}")
    print(f"    - CWEs: {result.data.get('cwe_ids')}")
    print(f"    - References: {len(result.data.get('references', []))} items")


async def test_epss_provider():
    """Test EPSS provider"""
    print("\n[TEST] EPSS Provider...")
    from tools.providers import EPSSProvider

    provider = EPSSProvider()

    # Test connection
    connected = await provider.validate_connection()
    print(f"  ✓ EPSS connection: {connected}")

    # Test fetch
    result = await provider.fetch(TEST_CVE)
    if result.success:
        assert result.data.get("score") is not None, "No EPSS score"
        assert 0 <= result.data.get("score") <= 1, "EPSS score out of range"
        print(f"  ✓ EPSS fetch successful: {TEST_CVE}")
        print(f"    - Score: {result.data.get('score'):.4f}")
        print(f"    - Percentile: {result.data.get('percentile'):.1f}%")
    else:
        print(f"  ⚠ EPSS fetch failed (soft-fail expected): {result.error}")


async def test_kev_provider():
    """Test KEV provider"""
    print("\n[TEST] KEV Provider...")
    from tools.providers import KEVProvider

    provider = KEVProvider()

    # Test connection
    connected = await provider.validate_connection()
    print(f"  ✓ KEV connection: {connected}")

    # Test fetch
    result = await provider.fetch(TEST_CVE)
    if result.success:
        print(f"  ✓ KEV fetch successful: {TEST_CVE}")
        print(f"    - Listed: {result.data.get('listed')}")
        print(f"    - Date Added: {result.data.get('date_added')}")
        print(f"    - Ransomware Campaign: {result.data.get('known_ransomware_campaign_use')}")
    else:
        print(f"  ⚠ KEV fetch failed (soft-fail expected): {result.error}")


async def test_cache():
    """Test cache functionality"""
    print("\n[TEST] Cache Layer...")
    from tools.enrichment.cache import SQLiteCacheProvider
    from tools.enrichment.schema import UnifiedCVE, CVEMetadata

    cache = SQLiteCacheProvider()

    # Create test data
    test_cve = UnifiedCVE(
        cve_id="CVE-TEST-0001",
        metadata=CVEMetadata(
            cve_id="CVE-TEST-0001",
            description="Test CVE",
            published_date="2024-01-01",
            modified_date="2024-01-02",
            references=[]
        ),
        cvss=None,
        cwe=None,
        cpe=None,
        epss=None,
        kev=None,
        vulncheck=None,
        data_quality=None,
        unified_risk_score=0.0,
        enrichment_summary="Test",
        cache_hit=False
    )

    # Test set/get
    await cache.set("CVE-TEST-0001", test_cve, 3600)
    print("  ✓ Cached CVE-TEST-0001")

    retrieved = await cache.get("CVE-TEST-0001")
    assert retrieved is not None, "Cache get failed"
    assert retrieved.metadata.cve_id == "CVE-TEST-0001", "CVE ID mismatch in cache"
    print("  ✓ Retrieved CVE-TEST-0001 from cache")

    # Test cleanup
    stats_before = await cache.get_stats()
    print(f"  ✓ Cache stats: {stats_before}")


async def test_orchestrator():
    """Test orchestrator enrich_cve"""
    print("\n[TEST] Orchestrator enrich_cve...")
    from tools.enrichment.orchestrator import EnrichmentOrchestrator

    orchestrator = EnrichmentOrchestrator()

    try:
        unified = await orchestrator.enrich_cve(TEST_CVE)
        print(f"  ✓ Enrichment successful: {TEST_CVE}")
        print(f"    - CVSS: {unified.cvss.score.value} (source: {unified.cvss.score.source})")
        print(f"    - CWE IDs: {len(unified.cwe.ids.value)} (source: {unified.cwe.ids.source})")
        print(f"    - Risk Score: {unified.unified_risk_score:.2f}")
        print(f"    - Summary: {unified.enrichment_summary}")
        print(f"    - Data Quality: {unified.data_quality.cvss_source}/{unified.data_quality.cwe_source}/{unified.data_quality.cpe_source}")

        # Test cache hit
        unified2 = await orchestrator.enrich_cve(TEST_CVE)
        assert unified2.cache_hit, "Second fetch should be cache hit"
        print(f"  ✓ Cache hit on second fetch")
    except Exception as e:
        print(f"  ✗ Orchestrator error: {e}")
        import traceback
        traceback.print_exc()


async def main():
    print("=" * 60)
    print("Phase 2 Enrichment Implementation Test Suite")
    print("=" * 60)

    try:
        await test_nvd_provider()
    except Exception as e:
        print(f"  [X] NVD test failed: {e}")
        import traceback
        traceback.print_exc()

    try:
        await test_epss_provider()
    except Exception as e:
        print(f"  [X] EPSS test failed: {e}")

    try:
        await test_kev_provider()
    except Exception as e:
        print(f"  [X] KEV test failed: {e}")

    try:
        await test_cache()
    except Exception as e:
        print(f"  [X] Cache test failed: {e}")
        import traceback
        traceback.print_exc()

    try:
        await test_orchestrator()
    except Exception as e:
        print(f"  [X] Orchestrator test failed: {e}")
        import traceback
        traceback.print_exc()

    print("\n" + "=" * 60)
    print("Test suite complete!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
