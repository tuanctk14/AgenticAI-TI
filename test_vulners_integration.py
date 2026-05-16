#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test Vulners integration"""
import asyncio
from tools.providers import VulnersProvider
from tools.enrichment.orchestrator import EnrichmentOrchestrator

async def test_vulners():
    """Test Vulners provider directly"""
    print("Testing Vulners Provider...")
    vulners = VulnersProvider()

    cve_id = "CVE-2021-44228"
    result = await vulners.fetch_with_timeout(cve_id)

    if result.success:
        print(f"✓ {cve_id}")
        data = result.data
        print(f"  - Public Exploit: {data.get('public_exploit_available')}")
        print(f"  - Exploit Count: {data.get('exploit_count')}")
        print(f"  - Sources: {data.get('exploit_sources')[:3] if data.get('exploit_sources') else 'None'}")
    else:
        print(f"✗ {cve_id}: {result.error}")

async def test_orchestrator():
    """Test enrichment orchestrator with Vulners"""
    print("\nTesting Enrichment Orchestrator...")
    orchestrator = EnrichmentOrchestrator()

    cve_id = "CVE-2021-44228"
    unified = await orchestrator.enrich_cve(cve_id)

    print(f"CVE: {unified.cve_id}")
    print(f"  - EPSS: {unified.epss.score if unified.epss else 'N/A'}")
    print(f"  - KEV Listed: {unified.kev.listed if unified.kev else 'N/A'}")
    print(f"  - Vulners Exploits: {unified.vulncheck.exploit_count if unified.vulncheck else 0}")
    print(f"  - Risk Score: {unified.unified_risk_score:.2f}")
    print(f"  - Summary: {unified.enrichment_summary}")

if __name__ == "__main__":
    asyncio.run(test_vulners())
    asyncio.run(test_orchestrator())
