"""
core/correlation_example.py - Example: Relationship Correlation Engine

Demonstrates:
- CVE-to-Asset correlation (CPE matching)
- IOC-to-Malware correlation
- Campaign-to-CVE correlation
- Attack path discovery
"""

import asyncio
from core.threat_schema import (
    Vulnerability,
    Asset,
    IOC,
    IOCType,
    SeverityLevel,
    RiskContext,
)
from core.threat_correlation import RelationshipCorrelationEngine


# Example data

CVE_2026_8181 = Vulnerability(
    id="CVE-2026-8181",
    description="Critical RCE in framework X",
    severity=SeverityLevel.CRITICAL,
    cpe_uris=["cpe:2.3:a:vendor:framework:1.0:*:*:*:*:*:*:*"],
    risk_context=RiskContext(cvss_score=9.8),
)

CVE_2026_1234 = Vulnerability(
    id="CVE-2026-1234",
    description="SQL injection in CMS",
    severity=SeverityLevel.HIGH,
    cpe_uris=["cpe:2.3:a:cms_vendor:cms:2.0:*:*:*:*:*:*:*"],
    risk_context=RiskContext(cvss_score=7.5),
)

ASSET_DMZ_WEB01 = Asset(
    id="dmz-web-01",
    hostname="dmz-web-01",
    ip_address="10.0.1.5",
    os="Ubuntu 20.04",
    internet_facing=True,
    criticality="high",
    cpe_mappings=[
        "cpe:2.3:a:vendor:framework:1.0:*:*:*:*:*:*:*",  # Matches CVE-2026-8181
    ],
)

ASSET_INTERNAL_DB = Asset(
    id="internal-db-01",
    hostname="internal-db-01",
    ip_address="10.1.0.10",
    os="Ubuntu 20.04",
    internet_facing=False,
    criticality="critical",
    cpe_mappings=[
        "cpe:2.3:a:cms_vendor:cms:2.0:*:*:*:*:*:*:*",  # Matches CVE-2026-1234
    ],
)

IOC_IP_MALWARE = IOC(
    id="192.168.1.100",
    ioc_type=IOCType.IP,
    value="192.168.1.100",
)

IOC_DOMAIN_C2 = IOC(
    id="malware-c2.example.com",
    ioc_type=IOCType.DOMAIN,
    value="malware-c2.example.com",
)

MALWARE_DATA = [
    {
        "id": "malware-ransomware-x",
        "name": "Ransomware-X",
        "iocs": ["192.168.1.100", "malware-c2.example.com"],
        "confidence": 0.95,
    },
]

CAMPAIGN_DATA = [
    {
        "id": "campaign-targeted-finance",
        "name": "Targeted Finance Campaign",
        "targeted_cves": ["CVE-2026-8181", "CVE-2026-1234"],
        "confidence": 0.9,
    },
]

NETWORK_DATA = {
    "reachable_assets": {
        "internal-db-01": {
            "confidence": 0.95,
            "type": "lateral_movement",
            "hops": 1,
        }
    }
}


async def example_cve_asset_correlation():
    """Example: CVE-to-Asset correlation via CPE matching."""
    print("\n" + "=" * 70)
    print("RELATIONSHIP CORRELATION - CVE TO ASSET")
    print("=" * 70)

    engine = RelationshipCorrelationEngine()

    print("\n[INPUTS]:")
    print(f"  CVE: {CVE_2026_8181.id}")
    print(f"    CPE: {CVE_2026_8181.cpe_uris[0]}")
    print(f"\n  Asset: {ASSET_DMZ_WEB01.id}")
    print(f"    CPE: {ASSET_DMZ_WEB01.cpe_mappings[0]}")

    print("\n[CORRELATING]...")
    relationships = await engine.correlate_cve_to_assets(
        CVE_2026_8181,
        [ASSET_DMZ_WEB01, ASSET_INTERNAL_DB],
    )

    print(f"\n[RELATIONSHIPS FOUND]: {len(relationships)}")
    for rel in relationships:
        print(f"  {rel.source_id} --[vulnerable_to]--> {rel.target_id}")
        print(f"    Confidence: {rel.confidence:.2f}")
        print(f"    Match Type: {rel.context.get('match_type')}")

    return relationships


async def example_ioc_malware_correlation():
    """Example: IOC-to-Malware correlation."""
    print("\n" + "=" * 70)
    print("RELATIONSHIP CORRELATION - IOC TO MALWARE")
    print("=" * 70)

    engine = RelationshipCorrelationEngine()

    print("\n[INPUTS]:")
    print(f"  IOCs: {IOC_IP_MALWARE.value}, {IOC_DOMAIN_C2.value}")
    print(f"\n  Malware: {MALWARE_DATA[0]['name']}")
    print(f"    IOCs: {MALWARE_DATA[0]['iocs']}")

    print("\n[CORRELATING]...")
    ip_rels = await engine.correlate_ioc_to_malware(
        IOC_IP_MALWARE, MALWARE_DATA
    )
    domain_rels = await engine.correlate_ioc_to_malware(
        IOC_DOMAIN_C2, MALWARE_DATA
    )
    all_rels = ip_rels + domain_rels

    print(f"\n[RELATIONSHIPS FOUND]: {len(all_rels)}")
    for rel in all_rels:
        print(f"  {rel.source_id} --[linked_to]--> {rel.target_id}")
        print(f"    Confidence: {rel.confidence:.2f}")

    return all_rels


async def example_campaign_cve_correlation():
    """Example: Campaign-to-CVE correlation."""
    print("\n" + "=" * 70)
    print("RELATIONSHIP CORRELATION - CAMPAIGN TO CVE")
    print("=" * 70)

    engine = RelationshipCorrelationEngine()

    print("\n[INPUTS]:")
    print(f"  Campaign: {CAMPAIGN_DATA[0]['name']}")
    print(f"    Target CVEs: {CAMPAIGN_DATA[0]['targeted_cves']}")
    print(f"\n  CVEs: {CVE_2026_8181.id}, {CVE_2026_1234.id}")

    print("\n[CORRELATING]...")
    relationships = await engine.correlate_campaign_to_cves(
        CAMPAIGN_DATA[0]["id"],
        CAMPAIGN_DATA[0],
        [CVE_2026_8181, CVE_2026_1234],
    )

    print(f"\n[RELATIONSHIPS FOUND]: {len(relationships)}")
    for rel in relationships:
        print(f"  {rel.source_id} --[exploits]--> {rel.target_id}")
        print(f"    Confidence: {rel.confidence:.2f}")

    return relationships


async def example_attack_paths():
    """Example: Attack path discovery."""
    print("\n" + "=" * 70)
    print("RELATIONSHIP CORRELATION - ATTACK PATH DISCOVERY")
    print("=" * 70)

    engine = RelationshipCorrelationEngine()

    # Build relationships manually for demo
    print("\n[SETUP]:")
    print("  Building relationship graph...")

    # CVE-asset relationships
    cve_asset_rels = await engine.correlate_cve_to_assets(
        CVE_2026_8181, [ASSET_DMZ_WEB01, ASSET_INTERNAL_DB]
    )
    cve2_asset_rels = await engine.correlate_cve_to_assets(
        CVE_2026_1234, [ASSET_INTERNAL_DB]
    )

    # Asset reachability
    reachability_rel = await engine.correlate_asset_reachability(
        ASSET_DMZ_WEB01, ASSET_INTERNAL_DB, NETWORK_DATA
    )

    all_rels = cve_asset_rels + cve2_asset_rels
    if reachability_rel:
        all_rels.append(reachability_rel)

    print(f"  Total relationships: {len(all_rels)}")

    print("\n[FINDING ATTACK PATHS]...")
    # Find paths to CVE-2026-8181
    paths = await engine.find_attack_paths(
        CVE_2026_8181,
        all_rels,
        [ASSET_DMZ_WEB01, ASSET_INTERNAL_DB],
    )

    print(f"\n[ATTACK PATHS FOUND]: {len(paths)}")
    for i, path in enumerate(paths, 1):
        print(f"\n  Path {i}:")
        print(f"    Type: {path['type'].upper()}")
        print(f"    Risk: {path['risk']}")
        print(f"    Steps: {' -> '.join(path['steps'])}")


async def example_bulk_correlation():
    """Example: Bulk correlation of all entities."""
    print("\n" + "=" * 70)
    print("RELATIONSHIP CORRELATION - BULK CORRELATION")
    print("=" * 70)

    engine = RelationshipCorrelationEngine()

    print("\n[INPUTS]:")
    print(f"  CVEs: 2")
    print(f"  IOCs: 2")
    print(f"  Assets: 2")
    print(f"  Malware: 1")
    print(f"  Campaigns: 1")

    print("\n[RUNNING BULK CORRELATION]...")
    relationships = await engine.correlate_all(
        vulnerabilities=[CVE_2026_8181, CVE_2026_1234],
        iocs=[IOC_IP_MALWARE, IOC_DOMAIN_C2],
        assets=[ASSET_DMZ_WEB01, ASSET_INTERNAL_DB],
        malware_data=MALWARE_DATA,
        campaign_data=CAMPAIGN_DATA,
        network_data=NETWORK_DATA,
    )

    print(f"\n[TOTAL RELATIONSHIPS]: {len(relationships)}")

    # Group by type
    by_type = {}
    for rel in relationships:
        rel_type = rel.relationship_type.value
        if rel_type not in by_type:
            by_type[rel_type] = []
        by_type[rel_type].append(rel)

    print("\n[RELATIONSHIPS BY TYPE]:")
    for rel_type, rels in sorted(by_type.items()):
        print(f"  {rel_type}: {len(rels)}")


async def main():
    """Run all examples."""
    await example_cve_asset_correlation()
    await example_ioc_malware_correlation()
    await example_campaign_cve_correlation()
    await example_attack_paths()
    await example_bulk_correlation()

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print("\n[RELATIONSHIP CORRELATION ENGINE]:")
    print("  * CVE-to-Asset correlation via CPE matching")
    print("  * IOC-to-Malware correlation")
    print("  * Campaign-to-CVE correlation")
    print("  * Asset-to-Asset reachability")
    print("  * Attack path discovery (BFS)")
    print("  * Campaign impact analysis")
    print("  * Bulk correlation across all entities")
    print("\nReady for Phase 1D: SQLite Implementation")


if __name__ == "__main__":
    asyncio.run(main())
