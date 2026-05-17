"""
core/fusion_example.py - Example: How Threat Fusion Engine Works

This demonstrates the flow:
API result → normalize → fuse → score → persist

Shows realistic multi-source CVE fusion.
"""

import asyncio
from core.threat_fusion import ThreatFusionEngine


# Example raw data from multiple sources (as they come from APIs)

NVD_CVE_2026_8181 = {
    "id": "CVE-2026-8181",
    "description": "Critical remote code execution in web framework X",
    "cvss_score": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "severity": "CRITICAL",
    "cwe_ids": ["CWE-79", "CWE-89"],
    "cpe_uris": ["cpe:2.3:a:vendor:framework:1.0:*:*:*:*:*:*:*"],
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-8181"],
    "published": "2026-05-16",
    "modified": "2026-05-17",
}

EPSS_CVE_2026_8181 = {
    "cve": "CVE-2026-8181",
    "epss": 0.97,
    "percentile": 98.5,
    "date": "2026-05-17",
}

KEV_CVE_2026_8181 = {
    "cveID": "CVE-2026-8181",
    "dateAdded": "2026-05-17",
    "knownRansomwareCampaignUse": "Yes",
}

VULNERS_CVE_2026_8181 = {
    "id": "CVE-2026-8181",
    "public_exploit_available": True,
    "metasploit_available": True,
    "exploit_count": 5,
    "exploit_sources": ["exploit-db", "rapid7", "packetstorm"],
}

INTERNAL_CONTEXT = {
    "internet_exposed": True,
    "asset_criticality": "critical",
    "attack_path_exists": True,
    "lateral_movement_potential": True,
    "affected_assets": ["dmz-web-01", "dmz-api-02"],
    "match_confidence": 0.95,
    "evidence_sources": ["cpematch", "vulnerability_scan"],
}


async def example_cve_fusion():
    """Example: Fuse CVE from multiple sources."""
    print("\n" + "=" * 70)
    print("THREAT FUSION ENGINE - CVE FUSION EXAMPLE")
    print("=" * 70)

    engine = ThreatFusionEngine()

    print("\n[INPUT SOURCES]:")
    print("  * NVD: CVSS 9.8, CRITICAL")
    print("  * EPSS: 0.97 (exploitable)")
    print("  * KEV: Listed, ransomware used")
    print("  * Vulners: 5 public exploits")
    print("  * Internal: Internet-facing critical asset")

    # Fuse all sources
    print("\n[FUSING]...")
    fused = await engine.fuse_cve(
        nvd_data=NVD_CVE_2026_8181,
        epss_data=EPSS_CVE_2026_8181,
        kev_data=KEV_CVE_2026_8181,
        vulners_data=VULNERS_CVE_2026_8181,
        internal_context=INTERNAL_CONTEXT,
    )

    # Display results
    print("\n[FUSION RESULT]:")
    print(f"  CVE ID: {fused.entity_id}")
    print(f"  Entity Type: {fused.entity_type.value}")

    print(f"\n[THREAT SCORE]: {fused.threat_score:.1f}/100")
    print(f"   Threat Level: {fused.threat_level.value}")

    print(f"\n[PERSISTENCE DECISION]:")
    print(f"   Should Persist: {fused.should_persist}")
    print(f"   Reason: {fused.persistence_reason}")

    print(f"\n[FUSION SOURCES]:")
    print(f"   {', '.join(fused.fusion_sources)}")

    print(f"\n[RELATIONSHIPS]:")
    for rel in fused.relationships:
        print(
            f"   {rel.source_id} --[{rel.relationship_type.value}]--> {rel.target_id}"
        )
        print(f"     Confidence: {rel.confidence:.2f}")

    print(f"\n[THREAT REASONING]:")
    for line in fused.threat_reasoning.split("\n"):
        print(f"   {line}")

    print(f"\n[FUSED RISK CONTEXT]:")
    risk = fused.fused_risk
    if risk:
        print(f"   CVSS: {risk.cvss_score} ({risk.cvss_vector})")
        print(f"   EPSS: {risk.epss_score:.2f}")
        print(f"   KEV Listed: {risk.kev_listed}")
        print(f"   Public Exploit: {risk.public_exploit_available}")
        print(f"   Exploit Count: {risk.exploit_count}")
        print(f"   Internet Exposed: {risk.internet_exposed}")
        print(f"   Attack Path Exists: {risk.attack_path_exists}")

    return fused


async def example_incomplete_source():
    """Example: CVE with missing EPSS/KEV (still works)."""
    print("\n" + "=" * 70)
    print("THREAT FUSION ENGINE - INCOMPLETE SOURCE EXAMPLE")
    print("=" * 70)

    engine = ThreatFusionEngine()

    print("\n[INPUT SOURCES]:")
    print("  * NVD: CVSS 7.5, HIGH")
    print("  * EPSS: (missing)")
    print("  * KEV: (missing)")
    print("  * Vulners: (missing)")
    print("  * Internal: (missing)")

    # Fuse with minimal sources
    print("\n[FUSING]...")
    fused = await engine.fuse_cve(
        nvd_data={
            "id": "CVE-2026-1234",
            "description": "Moderate vulnerability",
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            "severity": "HIGH",
            "cwe_ids": ["CWE-200"],
            "cpe_uris": [],
            "references": [],
            "published": "2026-05-17",
            "modified": "2026-05-17",
        }
    )

    print(f"\n[FUSION RESULT]:")
    print(f"  CVE ID: {fused.entity_id}")
    print(f"  Threat Score: {fused.threat_score:.1f}/100")
    print(f"  Threat Level: {fused.threat_level.value}")
    print(f"  Should Persist: {fused.should_persist}")
    print(f"  Reason: {fused.persistence_reason}")

    return fused


async def main():
    """Run all examples."""
    # Example 1: Complete fusion
    result1 = await example_cve_fusion()

    # Example 2: Incomplete source
    result2 = await example_incomplete_source()

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print("\n[THREAT FUSION ENGINE RESULTS]:")
    print("   * Merged 5 intelligence sources into 1 object")
    print("   * Calculated contextual threat score")
    print("   * Created relationships from fusion data")
    print("   * Made persistence decision")
    print("   * Built threat reasoning")
    print("\n   CVE-2026-8181: Score {:.0f}, Persist: {}".format(
        result1.threat_score, result1.should_persist
    ))
    print("   CVE-2026-1234: Score {:.0f}, Persist: {}".format(
        result2.threat_score, result2.should_persist
    ))


if __name__ == "__main__":
    asyncio.run(main())
