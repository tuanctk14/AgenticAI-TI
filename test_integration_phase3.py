#!/usr/bin/env python3
"""
Test Phase 3 integration - enriched CVE in Menu 1 output
"""

from tools.nvd_client import fetch_cve_by_id

# Test enriched CVE fetch
print("=" * 70)
print("Testing Phase 3 Integration: Enriched CVE Output")
print("=" * 70)

result = fetch_cve_by_id("CVE-2021-44228", enrich=True)

# Display result
if result["context"]:
    cve = result["context"][0]
    print(f"\nCVE: {cve['id']}")
    print(f"CVSS: {cve['cvss_score']}")
    print(f"Severity: {cve['severity']}")
    print(f"Published: {cve['published']}")
    print(f"CWEs: {cve['cwe_ids']}")
    print(f"Description: {cve['description'][:100]}...")

    # Display enrichment
    enrichment = cve.get("enrichment")
    if enrichment:
        print(f"\n[ENRICHMENT DATA]")
        if enrichment.get("epss"):
            print(f"  EPSS: {enrichment['epss']['score']:.4f}")
        if enrichment.get("kev"):
            print(f"  KEV Listed: {enrichment['kev']['listed']}")
        if enrichment.get("unified_risk_score"):
            print(f"  Risk Score: {enrichment['unified_risk_score']:.2f}/100")
        if enrichment.get("enrichment_summary"):
            print(f"  Summary: {enrichment['enrichment_summary']}")
    else:
        print("\n[No enrichment data]")
else:
    print("CVE not found")

print("\n" + "=" * 70)
print("Integration test complete!")
print("=" * 70)
